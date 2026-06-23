# Audit Log

This is the adversarial review pass against the policies and CI pipeline,
done with a different checklist than the one used to build them (correctness
of Rego logic, schema accuracy against real provider resources, and whether
the CI pipeline can actually execute end-to-end) rather than re-reading the
same design intent that produced them. This is not a substitute for an
independent second reviewer — it's a structured self-check, and it's
labeled as such rather than oversold as something it isn't.

## Findings fixed before calling this "ready"

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | `examples/terraform/{compliant,noncompliant}/main.tf` had no `required_providers` or `provider` block — `terraform init` would fail in CI before conftest ever runs | High | Added `versions.tf` to both example directories |

## Findings left open, with reasoning for why

| # | Finding | Severity | Why it's not fixed yet |
|---|---|---|---|
| 1 | `access_control.rego`'s AWS IAM check (`statement.Action`) assumes `Action` is a single string. Real AWS IAM policies frequently express `Action` as a list (e.g. `["s3:*", "iam:*"]`). As written, a wildcard inside a list won't be caught. | Medium | This is a real gap, not a stylistic nitpick — it means the policy under-detects on AWS. Fixing it correctly requires handling both the string and array case plus partial wildcards (`s3:Put*`), which is a bigger rule than the others and deserves its own test file rather than a rushed patch. Flagged here instead of silently shipped. |
| 2 | `encryption_at_rest.rego`'s secret-in-env-var check assumes a list-of-objects shape (`env = [{name, value}]`), which matches Cloud Run's schema. `aws_lambda_function` actually expresses environment variables as a single map block (`environment { variables = {...} }`), not a list — so the AWS branch of this check currently does nothing. | Medium | Same call as above: the GCP path is the one that matters for the actual GKE/Cloud Run-based SecureCart design, and the AWS path was added for breadth without being validated against AWS's actual Terraform schema. Listed here rather than left as an undocumented blind spot. |
| 3 | The CI workflow's `terraform plan` steps assume `terraform init` can complete without real GCP credentials. For the `google` provider, plan-time validation can fail without a configured credential, even for resources that don't make live API calls. | High (blocks CI from running green, not a logic bug) | This needs either (a) GCP service account credentials added as a GitHub Actions secret, or (b) switching the examples to a provider that supports a true offline/mock plan (e.g. using `terraform validate` instead of a full `plan` for the demo, which doesn't require credentials). Decision deferred to whoever deploys this — documented instead of guessed at. |
| 4 | No test exists for `pci_dss/access_control.rego` or `soc2/logging_monitoring.rego` or `nist_800_53/least_privilege.rego` — only `network_segmentation` and `encryption_at_rest` have unit test files. | High | Coverage gap, not a logic gap. Three policy files currently ship with zero unit tests, which means a future edit to them has no regression safety net. This is the single most important thing to fix before calling the repo "audit-ready" — a controls library without tests on most of its controls undermines the entire pitch of the project. |
| 5 | `least_privilege.rego`'s "oversized IAM binding" check uses a flat threshold (`count(members) > 10`) with no justification documented for why 10 is the right number. | Low | Arbitrary thresholds are a known audit smell — a real reviewer would ask "why 10, not 5 or 20." Worth a one-line comment citing an actual access-review cadence assumption, not a structural rewrite. |

## What this audit pass deliberately did not check

- Whether the Rego actually parses and runs (`opa test`) — **not verified**, because the sandbox this was built in cannot reach the hosts needed to download the OPA binary. This is the single biggest caveat on this entire repo: **run `opa test policies/ tests/ -v` yourself before treating any of this as proven**, and report back what breaks. Rego syntax mistakes that look fine on a read-through are the most common way these policies fail in practice.
- Whether the conftest CI pipeline actually goes green end-to-end on GitHub Actions, for the credential reasons in finding #3.

## Second audit pass — fixes applied after an independent model review

An external review (different model, adversarial prompt, no attachment to
the original design) caught more real bugs than the self-audit above did.
That's worth stating plainly rather than glossing over: self-review with a
different checklist is not a substitute for an actually independent
reviewer. Findings below were confirmed against the source files and fixed.

| # | Finding (from external review) | Fix applied |
|---|---|---|
| 1 | `is_encrypted()` used `!= ""` checks, which pass when a field is `null` (Terraform plan JSON's representation of an unset attribute) — a control that's bypassed by leaving a field unset, the most likely real-world misconfiguration. **Reclassified to blocks-deployment severity** rather than the "undermines pitch" tier the review suggested — this inverts the control's purpose. | Added `has_value()` helper rejecting both `null` and `""`; added a regression test (`test_deny_null_encryption_key_does_not_bypass`). |
| 2 | `google_logging_project_sink` has no `retention_days` field in the real GCP resource schema — retention lives on the log destination (`google_logging_project_bucket_config`), not the sink. | Rewrote the check against `google_logging_project_bucket_config`. |
| 3 | `aws_lambda_function` env-var check read a `env` list field; the real schema is `environment[0].variables`, a map. | Rewrote against the map shape with `some var_name, var_value in vars`. |
| 4 | `google_cloud_run_v2_service` env-var check read a top-level `env` field; the real schema nests it under `template[_].containers[_].env[_]`. | Rewrote against the nested path. |
| 5 | AWS sensitive-port detection only special-cased port 5432; ports 22/3389/3306/1433/6379 were never actually checked on AWS security group rules. | Replaced with a range-aware `port_range_overlaps_sensitive()` helper shared by both GCP and AWS branches, tested against an exact-port and a wide-range case. |
| 6 | `azurerm_network_security_rule` was listed as a covered resource type but had no actual deny logic referencing its real fields — dead code. | Implemented against `source_address_prefix` / `destination_port_range` with a test. |
| 7 | `aws_s3_bucket`'s inline `server_side_encryption_configuration` block was removed from the AWS provider in v4+; checking it meant auditing a schema that no longer exists. | Split into a separate check requiring a matching `aws_s3_bucket_server_side_encryption_configuration` resource. |
| 8 | `access_control.rego` referenced `google_cloud_run_service_iam_member` (v1) while every other policy targets the v2 resource family — a type mismatch that meant the rule could never fire against SecureCart's actual v2-based deployment. | Corrected to `google_cloud_run_v2_service_iam_member`. |
| 9 | The GCP "MFA org policy" check compared the Terraform resource's arbitrary label (`resource.name == "require_mfa"`) to a string — checking what the .tf author *named the block*, not what GCP constraint is actually enforced. | Rewrote to inspect the actual `constraints/iam.*` field, with an explicit code comment admitting this check cannot fully verify MFA on its own (GCP MFA is primarily a Context-Aware Access concern, outside this resource type). |
| 10 | `aws_iam_policy`'s wildcard check only matched `Action` as a single string; a JSON array (the more common real shape, e.g. `["s3:*", "iam:PassRole"]`) bypassed it entirely. | Added `action_has_wildcard()` handling both string and array forms, with tests for each. |
| 11 | Sensitive-port detection could be bypassed by expressing a port as part of a range string GCP's port match didn't parse. | Same range-aware fix as #5. |
| 12 | Name-based detection (`contains(name, "payment")`) for both the segmentation and alerting policies was a one-rename bypass — renaming "payment-service" to anything else defeated the control entirely. | Replaced with mandatory explicit labeling (`pci-scope` and `monitored` labels required on every relevant resource, regardless of name) — default-deny-if-undeclared instead of name-matching. Added explicit bypass-regression tests (`test_deny_renamed_payment_service_still_caught`, `test_deny_renamed_service_without_monitored_label_still_caught`). |
| 13 | PCI citation `10.6.1` for the alerting control was wrong — 10.6 in PCI DSS v4.0 covers time synchronization (NTP), not alerting. | Removed the incorrect citation rather than guess a replacement; flagged in `controls-mapping.md` for manual verification against the published standard. |
| 14 | PCI citation `8.3.1` for MFA was wrong — 8.3.x covers password/passphrase requirements; MFA-into-CDE is 8.4.2. | Corrected to 8.4.2, with a note in `controls-mapping.md` that every citation in this repo (including this corrected one) still needs a primary-source check before being relied on in an interview or real assessment. |
| 15 | No CI authentication — `terraform plan` against the `google` provider fails at provider-init without credentials, even before reaching a policy check. | Added a `google-github-actions/auth@v2` step to both CI jobs, requiring a `GCP_SA_KEY` repository secret to be configured before the workflow runs green — documented as a setup prerequisite, not silently assumed away. |
| 16 | 3 of 5 policy files (`access_control.rego`, `soc2/logging_monitoring.rego`, `nist_800_53/least_privilege.rego`) had zero unit tests. | Added test files for all three. |

### What's still genuinely open

- The IA-5(1) citation for service account keys is a stretch and hasn't
  been re-derived from the standard text — left as a cosmetic-tier item,
  consistent with the external review's own ranking.
- This audit log itself has not been re-verified by running `opa test`
  in a real OPA environment — the sandbox this was built in still cannot
  reach the hosts needed to download the binary. **The single most
  important thing to do before treating any of the above as proven is to
  run `opa test policies/ tests/ -v` yourself.** Everything above is
  "fixed by re-reading the schema and logic carefully," not "fixed and
  confirmed passing in a real OPA runtime." Those are different claims,
  and conflating them is exactly the kind of overclaim this document
  exists to prevent.
- No third review pass has happened. Two models (mine, then an external
  one) have now read this code. A third independent pass would likely
  find more — that's not a knock on either review, it's just what
  multi-pass review looks like, and one or two passes don't mean the
  code is exhaustively correct.

## Honest verdict, updated

This repo went through two real review passes — a self-audit, then an
independent adversarial review that caught more than the self-audit did —
and a fix pass that addressed all 16 confirmed findings down to the
cosmetic tier. That's a defensible state for a portfolio artifact: not
"perfect," but "demonstrably reviewed, with an honest record of what was
caught and what's still unverified." The remaining gap — Rego execution
has not been confirmed in a real OPA runtime — is the one thing to close
before treating this as finished. Run the tests. Report back what breaks.

## Third audit pass — a second external review round, fixes applied

The second external review pass caught bugs that survived the first fix
round, including one introduced by my own automated cleanup (see #6 below —
worth stating plainly, because "fixing a bug while introducing a new one in
the same edit" is a real risk of any refactor, mine included).

| # | Finding | Severity | Fix applied |
|---|---|---|---|
| 1 | `least_privilege_test.rego` used `some i in numbers.range(...)` without importing `future.keywords.in` — a parse error that blocks `opa test` entirely, taking down the whole pipeline, not just that file. | Blocks CI | Added the missing import. |
| 2 | `has_matching_alert_policy` compared an alert policy's `display_name` against `resource.name` (the Terraform block's local label, e.g. `payment_service`) instead of the actual cloud resource's `name` attribute (e.g. `payment-service`) — those are different strings, so a correctly-configured compliant example could still fail. | Blocks CI | Now resolves the real cloud resource name via `object.get(resource.change.after, "name", resource.name)` before comparing. |
| 3 | Azure `destination_port_range = "*"` (meaning "every port") wasn't handled by the range parser — `split("*", "-")` doesn't produce a numeric range, so a fully open Azure rule passed undetected. | Blocks enforcement | Added an explicit `"*"` case to `port_range_overlaps_sensitive`. |
| 4 | A GCP firewall `allow` block with `protocol = "all"` and no `ports` attribute (meaning all ports, all protocols — the worst possible misconfiguration) had nothing for the old logic to iterate, so it passed. | Blocks enforcement | Added a dedicated `is_open_ingress` clause matching `protocol == "all"` directly. |
| 5 | `has_matching_sse_config` linked an S3 bucket to its encryption config by checking whether the config resource's Terraform *label* contained the bucket's label as a substring — a naming-convention coupling, not a structural one. Two unrelated buckets with similar names could cross-match. | Undermines pitch | Rewrote to compare the actual `bucket` attribute on both resources, with a regression test proving a same-named-but-different-bucket SSE config does NOT count. |
| 6 | An automated cleanup pass (mine, fixing the hyphen/underscore test-fixture inconsistency the *previous* review found) accidentally snake_cased a `change.after.name` value that needed to stay hyphenated to match a real cloud resource name it was being compared against — breaking the test it was supposed to fix. | Self-introduced, caught on review of own diff | Reverted that one field; left the regex fix in place everywhere else since it was correct for true Terraform-label fields. |
| 7 | The Cloud Run IAM-condition check in `access_control.rego` still matched on `contains(name, "payment")` even after `network_segmentation.rego` switched to mandatory label-based scope declaration — an inconsistent posture within the same repo, and the same bypass risk the label-based fix was supposed to eliminate everywhere. | Undermines pitch | Rewrote to cross-reference the target service's actual `pci-scope` label instead of its name, with a bypass-regression test (`test_deny_renamed_pci_scoped_service_binding_still_caught`). |
| 8 | A resource can declare `pci-scope: false` and satisfy the mandatory-declaration requirement even if that declaration is false. | **Not fixed — documented limitation, see below.** | |
| 9 | No PCI citation exists for the alerting requirement in `logging_monitoring.rego`. | Cosmetic, intentional | Confirmed as a deliberate omission (the prior citation, 10.6.1, was wrong and removed rather than replaced with another guess) — left uncited rather than guessed. |
| 10 | `aws_lambda_function` and `azurerm_storage_account` had no test coverage on their encrypt/monitor paths. | Cosmetic | Added tests for both, including a null-CMK regression test for Azure mirroring the GCP one. |

### On finding #8 — why this is a documented limitation, not a code fix

A policy engine reading Terraform plan output has no way to verify that a
human's *declaration* about a resource is *true*. It can enforce "you must
say something" (which is the actual fix already made — removing the name-
based guess). It cannot enforce "what you said is accurate," because that
requires knowledge the plan JSON doesn't contain — what the service
actually does at runtime. Coding a keyword-based guess here (e.g., flagging
`pci-scope: false` if the resource also has a Stripe-shaped env var) would
just reintroduce the exact name/pattern-based heuristic that was removed
from two other policies for being unreliable and inconsistent. The honest
fix is a process control, not a Rego rule: any `pci-scope: false`
declaration on a resource that touches payment processing should require a
recorded architecture-review sign-off, enforced by code review policy, not
by this tool. That's a real gap in what static policy-as-code can do on its
own, and it belongs in the limitations section, not papered over with a
weaker version of the same bypass already fixed twice tonight.

## Honest verdict, updated again

Three review passes now: self-audit, external review #1, external review
#2. Each one found real things the previous pass missed, including one bug
my own fix for a prior finding introduced. That's not embarrassing — it's
what the audit trail in this repo is actually demonstrating, and it's a
more honest portfolio story than claiming zero defects after one pass. The
single open item — `opa test` has never been run in a real OPA environment
against this code — is still the most important thing to close. Everything
else has been re-read carefully against provider schemas, not proven by
execution. Run the tests before trusting any of this further.

## Fourth audit pass — a third external review round, fixes applied

| # | Finding | Severity | Fix applied |
|---|---|---|---|
| 1 | `aws_lambda_function` was listed in `monitorable_types`, but `has_matching_alert_policy` only ever checked for a `google_monitoring_alert_policy` — there was no AWS allow-path at all, so any Lambda function failed this check permanently, regardless of how it was configured. A monitorable type with zero satisfiable allow path is a worse defect than a check that's merely too strict. | Blocks enforcement | Added an explicit AWS branch checking for a matching `aws_cloudwatch_metric_alarm`. |
| 2 | `aws_cloudwatch_log_group` with no `retention_in_days` set (AWS's "never expire" / infinite retention — the MOST compliant configuration) was defaulting to `0` and getting denied as a 0-day-retention violation. | Blocks enforcement (false positive on the best-case config) | Changed the default from `0` to `null`, and only evaluate the `< 365` comparison when the field is actually present. |
| 3 | AWS security group rules with `protocol = "-1"` (all traffic) commonly render `from_port`/`to_port` as `0`/`0`, which produced a `"0-0"` range containing no sensitive port — the single worst possible AWS rule (everything, from everywhere) passed unchallenged. | Blocks enforcement | Added a direct `protocol == "-1"` check independent of the port-range logic. |
| 4 | `azurerm_network_security_rule` supports `destination_port_ranges` (plural, a list) as an alternative to the singular `destination_port_range` — rules written with the list form were checked against a field that didn't exist for them and bypassed entirely. | Undermines pitch | Added a second deny rule iterating the plural list form. |
| 5 | The previous pass's fix for the alert-policy name-matching bug over-corrected into requiring exact string equality between `display_name` and the service name — real naming conventions (e.g. "payment-service - error rate alert") would never match exactly, producing constant false positives on correctly-monitored services. | Undermines pitch | Replaced both the substring AND the exact-match approaches with an explicit `monitor-id` / `monitors` label cross-reference — the same "declare it explicitly, don't infer it from a string" pattern already used for `pci-scope`. Removed a silent fallback-to-resource-name default that would have reintroduced the same ambiguity one layer down. |
| 6 | Cross-reference checks (`pci-scope`, `monitor-id`) only resolve against resources present in the SAME plan/state being evaluated. A steady-state `terraform apply` with no changes to a given resource can still include it in `terraform show -json` output with action `["no-op"]`, so this mostly holds in practice — but a `-target`-scoped or partial plan could omit a resource entirely, silently breaking a cross-reference that was correctly configured. | **Not fully fixable from the Rego side — process recommendation documented below.** | |
| 7 | No tests existed for: the Azure `"*"` wildcard port path, the AWS SG `protocol = "-1"` bypass, or Lambda monitoring (the exact gaps that hid findings #1 and #3 from earlier review passes — untested code paths are where regressions hide). | Undermines pitch | Added all three as explicit regression tests, named to make clear what bug each one guards against. |
| 8 | No allow-path test existed for `aws_cloudwatch_log_group` with retention legitimately unset (infinite/compliant). | Cosmetic | Added `test_allow_cloudwatch_with_no_retention_set_is_infinite_and_compliant`. |
| 9 | `pci-scope: false` still satisfies the explicit-declaration requirement even when false. | Cosmetic (re-confirmed, not fixed) | Same reasoning as the prior pass: this is a process-control gap, not a code defect. No change. |
| 10 | AWS IAM wildcard detection was checked again against the current file state and found to already use `endswith(action, ":*")` plus an exact `"*"` match — this was already fixed correctly in an earlier pass and the review's concern was already addressed by the time it was raised. | Already fixed | Verified, no change needed. |
| 11 | No PCI citation for the alerting requirement. | Cosmetic, intentional | Unchanged — still an honest omission rather than a guessed citation. |

### On finding #6 — the limitation that can't be fixed in Rego, and what to do instead

A policy engine evaluating a single `terraform show -json` output can only
see what's in that output. A full, non-targeted `terraform plan` includes
every resource in the configuration (changed or not) with an action of
`["no-op"]` for unchanged ones, which means cross-reference checks
generally DO still work in normal CI usage. The actual risk is narrower
than "this is broken" — it's "this breaks under partial/targeted plans, or
if a module is refactored such that a previously-co-located resource moves
to a separate state file." The fix is operational, not a Rego change:
**CI should run policy checks against full, non-targeted plans only**, and
that constraint should be enforced at the pipeline level (reject any
`terraform plan` invocation passed a `-target` flag before it reaches
conftest), not inferred from policy logic that has no way to know whether
a plan was scoped. Documented here rather than coded around, because
coding around it would mean guessing at completeness this tool cannot
actually verify.
