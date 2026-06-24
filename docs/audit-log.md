# Audit log

This is the review record for the policies and CI pipeline. I went through three external review passes after the initial self-audit, and each one found real bugs the previous pass missed. That's not embarrassing. It's what real review looks like. The point of keeping this log is to show that process honestly, not to claim the first draft was clean.

One thing to flag before anything else: `opa test` has never been run against this code in a real OPA environment. Everything below was fixed by re-reading code against provider schemas. Re-reading and running are different things. **Run `opa test policies/ tests/ -v` yourself before treating any of this as proven.**

## Self-audit: fixed before shipping

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | `examples/terraform/{compliant,noncompliant}/main.tf` had no `required_providers` or `provider` block — `terraform init` would fail in CI before conftest ever ran | High | Added `versions.tf` to both example directories |

## Self-audit: left open, with reasoning

| # | Finding | Severity | Why left open |
|---|---|---|---|
| 1 | `access_control.rego`'s AWS IAM check assumes `Action` is a single string. Real AWS IAM policies frequently use a list (e.g. `["s3:*", "iam:*"]`). A wildcard inside a list won't be caught. | Medium | Fixing it correctly means handling both forms plus partial wildcards (`s3:Put*`). That's bigger than a patch and deserves its own test file. Flagged here rather than silently shipped. |
| 2 | `encryption_at_rest.rego`'s secret-in-env-var check assumes a list-of-objects shape (`env = [{name, value}]`), matching Cloud Run's schema. `aws_lambda_function` uses a map block instead, so the AWS branch does nothing. | Medium | The GCP path is the one that matters for SecureCart's actual design. The AWS path was added for breadth without being validated against the real schema. Listed here rather than left as an undocumented blind spot. |
| 3 | The CI workflow's `terraform plan` steps assume `terraform init` completes without GCP credentials. The Google provider fails at plan time without credentials, even for resources that don't make live API calls. | High (blocks CI) | Needs either GCP credentials as a GitHub Actions secret, or a different approach that doesn't require them. Decision left for whoever deploys this. |
| 4 | No unit tests exist for `pci_dss/access_control.rego`, `soc2/logging_monitoring.rego`, or `nist_800_53/least_privilege.rego`. Only `network_segmentation` and `encryption_at_rest` have tests. | High | Three policy files ship with zero regression safety. This is the most important thing to fix before calling the repo audit-ready. |
| 5 | `least_privilege.rego`'s oversized-IAM-binding check uses `count(members) > 10` with no documented reason for that number. | Low | Arbitrary thresholds are an audit smell. Worth a comment citing an actual assumption, not a structural rewrite. |

## External review #1

An independent review with an adversarial approach caught more than the self-audit. It was explicitly trying to break things rather than verify design intent. Here's what it found.

| # | Finding | Fix applied |
|---|---|---|
| 1 | `is_encrypted()` used `!= ""` checks, which pass when a field is `null`. Terraform plan JSON uses `null` for unset attributes, so leaving a field blank bypassed the check entirely. A control that's easier to bypass than to satisfy is worse than no control. | Added `has_value()` helper rejecting both `null` and `""`. Added a regression test. |
| 2 | `google_logging_project_sink` has no `retention_days` field in the real GCP schema — retention lives on `google_logging_project_bucket_config`, not the sink. The policy was checking a field that doesn't exist. | Rewrote the check against the correct resource type. |
| 3 | `aws_lambda_function` env-var check read an `env` list field. The real schema is `environment[0].variables`, a map. | Rewrote against the map shape. |
| 4 | `google_cloud_run_v2_service` env-var check read a top-level `env` field. The real schema nests it under `template[_].containers[_].env[_]`. | Rewrote against the nested path. |
| 5 | AWS sensitive-port detection only special-cased port 5432. Ports 22, 3389, 3306, 1433, and 6379 were never checked on AWS security group rules. | Added a range-aware `port_range_overlaps_sensitive()` helper shared by both GCP and AWS branches. |
| 6 | `azurerm_network_security_rule` was listed as a covered resource type but had no deny logic — dead code. | Implemented against the real fields (`source_address_prefix`, `destination_port_range`), with a test. |
| 7 | `aws_s3_bucket`'s inline `server_side_encryption_configuration` block was removed from the AWS provider in v4+. The policy was auditing a schema that no longer exists. | Split into a separate check requiring a matching `aws_s3_bucket_server_side_encryption_configuration` resource. |
| 8 | `access_control.rego` referenced `google_cloud_run_service_iam_member` (v1) while every other policy targets the v2 resource family. The rule could never fire against SecureCart's actual deployment. | Corrected to `google_cloud_run_v2_service_iam_member`. |
| 9 | The GCP "MFA org policy" check compared the Terraform block label (`resource.name == "require_mfa"`) to a string. It was checking what the author named the block, not what GCP constraint was actually being enforced. | Rewrote to inspect the actual `constraints/iam.*` field. Added a comment noting this check can't fully verify MFA on its own — GCP MFA is primarily a Context-Aware Access concern outside this resource type. |
| 10 | `aws_iam_policy`'s wildcard check only matched `Action` as a single string. A JSON array (`["s3:*", "iam:PassRole"]`) bypassed it entirely. | Added `action_has_wildcard()` handling both forms, with tests for each. |
| 11 | Sensitive-port detection could be bypassed by expressing a port as a range string the GCP match didn't parse. | Same range-aware fix as #5. |
| 12 | Name-based detection (`contains(name, "payment")`) for both the segmentation and alerting policies could be defeated by renaming the resource. | Replaced with mandatory explicit `pci-scope` and `monitored` labels. Every relevant resource must declare its scope status, regardless of its name. Added bypass regression tests. |
| 13 | PCI citation `10.6.1` for the alerting control was wrong — 10.6 in PCI DSS v4.0 covers NTP time sync, not alerting. | Removed rather than replaced with another guess. |
| 14 | PCI citation `8.3.1` for MFA was wrong — 8.3.x covers password/passphrase requirements. MFA into the CDE is 8.4.2. | Corrected to 8.4.2, with a note in `controls-mapping.md` that every citation needs a primary-source check. |
| 15 | No CI authentication — `terraform plan` against the Google provider fails at provider initialization without credentials. | Added a `google-github-actions/auth@v2` step to both CI jobs, requiring a `GCP_SA_KEY` secret. |
| 16 | 3 of 5 policy files had zero unit tests. | Added test files for all three. |

## External review #2

The second review found bugs that survived the first fix round, including one I introduced myself while fixing something else. That's worth stating directly, because "fixing a bug while introducing a new one in the same edit" is a real risk of any refactor.

| # | Finding | Severity | Fix applied |
|---|---|---|---|
| 1 | `least_privilege_test.rego` used `some i in numbers.range(...)` without importing `future.keywords.in`. A parse error that blocks `opa test` entirely, not just that file. | Blocks CI | Added the missing import. |
| 2 | `has_matching_alert_policy` compared an alert policy's `display_name` against `resource.name` (the Terraform block label, e.g. `payment_service`) instead of the actual cloud resource name (`payment-service`). These are different strings. A correctly configured compliant example could still fail. | Blocks CI | Now resolves the real cloud resource name before comparing. |
| 3 | Azure `destination_port_range = "*"` (meaning every port) wasn't handled by the range parser. A fully open Azure rule passed undetected. | Blocks enforcement | Added an explicit `"*"` case to `port_range_overlaps_sensitive`. |
| 4 | A GCP firewall `allow` block with `protocol = "all"` and no `ports` attribute — all ports, all protocols, the worst possible misconfiguration — had nothing for the old logic to iterate over. It passed. | Blocks enforcement | Added a dedicated `is_open_ingress` clause matching `protocol == "all"` directly. |
| 5 | `has_matching_sse_config` linked an S3 bucket to its encryption config by checking whether the config resource's Terraform label contained the bucket label as a substring. Two unrelated buckets with similar names could cross-match. | Undermines the point | Rewrote to compare the actual `bucket` attribute on both resources. Added a regression test. |
| 6 | My own automated cleanup pass accidentally snake_cased a `change.after.name` value that needed to stay hyphenated, breaking the test it was supposed to fix. | Self-introduced, caught on review | Reverted that one field. Left the other parts of the fix in place since they were correct. |
| 7 | `access_control.rego` still used `contains(name, "payment")` for the Cloud Run IAM-condition check, even after `network_segmentation.rego` switched to label-based scope. Inconsistent posture in the same repo, and the same bypass risk the label fix was supposed to eliminate. | Undermines the point | Rewrote to cross-reference the target service's actual `pci-scope` label. Added a bypass regression test. |
| 8 | A resource can declare `pci-scope: false` and satisfy the explicit-declaration requirement even if that declaration is inaccurate. | Not fixed — see below. | |
| 9 | No PCI citation for the alerting requirement in `logging_monitoring.rego`. | Cosmetic, intentional | Left uncited rather than guessing a replacement for the one that was wrong. |
| 10 | `aws_lambda_function` and `azurerm_storage_account` had no test coverage on their encrypt/monitor paths. | Cosmetic | Added tests for both, including a null-CMK regression test for Azure. |

### On finding #8

A policy engine reading Terraform plan output can enforce "you must declare a value." It can't enforce "that value is truthful," because verifying that would require knowing what the service actually does at runtime, which the plan JSON doesn't contain.

Trying to code around this (for example, flagging `pci-scope: false` when the resource also has a Stripe-shaped env var) would just reintroduce the name and pattern-based guessing that was already removed from two other policies. The right fix is a process control: any `pci-scope: false` declaration on a payment-adjacent resource should require a recorded architecture-review sign-off, enforced through code review policy rather than a Rego rule. That's something a human needs to own. This is a real limitation of static policy-as-code, and it belongs in the limitations section rather than being papered over with a weaker version of the same workaround that was already fixed twice.

## External review #3

| # | Finding | Severity | Fix applied |
|---|---|---|---|
| 1 | `aws_lambda_function` was in `monitorable_types`, but `has_matching_alert_policy` only ever checked for a `google_monitoring_alert_policy`. Any Lambda function failed this check permanently, regardless of how it was configured. A monitorable type with no satisfiable allow path is worse than a check that's too strict. | Blocks enforcement | Added an explicit AWS branch checking for a matching `aws_cloudwatch_metric_alarm`. |
| 2 | `aws_cloudwatch_log_group` with no `retention_in_days` set (AWS's "never expire" configuration, actually the most compliant option) defaulted to `0` and got denied as a 0-day violation. | Blocks enforcement (false positive on best-case config) | Changed the default to `null`. Only evaluate the `< 365` check when the field is actually present. |
| 3 | AWS security group rules with `protocol = "-1"` (all traffic) render `from_port`/`to_port` as `0`/`0`, producing a `"0-0"` range with no sensitive port. A rule allowing all traffic from everywhere passed unchallenged. | Blocks enforcement | Added a direct `protocol == "-1"` check independent of the port-range logic. |
| 4 | `azurerm_network_security_rule` supports `destination_port_ranges` (plural, a list) as an alternative to the singular `destination_port_range`. Rules using the list form were checked against a field that doesn't exist for them and bypassed entirely. | Undermines the point | Added a second deny rule iterating the plural list form. |
| 5 | The previous alert-policy name-matching fix over-corrected into requiring exact string equality between `display_name` and the service name. Real naming patterns like "payment-service - error rate alert" would never match exactly, generating constant false positives on correctly monitored services. | Undermines the point | Replaced both the substring and exact-match approaches with an explicit `monitor-id` / `monitors` label cross-reference, consistent with how `pci-scope` is handled everywhere else. |
| 6 | Cross-reference checks (`pci-scope`, `monitor-id`) only work if the referenced resource appears in the same plan. A partial or `-target`-scoped plan could omit a resource, silently breaking a cross-reference that was correctly configured. | Not fully fixable in Rego — see below. | |
| 7 | No tests existed for the Azure `"*"` wildcard port path, the AWS `protocol = "-1"` bypass, or Lambda monitoring. These were the exact untested gaps that hid findings #1 and #3 from earlier review passes. | Undermines the point | Added all three as explicit regression tests named to make clear what each one guards against. |
| 8 | No allow-path test for `aws_cloudwatch_log_group` with retention legitimately unset. | Cosmetic | Added `test_allow_cloudwatch_with_no_retention_set_is_infinite_and_compliant`. |
| 9 | `pci-scope: false` still satisfies the explicit-declaration requirement. | Cosmetic, re-confirmed | Same reasoning as the previous pass. No change. |
| 10 | AWS IAM wildcard detection was re-checked and found to already handle both string and array `Action` forms correctly — this was fixed in an earlier pass. | Already fixed | No change needed. |
| 11 | No PCI citation for the alerting requirement. | Cosmetic, intentional | Unchanged. |

### On finding #6

In normal CI usage, a full `terraform plan` includes every resource in the configuration — even unchanged ones appear with action `["no-op"]`. So cross-reference checks work as expected in practice. The actual risk is narrower: partial plans (using `-target`) or resources split across separate state files after a refactor.

The fix belongs at the pipeline level, not in Rego. CI should reject any `terraform plan` invocation that uses a `-target` flag before it reaches conftest. Rego has no way to know whether a plan was scoped, so trying to code around it would mean guessing at completeness the tool can't actually verify.

## What's still open

- The IA-5(1) citation for service account keys is a stretch and hasn't been verified against the actual NIST text.
- `opa test` has never been run against this code in a real OPA environment. Everything above was fixed by reading carefully, not by running. Those are different claims. **Run the tests. Report what breaks.**
- No third-party review has happened. Two independent passes each found real bugs. A third would likely find more.

## Current state

Three review passes, 16+ confirmed findings, each pass documented honestly. The repo is in a defensible state as a portfolio artifact: not perfect, but clearly reviewed with a real record of what was caught and what's still unverified. The single most important thing remaining is execution — run `opa test` in a real OPA environment before treating anything here as proven rather than re-read.
