# ADR-001: One control set, two rails

**Date**: 2026-08-04
**Status**: Accepted
**Authors**: Lanre Oluokun
**Reversibility**: One-way door
**Supersedes**: Nothing — first ADR in this repository

---

**Each compliance rule is written once and checked twice: before a change is applied, and against what is actually running.** Today the same rules are written twice across two repositories, they have already begun to disagree without anyone noticing, and neither can see a change made outside Terraform — a console edit or a manual command is invisible to both. This decision makes one rule the single definition, adds the ability to detect configuration that drifts after deployment, and narrows scope to Google Cloud only, deleting roughly 34 tested cases of Amazon and Microsoft cloud coverage in exchange.

The cost is stated plainly in Consequences and is not small: one component of the design cannot be covered by the existing test suite. That gap is held closed by a gate — no control merges until a test for it exists — rather than by a promise to get to it.

---

## Reversibility

**One-way door.** Substantiated rather than asserted:

- Reversal takes well over a week. Restoring AWS and Azure detection means recovering four policy files and four test files — roughly 34 test cases — then re-establishing the citations they never had.
- It creates architectural path dependency. Every control written after this ADR names properties rather than field paths and expects a normalised envelope. Reverting to per-rail rule bodies means rewriting each control authored under this design, not toggling a flag.
- Two consumers depend on the output. `gcp-landing-zone` consumes this policy repository, and `regcheck` retires to a citation pack on the strength of this decision.

No data migration and no contractual lock-in, so the cost is engineering time rather than money. The classification rests on the path dependency, which is the part that does not get cheaper with notice.

## Related decisions

This is the first ADR in this repository; `docs/adr/` did not exist before it. It supersedes nothing here.

It does **not** conflict with `regcheck`'s ADR-003, which selected OPA over Forseti and SCC Policy Analyzer as the policy engine. That decision is upstream of this one and survives it — this ADR assumes OPA and decides how controls are structured within it.

It **does** contradict two things written before it, both of which are corrected rather than left standing:

- The premise, held while this effort was being planned, that `regcheck` already had a working detective rail. It does not. See Context.
- `CONTROL_COVERAGE.md`, whose PCI Requirement 3 table counts AWS and Azure clauses. Those counts are wrong once the deletion lands and are rewritten in the same change.

## Requirements resolved

This ADR records decisions reached across seven investigation tickets under the `compliance-two-rail` effort. In order: the normalised input contract; canonical control identity and ID namespace; giving `regcheck` a remote; the two-rail Rego shape; twin-control equivalence; the control-set boundary; and the disposition of `regcheck`'s non-policy assets.

Deliberately **not** resolved here, and out of scope: live GCP access including authentication, scheduling and cost; changes to `secure-vault` and the SCC-publish chain into it; and PCI DSS Requirements 8 and 11, which `CONTROL_COVERAGE.md` lists as addressable but not built.

## Context

Two repositories hold overlapping GCP compliance logic.

This one evaluates Terraform plan JSON before apply — 163 OPA tests, six shared controls in `policies/controls/`, and framework packages that attach citations. A second repository, `regcheck`, evaluates the same class of GCP misconfiguration against FFIEC and PCI DSS, with 34 tests and its own copy of the same checks.

Four checks exist in both, implemented independently, with nothing forcing them to agree:

| regcheck | this repo |
| --- | --- |
| `cloudsql_cmek` | `cmek_at_rest` |
| `overprivileged_sa` | `privileged_access` |
| `public_bucket` | `req_2_system_defaults` (bucket clauses) |
| `open_firewall` | `req_1_network_controls` |

This repository has already lived through the consequence of that arrangement once, internally. `EVOLUTION.md` records that v1 ran three parallel implementations of the same checks, the suite was green, and consolidating them **exposed three false negatives that had been hidden the whole time**. The merge did not create the bugs. It revealed them. The same setup now exists across two repositories instead of within one, and the drift has already begun: `lib/utils.rego` defines `sensitive_ports` as twelve ports here and seven in `regcheck`.

Two further constraints shaped what was possible.

**Detection must cover configuration that Terraform never sees.** A console change, a manual `gcloud` command, or drift introduced after apply is invisible to a plan-time gate. Covering it requires reading actual state from Cloud Asset Inventory — a second evaluation path against a different input shape.

**Evaluation must keep working with no cloud credentials.** `regcheck` was built offline by design, and its CI runs with `_EVIDENCE_BUCKET` deliberately unset so the whole pipeline executes against committed fixtures. That property is worth preserving, not apologising for.

A correction belongs in this section, because the decision was originally framed on a false premise. This effort began believing `regcheck` already had a working detective rail to reconcile with. **It does not.** Every `input.*` reference across `regcheck/policies/` is `input.resource_changes` — twelve of them, zero reads of asset or finding data. `regcheck` has detective *architecture* — a boundary document, a Python enrichment function, committed Cloud Asset Inventory and Security Command Center fixtures, a Cloud Build stage that runs them — but no Rego that consumes any of it. The detective rail exists as a pipeline and has never had a policy rule in it.

## Decision

**One control, defined once, evaluated on two rails.**

A control lives in `policies/controls/`, carries a stable metadata identifier, and declares the resource types it applies to. It is evaluated against a **normalised envelope** produced outside OPA by a Python pre-step. The preventive rail builds that envelope from Terraform plan JSON; the detective rail builds it from a Cloud Asset Inventory export. Framework packages — PCI DSS, SOC 2, NIST 800-53, and FFIEC — import controls and attach citations. **They never detect.**

The control set is **GCP-only**. AWS and Azure detection is deleted.

Evaluation runs against committed fixtures today, through a reader seam designed so that pointing it at a live export is configuration rather than a rewrite.

## Rationale

### One rule, not two — the prototype changed this

The original design sketched two rules per control:

```rego
policies/controls/cmek_at_rest.rego
  deny_plan[msg]     # terraform plan json
  deny_asset[msg]    # asset inventory
```

Building it showed that shape to be wrong. If normalisation does its job, both rails arrive as the same envelope and there is nothing for a second rule to do. One rule body serves both; the rail becomes a field on the input rather than a fork in the policy.

Two rules would mean two implementations of *what counts as CMEK* — reintroducing, inside the control meant to fix the duplication, exactly the duplication this decision exists to remove.

The rail difference does not disappear. It **moves out of Rego and into the normaliser**, which is where the input shapes genuinely differ. That relocation is the substance of the decision.

A working prototype backs this rather than an argument: ten unit tests, and end-to-end evaluation returning two findings against the Cloud Asset Inventory fixture, one against the non-compliant plan, and zero against the compliant plan.

### Controls name properties, not field paths

A control refers to `props.cmek_key`. It never refers to `change.after.encryption_key_name` or `resource.data.encryption.defaultKmsKeyName`. A projection table maps `(property, type, rail)` to a source path.

The two rails do not merely spell fields differently — they model them differently. Bucket encryption is a repeated block in Terraform, so a list with snake_case keys; Cloud Asset Inventory reports the same thing as a single camelCase object. Putting that asymmetry in one data file, rather than in every control that touches encryption, is the only arrangement where a control body can be shared at all.

### Normalisation happens outside OPA because it has to

`opa eval` takes a single input document. A real Cloud Asset Inventory export is newline-delimited JSON, sharded into one file per asset type. Reconciling those inside Rego is not a stylistic preference to litigate; it is not available.

### Frameworks cite, never detect

`pci_dss/req_6_secure_systems.rego` already demonstrates the target shape — it imports `data.controls.*` and does nothing but phrase the violation in PCI's language. Its own header states the split: changing what counts as a violation belongs in the control; changing how PCI phrases it belongs in the framework package.

Six files in `policies/pci_dss/` still detect directly. `encryption_at_rest.rego` records that GCP CMEK checks were manually relocated to `req_6` "to avoid duplicate violation messages" — the duplication problem was already met once and solved by hand-partitioning files, which is a solution that requires someone to remember it.

### Why the alternatives were rejected

#### Why keeping two repositories in sync by convention was rejected

This is the status quo, and it has already failed measurably. `sensitive_ports` drifted to twelve values here and seven in `regcheck`, with both narrowings documented and defensible in their own context. Nothing detected it; it was found incidentally while looking at something else. A shared constant that silently changes what the engine denies, in a file nobody diffs, is the failure mode this decision exists to eliminate.

#### Why merging into regcheck instead was rejected

`regcheck` has the better regulatory framing and the evidence pipeline. This repository has 163 tests against 34, an expiring-exception mechanism, a control/citation layer that already works, five CI jobs with per-job credentials, and a public remote with history. Moving the larger, better-tested body of work into the smaller one inverts the risk for a naming preference.

#### Why two separate control sets, one per rail, was rejected

It reproduces the original problem with extra steps. Two sets means two definitions of every check, drifting independently, exactly as the two repositories did — with the added disadvantage that both would live in the same repository and therefore look reconciled.

#### Why keeping AWS and Azure detection was rejected

The detective rail is Cloud Asset Inventory, which is GCP-only. An AWS or Azure control cannot have a detective rail at all, so retaining them would mean a control set where the two-rail promise is true for some controls and silently false for others. A coverage table that does not distinguish those is worse than one that omits them.

## Consequences

### Positive

- **A check has one definition.** Twin controls merge as entries in an applicability set rather than surviving as siblings that might disagree.
- **Drift becomes detectable.** Configuration changed outside Terraform — console edits, manual `gcloud`, post-apply mutation — is in scope for the first time. Neither repository could see it before.
- **Offline evaluation is preserved.** The full pipeline runs on committed fixtures with zero cloud credentials. This is an inherited design constraint from `regcheck`, deliberately kept. **It is not a gap and should not be recorded as one.**
- **The citation layer needs no change.** Because there is one finding set per control, there is one thing to cite. Findings carry their rail, so a framework can distinguish "satisfied preventively, unproven detectively" by reading a field.
- **A net-new evidence capability arrives.** `regcheck`'s BigQuery drift table and evidence artifacts — carrying PCI three-year and SOX seven-year retention windows in the artifact itself — have no counterpart here.

### Negative

- **The projection table escapes the test suite, and this is measured rather than suspected.** Repointing one line of the projection table at a field that is always populated turned an unencrypted bucket into a compliant one, and `opa test` still reported PASS. A wrong field path is a false negative that no policy test can see. **The mitigation is a golden-normalised-document CI job that neither repository currently has.** It is the single largest cost of this decision, and it is held by a gate rather than an intention: no twin control merges until that job exists and runs on every pull request. See *What would invalidate this decision*.
- **The detective rail is new code, not migrated code.** No Rego in either repository has ever read asset data. Describing this as consolidating two existing rails would overstate what is proven. It is one proven rail plus one being written, against fixtures nothing has evaluated.
- **Roughly 34 tested cases are deleted with AWS and Azure.** The suite drops from 163 to approximately 129. A shrinking green suite is precisely the signal that reads as normal, so the deletion is its own reviewable step and its count is stated before it happens. `CONTROL_COVERAGE.md` currently counts AWS and Azure clauses toward PCI Requirement 3 and will be wrong until rewritten alongside it.
- **The merged engine denies more than `regcheck` does today.** `sensitive_ports` resolves to the superset of twelve, restoring etcd, the Kubernetes API server, and Elasticsearch. Any `regcheck`-derived environment currently passing may begin failing. The narrower list was rejected because adopting it would remove five ports from what this repository denies today, and weakening a control to ease a merge is not available. The deploy-friction concern it was protecting against routes to the existing expiring-exception mechanism instead.
- **The indeterminate state is unproven against real input.** Terraform cannot always say whether a value will exist after apply, so the contract carries an explicit third state. It works in the prototype, and **no committed fixture in either repository produces it** — `after_unknown` is empty for every encryption field in `examples/terraform/`. Every test of it is hand-built. Relatedly, the current `cmek_at_rest` never consults `after_unknown` at all, which makes a genuinely computed key a false positive today, latent only for want of a fixture.
- **Differential equivalence testing rests on biased fixtures.** Each repository's fixtures were written to match its own implementation, so they lean toward agreement. Adversarial per-twin fixtures were considered and not adopted, so this is an accepted risk rather than a closed one. The v1 history is the reason it matters.
- **Deployment questions entered scope earlier than intended.** `cloudbuild.yaml`, the evidence store, and the enrichment function are all settled here, in a design whose fixtures-now decision existed partly to defer them. The tension is real and accepted.
- **The two repositories pin different OPA versions, and a merged engine can only have one.** This repository's CI pins `1.0.0`; `regcheck` pins `0.68.0` in its workflow and in four `cloudbuild.yaml` steps. This ADR does not choose between them — it is a migration prerequisite rather than an architectural decision, and it is named here so it is not discovered during a merge.

  Measured rather than assumed, and the answer is cheap: both suites were run under both versions and all four combinations pass — this repository 163/163 under 0.68.0 and under 1.0.0, `regcheck` 34/34 under both. All 30 policy files across the two repositories already use `import rego.v1`, the syntax OPA 1.0 made the default. **Standardise on 1.0.0**, which this repository's CI already pins.

### What this forecloses

- **A non-GCP detective rail.** Adding AWS or Azure detection later means either a second inventory source with its own normaliser, or preventive-only controls sitting in a set that advertises two rails. Both are reversible; neither is cheap.
- **Controls that read Security Command Center findings.** See below — the input side of SCC is closed by this decision, not merely unbuilt.
- **Per-deployment policy tuning by editing shared constants.** With one shared `sensitive_ports`, a deployment that needs different ports uses the exception mechanism. Parameterised profiles were considered and rejected as a second untested data file alongside the projection table.

## What would invalidate this decision

Observable signals, not "if requirements change". Any one of these reopens the ADR.

| Trigger | Signal | What it would change |
| --- | --- | --- |
| The projection table proves untestable in practice | A projection error reaches `main` undetected by CI — that is, a control's verdict changes with no test failing | The largest accepted cost turns out to be unmitigable. Normalisation moves back toward Rego, or controls go back to naming field paths. |
| Differential evaluation misses a real defect | Any twin merges green under differential evaluation and a false negative in that control is found afterwards | The proof method is insufficient. Adversarial per-twin fixtures — considered and not adopted here — become mandatory. |
| The first merge disagrees unexpectedly | `open_firewall` ≡ `req_1_network_controls` surfaces any disagreement beyond the five known `sensitive_ports` values (2379, 2380, 6443, 9200, 9300) | The method has found something unmodelled. Merging stops until it is explained. |
| A second cloud becomes in scope | A workload targets AWS or Azure and needs the same controls | GCP-only is the wrong boundary. Either a second inventory source and normaliser, or controls that advertise two rails and have one. |
| Cloud Asset Inventory stops being sufficient | An asset type this control set needs is absent from CAI, or the required content type is unavailable | The detective rail's single source assumption fails and a second reader is needed. |
| The exception mechanism cannot absorb the port widening | More than a handful of standing exceptions accumulate against the five restored ports | The superset was the wrong call and parameterised profiles — rejected here as a second untested data file — need revisiting. |

Every trigger above is conditional. None is dated, and none should be read as one.

The projection-table gap is instead handled by a **gate**, which is stronger than a deadline and needs no calendar:

> **No twin control may merge until the golden-normalised-document CI job exists and runs on every pull request.**

A deadline can pass unnoticed; a gate cannot be passed without someone deciding to remove it. This is the mechanism that stops "accepted knowingly" decaying into "forgotten", and it is written into the migration plan as a stage-0 prerequisite rather than left to memory.

The one genuinely time-bound item is review of this ADR itself: revisit on **2026-11-04**, three months from acceptance, whether or not any trigger has fired. If none has, that is worth recording too — an ADR nobody revisits is indistinguishable from one nobody follows.

## Alternatives Considered

**Security Command Center as a control input.** Rejected on the shape of the data rather than on preference. An SCC `Finding` carries a verdict, not configuration, and `sourceProperties` is publisher-defined with no schema a control could rely on. A control that consumed findings would be re-deriving someone else's conclusion. **The detective rail reads Cloud Asset Inventory; SCC is a publish sink.** Any statement that this engine evaluates SCC findings is wrong.

Republishing findings back to SCC as a custom source remains the only SCC integration in the design. It is named in the seam and deliberately not built while evaluation is fixture-based — a documented absence in the same register as BankVault's missing revoke path, not an oversight.

**Joining Cloud Asset Inventory to SCC on resource name.** Rejected as unsound. A resource has multiple legal full names; the service host in a Cloud Asset Inventory name does not always match its own `assetType`; buckets carry `projects/_` rather than a project segment; and `resourceName` on a finding is free text. The committed fixtures join cleanly only because one author wrote both sides. The existing implementation joins by raw string equality and **degrades silently to a default owner on a miss** — a wrong answer rather than an error. That behaviour is not carried forward; the enrichment function is adopted as the normaliser on the explicit condition that the join raises or records an unresolved miss.

**Normalising inside OPA.** Rejected because `opa eval` accepts one document and real exports are sharded NDJSON.

**Retiring `vpc_sc_perimeter` with the rest of `regcheck`'s policy layer.** Rejected — it already carries a written PCI DSS 1.2.1/1.3.1 justification alongside its FFIEC one, so it was never FFIEC-specific. It joins the shared set, decomposed by property. Its second rule, which catches a perimeter configured in dry-run mode with no enforcing block, has no counterpart here and is the sharper of the two: a perimeter that enforces nothing reads as covered on a coverage report.

**Adopting FFIEC citations as a straight port.** Rejected. `regcheck` bakes its citations into the deny message strings themselves, which is detection and citation in one file — the arrangement the v1→v2 extraction removed. FFIEC becomes a fourth citation package only after those citations are lifted out into their own layer. Porting as-is would make "frameworks cite, never detect" false on the day it shipped.

**The FFIEC Appendix J citations do not hold, and the extraction step corrects them rather than porting them.** `regcheck` cites "FFIEC IT Examination Handbook, Business Continuity Management booklet, Appendix J" for bucket public-access prevention and for network segmentation.

Sourcing is separated below by strength, because a claim about a regulation made from a secondary summary would be the same defect this section is describing.

**Established from a primary source.** OCC Bulletin 2019-57 states verbatim that the revised booklet "replaces the 'Business Continuity Planning' booklet issued in February 2015" and "rescinds OCC Bulletin 2015-9, 'FFIEC Information Technology Examination Handbook: Strengthening the Resilience of Outsourced Technology Services, New Appendix for Business Continuity Planning Booklet.'"

Two things follow directly. Appendix J is titled *Strengthening the Resilience of Outsourced Technology Services* and concerns third-party and technology-service-provider resilience — a subject that does not reach bucket access controls or network segmentation. And it was an appendix to the Business Continuity **Planning** booklet, not the Business Continuity **Management** booklet that `regcheck` names.

**Reported by industry summaries, not yet confirmed primary.** The 2015 Planning booklet carried ten appendices, A through J; the 2019 Management booklet carries four, with the content of Appendices C through J folded into the body of the booklet rather than retained as appendices. If that holds, the current Management booklet has no Appendix J at all, and the citation names a document section that does not exist.

**Not verified.** The full text of Appendix J. Both `ffiec.gov` and `ithandbook.ffiec.gov` returned HTTP 403 to automated retrieval on 2026-08-04, so the appendix body and the current booklet's appendix list were not read directly. Confirming them requires opening the handbook by hand.

The subject-matter mismatch rests on the primary source and is enough on its own: an appendix about outsourcing resilience does not support a control about public bucket access. The missing-appendix claim is the stronger finding and the weaker citation, so the migration step re-checks it against the handbook before acting.

This is recorded here rather than quietly fixed because it is the failure mode this decision exists to prevent, found in the repository being merged in. A control that fires correctly while citing a regulation that does not say what the citation implies is not a compliance control — it is a lint rule with a footnote. It also argues for the topology: citations living inside `sprintf` strings are citations nobody reviews.
