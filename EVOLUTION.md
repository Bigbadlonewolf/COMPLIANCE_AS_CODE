# Evolution

Where this repo has been, what broke, and what changed as a result. Kept because the interesting part of a policy repo is not the rules it has now — it is the false negatives it shipped and how they were found.

---

## v3 — Exception workflow (2026-07-28)

**Status:** current

Added a risk-acceptance path. Until now a failing policy hard-blocked the build with no mechanism for an approved exception, which is a defensible position right up to the first legitimate case, after which it becomes a reason to delete the rule.

**What changed**

- `exceptions/registry.yaml` — the registry. Entries key on `resource_address` + `control_id` and carry a mandatory `expiration_date`.
- `policies/lib/exceptions.rego` — the lookup. `granted(address, control_id)` is a partial function, so an absent registry makes it undefined and every control denies as normal.
- All six controls in `policies/controls/` consult it.
- `policies/exception_report.rego` — a `warn` rule printing every active exception that touches a resource in the plan, so a suppressed finding is visible in the gate output.
- `exceptions/validate.rego` + a `exception-registry-valid` CI job — validates shape, `control_id` membership, date formats, `exception_id` uniqueness, and reports already-expired entries.
- `docs/GOVERNANCE.md` — the process, and an explicit list of what the mechanism does not do.
- 13 new tests. Suite: **150 → 163**.

**Design position: expiry is the mechanism.** An entry with no `expiration_date`, or a past one, grants nothing. There is no renewal — extending means a new `exception_id` and a fresh justification, because editing a date in place turns an expiry into a formality and the whole point is that lapsing is the default.

**What this deliberately does not do:** `approved_by` is a string in a YAML file. In a single-operator repo it records intent, not evidence — the real approval record is the PR review. Framework-local checks (AWS/Azure encryption, secret-shaped env vars, network segmentation) have no `control_id` and cannot be excepted at all. Both stated in GOVERNANCE.md rather than implied away.

**Also in this version**

- `CONTROL_COVERAGE.md` — the denominator `docs/controls-mapping.md` never stated. Five of twelve PCI DSS requirements partially automated, two addressable but unbuilt, five not addressable from a Terraform plan at all. Eight NIST controls of roughly 320 in the FedRAMP Moderate baseline.
- Fixed this repo's own `CLAUDE.md`, whose documented `opa test` command omitted `tests/controls/` — 45 of 150 tests never ran locally, while CI ran all of them. A doc bug that made local runs quietly weaker than the gate.

---

## v2 — Shared control layer (before 2026-07-26)

**Status:** superseded by v3, still the architecture

Three framework packages had each implemented the same checks independently. Merging them into `policies/controls/` — one file per control, framework packages attaching only citations — surfaced **three false negatives that had been passing CI**, each one a case where two implementations agreed and a third quietly did not.

### What broke: CMEK read `null` as "present"

`pci_dss/req_6` tested bucket CMEK with a bare truthiness check on `default_kms_key_name`. In Rego, `null` is a *defined* value, so a plan carrying an explicit `default_kms_key_name = null` satisfied the reference and read as compliant. `soc2/cc6` and `nist_800_53/sc` used `!= null` and caught it.

A bucket with encryption explicitly disabled passed the PCI check.

**Fixed by** making the explicit comparison canonical, and applying the same reasoning to Cloud SQL's `encryption_key_name`, which additionally has to handle the field being absent rather than null.

**Prevention:** `tests/controls/cmek_at_rest_test.rego` opens with a REGRESSION comment naming this bug, and asserts the explicit-null, empty-string, absent-block, and empty-array cases separately.

### What broke: absent blocks were not findings

`soc2/cc7` bound `backup_configuration[_]` before testing `enabled`, so a Cloud SQL instance with **no** `backup_configuration` block at all produced no finding. Having no backups is the same violation whether stated explicitly or achieved by omission.

`tls_in_transit` had the identical shape: `soc2/cc6` and `nist_800_53/sc` both bound `ip_configuration[_]` before testing `ssl_mode`, so an instance with no `ip_configuration` block passed. GCP does not enforce TLS unless told to, so an absent block is exactly as non-compliant as an explicit wrong value.

In both cases only the PCI implementation handled it, via a negated helper.

**Fixed by** making the negated-helper form canonical across all three frameworks.

**Prevention:** every control test asserts the absent-block case explicitly, not just the wrong-value case. The general lesson is written into `CLAUDE.md` § OPA Gotchas: absent, explicitly-null, and present-with-value are three states, and Rego treats them differently.

### The pattern behind all three

Every one was a rule that returned an empty set when it should have fired. Empty sets are indistinguishable from compliance in a green build — which is why `policy-check.yml` gates on `conftest-noncompliant-must-fail`, a job whose entire purpose is to fail the build if a deliberately broken plan produces no violations.

---

## v1 — Three parallel implementations

**Status:** deprecated

PCI DSS, SOC 2, and NIST 800-53 each got their own policy package, each implementing its own detection logic.

**What worked:** each framework's rules read cleanly on their own, and adding a framework did not risk breaking the others.

**What broke:** the same check existed three times with three subtly different behaviours, and nothing forced them to agree. Two could be right and one wrong indefinitely, with the suite green throughout. Every false negative in v2's list was already present here — the merge is what exposed them.

**What it cost to learn:** the merge, plus writing deny-and-allow tests per control from scratch.

---

## Unresolved

- **Five policy files carry checks with no citation trail.** `access_control`, `encryption_at_rest`, `network_segmentation`, `logging_monitoring`, `least_privilege`. They pass tests and run in CI; they are absent from `docs/controls-mapping.md` and `CONTROL_COVERAGE.md`.
- **Plan-time only.** These policies read `terraform show -json` output. A change made directly in the GCP console afterwards is invisible. Drift detection against live state is not built.
- **No exception expiry notification.** CI reports already-expired entries on every run, so you learn at the next build rather than in advance. An expired exception has already stopped suppressing anything by then, so the report is hygiene rather than an alert — but it does mean nothing warns you before an exception lapses.
- **`approved_by` is unverified.** Any string is accepted. Checking it against a group the requester cannot edit is the difference between a record and evidence.
