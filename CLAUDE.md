# CLAUDE.md

> **Scope.** This folder owns OPA/Conftest policy enforcement for PCI DSS v4.0, SOC 2 TSC (2017), and NIST SP 800-53 Rev 5 against GCP Terraform.
>
> If the prompt is about anything else, return to the root router [`CONTEXT.md`](../../CONTEXT.md) § Task Routing Table and route from there. Do not search sideways through the workspace — recursive scans across `node_modules/` at the root and in sibling projects will time out.
>
> **Session continuity:** `pickup` = resume a previous session by reading the root `CLAUDE.md` § Session Continuity. `handoff` = write a `.handoff` file with current state for the next session.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Prerequisites

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| OPA | ≥ 1.0 | `import rego.v1` syntax; unit test runner |
| Terraform | ≥ 1.5 | Plan generation for fixture updates |
| Conftest | ≥ 0.50 | CI gating against raw `.tfplan` files |
| `jq` | any | Plan JSON inspection |

---

## Quick Reference: OPA vs. Conftest

| Task | Tool | Command |
|------|------|---------|
| Unit-test a policy rule | OPA | `opa test policies/ tests/controls/ tests/pci_dss/ -v` |
| Gate a PR against a Terraform plan | Conftest | `conftest test tfplan.json -p policies/ --data exceptions/registry.yaml` |
| Lint all Rego | OPA | `opa check policies/ --strict` |
| Debug why a rule fired / didn't fire | OPA | `opa test ... --verbose --explain full` |
| Evaluate a fixture against one framework | OPA | `opa eval -d policies/ -i fixture.json 'data.pci_dss[_].deny[_]'` |

**Rule of thumb:** OPA for development and unit tests; Conftest for CI/CD gating. Do not mix them in the same command.

---

## Commands

```bash
# Run all OPA unit tests
# WRONG: `opa test . -v` silently loads fixtures/ as data bundles, causing path collisions.
# ALSO WRONG: omitting tests/controls/ — it skips 45 of 163 tests and still reports green.
opa test policies/ tests/controls/ tests/pci_dss/ tests/soc2/ tests/nist_800_53/ -v

# Validate the exception registry (relative path is required — see below)
opa eval -d exceptions/ 'data.exceptions_validate.errors'

# Run the gate the way CI does, with the registry loaded
conftest test examples/terraform/noncompliant/plan.json --policy policies --data exceptions/registry.yaml --all-namespaces

# Lint / parse check all policies
opa check policies/ --strict

# Evaluate a plan JSON against all policies
./scripts/check-plan.sh tests/fixtures/noncompliant.tfplan.json

# Evaluate one framework only
opa eval -d policies/ -i tests/fixtures/noncompliant.tfplan.json \
  '[m | m := data.pci_dss[_].deny[_]]'

# Reproduce CI locally
act -j opa-tests
act -j conftest-gate
```

---

## Architecture

```text
policies/
  controls/               — THE DETECTION LOGIC. One file per control, no deny rules.
                            Framework packages import these and attach citations.
                            Each exposes a `control_id` used by the exception registry.
  lib/utils.rego          — Shared constants: primitive_roles, public_members, sensitive_ports
  lib/exceptions.rego     — Exception lookup. Partial function, so an absent
                            registry means every control denies as normal.
  exception_report.rego   — `warn` rule printing active exceptions in the gate output
  pci_dss/                — Citations + framework-local checks (req_1, req_2, req_6, req_7, req_10)
  soc2/                   — CC6, CC7, logging_monitoring
  nist_800_53/            — AC, AU, SC, least_privilege
exceptions/
  registry.yaml           — Risk acceptances. Loads at `data.exceptions` (NOT
                            data.exceptions.registry — OPA merges a data file at
                            the root of the path it is given). Relative path only.
  validate.rego           — Validates the registry. Deliberately outside policies/
                            so conftest does not evaluate it against plans.
tests/
  controls/               — Deny path + allow path for every control, plus the
                            exception mechanism's own tests
  pci_dss/ soc2/ nist_800_53/ — Citation tests + framework-local rules
  fixtures/               — Pre-generated plan JSON; used by CI without GCP auth
terraform/                — NOT what CI evaluates. See examples/ below.
examples/terraform/
  compliant/plan.json     — Conftest must ACCEPT this
  noncompliant/plan.json  — Conftest must REJECT this
.github/workflows/
  opa-tests.yml           — Unit tests
  policy-check.yml        — The gate. Five jobs, all `needs: opa-unit-tests`:
                            exception-registry-valid, conftest-{noncompliant,compliant},
                            opa-eval-{noncompliant,compliant}
docs/
  controls-mapping.md     — Which framework requirement each rule satisfies
  GOVERNANCE.md           — Exception process, and what it deliberately does not do
CONTROL_COVERAGE.md       — What is NOT covered, and why
```

**Three separate Terraform fixture sets exist** (`tests/fixtures/`, `examples/terraform/`, `terraform/`) and each CI job reads exactly one. `terraform/` is not what the gate evaluates — editing it to make a policy change pass produces a green CI that never exercised the change.

---

## Baseline Numbers

**These are the canonical counts. Any deviation means something is broken.**

Run this and paste the output before claiming any rule change is correct:

```bash
opa test policies/ tests/controls/ tests/pci_dss/ tests/soc2/ tests/nist_800_53/ -v
```

| Metric | Expected | Last Verified |
|--------|----------|---------------|
| Total tests passing | **163** (45 control + 13 exception + 105 framework) | 2026-07-28 |
| PCI DSS violations (noncompliant fixture) | **18** | 2026-07-28 |
| SOC 2 violations (noncompliant fixture) | **12** | 2026-07-28 |
| NIST 800-53 violations (noncompliant fixture) | **14** | 2026-07-28 |
| Compliant fixture violations | **0** (all three frameworks) | 2026-07-28 |
| Conftest, noncompliant example | **19 failures, 56 tests** | 2026-07-28 |
| Conftest, compliant example | **0 failures, 56 tests** | 2026-07-28 |

Conftest counts differ from the OPA eval counts because conftest evaluates `examples/terraform/`, not `tests/fixtures/` — two different plan sets. Comparing them to each other is a mistake; compare each to its own row.

**To re-verify:** run the commands below and paste the raw terminal output. Do not estimate.

```bash
# Total test count
opa test policies/ tests/controls/ tests/pci_dss/ tests/soc2/ tests/nist_800_53/ -v | tail -5

# Violation counts per framework on noncompliant fixture
opa eval -d policies/ -i tests/fixtures/noncompliant.tfplan.json 'count([m | m := data.pci_dss[_].deny[_]])'
opa eval -d policies/ -i tests/fixtures/noncompliant.tfplan.json 'count([m | m := data.soc2[_].deny[_]])'
opa eval -d policies/ -i tests/fixtures/noncompliant.tfplan.json 'count([m | m := data.nist_800_53[_].deny[_]])'

# Compliant fixture must be zero
opa eval -d policies/ -i tests/fixtures/compliant.tfplan.json 'count([m | m := data.pci_dss[_].deny[_]])'
opa eval -d policies/ -i tests/fixtures/compliant.tfplan.json 'count([m | m := data.soc2[_].deny[_]])'
opa eval -d policies/ -i tests/fixtures/compliant.tfplan.json 'count([m | m := data.nist_800_53[_].deny[_]])'
```

---

## Hard Verification Rule

**No claim that a rule "works," "passes," or "is correct" is accepted without pasted terminal output.**

Before any commit, PR, or handoff, you must:

1. Run `opa test policies/ tests/controls/ tests/pci_dss/ tests/soc2/ tests/nist_800_53/ -v`
2. Run `opa check policies/ --strict`
3. Paste the **full terminal output** into the session.
4. Compare against the Baseline Numbers table above.
5. If counts changed, explain why before proceeding.

**This applies to:** new controls, modified rules, fixture updates, refactors, and dependency bumps. No exceptions.

---

## OPA Policy Conventions

- All files use `import rego.v1` (OPA v1.0+ syntax; no `import future.keywords` needed).
- Deny rules are partial sets: `deny contains msg if { ... }`.
- Only fires on `"create"` or `"update"` actions — destroy-only changes are ignored.
- `input` shape is Terraform plan JSON from `terraform show -json` (`input.resource_changes[_].change.after`).
- Helpers that check nested blocks (e.g., `has_pgaudit_enabled`) are defined at the bottom of each policy file.
- `lib/utils.rego` exports shared sets (`primitive_roles`, `public_members`, `sensitive_ports`) and `one_year_seconds`.

---

## Test Conventions

- Test package: `pci_dss.req_1_test` tests `data.pci_dss.req_1`.
- Every test file has both deny-path tests (bad config → violation) and allow-path tests (good config → no violation).
- Use `with input as { "resource_changes": [...] }` to inject minimal fixture data.
- Filter specific violations: `[v | v := deny[_]; contains(v, "keyword")]`.

---

## Key Schema Notes (google provider v5.x)

- `google_sql_database_instance.settings` is an array block — access as `settings[_]`.
- `ssl_mode` values: `"ENCRYPTED_ONLY"` (required), `"ALLOW_UNENCRYPTED_AND_ENCRYPTED"`, `"TRUSTED_CLIENT_CERTIFICATE_REQUIRED"`.
- `encryption_key_name` is `null` when CMEK not set (not an empty string).
- `google_kms_crypto_key.rotation_period` is a string with `s` suffix: `"7776000s"` — use `to_number(trim_suffix(period, "s"))` for numeric comparison.
- `google_storage_bucket.encryption` is an array block — empty `[]` when not set.
- `google_storage_bucket.public_access_prevention`: `"enforced"` or `"inherited"` (default).

---

## OPA Gotchas: Null, Absent, and Undefined

In Terraform plan JSON, a field can be **absent**, **explicitly `null`**, or **present with a value**. OPA treats these three states differently. Dot-access on an absent key throws an eval error.

### The three states

```rego
# 1. ABSENT key — dot-access CRASHES
r.change.after.rotation_period        # ERROR if key missing

# 2. EXPLICITLY NULL — dot-access returns null (safe)
r.change.after.rotation_period == null  # true

# 3. PRESENT with value — dot-access returns value
r.change.after.rotation_period == "7776000s"  # true
```

### Safe patterns for optional fields

```rego
# Pattern A: object.get() — handles absent AND null
# Use this when the key may not exist in the plan JSON.
object.get(r.change.after, "encryption_key_name", null) == null

# Pattern B: explicit null check — use ONLY when the key is guaranteed to exist
# (e.g., the provider always emits it, even as null).
r.change.after.encryption_key_name == null

# Pattern C: "exists and is not null" — for mandatory-value checks
object.get(r.change.after, "rotation_period", null) != null
```

### Decision tree

```
Is the field always present in the provider's JSON output?
├── YES → Use direct dot-access: r.change.after.field == null
└── NO  → Use object.get(): object.get(r.change.after, "field", null) == null
```

**When in doubt, use `object.get()`.** It is slower to read but never crashes.

---

## Debugging a Failing Rule

### Step 1: Identify the exact test failure

```bash
opa test policies/ tests/controls/ tests/pci_dss/ -v --run TestReq1DenyPublicSql
```

### Step 2: Trace the rule evaluation

```bash
opa test policies/ tests/controls/ tests/pci_dss/ -v --explain full --run TestReq1DenyPublicSql
```

### Step 3: Inspect the raw input shape

```bash
# Extract the resource block from a fixture
jq '.resource_changes[] | select(.type == "google_sql_database_instance")' \
  tests/fixtures/noncompliant.tfplan.json
```

### Step 4: Run the rule against the fixture in isolation

```bash
opa eval -d policies/pci_dss/req_1.rego -i tests/fixtures/noncompliant.tfplan.json \
  'data.pci_dss.req_1.deny'
```

### Common failure modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `opa test` crashes with "eval_type_error" | Dot-access on absent key | Switch to `object.get()` |
| Rule returns empty set when it should fire | Action filter excludes `"no-op"` or `"read"` | Verify action is `"create"` or `"update"` |
| Conftest passes but OPA unit test fails | Conftest loads data differently (no `input` wrapper) | Check `input` shape in test vs. raw plan |
| Test expects violation, gets none | Fixture uses wrong provider version schema | Verify field names match v5.x schema notes above |
| Test expects no violation, gets one | Allow-path test missing a required field | Add the field to the mock `input` block |

---

## Adding a New Control

Use this checklist when adding a new PCI DSS requirement, SOC 2 criteria, or NIST control.

1. **Map the control** in `docs/controls-mapping.md` — cite the exact framework paragraph.
2. **Create the policy file** at `policies/<framework>/<control_id>.rego`.
   - Use `import rego.v1`.
   - Name the package `data.<framework>.<control_id>`.
   - Define `deny contains msg if { ... }`.
   - Add helper functions at the bottom of the file.
3. **Create the test file** at `tests/<framework>/<control_id>_test.rego`.
   - Package name: `<framework>.<control_id>_test`.
   - Minimum two tests: one deny-path, one allow-path.
   - Use `with input as { ... }` for fixtures.
4. **Update fixtures** (if the new control needs new resource types).
   - Add to `tests/fixtures/noncompliant.tfplan.json` for deny tests.
   - Add to `tests/fixtures/compliant.tfplan.json` for allow tests.
5. **Run the full test suite and paste output** (see Hard Verification Rule).
   - Verify total test count increased by exactly 2 (one deny, one allow).
   - Verify noncompliant fixture violation count increased by 1.
   - Verify compliant fixture still shows 0 violations.
6. **Update the CI orchestrator** (`policy-check.yml`) if the new control introduces a new job or dependency.
7. **Commit** with message format: `feat(policies): add <framework> <control_id> — <short description>`.

---

## Decision Trees for Common Tasks

### "A rule is firing on a resource it shouldn't"

```
1. Check the action filter — is it limited to "create" / "update"?
2. Check the resource type filter — is it too broad?
3. Check the null/absent handling — is an absent key being treated as a violation?
4. Inspect the fixture — does the mock input match real plan JSON shape?
```

### "I need to update a fixture after changing Terraform"

```
1. cd terraform/compliant or terraform/noncompliant
2. terraform plan -out=tfplan.binary
3. terraform show -json tfplan.binary > ../../tests/fixtures/<name>.tfplan.json
4. Run OPA tests to verify counts
5. If violation counts changed, update test assertions
```

### "CI passes locally but fails in GitHub Actions"

```
1. Check OPA version match: `opa version` locally vs. CI
2. Check Conftest version match
3. Verify fixture files are committed (not .gitignored)
4. Re-run `act -j <job_name>` to reproduce exactly
```
