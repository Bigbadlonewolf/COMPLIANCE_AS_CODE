# CLAUDE.md

> **Scope.** This folder owns OPA/Conftest policy enforcement for PCI DSS, SOC 2, and NIST 800-53 against GCP Terraform plans.
> If the prompt is about anything else, return to the workspace router `ROUTER.md` § Task Routing and route from there. Do not search sideways through the workspace — `node_modules/` at the workspace root and in two projects makes a recursive scan time out.
> `pickup` and `handoff` are defined once in the workspace `AGENTS.md` §4–§5.
>
> Paths above are workspace files that sit outside this repository. If you are reading this in a standalone clone, they will not be present — everything needed to work on this repo is in this file.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

OPA (Open Policy Agent) policy-as-code library that enforces PCI DSS v4.0, SOC2 TSC (2017), and NIST SP 800-53 Rev 5 controls against GCP Terraform plans at deploy time. Targets the `hashicorp/google` provider v5.x.

Remote: `Bigbadlonewolf/COMPLIANCE_AS_CODE` (public).

## Commands

```bash
# Run all OPA unit tests — 116/116 PASS (verified 2026-07-26)
# Subdirectories MUST be enumerated. Passing `tests/` loads tests/fixtures/*.json
# as OPA data and fails with a JSON merge conflict.
opa test policies/ tests/pci_dss/ tests/soc2/ tests/nist_800_53/ -v

# Run a single test package
opa test policies/ tests/pci_dss/req_1_test.rego -v

# Lint/parse check all policies
opa check policies/ --strict

# Evaluate a plan JSON against all policies
./scripts/check-plan.sh tests/fixtures/noncompliant.tfplan.json

# Evaluate one framework only
opa eval -d policies/ -i tests/fixtures/noncompliant.tfplan.json \
  '[m | m := data.pci_dss[_].deny[_]]'

# Generate a plan JSON from Terraform (requires GCP auth)
cd terraform/compliant
terraform init -backend=false
terraform plan -var="project_id=myproject" -var="kms_key_id=fake" -out=tfplan.binary
terraform show -json tfplan.binary > plan.json
```

A Windows `opa.exe` may be present in the project root for local runs. It is **gitignored, not committed** — CI installs OPA `1.0.0` and Conftest `0.55.0` from upstream releases.

## Architecture

```
policies/
  lib/utils.rego          — Shared constants: primitive_roles, public_members, sensitive_ports
  pci_dss/                — One file per PCI DSS requirement
  soc2/                   — One file per SOC2 criteria cluster (CC6, CC7)
  nist_800_53/            — One file per NIST control family (AC, AU, SC)
tests/
  pci_dss/ soc2/ nist_800_53/ — Mirror of policies/; each file has deny + allow test cases
  fixtures/               — Pre-generated plan JSON. NOT a test directory; see Commands.
    compliant.tfplan.json     — Should produce 0 violations
    noncompliant.tfplan.json  — Should produce violations across all frameworks
examples/terraform/       — main.tf + versions.tf + COMMITTED plan.json
  compliant/ noncompliant/
terraform/                — Bare HCL only, no plan JSON
  compliant/main.tf       — Reference compliant GCP config (showcase)
  noncompliant/main.tf    — Deliberately violating config
.github/workflows/
  opa-tests.yml           — 1 job: OPA unit tests on policy/test file changes
  policy-check.yml        — 5-job gate; triggers on PR and push to main
docs/
  architecture.md         — Design and data flow
  controls-mapping.md     — Exact citation of each framework requirement to each policy rule
  audit-log.md            — Review record: what each audit pass found and fixed
```

### Three fixture sets — not interchangeable

This is the single easiest thing to get wrong here. There are three directories of Terraform, and each CI job reads exactly one of them:

| Directory | Contains | Consumed by |
| --- | --- | --- |
| `tests/fixtures/` | plan JSON only | the two `opa eval` jobs in `policy-check.yml` |
| `examples/terraform/{compliant,noncompliant}/` | `main.tf` + **committed `plan.json`** | the two Conftest jobs in `policy-check.yml` |
| `terraform/{compliant,noncompliant}/` | bare HCL, no plan JSON | `scripts/check-plan.sh` is documented against this; needs a `terraform plan` first |

Editing `terraform/` does **not** change what CI evaluates. The Conftest jobs read `examples/terraform/`, and its `plan.json` is committed — regenerate and commit it, or the policy change will not be exercised.

### CI jobs (`policy-check.yml`)

1. `opa-unit-tests` — unit tests + `opa check --strict`
2. `conftest-noncompliant-must-fail` — Conftest must REJECT `examples/terraform/noncompliant/`
3. `conftest-compliant-must-pass` — Conftest must ACCEPT `examples/terraform/compliant/`
4. `opa-eval-noncompliant-must-fail` — must detect violations in `tests/fixtures/noncompliant.tfplan.json`
5. `opa-eval-compliant-must-pass` — must find zero violations in `tests/fixtures/compliant.tfplan.json`

Jobs 2 and 3 are inverted assertions: a *passing* build requires the noncompliant example to be *rejected*. A policy that stops firing turns job 2 red, not green.

## OPA Policy Conventions

- All files use `import rego.v1` (OPA v1.0+ syntax; no `import future.keywords` needed) — verified across all 16 policy files
- Deny rules are partial sets: `deny contains msg if { ... }`
- Only fires on `"create"` or `"update"` actions — destroy-only changes are ignored
- `input` shape is Terraform plan JSON from `terraform show -json` (`input.resource_changes[_].change.after`)
- Helpers that check nested blocks (e.g. `has_pgaudit_enabled`) are defined at the bottom of each policy file
- `lib/utils.rego` exports shared sets (`primitive_roles`, `public_members`, `sensitive_ports`) and `one_year_seconds`

## Test Conventions

- Test package: `pci_dss.req_1_test` tests `data.pci_dss.req_1`
- Every test file has both deny-path tests (bad config → violation) and allow-path tests (good config → no violation)
- Use `with input as { "resource_changes": [...] }` to inject minimal fixture data
- Filter specific violations: `[v | v := deny[_]; contains(v, "keyword")]`
- Current count: 116 tests — PCI DSS 66, SOC 2 26, NIST 800-53 24

## Key Schema Notes (google provider v5.x)

- `google_sql_database_instance.settings` is an array block — access as `settings[_]`
- `ssl_mode` values: `"ENCRYPTED_ONLY"` (required), `"ALLOW_UNENCRYPTED_AND_ENCRYPTED"`, `"TRUSTED_CLIENT_CERTIFICATE_REQUIRED"`
- `encryption_key_name` is `null` when CMEK not set (not an empty string)
- `google_kms_crypto_key.rotation_period` is a string with `s` suffix: `"7776000s"` — use `to_number(trim_suffix(period, "s"))` for numeric comparison
- `google_storage_bucket.encryption` is an array block — empty `[]` when not set
- `google_storage_bucket.public_access_prevention`: `"enforced"` or `"inherited"` (default)

## OPA Gotcha: Null Field Checks

In OPA, `null` is a defined value — `not r.change.after.field` fails when `field = null` because the expression succeeds (produces `null`). Use explicit equality instead:

- `r.change.after.encryption_key_name == null` (not `not r.change.after.encryption_key_name`)
- `r.change.after.rotation_period == null` (not `not r.change.after.rotation_period`)
- `r.change.after.rotation_period != null` (for the "exists" check before parsing)

## Adding or Changing a Policy

1. Write the rule in `policies/<framework>/`, mirroring existing file naming.
2. Add both deny-path and allow-path tests in `tests/<framework>/`.
3. Add the control citation to `docs/controls-mapping.md` — the citation must match a real requirement in PCI DSS v4.0 / SOC 2 TSC / NIST 800-53 Rev 5.
4. If the rule should be caught by Conftest, update `examples/terraform/noncompliant/main.tf` **and regenerate its committed `plan.json`**.
5. Run the full test command above before committing.

Never weaken or delete a policy to make a build pass without updating `docs/controls-mapping.md` and the corresponding tests.
