# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

OPA (Open Policy Agent) policy-as-code library that enforces PCI DSS v4.0, SOC2 TSC (2017), and NIST SP 800-53 Rev 5 controls against GCP Terraform plans at deploy time. Targets the `hashicorp/google` provider v5.x.

## Commands

```bash
# Run all OPA unit tests — exclude tests/fixtures/ to avoid OPA JSON merge conflict
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

## Architecture

```
policies/
  lib/utils.rego          — Shared constants: primitive_roles, public_members, sensitive_ports
  pci_dss/                — One file per PCI DSS requirement
  soc2/                   — One file per SOC2 criteria cluster (CC6, CC7)
  nist_800_53/            — One file per NIST control family (AC, AU, SC)
tests/
  pci_dss/ soc2/ nist_800_53/ — Mirror of policies/; each file has deny + allow test cases
  fixtures/               — Pre-generated plan JSON; used by CI without needing GCP auth
    compliant.tfplan.json     — Should produce 0 violations
    noncompliant.tfplan.json  — Should produce violations across all frameworks
terraform/
  compliant/main.tf       — Reference compliant GCP config (showcase)
  noncompliant/main.tf    — Deliberately violating config (CI validation only)
.github/workflows/
  opa-tests.yml           — OPA unit tests; no GCP credentials needed
  terraform-policy-check.yml — Fixture-based policy eval; no GCP credentials needed
docs/controls-mapping.md  — Exact citation of each framework requirement to each policy rule
```

## OPA Policy Conventions

- All files use `import rego.v1` (OPA v1.0+ syntax; no `import future.keywords` needed)
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
