# Compliance as Code

Stop treating compliance like a document. Start treating it like production software.

Most cloud architects are still stuck managing compliance with giant, outdated spreadsheets — mapping every Terraform resource to PCI DSS, SOC 2, and NIST 800-53 controls for yet another quarterly sign-off. The dirty secret? That spreadsheet is just a statement of intent. It tells you nothing about what actually shipped to production last Tuesday.

This repo is my attempt to fix that gap. Instead of relying on plausible deniability and manual checklists, I'm using Policy-as-Code with OPA (Open Policy Agent). Every Terraform change gets scanned before a single resource hits the cloud. If it violates a security or compliance rule, the PR is blocked.

## The Core Idea

The real question is: Can we turn a regulatory requirement into an automated, repeatable, provable check that runs on every pull request? That's what this project is built around.

## It's a Program, Not Just Policies

This isn't just a pile of Rego files. It's meant to be a real engineering program with the same standards we apply to infrastructure:

- **Traceability:** `docs/controls-mapping.md` links specific regulatory citations to the actual policy rules. No more wondering which control covers what, and no duplicated effort across frameworks — each check is implemented **once** in `policies/controls/`, and the framework packages attach citations to it.
- **Discipline:** The policies are version-controlled, unit tested (163 policy tests — 45 control, 13 exception, 105 framework — green in CI), and enforced in CI — just like the rest of our code.
- **Honesty:** Scope limitations are documented, with a number attached. Five of PCI DSS v4.0's twelve requirements are partially automated and none is fully automated — [`CONTROL_COVERAGE.md`](CONTROL_COVERAGE.md) goes requirement by requirement. These policies catch what they catch; they don't replace a QSA.
- **A way out that expires:** approved risk acceptances live in [`exceptions/registry.yaml`](exceptions/registry.yaml), scoped to one resource and one control, with a mandatory expiry and no renewal-in-place.

## Repository Layout

```text
compliance-as-code/
├── policies/
│   ├── lib/utils.rego        # Shared constants (primitive roles, sensitive ports, etc.)
│   ├── lib/exceptions.rego   # Exception lookup — fails closed if the registry is absent
│   ├── exception_report.rego # Prints active exceptions in the gate output
│   ├── controls/             # THE DETECTION LOGIC — one file per control, no deny rules
│   ├── pci_dss/              # req_1 network, req_2 defaults, req_6 encryption, req_7 access, req_10 logging
│   ├── soc2/                 # cc6 logical access, cc7 system operations
│   └── nist_800_53/          # ac access control, au audit logging, sc comms protection
├── tests/
│   ├── controls/             # Detection logic — deny path + allow path for every control
│   ├── pci_dss/              # Citation tests + framework-local rules
│   ├── soc2/
│   ├── nist_800_53/
│   └── fixtures/
│       ├── compliant.tfplan.json     # Should produce 0 violations
│       └── noncompliant.tfplan.json  # Should trigger violations across all frameworks
├── terraform/
│   ├── compliant/            # Reference-compliant GCP infrastructure
│   └── noncompliant/         # Deliberately violating config (for CI validation only)
├── exceptions/
│   ├── registry.yaml         # Risk acceptances. Every entry expires.
│   └── validate.rego         # Validates the registry (kept out of policies/ on purpose)
├── docs/
│   ├── controls-mapping.md   # Requirement → policy rule citation table
│   └── GOVERNANCE.md         # Exception process, and what it does not do
├── scripts/
│   └── check-plan.sh         # Local evaluation script
└── .github/workflows/
    ├── opa-tests.yml              # Unit tests (no GCP credentials needed)
    └── policy-check.yml           # Fixture + example compliance checks (no GCP credentials needed)
```

## Try It Yourself (No Cloud Credentials Needed)

Pre-baked Terraform plan fixtures are committed so you can run policy checks locally without GCP access.

```bash
# Run all unit tests. tests/controls/ MUST be listed — omitting it skips 45 tests
# and the suite still reports green.
opa test policies/ tests/controls/ tests/pci_dss/ tests/soc2/ tests/nist_800_53/ -v

# Check the deliberately noncompliant fixture — should print violations
./scripts/check-plan.sh tests/fixtures/noncompliant.tfplan.json

# Check the compliant fixture — should pass clean
./scripts/check-plan.sh tests/fixtures/compliant.tfplan.json

# Evaluate one framework directly
opa eval -d policies/ -i tests/fixtures/noncompliant.tfplan.json \
  '[m | m := data.pci_dss[_].deny[_]]'
```

## OPA Version

Requires **OPA v1.0+**. Every policy file uses `import rego.v1` — verified across all policy files, with no `import future.keywords` remaining. CI installs OPA v1.0.0 and Conftest v0.55.0.

```bash
# Install (Linux)
curl -fsSL -o /usr/local/bin/opa \
  https://github.com/open-policy-agent/opa/releases/download/v1.0.0/opa_linux_amd64_static
chmod +x /usr/local/bin/opa

# Install (macOS)
brew install opa
```

## Framework Coverage

| Framework | Requirements Enforced |
|---|---|
| PCI DSS v4.0 | 1.3.2, 2.2.1, 6.3.5, 6.5.3, 7.2.5, 7.2.6, 10.2.1, 10.3.2 |
| SOC2 TSC (2017) | CC6.1, CC6.3, CC6.6, CC6.7, CC7.1, CC7.2, CC8.1 |
| NIST SP 800-53 Rev 5 | AC-3, AC-6, AC-17, AU-2, AU-9, AU-12, SC-8, SC-28 |

Full citation table with per-rule breakdown: [`docs/controls-mapping.md`](docs/controls-mapping.md)

That table is the numerator. For the denominator — which requirements are *not* covered, which are unaddressable from a Terraform plan at all, and which are simply not built yet — see [`CONTROL_COVERAGE.md`](CONTROL_COVERAGE.md). Five of PCI DSS's twelve requirements are partially automated; none is fully automated, and the document says so requirement by requirement.

## CI

Two GitHub Actions workflows trigger on every push or PR touching policies or Terraform:

| Workflow | What it checks | Credentials needed |
|---|---|---|
| `opa-tests.yml` | All 163 OPA unit tests pass (controls 45, exceptions 13, PCI DSS 60, SOC 2 23, NIST 800-53 22); `opa check --strict` syntax validation | None |
| `policy-check.yml` | Noncompliant fixture and example trigger ≥1 violation; compliant fixture and example produce 0 violations | None |

`policy-check.yml` is a six-job pipeline with `opa-unit-tests` as the gate — it runs the unit tests and `opa check --strict`. The other five jobs run only after it passes (`needs: opa-unit-tests`):

- `exception-registry-valid` — the exception registry parses, every `control_id` resolves, dates are well-formed, `exception_id`s are unique, and expired entries are reported
- `conftest-noncompliant-must-fail` — conftest must reject `examples/terraform/noncompliant/plan.json`
- `conftest-compliant-must-pass` — conftest must accept `examples/terraform/compliant/plan.json`
- `opa-eval-noncompliant-must-fail` — `opa eval` must find ≥1 violation in `tests/fixtures/noncompliant.tfplan.json`
- `opa-eval-compliant-must-pass` — `opa eval` must find 0 violations in `tests/fixtures/compliant.tfplan.json`

## What This Isn't

This gives you strong preventive compliance at deploy time, but it's not magic. It doesn't solve runtime drift, configuration changes made in the console, or replace a proper QSA/auditor sign-off. See [`CONTROL_COVERAGE.md`](CONTROL_COVERAGE.md) for what is covered, what is not, and what cannot be, and [`docs/controls-mapping.md`](docs/controls-mapping.md) for the citation trail on what is.

## Exceptions

A gate with no exception path is a gate people route around; one with an unbounded exception path is a spreadsheet with extra steps. [`exceptions/registry.yaml`](exceptions/registry.yaml) is the middle: one entry suppresses one control on one resource address, and **every entry expires**. An entry with no expiration date, or a past one, grants nothing — there is no permanent value and no renewal-in-place.

Active exceptions are printed by the gate as warnings naming the approver, expiry, and justification, so a suppressed finding never looks like a finding that did not fire. If the registry is not loaded, nothing is suppressed and every control enforces normally.

Process, and an honest list of what the mechanism does not do: [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

## Evolution

[`EVOLUTION.md`](EVOLUTION.md) records the three false negatives that were passing CI before the shared-control refactor — including a bucket with encryption explicitly set to `null` reading as compliant, because `null` is a defined value in Rego.
