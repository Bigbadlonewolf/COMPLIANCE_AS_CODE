# compliance-as-code

Policy-as-code enforcement of PCI DSS, SOC2, and NIST 800-53 controls against Terraform infrastructure, using OPA and Conftest.

The question this repo answers: can a compliance requirement be turned into an automated check that runs on every pull request, rather than a document someone reads once and forgets?

## Why this exists

A Security TPM's job is to translate compliance requirements into engineering work, define what "done" actually means for that work, and catch drift before an auditor does. That's what this repo shows, not just that I can write policy logic, but that I can run the full program around it: map the requirements, enforce them, verify the enforcement works, and keep an honest record of what's still open.

[`docs/controls-mapping.md`](docs/controls-mapping.md) is the requirements traceability document: which policy rule satisfies which regulatory citation, with no duplication between frameworks when the underlying control is the same.

[`docs/audit-log.md`](docs/audit-log.md) is the honest program status: what was reviewed, what got fixed, what's still open, and why. Not a "everything is green" summary.

## Repository layout

```
compliance-as-code/
├── policies/
│   ├── pci_dss/              # network segmentation, encryption, access control
│   ├── soc2/                 # logging and monitoring (CC7.2)
│   └── nist_800_53/          # least privilege (AC-6 family)
├── tests/                    # OPA unit tests — run with: opa test policies/ tests/ -v
├── examples/terraform/
│   ├── noncompliant/         # deliberately violates every policy — CI confirms it gets rejected
│   └── compliant/            # the corrected version — CI confirms it passes clean
├── docs/
│   ├── controls-mapping.md   # which policy satisfies which regulatory citation
│   ├── architecture.md       # how this fits the SecureCart PCI scope story
│   └── audit-log.md          # what was found in review, what was fixed, what is still open
└── .github/workflows/
    └── policy-check.yml      # CI: unit tests + conftest against both examples
```

## Running it locally

```bash
# Run the policy unit tests
opa test policies/ tests/ -v

# Check the deliberately broken example — should print violations
conftest test examples/terraform/noncompliant/plan.json --policy policies --all-namespaces

# Check the corrected example — should pass clean
conftest test examples/terraform/compliant/plan.json --policy policies --all-namespaces
```

The `plan.json` files are pre-committed fixtures. No GCP credentials needed to run the checks.

## What this repo doesn't cover

It checks infrastructure config at plan time. It doesn't scan runtime data, detect manual console changes, or replace a PCI QSA sign-off. [`docs/controls-mapping.md`](docs/controls-mapping.md) has the full list of gaps.

## Status

Built as a portfolio artifact. CI is green. OPA unit tests are written but haven't been verified in a live OPA runtime yet — that's the most important remaining step. See [`docs/audit-log.md`](docs/audit-log.md) for everything that was reviewed, fixed, and what's still genuinely unresolved.
