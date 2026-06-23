# compliance-as-code
Stop treating compliance like a document. Start treating it like production software.
Most cloud architects are still stuck managing compliance with giant, outdated spreadsheets — mapping every Terraform resource to PCI DSS, SOC 2, and NIST 800-53 controls for yet another quarterly sign-off. 
The dirty secret? That spreadsheet is just a statement of intent. It tells you nothing about what actually shipped to production last Tuesday.
This repo is my attempt to fix that gap.
Instead of relying on plausible deniability and manual checklists, I’m using Policy-as-Code with OPA (Open Policy Agent) and Conftest. Every Terraform change gets scanned before a single resource hits the cloud. If it violates our security or compliance rules, the PR is blocked. Simple as that.


## Why this exists
The Core Idea
The real question is: Can we turn a regulatory requirement into an automated, repeatable, provable check that runs on every pull request?
That’s what this project is built around.
It’s a Program, Not Just Policies
This isn’t just a pile of Rego files. It’s meant to be a real engineering program with the same standards we apply to infrastructure:



[`docs/controls-mapping.md`](docs/controls-mapping.md) is the requirements traceability document: which policy rule satisfies which regulatory citation, with no duplication between frameworks when the underlying control is the same.

[`docs/audit-log.md`](docs/audit-log.md) is the honest program status: what was reviewed, what got fixed, what's still open, and why. Not a "everything is green" summary.

## Repository layout

```
cRepository Layout
plaintextcompliance-as-code/
├── policies/             # Rego policies for PCI, SOC 2, NIST, etc.
├── tests/                # OPA unit tests
├── examples/terraform/   # Compliant vs non-compliant examples (with plan.json fixtures)
├── docs/                 # Control mappings, architecture decisions, and the audit log
└── .github/workflows/    # CI that runs tests + Conftest enforcement
Try It Yourself (No Cloud Credentials Needed)
I’ve included pre-baked Terraform plan fixtures so you can kick the tires locally:

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
