# compliance-as-code
Stop treating compliance like a document. Start treating it like production software.
Most cloud architects are still stuck managing compliance with giant, outdated spreadsheets — mapping every Terraform resource to PCI DSS, SOC 2, and NIST 800-53 controls for yet another quarterly sign-off. 
The dirty secret? That spreadsheet is just a statement of intent. It tells you nothing about what actually shipped to production last Tuesday.
This repo is my attempt to fix that gap.
Instead of relying on plausible deniability and manual checklists, I’m using Policy-as-Code with OPA (Open Policy Agent) and Conftest. Every Terraform change gets scanned before a single resource hits the cloud. If it violates our security or compliance rules, the PR is blocked. Simple as that.


## Why this exists

The real question is: Can we turn a regulatory requirement into an automated, repeatable, provable check that runs on every pull request?
That’s what this project is built around.
It’s a Program, Not Just Policies
This isn’t just a pile of Rego files. It’s meant to be a real engineering program with the same standards we apply to infrastructure:



[`docs/controls-mapping.md`](docs/controls-mapping.md) is the requirements traceability document: which policy rule satisfies which regulatory citation, with no duplication between frameworks when the underlying control is the same.

[`docs/audit-log.md`](docs/audit-log.md) is the honest program status: what was reviewed, what got fixed, what's still open, and why. Not a "everything is green" summary.

## Repository layout

```
Repository Layout
plaintextcompliance-as-code/
compliance-as-code/
├── policies/             # Rego logic for PCI, SOC2, and NIST
├── tests/                # OPA unit tests (opa test policies/ tests/ -v)
├── examples/terraform/   # Proof: noncompliant (rejected) vs. compliant (passed)
├── docs/                 # Mapping, architecture, and audit logs
└── .github/workflows/    # CI pipeline: unit tests + conftest enforcement
## What this repo doesn't cover

It checks infrastructure config at plan time. It doesn't scan runtime data, detect manual console changes, or replace a PCI QSA sign-off. [`docs/controls-mapping.md`](docs/controls-mapping.md) has the full list of gaps.

## Status

Built as a portfolio artifact. CI is green. OPA unit tests are written but haven't been verified in a live OPA runtime yet — that's the most important remaining step. See [`docs/audit-log.md`](docs/audit-log.md) for everything that was reviewed, fixed, and what's still genuinely unresolved.
