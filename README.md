# compliance-as-code

Policy-as-code enforcement of PCI DSS, SOC2, and NIST 800-53 controls against
Terraform infrastructure, using Open Policy Agent (OPA) and Conftest.

This exists to answer one question concretely instead of in a slide deck:
**can a regulatory control requirement be turned into an automated,
testable engineering check — and tracked end-to-end as a program, not just
written down once and forgotten?**

## Why this project, and why it's a program-management artifact, not just code

This repo is not a pitch that I can write production code under deadline
— that's not the claim being made here. It's evidence of the actual job a
Security Technical Program Manager does: translate compliance and
regulatory requirements (PCI DSS, SOC2, NIST 800-53) into engineering
work, define what "done" and "verified" mean for that work, and run the
process that catches drift before an auditor does.

[`docs/controls-mapping.md`](docs/controls-mapping.md) is the roadmap
artifact — it's the same shape as a program roadmap a Security TPM would
maintain across security, GRC, and engineering teams, except expressed as
a literal mapping of one engineering control to three regulatory
citations, so nobody on any of those three teams has to re-derive it.
[`docs/audit-log.md`](docs/audit-log.md) is the program status report —
an honest account of what's verified, what's open, and why, which is
the exact deliverable a Security TPM owes stakeholders every cycle, not
a polished "everything's green" summary that hides what's actually
unresolved.

## Repository layout

```
compliance-as-code/
├── policies/
│   ├── pci_dss/              # network segmentation, encryption, access control
│   ├── soc2/                 # logging & monitoring (CC7.2)
│   └── nist_800_53/          # least privilege (AC-6 family)
├── tests/                    # OPA unit tests — `opa test policies/ tests/ -v`
├── examples/terraform/
│   ├── noncompliant/         # deliberately violates every policy — CI proves it gets rejected
│   └── compliant/            # the fixed version — CI proves it gets accepted
├── docs/
│   ├── controls-mapping.md   # which Rego rule satisfies which regulatory citation
│   ├── architecture.md       # how this fits into the broader SecureCart PCI scope story
│   └── audit-log.md          # self-audit findings and what was fixed before this was "done"
└── .github/workflows/
    └── policy-check.yml      # CI: unit tests + conftest against both examples
```

## Running it locally

```bash
# Run the policy unit tests (no terraform required)
opa test policies/ tests/ -v

# Test the deliberately broken example — should print violations
cd examples/terraform/noncompliant
terraform init -backend=false && terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
conftest test plan.json --policy ../../../policies --all-namespaces

# Test the fixed example — should pass clean
cd ../compliant
terraform init -backend=false && terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
conftest test plan.json --policy ../../../policies --all-namespaces
```

## Scope and honesty about limitations

This repo enforces infrastructure-as-code at plan time. It does not scan
runtime data, does not detect manual console drift, and is not a substitute
for a Qualified Security Assessor's sign-off on an actual PCI assessment.
See the "What this repo does NOT prove" section in
[`docs/controls-mapping.md`](docs/controls-mapping.md) for the full list —
that section exists because pretending a tool does more than it does is the
fastest way to fail an actual interview about it.

## Status — read this as a program status report, not a finished product

Built as a portfolio artifact, not yet deployed against live
infrastructure. See [`docs/audit-log.md`](docs/audit-log.md) for the
self-review pass this went through, what's still outstanding, and the
explicit decision log of what got fixed versus deferred and why — that
decision log is the actual point. A Security TPM's job is not to claim
everything is done; it's to know precisely what isn't done, why, and what
the plan is to close it. This README and the audit log are written to
demonstrate that discipline, not to oversell a finished build.
