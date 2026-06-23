# Compliance as Code

Stop treating compliance like a document. Start treating it like production software.

Most cloud architects are still stuck managing compliance with giant, outdated spreadsheets — mapping every Terraform resource to PCI DSS, SOC 2, and NIST 800-53 controls for yet another quarterly sign-off. The dirty secret? That spreadsheet is just a statement of intent. It tells you nothing about what actually shipped to production last Tuesday.

This repo is my attempt to fix that gap. Instead of relying on plausible deniability and manual checklists, I'm using Policy-as-Code with OPA (Open Policy Agent) and Conftest. Every Terraform change gets scanned before a single resource hits the cloud. If it violates our security or compliance rules, the PR is blocked. Simple as that.

## The Core Idea

The real question is: Can we turn a regulatory requirement into an automated, repeatable, provable check that runs on every pull request? That's what this project is built around.

## It's a Program, Not Just Policies

This isn't just a pile of Rego files. It's meant to be a real engineering program with the same standards we apply to infrastructure:

- **Traceability:** `docs/controls-mapping.md` links specific regulatory citations to the actual policy rules. No more wondering which control covers what, and no duplicated effort across frameworks.
- **Accountability:** `docs/audit-log.md` is an honest record of what's been reviewed, what's been fixed, and what we still need to tackle. No fake "everything is green" reports.
- **Discipline:** The policies are version-controlled, unit tested, and peer-reviewed — just like the rest of our code.

## Repository Layout

```
compliance-as-code/
├── policies/            # Rego policies for PCI, SOC 2, NIST, etc.
├── tests/               # OPA unit tests
├── examples/terraform/  # Compliant vs non-compliant examples (with plan.json fixtures)
├── docs/                # Control mappings, architecture decisions, and the audit log
└── .github/workflows/   # CI that runs tests + Conftest enforcement
```

## Try It Yourself (No Cloud Credentials Needed)

I've included pre-baked Terraform plan fixtures so you can kick the tires locally.

**Run the policy tests:**

```bash
opa test policies/ tests/ -v
```

**Test the bad example (should fail):**

```bash
conftest test examples/terraform/noncompliant/plan.json --policy policies --all-namespaces
```

**Test the good example (should pass):**

```bash
conftest test examples/terraform/compliant/plan.json --policy policies --all-namespaces
```

## What This Isn't

This gives you strong preventive compliance at deploy time, but it's not magic. It doesn't solve runtime drift, configuration changes made in the console, or replace a proper QSA/auditor sign-off. See `docs/controls-mapping.md` for a clear view of what's covered and what still needs human eyes.

## Current Status

The CI is green, tests are passing, and we're steadily expanding coverage. Check `docs/audit-log.md` for the latest on open items and recent improvements.
