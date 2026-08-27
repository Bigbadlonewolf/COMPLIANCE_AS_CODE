# How this fits together

This repo stands alone. You don't need the rest of the SecureCart codebase to follow it. But it was built to answer a specific problem SecureCart had.

SecureCart's PCI approach tokenizes cardholder data at the browser so a full card number never reaches the backend. That's a clean design on paper. The problem is keeping it clean after the tenth Terraform change, when the original architects have moved on and nobody re-reads the design doc before merging.

This repo's answer: encode the design constraints as policy and run them in CI on every pull request. If a payment service gets deployed without its `pci-scope` label, or a database loses its KMS key, or someone grants `roles/owner` to a contractor, the build fails. The constraints are enforced, not just documented and hoped for.

## Why this is a portfolio artifact and not just code

Anyone can say "I designed a PCI-scope-reduced architecture." That's a slide. What's harder to fake is encoding the scope-reduction requirements as automatically enforced checks, writing unit tests that prove those checks catch real violations, and doing a second review pass against your own work before calling it done.

That's the program arc: requirement identified, translated into engineering constraints, enforced in CI, then audited. The story to tell isn't the Rego syntax. It's that sequence and the decision trail behind it.

## What's still incomplete

The controls mapping and the compliant/noncompliant example pair are solid, and unit tests exist for all five policy files. `opa test` now runs in CI on every push — 163/163 passing at HEAD (controls 58, PCI DSS 60, SOC 2 23, NIST 800-53 22) — alongside `opa check --strict`, so the policies are executed, not just re-read. What is still open is smaller: the IA-5(1) citation needs verifying against the NIST text, no third-party review has happened, and the `-target` plan-scoping gap is a pipeline-level fix, not a Rego one. [`docs/audit-log.md`](audit-log.md) tracks these.