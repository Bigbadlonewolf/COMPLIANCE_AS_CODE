# How this fits together

This repo stands alone. You don't need the rest of the SecureCart codebase to follow it. But it was built to answer a specific problem SecureCart had.

SecureCart's PCI approach tokenizes cardholder data at the browser so a full card number never reaches the backend. That's a clean design on paper. The problem is keeping it clean after the tenth Terraform change, when the original architects have moved on and nobody re-reads the design doc before merging.

This repo's answer: encode the design constraints as policy and run them in CI on every pull request. If a payment service gets deployed without its `pci-scope` label, or a database loses its KMS key, or someone grants `roles/owner` to a contractor, the build fails. The constraints are enforced, not just documented and hoped for.

## Why this is a portfolio artifact and not just code

Anyone can say "I designed a PCI-scope-reduced architecture." That's a slide. What's harder to fake is encoding the scope-reduction requirements as automatically enforced checks, writing unit tests that prove those checks catch real violations, and doing a second review pass against your own work before calling it done.

That's the program arc: requirement identified, translated into engineering constraints, enforced in CI, then audited. The story to tell isn't the Rego syntax. It's that sequence and the decision trail behind it.

## What's still incomplete

The controls mapping and the compliant/noncompliant example pair are solid. Unit tests exist for all five policy files. What hasn't happened yet: running `opa test` in a real OPA environment to confirm those tests actually pass. Everything was reviewed against provider schemas and fixed by re-reading carefully, not by running. Those are different things, and [`docs/audit-log.md`](audit-log.md) is honest about which is which.
