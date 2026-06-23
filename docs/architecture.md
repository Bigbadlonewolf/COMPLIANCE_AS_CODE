# Architecture Context

This repo is deliberately scoped to be useful on its own — you don't need
any other thing for it to make sense — but it exists to answer a
specific question raised by SecureCart's PCI scope-reduction design
(tokenize cardholder data at the browser, never let a PAN reach the
backend): **how do you prove that design holds over time, across every
future Terraform change, instead of just at the moment someone reviewed
the architecture diagram?**

The answer this repo gives: encode the design constraints as policy, run
them in CI on every pull request, and reject anything that quietly expands
PCI scope back out — a payment service deployed without its `pci-scope`
label, a database that loses its KMS key, an IAM binding that grants
`roles/owner` to a contractor six months after the architecture review
happened and everyone stopped paying attention.

## The argument this makes to an interviewer

"I designed a PCI-scope-reduced payment architecture" is a claim anyone can
make from a diagram. "I encoded the scope-reduction constraints as
automatically enforced policy, with unit tests proving the policy catches
real violations" is a claim backed by something a reviewer can run
themselves. That's the entire reason this exists as a separate repo instead
of a paragraph in SecureCart's README.

## The argument this makes in a Security TPM loop specifically

The technical-retrospective round in a TPM interview isn't asking "did you
write this code" — it's asking "walk me through the program." The story
here is the program, not the Rego: a compliance requirement (PCI scope
reduction) got identified, translated into something engineering had to
satisfy automatically, and then audited a second time before being called
done. That's a roadmap-kickoff-execution-verification arc with a stakeholder
(the future engineer who'll touch this Terraform without re-reading the
architecture doc) and a measurable outcome (a CI check that fails loudly
instead of a scope violation that ships silently). That arc is the thing to
narrate, not the syntax.

## Known incompleteness

See [`docs/audit-log.md`](audit-log.md) for the specific gaps. The honest
summary: the controls-mapping structure and the compliant/noncompliant
example pair are solid. Test coverage across all five policy files and live
verification that the Rego actually executes are not yet done, and saying
otherwise would be the kind of overclaim this whole project is supposed to
prevent.
