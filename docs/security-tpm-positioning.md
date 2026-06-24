# Using this repo in a Security TPM interview

This doc is intentionally direct. It exists to turn the repo into talking points, because nobody gives you credit for work they have to infer.

## "Tell me about a program you ran"

Don't describe the Rego. Describe the program.

A PCI DSS compliance requirement existed as an architecture decision and a diagram. The risk: that decision would erode silently over time. Someone adds a database without encryption, someone grants `roles/owner` to a contractor, and six months later the SAQ A claim is no longer true and nobody notices until an auditor does.

The program was: define the specific controls that have to hold, encode them as automatically enforced checks, build the CI pipeline that runs them on every change, and do a second-pass review against my own work before calling it done. Because "I built it" and "it's verified" are different claims, and conflating them is the exact gap a TPM is supposed to catch in other people's work, not produce in their own.

## "How do you handle incomplete work?"

Point at [`docs/audit-log.md`](audit-log.md).

It has open findings ranked by severity, with explicit reasoning for why each one wasn't fixed before shipping the draft. Not "I ran out of time." Specific tradeoffs: this finding needs its own test file, that one needs a credentials decision someone else has to make. That table is the artifact. Most candidates show you a finished demo and hope you don't ask what's missing. This shows the missing pieces on purpose, which is what the job actually requires day to day.

## "How do you work with engineering teams when you're not writing the code?"

Define what "compliant" means precisely enough that it can be tested. Make the test the source of truth instead of a person's judgment call at review time. Track the gap between what's enforced and what's aspirational — like the AWS-schema gaps and missing test coverage logged in the audit log — so engineering knows exactly what to build next rather than guessing.

## What not to claim

Do not claim you wrote and validated the Rego end-to-end. The audit log is explicit that `opa test` was never run in this build environment.

If asked "did you run this," the correct answer is: "The unit tests are written but unverified in the environment I used. Running them and reporting back is the first item on the punch list."

That's actually a stronger answer than pretending it's done. It shows you know the difference between "written" and "proven," which is the entire discipline a Security TPM is hired to enforce in everyone else's work too.
