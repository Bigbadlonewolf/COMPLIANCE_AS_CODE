# Using This Repo in a Security TPM Interview

This file is deliberately not subtle — it exists to turn this repo into
talking points, because nobody hands you credit for inference in an
interview.

## If asked "tell me about a program you ran"

Don't describe the Rego. Describe the program: a compliance requirement
(PCI DSS scope reduction) existed only as an architecture decision and a
diagram. The risk was that the decision would silently erode over time —
someone adds a database without encryption, someone grants a contractor
`roles/owner`, and six months later the SAQ A claim is no longer true and
nobody notices until an assessor does. The program was: define the
specific controls that have to hold, encode them as automatically
enforced checks, build the evidence pipeline (CI) that runs them on every
change, and — critically — run a second-pass review against my own work
before calling it done, because "I built it" and "it's verified" are
different claims and conflating them is exactly the kind of gap a TPM is
supposed to catch in other people's work, not just produce in their own.

## If asked "how do you handle incomplete work / what do you do when something's not ready"

Point directly at `docs/audit-log.md`. It has five open findings, ranked
by severity, with explicit reasoning for why each one wasn't fixed before
shipping the draft (not "I ran out of time" — specific tradeoffs: this
finding needs its own test file, that one needs a credentials decision
someone else has to make). That table is the artifact. Most candidates
will show you a finished demo and hope you don't ask what's missing. This
shows the missing pieces voluntarily, which is the behavior the job
actually requires day to day.

## If asked "how do you work with engineering teams when you're not writing the code yourself"

The honest answer, and the one this repo supports: you define what
"compliant" means precisely enough that it can be tested, you make the
test the source of truth instead of a person's judgment call at review
time, and you track the gap between what's enforced and what's aspirational
— like the AWS-schema gaps and missing test coverage logged here — so
engineering knows exactly what to build next instead of guessing.

## What NOT to claim in the room

Do not claim you wrote and validated the Rego end-to-end — the audit log
is explicit that `opa test` was never run in this build environment.
If asked "did you run this," the correct answer is: "the policy logic
unit-tests are written but unverified in the build environment I used;
running them and reporting back is the first item on the punch list" —
that's a stronger answer than pretending it's done, because it shows you
know the difference between "written" and "proven," which is the entire
discipline a Security TPM is hired to enforce in everyone else's work too.
