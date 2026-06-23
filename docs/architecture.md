The "Why" Behind the Repo
This repo is standalone by design. You don't need the rest of the SecureCart codebase to understand it, but it tackles the biggest headache we faced during our PCI scope-reduction design: How do you keep that security promise intact over time?

It’s easy to prove a design is secure when you’re standing in front of an architecture diagram during a review. It’s significantly harder to prove that same design still holds six months later, after dozens of Terraform changes and team rotations.

The Solution: We stopped relying on memory and documentation. Instead, we encoded our design constraints directly into policy. Now, every single pull request is automatically scanned. If someone tries to deploy a payment service without the required pci-scope label, misconfigures a database KMS key, or accidentally grants an IAM role that expands our PCI boundary, the CI pipeline fails loudly. We turned compliance into a "hard block" rather than a manual checklist.

Why this matters for an interview
If you’re telling this story in an interview, don’t get hung up on the syntax of the Rego files. The interviewer isn't there to watch you debug code—they want to see how you think about scale and risk.

The Claim: Anyone can say, "I designed a secure architecture."

The Proof: You can say, "I translated our security constraints into automated policy, and here is how I wrote unit tests to prove those policies actually catch violations."

That changes the conversation from theoretical security to operational security. It shows you understand that security is a living, breathing part of the development lifecycle, not just a document that lives in a Confluence page.

The TPM Perspective: Mapping the Arc
When you’re in a Security TPM interview, the "story" is the program, not the code. Focus on the project’s arc:

The Identification: Identifying the PCI-scope reduction requirement.

The Translation: Translating those high-level compliance goals into engineering constraints.

The Verification: Closing the loop with automated auditing.

Frame it as a roadmap: you built a system that protects future engineers—even those who haven't read the original architecture docs—from accidentally shipping a compliance violation. That shift from "human-verified" to "system-enforced" is the real win.

A Note on Where We Are
I believe in being transparent about where this project stands. The structure—specifically the mapping of controls and the pairing of compliant/non-compliant examples—is solid. However, the test coverage across all five policy files is still a work in progress.

The project exists to prevent "over-claiming" on security, so I’m holding myself to that same standard: see docs/audit-log.md for the gaps we’re still working to close.
verification that the Rego actually executes are not yet done, and saying
otherwise would be the kind of overclaim this whole project is supposed to
prevent.
