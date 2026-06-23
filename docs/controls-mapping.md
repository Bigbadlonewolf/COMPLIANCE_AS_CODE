# Controls mapping

This is the most important document in the repo. The policies are the enforcement mechanism; this is the evidence trail an auditor or hiring manager reads first.

| Policy file | What it checks | PCI DSS v4.0 | SOC2 (Trust Services Criteria) | NIST 800-53 Rev 5 |
|---|---|---|---|---|
| `pci_dss/network_segmentation.rego` | Deny 0.0.0.0/0 ingress on sensitive ports; require explicit `pci-scope` label (true/false) on every relevant compute resource | Req 1.2.1, 1.3.1 | CC6.6 | SC-7, SC-7(3) |
| `pci_dss/encryption_at_rest.rego` | Require customer-managed KMS key on storage and DB resources; deny plaintext secrets in env vars | Req 3.5.1, 3.6.1 | CC6.1 | SC-13, SC-28 |
| `pci_dss/access_control.rego` | Deny primitive/wildcard IAM roles; require IAM conditions on PCI-scoped service bindings; flag disabled IAM org policy constraints | Req 7.2.1, 7.3.1, 8.4.2 | CC6.1, CC6.2 | AC-6, AC-6(1), IA-2(1) |
| `soc2/logging_monitoring.rego` | Require at least 365-day log retention on the log destination; require explicit `monitored` label with a matching alert policy | Req 10.5.1 | CC7.2 | AU-11, SI-4 |
| `nist_800_53/least_privilege.rego` | Deny `roles/owner`; deny long-lived service account keys; flag oversized IAM bindings | Req 7.2.1 (cross-ref) | CC6.1 (cross-ref) | AC-6, AC-2(9), IA-5(1) |

**Citation status:** The MFA citation was corrected from 8.3.1 (password/passphrase requirements) to 8.4.2 (MFA into the CDE) after an adversarial review caught the error. The alerting citation 10.6.1 was removed entirely because 10.6 in PCI DSS v4.0 covers NTP time sync, not monitoring. It was dropped rather than replaced with another guess. Every citation in this table should be verified against the published PCI DSS v4.0 PDF before this repo is used in a real interview or assessment. These were corrected once already after a model-generated draft got them wrong, which is itself the argument for never trusting a regulatory citation without a primary-source check.

## Why one control maps to multiple frameworks

PCI 7.2.1, SOC2 CC6.1, and NIST AC-6 are all testing the same thing: least privilege. Three different standards bodies wrote them independently with different vocabulary. Implementing the same check three times in three separate files would mean three places to update when GCP changes an API field.

Instead, `access_control.rego` and `least_privilege.rego` share the same `roles/owner` detection logic and are cross-referenced here rather than duplicated. The only exception is `least_privilege.rego` covering long-lived service account keys, which has no direct PCI DSS equivalent.

One Rego rule, multiple framework citations, single place to maintain it.

## What this repo doesn't prove

- **No runtime data scanning.** These policies check Terraform plan output, not live data. They can't detect a PAN that ends up in a database despite the tokenization design. That requires a Cloud DLP scan, which is noted in `docs/architecture.md` but not built here.
- **No protection against manual changes.** A passing CI check proves the infrastructure config is compliant at plan time. It doesn't prevent someone from making a change directly in the GCP console afterward. Catching that requires scheduled drift detection against live state, which is on the roadmap.
- **No QSA sign-off.** Passing these policies is necessary but not sufficient for an actual PCI assessment. A Qualified Security Assessor still has to sign off. This repo is evidence you'd hand a QSA, not a replacement for one.
