# Controls Mapping

This is the artifact that matters most in this repo. The Rego policies are
the enforcement mechanism; this document is the evidence trail an auditor
or a hiring manager actually reads first.

| Policy file | Control logic | PCI DSS v4.0 | SOC2 (Trust Services Criteria) | NIST 800-53 Rev 5 |
|---|---|---|---|---|
| `pci_dss/network_segmentation.rego` | Deny 0.0.0.0/0 ingress on sensitive ports; require explicit `pci-scope` label (true/false) on every relevant compute resource | Req 1.2.1, 1.3.1 | CC6.6 | SC-7, SC-7(3) |
| `pci_dss/encryption_at_rest.rego` | Require customer-managed KMS key on storage/DB resources; deny plaintext secrets in env vars | Req 3.5.1, 3.6.1 | CC6.1 | SC-13, SC-28 |
| `pci_dss/access_control.rego` | Deny primitive/wildcard IAM roles; require IAM conditions on payment-named service bindings; flag disabled IAM org policy constraints | Req 7.2.1, 7.3.1, 8.4.2 | CC6.1, CC6.2 | AC-6, AC-6(1), IA-2(1) |
| `soc2/logging_monitoring.rego` | Require >=365 day log retention on the log destination; require explicit `monitored` label + matching alert policy | Req 10.5.1 | CC7.2 | AU-11, SI-4 |
| `nist_800_53/least_privilege.rego` | Deny `roles/owner`; deny long-lived service account keys; flag oversized IAM bindings | Req 7.2.1 (cross-ref) | CC6.1 (cross-ref) | AC-6, AC-2(9), IA-5(1) |

**Citation status (Last updated after adversarial review):** the MFA
citation was corrected from a previous draft's 8.3.1 to 8.4.2 (8.3.x
governs password/passphrase requirements in PCI DSS v4.0, not MFA; 8.4.2
is the MFA-into-CDE requirement). The alerting citation's previous 10.6.1
reference was removed — 10.6 in PCI DSS v4.0 concerns time synchronization
(NTP), not alerting/monitoring, so it was simply the wrong requirement
number and has been dropped rather than replaced with another guess.
**Every citation in this table should still be checked against the
published PCI DSS v4.0 PDF directly before this repo is used in a real
interview or assessment** — these numbers were corrected once already
after a model-generated first draft got them wrong, which is itself the
argument for never trusting an LLM's regulatory citation without a primary-
source check, mine included.

## Why one control sometimes maps to three frameworks

PCI 7.2.1, SOC2 CC6.1, and NIST AC-6 are testing the same underlying fact —
least privilege — using three different vocabularies because three different
standards bodies wrote them independently. Implementing the check three times
in three Rego files would mean three places to update when GCP changes an
API field. Instead, `access_control.rego` and `least_privilege.rego`
deliberately share the same `roles/owner` detection logic and are
cross-referenced here rather than duplicated, with the small exception of
`least_privilege.rego` covering long-lived service account keys, which has
no direct PCI DSS analogue.

This is the actual argument for compliance-as-code over a compliance
spreadsheet: one Rego rule, multiple framework citations, single source of
truth.

## What this repo does NOT prove

Being explicit about gaps is itself part of the audit trail:

- **No data-layer scanning.** These policies inspect Terraform plan output,
  not runtime data. They cannot detect a PAN that ends up in a database
  despite the architecture's tokenization design — that requires a
  complementary Cloud DLP scan (referenced in `docs/architecture.md` but
  not implemented in this repo).
- **No proof of operational enforcement.** A passing CI check proves the
  *infrastructure-as-code* is compliant at plan time. It does not prove a
  human didn't `gcloud` a manual change directly into the console afterward.
  That requires drift detection (e.g., a scheduled `terraform plan` diff
  against live state), which is on the roadmap, not built.
- **No formal PCI QSA validation.** Passing these policies is necessary,
  not sufficient, for an actual PCI assessment. A Qualified Security
  Assessor still has to sign off. This repo is evidence you'd hand a QSA,
  not a replacement for one.
