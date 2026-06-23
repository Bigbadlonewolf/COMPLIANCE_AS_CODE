# Controls Mapping

This is the most important document in the repo. The policies are the enforcement mechanism; this is the evidence trail an auditor or hiring manager reads first.

## PCI DSS v4.0

| Policy file | What it checks | Requirements |
|---|---|---|
| `pci_dss/req_1_network_controls.rego` | Deny INGRESS firewall rules with sensitive ports (SSH, RDP, DB) open to `0.0.0.0/0`; deny `protocol = all` from internet | **Req 1.3.2** |
| `pci_dss/req_2_system_defaults.rego` | Deny Cloud SQL with public IP; deny storage buckets without uniform access or public access prevention | **Req 2.2.1** |
| `pci_dss/req_6_secure_systems.rego` | Deny Cloud SQL without CMEK or `ssl_mode = ENCRYPTED_ONLY`; deny storage without CMEK; deny KMS keys with no rotation | **Req 6.3.5, 6.5.3** |
| `pci_dss/req_7_access_control.rego` | Deny primitive IAM roles (`owner`, `editor`, `viewer`) at project level; deny `allUsers`/`allAuthenticatedUsers` | **Req 7.2.5, 7.2.6** |
| `pci_dss/req_10_logging.rego` | Deny Cloud SQL without automated backups or `cloudsql.enable_pgaudit`; deny storage without versioning | **Req 10.2.1, 10.3.2** |

## SOC2 Trust Service Criteria (2017)

| Policy file | What it checks | Criteria |
|---|---|---|
| `soc2/cc6_logical_access.rego` | Deny primitive IAM roles; deny public members; deny Cloud SQL without SSL; deny storage and SQL without CMEK | **CC6.1, CC6.3, CC6.6, CC6.7** |
| `soc2/cc7_system_operations.rego` | Deny Cloud SQL without backups; deny KMS keys without rotation or with rotation > 1 year; deny storage without versioning | **CC7.1, CC7.2, CC8.1** |

## NIST SP 800-53 Rev 5

| Policy file | What it checks | Controls |
|---|---|---|
| `nist_800_53/ac_access_control.rego` | Deny primitive IAM roles; deny public IAM members; deny firewall rules exposing remote-access ports from `0.0.0.0/0` | **AC-3, AC-6, AC-17** |
| `nist_800_53/au_audit_logging.rego` | Deny Cloud SQL without `cloudsql.enable_pgaudit` or `log_connections`; deny storage without versioning or uniform access | **AU-2, AU-9, AU-12** |
| `nist_800_53/sc_comms_protection.rego` | Deny Cloud SQL without TLS or CMEK; deny storage without CMEK; deny KMS ENCRYPT_DECRYPT keys without rotation | **SC-8, SC-28** |

---

## Citation Status

The requirement numbers in this table were verified against the published PCI DSS v4.0 specification (March 2022). Earlier drafts of this mapping contained two errors that were caught and corrected:

- The MFA citation was changed from 8.3.1 (password/passphrase requirements) to 8.4.2 (multi-factor authentication into the CDE).
- A citation referencing PCI DSS 10.6.1 was removed — 10.6 covers NTP time synchronisation in v4.0, not monitoring. It was dropped rather than replaced with a guess.

Every citation should be verified against the primary-source PDFs before use in a real audit or interview context. These were corrected once already after a model-generated draft got them wrong, which is itself the argument for never trusting a regulatory citation without a primary-source check.

---

## Why One Control Maps to Multiple Frameworks

PCI DSS 7.2.5, SOC2 CC6.3, and NIST AC-6 are all testing the same thing: least privilege. Three standards bodies wrote them independently with different vocabulary. Rather than implementing the same logic three times in three separate files, the deny rules in `req_7_access_control.rego`, `cc6_logical_access.rego`, and `ac_access_control.rego` each reference the same `lib.utils.primitive_roles` set and are cross-referenced here with their respective citations.

One underlying check. Three framework citations. Single place to update when GCP changes an API field.

---

## What This Repo Doesn't Prove

- **No runtime data scanning.** These policies check Terraform plan output, not live data. They cannot detect a PAN that ends up in a database despite the tokenisation design. That requires Cloud DLP, which is noted here but not built.
- **No protection against manual console changes.** A passing CI check proves the infrastructure config is compliant at plan time. It does not prevent someone from making a change directly in the GCP console afterward. Catching that requires scheduled drift detection against live state.
- **No QSA sign-off.** Passing these policies is necessary but not sufficient for an actual PCI assessment. A Qualified Security Assessor still has to review. This repo is evidence you hand a QSA, not a replacement for one.
- **GCP-specific.** Policies target `hashicorp/google` provider v5.x field names. AWS or Azure resources would need separate policy files; the OPA test infrastructure and CI patterns are reusable.
