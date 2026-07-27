# Controls Mapping

This is the most important document in the repo. The policies are the enforcement mechanism; this is the evidence trail an auditor or hiring manager reads first.

## The crosswalk

Each row is **one check, implemented once** in `policies/controls/`. The framework packages import it and attach their own citation — they contain no detection logic of their own. Read a row left-to-right to answer "what does this enforce, and which requirement does each framework call it?"

| Control (`policies/controls/`) | What it denies | PCI DSS v4.0 | SOC 2 TSC | NIST 800-53 Rev 5 |
| --- | --- | --- | --- | --- |
| `privileged_access.primitive_role` | Project-level `roles/owner`, `roles/editor`, `roles/viewer` | **7.2.5** | **CC6.3** | **AC-6** |
| `privileged_access.public_member` | `allUsers` / `allAuthenticatedUsers` on a project IAM member or binding | **7.2.6** | **CC6.1** | **AC-3** |
| `tls_in_transit` | Cloud SQL not enforcing `ssl_mode = ENCRYPTED_ONLY`, including an absent `ip_configuration` block | **6.5.3** | **CC6.6** | **SC-8** |
| `cmek_at_rest` | Cloud SQL or storage bucket without a customer-managed key, including an explicit `null` key | **6.3.5** | **CC6.7** | **SC-28** |
| `key_rotation` | KMS `ENCRYPT_DECRYPT` keys with no `rotation_period`, or one exceeding 1 year | **6.3.5** | **CC7.1** | **SC-28** |
| `sql_backups` | Cloud SQL without automated backups, including an absent `backup_configuration` block | **10.3.2** | **CC8.1** | — |
| `object_versioning` | Storage buckets without object versioning | **10.3.2** | **CC7.2** | **AU-9** |

A dash means that framework has no counterpart control in this repo — not that the requirement does not exist.

## Framework-local checks

These have no counterpart in the other frameworks, so they stay in their framework package rather than `controls/`. Promoting a check with one consumer to a shared package adds indirection and buys nothing.

| Policy file | What it checks | Citation |
| --- | --- | --- |
| `pci_dss/req_1_network_controls.rego` | INGRESS firewall rules with sensitive ports (SSH, RDP, DB) open to `0.0.0.0/0`; `protocol = all` from the internet | **1.3.2** |
| `pci_dss/req_2_system_defaults.rego` | Cloud SQL with a public IP; buckets without uniform access or public access prevention | **2.2.1** |
| `pci_dss/req_10_logging.rego` | Cloud SQL missing the `cloudsql.enable_pgaudit` flag | **10.2.1** |
| `nist_800_53/ac_access_control.rego` | Firewall rules exposing remote-access ports from `0.0.0.0/0` | **AC-17** |
| `nist_800_53/au_audit_logging.rego` | Cloud SQL missing `cloudsql.enable_pgaudit` or `log_connections`; buckets without uniform access | **AU-2, AU-12, AU-9** |

The five unnumbered policy files (`access_control`, `encryption_at_rest`, `network_segmentation`, `logging_monitoring`, `least_privilege`) are **not yet represented in this table**. They carry additional checks — AWS IAM policy wildcards, Cloud Run IAM conditions, org-policy constraints — and mapping them is outstanding work. Stated here rather than left as a silent gap.

---

## Citation Status

The requirement numbers in this table were verified against the published PCI DSS v4.0 specification (March 2022). Earlier drafts of this mapping contained two errors that were caught and corrected:

- The MFA citation was changed from 8.3.1 (password/passphrase requirements) to 8.4.2 (multi-factor authentication into the CDE).
- A citation referencing PCI DSS 10.6.1 was removed — 10.6 covers NTP time synchronisation in v4.0, not monitoring. It was dropped rather than replaced with a guess.

Every citation should be verified against the primary-source PDFs before use in a real audit or interview context. These were corrected once already after a model-generated draft got them wrong, which is itself the argument for never trusting a regulatory citation without a primary-source check.

---

## Why One Control Maps to Multiple Frameworks

PCI DSS 7.2.5, SOC2 CC6.3, and NIST AC-6 are all testing the same thing: least privilege. Three standards bodies wrote them independently with different vocabulary.

One underlying check. Three framework citations. Single place to update when GCP changes an API field.

**This was aspirational until 2026-07-26.** The three packages shared the `lib.utils.primitive_roles` *data*, but each implemented the *logic* separately — five checks across fifteen rule bodies. They had already drifted apart, and the drift was not cosmetic: three of them had become false negatives, each one a case where a framework passed infrastructure the other two rejected.

- `soc2/cc6` and `nist_800_53/sc` bound `ip_configuration[_]` before testing `ssl_mode`, so a Cloud SQL instance with no such block passed both. GCP does not enforce TLS unless told to.
- `pci_dss/req_6` tested bucket CMEK with a bare truthiness check. In Rego `null` is a **defined** value, so an explicit `default_kms_key_name = null` read as "key present".
- `soc2/cc7` bound `backup_configuration[_]` before testing `enabled`, so an instance with no backup block passed.

Detection logic now lives once per control in `policies/controls/`. Each merged control carries a `CORRECTNESS NOTE` recording which implementation won and why. See `audit-log.md`.

---

## What this repo doesn't prove

These policies check Terraform plan output, not live data. They cannot detect a PAN that ends up in a database despite the tokenisation design. That requires Cloud DLP, which is noted here but not built.

A passing CI check proves the infrastructure config is compliant at plan time. It does not prevent someone from making a change directly in the GCP console afterward. Catching that requires scheduled drift detection against live state.

Passing these policies is necessary but not sufficient for an actual PCI assessment. A Qualified Security Assessor still has to review. This repo is evidence you hand a QSA, not a replacement for one.

Policies target `hashicorp/google` provider v5.x field names. AWS or Azure resources would need separate policy files; the OPA test infrastructure and CI patterns are reusable.
