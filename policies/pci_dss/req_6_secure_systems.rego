package pci_dss.req_6

import rego.v1

import data.controls.cmek_at_rest
import data.controls.key_rotation
import data.controls.tls_in_transit

# PCI DSS v4.0 — Requirement 6: Develop and Maintain Secure Systems and Software
#
# 6.3.5  All cardholder data (CHD) storage is encrypted at rest using
#         strong cryptography. CMEK is required for CDE resources.
# 6.5.3  All transmission of CHD over open, public networks is encrypted.
#
# This package is a CITATION LAYER. The detection logic lives in policies/controls/
# and is shared with soc2 and nist_800_53 — see docs/controls-mapping.md. Changing
# what counts as a violation belongs in the control; changing how PCI phrases it
# belongs here.
#
# Resource types checked (via controls):
#   google_sql_database_instance
#   google_storage_bucket
#   google_kms_crypto_key

# ── 6.5.3: SQL instances must enforce SSL-only connections ──────────────────

deny contains msg if {
	f := tls_in_transit.not_enforced[_]
	msg := sprintf(
		"PCI DSS 6.5.3 | %s: Cloud SQL does not enforce ssl_mode = 'ENCRYPTED_ONLY' (ip_configuration block or ssl_mode is absent). All database connections must use TLS.",
		[f.address],
	)
}

# ── 6.3.5: SQL instances must use CMEK encryption ───────────────────────────

deny contains msg if {
	f := cmek_at_rest.sql_missing[_]
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: Cloud SQL instance has no CMEK key (encryption_key_name not set). CHD at rest must use customer-managed encryption.",
		[f.address],
	)
}

# ── 6.3.5: Storage buckets must use CMEK encryption ─────────────────────────

deny contains msg if {
	f := cmek_at_rest.bucket_missing[_]
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: Storage bucket has no CMEK encryption configured. Set encryption { default_kms_key_name = \"...\" }.",
		[f.address],
	)
}

# ── 6.3.5: KMS ENCRYPT_DECRYPT keys must have rotation set ──────────────────

deny contains msg if {
	f := key_rotation.missing[_]
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: KMS crypto key has no rotation_period set. Automatic key rotation is required for CHD encryption keys.",
		[f.address],
	)
}

# ── 6.3.5: KMS rotation period must not exceed 1 year ───────────────────────

deny contains msg if {
	f := key_rotation.excessive[_]
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: KMS key rotation_period is %vs which exceeds 1 year (%vs). Keys encrypting CHD must rotate at least annually.",
		[f.address, f.seconds, f.limit],
	)
}
