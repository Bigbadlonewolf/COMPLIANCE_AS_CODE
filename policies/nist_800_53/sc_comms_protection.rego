package nist_800_53.sc

import rego.v1

import data.controls.cmek_at_rest
import data.controls.key_rotation
import data.controls.tls_in_transit

# NIST SP 800-53 Rev 5 — SC: System and Communications Protection
#
# SC-8   Transmission Confidentiality and Integrity: Implement cryptographic
#         mechanisms to prevent unauthorized disclosure of information during
#         transmission (TLS/SSL enforcement).
# SC-28  Protection of Information at Rest: Implement cryptographic mechanisms
#         to prevent unauthorized disclosure of information at rest (CMEK).
#
# This package is a CITATION LAYER. Detection logic lives in policies/controls/
# and is shared with pci_dss and soc2 — see docs/controls-mapping.md.
#
# NOTE: SC-8 previously required an ip_configuration block to exist before
# testing ssl_mode, so a Cloud SQL instance with no such block silently passed.
# The shared control treats an absent block as a violation.
#
# Resource types checked (via controls):
#   google_sql_database_instance
#   google_storage_bucket
#   google_kms_crypto_key

# ── SC-8: SQL must enforce TLS for all connections ──────────────────────────

deny contains msg if {
	f := tls_in_transit.not_enforced[_]
	msg := sprintf(
		"NIST SC-8 | %s: Cloud SQL ssl_mode is '%v'. All database connections must use TLS (set ssl_mode = \"ENCRYPTED_ONLY\").",
		[f.address, f.observed],
	)
}

# ── SC-28: SQL must use CMEK ────────────────────────────────────────────────

deny contains msg if {
	f := cmek_at_rest.sql_missing[_]
	msg := sprintf(
		"NIST SC-28 | %s: Cloud SQL has no CMEK key. Sensitive data at rest must be protected with a customer-managed encryption key.",
		[f.address],
	)
}

# ── SC-28: Storage buckets must use CMEK ────────────────────────────────────

deny contains msg if {
	f := cmek_at_rest.bucket_missing[_]
	msg := sprintf(
		"NIST SC-28 | %s: Storage bucket has no CMEK encryption. Set encryption { default_kms_key_name = \"...\" } to protect data at rest.",
		[f.address],
	)
}

# ── SC-28: KMS ENCRYPT_DECRYPT keys must have automatic rotation ────────────

deny contains msg if {
	f := key_rotation.missing[_]
	msg := sprintf(
		"NIST SC-28 | %s: KMS crypto key has no rotation_period. Keys must rotate automatically to limit the impact of key compromise.",
		[f.address],
	)
}

# ── SC-28: KMS rotation period must not exceed 1 year ───────────────────────

deny contains msg if {
	f := key_rotation.excessive[_]
	msg := sprintf(
		"NIST SC-28 | %s: KMS key rotation_period is %vs which exceeds 1 year (%vs). Reduce rotation frequency to limit key compromise impact.",
		[f.address, f.seconds, f.limit],
	)
}
