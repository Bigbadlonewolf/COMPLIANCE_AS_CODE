package nist_800_53.sc

import rego.v1

import data.lib.utils

# NIST SP 800-53 Rev 5 — SC: System and Communications Protection
#
# SC-8   Transmission Confidentiality and Integrity: Implement cryptographic
#         mechanisms to prevent unauthorized disclosure of information during
#         transmission (TLS/SSL enforcement).
# SC-28  Protection of Information at Rest: Implement cryptographic mechanisms
#         to prevent unauthorized disclosure of information at rest (CMEK).
#
# Resource types checked:
#   google_sql_database_instance
#   google_storage_bucket
#   google_kms_crypto_key

# ── SC-8: SQL must enforce TLS for all connections ───────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	settings := r.change.after.settings[_]
	ip_config := settings.ip_configuration[_]
	ip_config.ssl_mode != "ENCRYPTED_ONLY"
	msg := sprintf(
		"NIST SC-8 | %s: Cloud SQL ssl_mode is '%v'. All database connections must use TLS (set ssl_mode = \"ENCRYPTED_ONLY\").",
		[r.address, ip_config.ssl_mode],
	)
}

# ── SC-28: SQL must use CMEK ──────────────────────────────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	r.change.after.encryption_key_name == null
	msg := sprintf(
		"NIST SC-28 | %s: Cloud SQL has no CMEK key. Sensitive data at rest must be protected with a customer-managed encryption key.",
		[r.address],
	)
}

# ── SC-28: Storage buckets must use CMEK ─────────────────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not has_cmek(r)
	msg := sprintf(
		"NIST SC-28 | %s: Storage bucket has no CMEK encryption. Set encryption { default_kms_key_name = \"...\" } to protect data at rest.",
		[r.address],
	)
}

# ── SC-28: KMS ENCRYPT_DECRYPT keys must have automatic rotation ──────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_kms_crypto_key"
	utils.is_active_change(r.change)
	r.change.after.purpose == "ENCRYPT_DECRYPT"
	r.change.after.rotation_period == null
	msg := sprintf(
		"NIST SC-28 | %s: KMS crypto key has no rotation_period. Keys must rotate automatically to limit the impact of key compromise.",
		[r.address],
	)
}

# ── SC-28: KMS rotation period must not exceed 1 year ────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_kms_crypto_key"
	utils.is_active_change(r.change)
	r.change.after.purpose == "ENCRYPT_DECRYPT"
	r.change.after.rotation_period != null
	period_seconds := to_number(trim_suffix(r.change.after.rotation_period, "s"))
	period_seconds > utils.one_year_seconds
	msg := sprintf(
		"NIST SC-28 | %s: KMS key rotation_period is %vs which exceeds 1 year (%vs). Reduce rotation frequency to limit key compromise impact.",
		[r.address, period_seconds, utils.one_year_seconds],
	)
}

# ── Helpers ──────────────────────────────────────────────────────────────────

has_cmek(r) if {
	enc := r.change.after.encryption[_]
	enc.default_kms_key_name != null
	enc.default_kms_key_name != ""
}
