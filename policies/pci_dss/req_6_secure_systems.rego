package pci_dss.req_6

import rego.v1

import data.lib.utils

# PCI DSS v4.0 — Requirement 6: Develop and Maintain Secure Systems and Software
#
# 6.3.5  All cardholder data (CHD) storage is encrypted at rest using
#         strong cryptography. CMEK is required for CDE resources.
# 6.5.3  All transmission of CHD over open, public networks is encrypted.
#
# Resource types checked:
#   google_sql_database_instance
#   google_storage_bucket
#   google_kms_crypto_key

# ── Rule 1: SQL instances must enforce SSL-only connections ─────────────────

# Fires when ssl_mode is wrong AND when the ip_configuration block (or ssl_mode
# itself) is absent. GCP does not enforce TLS unless told to, so an absent
# ip_configuration is the same violation as an explicit non-ENCRYPTED_ONLY value.
deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	not ssl_enforced(r)
	msg := sprintf(
		"PCI DSS 6.5.3 | %s: Cloud SQL does not enforce ssl_mode = 'ENCRYPTED_ONLY' (ip_configuration block or ssl_mode is absent). All database connections must use TLS.",
		[r.address],
	)
}

# ── Rule 2: SQL instances must use CMEK encryption ──────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	r.change.after.encryption_key_name == null
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: Cloud SQL instance has no CMEK key (encryption_key_name not set). CHD at rest must use customer-managed encryption.",
		[r.address],
	)
}

# ── Rule 3: Storage buckets must use CMEK encryption ────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not has_cmek(r)
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: Storage bucket has no CMEK encryption configured. Set encryption { default_kms_key_name = \"...\" }.",
		[r.address],
	)
}

# ── Rule 4a: KMS ENCRYPT_DECRYPT keys must have rotation set ────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_kms_crypto_key"
	utils.is_active_change(r.change)
	r.change.after.purpose == "ENCRYPT_DECRYPT"
	r.change.after.rotation_period == null
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: KMS crypto key has no rotation_period set. Automatic key rotation is required for CHD encryption keys.",
		[r.address],
	)
}

# ── Rule 4b: KMS rotation period must not exceed 1 year ─────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_kms_crypto_key"
	utils.is_active_change(r.change)
	r.change.after.purpose == "ENCRYPT_DECRYPT"
	r.change.after.rotation_period != null
	period_seconds := to_number(trim_suffix(r.change.after.rotation_period, "s"))
	period_seconds > utils.one_year_seconds
	msg := sprintf(
		"PCI DSS 6.3.5 | %s: KMS key rotation_period is %vs which exceeds 1 year (%vs). Keys encrypting CHD must rotate at least annually.",
		[r.address, period_seconds, utils.one_year_seconds],
	)
}

# ── Helpers ─────────────────────────────────────────────────────────────────

has_cmek(r) if {
	enc := r.change.after.encryption[_]
	enc.default_kms_key_name
	enc.default_kms_key_name != ""
}

ssl_enforced(r) if {
	settings := r.change.after.settings[_]
	settings.ip_configuration[_].ssl_mode == "ENCRYPTED_ONLY"
}
