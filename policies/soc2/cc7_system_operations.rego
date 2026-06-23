package soc2.cc7

import rego.v1

import data.lib.utils

# SOC2 Trust Service Criteria — CC7: System Operations
#
# CC7.1  Detection and monitoring tools are implemented to identify anomalies,
#         security incidents, and threats on an ongoing basis.
# CC7.2  Anomalies and security events are identified and responded to.
# CC8.1  Change management — system changes follow defined procedures including
#         backup and recovery capabilities.
#
# Resource types checked:
#   google_sql_database_instance
#   google_kms_crypto_key
#   google_storage_bucket

# ── CC8.1: SQL must have automated backups with PITR enabled ────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	settings := r.change.after.settings[_]
	backup := settings.backup_configuration[_]
	backup.enabled != true
	msg := sprintf(
		"SOC2 CC8.1 | %s: Cloud SQL automated backups are disabled. Backups are required to support incident recovery and change rollback.",
		[r.address],
	)
}

# ── CC7.1: KMS ENCRYPT_DECRYPT keys must have automatic rotation ─────────────
# Keys without rotation create a long-lived secret that undermines key hygiene.

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_kms_crypto_key"
	utils.is_active_change(r.change)
	r.change.after.purpose == "ENCRYPT_DECRYPT"
	r.change.after.rotation_period == null
	msg := sprintf(
		"SOC2 CC7.1 | %s: KMS ENCRYPT_DECRYPT key has no rotation_period. Set rotation_period to 7776000s (90 days) or less.",
		[r.address],
	)
}

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_kms_crypto_key"
	utils.is_active_change(r.change)
	r.change.after.purpose == "ENCRYPT_DECRYPT"
	r.change.after.rotation_period != null
	period_seconds := to_number(trim_suffix(r.change.after.rotation_period, "s"))
	period_seconds > utils.one_year_seconds
	msg := sprintf(
		"SOC2 CC7.1 | %s: KMS key rotation_period is %vs which exceeds 1 year (%vs). Reduce rotation frequency.",
		[r.address, period_seconds, utils.one_year_seconds],
	)
}

# ── CC7.2: Storage buckets must have versioning for tamper detection ──────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not has_versioning_enabled(r)
	msg := sprintf(
		"SOC2 CC7.2 | %s: Storage bucket versioning is not enabled. Versioning is required to detect and recover from unauthorized object modifications.",
		[r.address],
	)
}

# ── Helpers ──────────────────────────────────────────────────────────────────

has_versioning_enabled(r) if {
	ver := r.change.after.versioning[_]
	ver.enabled == true
}
