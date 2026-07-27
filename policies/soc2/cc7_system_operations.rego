package soc2.cc7

import rego.v1

import data.controls.key_rotation
import data.controls.object_versioning
import data.controls.sql_backups

# SOC2 Trust Service Criteria — CC7: System Operations
#
# CC7.1  Detection and monitoring tools are implemented to identify anomalies,
#         security incidents, and threats on an ongoing basis.
# CC7.2  Anomalies and security events are identified and responded to.
# CC8.1  Change management — system changes follow defined procedures including
#         backup and recovery capabilities.
#
# This package is a CITATION LAYER. Detection logic lives in policies/controls/
# and is shared with pci_dss and nist_800_53 — see docs/controls-mapping.md.
#
# NOTE: CC8.1 previously required a backup_configuration block to exist before
# testing `enabled`, so a Cloud SQL instance with no such block silently passed.
# The shared control treats an absent block as a violation.
#
# Resource types checked (via controls):
#   google_sql_database_instance
#   google_kms_crypto_key
#   google_storage_bucket

# ── CC8.1: SQL must have automated backups ──────────────────────────────────

deny contains msg if {
	f := sql_backups.not_enabled[_]
	msg := sprintf(
		"SOC2 CC8.1 | %s: Cloud SQL automated backups are disabled. Backups are required to support incident recovery and change rollback.",
		[f.address],
	)
}

# ── CC7.1: KMS ENCRYPT_DECRYPT keys must have automatic rotation ────────────

deny contains msg if {
	f := key_rotation.missing[_]
	msg := sprintf(
		"SOC2 CC7.1 | %s: KMS ENCRYPT_DECRYPT key has no rotation_period. Set rotation_period to 7776000s (90 days) or less.",
		[f.address],
	)
}

deny contains msg if {
	f := key_rotation.excessive[_]
	msg := sprintf(
		"SOC2 CC7.1 | %s: KMS key rotation_period is %vs which exceeds 1 year (%vs). Reduce rotation frequency.",
		[f.address, f.seconds, f.limit],
	)
}

# ── CC7.2: Storage buckets must have versioning for tamper detection ────────

deny contains msg if {
	f := object_versioning.not_enabled[_]
	msg := sprintf(
		"SOC2 CC7.2 | %s: Storage bucket versioning is not enabled. Versioning is required to detect and recover from unauthorized object modifications.",
		[f.address],
	)
}
