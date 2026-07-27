package pci_dss.req_10

import rego.v1

import data.controls.object_versioning
import data.controls.sql_backups
import data.lib.utils

# PCI DSS v4.0 — Requirement 10: Log and Monitor All Access to System Components and CHD
#
# 10.2.1  Implement audit logs to capture all individual user access to CHD,
#          all actions taken by root/admin, all access to audit trails,
#          and all invalid logical access attempts.
# 10.3.2  Protect audit log files from unauthorized modifications.
# 10.5.1  Retain audit logs for at least 12 months.
#
# Resource types checked:
#   google_sql_database_instance
#   google_storage_bucket

# ── Rule 1: SQL instances must have automated backups enabled ────────────────

# Fires when backups are disabled AND when the backup_configuration block is
# absent. No backups is the same violation whether it is explicit or by omission.
deny contains msg if {
	f := sql_backups.not_enabled[_]
	msg := sprintf(
		"PCI DSS 10.3.2 | %s: Cloud SQL backup_configuration is missing or enabled is not true. Automated backups are required to protect audit and transaction logs.",
		[f.address],
	)
}

# ── Rule 2: SQL instances must have pgaudit enabled ──────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	not has_pgaudit_enabled(r)
	msg := sprintf(
		"PCI DSS 10.2.1 | %s: Cloud SQL instance is missing the 'cloudsql.enable_pgaudit' database flag set to 'on'. pgaudit is required for DDL/DML audit logging.",
		[r.address],
	)
}

# ── Rule 3: Storage buckets used for logs must enable versioning ─────────────

deny contains msg if {
	f := object_versioning.not_enabled[_]
	msg := sprintf(
		"PCI DSS 10.3.2 | %s: Storage bucket does not have versioning enabled. Versioning is required to detect and recover from unauthorized log modifications.",
		[f.address],
	)
}

# ── Helpers ──────────────────────────────────────────────────────────────────
#
# pgaudit stays local: it is a PCI-specific logging requirement with no SOC 2 or
# NIST counterpart in this repo, so promoting it to controls/ would create a
# shared package with exactly one consumer.

has_pgaudit_enabled(r) if {
	settings := r.change.after.settings[_]
	flag := settings.database_flags[_]
	flag.name == "cloudsql.enable_pgaudit"
	flag.value == "on"
}
