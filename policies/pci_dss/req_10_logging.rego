package pci_dss.req_10

import rego.v1

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

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	settings := r.change.after.settings[_]
	backup := settings.backup_configuration[_]
	backup.enabled != true
	msg := sprintf(
		"PCI DSS 10.3.2 | %s: Cloud SQL backup_configuration.enabled is false. Automated backups are required to protect audit and transaction logs.",
		[r.address],
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
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not has_versioning_enabled(r)
	msg := sprintf(
		"PCI DSS 10.3.2 | %s: Storage bucket does not have versioning enabled. Versioning is required to detect and recover from unauthorized log modifications.",
		[r.address],
	)
}

# ── Helpers ──────────────────────────────────────────────────────────────────

has_pgaudit_enabled(r) if {
	settings := r.change.after.settings[_]
	flag := settings.database_flags[_]
	flag.name == "cloudsql.enable_pgaudit"
	flag.value == "on"
}

has_versioning_enabled(r) if {
	ver := r.change.after.versioning[_]
	ver.enabled == true
}
