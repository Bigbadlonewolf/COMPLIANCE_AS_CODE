package nist_800_53.au

import rego.v1

import data.lib.utils

# NIST SP 800-53 Rev 5 — AU: Audit and Accountability
#
# AU-2   Event Logging: Identify the types of events that the system is capable
#         of logging in support of the audit function and coordinate the event
#         logging function with other organizations.
# AU-9   Protection of Audit Information: Protect audit information and tools
#         from unauthorized access, modification, and deletion.
# AU-12  Audit Record Generation: Provide audit record generation capability
#         for events defined in AU-2 on organizational information systems.
#
# Resource types checked:
#   google_sql_database_instance
#   google_storage_bucket

# ── AU-2 / AU-12: SQL must have pgaudit logging enabled ──────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	not has_flag(r, "cloudsql.enable_pgaudit", "on")
	msg := sprintf(
		"NIST AU-12 | %s: Missing database flag 'cloudsql.enable_pgaudit = on'. pgaudit is required for DDL/DML event logging per AU-2.",
		[r.address],
	)
}

# ── AU-2: SQL must log connection events ─────────────────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	not has_flag(r, "log_connections", "on")
	msg := sprintf(
		"NIST AU-2 | %s: Missing database flag 'log_connections = on'. Connection events must be audited for accountability.",
		[r.address],
	)
}

# ── AU-9: Storage buckets must have versioning to protect audit integrity ─────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not has_versioning_enabled(r)
	msg := sprintf(
		"NIST AU-9 | %s: Storage bucket versioning is not enabled. Versioning protects audit logs from unauthorized deletion or modification.",
		[r.address],
	)
}

# ── AU-9: Storage buckets must use uniform access to prevent ACL bypass ───────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	r.change.after.uniform_bucket_level_access != true
	msg := sprintf(
		"NIST AU-9 | %s: Storage bucket does not enforce uniform_bucket_level_access. Object-level ACLs can bypass bucket-level audit protections.",
		[r.address],
	)
}

# ── Helpers ──────────────────────────────────────────────────────────────────

has_flag(r, name, value) if {
	settings := r.change.after.settings[_]
	flag := settings.database_flags[_]
	flag.name == name
	flag.value == value
}

has_versioning_enabled(r) if {
	ver := r.change.after.versioning[_]
	ver.enabled == true
}
