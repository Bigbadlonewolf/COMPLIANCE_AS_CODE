package soc2.cc6

import rego.v1

import data.lib.utils

# SOC2 Trust Service Criteria — CC6: Logical and Physical Access Controls
#
# CC6.1  Logical access security measures restrict access to information assets
#         and facilities to authorized personnel only.
# CC6.3  Role-based access is implemented. Access is recertified periodically.
# CC6.6  Transmission of sensitive information uses encryption.
# CC6.7  At-rest encryption protects sensitive information on storage media.
#
# Resource types checked:
#   google_project_iam_member
#   google_project_iam_binding
#   google_sql_database_instance
#   google_storage_bucket

# ── CC6.1 / CC6.3: Deny primitive project-level roles ───────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type in {"google_project_iam_member", "google_project_iam_binding"}
	utils.is_active_change(r.change)
	r.change.after.role in utils.primitive_roles
	msg := sprintf(
		"SOC2 CC6.3 | %s: Primitive role '%s' grants project-wide permissions. Define granular roles aligned to job functions.",
		[r.address, r.change.after.role],
	)
}

# ── CC6.1: Deny public IAM members ──────────────────────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_project_iam_member"
	utils.is_active_change(r.change)
	r.change.after.member in utils.public_members
	msg := sprintf(
		"SOC2 CC6.1 | %s: IAM member '%s' grants unauthenticated public access. Access must be restricted to identified and authenticated principals.",
		[r.address, r.change.after.member],
	)
}

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_project_iam_binding"
	utils.is_active_change(r.change)
	member := r.change.after.members[_]
	member in utils.public_members
	msg := sprintf(
		"SOC2 CC6.1 | %s: IAM binding includes public member '%s'. All access must require authentication.",
		[r.address, member],
	)
}

# ── CC6.6: SQL must enforce encrypted-only connections ───────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	settings := r.change.after.settings[_]
	ip_config := settings.ip_configuration[_]
	ip_config.ssl_mode != "ENCRYPTED_ONLY"
	msg := sprintf(
		"SOC2 CC6.6 | %s: Cloud SQL ssl_mode is '%v'. All database connections must be encrypted (set ssl_mode = \"ENCRYPTED_ONLY\").",
		[r.address, ip_config.ssl_mode],
	)
}

# ── CC6.7: Storage buckets must use CMEK ────────────────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not has_cmek(r)
	msg := sprintf(
		"SOC2 CC6.7 | %s: Storage bucket lacks CMEK encryption. Sensitive data at rest must be protected with customer-managed keys.",
		[r.address],
	)
}

# ── CC6.7: SQL must use CMEK ─────────────────────────────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	r.change.after.encryption_key_name == null
	msg := sprintf(
		"SOC2 CC6.7 | %s: Cloud SQL instance lacks CMEK encryption. Set encryption_key_name to a customer-managed KMS key.",
		[r.address],
	)
}

# ── Helpers ──────────────────────────────────────────────────────────────────

has_cmek(r) if {
	enc := r.change.after.encryption[_]
	enc.default_kms_key_name
	enc.default_kms_key_name != ""
}
