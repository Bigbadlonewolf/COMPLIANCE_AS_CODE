package pci_dss.req_2

import rego.v1

import data.lib.utils

# PCI DSS v4.0 — Requirement 2: Apply Secure Configurations to All System Components
#
# 2.2.1  Configuration standards address all known security vulnerabilities and
#         are consistent with industry-hardening standards.
#
# Resource types checked:
#   google_sql_database_instance
#   google_storage_bucket

# ── Rule 1: SQL instances must not have a public IPv4 address ───────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	settings := r.change.after.settings[_]
	ip_config := settings.ip_configuration[_]
	ip_config.ipv4_enabled == true
	msg := sprintf(
		"PCI DSS 2.2.1 | %s: Cloud SQL instance has a public IPv4 address (ipv4_enabled = true). Use Private Service Connect or VPC peering.",
		[r.address],
	)
}

# ── Rule 2: Storage buckets must enable uniform bucket-level access ─────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	r.change.after.uniform_bucket_level_access != true
	msg := sprintf(
		"PCI DSS 2.2.1 | %s: Storage bucket does not enforce uniform_bucket_level_access. Legacy ACLs allow object-level permission bypass.",
		[r.address],
	)
}

# ── Rule 3: Storage buckets must enforce public access prevention ───────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	r.change.after.public_access_prevention != "enforced"
	msg := sprintf(
		"PCI DSS 2.2.1 | %s: Storage bucket public_access_prevention is not 'enforced'. Set it to 'enforced' to block all public access.",
		[r.address],
	)
}
