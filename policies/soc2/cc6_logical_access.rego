package soc2.cc6

import rego.v1

import data.controls.cmek_at_rest
import data.controls.privileged_access
import data.controls.tls_in_transit

# SOC2 Trust Service Criteria — CC6: Logical and Physical Access Controls
#
# CC6.1  Logical access security measures restrict access to information assets
#         and facilities to authorized personnel only.
# CC6.3  Role-based access is implemented. Access is recertified periodically.
# CC6.6  Transmission of sensitive information uses encryption.
# CC6.7  At-rest encryption protects sensitive information on storage media.
#
# This package is a CITATION LAYER. Detection logic lives in policies/controls/
# and is shared with pci_dss and nist_800_53 — see docs/controls-mapping.md.
#
# NOTE: CC6.6 previously required an ip_configuration block to exist before
# testing ssl_mode, so a Cloud SQL instance with no such block silently passed.
# The shared control treats an absent block as a violation, which means this
# criterion now fires on plans it used to miss.
#
# Resource types checked (via controls):
#   google_project_iam_member
#   google_project_iam_binding
#   google_sql_database_instance
#   google_storage_bucket

# ── CC6.3: Deny primitive project-level roles ───────────────────────────────

deny contains msg if {
	f := privileged_access.primitive_role[_]
	msg := sprintf(
		"SOC2 CC6.3 | %s: Primitive role '%s' grants project-wide permissions. Define granular roles aligned to job functions.",
		[f.address, f.role],
	)
}

# ── CC6.1: Deny public IAM members ──────────────────────────────────────────

deny contains msg if {
	f := privileged_access.public_member[_]
	f.shape == "member"
	msg := sprintf(
		"SOC2 CC6.1 | %s: IAM member '%s' grants unauthenticated public access. Access must be restricted to identified and authenticated principals.",
		[f.address, f.member],
	)
}

deny contains msg if {
	f := privileged_access.public_member[_]
	f.shape == "binding"
	msg := sprintf(
		"SOC2 CC6.1 | %s: IAM binding includes public member '%s'. All access must require authentication.",
		[f.address, f.member],
	)
}

# ── CC6.6: SQL must enforce encrypted-only connections ──────────────────────

deny contains msg if {
	f := tls_in_transit.not_enforced[_]
	msg := sprintf(
		"SOC2 CC6.6 | %s: Cloud SQL ssl_mode is '%v'. All database connections must be encrypted (set ssl_mode = \"ENCRYPTED_ONLY\").",
		[f.address, f.observed],
	)
}

# ── CC6.7: Storage buckets must use CMEK ────────────────────────────────────

deny contains msg if {
	f := cmek_at_rest.bucket_missing[_]
	msg := sprintf(
		"SOC2 CC6.7 | %s: Storage bucket lacks CMEK encryption. Sensitive data at rest must be protected with customer-managed keys.",
		[f.address],
	)
}

# ── CC6.7: SQL must use CMEK ────────────────────────────────────────────────

deny contains msg if {
	f := cmek_at_rest.sql_missing[_]
	msg := sprintf(
		"SOC2 CC6.7 | %s: Cloud SQL instance lacks CMEK encryption. Set encryption_key_name to a customer-managed KMS key.",
		[f.address],
	)
}
