package pci_dss.req_7

import rego.v1

import data.lib.utils

# PCI DSS v4.0 — Requirement 7: Restrict Access to System Components and CHD
#
# 7.2.1  All access to system components and cardholder data is assigned based
#         on the minimum necessary for the business function (least privilege).
# 7.2.5  Primitive roles (owner/editor/viewer) are not assigned to project-level
#         principals — they grant excessive, non-specific permissions.
# 7.2.6  All user IDs and authentication factors are managed rigorously.
#         Public IAM members (allUsers) are explicitly prohibited.
#
# Resource types checked:
#   google_project_iam_member
#   google_project_iam_binding

# ── Rule 1: Deny primitive project-level IAM roles ──────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type in {"google_project_iam_member", "google_project_iam_binding"}
	utils.is_active_change(r.change)
	r.change.after.role in utils.primitive_roles
	msg := sprintf(
		"PCI DSS 7.2.5 | %s: Primitive role '%s' assigned at project level. Use predefined roles scoped to minimum required permissions.",
		[r.address, r.change.after.role],
	)
}

# ── Rule 2: Deny public IAM members on project bindings ─────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_project_iam_member"
	utils.is_active_change(r.change)
	r.change.after.member in utils.public_members
	msg := sprintf(
		"PCI DSS 7.2.6 | %s: IAM member '%s' grants public access to the project. All access must be restricted to authenticated, authorized principals.",
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
		"PCI DSS 7.2.6 | %s: IAM binding includes public member '%s'. All access must be restricted to authenticated, authorized principals.",
		[r.address, member],
	)
}
