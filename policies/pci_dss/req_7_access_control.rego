package pci_dss.req_7

import rego.v1

import data.controls.privileged_access

# PCI DSS v4.0 — Requirement 7: Restrict Access to System Components and CHD
#
# 7.2.1  All access to system components and cardholder data is assigned based
#         on the minimum necessary for the business function (least privilege).
# 7.2.5  Primitive roles (owner/editor/viewer) are not assigned to project-level
#         principals — they grant excessive, non-specific permissions.
# 7.2.6  All user IDs and authentication factors are managed rigorously.
#         Public IAM members (allUsers) are explicitly prohibited.
#
# This package is a CITATION LAYER over controls.privileged_access, shared with
# soc2.cc6 and nist_800_53.ac — see docs/controls-mapping.md.
#
# Resource types checked (via controls):
#   google_project_iam_member
#   google_project_iam_binding

# ── 7.2.5: Deny primitive project-level IAM roles ───────────────────────────

deny contains msg if {
	f := privileged_access.primitive_role[_]
	msg := sprintf(
		"PCI DSS 7.2.5 | %s: Primitive role '%s' assigned at project level. Use predefined roles scoped to minimum required permissions.",
		[f.address, f.role],
	)
}

# ── 7.2.6: Deny public IAM members on project bindings ──────────────────────
#
# Two rules preserve the distinct wording for the single-member and array-member
# plan shapes.

deny contains msg if {
	f := privileged_access.public_member[_]
	f.shape == "member"
	msg := sprintf(
		"PCI DSS 7.2.6 | %s: IAM member '%s' grants public access to the project. All access must be restricted to authenticated, authorized principals.",
		[f.address, f.member],
	)
}

deny contains msg if {
	f := privileged_access.public_member[_]
	f.shape == "binding"
	msg := sprintf(
		"PCI DSS 7.2.6 | %s: IAM binding includes public member '%s'. All access must be restricted to authenticated, authorized principals.",
		[f.address, f.member],
	)
}
