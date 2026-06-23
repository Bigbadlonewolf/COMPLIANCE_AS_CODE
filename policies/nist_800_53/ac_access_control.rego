package nist_800_53.ac

import rego.v1

import data.lib.utils

# NIST SP 800-53 Rev 5 — AC: Access Control
#
# AC-2   Account Management: Authorize access consistent with organizational
#         mission and business functions. Disable or remove accounts when no
#         longer required.
# AC-3   Access Enforcement: Enforce approved authorizations for logical access
#         to information and system resources using access control policies.
# AC-6   Least Privilege: Employ the principle of least privilege, allowing only
#         authorized accesses necessary for users to accomplish assigned tasks.
# AC-17  Remote Access: Establish usage restrictions, configuration requirements,
#         and connection requirements for remote access sessions.
#
# Resource types checked:
#   google_project_iam_member
#   google_project_iam_binding
#   google_compute_firewall

# ── AC-3 / AC-6: Deny primitive project-level roles ─────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type in {"google_project_iam_member", "google_project_iam_binding"}
	utils.is_active_change(r.change)
	r.change.after.role in utils.primitive_roles
	msg := sprintf(
		"NIST AC-6 | %s: Primitive role '%s' violates least-privilege. Assign purpose-specific predefined roles (e.g. roles/cloudsql.client, roles/storage.objectViewer).",
		[r.address, r.change.after.role],
	)
}

# ── AC-3: Deny public IAM members ───────────────────────────────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_project_iam_member"
	utils.is_active_change(r.change)
	r.change.after.member in utils.public_members
	msg := sprintf(
		"NIST AC-3 | %s: Member '%s' grants access without authentication. All project access must be restricted to identified principals.",
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
		"NIST AC-3 | %s: Binding includes public member '%s'. Access control policies must enforce authenticated access.",
		[r.address, member],
	)
}

# ── AC-17: Deny unrestricted remote management port exposure ─────────────────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_compute_firewall"
	utils.is_active_change(r.change)
	r.change.after.direction == "INGRESS"
	r.change.after.source_ranges[_] == "0.0.0.0/0"
	allowed := r.change.after.allow[_]
	port := allowed.ports[_]
	port in utils.sensitive_ports
	msg := sprintf(
		"NIST AC-17 | %s: Firewall rule allows remote access port %s from 0.0.0.0/0. Remote access must originate from authorized, defined source ranges.",
		[r.address, port],
	)
}
