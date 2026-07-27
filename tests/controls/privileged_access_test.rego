package controls.privileged_access_test

import rego.v1

import data.controls.privileged_access

# This control was pure triplication — pci_dss/req_7, soc2/cc6 and nist_800_53/ac
# each carried byte-identical logic and differed only in message wording. These
# tests pin the shared behaviour; the framework tests assert only the citations.

iam(type, after) := {"resource_changes": [{
	"address": sprintf("%s.t", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after},
}]}

# ── Primitive roles ─────────────────────────────────────────────────────────

test_owner_role_on_member_is_a_finding if {
	f := privileged_access.primitive_role[_] with input as iam("google_project_iam_member", {"role": "roles/owner"})
	f.role == "roles/owner"
}

test_editor_role_on_binding_is_a_finding if {
	count(privileged_access.primitive_role) == 1 with input as iam("google_project_iam_binding", {"role": "roles/editor"})
}

test_viewer_role_is_a_finding if {
	count(privileged_access.primitive_role) == 1 with input as iam("google_project_iam_member", {"role": "roles/viewer"})
}

# roles/viewer is primitive; roles/storage.objectViewer is not. Substring-style
# matching would wrongly flag the latter.
test_predefined_role_is_allowed if {
	count(privileged_access.primitive_role) == 0 with input as iam("google_project_iam_member", {"role": "roles/storage.objectViewer"})
}

# ── Public members ──────────────────────────────────────────────────────────

test_all_users_on_member_is_a_finding if {
	f := privileged_access.public_member[_] with input as iam("google_project_iam_member", {"member": "allUsers"})
	f.member == "allUsers"
	f.shape == "member"
}

test_all_authenticated_users_is_a_finding if {
	count(privileged_access.public_member) == 1 with input as iam("google_project_iam_member", {"member": "allAuthenticatedUsers"})
}

# The binding shape carries a members ARRAY, not a single member. The shape tag is
# what lets each framework keep its distinct wording for the two cases.
test_public_member_inside_binding_array_is_a_finding if {
	f := privileged_access.public_member[_] with input as iam("google_project_iam_binding", {"members": ["user:a@example.com", "allUsers"]})
	f.member == "allUsers"
	f.shape == "binding"
}

test_named_members_are_allowed if {
	count(privileged_access.public_member) == 0 with input as iam("google_project_iam_binding", {"members": ["user:a@example.com", "group:eng@example.com"]})
}

test_destroy_only_change_is_ignored if {
	count(privileged_access.primitive_role) == 0 with input as {"resource_changes": [{
		"address": "google_project_iam_member.gone",
		"type": "google_project_iam_member",
		"change": {"actions": ["delete"], "after": null},
	}]}
}
