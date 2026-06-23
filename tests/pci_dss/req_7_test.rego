package pci_dss.req_7_test

import rego.v1

import data.pci_dss.req_7

# ── DENY: primitive role on google_project_iam_member ────────────────────────

test_deny_owner_role_member if {
	count(req_7.deny) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.bad",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {
			"project": "my-project",
			"role": "roles/owner",
			"member": "user:admin@example.com",
		}},
	}]}
}

test_deny_editor_role_member if {
	count(req_7.deny) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.editor",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {
			"project": "my-project",
			"role": "roles/editor",
			"member": "serviceAccount:sa@project.iam.gserviceaccount.com",
		}},
	}]}
}

# ── DENY: primitive role on google_project_iam_binding ───────────────────────

test_deny_owner_role_binding if {
	count(req_7.deny) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_binding.bad",
		"type": "google_project_iam_binding",
		"change": {"actions": ["create"], "after": {
			"project": "my-project",
			"role": "roles/owner",
			"members": ["user:admin@example.com"],
		}},
	}]}
}

# ── DENY: public member (allUsers) ───────────────────────────────────────────

test_deny_all_users_member if {
	count([v | v := req_7.deny[_]; contains(v, "allUsers")]) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.public",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {
			"project": "my-project",
			"role": "roles/viewer",
			"member": "allUsers",
		}},
	}]}
}

test_deny_all_authenticated_users if {
	count([v | v := req_7.deny[_]; contains(v, "allAuthenticatedUsers")]) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.semi_public",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {
			"project": "my-project",
			"role": "roles/viewer",
			"member": "allAuthenticatedUsers",
		}},
	}]}
}

# ── ALLOW: least-privilege service account roles ─────────────────────────────

test_allow_specific_role_service_account if {
	count(req_7.deny) == 0 with input as {"resource_changes": [{
		"address": "google_project_iam_member.good",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {
			"project": "my-project",
			"role": "roles/cloudsql.client",
			"member": "serviceAccount:sa-app@my-project.iam.gserviceaccount.com",
		}},
	}]}
}

test_allow_logging_role if {
	count(req_7.deny) == 0 with input as {"resource_changes": [{
		"address": "google_project_iam_member.log_writer",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {
			"project": "my-project",
			"role": "roles/logging.logWriter",
			"member": "serviceAccount:sa-build@ops-project.iam.gserviceaccount.com",
		}},
	}]}
}
