package nist_800_53.least_privilege

import future.keywords.if
import future.keywords.in

test_deny_owner_grant if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_project_iam_member",
		"name": "broad_grant",
		"change": {"after": {"role": "roles/owner", "member": "user:contractor@example.com"}},
	}]}
}

test_allow_scoped_grant if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_project_iam_member",
		"name": "scoped_grant",
		"change": {"after": {"role": "roles/cloudsql.viewer", "member": "user:contractor@example.com"}},
	}]}
}

test_deny_static_service_account_key if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_service_account_key",
		"name": "ci_deploy_key",
		"change": {"after": {}},
	}]}
}

test_deny_oversized_iam_binding if {
	members := [sprintf("user:person%d@example.com", [i]) | some i in numbers.range(1, 15)]
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_project_iam_binding",
		"name": "broad_binding",
		"change": {"after": {"role": "roles/cloudsql.viewer", "members": members}},
	}]}
}

test_allow_small_iam_binding if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_project_iam_binding",
		"name": "small_binding",
		"change": {"after": {"role": "roles/cloudsql.viewer", "members": ["user:a@example.com", "user:b@example.com"]}},
	}]}
}
