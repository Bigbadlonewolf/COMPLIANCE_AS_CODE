package nist_800_53.least_privilege

import rego.v1

# Primitive IAM role tests (including roles/owner) are in tests/nist_800_53/ac_test.rego.
# This file covers service account keys and oversized IAM bindings.

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
