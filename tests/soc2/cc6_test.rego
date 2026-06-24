package soc2.cc6_test

import rego.v1

import data.soc2.cc6

# ── DENY: primitive roles ────────────────────────────────────────────────────

test_deny_primitive_role_member if {
	count([v | v := cc6.deny[_]; contains(v, "CC6.3")]) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.bad",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/editor", "member": "user:dev@example.com"}},
	}]}
}

test_deny_primitive_role_binding if {
	count([v | v := cc6.deny[_]; contains(v, "CC6.3")]) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_binding.bad",
		"type": "google_project_iam_binding",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/viewer", "members": ["user:bob@example.com"]}},
	}]}
}

# ── DENY: public members ─────────────────────────────────────────────────────

test_deny_all_users if {
	count([v | v := cc6.deny[_]; contains(v, "CC6.1")]) >= 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.public",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/viewer", "member": "allUsers"}},
	}]}
}

# ── DENY: SQL without SSL ────────────────────────────────────────────────────

test_deny_sql_unencrypted_connections if {
	count([v | v := cc6.deny[_]; contains(v, "CC6.6")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.bad",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── DENY: bucket without CMEK ────────────────────────────────────────────────

test_deny_bucket_no_cmek if {
	count([v | v := cc6.deny[_]; contains(v, "CC6.7")]) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.no_cmek",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": true,
			"public_access_prevention": "enforced",
			"encryption": [],
			"versioning": [{"enabled": true}],
		}},
	}]}
}

# ── DENY: SQL without CMEK ───────────────────────────────────────────────────

test_deny_sql_no_cmek if {
	count([v | v := cc6.deny[_]; contains(v, "CC6.7")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_cmek",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": null,
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── ALLOW: compliant IAM member ───────────────────────────────────────────────

test_allow_specific_role if {
	count(cc6.deny) == 0 with input as {"resource_changes": [{
		"address": "google_project_iam_member.good",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/cloudsql.client", "member": "serviceAccount:sa@p.iam.gserviceaccount.com"}},
	}]}
}

# ── ALLOW: compliant SQL ─────────────────────────────────────────────────────

test_allow_sql_encrypted if {
	count(cc6.deny) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.good",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── DENY: bucket with null CMEK key must not bypass check (CC6.7) ────────────

test_deny_bucket_null_cmek_does_not_bypass if {
	count([v | v := cc6.deny[_]; contains(v, "CC6.7")]) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.null_cmek",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": true,
			"public_access_prevention": "enforced",
			"encryption": [{"default_kms_key_name": null}],
			"versioning": [{"enabled": true}],
		}},
	}]}
}
