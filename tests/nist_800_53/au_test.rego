package nist_800_53.au_test

import rego.v1

import data.nist_800_53.au

# ── DENY: SQL without pgaudit (AU-12) ────────────────────────────────────────

test_deny_sql_no_pgaudit if {
	count([v | v := au.deny[_]; contains(v, "AU-12")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_pgaudit",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"settings": [{"database_flags": [], "backup_configuration": [{"enabled": true}], "ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}]}],
		}},
	}]}
}

# ── DENY: SQL without log_connections (AU-2) ─────────────────────────────────

test_deny_sql_no_log_connections if {
	count([v | v := au.deny[_]; contains(v, "AU-2")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_log_conn",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"settings": [{
				"database_flags": [{"name": "cloudsql.enable_pgaudit", "value": "on"}],
				"backup_configuration": [{"enabled": true}],
				"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}],
			}],
		}},
	}]}
}

# ── DENY: bucket without versioning (AU-9) ───────────────────────────────────

test_deny_bucket_no_versioning if {
	count([v | v := au.deny[_]; contains(v, "versioning")]) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.no_ver",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": true,
			"public_access_prevention": "enforced",
			"encryption": [{"default_kms_key_name": "k"}],
			"versioning": [],
		}},
	}]}
}

# ── DENY: bucket without uniform access (AU-9) ───────────────────────────────

test_deny_bucket_no_uniform_access if {
	count([v | v := au.deny[_]; contains(v, "uniform_bucket_level_access")]) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.no_uniform",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": false,
			"public_access_prevention": "enforced",
			"encryption": [{"default_kms_key_name": "k"}],
			"versioning": [{"enabled": true}],
		}},
	}]}
}

# ── ALLOW: fully compliant SQL ────────────────────────────────────────────────

test_allow_sql_full_audit if {
	count(au.deny) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.good",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"settings": [{
				"database_flags": [
					{"name": "cloudsql.enable_pgaudit", "value": "on"},
					{"name": "log_connections", "value": "on"},
					{"name": "log_disconnections", "value": "on"},
				],
				"backup_configuration": [{"enabled": true}],
				"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}],
			}],
		}},
	}]}
}
