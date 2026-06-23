package pci_dss.req_10_test

import rego.v1

import data.pci_dss.req_10

# ── DENY: SQL without backups ────────────────────────────────────────────────

test_deny_sql_backups_disabled if {
	count([v | v := req_10.deny[_]; contains(v, "backup")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_backup",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{
				"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}],
				"backup_configuration": [{"enabled": false}],
				"database_flags": [{"name": "cloudsql.enable_pgaudit", "value": "on"}, {"name": "log_connections", "value": "on"}],
			}],
		}},
	}]}
}

# ── DENY: SQL without pgaudit ────────────────────────────────────────────────

test_deny_sql_no_pgaudit if {
	count([v | v := req_10.deny[_]; contains(v, "pgaudit")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_pgaudit",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{
				"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}],
				"backup_configuration": [{"enabled": true}],
				"database_flags": [],
			}],
		}},
	}]}
}

# ── DENY: storage bucket without versioning ───────────────────────────────────

test_deny_bucket_no_versioning if {
	count(req_10.deny) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.no_versioning",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": true,
			"public_access_prevention": "enforced",
			"encryption": [{"default_kms_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k"}],
			"versioning": [],
		}},
	}]}
}

# ── ALLOW: fully compliant SQL with all audit flags ───────────────────────────

test_allow_compliant_sql_all_audit if {
	count(req_10.deny) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.good",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{
				"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}],
				"backup_configuration": [{"enabled": true, "point_in_time_recovery_enabled": true}],
				"database_flags": [
					{"name": "cloudsql.enable_pgaudit", "value": "on"},
					{"name": "log_connections", "value": "on"},
					{"name": "log_disconnections", "value": "on"},
				],
			}],
		}},
	}]}
}

# ── ALLOW: storage bucket with versioning ────────────────────────────────────

test_allow_bucket_with_versioning if {
	count(req_10.deny) == 0 with input as {"resource_changes": [{
		"address": "google_storage_bucket.good",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": true,
			"public_access_prevention": "enforced",
			"encryption": [{"default_kms_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k"}],
			"versioning": [{"enabled": true}],
		}},
	}]}
}
