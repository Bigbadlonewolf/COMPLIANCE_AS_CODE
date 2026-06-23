package pci_dss.req_2_test

import rego.v1

import data.pci_dss.req_2

# ── DENY: SQL with public IP ─────────────────────────────────────────────────

test_deny_sql_public_ip if {
	count(req_2.deny) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.bad",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{"ip_configuration": [{"ipv4_enabled": true, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── DENY: storage bucket without uniform access ──────────────────────────────

test_deny_bucket_no_uniform_access if {
	count([v | v := req_2.deny[_]; contains(v, "uniform_bucket_level_access")]) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.bad",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": false,
			"public_access_prevention": "enforced",
			"encryption": [{"default_kms_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k"}],
			"versioning": [{"enabled": true}],
		}},
	}]}
}

# ── DENY: storage bucket without public access prevention ────────────────────

test_deny_bucket_no_public_access_prevention if {
	count([v | v := req_2.deny[_]; contains(v, "public_access_prevention")]) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.bad",
		"type": "google_storage_bucket",
		"change": {"actions": ["create"], "after": {
			"uniform_bucket_level_access": true,
			"public_access_prevention": "inherited",
			"encryption": [{"default_kms_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k"}],
			"versioning": [{"enabled": true}],
		}},
	}]}
}

# ── ALLOW: compliant SQL (private IP) ───────────────────────────────────────

test_allow_sql_private_ip if {
	count(req_2.deny) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.good",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── ALLOW: compliant storage bucket ─────────────────────────────────────────

test_allow_compliant_bucket if {
	count(req_2.deny) == 0 with input as {"resource_changes": [{
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
