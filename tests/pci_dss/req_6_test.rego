package pci_dss.req_6_test

import rego.v1

import data.pci_dss.req_6

# ── DENY: SQL without SSL enforcement ────────────────────────────────────────

test_deny_sql_no_ssl if {
	count([v | v := req_6.deny[_]; contains(v, "ssl_mode")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.bad_ssl",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── DENY: SQL without CMEK ───────────────────────────────────────────────────

test_deny_sql_no_cmek if {
	count([v | v := req_6.deny[_]; contains(v, "CMEK")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_cmek",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": null,
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── DENY: storage bucket without CMEK ────────────────────────────────────────

test_deny_bucket_no_cmek if {
	count(req_6.deny) == 1 with input as {"resource_changes": [{
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

# ── DENY: KMS key without rotation ───────────────────────────────────────────

test_deny_kms_no_rotation if {
	count(req_6.deny) == 1 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.no_rotation",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {
			"name": "my-key",
			"purpose": "ENCRYPT_DECRYPT",
			"rotation_period": null,
		}},
	}]}
}

# ── ALLOW: fully compliant SQL ───────────────────────────────────────────────

test_allow_compliant_sql if {
	count(req_6.deny) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.good",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/sql",
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── ALLOW: asymmetric signing key skips rotation check ───────────────────────

test_allow_asymmetric_key_no_rotation if {
	count(req_6.deny) == 0 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.signing",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {
			"name": "signing-key",
			"purpose": "ASYMMETRIC_SIGN",
			"rotation_period": null,
		}},
	}]}
}

# ── DENY: KMS rotation period exceeds 1 year ─────────────────────────────────

test_deny_kms_rotation_period_exceeds_one_year if {
	count([v | v := req_6.deny[_]; contains(v, "exceeds 1 year")]) == 1 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.slow_rotation",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {
			"name": "slow-key",
			"purpose": "ENCRYPT_DECRYPT",
			"rotation_period": "63072001s",
		}},
	}]}
}

# ── ALLOW: KMS rotation period within 1 year ─────────────────────────────────

test_allow_kms_rotation_period_within_one_year if {
	count(req_6.deny) == 0 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.good_rotation",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {
			"name": "good-key",
			"purpose": "ENCRYPT_DECRYPT",
			"rotation_period": "7776000s",
		}},
	}]}
}
