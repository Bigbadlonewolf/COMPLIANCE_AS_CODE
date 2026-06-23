package nist_800_53.sc_test

import rego.v1

import data.nist_800_53.sc

# ── DENY: SQL without TLS (SC-8) ────────────────────────────────────────────

test_deny_sql_no_tls if {
	count([v | v := sc.deny[_]; contains(v, "SC-8")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_tls",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── DENY: SQL without CMEK (SC-28) ──────────────────────────────────────────

test_deny_sql_no_cmek if {
	count([v | v := sc.deny[_]; contains(v, "Cloud SQL has no CMEK")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_cmek",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": null,
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── DENY: bucket without CMEK (SC-28) ────────────────────────────────────────

test_deny_bucket_no_cmek if {
	count([v | v := sc.deny[_]; contains(v, "Storage bucket")]) == 1 with input as {"resource_changes": [{
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

# ── DENY: KMS key without rotation (SC-28) ───────────────────────────────────

test_deny_kms_no_rotation if {
	count([v | v := sc.deny[_]; contains(v, "KMS crypto key has no rotation_period")]) == 1 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.no_rotation",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {"name": "k", "purpose": "ENCRYPT_DECRYPT", "rotation_period": null}},
	}]}
}

# ── ALLOW: fully compliant SQL ────────────────────────────────────────────────

test_allow_compliant_sql if {
	count(sc.deny) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.good",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
			"settings": [{"ip_configuration": [{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}], "backup_configuration": [{"enabled": true}], "database_flags": []}],
		}},
	}]}
}

# ── ALLOW: compliant bucket with CMEK ────────────────────────────────────────

test_allow_bucket_with_cmek if {
	count(sc.deny) == 0 with input as {"resource_changes": [{
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

# ── ALLOW: asymmetric key without rotation ────────────────────────────────────

test_allow_asymmetric_key_no_rotation if {
	count(sc.deny) == 0 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.signing",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {"name": "k", "purpose": "ASYMMETRIC_SIGN", "rotation_period": null}},
	}]}
}
