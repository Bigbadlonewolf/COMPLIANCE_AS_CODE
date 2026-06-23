package soc2.cc7_test

import rego.v1

import data.soc2.cc7

# ── DENY: SQL without backups ────────────────────────────────────────────────

test_deny_sql_no_backups if {
	count([v | v := cc7.deny[_]; contains(v, "CC8.1")]) == 1 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.no_backup",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"settings": [{"backup_configuration": [{"enabled": false}]}],
		}},
	}]}
}

# ── DENY: KMS key with no rotation ───────────────────────────────────────────

test_deny_kms_no_rotation if {
	count([v | v := cc7.deny[_]; contains(v, "no rotation_period")]) == 1 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.no_rotation",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {"name": "k", "purpose": "ENCRYPT_DECRYPT", "rotation_period": null}},
	}]}
}

# ── DENY: KMS key with rotation > 1 year ─────────────────────────────────────

test_deny_kms_rotation_too_long if {
	count([v | v := cc7.deny[_]; contains(v, "exceeds 1 year")]) == 1 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.long_rotation",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {"name": "k", "purpose": "ENCRYPT_DECRYPT", "rotation_period": "63072000s"}},
	}]}
}

# ── DENY: bucket without versioning ──────────────────────────────────────────

test_deny_bucket_no_versioning if {
	count([v | v := cc7.deny[_]; contains(v, "CC7.2")]) == 1 with input as {"resource_changes": [{
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

# ── ALLOW: SQL with backups ───────────────────────────────────────────────────

test_allow_sql_with_backups if {
	count(cc7.deny) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.good",
		"type": "google_sql_database_instance",
		"change": {"actions": ["create"], "after": {
			"settings": [{"backup_configuration": [{"enabled": true, "point_in_time_recovery_enabled": true}]}],
		}},
	}]}
}

# ── ALLOW: KMS key with 90-day rotation ──────────────────────────────────────

test_allow_kms_90_day_rotation if {
	count(cc7.deny) == 0 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.good",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {"name": "k", "purpose": "ENCRYPT_DECRYPT", "rotation_period": "7776000s"}},
	}]}
}

# ── ALLOW: asymmetric key without rotation (not ENCRYPT_DECRYPT) ─────────────

test_allow_asymmetric_key if {
	count(cc7.deny) == 0 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.signing",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {"name": "k", "purpose": "ASYMMETRIC_SIGN", "rotation_period": null}},
	}]}
}
