package nist_800_53.sc_test

import rego.v1

import data.nist_800_53.sc

# sc is a CITATION LAYER over controls.tls_in_transit, controls.cmek_at_rest and
# controls.key_rotation. Detection logic — absent blocks, null fields, the
# asymmetric-key exclusion, rotation boundaries — is asserted once in
# tests/controls/. These tests prove only that NIST cites the right control.

sql(after) := {"resource_changes": [{
	"address": "google_sql_database_instance.t",
	"type": "google_sql_database_instance",
	"change": {"actions": ["create"], "after": after},
}]}

bucket(after) := {"resource_changes": [{
	"address": "google_storage_bucket.t",
	"type": "google_storage_bucket",
	"change": {"actions": ["create"], "after": after},
}]}

key(after) := {"resource_changes": [{
	"address": "google_kms_crypto_key.t",
	"type": "google_kms_crypto_key",
	"change": {"actions": ["create"], "after": after},
}]}

cited(msgs, citation) if count([m | m := msgs[_]; startswith(m, citation)]) > 0

# ── SC-8 — transmission confidentiality and integrity ───────────────────────

test_tls_cites_sc_8 if {
	cited(sc.deny, "NIST SC-8") with input as sql({"encryption_key_name": "k", "settings": [{"ip_configuration": [{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}]}]})
}

# REGRESSION: SC-8 used to require an ip_configuration block to exist before
# testing ssl_mode, so an instance without one passed silently.
test_absent_ip_configuration_cites_sc_8 if {
	msgs := [m | m := sc.deny[_]; startswith(m, "NIST SC-8")] with input as sql({"encryption_key_name": "k", "settings": [{"tier": "t"}]})
	count(msgs) == 1
	contains(msgs[0], "'absent'")
}

# ── SC-28 — protection of information at rest ───────────────────────────────

test_sql_cmek_cites_sc_28 if {
	cited(sc.deny, "NIST SC-28") with input as sql({"encryption_key_name": null, "settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}]})
}

test_bucket_cmek_cites_sc_28 if {
	cited(sc.deny, "NIST SC-28") with input as bucket({"encryption": []})
}

test_missing_key_rotation_cites_sc_28 if {
	cited(sc.deny, "NIST SC-28") with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": null})
}

test_excessive_key_rotation_cites_sc_28 if {
	msgs := [m | m := sc.deny[_]; contains(m, "exceeds 1 year")] with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": "63072001s"})
	count(msgs) == 1
}

# ── Allow paths ─────────────────────────────────────────────────────────────

test_compliant_sql_produces_no_findings if {
	count(sc.deny) == 0 with input as sql({
		"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
		"settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}],
	})
}

test_compliant_bucket_produces_no_findings if {
	count(sc.deny) == 0 with input as bucket({"encryption": [{"default_kms_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k"}]})
}
