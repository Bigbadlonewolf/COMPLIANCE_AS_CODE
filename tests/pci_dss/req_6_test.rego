package pci_dss.req_6_test

import rego.v1

import data.pci_dss.req_6

# req_6 is a CITATION LAYER over controls.tls_in_transit, controls.cmek_at_rest
# and controls.key_rotation. The detection logic — absent blocks, null fields,
# rotation boundaries, destroy-only changes — is asserted once in
# tests/controls/. These tests prove only that PCI cites the right requirement
# for each control, which is the thing this package is responsible for.

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

# ── 6.5.3 — transmission of CHD over open networks ──────────────────────────

test_tls_cites_6_5_3 if {
	cited(req_6.deny, "PCI DSS 6.5.3") with input as sql({"encryption_key_name": "k", "settings": [{"tier": "t"}]})
}

# ── 6.3.5 — CHD at rest encrypted with strong cryptography ──────────────────

test_sql_cmek_cites_6_3_5 if {
	cited(req_6.deny, "PCI DSS 6.3.5") with input as sql({"encryption_key_name": null, "settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}]})
}

test_bucket_cmek_cites_6_3_5 if {
	cited(req_6.deny, "PCI DSS 6.3.5") with input as bucket({"encryption": []})
}

test_missing_key_rotation_cites_6_3_5 if {
	cited(req_6.deny, "PCI DSS 6.3.5") with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": null})
}

test_excessive_key_rotation_cites_6_3_5 if {
	msgs := [m | m := req_6.deny[_]; contains(m, "exceeds 1 year")] with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": "63072001s"})
	count(msgs) == 1
}

# ── Allow path: a fully compliant instance produces nothing ─────────────────

test_compliant_sql_produces_no_findings if {
	count(req_6.deny) == 0 with input as sql({
		"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/sql",
		"settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}],
	})
}
