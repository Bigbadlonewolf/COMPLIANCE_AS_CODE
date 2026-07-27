package soc2.cc7_test

import rego.v1

import data.soc2.cc7

# cc7 is a CITATION LAYER over controls.sql_backups, controls.key_rotation and
# controls.object_versioning. Detection logic is asserted once in tests/controls/;
# these tests prove only that SOC 2 cites the right criterion per control.

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

# ── CC8.1 — change management includes backup and recovery ──────────────────

test_backups_cite_cc8_1 if {
	cited(cc7.deny, "SOC2 CC8.1") with input as sql({"settings": [{"backup_configuration": [{"enabled": false}]}]})
}

# REGRESSION: an absent backup_configuration block used to pass this criterion.
test_absent_backup_block_cites_cc8_1 if {
	cited(cc7.deny, "SOC2 CC8.1") with input as sql({"settings": [{"tier": "t"}]})
}

# ── CC7.1 — detection and monitoring of anomalies ───────────────────────────

test_missing_key_rotation_cites_cc7_1 if {
	cited(cc7.deny, "SOC2 CC7.1") with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": null})
}

test_excessive_key_rotation_cites_cc7_1 if {
	msgs := [m | m := cc7.deny[_]; contains(m, "exceeds 1 year")] with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": "63072000s"})
	count(msgs) == 1
}

# ── CC7.2 — anomalies and security events are identified ────────────────────

test_versioning_cites_cc7_2 if {
	cited(cc7.deny, "SOC2 CC7.2") with input as bucket({"versioning": []})
}

# ── Allow path ──────────────────────────────────────────────────────────────

test_compliant_sql_produces_no_findings if {
	count(cc7.deny) == 0 with input as sql({"settings": [{"backup_configuration": [{"enabled": true}]}]})
}
