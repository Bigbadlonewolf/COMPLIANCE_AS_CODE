package soc2.cc6_test

import rego.v1

import data.soc2.cc6

# cc6 is a CITATION LAYER over controls.privileged_access, controls.tls_in_transit
# and controls.cmek_at_rest. Detection logic is asserted once in tests/controls/;
# these tests prove only that SOC 2 cites the right criterion per control.

iam(rtype, after) := {"resource_changes": [{
	"address": sprintf("%s.t", [rtype]),
	"type": rtype,
	"change": {"actions": ["create"], "after": after},
}]}

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

cited(msgs, citation) if count([m | m := msgs[_]; startswith(m, citation)]) > 0

# ── CC6.3 — role-based access ───────────────────────────────────────────────

test_primitive_role_cites_cc6_3 if {
	cited(cc6.deny, "SOC2 CC6.3") with input as iam("google_project_iam_member", {"role": "roles/editor"})
}

# ── CC6.1 — logical access restricted to authorized personnel ───────────────

test_public_member_cites_cc6_1 if {
	cited(cc6.deny, "SOC2 CC6.1") with input as iam("google_project_iam_member", {"member": "allUsers"})
}

# ── CC6.6 — transmission encryption ─────────────────────────────────────────

test_tls_cites_cc6_6 if {
	cited(cc6.deny, "SOC2 CC6.6") with input as sql({"encryption_key_name": "k", "settings": [{"ip_configuration": [{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}]}]})
}

# REGRESSION: this criterion used to require an ip_configuration block to exist
# before testing ssl_mode, so an instance without one passed silently.
test_absent_ip_configuration_cites_cc6_6 if {
	msgs := [m | m := cc6.deny[_]; startswith(m, "SOC2 CC6.6")] with input as sql({"encryption_key_name": "k", "settings": [{"tier": "t"}]})
	count(msgs) == 1
	contains(msgs[0], "'absent'")
}

# ── CC6.7 — at-rest encryption ──────────────────────────────────────────────

test_bucket_cmek_cites_cc6_7 if {
	cited(cc6.deny, "SOC2 CC6.7") with input as bucket({"encryption": []})
}

test_sql_cmek_cites_cc6_7 if {
	cited(cc6.deny, "SOC2 CC6.7") with input as sql({"encryption_key_name": null, "settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}]})
}

# ── Allow path ──────────────────────────────────────────────────────────────

test_compliant_sql_produces_no_findings if {
	count(cc6.deny) == 0 with input as sql({
		"encryption_key_name": "projects/p/locations/us/keyRings/k/cryptoKeys/k",
		"settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}],
	})
}
