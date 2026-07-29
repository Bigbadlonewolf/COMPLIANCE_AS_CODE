package controls.cmek_at_rest

import rego.v1

import data.lib.exceptions
import data.lib.utils

# CONTROL: Customer-managed encryption keys (CMEK) on data at rest.
#
# Exposes no `deny` / `violation` / `warn` — see controls/privileged_access.rego
# for why.
#
# Framework packages import these and attach their own citation:
#   pci_dss.req_6   → PCI DSS 6.3.5
#   soc2.cc6        → SOC 2 CC6.7
#   nist_800_53.sc  → NIST SC-28
#
# Resource types: google_sql_database_instance, google_storage_bucket
#
# ─────────────────────────────────────────────────────────────────────────────
# CORRECTNESS NOTE — this control merges three implementations that disagreed.
#
# pci_dss/req_6 tested bucket CMEK with a bare truthiness check on
# `default_kms_key_name`. In Rego, `null` IS a defined value, so a plan carrying
# an explicit `default_kms_key_name = null` satisfied the reference and read as
# "CMEK present" — a false negative. soc2/cc6 and nist_800_53/sc used `!= null`
# and caught it.
#
# The explicit comparison is now canonical. The same reasoning is applied to
# Cloud SQL's `encryption_key_name`, which additionally handles the field being
# absent rather than null.
# ─────────────────────────────────────────────────────────────────────────────

# Exception key. Must match `control_id` in exceptions/registry.yaml exactly;
# a typo grants nothing, which is the safe direction to fail.
control_id := "cmek-at-rest"

sql_missing contains finding if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	not sql_has_cmek(r)
	not exceptions.granted(r.address, control_id)
	finding := {"address": r.address}
}

bucket_missing contains finding if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not bucket_has_cmek(r)
	not exceptions.granted(r.address, control_id)
	finding := {"address": r.address}
}

# Negated rather than compared directly so that an ABSENT key (undefined
# reference) is a finding, not just an explicitly null one.
sql_has_cmek(r) if {
	key := r.change.after.encryption_key_name
	key != null
	key != ""
}

bucket_has_cmek(r) if {
	enc := r.change.after.encryption[_]
	enc.default_kms_key_name != null
	enc.default_kms_key_name != ""
}
