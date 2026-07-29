package controls.object_versioning

import rego.v1

import data.lib.exceptions
import data.lib.utils

# CONTROL: Object versioning on storage buckets.
#
# Versioning is what makes an audit-log bucket tamper-evident: without it an
# object can be overwritten in place and the previous content is unrecoverable.
#
# Exposes no `deny` / `violation` / `warn` — see controls/privileged_access.rego
# for why.
#
# Framework packages import this and attach their own citation:
#   pci_dss.req_10  → PCI DSS 10.3.2
#   soc2.cc7        → SOC 2 CC7.2
#   nist_800_53.au  → NIST AU-9
#
# Resource types: google_storage_bucket
#
# The three original implementations of this check agreed — all three negated an
# `enabled == true` helper, so an absent versioning block was already a finding
# in each. No behaviour change; this removes the triplication only.

# Exception key. Must match `control_id` in exceptions/registry.yaml exactly;
# a typo grants nothing, which is the safe direction to fail.
control_id := "object-versioning"

not_enabled contains finding if {
	r := input.resource_changes[_]
	r.type == "google_storage_bucket"
	utils.is_active_change(r.change)
	not enabled(r)
	not exceptions.granted(r.address, control_id)
	finding := {"address": r.address}
}

enabled(r) if {
	r.change.after.versioning[_].enabled == true
}
