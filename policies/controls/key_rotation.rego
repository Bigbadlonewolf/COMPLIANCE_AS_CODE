package controls.key_rotation

import rego.v1

import data.lib.utils

# CONTROL: Automatic rotation of KMS encryption keys.
#
# Exposes no `deny` / `violation` / `warn` — see controls/privileged_access.rego
# for why.
#
# Framework packages import these and attach their own citation:
#   pci_dss.req_6   → PCI DSS 6.3.5
#   soc2.cc7        → SOC 2 CC7.1 / CC8.1
#   nist_800_53.sc  → NIST SC-28
#
# Resource types: google_kms_crypto_key
#
# Scoped to purpose == ENCRYPT_DECRYPT. Asymmetric signing keys have no
# rotation_period in the provider schema, so including them would fire on every
# signing key in the plan.

# ── No rotation configured at all ────────────────────────────────────────────

# Negated rather than compared to null directly, so that a rotation_period which
# is ABSENT from the plan is treated the same as one explicitly set to null. This
# matches how cmek_at_rest handles encryption_key_name — the control layer should
# not have two different answers to "what does a missing field mean".
missing contains finding if {
	r := input.resource_changes[_]
	rotatable(r)
	not has_rotation(r)
	finding := {"address": r.address}
}

has_rotation(r) if r.change.after.rotation_period != null

# ── Rotation configured, but slower than annually ────────────────────────────

excessive contains finding if {
	r := input.resource_changes[_]
	rotatable(r)
	r.change.after.rotation_period != null
	seconds := to_number(trim_suffix(r.change.after.rotation_period, "s"))
	seconds > utils.one_year_seconds
	finding := {
		"address": r.address,
		"seconds": seconds,
		"limit": utils.one_year_seconds,
	}
}

rotatable(r) if {
	r.type == "google_kms_crypto_key"
	utils.is_active_change(r.change)
	r.change.after.purpose == "ENCRYPT_DECRYPT"
}
