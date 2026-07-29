package controls.tls_in_transit

import rego.v1

import data.lib.exceptions
import data.lib.utils

# CONTROL: TLS enforcement on Cloud SQL connections.
#
# Exposes no `deny` / `violation` / `warn` — see controls/privileged_access.rego
# for why.
#
# Framework packages import this and attach their own citation:
#   pci_dss.req_6   → PCI DSS 6.5.3
#   soc2.cc6        → SOC 2 CC6.6
#   nist_800_53.sc  → NIST SC-8
#
# Resource types: google_sql_database_instance
#
# ─────────────────────────────────────────────────────────────────────────────
# CORRECTNESS NOTE — this control merges three implementations that disagreed.
#
# soc2/cc6 and nist_800_53/sc both bound `ip_configuration[_]` before testing
# ssl_mode, so an instance with NO ip_configuration block produced no finding —
# a false negative. GCP does not enforce TLS unless explicitly told to, so an
# absent block is exactly as non-compliant as an explicit wrong value.
#
# Only pci_dss/req_6 handled it, via a negated helper. That behaviour is now
# canonical for all three frameworks.
# ─────────────────────────────────────────────────────────────────────────────

# Exception key. Must match `control_id` in exceptions/registry.yaml exactly;
# a typo grants nothing, which is the safe direction to fail.
control_id := "tls-in-transit"

not_enforced contains finding if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	not enforced(r)
	not exceptions.granted(r.address, control_id)
	finding := {
		"address": r.address,
		"observed": observed_mode(r),
	}
}

# True only when ssl_mode is explicitly ENCRYPTED_ONLY. Negating this rule is
# what makes an absent settings/ip_configuration block a finding.
enforced(r) if {
	settings := r.change.after.settings[_]
	settings.ip_configuration[_].ssl_mode == "ENCRYPTED_ONLY"
}

# The value to report. Falls back to "absent" when the block or field is missing,
# so a framework message can say what it actually saw.
observed_mode(r) := mode if {
	settings := r.change.after.settings[_]
	mode := settings.ip_configuration[_].ssl_mode
	mode != null
} else := "absent"
