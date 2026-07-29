package controls.sql_backups

import rego.v1

import data.lib.exceptions
import data.lib.utils

# CONTROL: Automated backups on Cloud SQL.
#
# Exposes no `deny` / `violation` / `warn` — see controls/privileged_access.rego
# for why.
#
# Framework packages import this and attach their own citation:
#   pci_dss.req_10  → PCI DSS 10.3.2
#   soc2.cc7        → SOC 2 CC8.1
#
# Resource types: google_sql_database_instance
#
# ─────────────────────────────────────────────────────────────────────────────
# CORRECTNESS NOTE — this control merges two implementations that disagreed.
#
# soc2/cc7 bound `backup_configuration[_]` before testing `enabled`, so an
# instance with NO backup_configuration block at all produced no finding — a
# false negative. Having no backups is the same violation whether it is stated
# explicitly or achieved by omission.
#
# Only pci_dss/req_10 handled it, via a negated helper. That behaviour is now
# canonical.
# ─────────────────────────────────────────────────────────────────────────────

# Exception key. Must match `control_id` in exceptions/registry.yaml exactly;
# a typo grants nothing, which is the safe direction to fail.
control_id := "sql-backups"

not_enabled contains finding if {
	r := input.resource_changes[_]
	r.type == "google_sql_database_instance"
	utils.is_active_change(r.change)
	not enabled(r)
	not exceptions.granted(r.address, control_id)
	finding := {"address": r.address}
}

enabled(r) if {
	settings := r.change.after.settings[_]
	settings.backup_configuration[_].enabled == true
}
