package controls.sql_backups_test

import rego.v1

import data.controls.sql_backups

# REGRESSION: soc2/cc7 bound backup_configuration[_] before testing `enabled`,
# so an instance with no backup_configuration block at all produced no finding.
# Only pci_dss/req_10 caught it. Absent == disabled.

sql(after) := {"resource_changes": [{
	"address": "google_sql_database_instance.t",
	"type": "google_sql_database_instance",
	"change": {"actions": ["create"], "after": after},
}]}

test_absent_backup_configuration_is_a_finding if {
	count(sql_backups.not_enabled) == 1 with input as sql({"settings": [{"tier": "db-f1-micro"}]})
}

test_absent_settings_block_is_a_finding if {
	count(sql_backups.not_enabled) == 1 with input as sql({"name": "db"})
}

test_backups_explicitly_disabled_is_a_finding if {
	count(sql_backups.not_enabled) == 1 with input as sql({"settings": [{"backup_configuration": [{"enabled": false}]}]})
}

test_backups_enabled_null_is_a_finding if {
	count(sql_backups.not_enabled) == 1 with input as sql({"settings": [{"backup_configuration": [{"enabled": null}]}]})
}

test_backups_enabled_is_allowed if {
	count(sql_backups.not_enabled) == 0 with input as sql({"settings": [{"backup_configuration": [{"enabled": true}]}]})
}

test_destroy_only_change_is_ignored if {
	count(sql_backups.not_enabled) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.gone",
		"type": "google_sql_database_instance",
		"change": {"actions": ["delete"], "after": null},
	}]}
}
