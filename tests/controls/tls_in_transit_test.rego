package controls.tls_in_transit_test

import rego.v1

import data.controls.tls_in_transit

# REGRESSION: soc2/cc6 and nist_800_53/sc both bound ip_configuration[_] before
# testing ssl_mode, so an instance with no ip_configuration block produced no
# finding. GCP does not enforce TLS unless told to — absent is non-compliant.

sql(after) := {"resource_changes": [{
	"address": "google_sql_database_instance.t",
	"type": "google_sql_database_instance",
	"change": {"actions": ["create"], "after": after},
}]}

test_absent_ip_configuration_is_a_finding if {
	count(tls_in_transit.not_enforced) == 1 with input as sql({"settings": [{"tier": "db-f1-micro"}]})
}

test_absent_ip_configuration_reports_absent if {
	f := tls_in_transit.not_enforced[_] with input as sql({"settings": [{"tier": "db-f1-micro"}]})
	f.observed == "absent"
}

test_absent_settings_block_is_a_finding if {
	count(tls_in_transit.not_enforced) == 1 with input as sql({"name": "db"})
}

test_wrong_ssl_mode_is_a_finding if {
	f := tls_in_transit.not_enforced[_] with input as sql({"settings": [{"ip_configuration": [{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}]}]})
	f.observed == "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
}

test_null_ssl_mode_is_a_finding if {
	count(tls_in_transit.not_enforced) == 1 with input as sql({"settings": [{"ip_configuration": [{"ssl_mode": null}]}]})
}

test_encrypted_only_is_allowed if {
	count(tls_in_transit.not_enforced) == 0 with input as sql({"settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}]})
}

test_destroy_only_change_is_ignored if {
	count(tls_in_transit.not_enforced) == 0 with input as {"resource_changes": [{
		"address": "google_sql_database_instance.gone",
		"type": "google_sql_database_instance",
		"change": {"actions": ["delete"], "after": null},
	}]}
}
