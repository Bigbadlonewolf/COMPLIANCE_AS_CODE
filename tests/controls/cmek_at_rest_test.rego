package controls.cmek_at_rest_test

import rego.v1

import data.controls.cmek_at_rest

# REGRESSION: pci_dss/req_6 tested bucket CMEK with a bare truthiness check on
# default_kms_key_name. `null` is a DEFINED value in Rego, so an explicit null
# satisfied the reference and read as "CMEK present" — a false negative.

bucket(after) := {"resource_changes": [{
	"address": "google_storage_bucket.t",
	"type": "google_storage_bucket",
	"change": {"actions": ["create"], "after": after},
}]}

sql(after) := {"resource_changes": [{
	"address": "google_sql_database_instance.t",
	"type": "google_sql_database_instance",
	"change": {"actions": ["create"], "after": after},
}]}

test_bucket_explicit_null_kms_key_is_a_finding if {
	count(cmek_at_rest.bucket_missing) == 1 with input as bucket({"encryption": [{"default_kms_key_name": null}]})
}

test_bucket_empty_string_kms_key_is_a_finding if {
	count(cmek_at_rest.bucket_missing) == 1 with input as bucket({"encryption": [{"default_kms_key_name": ""}]})
}

test_bucket_absent_encryption_block_is_a_finding if {
	count(cmek_at_rest.bucket_missing) == 1 with input as bucket({"name": "b"})
}

test_bucket_empty_encryption_array_is_a_finding if {
	count(cmek_at_rest.bucket_missing) == 1 with input as bucket({"encryption": []})
}

test_bucket_with_kms_key_is_allowed if {
	count(cmek_at_rest.bucket_missing) == 0 with input as bucket({"encryption": [{"default_kms_key_name": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}]})
}

test_sql_explicit_null_key_is_a_finding if {
	count(cmek_at_rest.sql_missing) == 1 with input as sql({"encryption_key_name": null})
}

# The field being absent entirely must behave the same as an explicit null.
test_sql_absent_key_field_is_a_finding if {
	count(cmek_at_rest.sql_missing) == 1 with input as sql({"name": "db"})
}

test_sql_with_key_is_allowed if {
	count(cmek_at_rest.sql_missing) == 0 with input as sql({"encryption_key_name": "projects/p/locations/l/keyRings/r/cryptoKeys/k"})
}
