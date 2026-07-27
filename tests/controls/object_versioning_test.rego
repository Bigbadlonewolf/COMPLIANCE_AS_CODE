package controls.object_versioning_test

import rego.v1

import data.controls.object_versioning

# Versioning is what makes an audit-log bucket tamper-evident. The three original
# implementations of this check agreed, so this control was a pure deduplication —
# these tests pin the behaviour so a future edit cannot quietly loosen it.

bucket(after) := {"resource_changes": [{
	"address": "google_storage_bucket.t",
	"type": "google_storage_bucket",
	"change": {"actions": ["create"], "after": after},
}]}

test_absent_versioning_block_is_a_finding if {
	count(object_versioning.not_enabled) == 1 with input as bucket({"name": "b"})
}

test_empty_versioning_array_is_a_finding if {
	count(object_versioning.not_enabled) == 1 with input as bucket({"versioning": []})
}

test_versioning_disabled_is_a_finding if {
	count(object_versioning.not_enabled) == 1 with input as bucket({"versioning": [{"enabled": false}]})
}

test_versioning_null_is_a_finding if {
	count(object_versioning.not_enabled) == 1 with input as bucket({"versioning": [{"enabled": null}]})
}

test_versioning_enabled_is_allowed if {
	count(object_versioning.not_enabled) == 0 with input as bucket({"versioning": [{"enabled": true}]})
}

test_update_action_is_checked if {
	count(object_versioning.not_enabled) == 1 with input as {"resource_changes": [{
		"address": "google_storage_bucket.updated",
		"type": "google_storage_bucket",
		"change": {"actions": ["update"], "after": {"name": "b"}},
	}]}
}

test_destroy_only_change_is_ignored if {
	count(object_versioning.not_enabled) == 0 with input as {"resource_changes": [{
		"address": "google_storage_bucket.gone",
		"type": "google_storage_bucket",
		"change": {"actions": ["delete"], "after": null},
	}]}
}
