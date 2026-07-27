package controls.key_rotation_test

import rego.v1

import data.controls.key_rotation

# Scoped to purpose == ENCRYPT_DECRYPT. Asymmetric signing keys have no
# rotation_period in the provider schema, so an unscoped rule would fire on every
# signing key in the plan — these tests pin that boundary.

key(after) := {"resource_changes": [{
	"address": "google_kms_crypto_key.t",
	"type": "google_kms_crypto_key",
	"change": {"actions": ["create"], "after": after},
}]}

# 400 days — over the one-year limit.
long_rotation := "34560000s"

# 90 days — well inside the limit.
short_rotation := "7776000s"

test_missing_rotation_is_a_finding if {
	count(key_rotation.missing) == 1 with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": null})
}

# An absent rotation_period must behave identically to an explicit null. The
# provider normally emits null when unset, but a hand-written or trimmed plan
# fixture can omit the key entirely, and that must not read as "rotation set".
test_absent_rotation_field_is_a_finding if {
	count(key_rotation.missing) == 1 with input as key({"purpose": "ENCRYPT_DECRYPT"})
}

test_signing_key_without_rotation_is_ignored if {
	count(key_rotation.missing) == 0 with input as key({"purpose": "ASYMMETRIC_SIGN", "rotation_period": null})
}

test_rotation_over_one_year_is_a_finding if {
	f := key_rotation.excessive[_] with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": long_rotation})
	f.seconds == 34560000
	f.limit == 31536000
}

test_rotation_under_one_year_is_allowed if {
	count(key_rotation.excessive) == 0 with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": short_rotation})
}

test_rotation_exactly_one_year_is_allowed if {
	count(key_rotation.excessive) == 0 with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": "31536000s"})
}

test_missing_and_excessive_are_mutually_exclusive if {
	count(key_rotation.excessive) == 0 with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": null})
	count(key_rotation.missing) == 0 with input as key({"purpose": "ENCRYPT_DECRYPT", "rotation_period": long_rotation})
}

test_destroy_only_change_is_ignored if {
	count(key_rotation.missing) == 0 with input as {"resource_changes": [{
		"address": "google_kms_crypto_key.gone",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["delete"], "after": null},
	}]}
}
