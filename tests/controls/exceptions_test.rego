package lib.exceptions_test

import rego.v1

import data.controls.object_versioning
import data.controls.privileged_access
import data.lib.exceptions

# Dates far enough either side of any plausible run that these tests never
# depend on the clock. An exception expiring in 1999 is always dead; one
# expiring in 2999 is always live.
past := "1999-01-01"

future := "2999-01-01"

bucket(address) := {"resource_changes": [{
	"address": address,
	"type": "google_storage_bucket",
	"change": {"actions": ["create"], "after": {"name": "b"}},
}]}

iam_member(address) := {"resource_changes": [{
	"address": address,
	"type": "google_project_iam_member",
	"change": {"actions": ["create"], "after": {
		"role": "roles/owner",
		"member": "user:someone@example.com",
	}},
}]}

registry(entries) := entries

entry(address, control, expiry) := {
	"exception_id": "EXC-TEST-001",
	"resource_address": address,
	"control_id": control,
	"justification": "test fixture",
	"approved_by": "test",
	"approved_date": "2026-07-28",
	"expiration_date": expiry,
}

# ── The control fires normally when nothing is excepted ──────────────────────

test_finding_stands_with_an_empty_registry if {
	count(object_versioning.not_enabled) == 1 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([])
}

# ── FAIL-CLOSED: no registry loaded at all ───────────────────────────────────
#
# The single most important test here. If `data.exceptions` is undefined the
# control must still deny. An exception mechanism that suppresses findings when
# its own data source goes missing is worse than having no mechanism.

test_finding_stands_when_the_registry_is_absent if {
	count(object_versioning.not_enabled) == 1 with input as bucket("google_storage_bucket.b")
}

# ── A valid, unexpired exception suppresses exactly its own finding ──────────

test_valid_exception_suppresses_the_finding if {
	count(object_versioning.not_enabled) == 0 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.b", "object-versioning", future)])
}

# ── EXPIRY IS ENFORCED ───────────────────────────────────────────────────────
#
# The reason the registry is not just a mute list. An entry whose date has
# passed grants nothing, with no cleanup step required.

test_expired_exception_does_not_suppress if {
	count(object_versioning.not_enabled) == 1 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.b", "object-versioning", past)])
}

test_exception_with_no_expiration_date_does_not_suppress if {
	no_expiry := object.remove(entry("google_storage_bucket.b", "object-versioning", future), {"expiration_date"})
	count(object_versioning.not_enabled) == 1 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([no_expiry])
}

# ── Scoping: an exception is not a blanket ───────────────────────────────────

test_exception_for_another_resource_does_not_suppress if {
	count(object_versioning.not_enabled) == 1 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.other", "object-versioning", future)])
}

test_exception_for_another_control_does_not_suppress if {
	count(object_versioning.not_enabled) == 1 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.b", "cmek-at-rest", future)])
}

# A mistyped control_id must grant nothing rather than matching loosely.
test_misspelled_control_id_does_not_suppress if {
	count(object_versioning.not_enabled) == 1 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.b", "object_versioning", future)])
}

# ── The mechanism works across controls, not just the one used above ─────────

test_privileged_access_honours_a_valid_exception if {
	count(privileged_access.primitive_role) == 0 with input as iam_member("google_project_iam_member.admin")
		with data.exceptions as registry([entry("google_project_iam_member.admin", "privileged-access", future)])
}

test_privileged_access_ignores_an_expired_exception if {
	count(privileged_access.primitive_role) == 1 with input as iam_member("google_project_iam_member.admin")
		with data.exceptions as registry([entry("google_project_iam_member.admin", "privileged-access", past)])
}

# ── Visibility: a suppressed finding leaves a trace ──────────────────────────

test_active_exception_is_reported_for_the_plan if {
	count(exceptions.active_for_plan) == 1 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.b", "object-versioning", future)])
}

test_expired_exception_is_not_reported_as_active if {
	count(exceptions.active_for_plan) == 0 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.b", "object-versioning", past)])
}

test_exception_for_a_resource_not_in_the_plan_is_not_reported if {
	count(exceptions.active_for_plan) == 0 with input as bucket("google_storage_bucket.b")
		with data.exceptions as registry([entry("google_storage_bucket.elsewhere", "object-versioning", future)])
}
