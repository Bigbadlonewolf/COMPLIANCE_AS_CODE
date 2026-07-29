package exceptions_validate

import rego.v1

# Validates the exception registry itself.
#
# Deliberately NOT under policies/. Conftest loads policies/ with
# --all-namespaces against Terraform plans; a validation package living there
# would be evaluated against every plan and report nonsense. This runs on its
# own, against the registry as data:
#
#   opa eval -d exceptions/ 'data.exceptions_validate.errors'
#
# CI fails the build when the result is non-empty. The registry is the one file
# in this repo whose whole job is to let a check not fire, so it gets a check of
# its own.

required_fields := {
	"exception_id",
	"resource_address",
	"control_id",
	"justification",
	"approved_by",
	"approved_date",
	"expiration_date",
}

# Must match the control_id constants in policies/controls/*.rego. Kept as an
# explicit set rather than derived, so adding a control does not silently widen
# what the registry accepts.
valid_control_ids := {
	"cmek-at-rest",
	"key-rotation",
	"object-versioning",
	"privileged-access",
	"sql-backups",
	"tls-in-transit",
}

errors contains msg if {
	e := data.exceptions[i]
	some field in required_fields
	not e[field]
	msg := sprintf("exceptions[%d] (%v): missing required field '%s'", [i, object.get(e, "exception_id", "<no id>"), field])
}

errors contains msg if {
	e := data.exceptions[i]
	e.control_id
	not e.control_id in valid_control_ids
	msg := sprintf(
		"exceptions[%d] (%v): control_id '%s' matches no control. Valid: %v",
		[i, object.get(e, "exception_id", "<no id>"), e.control_id, sort(valid_control_ids)],
	)
}

# A date OPA cannot parse would abort policy evaluation at gate time with an
# eval trace instead of a message. Catching it here turns that into a build
# failure that names the entry.
errors contains msg if {
	e := data.exceptions[i]
	some field in {"approved_date", "expiration_date"}
	value := e[field]
	not parsable(value)
	msg := sprintf("exceptions[%d] (%v): %s '%v' is not a YYYY-MM-DD date", [i, object.get(e, "exception_id", "<no id>"), field, value])
}

# Already-expired entries are not an error at gate time — they simply grant
# nothing — but leaving them in the file makes the registry read as if more is
# suppressed than actually is. CI reports them so they get removed.
errors contains msg if {
	e := data.exceptions[i]
	parsable(e.expiration_date)
	time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [e.expiration_date])) <= time.now_ns()
	msg := sprintf(
		"exceptions[%d] (%v): expired on %s and suppresses nothing — remove it or renew it with a fresh justification",
		[i, object.get(e, "exception_id", "<no id>"), e.expiration_date],
	)
}

# exception_id must be unique. Two entries sharing an id make the audit trail
# ambiguous the moment anyone cites one.
errors contains msg if {
	ids := [e.exception_id | e := data.exceptions[_]]
	some id in ids
	count([x | x := ids[_]; x == id]) > 1
	msg := sprintf("exception_id '%s' is used more than once", [id])
}

parsable(value) if {
	is_string(value)
	regex.match(`^\d{4}-\d{2}-\d{2}$`, value)
	time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [value]))
}
