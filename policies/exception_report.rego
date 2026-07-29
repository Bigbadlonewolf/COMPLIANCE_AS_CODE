package exception_report

import rego.v1

import data.lib.exceptions

# Surfaces active exceptions in the conftest output.
#
# A suppressed finding and a finding that never fired look identical in a green
# build. That is the failure mode every exception mechanism eventually has, and
# it is why this file exists: `warn` is a Conftest-reserved rule name, so these
# appear in the gate output alongside the denials without blocking the build.
#
# Requires the registry to be loaded:
#   conftest test plan.json --policy policies --data exceptions/registry.yaml --all-namespaces
#
# Without --data, this reports nothing and every control enforces normally.

warn contains msg if {
	e := exceptions.active_for_plan[_]
	msg := sprintf(
		"EXCEPTION ACTIVE — %s: '%s' is exempt from control '%s' until %s. Approved by %s on %s. Reason: %s",
		[
			e.exception_id,
			e.resource_address,
			e.control_id,
			e.expiration_date,
			e.approved_by,
			e.approved_date,
			e.justification,
		],
	)
}
