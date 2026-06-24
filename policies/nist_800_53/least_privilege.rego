package nist_800_53.least_privilege

import rego.v1

# NIST SP 800-53 Rev 5 — AC-6 Least Privilege / AC-6(1) / IA-5(1)
#
# NOTE: Primitive IAM role checks (AC-6) are in nist_800_53/ac_access_control.rego
# to avoid duplicate violation messages. This package covers additional signals:
# static service account keys (long-lived exportable credentials) and oversized
# IAM bindings that indicate access reviews aren't happening.

# ── IA-5(1): Static service account keys create exportable long-lived secrets ─

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_service_account_key"
	msg := sprintf(
		"Service account key '%s' creates a long-lived, exportable credential — NIST 800-53 IA-5(1) and AC-2(9) favor workload identity federation over static keys",
		[resource.name],
	)
}

# ── AC-6: Oversized IAM bindings indicate access review failures ─────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_project_iam_binding"
	count(resource.change.after.members) > 10
	msg := sprintf(
		"IAM binding for role '%s' has %d members — AC-6 requires periodic access review; bindings this large are a sign reviews aren't happening",
		[resource.change.after.role, count(resource.change.after.members)],
	)
}
