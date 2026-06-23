package nist_800_53.least_privilege

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# NIST 800-53 AC-6 (Least Privilege) and AC-6(1) (Authorize Access to Security Functions)
# This reuses the same underlying signal as PCI Req 7 — primitive/wildcard role grants —
# because AC-6 and PCI 7.2.1 are testing the same control with different vocabulary.
# Deliberately implemented once here and cross-referenced in the controls mapping,
# rather than duplicated, so there's a single source of truth to maintain.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_project_iam_member"
	resource.change.after.role == "roles/owner"
	msg := sprintf(
		"'%s' granted roles/owner — NIST 800-53 AC-6(1) requires that security-relevant functions be restricted to a documented, minimal set of authorized users",
		[resource.change.after.member],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_service_account_key"
	msg := sprintf(
		"Service account key '%s' creates a long-lived, exportable credential — NIST 800-53 IA-5(1) and AC-2(9) favor workload identity federation over static keys",
		[resource.name],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_project_iam_binding"
	count(resource.change.after.members) > 10
	msg := sprintf(
		"IAM binding for role '%s' has %d members — AC-6 requires periodic access review; bindings this large are a sign reviews aren't happening",
		[resource.change.after.role, count(resource.change.after.members)],
	)
}
