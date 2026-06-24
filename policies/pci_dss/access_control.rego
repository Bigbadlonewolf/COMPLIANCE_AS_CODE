package pci_dss.access_control

import rego.v1

# PCI DSS Requirement 7 — restrict access by business need-to-know.
# PCI DSS Requirement 8.4.2 — MFA for all access into the CDE.
#
# NOTE: Primitive IAM role checks (Req 7.2.1/7.2.5) are enforced in
# pci_dss/req_7_access_control.rego. This package handles the remaining
# unique controls: AWS IAM policy wildcards, Cloud Run IAM conditions on
# pci-scope=true services, and GCP org policy MFA constraints.

# ── AWS: IAM policy wildcard action ─────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_iam_policy"
	statement := json.unmarshal(resource.change.after.policy).Statement[_]
	statement.Effect == "Allow"
	action_has_wildcard(statement.Action)
	msg := sprintf(
		"IAM policy '%s' grants a wildcard action — violates PCI DSS Req 7.2.1 least-privilege",
		[resource.name],
	)
}

action_has_wildcard(action) if {
	is_string(action)
	is_wildcard_action(action)
}

action_has_wildcard(action) if {
	is_array(action)
	some a in action
	is_wildcard_action(a)
}

is_wildcard_action(action) if { action == "*" }

is_wildcard_action(action) if { endswith(action, ":*") }

# ── Cloud Run: IAM bindings on pci-scope=true services need an IAM condition ─

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_cloud_run_v2_service_iam_member"
	target_service_name := resource.change.after.name
	is_pci_scoped_service(target_service_name)
	not resource.change.after.condition
	msg := sprintf(
		"Cloud Run IAM binding on '%s' grants access to a pci-scope=true service with no IAM condition — PCI DSS Req 7 expects scoped, auditable access, not standing access",
		[target_service_name],
	)
}

is_pci_scoped_service(service_name) if {
	svc := input.resource_changes[_]
	svc.type == "google_cloud_run_v2_service"
	object.get(svc.change.after, "name", svc.name) == service_name
	tags := object.get(svc.change.after, "labels", {})
	tags["pci-scope"] == "true"
}

# ── Org policy: detect explicit disablement of IAM constraints ───────────────
# Caveat: GCP MFA is governed via Context-Aware Access, not this resource.
# This check catches org policies explicitly setting enforce=false on IAM
# constraints — a necessary but not sufficient signal for Req 8.4.2.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_org_policy_policy"
	contains(resource.change.after.name, "constraints/iam.")
	some rule in resource.change.after.spec.rules
	rule.enforce == false
	msg := sprintf(
		"Org policy '%s' explicitly disables an IAM-related constraint (enforce: false) — review impact on PCI DSS Req 8.4.2. NOTE: full MFA verification requires Context-Aware Access, not this resource type alone.",
		[resource.change.after.name],
	)
}
