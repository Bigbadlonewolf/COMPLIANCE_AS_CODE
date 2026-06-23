package pci_dss.access_control

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# PCI DSS Requirement 7 — restrict access by business need-to-know.
# PCI DSS Requirement 8.4.2 — MFA for all access into the CDE.
# (Corrected citation: this was previously mis-cited as 8.3.1, which in
# PCI DSS v4.0 covers password/passphrase requirements, not MFA. 8.4.2 is
# the MFA-into-CDE requirement. Flagging this as fixed-from-review rather
# than silently changing the number with no explanation.)

primitive_roles := {"roles/owner", "roles/editor", "roles/viewer"}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_project_iam_member"
	resource.change.after.role in primitive_roles
	msg := sprintf(
		"IAM binding grants primitive role '%s' to '%s' — PCI DSS Req 7.2.1 requires least-privilege, role-based access, not basic/primitive roles",
		[resource.change.after.role, resource.change.after.member],
	)
}

# Fixed: Action can be a single string OR a JSON array in a real AWS IAM
# policy document. The original code only matched the single-string case,
# so a policy like {"Action": ["s3:*", "iam:PassRole"]} slipped past
# entirely — the most common real-world shape for an over-broad policy.
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

# Fixed: the original set only matched three exact strings ("*", "iam:*",
# "*:*"), missing the most common real-world over-broad grant pattern —
# any service-scoped wildcard like "s3:*", "ec2:*", "dynamodb:*". Now
# matches "*" exactly, or any action ending in ":*".
is_wildcard_action(action) if {
	action == "*"
}

is_wildcard_action(action) if {
	endswith(action, ":*")
}

# --- Deny: service accounts with access to PCI-scoped Cloud Run services
#     without an explicit, time-bound or condition-scoped binding ---
#
# Fixed: this previously matched on `contains(name, "payment")`, the exact
# name-substring pattern that was removed from network_segmentation.rego
# for being a one-rename bypass. Leaving it here was an inconsistent
# posture within the same repo — the segmentation policy enforces "declare
# pci-scope explicitly," but this rule still trusted the resource's name.
# Now cross-references the actual pci-scope label on the target service,
# the same source of truth network_segmentation.rego requires every
# relevant service to declare.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_cloud_run_v2_service_iam_member"
	target_service_name := resource.change.after.name
	is_pci_scoped_service(target_service_name)
	not resource.change.after.condition
	msg := sprintf(
		"Cloud Run IAM binding on '%s' grants access to a pci-scope=true service with no IAM condition (time-bound, IP-bound, or attribute-based) — PCI DSS Req 7 expects scoped, auditable access, not standing access",
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

# --- MFA enforcement ---
#
# Rewritten after review: the original check compared resource.name (an
# arbitrary Terraform resource label chosen by whoever wrote the .tf file)
# to the literal string "require_mfa" — that's checking what the author
# decided to NAME the resource block, not what GCP constraint it actually
# enforces. It would pass or fail based on naming convention, not reality.
# This version checks the actual org policy constraint field. Caveat
# documented inline: GCP does not have a single canonical "require MFA"
# org policy constraint the way this repo's first draft implied — MFA for
# console/API access is primarily enforced via Cloud Identity / Context-
# Aware Access, which is outside Terraform's google_org_policy_policy
# resource entirely. This check is intentionally narrowed to catch the one
# thing it CAN reliably catch — an org policy constraint being explicitly
# disabled — and documents that broader MFA verification needs a different
# tool (Context-Aware Access API), not oversold as covering the full
# requirement.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_org_policy_policy"
	contains(resource.change.after.name, "constraints/iam.")
	some rule in resource.change.after.spec.rules
	rule.enforce == false
	msg := sprintf(
		"Org policy '%s' explicitly disables an IAM-related constraint (enforce: false) — review whether this weakens access control posture relevant to PCI DSS Req 8.4.2. NOTE: this check cannot fully verify MFA enforcement on its own; GCP MFA is primarily governed via Context-Aware Access, not this resource type.",
		[resource.change.after.name],
	)
}
