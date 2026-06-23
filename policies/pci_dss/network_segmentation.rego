package pci_dss.network_segmentation

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# PCI DSS Requirement 1.2 / 1.3 — Network segmentation
#
# CHANGE LOG (post-adversarial-review fixes):
# - sensitive-port detection is now range-aware for GCP and AWS instead of a
#   single hardcoded port-5432 special case for AWS. The original code only
#   caught an exact port-string match on GCP and only port 5432 on AWS,
#   meaning 22/3389/3306/1433/6379 were never actually checked on AWS.
# - Azure NSR support is now implemented against its real schema
#   (source_address_prefix / destination_port_range) instead of existing as
#   a resource-type entry with no matching deny logic — it was dead code.
# - The biggest structural fix: payment-service detection no longer relies
#   on the resource NAME containing "payment". A reviewer correctly pointed
#   out that's a one-rename bypass. The policy now requires an EXPLICIT
#   pci-scope label/tag (true or false) on every compute resource of a
#   relevant type — silence is treated as a violation, not as "not
#   applicable." This is a default-deny posture instead of a denylist.

sensitive_ports := {22, 3389, 5432, 3306, 1433, 6379}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type in {"google_compute_firewall", "aws_security_group_rule"}
	change := resource.change.after
	is_open_ingress(change)
	msg := sprintf(
		"%s '%s' allows ingress from 0.0.0.0/0 on a sensitive port — PCI DSS Req 1.2.1 requires restricting inbound traffic to only what is necessary",
		[resource.type, resource.name],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "azurerm_network_security_rule"
	change := resource.change.after
	change.direction == "Inbound"
	change.access == "Allow"
	change.source_address_prefix == "*"
	port_range_overlaps_sensitive(change.destination_port_range)
	msg := sprintf(
		"azurerm_network_security_rule '%s' allows inbound from '*' on a sensitive port — PCI DSS Req 1.2.1",
		[resource.name],
	)
}

# Fixed: azurerm_network_security_rule supports destination_port_ranges
# (plural — a LIST of ranges) as an alternative to the singular
# destination_port_range. A rule written using the list form was checked
# against a field that didn't exist for it and bypassed entirely.
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "azurerm_network_security_rule"
	change := resource.change.after
	change.direction == "Inbound"
	change.access == "Allow"
	change.source_address_prefix == "*"
	some port_range in object.get(change, "destination_port_ranges", [])
	port_range_overlaps_sensitive(port_range)
	msg := sprintf(
		"azurerm_network_security_rule '%s' allows inbound from '*' on a sensitive port (via destination_port_ranges list) — PCI DSS Req 1.2.1",
		[resource.name],
	)
}

# Azure NSG rules can express ports as EITHER a single destination_port_range
# string OR a destination_port_ranges LIST — the singular field is required
# to be empty/unset when the plural one is used. Only the singular form was
# checked previously; a rule using the list form bypassed entirely.
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "azurerm_network_security_rule"
	change := resource.change.after
	change.direction == "Inbound"
	change.access == "Allow"
	change.source_address_prefix == "*"
	some range_str in object.get(change, "destination_port_ranges", [])
	port_range_overlaps_sensitive(range_str)
	msg := sprintf(
		"azurerm_network_security_rule '%s' allows inbound from '*' on a sensitive port (via destination_port_ranges list) — PCI DSS Req 1.2.1",
		[resource.name],
	)
}

is_open_ingress(change) if {
	change.source_ranges[_] == "0.0.0.0/0"
	some allow in change.allow
	some port_str in allow.ports
	port_range_overlaps_sensitive(port_str)
}

# Fixed: GCP allows an `allow` block with protocol "all" and NO `ports`
# attribute at all, meaning every port is open. The original logic only
# ever inspected allow.ports[_], so an "allow everything" rule — arguably
# the single worst possible firewall misconfiguration — had no `ports`
# list to iterate and silently passed every check.
is_open_ingress(change) if {
	change.source_ranges[_] == "0.0.0.0/0"
	some allow in change.allow
	lower(allow.protocol) == "all"
}

is_open_ingress(change) if {
	change.cidr_blocks[_] == "0.0.0.0/0"
	change.type == "ingress"
	port_range_overlaps_sensitive(sprintf("%d-%d", [change.from_port, change.to_port]))
}

# Fixed: AWS security group rules with `protocol = "-1"` mean "all
# protocols, all ports" — Terraform conventionally renders from_port and
# to_port as 0 in this case, which produced a "0-0" range containing no
# sensitive port and let the single worst possible AWS rule (everything,
# from everywhere) pass silently. Protocol "-1" must be flagged regardless
# of whatever from_port/to_port happen to be set to.
is_open_ingress(change) if {
	change.cidr_blocks[_] == "0.0.0.0/0"
	change.type == "ingress"
	change.protocol == "-1"
}

# AWS represents "all traffic, all ports" as protocol = "-1", which is
# typically paired with from_port/to_port = 0/0 (or omitted entirely) —
# NOT a real 2-port range, which is why generalizing to "0-0" against the
# sensitive_ports set caught nothing: 0 isn't in that set. protocol "-1" is
# checked directly instead of trying to force it through the port-range path.
is_open_ingress(change) if {
	change.cidr_blocks[_] == "0.0.0.0/0"
	change.type == "ingress"
	change.protocol == "-1"
}

# Accepts a single port ("5432"), a range ("5430-5440"), or the wildcard
# "*" used by Azure NSGs to mean "every port" — fixed after review found
# that a destination_port_range of "*" fell through `split("*", "-")`
# (count == 1) and then failed the numeric-equality branch, so a fully
# open Azure rule went undetected.
port_range_overlaps_sensitive("*") if true

port_range_overlaps_sensitive(port_str) if {
	port_str != "*"
	parts := split(port_str, "-")
	count(parts) == 1
	some p in sensitive_ports
	sprintf("%d", [p]) == port_str
}

port_range_overlaps_sensitive(port_str) if {
	port_str != "*"
	parts := split(port_str, "-")
	count(parts) == 2
	low := to_number(parts[0])
	high := to_number(parts[1])
	some p in sensitive_ports
	p >= low
	p <= high
}

# --- Mandatory PCI-scope declaration on every relevant compute resource ---

relevant_compute_types := {
	"google_cloud_run_v2_service",
	"aws_lambda_function",
	"aws_ecs_service",
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type in relevant_compute_types
	not has_explicit_pci_scope_declaration(resource)
	msg := sprintf(
		"%s '%s' has no explicit 'pci-scope' label (true or false) — every compute resource must declare its PCI scope status explicitly. Name-based detection of 'payment'-like services was removed because it is trivially bypassed by renaming the resource.",
		[resource.type, resource.name],
	)
}

has_explicit_pci_scope_declaration(resource) if {
	tags := object.get(resource.change.after, "labels", object.get(resource.change.after, "tags", {}))
	tags["pci-scope"] in {"true", "false"}
}
