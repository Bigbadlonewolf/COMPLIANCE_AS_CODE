package pci_dss.network_segmentation

import rego.v1

# PCI DSS Requirement 1.2 / 1.3 — Network segmentation
#
# NOTE: GCP google_compute_firewall checks are in pci_dss/req_1_network_controls.rego.
# This package covers AWS security group rules, Azure NSRs, and the mandatory
# pci-scope label declaration on every relevant compute resource.

sensitive_ports := {22, 3389, 5432, 3306, 1433, 6379}

# ── AWS: security group rules with open ingress on sensitive ports ───────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group_rule"
	change := resource.change.after
	is_open_ingress(change)
	msg := sprintf(
		"aws_security_group_rule '%s' allows ingress from 0.0.0.0/0 on a sensitive port — PCI DSS Req 1.2.1 requires restricting inbound traffic to only what is necessary",
		[resource.name],
	)
}

# ── Azure: NSR with open ingress — singular destination_port_range ───────────

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

# ── Azure: NSR — plural destination_port_ranges list form ────────────────────

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

# ── Mandatory pci-scope label on every relevant compute resource ─────────────

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
		"%s '%s' has no explicit 'pci-scope' label (true or false) — every compute resource must declare its PCI scope status explicitly. Name-based detection was removed as a one-rename bypass.",
		[resource.type, resource.name],
	)
}

has_explicit_pci_scope_declaration(resource) if {
	tags := object.get(resource.change.after, "labels", object.get(resource.change.after, "tags", {}))
	tags["pci-scope"] in {"true", "false"}
}

# ── Helpers ──────────────────────────────────────────────────────────────────

is_open_ingress(change) if {
	change.cidr_blocks[_] == "0.0.0.0/0"
	change.type == "ingress"
	port_range_overlaps_sensitive(sprintf("%d-%d", [change.from_port, change.to_port]))
}

# AWS protocol "-1" means "all traffic, all ports" — from_port/to_port = 0
# which would compute to "0-0" and miss the sensitive_ports set entirely.
is_open_ingress(change) if {
	change.cidr_blocks[_] == "0.0.0.0/0"
	change.type == "ingress"
	change.protocol == "-1"
}

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
