package pci_dss.req_1

import rego.v1

import data.lib.utils

# PCI DSS v4.0 — Requirement 1: Install and Maintain Network Security Controls
#
# 1.3.2  Restrict inbound traffic from 0.0.0.0/0 to only that which is
#         necessary for the system component, including protocols, ports, and IP.
#
# Resource types checked:
#   google_compute_firewall (google provider ≥ 5.0)

# ── Rule 1: Deny INGRESS rules that expose sensitive ports from 0.0.0.0/0 ──

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_compute_firewall"
	utils.is_active_change(r.change)
	r.change.after.direction == "INGRESS"
	r.change.after.source_ranges[_] == "0.0.0.0/0"
	allowed := r.change.after.allow[_]
	port := allowed.ports[_]
	port in utils.sensitive_ports
	msg := sprintf(
		"PCI DSS 1.3.2 | %s: INGRESS allows sensitive port %s from 0.0.0.0/0. Restrict source to known IP ranges.",
		[r.address, port],
	)
}

# ── Rule 2: Deny INGRESS rules allowing ALL protocols from 0.0.0.0/0 ──────

deny contains msg if {
	r := input.resource_changes[_]
	r.type == "google_compute_firewall"
	utils.is_active_change(r.change)
	r.change.after.direction == "INGRESS"
	r.change.after.source_ranges[_] == "0.0.0.0/0"
	r.change.after.allow[_].protocol == "all"
	msg := sprintf(
		"PCI DSS 1.3.2 | %s: INGRESS allows ALL protocols from 0.0.0.0/0. Use explicit allow rules with minimal port sets.",
		[r.address],
	)
}
