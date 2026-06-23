package pci_dss.req_1_test

import rego.v1

import data.pci_dss.req_1

# ── Helpers ──────────────────────────────────────────────────────────────────

firewall_resource(address, direction, source_ranges, allow_rules) := {"resource_changes": [{
	"address": address,
	"type": "google_compute_firewall",
	"change": {
		"actions": ["create"],
		"after": {
			"direction": direction,
			"source_ranges": source_ranges,
			"allow": allow_rules,
			"deny": [],
		},
	},
}]}

# ── DENY: sensitive port from 0.0.0.0/0 ─────────────────────────────────────

test_deny_ssh_from_any if {
	count(req_1.deny) == 1 with input as firewall_resource(
		"google_compute_firewall.bad_ssh",
		"INGRESS",
		["0.0.0.0/0"],
		[{"protocol": "tcp", "ports": ["22"]}],
	)
}

test_deny_rdp_from_any if {
	count(req_1.deny) == 1 with input as firewall_resource(
		"google_compute_firewall.bad_rdp",
		"INGRESS",
		["0.0.0.0/0"],
		[{"protocol": "tcp", "ports": ["3389"]}],
	)
}

test_deny_postgres_from_any if {
	count(req_1.deny) == 1 with input as firewall_resource(
		"google_compute_firewall.bad_pg",
		"INGRESS",
		["0.0.0.0/0"],
		[{"protocol": "tcp", "ports": ["5432"]}],
	)
}

test_deny_all_protocols_from_any if {
	count(req_1.deny) == 1 with input as firewall_resource(
		"google_compute_firewall.bad_all",
		"INGRESS",
		["0.0.0.0/0"],
		[{"protocol": "all", "ports": []}],
	)
}

test_deny_on_update if {
	count(req_1.deny) == 1 with input as {"resource_changes": [{
		"address": "google_compute_firewall.updated",
		"type": "google_compute_firewall",
		"change": {
			"actions": ["update"],
			"after": {
				"direction": "INGRESS",
				"source_ranges": ["0.0.0.0/0"],
				"allow": [{"protocol": "tcp", "ports": ["22"]}],
				"deny": [],
			},
		},
	}]}
}

# ── ALLOW: legitimate configurations ────────────────────────────────────────

test_allow_https_from_any if {
	count(req_1.deny) == 0 with input as firewall_resource(
		"google_compute_firewall.good_https",
		"INGRESS",
		["0.0.0.0/0"],
		[{"protocol": "tcp", "ports": ["443"]}],
	)
}

test_allow_http_from_any if {
	count(req_1.deny) == 0 with input as firewall_resource(
		"google_compute_firewall.good_http",
		"INGRESS",
		["0.0.0.0/0"],
		[{"protocol": "tcp", "ports": ["80"]}],
	)
}

test_allow_ssh_from_internal if {
	count(req_1.deny) == 0 with input as firewall_resource(
		"google_compute_firewall.internal_ssh",
		"INGRESS",
		["10.0.0.0/8"],
		[{"protocol": "tcp", "ports": ["22"]}],
	)
}

test_allow_egress_not_checked if {
	count(req_1.deny) == 0 with input as firewall_resource(
		"google_compute_firewall.egress_ssh",
		"EGRESS",
		["0.0.0.0/0"],
		[{"protocol": "tcp", "ports": ["22"]}],
	)
}

test_allow_destroy_action if {
	count(req_1.deny) == 0 with input as {"resource_changes": [{
		"address": "google_compute_firewall.old",
		"type": "google_compute_firewall",
		"change": {"actions": ["delete"], "after": null},
	}]}
}
