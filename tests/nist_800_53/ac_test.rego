package nist_800_53.ac_test

import rego.v1

import data.nist_800_53.ac

# ── DENY: primitive roles (AC-6) ─────────────────────────────────────────────

test_deny_owner_role if {
	count([v | v := ac.deny[_]; contains(v, "AC-6")]) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.bad",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/owner", "member": "user:admin@example.com"}},
	}]}
}

test_deny_viewer_role_binding if {
	count([v | v := ac.deny[_]; contains(v, "AC-6")]) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_binding.bad",
		"type": "google_project_iam_binding",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/viewer", "members": ["group:devs@example.com"]}},
	}]}
}

# ── DENY: public member (AC-3) ───────────────────────────────────────────────

test_deny_all_users_member if {
	count([v | v := ac.deny[_]; contains(v, "AC-3")]) == 1 with input as {"resource_changes": [{
		"address": "google_project_iam_member.public",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/viewer", "member": "allUsers"}},
	}]}
}

# ── DENY: firewall open remote port (AC-17) ──────────────────────────────────

test_deny_ssh_from_internet if {
	count([v | v := ac.deny[_]; contains(v, "AC-17")]) == 1 with input as {"resource_changes": [{
		"address": "google_compute_firewall.bad",
		"type": "google_compute_firewall",
		"change": {"actions": ["create"], "after": {
			"direction": "INGRESS",
			"source_ranges": ["0.0.0.0/0"],
			"allow": [{"protocol": "tcp", "ports": ["22"]}],
			"deny": [],
		}},
	}]}
}

# ── ALLOW: specific role for service account ──────────────────────────────────

test_allow_specific_sa_role if {
	count(ac.deny) == 0 with input as {"resource_changes": [{
		"address": "google_project_iam_member.good",
		"type": "google_project_iam_member",
		"change": {"actions": ["create"], "after": {"project": "p", "role": "roles/run.invoker", "member": "serviceAccount:sa@p.iam.gserviceaccount.com"}},
	}]}
}

# ── ALLOW: internal firewall with SSH ────────────────────────────────────────

test_allow_ssh_internal_range if {
	count(ac.deny) == 0 with input as {"resource_changes": [{
		"address": "google_compute_firewall.good",
		"type": "google_compute_firewall",
		"change": {"actions": ["create"], "after": {
			"direction": "INGRESS",
			"source_ranges": ["10.0.0.0/8"],
			"allow": [{"protocol": "tcp", "ports": ["22"]}],
			"deny": [],
		}},
	}]}
}
