package controls.privileged_access

import rego.v1

import data.lib.exceptions
import data.lib.utils

# CONTROL: Privileged and unauthenticated project access.
#
# This package owns the LOGIC. It deliberately exposes no `deny` / `violation` /
# `warn` rule — those are Conftest's reserved rule names, and `conftest test
# --all-namespaces` would report every finding twice: once here, once from each
# framework package that cites it.
#
# Framework packages import these sets and attach their own citation:
#   pci_dss.req_7   → PCI DSS 7.2.5 / 7.2.6
#   soc2.cc6        → SOC 2 CC6.3 / CC6.1
#   nist_800_53.ac  → NIST AC-6 / AC-3
#
# Resource types: google_project_iam_member, google_project_iam_binding

# ── Primitive project-level roles (owner / editor / viewer) ──────────────────

# Exception key. Must match `control_id` in exceptions/registry.yaml exactly;
# a typo grants nothing, which is the safe direction to fail.
control_id := "privileged-access"

primitive_role contains finding if {
	r := input.resource_changes[_]
	r.type in {"google_project_iam_member", "google_project_iam_binding"}
	utils.is_active_change(r.change)
	r.change.after.role in utils.primitive_roles
	not exceptions.granted(r.address, control_id)
	finding := {
		"address": r.address,
		"role": r.change.after.role,
	}
}

# ── Public / unauthenticated members ─────────────────────────────────────────
#
# Two rules because the plan shape differs: `google_project_iam_member` carries a
# single `member`, `google_project_iam_binding` carries a `members` array.

public_member contains finding if {
	r := input.resource_changes[_]
	r.type == "google_project_iam_member"
	utils.is_active_change(r.change)
	r.change.after.member in utils.public_members
	not exceptions.granted(r.address, control_id)
	finding := {
		"address": r.address,
		"member": r.change.after.member,
		"shape": "member",
	}
}

public_member contains finding if {
	r := input.resource_changes[_]
	r.type == "google_project_iam_binding"
	utils.is_active_change(r.change)
	member := r.change.after.members[_]
	member in utils.public_members
	not exceptions.granted(r.address, control_id)
	finding := {
		"address": r.address,
		"member": member,
		"shape": "binding",
	}
}
