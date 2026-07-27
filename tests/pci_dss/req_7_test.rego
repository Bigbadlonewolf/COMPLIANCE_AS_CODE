package pci_dss.req_7_test

import rego.v1

import data.pci_dss.req_7

# req_7 is a CITATION LAYER over controls.privileged_access. Detection logic —
# which roles count as primitive, which members count as public, the member vs
# binding plan shapes, destroy-only changes — is asserted once in
# tests/controls/privileged_access_test.rego. These tests prove only that PCI
# cites the right requirement, and that the two message shapes stay distinct.

iam(rtype, after) := {"resource_changes": [{
	"address": sprintf("%s.t", [rtype]),
	"type": rtype,
	"change": {"actions": ["create"], "after": after},
}]}

cited(msgs, citation) if count([m | m := msgs[_]; startswith(m, citation)]) > 0

# ── 7.2.5 — least privilege, no primitive roles ─────────────────────────────

test_primitive_role_cites_7_2_5 if {
	cited(req_7.deny, "PCI DSS 7.2.5") with input as iam("google_project_iam_member", {"role": "roles/owner"})
}

# ── 7.2.6 — user IDs and authentication factors managed rigorously ──────────

test_public_member_cites_7_2_6 if {
	cited(req_7.deny, "PCI DSS 7.2.6") with input as iam("google_project_iam_member", {"member": "allUsers"})
}

# The member and binding shapes carry deliberately different wording. Splitting
# them is the reason controls.privileged_access tags findings with `shape`, so
# both paths are asserted here rather than assumed.
test_member_and_binding_wording_stay_distinct if {
	member_msg := [m | m := req_7.deny[_]][0] with input as iam("google_project_iam_member", {"member": "allUsers"})
	binding_msg := [m | m := req_7.deny[_]][0] with input as iam("google_project_iam_binding", {"members": ["allUsers"]})
	contains(member_msg, "IAM member")
	contains(binding_msg, "IAM binding")
}

# ── Allow path ──────────────────────────────────────────────────────────────

test_predefined_role_produces_no_findings if {
	count(req_7.deny) == 0 with input as iam("google_project_iam_member", {
		"role": "roles/cloudsql.client",
		"member": "serviceAccount:sa-app@my-project.iam.gserviceaccount.com",
	})
}
