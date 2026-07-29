package lib.exceptions

import rego.v1

# Risk-acceptance exceptions.
#
# An exception suppresses ONE control's finding for ONE resource address, and
# only until its expiration date. It is not a global mute and it cannot be made
# permanent — an entry with no expiration date, or a past one, grants nothing.
#
# The registry is data, not policy: `exceptions/registry.yaml`, loaded as
# `data.exceptions`. See docs/GOVERNANCE.md for the request process.
#
# ─────────────────────────────────────────────────────────────────────────────
# FAIL-CLOSED BY CONSTRUCTION
#
# `granted` is a partial function. When the registry is absent — no `-d
# exceptions/`, a deleted file, a typo'd path — it is undefined for every input,
# so `not exceptions.granted(...)` is TRUE and every control denies as normal.
#
# That ordering is deliberate and load-bearing. The dangerous failure for an
# exception mechanism is the one where losing the registry silently suppresses
# nothing and everything passes; here, losing the registry suppresses nothing
# and everything is enforced.
#
# A MALFORMED expiration_date is a different case: `time.parse_rfc3339_ns`
# raises, which aborts evaluation and fails the build. That is intended. A
# garbled date must not be silently treated as either valid or expired — the
# two readings differ by exactly the thing the control was protecting. CI
# validates the registry shape separately so this surfaces as a clear error
# rather than an eval trace.
# ─────────────────────────────────────────────────────────────────────────────

granted(address, control_id) if {
	e := data.exceptions[_]
	e.resource_address == address
	e.control_id == control_id
	not expired(e)
}

# Dates are plain YYYY-MM-DD. An exception expires at the START of its
# expiration date, so `expiration_date: 2026-08-01` is dead on 2026-08-01
# rather than lingering through it. Ambiguity in an expiry boundary is how
# "temporary" becomes permanent.
expired(e) if {
	expiry_ns := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [e.expiration_date]))
	expiry_ns <= time.now_ns()
}

# An entry with no expiration_date at all grants nothing. Stated as its own
# rule rather than relying on the parse above erroring, so the intent survives
# a future refactor of `expired`.
expired(e) if not e.expiration_date

# Every exception currently present in the registry that names a resource in
# this plan. Reported so a suppressed finding leaves a trace — an exception
# nobody can see is indistinguishable from a policy that never fired.
active_for_plan contains e if {
	e := data.exceptions[_]
	not expired(e)
	input.resource_changes[_].address == e.resource_address
}
