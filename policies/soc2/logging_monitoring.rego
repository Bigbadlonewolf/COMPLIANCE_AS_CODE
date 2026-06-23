package soc2.logging_monitoring

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# SOC2 CC7.2 — the entity monitors system components and the operation of
# controls to detect anomalies. Maps loosely to PCI DSS Req 10 as well.
#
# CHANGE LOG (latest fix pass):
# - Fixed: aws_lambda_function was listed in monitorable_types, but the
#   only satisfiable allow-path checked for google_monitoring_alert_policy.
#   There was no AWS equivalent, so any Lambda function failed this check
#   permanently — not "usually fails," PERMANENTLY, regardless of how
#   correctly it was configured. A monitorable type with no satisfiable
#   allow path is worse than no check at all.
# - Fixed: missing retention_in_days on aws_cloudwatch_log_group means
#   "never expire" (infinite retention) in AWS's actual semantics, not
#   "0 days." The old object.get(..., 0) default treated the MOST
#   compliant possible configuration as a violation.
# - Fixed (overcorrection from a prior fix): comparing alert policy
#   display_name to the service's exact name traded a too-loose substring
#   match for a too-strict exact match — real naming conventions
#   (e.g. "payment-service - error rate alert") would never match exactly,
#   producing constant false positives. Replaced both the substring and
#   the exact-match approaches with an explicit cross-reference label,
#   consistent with how pci-scope is already handled elsewhere in this
#   repo: the monitored resource must carry a `monitors` label naming
#   itself, and the alert policy must carry a matching label. This is
#   slightly more setup burden on whoever writes the Terraform, in
#   exchange for zero ambiguity about whether two resources are actually
#   linked.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_logging_project_bucket_config"
	retention := object.get(resource.change.after, "retention_days", 0)
	retention < 365
	msg := sprintf(
		"Log bucket config '%s' has retention of %d days — SOC2 CC7.2 evidence requires at least 365 days of retained audit logs",
		[resource.name, retention],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_cloudwatch_log_group"
	retention := object.get(resource.change.after, "retention_in_days", null)
	retention != null
	retention < 365
	msg := sprintf(
		"CloudWatch log group '%s' has retention of %d days — below the 365-day SOC2 evidence requirement",
		[resource.name, retention],
	)
}

monitorable_types := {"google_cloud_run_v2_service", "aws_lambda_function"}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type in monitorable_types
	not has_explicit_monitoring_declaration(resource)
	msg := sprintf(
		"%s '%s' has no explicit 'monitored' label/tag with a matching 'monitor-id', and/or no alerting resource declares a matching 'monitors' label — SOC2 CC7.2 requires automated anomaly detection, declared explicitly and unambiguously linked, not inferred from naming conventions or dashboard wiring",
		[resource.type, resource.name],
	)
}

# Fixed (this pass): removed a silent fallback that defaulted the
# cross-reference ID to the Terraform block's local label when no
# `monitor-id` tag was set. That fallback reintroduced exactly the kind of
# naming-convention coupling this design is supposed to avoid. The
# `monitor-id` value is now required explicitly — no default, no guess —
# and the same value must appear on the alerting resource's `monitors`
# tag/label on EITHER cloud (GCP `user_labels`, AWS `tags`), so there's
# one mechanism to reason about instead of two different ones per cloud.
has_explicit_monitoring_declaration(resource) if {
	tags := object.get(resource.change.after, "labels", object.get(resource.change.after, "tags", {}))
	tags["monitored"] == "true"
	monitor_id := tags["monitor-id"]
	has_matching_alert_resource(monitor_id)
}

has_matching_alert_resource(monitor_id) if {
	policy := input.resource_changes[_]
	policy.type == "google_monitoring_alert_policy"
	object.get(policy.change.after, "user_labels", {})["monitors"] == monitor_id
}

has_matching_alert_resource(monitor_id) if {
	alarm := input.resource_changes[_]
	alarm.type == "aws_cloudwatch_metric_alarm"
	object.get(alarm.change.after, "tags", {})["monitors"] == monitor_id
}
