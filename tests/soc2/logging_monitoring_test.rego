package soc2.logging_monitoring

import future.keywords.if

test_deny_short_retention_gcp_bucket_config if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_logging_project_bucket_config",
		"name": "audit_bucket",
		"change": {"after": {"retention_days": 30}},
	}]}
}

test_allow_compliant_retention_gcp_bucket_config if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_logging_project_bucket_config",
		"name": "audit_bucket",
		"change": {"after": {"retention_days": 400}},
	}]}
}

test_deny_short_retention_cloudwatch if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_cloudwatch_log_group",
		"name": "payment_logs",
		"change": {"after": {"retention_in_days": 90}},
	}]}
}

test_allow_cloudwatch_with_no_retention_set_is_infinite_and_compliant if {
	# Regression test for the false-positive bug: an absent
	# retention_in_days means "never expire" in AWS, which is MORE
	# compliant than the 365-day floor, not a violation.
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_cloudwatch_log_group",
		"name": "payment_logs",
		"change": {"after": {}},
	}]}
}

test_allow_cloudwatch_with_long_explicit_retention if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_cloudwatch_log_group",
		"name": "payment_logs",
		"change": {"after": {"retention_in_days": 730}},
	}]}
}

test_deny_renamed_service_without_monitored_label_still_caught if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "checkout_orchestrator",
		"change": {"after": {"labels": {}}},
	}]}
}

test_allow_service_with_label_and_matching_alert_policy if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "google_cloud_run_v2_service",
			"name": "payment_service",
			"change": {"after": {"name": "payment-service", "labels": {"monitored": "true", "monitor-id": "payment-service-monitor"}}},
		},
		{
			"type": "google_monitoring_alert_policy",
			"name": "payment_service_alerts",
			"change": {"after": {
				"display_name": "payment-service-error-rate",
				"user_labels": {"monitors": "payment-service-monitor"},
			}},
		},
	]}
}

test_deny_service_with_monitored_true_but_no_monitor_id if {
	# Regression test: 'monitored: true' alone is not enough — without an
	# explicit monitor-id to cross-reference against an alerting resource,
	# the declaration is unverifiable and must still be denied.
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "payment_service",
		"change": {"after": {"name": "payment-service", "labels": {"monitored": "true"}}},
	}]}
}

test_deny_lambda_monitoring_with_no_satisfiable_allow_path if {
	# Regression test for the bug where aws_lambda_function was listed as
	# monitorable but no AWS alert resource type was ever checked, making
	# this permanently denied regardless of configuration. Confirms the
	# deny still fires when no matching CloudWatch alarm exists at all.
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_lambda_function",
		"name": "payment_webhook_handler",
		"change": {"after": {"function_name": "payment-webhook-handler", "tags": {"monitored": "true", "monitor-id": "payment-webhook-monitor"}}},
	}]}
}

test_allow_lambda_with_matching_cloudwatch_alarm if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "aws_lambda_function",
			"name": "payment_webhook_handler",
			"change": {"after": {"function_name": "payment-webhook-handler", "tags": {"monitored": "true", "monitor-id": "payment-webhook-monitor"}}},
		},
		{
			"type": "aws_cloudwatch_metric_alarm",
			"name": "payment_webhook_handler_errors",
			"change": {"after": {"tags": {"monitors": "payment-webhook-monitor"}}},
		},
	]}
}
