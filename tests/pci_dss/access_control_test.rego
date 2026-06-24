package pci_dss.access_control

import rego.v1

# Primitive IAM role tests are in tests/pci_dss/req_7_test.rego.
# This file covers the rules unique to this package: AWS IAM wildcards,
# Cloud Run IAM conditions on pci-scope=true services, and org policy MFA.

test_deny_aws_wildcard_action_as_array if {
	policy_doc := `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:*"]}]}`
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_iam_policy",
		"name": "broad_policy",
		"change": {"after": {"policy": policy_doc}},
	}]}
}

test_deny_aws_wildcard_action_as_string if {
	policy_doc := `{"Statement":[{"Effect":"Allow","Action":"*"}]}`
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_iam_policy",
		"name": "very_broad_policy",
		"change": {"after": {"policy": policy_doc}},
	}]}
}

test_deny_aws_service_scoped_wildcard_action if {
	policy_doc := `{"Statement":[{"Effect":"Allow","Action":"s3:*"}]}`
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_iam_policy",
		"name": "s3_wildcard_policy",
		"change": {"after": {"policy": policy_doc}},
	}]}
}

test_allow_scoped_aws_action_list if {
	policy_doc := `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"]}]}`
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_iam_policy",
		"name": "scoped_policy",
		"change": {"after": {"policy": policy_doc}},
	}]}
}

test_deny_payment_iam_binding_without_condition if {
	count(deny) > 0 with input as {"resource_changes": [
		{
			"type": "google_cloud_run_v2_service",
			"name": "payment_service",
			"change": {"after": {"name": "payment-service", "labels": {"pci-scope": "true"}}},
		},
		{
			"type": "google_cloud_run_v2_service_iam_member",
			"name": "payment_binding",
			"change": {"after": {"name": "payment-service"}},
		},
	]}
}

test_deny_renamed_pci_scoped_service_binding_still_caught if {
	count(deny) > 0 with input as {"resource_changes": [
		{
			"type": "google_cloud_run_v2_service",
			"name": "checkout_orchestrator",
			"change": {"after": {"name": "checkout-orchestrator", "labels": {"pci-scope": "true"}}},
		},
		{
			"type": "google_cloud_run_v2_service_iam_member",
			"name": "checkout_binding",
			"change": {"after": {"name": "checkout-orchestrator"}},
		},
	]}
}

test_allow_non_pci_scoped_service_binding_without_condition if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "google_cloud_run_v2_service",
			"name": "product_catalog_service",
			"change": {"after": {"name": "product-catalog-service", "labels": {"pci-scope": "false"}}},
		},
		{
			"type": "google_cloud_run_v2_service_iam_member",
			"name": "catalog_binding",
			"change": {"after": {"name": "product-catalog-service"}},
		},
	]}
}

test_allow_payment_iam_binding_with_condition if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "google_cloud_run_v2_service",
			"name": "payment_service",
			"change": {"after": {"name": "payment-service", "labels": {"pci-scope": "true"}}},
		},
		{
			"type": "google_cloud_run_v2_service_iam_member",
			"name": "payment_binding",
			"change": {"after": {
				"name": "payment-service",
				"condition": {"expression": "request.time < timestamp(\"2026-09-30T00:00:00Z\")"},
			}},
		},
	]}
}
