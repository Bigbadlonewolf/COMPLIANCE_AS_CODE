package pci_dss.encryption_at_rest

import rego.v1

# GCP Cloud SQL and Cloud Storage CMEK tests are in tests/pci_dss/req_6_test.rego.
# This file covers AWS RDS, AWS S3, Azure Storage encryption, and
# secret detection in compute environment variables.

# ── AWS S3 SSE config ────────────────────────────────────────────────────────

test_deny_s3_bucket_without_sse_config_resource if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket",
		"name": "orders_archive",
		"change": {"after": {"bucket": "securecart-orders-archive"}},
	}]}
}

test_allow_s3_bucket_with_matching_sse_config if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "aws_s3_bucket",
			"name": "orders_archive",
			"change": {"after": {"bucket": "securecart-orders-archive"}},
		},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "orders_archive_sse",
			"change": {"after": {
				"bucket": "securecart-orders-archive",
				"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": "arn:aws:kms:us-east-1:111111111111:key/abc"}]}],
			}},
		},
	]}
}

test_deny_s3_bucket_sse_config_for_different_bucket_does_not_count if {
	count(deny) > 0 with input as {"resource_changes": [
		{
			"type": "aws_s3_bucket",
			"name": "orders_archive",
			"change": {"after": {"bucket": "securecart-orders-archive"}},
		},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "unrelated_sse",
			"change": {"after": {
				"bucket": "some-other-bucket",
				"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": "arn:aws:kms:us-east-1:111111111111:key/abc"}]}],
			}},
		},
	]}
}

# ── Secret detection: Cloud Run ──────────────────────────────────────────────

test_deny_plaintext_stripe_key_in_cloud_run_env if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "payment_service",
		"change": {"after": {"template": [{"containers": [{"env": [{"name": "STRIPE_SECRET_KEY", "value": "sk_live_abc123"}]}]}]}},
	}]}
}

test_allow_secret_manager_reference_in_cloud_run_env if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "payment_service",
		"change": {"after": {"template": [{"containers": [{"env": [{"name": "STRIPE_SECRET_KEY_SECRET_MANAGER_REF", "value": "projects/securecart/secrets/stripe-key"}]}]}]}},
	}]}
}

# ── Secret detection: AWS Lambda ─────────────────────────────────────────────

test_deny_plaintext_secret_in_lambda_env_map if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_lambda_function",
		"name": "payment_webhook_handler",
		"change": {"after": {"environment": [{"variables": {"STRIPE_SECRET_KEY": "sk_live_abc123"}}]}},
	}]}
}

test_allow_secret_manager_reference_in_lambda_env_map if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_lambda_function",
		"name": "payment_webhook_handler",
		"change": {"after": {"environment": [{"variables": {"STRIPE_SECRET_KEY_SECRET_MANAGER_REF": "arn:aws:secretsmanager:us-east-1:111111111111:secret:stripe"}}]}},
	}]}
}

# ── Azure Storage CMEK ───────────────────────────────────────────────────────

test_deny_unencrypted_azure_storage_account if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_storage_account",
		"name": "orders_blob_storage",
		"change": {"after": {"customer_managed_key": []}},
	}]}
}

test_deny_null_azure_cmk_key_vault_id_does_not_bypass if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_storage_account",
		"name": "orders_blob_storage",
		"change": {"after": {"customer_managed_key": [{"key_vault_key_id": null}]}},
	}]}
}

test_allow_encrypted_azure_storage_account if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "azurerm_storage_account",
		"name": "orders_blob_storage",
		"change": {"after": {"customer_managed_key": [{"key_vault_key_id": "https://securecart-kv.vault.azure.net/keys/orders/abc123"}]}},
	}]}
}
