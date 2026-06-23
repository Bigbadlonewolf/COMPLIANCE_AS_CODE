package pci_dss.encryption_at_rest

import future.keywords.if

test_deny_unencrypted_cloud_sql if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_sql_database_instance",
		"name": "orders_db",
		"change": {"after": {"encryption_key_name": ""}},
	}]}
}

test_deny_null_encryption_key_does_not_bypass if {
	# Regression test for the null-bypass bug a reviewer found: a missing/
	# null field must NOT be treated as "encrypted." Terraform plan JSON
	# represents an unset attribute as null, not "", so this is the
	# realistic shape of an actual misconfigured resource.
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_sql_database_instance",
		"name": "orders_db",
		"change": {"after": {"encryption_key_name": null}},
	}]}
}

test_allow_encrypted_cloud_sql if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_sql_database_instance",
		"name": "orders_db",
		"change": {"after": {"encryption_key_name": "projects/securecart/locations/us-central1/keyRings/cde/cryptoKeys/orders"}},
	}]}
}

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
	# Regression test for the name-substring bug: an SSE config resource
	# that exists in the plan but points at a DIFFERENT bucket's `bucket`
	# attribute must not satisfy this bucket's requirement.
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
