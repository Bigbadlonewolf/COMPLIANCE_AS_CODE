package pci_dss.encryption_at_rest

import rego.v1

# PCI DSS Requirement 3.5 / 3.6 — render stored data unreadable, manage keys properly.
#
# NOTE: GCP Cloud SQL and Cloud Storage CMEK checks are in
# pci_dss/req_6_secure_systems.rego to avoid duplicate violation messages.
# This package covers AWS RDS, AWS S3, Azure Storage encryption, and
# secret detection in compute environment variables (GCP Cloud Run + AWS Lambda).

# ── AWS and Azure: CMEK / storage encryption ─────────────────────────────────

encryptable_types := {
	"aws_db_instance",
	"azurerm_storage_account",
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type in encryptable_types
	not is_encrypted(resource)
	msg := sprintf(
		"%s '%s' has no customer-managed encryption key configured (or the field is null/empty) — PCI DSS Req 3.6 requires documented key management, not provider-default encryption alone",
		[resource.type, resource.name],
	)
}

# aws_s3_bucket encryption is a separate resource as of provider v4+.
# A bucket with no matching SSE-configuration resource in the plan is unencrypted.
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket"
	not has_matching_sse_config(resource)
	msg := sprintf(
		"aws_s3_bucket '%s' has no corresponding aws_s3_bucket_server_side_encryption_configuration resource — PCI DSS Req 3.6 requires customer-managed key encryption",
		[resource.name],
	)
}

has_matching_sse_config(resource) if {
	bucket_ref := object.get(resource.change.after, "bucket", resource.name)
	cfg := input.resource_changes[_]
	cfg.type == "aws_s3_bucket_server_side_encryption_configuration"
	cfg.change.after.bucket == bucket_ref
	kms_key := cfg.change.after.rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id
	has_value(kms_key)
}

# has_value rejects both null AND "". Terraform plan JSON represents an unset
# attribute as null — `null != ""` is true, so only checking != "" lets null
# bypass this guard silently.
has_value(x) if {
	x != null
	x != ""
}

is_encrypted(resource) if {
	resource.type == "aws_db_instance"
	resource.change.after.storage_encrypted == true
	has_value(resource.change.after.kms_key_id)
}

is_encrypted(resource) if {
	resource.type == "azurerm_storage_account"
	has_value(resource.change.after.customer_managed_key[_].key_vault_key_id)
}

# ── Secret detection in compute environment variables ────────────────────────

secret_keywords := {"key", "secret", "password", "token", "stripe"}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "google_cloud_run_v2_service"
	env := resource.change.after.template[_].containers[_].env[_]
	some kw in secret_keywords
	contains(lower(env.name), kw)
	has_value(env.value)
	not contains(env.name, "SECRET_MANAGER_REF")
	msg := sprintf(
		"google_cloud_run_v2_service '%s' has a credential-shaped value ('%s') in a plain container env var — must reference Secret Manager via a *_SECRET_MANAGER_REF convention or secret volume mount",
		[resource.name, env.name],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_lambda_function"
	vars := resource.change.after.environment[_].variables
	some var_name, var_value in vars
	some kw in secret_keywords
	contains(lower(var_name), kw)
	has_value(var_value)
	not contains(var_name, "SECRET_MANAGER_REF")
	msg := sprintf(
		"aws_lambda_function '%s' has a credential-shaped value in environment.variables['%s'] — must reference Secrets Manager / SSM Parameter Store, not a plaintext env variable",
		[resource.name, var_name],
	)
}
