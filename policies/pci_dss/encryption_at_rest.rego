package pci_dss.encryption_at_rest

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# PCI DSS Requirement 3.5 / 3.6 — render stored data unreadable, manage keys properly.
#
# CHANGE LOG (post-adversarial-review fixes):
# - has_value() now explicitly rejects null AND "" — the original `!= ""`
#   check let a missing/null field pass as "encrypted" because in Terraform's
#   JSON plan output, an unset attribute serializes as null, and `null != ""`
#   evaluates to true in Rego. This was the single most dangerous bug in the
#   repo: a control that's easier to silently bypass than to actually satisfy
#   is worse than no control.
# - aws_s3_bucket's inline server_side_encryption_configuration block was
#   removed from the AWS provider in v4+. Encryption is now its own resource:
#   aws_s3_bucket_server_side_encryption_configuration. Checking the old
#   shape meant this policy was auditing a schema that no longer exists.

encryptable_types := {
	"google_sql_database_instance",
	"google_storage_bucket",
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

# aws_s3_bucket encryption is a separate resource as of provider v4+. A bucket
# with no matching SSE-configuration resource in the same plan is unencrypted.
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket"
	not has_matching_sse_config(resource)
	msg := sprintf(
		"aws_s3_bucket '%s' has no corresponding aws_s3_bucket_server_side_encryption_configuration resource — PCI DSS Req 3.6 requires customer-managed key encryption, and bucket-level SSE blocks are no longer valid syntax in provider v4+",
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

# has_value rejects both the empty string AND null/missing. This is the fix
# for the CMEK-null bypass: object.get's default only fires when the key is
# entirely absent, not when it's present-but-null, so we check both forms.
has_value(x) if {
	x != null
	x != ""
}

is_encrypted(resource) if {
	resource.type == "google_sql_database_instance"
	has_value(resource.change.after.encryption_key_name)
}

is_encrypted(resource) if {
	resource.type == "google_storage_bucket"
	has_value(resource.change.after.encryption[_].default_kms_key_name)
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

# --- Deny: secrets stored as plain environment variables instead of Secret Manager / KMS ---
#
# Fixed: google_cloud_run_v2_service nests env vars under
# template[0].containers[_].env, not a top-level `env` field. The original
# top-level read meant this check never fired against the real schema.
# aws_lambda_function exposes them as a MAP under environment[0].variables,
# not a list of {name, value} objects — the original code assumed the
# Cloud Run list shape for both resource types.

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
		"google_cloud_run_v2_service '%s' has a credential-shaped value ('%s') in a plain container env var — must reference Secret Manager via a *_SECRET_MANAGER_REF naming convention or secret volume mount instead",
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
		"aws_lambda_function '%s' has a credential-shaped value in environment.variables['%s'] — must reference Secrets Manager / SSM Parameter Store, not a plaintext Lambda environment variable",
		[resource.name, var_name],
	)
}
