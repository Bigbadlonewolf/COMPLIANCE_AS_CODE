package lib.utils

import rego.v1

# Primitive IAM roles that violate least-privilege requirements.
# Any project-level binding with these roles is an automatic PCI/SOC2/NIST violation.
primitive_roles := {
	"roles/owner",
	"roles/editor",
	"roles/viewer",
}

# IAM members that grant public, unauthenticated access.
public_members := {
	"allUsers",
	"allAuthenticatedUsers",
}

# Ports that must never be reachable from 0.0.0.0/0 on an ingress rule.
# Web ports (80, 443) are intentionally excluded — they are legitimate public endpoints.
sensitive_ports := {
	"22",    # SSH
	"3389",  # RDP
	"1433",  # MSSQL
	"3306",  # MySQL
	"5432",  # PostgreSQL
	"6379",  # Redis
	"9200",  # Elasticsearch HTTP
	"9300",  # Elasticsearch cluster
	"27017", # MongoDB
	"2379",  # etcd client
	"2380",  # etcd peer
	"6443",  # Kubernetes API server
}

# One year in seconds — used for KMS key rotation enforcement.
one_year_seconds := 31536000

# Returns true when the resource change is a create or update (not a destroy).
is_active_change(change) if change.actions[_] in {"create", "update"}
