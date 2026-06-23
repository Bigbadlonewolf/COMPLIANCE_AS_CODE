# WARNING: This Terraform configuration is intentionally noncompliant.
# It is used to validate that OPA policies correctly detect violations.
# NEVER deploy this to a real environment.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

variable "project_id" {
  type    = string
  default = "example-project"
}

variable "region" {
  type    = string
  default = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ── VIOLATION: PCI 1.3.2, SOC2 CC6.1, NIST AC-17 ────────────────────────────
# Firewall allows SSH from the public internet.

resource "google_compute_firewall" "allow_ssh_public" {
  name      = "allow-ssh-public"
  network   = "default"
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

# ── VIOLATION: PCI 1.3.2 ─────────────────────────────────────────────────────
# Firewall allows ALL protocols from the internet.

resource "google_compute_firewall" "allow_all_ingress" {
  name      = "allow-all-ingress"
  network   = "default"
  direction = "INGRESS"
  allow { protocol = "all" }
  source_ranges = ["0.0.0.0/0"]
}

# ── VIOLATION: PCI 2.2.1, 6.5.3, 6.3.5, 10.2.1, 10.3.2; SOC2 CC6.6, CC6.7, CC8.1 ──
# SQL: public IP, no SSL enforcement, no CMEK, backups off, no audit flags.

resource "google_sql_database_instance" "insecure" {
  name             = "insecure-db"
  database_version = "POSTGRES_15"
  region           = var.region

  # No encryption_key_name — violates PCI 6.3.5, SOC2 CC6.7, NIST SC-28.

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true                              # violates PCI 2.2.1
      ssl_mode     = "ALLOW_UNENCRYPTED_AND_ENCRYPTED" # violates PCI 6.5.3
    }

    backup_configuration {
      enabled = false # violates PCI 10.3.2, SOC2 CC8.1
    }

    # No database_flags — cloudsql.enable_pgaudit missing (PCI 10.2.1, NIST AU-12)
    # No log_connections flag (NIST AU-2)
  }
}

# ── VIOLATION: PCI 2.2.1, 6.3.5, 10.3.2; SOC2 CC6.7, CC7.2; NIST AU-9, SC-28 ──
# Storage: non-uniform access, no public access prevention, no CMEK, no versioning.

resource "google_storage_bucket" "insecure" {
  name                        = "${var.project_id}-insecure-data"
  location                    = var.region
  uniform_bucket_level_access = false # violates PCI 2.2.1, NIST AU-9
  public_access_prevention    = "inherited" # violates PCI 2.2.1

  # No encryption block — violates PCI 6.3.5, SOC2 CC6.7, NIST SC-28
  # No versioning block — violates PCI 10.3.2, SOC2 CC7.2, NIST AU-9
}

# ── VIOLATION: PCI 7.2.5, SOC2 CC6.3, NIST AC-6 ─────────────────────────────
# Primitive role (owner) assigned at project level.

resource "google_project_iam_member" "owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "user:admin@example.com"
}

# ── VIOLATION: PCI 7.2.6, SOC2 CC6.1, NIST AC-3 ─────────────────────────────
# Public IAM member grants unauthenticated access.

resource "google_project_iam_member" "all_users_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "allUsers"
}

# ── VIOLATION: PCI 6.3.5, SOC2 CC7.1, NIST SC-28 ────────────────────────────
# KMS key with no rotation period.

resource "google_kms_key_ring" "main" {
  name     = "insecure-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "no_rotation" {
  name     = "no-rotation-key"
  key_ring = google_kms_key_ring.main.id
  purpose  = "ENCRYPT_DECRYPT"
  # No rotation_period — violates PCI 6.3.5, SOC2 CC7.1, NIST SC-28
}
