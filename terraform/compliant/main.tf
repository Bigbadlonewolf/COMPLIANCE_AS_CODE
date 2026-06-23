terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project ID for the CDE environment"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "kms_key_id" {
  type        = string
  description = "Fully-qualified KMS CryptoKey resource ID for CMEK"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ── Network: deny-all default + allow internal only ──────────────────────────
# Satisfies: PCI DSS 1.3.2, NIST AC-17

resource "google_compute_firewall" "deny_all_ingress" {
  name      = "deny-all-ingress"
  network   = "default"
  direction = "INGRESS"
  priority  = 65534
  deny { protocol = "all" }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_internal" {
  name      = "allow-internal"
  network   = "default"
  direction = "INGRESS"
  priority  = 1000
  allow { protocol = "tcp" }
  allow { protocol = "udp" }
  allow { protocol = "icmp" }
  source_ranges = ["10.0.0.0/8"]
}

resource "google_compute_firewall" "allow_lb_health_checks" {
  name      = "allow-lb-health-checks"
  network   = "default"
  direction = "INGRESS"
  priority  = 900
  allow { protocol = "tcp", ports = ["80", "443"] }
  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
}

# ── KMS: 90-day key rotation ──────────────────────────────────────────────────
# Satisfies: PCI DSS 6.3.5, SOC2 CC7.1, NIST SC-28

resource "google_kms_key_ring" "main" {
  name     = "cde-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "sql" {
  name            = "cloud-sql-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s" # 90 days
  purpose         = "ENCRYPT_DECRYPT"
  lifecycle { prevent_destroy = true }
}

resource "google_kms_crypto_key" "gcs" {
  name            = "gcs-audit-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"
  purpose         = "ENCRYPT_DECRYPT"
  lifecycle { prevent_destroy = true }
}

# ── Cloud SQL: private IP, SSL-only, CMEK, backups, pgaudit ──────────────────
# Satisfies: PCI DSS 2.2.1, 6.3.5, 6.5.3, 10.2.1; SOC2 CC6.6, CC6.7, CC8.1;
#            NIST SC-8, SC-28, AU-2, AU-12

resource "google_sql_database_instance" "main" {
  name                = "cde-db"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = true

  encryption_key_name = var.kms_key_id

  settings {
    tier              = "db-n1-standard-2"
    availability_type = "REGIONAL"

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/${var.project_id}/global/networks/default"
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "02:00"
      transaction_log_retention_days = 7
    }

    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_statement"
      value = "ddl"
    }
  }
}

# ── Storage: WORM audit log bucket with CMEK, uniform access ─────────────────
# Satisfies: PCI DSS 2.2.1, 6.3.5, 10.3.2; SOC2 CC6.7, CC7.2; NIST AU-9, SC-28

resource "google_storage_bucket" "audit_logs" {
  name                        = "${var.project_id}-audit-logs"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.gcs.id
  }

  versioning { enabled = true }

  retention_policy {
    is_locked        = true
    retention_period = 31536000 # 365 days
  }

  lifecycle_rule {
    condition { age = 90 }
    action { type = "SetStorageClass", storage_class = "COLDLINE" }
  }
}

# ── IAM: least-privilege service accounts only ────────────────────────────────
# Satisfies: PCI DSS 7.2.1, 7.2.5, 7.2.6; SOC2 CC6.1, CC6.3; NIST AC-3, AC-6

resource "google_service_account" "app" {
  account_id   = "sa-app"
  display_name = "Application Service Account"
  project      = var.project_id
}

resource "google_project_iam_member" "app_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_project_iam_member" "app_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.app.email}"
}

# ── Audit config: capture all admin and data access ───────────────────────────
# Satisfies: PCI DSS 10.2.1; NIST AU-2, AU-12

resource "google_project_iam_audit_config" "all_services" {
  project = var.project_id
  service = "allServices"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}
