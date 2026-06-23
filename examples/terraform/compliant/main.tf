# The corrected version of ../noncompliant/main.tf — every violation fixed,
# one-for-one, so the diff itself is documentation.

resource "google_compute_firewall" "allow_ssh_internal_only" {
  name    = "allow-ssh-internal-only"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["10.0.0.0/8"] # restricted to internal range only
}

resource "google_cloud_run_v2_service" "payment_service" {
  name     = "payment-service"
  location = "us-central1"

  labels = {
    "pci-scope"  = "true"
    "monitored"  = "true"
    "monitor-id" = "payment-service-monitor"
  }

  template {
    containers {
      image = "gcr.io/securecart/payment-service:latest"
      env {
        name  = "STRIPE_SECRET_KEY_SECRET_MANAGER_REF"
        value = "projects/securecart-prod/secrets/stripe-secret-key/versions/latest"
      }
    }
    vpc_access {
      connector = google_vpc_access_connector.payment_connector.id
      egress    = "ALL_TRAFFIC"
    }
  }
}

resource "google_monitoring_alert_policy" "payment_service_alerts" {
  display_name = "payment-service-error-rate"
  combiner      = "OR"

  user_labels = {
    "monitors" = "payment-service-monitor"
  }

  conditions {
    display_name = "payment-service error rate"
    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"payment-service\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.05
      duration        = "300s"
    }
  }
}

resource "google_vpc_access_connector" "payment_connector" {
  name   = "payment-vpc-connector"
  region = "us-central1"
  subnet {
    name = "payment-pci-scope"
  }
}

resource "google_sql_database_instance" "orders_db" {
  name             = "orders-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  encryption_key_name = "projects/securecart-prod/locations/us-central1/keyRings/cde/cryptoKeys/orders-db-key"

  settings {
    tier              = "db-custom-2-8192"
    availability_type = "REGIONAL"

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/securecart-prod/global/networks/default"
    }

    backup_configuration {
      enabled = true
    }
  }
}    }
  }
}

resource "google_project_iam_member" "contractor_scoped_access" {
  project = "securecart-prod"
  role    = "roles/cloudsql.viewer" # least-privilege, not roles/owner
  member  = "user:contractor@example.com"

  condition {
    title       = "expires_after_engagement"
    expression  = "request.time < timestamp(\"2026-09-30T00:00:00Z\")"
    description = "Contractor access expires at end of engagement per AC-2(2)/NIST 800-53"
  }
}
