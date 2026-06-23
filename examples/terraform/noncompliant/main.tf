# INTENTIONALLY NON-COMPLIANT — used in CI to prove the policies actually catch violations.
# Do not deploy this. See examples/terraform/compliant/ for the corrected version.

resource "google_compute_firewall" "allow_ssh_everywhere" {
  name    = "allow-ssh-everywhere"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] # <- PCI DSS 1.2.1 violation
}

resource "google_cloud_run_v2_service" "payment_service" {
  name     = "payment-service"
  location = "us-central1"

  template {
    containers {
      image = "gcr.io/securecart/payment-service:latest"
      env {
        name  = "STRIPE_SECRET_KEY" # <- plaintext secret in env, no Secret Manager ref
        value = "sk_live_REDACTED_EXAMPLE"
      }
    }
  }

  # no labels = { pci-scope = "true" } -> segmentation policy will flag this
}

resource "google_sql_database_instance" "orders_db" {
  name             = "orders-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"
  # no encryption_key_name set -> uses Google-default encryption only,
  # which is fine for many workloads but insufficient evidence for PCI 3.6
  # key-management documentation requirements.
}

resource "google_project_iam_member" "everyone_is_owner" {
  project = "securecart-prod"
  role    = "roles/owner" # <- PCI 7.2.1 / NIST AC-6 violation
  member  = "user:contractor@example.com"
}
