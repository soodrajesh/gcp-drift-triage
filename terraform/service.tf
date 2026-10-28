resource "google_service_account" "app" {
  account_id   = "dt-app"
  display_name = "drift-triage runtime"
}
resource "google_project_iam_member" "app_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.app.email}"
}
# Read Cloud Audit Logs (who changed a resource). Admin Activity logs are readable with logging.viewer.
resource "google_project_iam_member" "app_log_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_cloud_run_v2_service" "app" {
  count               = var.image != "" ? 1 : 0
  name                = "drift-triage"
  location            = var.region
  deletion_protection = false
  labels              = { env = "demo", owner = "platform" }
  template {
    service_account                  = google_service_account.app.email
    timeout                          = "120s"
    max_instance_request_concurrency = 20
    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }
    containers {
      image = var.image
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
      startup_probe {
        http_get { path = "/healthz" }
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "DRIFTRIAGE_LLM"
        value = "vertex"
      }
      env {
        name  = "DRIFTRIAGE_MODEL"
        value = var.model
      }
      env {
        name  = "DRIFTRIAGE_ALLOWED_PROVIDERS"
        value = "vertex,none"
      }
      env {
        name  = "DRIFTRIAGE_AUDIT_PROJECT"
        value = var.project_id
      }
      env {
        name  = "DRIFTRIAGE_DAILY_BUDGET_USD"
        value = tostring(var.daily_budget_usd)
      }
    }
  }
  depends_on = [
    google_project_iam_member.app_vertex,
    google_project_iam_member.app_log_viewer,
  ]
}

# Private: only the admin may invoke. No allUsers binding.
resource "google_cloud_run_v2_service_iam_member" "admin_invoker" {
  count    = var.image != "" ? 1 : 0
  name     = google_cloud_run_v2_service.app[0].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "user:${var.admin_email}"
}
