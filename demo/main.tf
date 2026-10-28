# Throwaway stack used to produce REAL drift for the end-to-end demo (see docs/runbooks/05-real-drift-demo.md).
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project_id" { type = string }
variable "iam_member" {
  type        = string
  description = "The one identity Terraform grants objectViewer on the demo bucket"
}

provider "google" {
  project = var.project_id
  region  = "us-central1"
}

resource "google_storage_bucket" "demo" {
  name                        = "${var.project_id}-drift-demo"
  location                    = "US-CENTRAL1"
  force_destroy               = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = { env = "demo", owner = "platform" }
  versioning {
    enabled = true
  }
}

resource "google_pubsub_topic" "demo" {
  name   = "drift-demo-events"
  labels = { env = "demo", owner = "platform" }
}

resource "google_storage_bucket_iam_binding" "viewers" {
  bucket  = google_storage_bucket.demo.name
  role    = "roles/storage.objectViewer"
  members = [var.iam_member]
}
