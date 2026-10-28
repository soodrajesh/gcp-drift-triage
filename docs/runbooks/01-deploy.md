# Runbook 01: deploy

1. `cp deploy.env.example deploy.env` (PROJECT_ID, REGION, ADMIN_EMAIL); `gcloud auth login`.
2. `./scripts/up.sh`: foundation, Cloud Build image, Cloud Run. Each Terraform change is a saved plan that is summarised first; destroys need `ALLOW_DESTROY=1`.
3. `gcloud run services proxy drift-triage --region us-central1 --port 8081`.
4. Verify: unauthenticated `curl <url>/` returns 403; with an identity token `/api/config` shows `audit_project`.
