# Runbook 05: reproduce the real-drift demo

Uses `demo/main.tf` (a bucket, a topic and an IAM binding in your project; cost is negligible).

```bash
cd demo
export TF_VAR_project_id=<project> TF_VAR_iam_member=user:<you>
terraform init && terraform plan -out=demo.plan && terraform apply demo.plan      # review the plan first

B=gs://<project>-drift-demo
gcloud storage buckets update $B --update-labels=cost-center=4410
gcloud storage buckets update $B --no-versioning
gcloud storage buckets add-iam-policy-binding $B --member=serviceAccount:<some-sa> --role=roles/storage.objectViewer
gcloud pubsub topics delete drift-demo-events

sleep 45                                                                          # audit log latency
terraform plan -refresh-only -out=drift.plan && terraform show -json drift.plan > drift.json
driftriage triage drift.json --audit-project <project> --llm vertex

terraform plan -destroy -out=destroy.plan && terraform apply destroy.plan         # clean up
```

Expected: the topic (critical, deleted), the IAM binding (critical, member added by a human) and the bucket (high, versioning off, label added) are all
reported with your principal from the audit log.
