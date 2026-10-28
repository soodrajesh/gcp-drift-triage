# Runbook 02: triage a drift report

1. In your Terraform root: `terraform plan -refresh-only -out=drift.plan && terraform show -json drift.plan > drift.json`.
2. `driftriage triage drift.json --audit-project <project> --llm vertex` or upload the file in the UI (audit source: *Cloud Audit Logs*).
3. Work top-down: CRITICAL/HIGH *investigate* first. Read the actor line: a human changing access by hand outside CI is the main signal.
4. `ignore` items need no action (consider `lifecycle { ignore_changes = [...] }` for controller-managed attributes).
5. `adopt` items: apply the listed code edits, then `terraform apply -refresh-only -target=...`.
Treat `drift.json` as sensitive (it contains resource values).
