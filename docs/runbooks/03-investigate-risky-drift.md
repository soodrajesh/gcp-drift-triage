# Runbook 03: investigate a risky drift

1. Confirm the audit evidence: principal, method, time, caller IP. Ask the owner whether it was intentional (a ticket reference in labels helps).
2. Unintended or unknown: revert. `terraform plan -target='<addr>' -out=revert.plan`, read it, then `terraform apply revert.plan`.
3. Intended: change the code to match, review as a normal PR, then `terraform apply -refresh-only -target='<addr>'`.
4. Public IAM or `0.0.0.0/0`: treat as an incident. Revert first, then review access logs for the exposure window and rotate anything exposed.
5. Deleted stateful resource: check backups before recreating; recreation does not restore data.
6. "no audit trail": the change may be older than 7 days or made through a path not logged as Admin Activity. Widen `since_days` or query Data Access logs manually.
