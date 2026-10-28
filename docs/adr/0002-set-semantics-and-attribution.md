# ADR 0002: set semantics for lists, audit logs for attribution

**Decision**: lists of scalars are diffed as sets; attribution comes from Admin Activity audit logs and can only escalate severity.
**Why**: found by running against real drift: GCP returns IAM members sorted, so a naive index diff reported a reorder as a new grant; and the audit search must use real resource names, not Terraform names.
**Consequence**: ordered scalar lists are not supported; attribution is a strong lead, not proof (see README limits).
