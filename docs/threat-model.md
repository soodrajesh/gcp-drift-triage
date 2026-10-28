# Threat model

| Threat | Mitigation | Test |
|---|---|---|
| Resource names / labels carrying prompt injection | decisions are code-only; model text validated | `test_injection_in_resource_names...` |
| Model calls a risky change benign | model cannot change decision, severity or posture | `test_model_cannot_change_decision_or_severity` |
| Model invents a principal or resource | `check_text` rejects it | `test_note_naming_unknown_principal_or_resource_is_dropped` |
| Links in PR text or notes | rejected | `test_pr_text_with_link_is_dropped` |
| Audit log unavailable | drift still reported, marked degraded and `unknown` actor | `test_audit_failure_does_not_hide_drift` |
| Misattributed change | documented limit; attribution only escalates | `test_actor_never_lowers_severity` |
| Revert command applied blindly | commands are plans (`-out`), never `-auto-approve`; nothing is executed by the tool | by design |
| Tool used to read other projects' logs | audit lookup only for the configured project | `test_api_flow_and_validation` |
| Sensitive data at rest | memory only, 50-entry cap, plan hash only | by design |
| Unauthorised use | Cloud Run IAM, one invoker | live: 403 |

Residual risk: the runtime SA can read audit logs for its project; protect the invoker role.
