# Architecture

**Input** is the JSON of a refresh-only plan: `resource_drift[]` with `change.before` (state) and `change.after` (live).

**Parse** (`parse.py`): flattens both sides. Lists of scalars are compared as sets (`members.+` / `members.-`), because GCP
returns `members` and `source_ranges` sorted. Provider-computed attributes (etags, update times, revisions, `terraform_labels`)
are filtered into `noise`. `labels` in state holds only configured labels, so real label drift arrives via `effective_labels`
and is de-duplicated against `labels`. `hints` collect the real resource names (`name`, `bucket`, `id`...) for audit search.

**Classify** (`classify.py`): ordered rules D001-D008 turn each attribute change into (category, severity, reason).
A drift's decision comes from its worst change: loosening >= medium, reliability/cost >= medium, unknown -> `investigate`;
only all-benign/low -> `adopt`; controller-managed (autoscaler) -> `ignore`; deleted stateful -> critical `investigate`.

**Forensics** (`forensics.py`): per non-ignored drift, queries `logging.googleapis.com/v2/entries:list` for Admin Activity
entries matching the real resource name in the last 7 days, newest first. The principal becomes `human`, `automation`
(service account) or `google`. No events = `unknown`, which is flagged ("no audit trail"), never assumed benign.
Failures are recorded as `degraded` and do not hide the drift.

**Attribute** (`classify.apply_actor`): a human principal on a loosening/reliability change raises severity one level.
Attribution can only escalate, never lower anything.

**Commands** (`remediate.py`): revert = `terraform plan -target=ADDR -out=revert.plan`; adopt = a code edit line plus
`terraform apply -refresh-only -target=ADDR`; deleted = recreate plan or `state rm`. Nothing is executed.

**Agents** (`agents.py`): analyst (top 5 risky) and drafter (adopt set) run in parallel under one budget (12 calls, $0.05).
`check_text` rejects links, principals not in the audit evidence and addresses not in the drift. **Judge** computes posture
from rules and guards the model summary with a template fallback.
