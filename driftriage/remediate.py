"""Commands and code edits for each decision. Nothing here is executed."""

from __future__ import annotations

import json
from typing import Any

from .models import Drift


def hcl(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return f"{v:g}" if isinstance(v, float) else str(v)
    if isinstance(v, str):
        return json.dumps(v)
    return json.dumps(v)


def attach(d: Drift) -> Drift:
    t = f"-target='{d.address}'"
    if d.decision == "ignore":
        return d
    if d.kind == "deleted":
        d.commands = [
            f"terraform plan {t} -out=recreate.plan   # review, then: terraform apply recreate.plan",
            f"terraform state rm '{d.address}'         # only if the deletion was intentional",
        ]
        return d
    if d.decision == "adopt":
        d.hcl = [f"{d.address}: set {c.path} = {hcl(c.after)}" for c in d.changes]
        d.commands = [
            f"terraform apply -refresh-only {t}   # accept live values into state after editing code"
        ]
    else:  # investigate: reverting is the safe default; adopting is a conscious choice after review
        d.commands = [
            f"terraform plan {t} -out=revert.plan   # shows the revert; review, then: terraform apply revert.plan"
        ]
        d.hcl = [
            f"# if the change is intended, edit code instead: {d.address}: {c.path} = {hcl(c.after)}"
            for c in d.changes
            if c.severity not in ("info",)
        ]
    return d
