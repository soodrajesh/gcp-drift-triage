"""Parse `terraform show -json <refresh-only plan>`: its `resource_drift` lists what changed
outside Terraform (change.before = state, change.after = live)."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .models import AttrChange, Drift

MAX_DRIFTS = 1000

# Provider-computed or derived attributes that change without anyone touching the resource.
NOISE = re.compile(
    r"(^|\.)(etag|fingerprint|generation|metageneration|update_time|updated|time_created|creation_timestamp|"
    r"self_link|uid|id|terraform_labels|observed_generation|latest_ready_revision|"
    r"latest_created_revision|conditions|reconciling|last_modifier|creator|create_time|delete_time|"
    r"expire_time|instance_id|cpu_platform|label_fingerprint|tags_fingerprint|metadata_fingerprint|"
    r"settings\.\d+\.version|template\.\d+\.revision|traffic_statuses\.\d+\.(revision|percent)|"
    r"labels\.goog-[^.]+|effective_annotations|annotations\.run\.googleapis\.com/.+)(\..*)?$"
)


class DriftParseError(ValueError):
    pass


def plan_sha256(doc: Any) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()


def flatten(v: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for k, x in v.items():
            out.update(flatten(x, f"{prefix}.{k}" if prefix else k))
        return out
    if isinstance(v, list):
        if not v:
            return {prefix: []}
        out = {}
        for i, x in enumerate(v):
            out.update(flatten(x, f"{prefix}.{i}"))
        return out
    return {prefix: v}


def _is_scalar_list(v: Any) -> bool:
    return (
        isinstance(v, list) and v != [] and all(isinstance(x, (str, int, float, bool)) for x in v)
    )


def flatten_sets(v: Any, prefix: str = "") -> dict[str, Any]:
    """Like flatten, but a list of scalars becomes a set: GCP returns members / source_ranges
    sorted, and a reorder must not look like a change. Elements become `path.=<value>` keys."""
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for k, x in v.items():
            out.update(flatten_sets(x, f"{prefix}.{k}" if prefix else k))
        return out
    if _is_scalar_list(v):
        return {f"{prefix}.={x}": x for x in v}
    if isinstance(v, list):
        if not v:
            return {}
        out = {}
        for i, x in enumerate(v):
            out.update(flatten_sets(x, f"{prefix}.{i}"))
        return out
    return {prefix: v}


def diff(before: Any, after: Any) -> tuple[list[AttrChange], list[str]]:
    b, a = flatten_sets(before or {}), flatten_sets(after or {})
    changes, noise = [], []
    for path in sorted(set(b) | set(a)):
        vb, va = b.get(path), a.get(path)
        if vb == va:
            continue
        if vb in ([], None) and va in ([], None):
            continue
        if NOISE.search(path):
            noise.append(path)
        elif ".=" in path:  # set element: added or removed
            base, _, val = path.partition(".=")
            changes.append(
                AttrChange(path=f"{base}.+" if vb is None else f"{base}.-", before=vb, after=va)
            )
        else:
            changes.append(AttrChange(path=path, before=vb, after=va))
    # `labels` in state holds only configured labels; the provider reports real drift in effective_labels.
    configured = {
        c.path.removeprefix("labels.")
        for c in changes
        if isinstance(c, AttrChange) and c.path.startswith("labels.")
    }
    changes = [
        c
        for c in changes
        if not (
            c.path.startswith("effective_labels.")
            and c.path.removeprefix("effective_labels.") in configured
        )
    ]
    return changes, noise  # type: ignore[return-value]


HINT_KEYS = ("name", "bucket", "instance", "topic", "dataset_id", "table_id", "service", "id")


def hints(before: Any, after: Any) -> list[str]:
    """Real GCP resource names, for audit-log search (the Terraform name is often different)."""
    out: list[str] = []
    for doc in (before, after):
        for k in HINT_KEYS:
            v = (doc or {}).get(k) if isinstance(doc, dict) else None
            if isinstance(v, str) and v:
                seg = v.rstrip("/").split("/")[-1].replace('"', "")
                if seg and seg not in out:
                    out.append(seg)
    return out[:4]


def parse(doc: Any) -> list[Drift]:
    if not isinstance(doc, dict) or not isinstance(doc.get("resource_drift"), list):
        raise DriftParseError(
            "not a refresh-only plan: missing 'resource_drift' "
            "(run `terraform plan -refresh-only -out=p && terraform show -json p`)"
        )
    out: list[Drift] = []
    for i, rd in enumerate(doc["resource_drift"]):
        try:
            ch = rd["change"]
            actions = list(ch["actions"])
            drift = Drift(
                address=rd["address"],
                type=rd["type"],
                name=rd.get("name", rd["address"]),
                kind="deleted" if "delete" in actions else "changed",
                hints=hints(ch.get("before"), ch.get("after")),
            )
        except (KeyError, TypeError) as e:
            raise DriftParseError(f"resource_drift[{i}] is malformed: missing {e}") from e
        if drift.kind == "changed":
            drift.changes, drift.noise = diff(ch.get("before"), ch.get("after"))
        else:
            drift.changes = [
                AttrChange(path="(resource)", before="exists in state", after="missing in GCP")
            ]
        out.append(drift)
        if len(out) > MAX_DRIFTS:
            raise DriftParseError(f"more than {MAX_DRIFTS} drifted resources")
    return out
