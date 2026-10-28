"""Deterministic classification. Category, severity and decision come from here; models and audit
logs can add context or raise severity for human-made loosening, never lower anything."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from .models import SEV_RANK, SEVS, Actor, AttrChange, Drift

PUBLIC = {"allUsers", "allAuthenticatedUsers"}
STATEFUL = {
    "google_sql_database_instance",
    "google_storage_bucket",
    "google_spanner_instance",
    "google_spanner_database",
    "google_bigtable_instance",
    "google_firestore_database",
    "google_compute_disk",
    "google_bigquery_dataset",
    "google_bigquery_table",
    "google_kms_crypto_key",
    "google_redis_instance",
    "google_pubsub_topic",
    "google_pubsub_subscription",
}

Result = tuple[str, str, str]  # category, severity, reason
Rule = Callable[[AttrChange, Drift], Result | None]
RULES: list[tuple[str, Rule]] = []


def rule(rule_id: str):
    def deco(fn: Rule):
        RULES.append((rule_id, fn))
        return fn

    return deco


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


@rule("D001")
def public_iam(c, d):
    if "_iam_" not in d.type or not re.search(r"(^|\.)(members\.(\d+|\+|-)|member)$", c.path):
        return None
    if c.after in PUBLIC and c.before != c.after:
        return "loosening", "critical", f"{c.after} was granted access outside Terraform"
    if c.before is None and c.after:
        return "loosening", "high", f"{c.after} was granted access outside Terraform"
    if c.after is None and c.before:
        return "tightening", "low", f"{c.before} lost access outside Terraform"
    return "loosening", "medium", "IAM member changed outside Terraform"


@rule("D002")
def open_cidr(c, d):
    if (
        re.search(r"(source_ranges\.(\d+|\+)|authorized_networks\.\d+\.value)$", c.path)
        and c.after == "0.0.0.0/0"
    ):
        return "loosening", "critical", "0.0.0.0/0 was added to an ingress allow-list"
    return None


FLAGS = {  # path suffix -> (safe value, severity if it moves away from it, category)
    "deletion_protection": (True, "high", "reliability"),
    "public_access_prevention": ("enforced", "high", "loosening"),
    "uniform_bucket_level_access": (True, "medium", "loosening"),
    "ipv4_enabled": (False, "high", "loosening"),
    "versioning.0.enabled": (True, "medium", "reliability"),
    "enabled": (True, "medium", "reliability"),
}


@rule("D003")
def safety_flags(c, d):
    for suffix, (safe, sev, cat) in FLAGS.items():
        if suffix == "enabled" and "backup_configuration" not in c.path:
            continue
        if c.path.endswith(suffix):
            if c.before == safe and c.after != safe:
                return cat, sev, f"{suffix.split('.')[-1]} moved from {c.before!r} to {c.after!r}"
            if c.after == safe and c.before != safe:
                return (
                    "tightening",
                    "low",
                    f"{suffix.split('.')[-1]} moved to the safe value {c.after!r}",
                )
    return None


@rule("D004")
def ingress(c, d):
    if c.path.endswith("ingress") and c.after == "INGRESS_TRAFFIC_ALL" and c.before != c.after:
        return "loosening", "medium", "ingress opened to all traffic"
    return None


@rule("D005")
def autoscaled(c, d):
    if d.type == "google_container_node_pool" and c.path.endswith("node_count"):
        return "operational", "info", "node count is managed by the autoscaler"
    return None


@rule("D006")
def cost_knobs(c, d):
    last = c.path.split(".")[-1]
    if last in ("machine_type", "tier"):
        return "cost", "medium", f"{last} changed from {c.before} to {c.after}"
    if last in ("max_instance_count", "min_instance_count", "size", "node_count", "max_node_count"):
        b, a = _num(c.before), _num(c.after)
        if b is not None and a is not None:
            return (
                ("cost", "medium", f"{last} rose from {b:g} to {a:g}")
                if a > b
                else ("cost", "low", f"{last} fell from {b:g} to {a:g}")
            )
    return None


@rule("D007")
def image(c, d):
    if re.search(r"containers\.\d+\.image$", c.path):
        return (
            "operational",
            "low",
            "container image changed outside Terraform (out-of-band deploy)",
        )
    return None


@rule("D008")
def metadata(c, d):
    if re.match(
        r"(labels|effective_labels|annotations|user_labels|settings\.\d+\.user_labels)\.", c.path
    ) or c.path in ("description", "display_name"):
        return "benign", "info", "label/description change"
    return None


def classify_change(c: AttrChange, d: Drift) -> AttrChange:
    for _, fn in RULES:
        r = fn(c, d)
        if r:
            c.category, c.severity, c.reason = r  # type: ignore[assignment]
            return c
    c.category, c.severity, c.reason = "unknown", "low", "attribute not covered by a rule"  # type: ignore[assignment]
    return c


def bump(sev: str) -> str:
    return SEVS[min(SEV_RANK[sev] + 1, 4)]


def classify(d: Drift) -> Drift:
    if d.kind == "deleted":
        stateful = d.type in STATEFUL
        d.category, d.severity = "deleted", "critical" if stateful else "high"
        d.decision = "investigate" if stateful else "revert"
        d.why = (
            "stateful resource is gone from GCP; data may be lost"
            if stateful
            else "resource was deleted outside Terraform; recreate it or remove it from state"
        )
        return d
    d.changes = [classify_change(c, d) for c in d.changes]
    if not d.changes:
        d.category, d.severity, d.decision, d.why = (
            "noise",
            "info",
            "ignore",
            "only provider-computed attributes changed",
        )
        return d
    worst = max(
        d.changes, key=lambda c: (SEV_RANK[c.severity], c.category in ("loosening", "reliability"))
    )
    d.category, d.severity = worst.category, worst.severity
    if any(c.category == "loosening" and SEV_RANK[c.severity] >= 2 for c in d.changes):
        d.decision, d.why = "investigate", worst.reason
        d.category = "loosening"
    elif any(
        c.category in ("reliability", "cost") and SEV_RANK[c.severity] >= 2 for c in d.changes
    ):
        d.decision, d.why = "investigate", worst.reason
    elif all(c.category == "operational" and c.severity == "info" for c in d.changes):
        d.decision, d.why = (
            "ignore",
            "managed by a controller (e.g. autoscaler); consider lifecycle.ignore_changes",
        )
    elif all(c.severity in ("info", "low") for c in d.changes) and all(
        c.category != "unknown" for c in d.changes
    ):
        d.decision, d.why = "adopt", "low-risk change; update code to match GCP"
    else:
        d.decision, d.why = "investigate", worst.reason
    return d


def apply_actor(d: Drift, actor: Actor) -> None:
    """Attribution can only make a finding more serious: a human loosening access by hand is worse
    than the same change made by a pipeline."""
    if (
        d.decision == "investigate"
        and d.category in ("loosening", "reliability")
        and actor == "human"
    ):
        d.severity = bump(d.severity)  # type: ignore[assignment]
        d.why += "; made by a human principal, outside the pipeline"
    elif actor == "unknown" and d.decision == "investigate":
        d.why += "; no audit trail found for the change"
