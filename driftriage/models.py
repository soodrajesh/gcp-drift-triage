from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVS = ["info", "low", "medium", "high", "critical"]
Category = Literal[
    "noise",
    "benign",
    "operational",
    "loosening",
    "tightening",
    "cost",
    "reliability",
    "deleted",
    "unknown",
]
Decision = Literal["ignore", "adopt", "revert", "investigate"]
Actor = Literal["human", "automation", "google", "unknown"]


class AttrChange(BaseModel):
    path: str
    before: Any = None
    after: Any = None
    category: Category = "unknown"
    severity: Severity = "info"
    reason: str = ""


class AuditEvent(BaseModel):
    time: str
    principal: str
    method: str
    caller_ip: str = ""
    resource: str = ""


class Evidence(BaseModel):
    events: list[AuditEvent] = Field(default_factory=list)
    actor: Actor = "unknown"
    note: str = ""  # e.g. "no audit events found"


class Drift(BaseModel):
    address: str
    type: str
    name: str
    kind: Literal["changed", "deleted"]
    changes: list[AttrChange] = Field(default_factory=list)
    hints: list[str] = Field(default_factory=list)  # real resource names for audit-log search
    noise: list[str] = Field(default_factory=list)  # paths filtered as provider/computed noise
    category: Category = "noise"
    severity: Severity = "info"
    decision: Decision = "ignore"
    why: str = ""
    evidence: Evidence = Field(default_factory=Evidence)
    commands: list[str] = Field(default_factory=list)
    hcl: list[str] = Field(default_factory=list)  # suggested code edits when adopting
    note: str = ""  # validated model explanation; never affects decision


class TraceStep(BaseModel):
    agent: str
    action: str
    status: Literal["ok", "skipped", "error"] = "ok"
    start_ms: int = 0
    duration_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    note: str = ""


class Report(BaseModel):
    id: str
    created_at: str
    provider: str
    model: str
    posture: Literal["clean", "attention", "alert"]
    summary: str
    pr_text: str = ""
    drifts: list[Drift] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    dropped: list[dict[str, str]] = Field(default_factory=list)
    degraded: list[str] = Field(default_factory=list)
    trace: list[TraceStep] = Field(default_factory=list)
    plan_sha256: str = ""
    cost_usd: float = 0.0
    duration_ms: int = 0
