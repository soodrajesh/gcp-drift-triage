from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str, default: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(name, default).split(",") if x.strip())


@dataclass
class Settings:
    provider: str = field(default_factory=lambda: os.environ.get("DRIFTRIAGE_LLM", "mock"))
    model: str | None = field(default_factory=lambda: os.environ.get("DRIFTRIAGE_MODEL") or None)
    allowed_providers: tuple[str, ...] = field(
        default_factory=lambda: _list("DRIFTRIAGE_ALLOWED_PROVIDERS", "mock,none")
    )
    audit_project: str | None = field(
        default_factory=lambda: os.environ.get("DRIFTRIAGE_AUDIT_PROJECT") or None
    )
    daily_budget_usd: float = field(
        default_factory=lambda: float(os.environ.get("DRIFTRIAGE_DAILY_BUDGET_USD", 0.5))
    )
    review_budget_usd: float = field(
        default_factory=lambda: float(os.environ.get("DRIFTRIAGE_REVIEW_BUDGET_USD", 0.05))
    )
    max_llm_calls: int = field(
        default_factory=lambda: int(os.environ.get("DRIFTRIAGE_MAX_LLM_CALLS", 12))
    )
    max_body_bytes: int = 8_000_000
