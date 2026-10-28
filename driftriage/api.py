"""HTTP API and viewer. Auth is Cloud Run IAM. Reports are kept in memory only."""

from __future__ import annotations

import json
import logging
import re
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import __version__
from .config import Settings
from .forensics import CloudLoggingAudit, NullAudit, audit_from_doc
from .llm import Budget, LLMError, make_llm
from .models import Report
from .orchestrator import triage
from .parse import DriftParseError

SAMPLES = resources.files("driftriage") / "samples"


class TriageRequest(BaseModel):
    plan: dict
    llm: str | None = None
    audit: str = "fixture"  # fixture (x_audit in the file) | cloud | none


class _Memory:
    def __init__(self, cap: int = 50):
        self._d: OrderedDict[str, Report] = OrderedDict()
        self._cap, self._lock, self._spend = cap, threading.Lock(), {}

    def save(self, r: Report) -> None:
        with self._lock:
            self._d[r.id] = r
            while len(self._d) > self._cap:
                self._d.popitem(last=False)

    def get(self, i):
        return self._d.get(i)

    def recent(self, n):
        return list(reversed(self._d.values()))[:n]

    def spend(self) -> float:
        return self._spend.get(datetime.now(UTC).strftime("%Y%m%d"), 0.0)

    def add_spend(self, usd: float) -> None:
        k = datetime.now(UTC).strftime("%Y%m%d")
        with self._lock:
            self._spend[k] = self._spend.get(k, 0.0) + usd


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg, mem = settings or Settings(), _Memory()
    app = FastAPI(title="driftriage", version=__version__)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (resources.files("driftriage") / "ui.html").read_text()

    @app.get("/api/config")
    def config():
        return {
            "version": __version__,
            "provider": cfg.provider,
            "model": cfg.model,
            "allowed_providers": cfg.allowed_providers,
            "audit_project": cfg.audit_project,
            "daily_budget_usd": cfg.daily_budget_usd,
            "spend_today_usd": round(mem.spend(), 6),
        }

    @app.get("/api/samples")
    def samples():
        return sorted(p.name.removesuffix(".json") for p in Path(str(SAMPLES)).glob("*.json"))

    @app.get("/api/samples/{name}")
    def sample(name: str):
        f = SAMPLES / f"{name}.json"
        if not re.fullmatch(r"[a-z0-9_]+", name) or not f.is_file():
            raise HTTPException(404, "no such sample")
        return json.loads(f.read_text())

    @app.post("/api/reports", response_model=Report)
    async def create(req: Request):
        raw = await req.body()
        if len(raw) > cfg.max_body_bytes:
            raise HTTPException(413, "plan too large")
        try:
            body = TriageRequest.model_validate_json(raw)
        except ValueError as e:
            raise HTTPException(422, f"invalid request: {str(e)[:300]}") from e
        provider = body.llm or cfg.provider
        if provider not in cfg.allowed_providers:
            raise HTTPException(
                403, f"provider '{provider}' not allowed here ({', '.join(cfg.allowed_providers)})"
            )
        notes: list[str] = []
        if provider not in ("none", "mock") and mem.spend() >= cfg.daily_budget_usd:
            provider = "none"
            notes.append(f"daily model budget ${cfg.daily_budget_usd:.2f} reached; rules only")
        if body.audit == "cloud":
            if not cfg.audit_project:
                raise HTTPException(403, "cloud audit lookup is not enabled here")
            audit = CloudLoggingAudit(cfg.audit_project)
        elif body.audit == "fixture":
            audit = audit_from_doc(body.plan)
        else:
            audit = NullAudit()
        try:
            llm = make_llm(provider, cfg.model if provider == cfg.provider else None)
        except LLMError as e:
            raise HTTPException(503, str(e)) from e
        try:
            r = await triage(
                body.plan, llm, audit, budget=Budget(cfg.max_llm_calls, cfg.review_budget_usd)
            )
        except DriftParseError as e:
            raise HTTPException(422, str(e)) from e
        r.degraded = notes + r.degraded
        mem.add_spend(r.cost_usd)
        mem.save(r)
        return r

    @app.get("/api/reports", response_model=list[Report])
    def list_reports(limit: int = 20):
        return mem.recent(max(1, min(limit, 50)))

    @app.get("/api/reports/{rid}", response_model=Report)
    def get(rid: str):
        r = mem.get(rid)
        if r is None:
            raise HTTPException(404, "no such report")
        return r

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        logging.getLogger("driftriage").exception("unhandled error", exc_info=exc)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app


def app_factory() -> FastAPI:
    return create_app()
