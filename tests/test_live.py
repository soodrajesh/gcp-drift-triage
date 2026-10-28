"""Opt-in tests against real services (read-only)."""

import os

import pytest

from driftriage.forensics import CloudLoggingAudit, audit_from_doc
from driftriage.llm import Budget, make_llm
from driftriage.models import Drift
from driftriage.orchestrator import triage

from .helpers import sample


async def _check(provider):
    doc = sample("incident_weekend")
    r = await triage(doc, make_llm(provider), audit_from_doc(doc), budget=Budget())
    assert r.posture == "alert" and r.counts["investigate"] == 4 and r.cost_usd < 0.05


@pytest.mark.live_vertex
@pytest.mark.skipif(
    not os.environ.get("DRIFTRIAGE_LIVE_VERTEX"), reason="set DRIFTRIAGE_LIVE_VERTEX=1"
)
async def test_vertex():
    await _check("vertex")


@pytest.mark.live_openai
@pytest.mark.skipif(
    not os.environ.get("DRIFTRIAGE_LIVE_OPENAI"), reason="set DRIFTRIAGE_LIVE_OPENAI=1"
)
async def test_openai():
    await _check("openai")


@pytest.mark.live_gcp
@pytest.mark.skipif(
    not os.environ.get("DRIFTRIAGE_LIVE_PROJECT"), reason="set DRIFTRIAGE_LIVE_PROJECT=<project>"
)
def test_cloud_audit_lookup_returns_events_shape():
    ev = CloudLoggingAudit(os.environ["DRIFTRIAGE_LIVE_PROJECT"], since_days=30).lookup(
        Drift(
            address="google_storage_bucket.x",
            type="google_storage_bucket",
            name="x",
            kind="changed",
            hints=["cloudbuild"],
        )
    )
    assert isinstance(ev, list)
