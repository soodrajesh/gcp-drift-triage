"""Pipeline:

refresh-only plan -> [parse]      diff state vs live, strip computed noise
                  -> [classify]   category / severity / decision (rules)
                  -> [forensics]  audit-log lookup per non-ignored drift, in parallel
                  -> [attribute]  human-made loosening is escalated (rules)
                  -> [commands]   revert / adopt commands and code edits
                  -> parallel:    [analyst x N] explain risky drifts, [drafter] PR text for adopt set
                  -> [judge]      posture from rules, summary guarded"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

from . import classify as cl
from . import judge, parse
from .agents import check_text, draft_pr, explain
from .forensics import AuditProvider, NullAudit, classify_events
from .llm import LLM, Budget
from .models import SEV_RANK, Report, TraceStep
from .remediate import attach

TOP_ANALYSTS = 5


async def triage(
    doc,
    llm: LLM,
    audit: AuditProvider | None = None,
    *,
    budget: Budget | None = None,
    timeout: float = 45.0,
) -> Report:
    t0 = time.perf_counter()
    budget, audit = budget or Budget(), audit or NullAudit()
    ms = lambda: int((time.perf_counter() - t0) * 1000)  # noqa: E731
    drifts = parse.parse(doc)
    trace = [
        TraceStep(
            agent="parse",
            action="diff",
            duration_ms=ms(),
            note=f"{len(drifts)} drifted resource(s), {sum(len(d.noise) for d in drifts)} noise attribute(s) filtered",
        )
    ]
    for d in drifts:
        cl.classify(d)
    degraded: list[str] = []
    dropped: list[dict[str, str]] = []

    live = [d for d in drifts if d.decision != "ignore"]
    f0 = time.perf_counter()

    async def look(d):
        try:
            return d, await asyncio.wait_for(asyncio.to_thread(audit.lookup, d), timeout), None
        except Exception as e:  # audit lookup is best effort; its failure must not hide the drift
            return d, [], f"{type(e).__name__}: {str(e)[:100]}"

    if audit.__class__ is NullAudit:
        trace.append(
            TraceStep(
                agent="forensics",
                action="audit lookup",
                status="skipped",
                start_ms=ms(),
                note="no audit source configured",
            )
        )
    else:
        for d, events, err in await asyncio.gather(*(look(d) for d in live)):
            d.evidence = classify_events(events)
            if err:
                degraded.append(f"forensics {d.address}: {err}")
        trace.append(
            TraceStep(
                agent="forensics",
                action="audit lookup",
                start_ms=int((f0 - t0) * 1000),
                duration_ms=int((time.perf_counter() - f0) * 1000),
                note=f"{sum(bool(d.evidence.events) for d in live)} of {len(live)} attributed",
            )
        )
    for d in live:
        cl.apply_actor(d, d.evidence.actor)
        attach(d)

    use_llm = llm.name != "none"
    risky = sorted(
        (d for d in live if d.decision == "investigate"), key=lambda d: -SEV_RANK[d.severity]
    )[:TOP_ANALYSTS]
    adopt = [d for d in live if d.decision == "adopt"]
    pr_text = ""
    if use_llm:
        notes, pr = await asyncio.gather(
            asyncio.gather(*(explain(d, drifts, llm, budget, t0, timeout) for d in risky)),
            draft_pr(adopt, drifts, llm, budget, t0, timeout)
            if adopt
            else asyncio.sleep(0, ("", None, None)),
        )
        for d, (note, step, why) in zip(risky, notes, strict=True):
            trace.append(step)
            if note:
                d.note = note
            elif why:
                dropped.append({"agent": "analyst", "item": f"note for {d.address}", "reason": why})
            elif step.status == "error":
                degraded.append(f"analyst {d.address}: {step.note}")
        text, pstep, pwhy = pr
        if pstep:
            trace.append(pstep)
            pr_text = text
            if pwhy:
                dropped.append({"agent": "drafter", "item": "PR text", "reason": pwhy})
            elif pstep.status == "error":
                degraded.append(f"drafter: {pstep.note}")
    else:
        trace.append(
            TraceStep(
                agent="analyst",
                action="explain",
                status="skipped",
                start_ms=ms(),
                note="no model configured",
            )
        )

    post = judge.posture(drifts)
    j0 = time.perf_counter()
    step = TraceStep(agent="judge", action="summarize", start_ms=int((j0 - t0) * 1000))
    summary = await judge.summarize(post, drifts, llm, budget, step)
    step.duration_ms = int((time.perf_counter() - j0) * 1000)
    trace.append(step)

    drifts.sort(key=lambda d: (-SEV_RANK[d.severity], d.decision == "ignore", d.address))
    return Report(
        id=uuid.uuid4().hex[:12],
        created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        provider=llm.name,
        model=llm.model,
        posture=post,
        summary=summary,
        pr_text=pr_text,
        drifts=drifts,  # type: ignore[arg-type]
        counts=judge.counts(drifts),
        dropped=dropped,
        degraded=degraded,
        trace=trace,
        plan_sha256=parse.plan_sha256(doc),
        cost_usd=round(sum(s.cost_usd for s in trace), 6),
        duration_ms=ms(),
    )


__all__ = ["triage", "check_text"]
