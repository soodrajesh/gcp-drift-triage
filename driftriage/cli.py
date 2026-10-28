"""CLI.  Exit codes: 0 clean, 1 attention, 2 alert, 3 error.

terraform plan -refresh-only -out=drift.plan && terraform show -json drift.plan > drift.json
driftriage triage drift.json --audit-project my-project --llm vertex
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .forensics import CloudLoggingAudit, audit_from_doc
from .llm import Budget, LLMError, make_llm
from .models import Report
from .orchestrator import triage
from .parse import DriftParseError

EXIT = {"clean": 0, "attention": 1, "alert": 2}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}


def render(r: Report, color: bool) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    out = [
        c(
            {"clean": "32", "attention": "33", "alert": "1;31"}[r.posture],
            f"POSTURE: {r.posture.upper()}",
        ),
        r.summary,
        "",
    ]
    for d in r.drifts:
        who = f" by {d.evidence.events[0].principal}" if d.evidence.events else ""
        out.append(
            f"{c(COLOR[d.severity], d.severity.upper().ljust(8))} {d.decision.upper().ljust(11)} {d.address}{who}"
        )
        out.append(f"           {d.why}")
        for ch in d.changes[:3]:
            out.append(f"           {ch.path}: {ch.before!r} -> {ch.after!r}")
        if d.note:
            out.append(f"           note: {d.note}")
        out += [f"           $ {cmd}" for cmd in d.commands[:2]]
    if r.pr_text:
        out += ["", "Suggested PR description:", r.pr_text]
    for x in r.degraded:
        out.append(c("33", f"! {x}"))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="driftriage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage", help="triage a refresh-only plan JSON (or - for stdin)")
    t.add_argument("plan")
    t.add_argument("--llm", default="none", choices=["none", "mock", "vertex", "openai"])
    t.add_argument("--model")
    t.add_argument(
        "--audit-project", help="look up who made each change in this project's Cloud Audit Logs"
    )
    t.add_argument("--format", default="text", choices=["text", "json"])
    a = ap.parse_args(argv)
    try:
        doc = json.load(sys.stdin) if a.plan == "-" else json.loads(Path(a.plan).read_text())
        audit = CloudLoggingAudit(a.audit_project) if a.audit_project else audit_from_doc(doc)
        rep = asyncio.run(triage(doc, make_llm(a.llm, a.model), audit, budget=Budget()))
    except (OSError, ValueError, DriftParseError, LLMError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    print(rep.model_dump_json(indent=1) if a.format == "json" else render(rep, sys.stdout.isatty()))
    return EXIT[rep.posture]


if __name__ == "__main__":
    sys.exit(main())
