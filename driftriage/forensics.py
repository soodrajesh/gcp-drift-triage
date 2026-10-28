"""Who made the change? Looks up Cloud Audit Logs (Admin Activity: writes only, on by default)
for the drifted resource. Read-only; needs roles/logging.viewer. Fixture and null providers keep
tests and demos offline."""

from __future__ import annotations

import re
from datetime import UTC
from typing import Any, Protocol

from .models import Actor, AuditEvent, Drift, Evidence

LOGGING = "https://logging.googleapis.com/v2/entries:list"
AUTOMATION = re.compile(r"(terraform|tf-|ci-|cicd|deploy|build|pipeline|github|automation)", re.I)


class AuditProvider(Protocol):
    def lookup(self, drift: Drift) -> list[AuditEvent]: ...


class NullAudit:
    def lookup(self, drift: Drift) -> list[AuditEvent]:
        return []


class FixtureAudit:
    """events keyed by resource address, from the sample file or a test."""

    def __init__(self, events: dict[str, list[dict[str, Any]]]):
        self._e = events

    def lookup(self, drift: Drift) -> list[AuditEvent]:
        return [AuditEvent(**e) for e in self._e.get(drift.address, [])]


def actor_of(principal: str) -> Actor:
    if principal.endswith(".gserviceaccount.com"):
        if (
            "@gcp-sa-" in principal
            or principal.startswith("service-")
            or "cloudservices" in principal
        ):
            return "google"
        return "automation"
    if "@" in principal:
        return "human"
    return "unknown"


def classify_events(events: list[AuditEvent]) -> Evidence:
    if not events:
        return Evidence(
            actor="unknown", note="no Admin Activity audit events found for this resource"
        )
    newest = events[0]
    a = actor_of(newest.principal)
    if a == "automation" and not AUTOMATION.search(newest.principal):
        a = "automation"  # a service account is still not a person, even with an opaque name
    return Evidence(events=events[:5], actor=a)


class CloudLoggingAudit:
    def __init__(self, project: str, since_days: int = 7, session=None):
        self.project, self.since_days, self._s = project, since_days, session

    def _session(self):
        if self._s is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession

            creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
            )
            self._s = AuthorizedSession(creds)
        return self._s

    @staticmethod
    def tokens(d: Drift) -> list[str]:
        found = [h.replace('"', "") for h in d.hints] or [d.name.replace("_", "-")]
        return list(dict.fromkeys(found))

    def lookup(self, drift: Drift) -> list[AuditEvent]:
        names = " OR ".join(f'protoPayload.resourceName:"{t}"' for t in self.tokens(drift))
        flt = (
            f'logName:"cloudaudit.googleapis.com%2Factivity" AND ({names}) '
            f'AND timestamp>="{_since(self.since_days)}"'
        )
        r = self._session().post(
            LOGGING,
            timeout=30,
            json={
                "resourceNames": [f"projects/{self.project}"],
                "filter": flt,
                "orderBy": "timestamp desc",
                "pageSize": 20,
            },
        )
        if r.status_code != 200:
            raise RuntimeError(f"logging {r.status_code}: {r.text[:160]}")
        out = []
        for e in r.json().get("entries", []):
            p = e.get("protoPayload", {})
            out.append(
                AuditEvent(
                    time=e.get("timestamp", ""),
                    principal=p.get("authenticationInfo", {}).get("principalEmail", ""),
                    method=p.get("methodName", ""),
                    caller_ip=p.get("requestMetadata", {}).get("callerIp", ""),
                    resource=p.get("resourceName", "")[:200],
                )
            )
        return out


def _since(days: int) -> str:
    from datetime import datetime, timedelta

    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_from_doc(doc) -> AuditProvider:
    """Offline demo files may carry audit events under `x_audit`."""
    x = doc.get("x_audit") if isinstance(doc, dict) else None
    return FixtureAudit(x) if isinstance(x, dict) else NullAudit()
