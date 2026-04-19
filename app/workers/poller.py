"""
Background worker that polls Devin for in-flight sessions and GitHub for
PR merge status. Runs inside the API process for simplicity; in production
this would be a separate container scaled independently.
"""
from __future__ import annotations

import logging
from datetime import datetime

from sqlmodel import Session, select

from app.core.orchestrator import Orchestrator
from app.models.schema import EventLog, RemediationStatus, Vulnerability

log = logging.getLogger(__name__)


async def poll_once(db: Session, orch: Orchestrator) -> dict:
    """
    One pass: refresh all non-terminal Devin sessions, check all PR_OPENED
    vulns for merge, return a summary. Safe to call concurrently because
    each vuln is updated in its own commit scope.
    """
    summary = {"polled": 0, "merged": 0, "failed": 0}

    # 1. Running sessions → ask Devin for status
    running = db.exec(
        select(Vulnerability).where(
            Vulnerability.status.in_([
                RemediationStatus.QUEUED,
                RemediationStatus.RUNNING,
            ]),
            Vulnerability.devin_session_id.is_not(None),
        )
    ).all()

    for v in running:
        try:
            await orch.poll_session(v)
            summary["polled"] += 1
        except Exception:
            log.exception("poll failed for vuln %s", v.id)

    # 2. PR_OPENED → check GitHub for merge
    pr_open = db.exec(
        select(Vulnerability).where(
            Vulnerability.status == RemediationStatus.PR_OPENED,
            Vulnerability.devin_pr_url.is_not(None),
        )
    ).all()

    for v in pr_open:
        try:
            pr = await orch.github.get_pr_by_url(v.devin_pr_url)
            if pr and pr.merged and v.status != RemediationStatus.MERGED:
                v.status = RemediationStatus.MERGED
                v.merged_at = datetime.utcnow()
                db.add(EventLog(
                    vulnerability_id=v.id,
                    event="pr_merged",
                    details={"pr_url": v.devin_pr_url},
                ))
                db.add(v)
                db.commit()
                summary["merged"] += 1
        except Exception:
            log.exception("pr check failed for vuln %s", v.id)

    return summary
