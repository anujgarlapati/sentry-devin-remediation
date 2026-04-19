"""
The orchestrator — the main business logic.

Given a Vulnerability row, decide what to do and make it happen. This module
is the one an interviewer is most likely to ask questions about, so it's
written to read linearly.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlmodel import Session

from app.core.prompts import (
    PromptContext,
    REMEDIATION_OUTPUT_SCHEMA,
    build_remediation_prompt,
    idempotency_key_for,
)
from app.core.triage import triage
from app.integrations.devin import DevinClient, DevinSession, SessionStatus
from app.integrations.github import GitHubClient
from app.models.schema import (
    EventLog,
    RemediationStatus,
    TriageDecision,
    Vulnerability,
)

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        db: Session,
        devin: DevinClient,
        github: GitHubClient,
        target_repo: str,
        target_branch: str = "main",
    ):
        self.db = db
        self.devin = devin
        self.github = github
        self.target_repo = target_repo
        self.target_branch = target_branch

    # ------------------------------------------------------- entry points

    async def handle_new_vulnerability(self, vuln: Vulnerability) -> None:
        """
        Full lifecycle for a newly-detected vulnerability:
        triage → create tracking issue → dispatch (if Devin) → return.

        Polling happens in a separate worker (see app.workers.poller).
        """
        # 1. Triage
        result = triage(vuln)
        vuln.triage_decision = result.decision
        vuln.triage_reason = result.reason
        vuln.triaged_at = datetime.utcnow()
        vuln.status = RemediationStatus.TRIAGED
        self._log_event(vuln, "triaged", {
            "decision": result.decision.value,
            "reason": result.reason,
            "priority": result.priority,
        })

        if result.decision == TriageDecision.SKIP:
            vuln.status = RemediationStatus.SKIPPED
            self._persist(vuln)
            log.info("skip %s: %s", vuln.dedupe_key, result.reason)
            return

        # 2. Create a GitHub issue on the fork so there's a human-readable
        #    record, regardless of which path handles the remediation.
        issue = await self.github.create_vulnerability_issue(
            repo=self.target_repo,
            vulnerability=vuln,
            triage_result=result,
        )
        vuln.github_issue_number = issue.number
        vuln.github_issue_url = issue.url
        self._log_event(vuln, "issue_created", {"url": issue.url})

        # 3. If triage routed to Dependabot, we're done — GitHub's native
        #    flow takes over. We just track status.
        if result.decision == TriageDecision.DEPENDABOT:
            self._persist(vuln)
            log.info("dependabot handles %s", vuln.dedupe_key)
            return

        # 4. Route to Devin
        await self._dispatch_to_devin(vuln)
        self._persist(vuln)

    async def poll_session(self, vuln: Vulnerability) -> None:
        """
        Refresh a single in-flight Devin session and update our state.
        Called by the background poller on a tight loop for running sessions.
        """
        if not vuln.devin_session_id:
            return

        session = await self.devin.get_session(vuln.devin_session_id)
        self._reconcile(vuln, session)
        self._persist(vuln)

    # ----------------------------------------------------------- helpers

    async def _dispatch_to_devin(self, vuln: Vulnerability) -> None:
        ctx = PromptContext(
            vulnerability=vuln,
            target_repo=self.target_repo,
            target_branch=self.target_branch,
            issue_url=vuln.github_issue_url,
        )
        prompt = build_remediation_prompt(ctx)

        session = await self.devin.create_session(
            prompt=prompt,
            title=f"Remediate {vuln.cve_id} in {vuln.package}",
            tags=[
                "sentry",
                f"cve:{vuln.cve_id}",
                f"pkg:{vuln.package}",
                f"severity:{vuln.severity.value}",
            ],
            structured_output_schema=REMEDIATION_OUTPUT_SCHEMA,
            idempotency_key=idempotency_key_for(vuln),
        )

        vuln.devin_session_id = session.session_id
        vuln.devin_session_url = session.url
        vuln.dispatched_at = datetime.utcnow()
        vuln.status = RemediationStatus.RUNNING
        self._log_event(vuln, "devin_session_created", {
            "session_id": session.session_id,
            "url": session.url,
        })
        log.info("dispatched %s → %s", vuln.dedupe_key, session.session_id)

    def _reconcile(self, vuln: Vulnerability, session: DevinSession) -> None:
        """
        Update the vulnerability record from the latest session snapshot.
        Writes an event log row on every status change.
        """
        old_status = vuln.status

        # Absorb updated Devin-side metadata regardless of status
        if session.pr_url and session.pr_url != vuln.devin_pr_url:
            vuln.devin_pr_url = session.pr_url
            if vuln.pr_opened_at is None:
                vuln.pr_opened_at = datetime.utcnow()
        if session.structured_output:
            vuln.devin_structured_output = session.structured_output
        if session.acus_consumed is not None:
            vuln.devin_acus_consumed = session.acus_consumed

        # Map Devin status → our status
        new_status = _map_status(session, vuln)
        if new_status != old_status:
            vuln.status = new_status
            self._log_event(vuln, "status_change", {
                "from": old_status.value,
                "to": new_status.value,
                "devin_status": session.status.value,
                "pr_url": session.pr_url,
            })

    def _log_event(self, vuln: Vulnerability, event: str, details: dict) -> None:
        # Must persist the vuln first if it has no id yet (new row)
        if vuln.id is None:
            self.db.add(vuln)
            self.db.flush()
        self.db.add(EventLog(
            vulnerability_id=vuln.id,
            event=event,
            details=details,
        ))

    def _persist(self, vuln: Vulnerability) -> None:
        self.db.add(vuln)
        self.db.commit()


def _map_status(session: DevinSession, vuln: Vulnerability) -> RemediationStatus:
    """
    Translate Devin's view of the world into ours. Kept as a free function
    so it's testable without a DB.
    """
    # PR merged wins over everything — we only learn this from GitHub polling,
    # not from Devin, but the reconciler calls this with current `vuln` state.
    if vuln.status == RemediationStatus.MERGED:
        return RemediationStatus.MERGED

    if session.status == SessionStatus.WORKING:
        # Promote to PR_OPENED as soon as we see a PR URL
        return (
            RemediationStatus.PR_OPENED
            if session.pr_url
            else RemediationStatus.RUNNING
        )

    if session.is_terminal:
        if session.pr_url:
            return RemediationStatus.PR_OPENED
        # Terminal with no PR — look at structured output for nuance
        so = session.structured_output or {}
        if so.get("remediation_status") == "blocked":
            return RemediationStatus.FAILED   # failed in the sense that *we* failed to remediate
        return RemediationStatus.FAILED

    return RemediationStatus.RUNNING
