"""
Devin API client — the core primitive.

Two modes:
  - live: hits https://api.devin.ai/v1/* with a real API key
  - mock: simulates session lifecycle with realistic timing, for demos

The mock is deliberately honest — it doesn't pretend sessions succeed instantly,
and it occasionally fails to exercise the retry/reporting paths.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)


class SessionStatus(str, Enum):
    """Mirrors Devin's status_enum but with our own terminal states layered on."""
    QUEUED = "queued"
    WORKING = "working"
    BLOCKED = "blocked"           # Devin needs input
    STOPPED = "stopped"           # user-terminated
    FINISHED = "finished"         # Devin completed
    EXPIRED = "expired"           # session timed out


@dataclass
class DevinSession:
    """Thin wrapper around the subset of Devin's response we care about."""
    session_id: str
    status: SessionStatus
    url: Optional[str] = None           # deep link to Devin UI
    pr_url: Optional[str] = None         # populated when Devin opens the PR
    structured_output: Optional[dict] = None
    acus_consumed: float = 0.0
    title: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    raw: dict = field(default_factory=dict)   # full API response for debugging

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            SessionStatus.FINISHED,
            SessionStatus.STOPPED,
            SessionStatus.EXPIRED,
        }

    @property
    def succeeded(self) -> bool:
        return self.status == SessionStatus.FINISHED and self.pr_url is not None


class DevinClient:
    """
    Wraps Devin's v1 session API. Async so we can orchestrate a fleet.

    Usage:
        client = DevinClient(api_key=..., mode="live")
        session = await client.create_session(prompt="...", tags=["cve-2024-...."])
        while not session.is_terminal:
            await asyncio.sleep(30)
            session = await client.get_session(session.session_id)
    """

    BASE_URL = "https://api.devin.ai/v1"

    def __init__(
        self,
        api_key: Optional[str] = None,
        mode: str = "mock",
        timeout: float = 30.0,
    ):
        self.mode = mode
        self.api_key = api_key
        self.timeout = timeout
        if mode == "live" and not api_key:
            raise ValueError("DEVIN_API_KEY required in live mode")
        self._mock_sessions: dict[str, _MockSession] = {}

    # ------------------------------------------------------------------ public

    async def create_session(
        self,
        prompt: str,
        *,
        title: Optional[str] = None,
        tags: Optional[list[str]] = None,
        structured_output_schema: Optional[dict] = None,
        max_acu_limit: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> DevinSession:
        """Create a Devin session. Returns immediately; session runs async on Devin side."""
        if self.mode == "mock":
            return self._mock_create(prompt, title=title, tags=tags or [])

        body: dict[str, Any] = {"prompt": prompt}
        if title:
            body["title"] = title
        if tags:
            body["tags"] = tags
        if structured_output_schema:
            body["structured_output_schema"] = structured_output_schema
        if max_acu_limit:
            body["max_acu_limit"] = max_acu_limit
        if idempotency_key:
            body["idempotent"] = True
            body["tags"] = (tags or []) + [f"idem:{idempotency_key}"]

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            resp = await http.post(
                f"{self.BASE_URL}/sessions",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
            return self._parse(data)

    async def get_session(self, session_id: str) -> DevinSession:
        if self.mode == "mock":
            return self._mock_get(session_id)

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            resp = await http.get(
                f"{self.BASE_URL}/sessions/{session_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return self._parse(resp.json())

    async def send_message(self, session_id: str, message: str) -> None:
        """Nudge a blocked session. Devin supports mid-session messages."""
        if self.mode == "mock":
            log.info("mock: message to %s: %s", session_id, message[:80])
            return

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            resp = await http.post(
                f"{self.BASE_URL}/sessions/{session_id}/message",
                headers=self._headers(),
                json={"message": message},
            )
            resp.raise_for_status()

    # ---------------------------------------------------------------- internal

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _parse(self, data: dict) -> DevinSession:
        status_str = data.get("status_enum") or data.get("status", "working")
        try:
            status = SessionStatus(status_str)
        except ValueError:
            # Unknown status — map conservatively to WORKING rather than crash
            log.warning("unknown Devin status %r, treating as working", status_str)
            status = SessionStatus.WORKING

        return DevinSession(
            session_id=data["session_id"],
            status=status,
            url=data.get("url"),
            pr_url=(data.get("pull_request") or {}).get("url"),
            structured_output=data.get("structured_output"),
            title=data.get("title"),
            tags=data.get("tags", []),
            # v1 returns ISO strings; we keep raw for dashboard display
            raw=data,
        )

    # ------------------------------------------------------------------- mock

    def _mock_create(self, prompt: str, *, title, tags) -> DevinSession:
        sid = f"devin-mock-{uuid.uuid4().hex[:12]}"
        mock = _MockSession(
            session_id=sid,
            title=title or f"Mock: {prompt[:50]}",
            tags=list(tags),
            created_at=time.time(),
        )
        self._mock_sessions[sid] = mock
        log.info("mock: created session %s (will finish in ~%ss)", sid, int(mock.duration_s))
        return mock.snapshot()

    def _mock_get(self, session_id: str) -> DevinSession:
        mock = self._mock_sessions.get(session_id)
        if not mock:
            # Mock state is in-memory, so a server restart loses it. Rather
            # than crash the poller, return a synthetic "finished, no-PR"
            # snapshot with a flag so downstream treats it as a blocked
            # remediation. In production the live client wouldn't have this
            # issue because Devin is the source of truth.
            log.warning("mock session %s not found in memory; returning blocked snapshot", session_id)
            return DevinSession(
                session_id=session_id,
                status=SessionStatus.FINISHED,
                url=f"https://app.devin.ai/sessions/{session_id}",
                pr_url=None,
                structured_output={
                    "remediation_status": "blocked",
                    "reason": "Session state lost (server restart in mock mode).",
                },
                acus_consumed=0.0,
                raw={"mock": True, "synthetic": True},
            )
        return mock.snapshot()


@dataclass
class _MockSession:
    """Simulates a Devin session with realistic-ish timing and a 90% success rate."""
    session_id: str
    title: str
    tags: list[str]
    created_at: float
    # Sessions take 5-20 minutes in reality; we compress to 20-90s for demo
    duration_s: float = field(default_factory=lambda: random.uniform(20, 90))
    # 10% of mock sessions fail to exercise the failure-reporting path
    will_succeed: bool = field(default_factory=lambda: random.random() > 0.1)
    _pr_number: int = field(default_factory=lambda: random.randint(100, 999))

    def snapshot(self) -> DevinSession:
        elapsed = time.time() - self.created_at
        progress = min(elapsed / self.duration_s, 1.0)

        if progress < 1.0:
            status = SessionStatus.WORKING
            pr_url = None
            acus = round(progress * 3.5, 2)
            structured_output = None
        else:
            if self.will_succeed:
                status = SessionStatus.FINISHED
                pr_url = f"https://github.com/mock/superset-fork/pull/{self._pr_number}"
                acus = round(random.uniform(2.8, 4.2), 2)
                structured_output = {
                    "remediation_status": "completed",
                    "pr_url": pr_url,
                    "files_changed": random.randint(2, 8),
                    "tests_passing": True,
                    "approach": "Bumped package to patched version and updated lockfile. "
                                "No breaking changes detected in API surface.",
                }
            else:
                status = SessionStatus.FINISHED
                pr_url = None
                acus = round(random.uniform(1.5, 3.0), 2)
                structured_output = {
                    "remediation_status": "blocked",
                    "reason": "Upstream fix not yet released; workaround would require "
                              "pinning to pre-release which project policy disallows.",
                }

        return DevinSession(
            session_id=self.session_id,
            status=status,
            url=f"https://app.devin.ai/sessions/{self.session_id}",
            pr_url=pr_url,
            structured_output=structured_output,
            acus_consumed=acus,
            title=self.title,
            tags=self.tags,
            created_at=self.created_at,
            updated_at=time.time(),
            raw={"mock": True},
        )


# ----------------------------------------------------------------- convenience

async def wait_for_terminal(
    client: DevinClient,
    session_id: str,
    *,
    poll_interval: float = 30.0,
    timeout_s: float = 3600.0,
) -> DevinSession:
    """
    Poll a session until it reaches a terminal state or timeout.
    Used by the worker; the dashboard polls independently for liveness.
    """
    start = time.time()
    while time.time() - start < timeout_s:
        session = await client.get_session(session_id)
        if session.is_terminal:
            return session
        await asyncio.sleep(poll_interval)
    raise TimeoutError(f"session {session_id} did not finish within {timeout_s}s")
