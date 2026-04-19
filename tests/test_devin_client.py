"""
Devin client tests. The mock path is tested for realistic behavior
(progresses through states, reports ACUs, generates PR URLs); the live
path is tested against a monkeypatched httpx to verify request shape.
"""
from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from app.integrations.devin import (
    DevinClient,
    SessionStatus,
)


# ───────────────────────── mock mode ─────────────────────────

@pytest.mark.asyncio
async def test_mock_session_starts_in_working_state():
    client = DevinClient(mode="mock")
    session = await client.create_session(
        prompt="fix CVE-2024-0001",
        title="test",
        tags=["test"],
    )
    assert session.status == SessionStatus.WORKING
    assert session.session_id.startswith("devin-mock-")
    assert session.is_terminal is False
    assert session.pr_url is None


@pytest.mark.asyncio
async def test_mock_session_progresses_and_terminates():
    """
    The mock compresses the session lifetime to 20-90s. We shorten it by
    reaching into the internals so the test doesn't sleep for a minute.
    """
    client = DevinClient(mode="mock")
    session = await client.create_session(prompt="x")

    # Force near-instant completion
    mock = client._mock_sessions[session.session_id]
    mock.duration_s = 0.05
    mock.will_succeed = True
    await asyncio.sleep(0.1)

    final = await client.get_session(session.session_id)
    assert final.is_terminal
    assert final.status == SessionStatus.FINISHED
    assert final.pr_url is not None
    assert final.succeeded is True
    assert final.acus_consumed > 0
    assert final.structured_output is not None
    assert final.structured_output["remediation_status"] == "completed"


@pytest.mark.asyncio
async def test_mock_session_can_fail():
    client = DevinClient(mode="mock")
    session = await client.create_session(prompt="x")

    mock = client._mock_sessions[session.session_id]
    mock.duration_s = 0.05
    mock.will_succeed = False
    await asyncio.sleep(0.1)

    final = await client.get_session(session.session_id)
    assert final.is_terminal
    assert final.succeeded is False
    assert final.pr_url is None
    assert final.structured_output["remediation_status"] == "blocked"


@pytest.mark.asyncio
async def test_unknown_session_raises():
    client = DevinClient(mode="mock")
    with pytest.raises(KeyError):
        await client.get_session("devin-mock-nonexistent")


@pytest.mark.asyncio
async def test_acus_accumulate_over_time():
    client = DevinClient(mode="mock")
    session = await client.create_session(prompt="x")
    mock = client._mock_sessions[session.session_id]
    mock.duration_s = 2.0

    s1 = await client.get_session(session.session_id)
    await asyncio.sleep(0.3)
    s2 = await client.get_session(session.session_id)
    # ACUs should only go up while running
    assert s2.acus_consumed >= s1.acus_consumed


# ───────────────────────── live mode ─────────────────────────

@pytest.mark.asyncio
async def test_live_mode_requires_api_key():
    with pytest.raises(ValueError, match="DEVIN_API_KEY"):
        DevinClient(mode="live", api_key=None)


@pytest.mark.asyncio
async def test_live_create_session_posts_correct_body(monkeypatch):
    """Snapshot the body we send so it doesn't drift from the v1 spec."""
    captured: dict = {}

    class FakeResponse:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {
                "session_id": "devin-abc123",
                "status_enum": "working",
                "url": "https://app.devin.ai/sessions/devin-abc123",
                "title": "test",
                "tags": ["sentry"],
            }

    class FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, url, headers=None, json=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeResponse()

    monkeypatch.setattr("app.integrations.devin.httpx.AsyncClient", FakeClient)

    client = DevinClient(mode="live", api_key="cog_test_key")
    result = await client.create_session(
        prompt="fix this",
        title="test",
        tags=["sentry"],
        structured_output_schema={"type": "object"},
        idempotency_key="abc",
    )

    assert captured["url"] == "https://api.devin.ai/v1/sessions"
    assert captured["headers"]["Authorization"] == "Bearer cog_test_key"
    assert captured["json"]["prompt"] == "fix this"
    assert captured["json"]["title"] == "test"
    assert captured["json"]["structured_output_schema"] == {"type": "object"}
    assert captured["json"]["idempotent"] is True
    assert "idem:abc" in captured["json"]["tags"]
    assert result.session_id == "devin-abc123"


@pytest.mark.asyncio
async def test_live_parses_pull_request_field(monkeypatch):
    """The PR URL lives at pull_request.url — easy to regress."""
    class FakeResponse:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {
                "session_id": "devin-abc",
                "status_enum": "finished",
                "pull_request": {"url": "https://github.com/x/y/pull/42"},
            }

    class FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, *a, **kw): return FakeResponse()

    monkeypatch.setattr("app.integrations.devin.httpx.AsyncClient", FakeClient)

    client = DevinClient(mode="live", api_key="cog_test_key")
    result = await client.get_session("devin-abc")
    assert result.pr_url == "https://github.com/x/y/pull/42"
    assert result.succeeded is True


@pytest.mark.asyncio
async def test_unknown_status_does_not_crash(monkeypatch):
    """Devin might add new statuses; we should degrade to WORKING, not 500."""
    class FakeResponse:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {
                "session_id": "devin-abc",
                "status_enum": "something_new_we_dont_know_about",
            }

    class FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, *a, **kw): return FakeResponse()

    monkeypatch.setattr("app.integrations.devin.httpx.AsyncClient", FakeClient)

    client = DevinClient(mode="live", api_key="k")
    result = await client.get_session("devin-abc")
    assert result.status == SessionStatus.WORKING   # conservative fallback
