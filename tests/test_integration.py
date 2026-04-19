"""
Integration test. End-to-end exercise of the orchestrator using
in-memory SQLite, mock Devin, and mock GitHub. Confirms the happy path
actually works and that the event log tells the right story.
"""
from __future__ import annotations

import asyncio

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.core.orchestrator import Orchestrator
from app.integrations.devin import DevinClient
from app.integrations.github import GitHubClient
from app.models.schema import (
    EventLog,
    RemediationStatus,
    Severity,
    Source,
    TriageDecision,
    Vulnerability,
)


@pytest.fixture
def db() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def orch(db):
    return Orchestrator(
        db=db,
        devin=DevinClient(mode="mock"),
        github=GitHubClient(mode="mock"),
        target_repo="acme/superset-fork",
        target_branch="main",
    )


@pytest.mark.asyncio
async def test_skip_path_ends_in_skipped_status(orch, db):
    """Low-severity in a dev manifest should short-circuit."""
    v = Vulnerability(
        cve_id="CVE-X",
        package="pytest-plugin",
        ecosystem="pip",
        manifest_path="requirements-dev.txt",
        severity=Severity.LOW,
        fixed_version="1.2.3",
        current_version="1.2.0",
        source=Source.PIP_AUDIT,
    )
    await orch.handle_new_vulnerability(v)

    stored = db.exec(select(Vulnerability)).one()
    assert stored.status == RemediationStatus.SKIPPED
    assert stored.triage_decision == TriageDecision.SKIP
    # Skip path shouldn't touch Devin
    assert stored.devin_session_id is None


@pytest.mark.asyncio
async def test_dependabot_path_creates_issue_only(orch, db):
    v = Vulnerability(
        cve_id="CVE-Y",
        package="requests",
        ecosystem="pip",
        manifest_path="requirements.txt",
        severity=Severity.MODERATE,
        fixed_version="2.32.0",
        current_version="2.31.1",
        source=Source.PIP_AUDIT,
    )
    await orch.handle_new_vulnerability(v)

    stored = db.exec(select(Vulnerability)).one()
    assert stored.triage_decision == TriageDecision.DEPENDABOT
    assert stored.github_issue_url is not None
    assert stored.devin_session_id is None


@pytest.mark.asyncio
async def test_devin_path_dispatches_and_reaches_pr_opened(orch, db):
    v = Vulnerability(
        cve_id="CVE-Z",
        package="pyarrow",
        ecosystem="pip",
        manifest_path="requirements.txt",
        severity=Severity.CRITICAL,
        fixed_version="14.0.1",
        current_version="10.0.0",
        source=Source.PIP_AUDIT,
    )
    await orch.handle_new_vulnerability(v)

    stored = db.exec(select(Vulnerability)).one()
    assert stored.triage_decision == TriageDecision.DEVIN
    assert stored.devin_session_id is not None
    assert stored.status == RemediationStatus.RUNNING
    assert stored.dispatched_at is not None

    # Fast-forward the mock session and poll
    mock_session = orch.devin._mock_sessions[stored.devin_session_id]
    mock_session.duration_s = 0.05
    mock_session.will_succeed = True
    await asyncio.sleep(0.1)

    await orch.poll_session(stored)
    db.refresh(stored)

    assert stored.status == RemediationStatus.PR_OPENED
    assert stored.devin_pr_url is not None
    assert stored.pr_opened_at is not None
    assert stored.devin_acus_consumed > 0
    assert stored.devin_structured_output["remediation_status"] == "completed"


@pytest.mark.asyncio
async def test_event_log_records_every_transition(orch, db):
    v = Vulnerability(
        cve_id="CVE-Q",
        package="pyarrow",
        ecosystem="pip",
        manifest_path="requirements.txt",
        severity=Severity.CRITICAL,
        fixed_version="14.0.1",
        current_version="10.0.0",
        source=Source.PIP_AUDIT,
    )
    await orch.handle_new_vulnerability(v)
    stored = db.exec(select(Vulnerability)).one()

    mock = orch.devin._mock_sessions[stored.devin_session_id]
    mock.duration_s = 0.05
    mock.will_succeed = True
    await asyncio.sleep(0.1)
    await orch.poll_session(stored)

    events = db.exec(
        select(EventLog)
        .where(EventLog.vulnerability_id == stored.id)
        .order_by(EventLog.at)
    ).all()

    event_names = [e.event for e in events]
    assert "triaged" in event_names
    assert "issue_created" in event_names
    assert "devin_session_created" in event_names
    assert "status_change" in event_names


@pytest.mark.asyncio
async def test_failed_session_is_recorded(orch, db):
    v = Vulnerability(
        cve_id="CVE-F",
        package="sqlparse",
        ecosystem="pip",
        manifest_path="requirements.txt",
        severity=Severity.HIGH,
        fixed_version=None,
        current_version="0.4.3",
        source=Source.PIP_AUDIT,
    )
    await orch.handle_new_vulnerability(v)
    stored = db.exec(select(Vulnerability)).one()

    mock = orch.devin._mock_sessions[stored.devin_session_id]
    mock.duration_s = 0.05
    mock.will_succeed = False
    await asyncio.sleep(0.1)

    await orch.poll_session(stored)
    db.refresh(stored)

    assert stored.status == RemediationStatus.FAILED
    assert stored.devin_pr_url is None
    # Structured output should capture the reason
    assert stored.devin_structured_output is not None
    assert stored.devin_structured_output["remediation_status"] == "blocked"
    assert "reason" in stored.devin_structured_output
