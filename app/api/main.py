"""
FastAPI entrypoint. Three responsibilities:

1. /webhooks/github — receive Dependabot alert webhooks (and optionally PR
   webhooks so we learn when a Devin PR merges without polling every one).
2. /api/* — JSON endpoints the dashboard calls.
3. / — HTMX dashboard.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, SQLModel, create_engine, select

from app.core.orchestrator import Orchestrator
from app.integrations.devin import DevinClient
from app.integrations.github import GitHubClient
from app.integrations.scanners import parse_dependabot_webhook
from app.models.schema import EventLog, RemediationStatus, Severity, Source, Vulnerability

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ wiring

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentry.db")
DEVIN_MODE = os.getenv("DEVIN_MODE", "mock")
GITHUB_MODE = os.getenv("GITHUB_MODE", "mock")
TARGET_REPO = os.getenv("TARGET_REPO", "anujgarlapati/superset")

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)


def get_db() -> AsyncIterator[Session]:
    with Session(engine) as session:
        yield session


def get_devin() -> DevinClient:
    return DevinClient(api_key=os.getenv("DEVIN_API_KEY"), mode=DEVIN_MODE)


def get_github() -> GitHubClient:
    return GitHubClient(token=os.getenv("GITHUB_TOKEN"), mode=GITHUB_MODE)


def get_orchestrator(
    db: Session = Depends(get_db),
    devin: DevinClient = Depends(get_devin),
    github: GitHubClient = Depends(get_github),
) -> Orchestrator:
    return Orchestrator(
        db=db,
        devin=devin,
        github=github,
        target_repo=TARGET_REPO,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    SQLModel.metadata.create_all(engine)
    # Kick off the background poller. In production, run this as a
    # separate worker container — here we keep it in-process for simplicity.
    poller_task = asyncio.create_task(_background_poller())
    # uvicorn.error so the line appears in `docker compose logs` (default log config hides app.*)
    logging.getLogger("uvicorn.error").info(
        "sentry up. devin=%s github=%s repo=%s",
        DEVIN_MODE,
        GITHUB_MODE,
        TARGET_REPO,
    )
    try:
        yield
    finally:
        poller_task.cancel()


app = FastAPI(title="Sentry", lifespan=lifespan)

# Templates + static. app/api/main.py lives in app/api, templates in app/ui.
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "ui" / "templates"
STATIC_DIR = Path(__file__).resolve().parent.parent / "ui" / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --------------------------------------------------------------- webhooks

@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    orch: Orchestrator = Depends(get_orchestrator),
):
    """
    Accept Dependabot vulnerability alert webhooks. We don't verify the
    GitHub signature in this demo — see docs/SECURITY.md for the
    production hardening.
    """
    event = request.headers.get("X-GitHub-Event", "")
    payload = await request.json()

    if event == "repository_vulnerability_alert":
        vuln = parse_dependabot_webhook(payload)
        # Dedupe: if we've already seen this CVE+pkg+manifest, skip.
        with Session(engine) as db:
            existing = db.exec(
                select(Vulnerability).where(
                    Vulnerability.cve_id == vuln.cve_id,
                    Vulnerability.package == vuln.package,
                    Vulnerability.manifest_path == vuln.manifest_path,
                )
            ).first()
            if existing:
                return {"status": "duplicate", "id": existing.id}
        # Process
        await orch.handle_new_vulnerability(vuln)
        return {"status": "accepted", "cve": vuln.cve_id, "package": vuln.package}

    # Future: pull_request events so we detect PR merges without polling
    return {"status": "ignored", "event": event}


# ----------------------------------------------------------------- JSON API

@app.get("/api/vulnerabilities")
def list_vulnerabilities(
    status: str | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(Vulnerability).order_by(Vulnerability.first_seen_at.desc())
    if status:
        stmt = stmt.where(Vulnerability.status == RemediationStatus(status))
    rows = db.exec(stmt).all()
    return [_serialize_vuln(v) for v in rows]


@app.get("/api/vulnerabilities/{vuln_id}")
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    v = db.get(Vulnerability, vuln_id)
    if not v:
        raise HTTPException(404)
    events = db.exec(
        select(EventLog).where(EventLog.vulnerability_id == vuln_id).order_by(EventLog.at)
    ).all()
    return {
        "vulnerability": _serialize_vuln(v),
        "events": [{"at": e.at.isoformat(), "event": e.event, "details": e.details} for e in events],
    }


@app.get("/api/metrics")
def metrics(db: Session = Depends(get_db)):
    """
    The headline numbers. Kept cheap enough to poll every 5 seconds from
    the dashboard without a cache.
    """
    rows = db.exec(select(Vulnerability)).all()
    from app.core.metrics import compute_metrics
    return compute_metrics(rows)


@app.post("/api/triage/preview")
async def preview_triage(payload: dict):
    """
    Dry-run endpoint: given a CVE payload, show what Sentry WOULD do
    (triage decision, reason, priority, prompt preview) without actually
    dispatching a Devin session or creating a GitHub issue.

    Lets a customer audit routing logic before turning Sentry on in prod.
    """
    from app.core.triage import triage
    from app.core.prompts import PromptContext, build_remediation_prompt

    # Accept either a Dependabot-shaped payload or a raw Vulnerability spec
    if "alert" in payload:
        vuln = parse_dependabot_webhook(payload)
    else:
        vuln = Vulnerability(
            cve_id=payload.get("cve_id", "CVE-UNKNOWN"),
            package=payload.get("package", "unknown"),
            ecosystem=payload.get("ecosystem", "pip"),
            manifest_path=payload.get("manifest_path", "requirements.txt"),
            severity=Severity(payload.get("severity", "unknown")),
            summary=payload.get("summary", ""),
            affected_range=payload.get("affected_range", ""),
            fixed_version=payload.get("fixed_version"),
            current_version=payload.get("current_version"),
            advisory_url=payload.get("advisory_url"),
            source=Source.MANUAL,
        )

    decision = triage(vuln)

    prompt_preview = None
    if decision.decision.value == "devin":
        ctx = PromptContext(
            vulnerability=vuln,
            target_repo=TARGET_REPO,
            target_branch="main",
        )
        prompt_preview = build_remediation_prompt(ctx)

    return {
        "vulnerability": {
            "cve_id": vuln.cve_id,
            "package": vuln.package,
            "severity": vuln.severity.value,
            "current_version": vuln.current_version,
            "fixed_version": vuln.fixed_version,
            "manifest_path": vuln.manifest_path,
        },
        "triage": {
            "decision": decision.decision.value,
            "reason": decision.reason,
            "priority": decision.priority,
        },
        "would_dispatch": decision.decision.value == "devin",
        "prompt_preview": prompt_preview,
    }


# ---------------------------------------------------------------- dashboard

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "target_repo": TARGET_REPO,
        "devin_mode": DEVIN_MODE,
    })


@app.get("/vulnerabilities/{vuln_id}", response_class=HTMLResponse)
def vuln_detail(vuln_id: int, request: Request, db: Session = Depends(get_db)):
    v = db.get(Vulnerability, vuln_id)
    if not v:
        raise HTTPException(404)
    events = db.exec(
        select(EventLog).where(EventLog.vulnerability_id == vuln_id).order_by(EventLog.at)
    ).all()
    return templates.TemplateResponse("detail.html", {
        "request": request,
        "v": v,
        "events": events,
    })


# ------------------------------------------------------------- poller task

async def _background_poller():
    """Poll running Devin sessions every 30 seconds."""
    from app.workers.poller import poll_once

    while True:
        try:
            with Session(engine) as db:
                devin = get_devin()
                gh = get_github()
                orch = Orchestrator(db=db, devin=devin, github=gh, target_repo=TARGET_REPO)
                await poll_once(db, orch)
        except Exception:
            log.exception("poller iteration failed")
        await asyncio.sleep(30)


# ------------------------------------------------------------ serializer

def _serialize_vuln(v: Vulnerability) -> dict:
    return {
        "id": v.id,
        "cve_id": v.cve_id,
        "package": v.package,
        "ecosystem": v.ecosystem,
        "severity": v.severity.value,
        "summary": v.summary,
        "current_version": v.current_version,
        "fixed_version": v.fixed_version,
        "source": v.source.value,
        "status": v.status.value,
        "triage_decision": v.triage_decision.value if v.triage_decision else None,
        "triage_reason": v.triage_reason,
        "github_issue_url": v.github_issue_url,
        "devin_session_id": v.devin_session_id,
        "devin_session_url": v.devin_session_url,
        "devin_pr_url": v.devin_pr_url,
        "devin_acus_consumed": v.devin_acus_consumed,
        "devin_structured_output": v.devin_structured_output,
        "first_seen_at": v.first_seen_at.isoformat() if v.first_seen_at else None,
        "dispatched_at": v.dispatched_at.isoformat() if v.dispatched_at else None,
        "pr_opened_at": v.pr_opened_at.isoformat() if v.pr_opened_at else None,
        "merged_at": v.merged_at.isoformat() if v.merged_at else None,
    }
