"""
Domain models. One canonical `Vulnerability` that webhook and scanner paths
both normalize into, so downstream triage/dispatch doesn't care about source.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlmodel import Field, JSON, SQLModel, Column


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class Source(str, Enum):
    DEPENDABOT = "dependabot"
    PIP_AUDIT = "pip_audit"
    OSV_SCANNER = "osv_scanner"
    MANUAL = "manual"


class TriageDecision(str, Enum):
    DEVIN = "devin"
    DEPENDABOT = "dependabot"
    SKIP = "skip"


class RemediationStatus(str, Enum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    QUEUED = "queued"
    RUNNING = "running"
    PR_OPENED = "pr_opened"
    MERGED = "merged"
    FAILED = "failed"
    SKIPPED = "skipped"


class Vulnerability(SQLModel, table=True):
    """
    One row per unique (cve_id, package, manifest_path) in the target repo.
    If the same CVE fires from both Dependabot and a scanner, we dedupe here.
    """
    id: Optional[int] = Field(default=None, primary_key=True)

    # Identity
    cve_id: str = Field(index=True)              # CVE-2024-xxxx or GHSA-xxxx
    package: str = Field(index=True)
    ecosystem: str                                # pip, npm, etc.
    manifest_path: str                            # requirements.txt, package.json
    target_branch: str = "master"

    # Content
    severity: Severity = Severity.UNKNOWN
    summary: str = ""
    affected_range: str = ""                      # ">=1.0.0,<1.2.3"
    fixed_version: Optional[str] = None           # None when no patch exists
    current_version: Optional[str] = None
    advisory_url: Optional[str] = None

    # Provenance
    source: Source
    source_payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
    first_seen_at: datetime = Field(default_factory=datetime.utcnow)

    # Tracking on the target repo
    github_issue_number: Optional[int] = None
    github_issue_url: Optional[str] = None

    # State
    triage_decision: Optional[TriageDecision] = None
    triage_reason: Optional[str] = None
    status: RemediationStatus = RemediationStatus.DETECTED

    # Devin linkage (nullable — only set for Devin-routed items)
    devin_session_id: Optional[str] = Field(default=None, index=True)
    devin_session_url: Optional[str] = None
    devin_pr_url: Optional[str] = None
    devin_acus_consumed: Optional[float] = None
    devin_structured_output: Optional[dict] = Field(
        default=None, sa_column=Column(JSON)
    )

    # Timing (for MTTR calculations)
    triaged_at: Optional[datetime] = None
    dispatched_at: Optional[datetime] = None
    pr_opened_at: Optional[datetime] = None
    merged_at: Optional[datetime] = None

    @property
    def dedupe_key(self) -> str:
        return f"{self.cve_id}:{self.package}:{self.manifest_path}"

    @property
    def has_patch(self) -> bool:
        return bool(self.fixed_version)


class EventLog(SQLModel, table=True):
    """
    Append-only event log. Every state change writes a row here so we can
    replay a vulnerability's history and compute metrics without back-filling.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    vulnerability_id: int = Field(foreign_key="vulnerability.id", index=True)
    at: datetime = Field(default_factory=datetime.utcnow, index=True)
    event: str                                     # free-form: "triaged", "devin_session_created"
    details: dict = Field(default_factory=dict, sa_column=Column(JSON))
