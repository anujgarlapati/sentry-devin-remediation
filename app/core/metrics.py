"""
Metrics derived from the Vulnerability table.

Kept as pure functions over a list of Vulnerability rows so we can unit-test
without a DB and swap the underlying store later without touching metric
definitions.

The four questions a VP of Eng asks:
  1. Is it working?     → success_rate, prs_opened_7d, prs_merged_7d
  2. Is it fast?        → mttr_p50_minutes, mttr_p95_minutes, time_to_pr_p50
  3. Is it efficient?   → acus_per_success, cost_per_success_usd
  4. What's in flight?  → running_count, queued_count
"""
from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from app.models.schema import RemediationStatus, TriageDecision, Vulnerability

# Rough ACU cost; Devin's pricing isn't published and varies by plan.
# Documented as a config knob in the README so the VP doesn't think it's load-bearing.
USD_PER_ACU = 2.25


@dataclass
class Metrics:
    # Volume
    total: int = 0
    detected_24h: int = 0
    routed_to_devin: int = 0
    routed_to_dependabot: int = 0
    skipped: int = 0

    # Health
    running: int = 0
    pr_opened: int = 0
    merged: int = 0
    failed: int = 0
    success_rate: float = 0.0       # 0.0-1.0, over terminal Devin sessions
    prs_opened_7d: int = 0
    prs_merged_7d: int = 0

    # Speed (minutes)
    time_to_pr_p50: float | None = None
    time_to_pr_p95: float | None = None
    mttr_p50: float | None = None   # dispatched → merged
    mttr_p95: float | None = None

    # Cost
    total_acus: float = 0.0
    acus_per_success: float | None = None
    cost_per_success_usd: float | None = None
    cost_savings_multiplier: float | None = None

    # Breakdowns for UI
    by_severity: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)


def compute_metrics(rows: Iterable[Vulnerability]) -> dict:
    rows = list(rows)
    m = Metrics()

    now = datetime.utcnow()
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    time_to_pr: list[float] = []
    mttr: list[float] = []
    devin_terminal = 0
    devin_successes = 0

    for v in rows:
        m.total += 1

        if v.first_seen_at and v.first_seen_at >= day_ago:
            m.detected_24h += 1

        # Route counts
        if v.triage_decision == TriageDecision.DEVIN:
            m.routed_to_devin += 1
        elif v.triage_decision == TriageDecision.DEPENDABOT:
            m.routed_to_dependabot += 1
        elif v.triage_decision == TriageDecision.SKIP:
            m.skipped += 1

        # Status counts
        if v.status == RemediationStatus.RUNNING:
            m.running += 1
        elif v.status == RemediationStatus.PR_OPENED:
            m.pr_opened += 1
        elif v.status == RemediationStatus.MERGED:
            m.merged += 1
        elif v.status == RemediationStatus.FAILED:
            m.failed += 1

        # Severity
        sev = v.severity.value
        m.by_severity[sev] = m.by_severity.get(sev, 0) + 1
        m.by_status[v.status.value] = m.by_status.get(v.status.value, 0) + 1

        # Devin-only measurements
        if v.triage_decision == TriageDecision.DEVIN:
            if v.status in {
                RemediationStatus.PR_OPENED,
                RemediationStatus.MERGED,
                RemediationStatus.FAILED,
            }:
                devin_terminal += 1
                if v.status != RemediationStatus.FAILED:
                    devin_successes += 1

            if v.devin_acus_consumed:
                m.total_acus += v.devin_acus_consumed

            # Timing — only count when we have both endpoints
            if v.dispatched_at and v.pr_opened_at:
                dt = (v.pr_opened_at - v.dispatched_at).total_seconds() / 60
                if dt >= 0:
                    time_to_pr.append(dt)
                    if v.pr_opened_at >= week_ago:
                        m.prs_opened_7d += 1

            if v.dispatched_at and v.merged_at:
                dt = (v.merged_at - v.dispatched_at).total_seconds() / 60
                if dt >= 0:
                    mttr.append(dt)
                    if v.merged_at >= week_ago:
                        m.prs_merged_7d += 1

    # Derived numbers
    if devin_terminal > 0:
        m.success_rate = round(devin_successes / devin_terminal, 3)

    if devin_successes > 0 and m.total_acus > 0:
        m.acus_per_success = round(m.total_acus / devin_successes, 2)
        m.cost_per_success_usd = round(m.acus_per_success * USD_PER_ACU, 2)
        ENGINEER_COST_PER_CVE_USD = 200.0  # 2h engineer time * $100/h fully loaded
        if m.cost_per_success_usd and m.cost_per_success_usd > 0:
            m.cost_savings_multiplier = round(
                ENGINEER_COST_PER_CVE_USD / m.cost_per_success_usd, 1
            )

    if time_to_pr:
        m.time_to_pr_p50 = round(statistics.median(time_to_pr), 1)
        m.time_to_pr_p95 = round(_percentile(time_to_pr, 0.95), 1)
    if mttr:
        m.mttr_p50 = round(statistics.median(mttr), 1)
        m.mttr_p95 = round(_percentile(mttr, 0.95), 1)

    return asdict(m)


def _percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[int(k)]
    return xs[f] + (xs[c] - xs[f]) * (k - f)
