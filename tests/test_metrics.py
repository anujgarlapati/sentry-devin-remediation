"""
Metrics tests. The dashboard's credibility depends on these numbers being
right, so we exercise the edge cases (empty DB, all-failed, mixed timings).
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.core.metrics import compute_metrics
from app.models.schema import (
    RemediationStatus,
    Severity,
    Source,
    TriageDecision,
    Vulnerability,
)


def _v(**kwargs) -> Vulnerability:
    base = dict(
        cve_id="CVE-2024-0000",
        package="pkg",
        ecosystem="pip",
        manifest_path="requirements.txt",
        severity=Severity.HIGH,
        source=Source.PIP_AUDIT,
    )
    base.update(kwargs)
    return Vulnerability(**base)


class TestEmptyState:
    def test_no_vulns_returns_zeros_not_nones(self):
        m = compute_metrics([])
        assert m["total"] == 0
        assert m["success_rate"] == 0.0
        assert m["total_acus"] == 0.0
        # Derived metrics correctly report None when undefined
        assert m["time_to_pr_p50"] is None
        assert m["cost_per_success_usd"] is None


class TestSuccessRate:
    def test_success_rate_is_over_terminal_devin_only(self):
        rows = [
            # 3 devin — 2 succeeded (pr_opened or merged), 1 failed
            _v(triage_decision=TriageDecision.DEVIN, status=RemediationStatus.MERGED),
            _v(triage_decision=TriageDecision.DEVIN, status=RemediationStatus.PR_OPENED),
            _v(triage_decision=TriageDecision.DEVIN, status=RemediationStatus.FAILED),
            # Running devin: not yet terminal, shouldn't count
            _v(triage_decision=TriageDecision.DEVIN, status=RemediationStatus.RUNNING),
            # Dependabot-routed ignored entirely
            _v(triage_decision=TriageDecision.DEPENDABOT, status=RemediationStatus.TRIAGED),
        ]
        m = compute_metrics(rows)
        assert m["success_rate"] == round(2 / 3, 3)

    def test_all_failed_gives_zero(self):
        rows = [
            _v(triage_decision=TriageDecision.DEVIN, status=RemediationStatus.FAILED),
            _v(triage_decision=TriageDecision.DEVIN, status=RemediationStatus.FAILED),
        ]
        assert compute_metrics(rows)["success_rate"] == 0.0


class TestTiming:
    def test_time_to_pr_p50(self):
        t0 = datetime.utcnow() - timedelta(days=3)
        rows = [
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.PR_OPENED,
                dispatched_at=t0,
                pr_opened_at=t0 + timedelta(minutes=10),
            ),
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.PR_OPENED,
                dispatched_at=t0,
                pr_opened_at=t0 + timedelta(minutes=20),
            ),
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.PR_OPENED,
                dispatched_at=t0,
                pr_opened_at=t0 + timedelta(minutes=30),
            ),
        ]
        m = compute_metrics(rows)
        assert m["time_to_pr_p50"] == 20.0

    def test_mttr_computed_from_dispatch_to_merge(self):
        t0 = datetime.utcnow() - timedelta(days=1)
        rows = [
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.MERGED,
                dispatched_at=t0,
                merged_at=t0 + timedelta(hours=2),
            ),
        ]
        m = compute_metrics(rows)
        assert m["mttr_p50"] == 120.0   # minutes


class TestCost:
    def test_cost_per_success_uses_successful_sessions(self):
        rows = [
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.MERGED,
                devin_acus_consumed=3.0,
            ),
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.PR_OPENED,
                devin_acus_consumed=4.0,
            ),
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.FAILED,
                devin_acus_consumed=1.5,   # burned ACUs on a failure; still counted in total
            ),
        ]
        m = compute_metrics(rows)
        # total_acus includes failed session
        assert m["total_acus"] == 8.5
        # but acus_per_success divides by successes only (2)
        assert m["acus_per_success"] == round(8.5 / 2, 2)

    def test_zero_successes_returns_none_cost(self):
        rows = [
            _v(
                triage_decision=TriageDecision.DEVIN,
                status=RemediationStatus.FAILED,
                devin_acus_consumed=2.0,
            ),
        ]
        m = compute_metrics(rows)
        assert m["cost_per_success_usd"] is None


class TestBreakdowns:
    def test_severity_breakdown(self):
        rows = [
            _v(severity=Severity.CRITICAL),
            _v(severity=Severity.CRITICAL),
            _v(severity=Severity.HIGH),
            _v(severity=Severity.LOW),
        ]
        by_sev = compute_metrics(rows)["by_severity"]
        assert by_sev["critical"] == 2
        assert by_sev["high"] == 1
        assert by_sev["low"] == 1

    def test_24h_window_respected(self):
        old = datetime.utcnow() - timedelta(days=3)
        new = datetime.utcnow() - timedelta(hours=1)
        rows = [
            _v(first_seen_at=old),
            _v(first_seen_at=new),
            _v(first_seen_at=new),
        ]
        assert compute_metrics(rows)["detected_24h"] == 2
