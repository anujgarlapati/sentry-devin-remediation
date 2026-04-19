"""Tests for the triage engine. All pure functions — no fixtures needed."""
from __future__ import annotations

from app.core.triage import triage
from app.models.schema import Severity, Source, TriageDecision, Vulnerability


def _make_vuln(**overrides) -> Vulnerability:
    defaults = dict(
        cve_id="CVE-2024-0001",
        package="somepkg",
        ecosystem="pip",
        manifest_path="requirements.txt",
        severity=Severity.HIGH,
        summary="example",
        affected_range=">=1.0,<1.5",
        fixed_version="1.5.0",
        current_version="1.2.0",
        source=Source.PIP_AUDIT,
    )
    defaults.update(overrides)
    return Vulnerability(**defaults)


class TestTriageRouting:
    def test_no_patch_available_goes_to_devin(self):
        v = _make_vuln(fixed_version=None)
        result = triage(v)
        assert result.decision == TriageDecision.DEVIN
        assert "workaround" in result.reason.lower()

    def test_major_version_bump_goes_to_devin(self):
        v = _make_vuln(current_version="1.9.0", fixed_version="2.0.0")
        result = triage(v)
        assert result.decision == TriageDecision.DEVIN
        assert "major" in result.reason.lower()

    def test_critical_severity_always_goes_to_devin(self):
        # Patch-level bump, normally Dependabot — but critical overrides
        v = _make_vuln(
            severity=Severity.CRITICAL,
            current_version="1.4.1",
            fixed_version="1.4.2",
        )
        result = triage(v)
        assert result.decision == TriageDecision.DEVIN
        assert "critical" in result.reason.lower()
        assert result.priority >= 90

    def test_patch_bump_goes_to_dependabot(self):
        v = _make_vuln(
            severity=Severity.MODERATE,
            current_version="1.4.1",
            fixed_version="1.4.2",
        )
        result = triage(v)
        assert result.decision == TriageDecision.DEPENDABOT

    def test_low_severity_in_dev_manifest_is_skipped(self):
        v = _make_vuln(
            severity=Severity.LOW,
            manifest_path="requirements-dev.txt",
        )
        result = triage(v)
        assert result.decision == TriageDecision.SKIP
        assert "non-prod" in result.reason.lower()

    def test_critical_in_dev_manifest_still_remediated(self):
        # The skip rule only fires for low/moderate — critical in a dev
        # manifest is still a real problem if it ships.
        v = _make_vuln(
            severity=Severity.CRITICAL,
            manifest_path="requirements-dev.txt",
            fixed_version=None,
        )
        result = triage(v)
        assert result.decision == TriageDecision.DEVIN

    def test_nested_dev_manifest_path_still_skipped(self):
        v = _make_vuln(
            severity=Severity.LOW,
            manifest_path="superset/requirements/development.txt",
        )
        result = triage(v)
        assert result.decision == TriageDecision.SKIP


class TestPriority:
    def test_critical_beats_high(self):
        crit = triage(_make_vuln(severity=Severity.CRITICAL, fixed_version=None))
        high = triage(_make_vuln(severity=Severity.HIGH, fixed_version=None))
        assert crit.priority > high.priority

    def test_high_beats_moderate(self):
        high = triage(_make_vuln(severity=Severity.HIGH, fixed_version=None))
        mod = triage(_make_vuln(severity=Severity.MODERATE, fixed_version=None))
        assert high.priority > mod.priority


class TestVersionParsing:
    """Exercise edge cases in the version-comparison helper through public API."""

    def test_v_prefix_is_stripped(self):
        v = _make_vuln(current_version="v1.9.0", fixed_version="v2.0.0")
        assert triage(v).decision == TriageDecision.DEVIN

    def test_missing_versions_dont_crash(self):
        v = _make_vuln(current_version=None, fixed_version="2.0.0")
        # Shouldn't be classified as major bump when we can't determine current
        result = triage(v)
        # Should fall through to Dependabot (patch path), not DEVIN
        assert result.decision == TriageDecision.DEPENDABOT

    def test_same_major_is_not_bump(self):
        v = _make_vuln(current_version="1.4.1", fixed_version="1.9.0")
        # Minor bump, same major — Dependabot
        assert triage(v).decision == TriageDecision.DEPENDABOT
