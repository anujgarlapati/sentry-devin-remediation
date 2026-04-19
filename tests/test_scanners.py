"""
Tests for scanner adapters. These guard the boundary between external tools
(pip-audit, osv-scanner, GitHub) and our canonical Vulnerability model.
Schema drift in any of those tools would break us silently without these.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.integrations.scanners import (
    parse_dependabot_webhook,
    parse_osv_scanner,
    parse_pip_audit,
)
from app.models.schema import Severity, Source

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestPipAudit:
    def test_extracts_all_vulns(self):
        vulns = parse_pip_audit(_load("pip-audit-sample.json"))
        # Five entries in the fixture
        assert len(vulns) == 5

    def test_prefers_cve_over_ghsa_id(self):
        vulns = parse_pip_audit(_load("pip-audit-sample.json"))
        flask = next(v for v in vulns if v.package == "flask")
        # aliases contain CVE — we should surface that as cve_id
        assert flask.cve_id == "CVE-2023-30861"

    def test_current_version_populated_from_dep(self):
        vulns = parse_pip_audit(_load("pip-audit-sample.json"))
        flask = next(v for v in vulns if v.package == "flask")
        assert flask.current_version == "2.0.1"
        assert flask.fixed_version == "2.2.5"

    def test_severity_mapped(self):
        vulns = parse_pip_audit(_load("pip-audit-sample.json"))
        pyarrow = next(v for v in vulns if v.package == "pyarrow")
        assert pyarrow.severity == Severity.CRITICAL

    def test_no_fix_version_handled(self):
        vulns = parse_pip_audit(_load("pip-audit-sample.json"))
        sqlparse = next(v for v in vulns if v.package == "sqlparse")
        assert sqlparse.fixed_version is None

    def test_source_tagged(self):
        vulns = parse_pip_audit(_load("pip-audit-sample.json"))
        assert all(v.source == Source.PIP_AUDIT for v in vulns)

    def test_raw_payload_preserved(self):
        """Preserving the raw payload lets us audit what the scanner told us."""
        vulns = parse_pip_audit(_load("pip-audit-sample.json"))
        assert all(v.source_payload for v in vulns)


class TestOsvScanner:
    def test_extracts_both_npm_deps(self):
        vulns = parse_osv_scanner(_load("osv-scanner-sample.json"))
        packages = {v.package for v in vulns}
        assert packages == {"axios", "lodash.template"}

    def test_deprecated_package_has_no_fix(self):
        vulns = parse_osv_scanner(_load("osv-scanner-sample.json"))
        lt = next(v for v in vulns if v.package == "lodash.template")
        assert lt.fixed_version is None

    def test_fix_extracted_from_events(self):
        vulns = parse_osv_scanner(_load("osv-scanner-sample.json"))
        axios = next(v for v in vulns if v.package == "axios")
        assert axios.fixed_version == "1.7.4"

    def test_manifest_path_from_source(self):
        vulns = parse_osv_scanner(_load("osv-scanner-sample.json"))
        assert all("package.json" in v.manifest_path for v in vulns)

    def test_ecosystem_lowercased(self):
        vulns = parse_osv_scanner(_load("osv-scanner-sample.json"))
        assert all(v.ecosystem == "npm" for v in vulns)


class TestDependabotWebhook:
    def test_parses_basic_alert(self):
        v = parse_dependabot_webhook(_load("dependabot-alert-example.json"))
        assert v.cve_id == "CVE-2024-35195"
        assert v.package == "requests"
        assert v.fixed_version == "2.32.0"
        assert v.severity == Severity.MODERATE
        assert v.source == Source.DEPENDABOT

    def test_source_payload_preserved_for_audit(self):
        payload = _load("dependabot-alert-example.json")
        v = parse_dependabot_webhook(payload)
        # Full webhook kept for forensics
        assert v.source_payload == payload
