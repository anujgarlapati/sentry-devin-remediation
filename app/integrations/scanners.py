"""
Adapters that turn scanner output into our canonical Vulnerability model.

pip-audit (JSON):
  https://github.com/pypa/pip-audit
  {
    "dependencies": [
      {"name": "flask", "version": "1.0", "vulns": [
        {"id": "GHSA-...", "fix_versions": ["2.1.0"], "description": "..."}
      ]}
    ]
  }

osv-scanner (JSON):
  Similar structure, different shape. Both normalized to Vulnerability.

We support both because they find different things — pip-audit uses PyPI
advisory data, osv-scanner uses Google's OSV DB which covers more ecosystems.
"""
from __future__ import annotations

import logging
from typing import Iterable

from app.models.schema import Severity, Source, Vulnerability

log = logging.getLogger(__name__)


def parse_pip_audit(
    data: dict,
    *,
    manifest_path: str = "requirements.txt",
) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for dep in data.get("dependencies", []):
        name = dep.get("name")
        version = dep.get("version")
        for vuln in dep.get("vulns", []):
            fix = (vuln.get("fix_versions") or [None])[0]
            out.append(Vulnerability(
                cve_id=_prefer_cve(vuln),
                package=name,
                ecosystem="pip",
                manifest_path=manifest_path,
                severity=_severity_from_pip_audit(vuln),
                summary=vuln.get("description", "")[:1000],
                affected_range=vuln.get("affected_range", ""),
                fixed_version=fix,
                current_version=version,
                advisory_url=_advisory_url(vuln),
                source=Source.PIP_AUDIT,
                source_payload=vuln,
            ))
    return out


def parse_osv_scanner(data: dict) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for result in data.get("results", []):
        manifest = result.get("source", {}).get("path", "unknown")
        for pkg_result in result.get("packages", []):
            pkg = pkg_result.get("package", {})
            for vuln in pkg_result.get("vulnerabilities", []):
                # OSV gives us 'affected' with version ranges and fix events
                fix_version = _fix_from_osv(vuln)
                affected = _range_from_osv(vuln)
                out.append(Vulnerability(
                    cve_id=vuln.get("id", "UNKNOWN"),
                    package=pkg.get("name", "unknown"),
                    ecosystem=pkg.get("ecosystem", "unknown").lower(),
                    manifest_path=manifest,
                    severity=_severity_from_osv(vuln),
                    summary=(vuln.get("summary") or vuln.get("details", ""))[:1000],
                    affected_range=affected,
                    fixed_version=fix_version,
                    current_version=pkg.get("version"),
                    advisory_url=f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                    source=Source.OSV_SCANNER,
                    source_payload=vuln,
                ))
    return out


def parse_dependabot_webhook(payload: dict) -> Vulnerability:
    """
    GitHub's repository_vulnerability_alert payload → Vulnerability.
    The webhook has less metadata than scanners, so we accept that.
    """
    alert = payload.get("alert", {})
    pkg = alert.get("affected_package_name", "unknown")
    return Vulnerability(
        cve_id=alert.get("external_identifier", "UNKNOWN"),
        package=pkg,
        ecosystem=alert.get("package_ecosystem", "unknown").lower() or "unknown",
        manifest_path=alert.get("affected_manifest_path", "unknown"),
        severity=_severity_from_string(alert.get("severity")),
        summary=alert.get("external_reference", ""),
        affected_range=alert.get("affected_range", ""),
        fixed_version=alert.get("fixed_in"),
        current_version=None,
        advisory_url=alert.get("external_reference"),
        source=Source.DEPENDABOT,
        source_payload=payload,
    )


# --------------------------------------------------------------- helpers

def _prefer_cve(vuln: dict) -> str:
    # pip-audit 'id' is usually GHSA; aliases sometimes have the CVE
    aliases = vuln.get("aliases", []) or []
    for a in aliases:
        if a.startswith("CVE-"):
            return a
    return vuln.get("id", "UNKNOWN")


def _advisory_url(vuln: dict) -> str | None:
    # Try common shapes
    if "link" in vuln:
        return vuln["link"]
    for ref in vuln.get("references", []) or []:
        if isinstance(ref, dict) and ref.get("type") == "ADVISORY":
            return ref.get("url")
        if isinstance(ref, str):
            return ref
    gid = vuln.get("id")
    if gid and gid.startswith("GHSA"):
        return f"https://github.com/advisories/{gid}"
    return None


def _severity_from_pip_audit(vuln: dict) -> Severity:
    sev = (vuln.get("severity") or "").lower()
    return _severity_from_string(sev)


def _severity_from_osv(vuln: dict) -> Severity:
    for s in vuln.get("severity", []) or []:
        # OSV uses CVSS strings; very rough mapping
        score = s.get("score", "")
        if "CRITICAL" in score.upper():
            return Severity.CRITICAL
        if "HIGH" in score.upper():
            return Severity.HIGH
        if "MEDIUM" in score.upper():
            return Severity.MODERATE
        if "LOW" in score.upper():
            return Severity.LOW
    # Fall back to a database_specific.severity field sometimes populated
    ds = (vuln.get("database_specific", {}) or {}).get("severity", "")
    return _severity_from_string(ds)


def _severity_from_string(s: str | None) -> Severity:
    if not s:
        return Severity.UNKNOWN
    s = s.lower()
    if "crit" in s:
        return Severity.CRITICAL
    if "high" in s:
        return Severity.HIGH
    if "mod" in s or "med" in s:
        return Severity.MODERATE
    if "low" in s:
        return Severity.LOW
    return Severity.UNKNOWN


def _fix_from_osv(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []) or []:
        for r in affected.get("ranges", []) or []:
            for event in r.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _range_from_osv(vuln: dict) -> str:
    parts: list[str] = []
    for affected in vuln.get("affected", []) or []:
        for r in affected.get("ranges", []) or []:
            intro = next(
                (e["introduced"] for e in r.get("events", []) if "introduced" in e),
                None,
            )
            fixed = next(
                (e["fixed"] for e in r.get("events", []) if "fixed" in e),
                None,
            )
            if intro and fixed:
                parts.append(f">={intro},<{fixed}")
            elif intro:
                parts.append(f">={intro}")
    return ",".join(parts) if parts else ""
