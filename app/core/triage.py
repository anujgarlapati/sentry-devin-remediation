"""
Triage engine.

This is the judgment layer that decides: does this finding need Devin, or
can Dependabot handle it, or should we ignore it entirely?

Rationale for the rules below (discussed in docs/ADR-001-triage.md):

- We WANT to send Devin the hard stuff — major version bumps, transitive
  dependencies, no-patch situations — because that's where its code
  reasoning pays off.

- We DON'T want to send Devin trivial patch bumps because Dependabot
  already handles those and Devin time is expensive (~$2-4 per session).

- We DON'T want to waste ACUs on dev/test-only dependencies in the
  critical path; those can wait for scheduled maintenance windows.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from app.models.schema import Severity, TriageDecision, Vulnerability

log = logging.getLogger(__name__)


@dataclass
class TriageResult:
    decision: TriageDecision
    reason: str
    priority: int = 50   # 0-100, higher = dispatch sooner


# Manifest basenames we treat as non-prod. Matched by leaf filename AND
# by suffix, so `superset/requirements/development.txt` matches too.
NON_PROD_MANIFEST_LEAVES = {
    "requirements-dev.txt",
    "requirements-test.txt",
    "dev-requirements.txt",
    "test-requirements.txt",
    "development.txt",
    "testing.txt",
    "test.txt",
}

# Path fragments that indicate a non-prod manifest regardless of leaf name
NON_PROD_PATH_HINTS = ("/dev/", "/test/", "/tests/")

# Packages we've seen cause noise. Real deployment would read this from a
# YAML config; hardcoded here for demo clarity.
KNOWN_FALSE_POSITIVES: set[str] = set()


def triage(vuln: Vulnerability) -> TriageResult:
    """
    Route a vulnerability to Devin, Dependabot, or skip.
    Pure function — no DB or network calls, easy to unit test.
    """
    # --- Hard skips ------------------------------------------------------

    if vuln.package in KNOWN_FALSE_POSITIVES:
        return TriageResult(
            TriageDecision.SKIP,
            f"{vuln.package} is on the false-positive allowlist",
            priority=0,
        )

    manifest_leaf = vuln.manifest_path.split("/")[-1]
    manifest_normalized = vuln.manifest_path.replace("\\", "/").lower()
    is_non_prod = (
        manifest_leaf in NON_PROD_MANIFEST_LEAVES
        or any(hint in f"/{manifest_normalized}" for hint in NON_PROD_PATH_HINTS)
    )
    if is_non_prod and vuln.severity in {
        Severity.LOW,
        Severity.MODERATE,
    }:
        return TriageResult(
            TriageDecision.SKIP,
            f"Low/moderate severity in non-prod manifest ({vuln.manifest_path})",
            priority=10,
        )

    # --- Devin-only cases ------------------------------------------------

    # No fix available → needs creative work (workaround, patch, dependency swap)
    if not vuln.has_patch:
        return TriageResult(
            TriageDecision.DEVIN,
            "No patched version available — requires workaround analysis",
            priority=_severity_priority(vuln.severity) + 20,
        )

    # Major version bump → Dependabot can open the PR but usually breaks tests.
    # Devin can read the changelog, update call sites, fix tests.
    if _is_major_bump(vuln.current_version, vuln.fixed_version):
        return TriageResult(
            TriageDecision.DEVIN,
            f"Major version bump ({vuln.current_version} → {vuln.fixed_version}) "
            "likely needs code changes",
            priority=_severity_priority(vuln.severity) + 10,
        )

    # Critical severity always gets Devin, even for patch bumps — we want the
    # extra verification (test runs, blast radius check).
    if vuln.severity == Severity.CRITICAL:
        return TriageResult(
            TriageDecision.DEVIN,
            "Critical severity — dispatch Devin for full verification",
            priority=95,
        )

    # --- Default: let Dependabot handle it -------------------------------

    return TriageResult(
        TriageDecision.DEPENDABOT,
        f"Patch-level bump ({vuln.current_version} → {vuln.fixed_version}); "
        "Dependabot is sufficient",
        priority=_severity_priority(vuln.severity),
    )


# --------------------------------------------------------------------- helpers

_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_major(version: Optional[str]) -> Optional[int]:
    if not version:
        return None
    m = _VERSION_RE.match(version.strip())
    if not m:
        return None
    return int(m.group(1))


def _is_major_bump(current: Optional[str], fixed: Optional[str]) -> bool:
    c, f = _parse_major(current), _parse_major(fixed)
    if c is None or f is None:
        return False
    return f > c


def _severity_priority(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 90,
        Severity.HIGH: 70,
        Severity.MODERATE: 40,
        Severity.LOW: 20,
        Severity.UNKNOWN: 30,
    }[sev]
