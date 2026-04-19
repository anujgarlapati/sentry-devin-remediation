"""
Prompt-builder tests. These catch regressions where a refactor silently
drops something Devin depends on (the advisory URL, the bail-out
instructions, the structured_output schema).
"""
from __future__ import annotations

import json

from app.core.prompts import (
    PromptContext,
    REMEDIATION_OUTPUT_SCHEMA,
    build_remediation_prompt,
    idempotency_key_for,
)
from app.models.schema import Severity, Source, Vulnerability


def _vuln(**overrides) -> Vulnerability:
    defaults = dict(
        cve_id="CVE-2024-12345",
        package="requests",
        ecosystem="pip",
        manifest_path="requirements.txt",
        severity=Severity.HIGH,
        summary="Request smuggling vulnerability in url parser.",
        affected_range=">=2.0,<2.32.0",
        fixed_version="2.32.0",
        current_version="2.28.0",
        advisory_url="https://github.com/advisories/GHSA-xxxx",
        source=Source.PIP_AUDIT,
    )
    defaults.update(overrides)
    return Vulnerability(**defaults)


class TestPromptContent:
    def test_includes_all_core_identifiers(self):
        ctx = PromptContext(
            vulnerability=_vuln(),
            target_repo="acme/superset-fork",
            target_branch="main",
        )
        prompt = build_remediation_prompt(ctx)

        # The CVE, package, repo, manifest, and versions must appear verbatim.
        # If any of these drop, Devin loses its anchor.
        assert "CVE-2024-12345" in prompt
        assert "requests" in prompt
        assert "acme/superset-fork" in prompt
        assert "requirements.txt" in prompt
        assert "2.28.0" in prompt       # current
        assert "2.32.0" in prompt       # fixed

    def test_advisory_url_is_included_when_available(self):
        ctx = PromptContext(
            vulnerability=_vuln(),
            target_repo="acme/superset-fork",
        )
        prompt = build_remediation_prompt(ctx)
        assert "https://github.com/advisories/GHSA-xxxx" in prompt

    def test_issue_url_is_referenced_when_provided(self):
        ctx = PromptContext(
            vulnerability=_vuln(),
            target_repo="acme/superset-fork",
            issue_url="https://github.com/acme/superset-fork/issues/7",
        )
        prompt = build_remediation_prompt(ctx)
        assert "issues/7" in prompt
        assert "Closes" in prompt       # PR body directive

    def test_no_patch_available_emits_workaround_guidance(self):
        v = _vuln(fixed_version=None)
        ctx = PromptContext(vulnerability=v, target_repo="a/b")
        prompt = build_remediation_prompt(ctx)
        assert "No patched version" in prompt
        assert "workaround" in prompt.lower()
        # Shouldn't confidently name a version that doesn't exist
        assert "fix in **version" not in prompt

    def test_bailout_instructions_present(self):
        """Devin must know WHEN to stop. This is critical for hard CVEs."""
        ctx = PromptContext(vulnerability=_vuln(), target_repo="a/b")
        prompt = build_remediation_prompt(ctx)
        assert "blocked" in prompt.lower()
        assert "NOT to open" in prompt or "When NOT" in prompt

    def test_structured_output_schema_embedded(self):
        ctx = PromptContext(vulnerability=_vuln(), target_repo="a/b")
        prompt = build_remediation_prompt(ctx)
        # Full schema should be in the prompt; we check a representative field
        assert "remediation_status" in prompt
        assert "pr_url" in prompt


class TestSchema:
    def test_schema_is_valid_json_schema(self):
        # Should round-trip through json without issue
        serialized = json.dumps(REMEDIATION_OUTPUT_SCHEMA)
        parsed = json.loads(serialized)
        assert parsed["type"] == "object"
        assert "remediation_status" in parsed["properties"]
        assert "remediation_status" in parsed["required"]

    def test_status_enum_covers_expected_cases(self):
        status = REMEDIATION_OUTPUT_SCHEMA["properties"]["remediation_status"]
        assert set(status["enum"]) >= {"completed", "blocked"}


class TestIdempotency:
    def test_key_is_deterministic(self):
        v1 = _vuln()
        v2 = _vuln()
        assert idempotency_key_for(v1) == idempotency_key_for(v2)

    def test_key_differs_by_manifest(self):
        v1 = _vuln(manifest_path="requirements.txt")
        v2 = _vuln(manifest_path="requirements/dev.txt")
        assert idempotency_key_for(v1) != idempotency_key_for(v2)

    def test_key_differs_by_package(self):
        v1 = _vuln(package="requests")
        v2 = _vuln(package="urllib3")
        assert idempotency_key_for(v1) != idempotency_key_for(v2)
