"""
Prompt construction for Devin sessions.

This is arguably the most important file in the system. A Devin session is
only as good as its prompt. We've learned (and documented in
docs/PROMPT-ENGINEERING.md) that the highest-leverage elements are:

1. Precise target — the exact repo, branch, manifest path, and package
2. Non-negotiable acceptance criteria — Devin should know when it's "done"
3. A structured_output schema — forces Devin to report machine-readably
4. Explicit bail-out instructions — when NOT to open a PR
5. Reference material — the advisory URL, not just the CVE id

We keep the prompt deterministic per vulnerability so session creation can
be idempotent on retry.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from app.models.schema import Vulnerability


# JSON Schema (Draft 7) for what we want Devin to report back.
# Devin fills this in via the structured_output endpoint while it works.
REMEDIATION_OUTPUT_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["remediation_status"],
    "properties": {
        "remediation_status": {
            "type": "string",
            "enum": ["completed", "blocked", "investigating", "abandoned"],
            "description": "Current state. Use 'completed' only when a PR is open "
                           "with green CI.",
        },
        "pr_url": {
            "type": "string",
            "format": "uri",
            "description": "The GitHub PR URL, once opened.",
        },
        "approach": {
            "type": "string",
            "description": "1-3 sentences describing what you did. Focus on "
                           "non-obvious decisions (e.g. 'chose alternative package X "
                           "because maintainer abandoned original').",
        },
        "files_changed": {
            "type": "integer",
            "description": "Number of files modified in the PR.",
        },
        "tests_passing": {
            "type": "boolean",
            "description": "Whether the project's test suite passes on your branch.",
        },
        "breaking_changes": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Any API or behavior changes that downstream code needs "
                           "to know about. Empty array if none.",
        },
        "reason": {
            "type": "string",
            "description": "If remediation_status is 'blocked' or 'abandoned', "
                           "explain why.",
        },
        "reachability_analysis": {
            "type": "object",
            "description": "Quick sanity check — does this repo actually invoke the vulnerable code path?",
            "properties": {
                "code_path_reachable": {"type": "boolean"},
                "call_sites_found": {"type": "integer"},
                "notes": {"type": "string"},
            },
        },
        "alternative_packages_considered": {
            "type": "array",
            "description": "If the fix required switching packages, list alternatives you evaluated.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "rejected_because": {"type": "string"},
                },
            },
        },
        "rollback_plan": {
            "type": "string",
            "description": "One-sentence rollback instructions if this PR needs to be reverted. e.g. 'git revert <sha>; pin werkzeug==2.0.2'.",
        },
    },
}


@dataclass
class PromptContext:
    """Everything Devin needs to know to remediate one CVE."""
    vulnerability: Vulnerability
    target_repo: str           # "myorg/superset-fork"
    target_branch: str = "main"
    issue_url: str | None = None


def build_remediation_prompt(ctx: PromptContext) -> str:
    """
    Build the initial prompt for a remediation session.

    Devin reads this and then operates autonomously. The prompt is long on
    purpose — empirically, terse prompts cause Devin to guess.
    """
    v = ctx.vulnerability

    patch_info = (
        f"The advisory lists a fix in **version `{v.fixed_version}`**."
        if v.has_patch
        else "**No patched version is currently available.** Investigate "
             "workarounds: alternative packages, local patches via overrides, "
             "or whether the vulnerable code path is reachable at all in this "
             "repo. Only open a PR if you find a defensible fix."
    )

    issue_ref = (
        f"\nThis work is tracked in issue {ctx.issue_url}. "
        f"Reference it in your PR body with 'Closes {ctx.issue_url}'."
        if ctx.issue_url
        else ""
    )

    schema_json = json.dumps(REMEDIATION_OUTPUT_SCHEMA, indent=2)

    return f"""You are remediating a security vulnerability in an open-source codebase.

# Target
- Repository: `{ctx.target_repo}`
- Branch to open PR against: `{ctx.target_branch}`
- Manifest: `{v.manifest_path}`

# Vulnerability
- Advisory: **{v.cve_id}** ({v.severity.value})
- Package: `{v.package}` ({v.ecosystem})
- Current version in this repo: `{v.current_version or 'unknown'}`
- Affected range: `{v.affected_range}`
- Summary: {v.summary}
- Advisory URL: {v.advisory_url or 'none provided'}

{patch_info}

# What success looks like

1. Open a pull request against `{ctx.target_repo}:{ctx.target_branch}` that \
resolves the advisory for this package in this manifest.
2. The PR must:
   - Update `{v.manifest_path}` and any lockfiles regenerated as a result.
   - Not downgrade any other dependency.
   - Pass the project's existing CI checks (lint, type, tests).
   - Include a PR body that names the CVE, links the advisory, explains your \
     approach in 2-3 sentences, and lists any breaking changes.
   - Have a descriptive title following the project's conventional-commit \
     style (look at recent PRs for format).
3. If code elsewhere in the repo needs to change to accommodate the fix \
(import renames, removed APIs, changed signatures), make those changes in \
the same PR.

# When NOT to open a PR

Open a session output with `remediation_status: "blocked"` and STOP if:
- The only available fix requires a pre-release or yanked version.
- The vulnerable code path is clearly unreachable in this repo and a bump \
  would introduce more risk than it removes (explain your reasoning).
- The fix requires architectural changes that need human judgment (touching \
  more than ~15 files, changing public APIs of the host project).

It is better to escalate than to open a bad PR.

# Reporting

Update your structured output regularly using this schema:

```json
{schema_json}
```

Update it immediately when:
- You start investigating (set status to `investigating`).
- You open the PR (set status to `completed`, fill `pr_url`).
- You hit a blocker (set status to `blocked`, fill `reason`).

# Context{issue_ref}

Treat this like a standard dependency-security ticket. You have autonomy to \
read the changelog, inspect the dependency graph, run tests, and iterate on \
failures. Take your time on the diagnosis; speed matters less than a clean PR."""


def idempotency_key_for(vuln: Vulnerability) -> str:
    """
    Deterministic key so re-dispatches of the same vulnerability don't
    create duplicate Devin sessions. Devin's v1 API supports idempotent=true.
    """
    return f"sentry:{vuln.dedupe_key}"
