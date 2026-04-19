"""
GitHub client. Handles:
  - Creating vulnerability tracking issues on the fork
  - Polling PR merge status (Devin tells us a PR opened; only GH tells us it merged)
  - Optionally closing the issue when the PR merges

Has a mock mode that writes to an in-memory store and prints what it would do.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import httpx

log = logging.getLogger(__name__)


@dataclass
class GitHubIssue:
    number: int
    url: str
    title: str
    body: str


@dataclass
class GitHubPR:
    number: int
    url: str
    state: str                 # "open", "closed"
    merged: bool
    head_sha: Optional[str] = None


class GitHubClient:
    def __init__(
        self,
        token: Optional[str] = None,
        mode: str = "mock",
        timeout: float = 20.0,
    ):
        self.mode = mode
        self.token = token
        self.timeout = timeout
        self._mock_issues: list[GitHubIssue] = []
        self._mock_issue_counter = 1

    # ---------------------------------------------------------------- issues

    async def create_vulnerability_issue(
        self,
        *,
        repo: str,
        vulnerability,                     # app.models.schema.Vulnerability
        triage_result,                     # app.core.triage.TriageResult
    ) -> GitHubIssue:
        title = f"[{vulnerability.severity.value.upper()}] {vulnerability.cve_id}: {vulnerability.package}"
        body = self._format_issue_body(vulnerability, triage_result)
        labels = [
            "security",
            f"severity:{vulnerability.severity.value}",
            f"triage:{triage_result.decision.value}",
        ]

        if self.mode == "mock":
            self._mock_issue_counter += 1
            issue = GitHubIssue(
                number=self._mock_issue_counter,
                url=f"https://github.com/{repo}/issues/{self._mock_issue_counter}",
                title=title,
                body=body,
            )
            self._mock_issues.append(issue)
            log.info("mock: created issue #%d on %s", issue.number, repo)
            return issue

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            resp = await http.post(
                f"https://api.github.com/repos/{repo}/issues",
                headers=self._headers(),
                json={"title": title, "body": body, "labels": labels},
            )
            resp.raise_for_status()
            data = resp.json()
            return GitHubIssue(
                number=data["number"],
                url=data["html_url"],
                title=title,
                body=body,
            )

    # ------------------------------------------------------------------- PRs

    async def get_pr_by_url(self, pr_url: str) -> Optional[GitHubPR]:
        """Used by the poller to check if a Devin-opened PR has merged."""
        # Parse owner/repo/number out of the URL
        # e.g. https://github.com/owner/repo/pull/123
        if self.mode == "mock":
            # In mock mode, pretend a random subset of PRs have merged
            import random
            merged = random.random() < 0.3
            return GitHubPR(
                number=int(pr_url.rsplit("/", 1)[-1]),
                url=pr_url,
                state="closed" if merged else "open",
                merged=merged,
            )

        try:
            parts = pr_url.replace("https://github.com/", "").split("/")
            owner, repo, _, number = parts[0], parts[1], parts[2], int(parts[3])
        except (ValueError, IndexError):
            log.warning("could not parse PR url %r", pr_url)
            return None

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            resp = await http.get(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}",
                headers=self._headers(),
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            return GitHubPR(
                number=data["number"],
                url=data["html_url"],
                state=data["state"],
                merged=bool(data.get("merged")),
                head_sha=data.get("head", {}).get("sha"),
            )

    # --------------------------------------------------------------- helpers

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _format_issue_body(self, v, triage_result) -> str:
        patch_line = (
            f"- Fixed in: `{v.fixed_version}`"
            if v.fixed_version
            else "- **No patched version available**"
        )
        advisory_line = (
            f"- Advisory: {v.advisory_url}" if v.advisory_url else ""
        )
        return f"""## Security Advisory

- CVE / Advisory ID: `{v.cve_id}`
- Package: `{v.package}` ({v.ecosystem})
- Severity: **{v.severity.value}**
- Manifest: `{v.manifest_path}`
- Current version: `{v.current_version or 'unknown'}`
- Affected range: `{v.affected_range}`
{patch_line}
{advisory_line}

### Summary

{v.summary}

### Triage

**Routed to:** `{triage_result.decision.value}`

{triage_result.reason}

---

<sub>Filed automatically by [Sentry](https://github.com/your-org/sentry) — \
an event-driven vulnerability remediation system. If this was routed to \
Devin, a session will update this issue with a PR link shortly.</sub>
"""
