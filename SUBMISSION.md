# Cognition Take-Home Submission — Anuj Garlapati

## Links
- **Code:** https://github.com/anujgarlapati/sentry-devin-remediation
- **Superset fork:** https://github.com/anujgarlapati/superset
- **PR opened by Devin:** https://github.com/anujgarlapati/superset/pull/13
- **Issues closed by Devin:** https://github.com/anujgarlapati/superset/issues?q=is%3Aissue+is%3Aclosed

## What happened

I built Sentry, dispatched three real Devin sessions against my Apache Superset fork, and captured three distinct outcomes that together show the full spectrum of what the system handles.

| Case | CVE | Target | Outcome | What it demonstrates |
|---|---|---|---|---|
| **A** | CVE-2023-46136 (werkzeug) | `demo-vulnerable-werkzeug` branch (werkzeug pinned to vulnerable 2.0.2) | **PR opened** at https://github.com/anujgarlapati/superset/pull/13. Devin bumped werkzeug to patched version, updated affected call sites, tests pass. | Devin executes autonomous remediation when there's real work to do. |
| **B** | CVE-2023-47248 (pyarrow) | `master` | Completed without PR. pyarrow already at 16.1.0 on master (> 14.0.1 fix). [Issue](https://github.com/anujgarlapati/superset/issues/11) with Devin verification output. | Devin doesn't open noise PRs when the fix is already present. |
| **C** | CVE-2024-4340 (sqlparse) | `master` | Not applicable. Devin discovered sqlparse isn't a dependency of this repo — Superset explicitly bans sqlparse imports via a pylint rule enforcing the v6 migration to sqlglot + sqloxide. Advisory data was stale (0.5.0 is patched). [Issue closed](https://github.com/anujgarlapati/superset/issues/12) with full reasoning. | Devin catches bad inputs by reading the code, not just reacting to alerts. |

## The point

A rule-based remediation bot (Dependabot, Renovate) would have opened three PRs on my fork: one on the vulnerable branch, one redundant update on master, one fabricated against a non-existent dependency.

Sentry + Devin opened one PR where it was warranted and escalated twice with written, code-level evidence. One reviewer cycle spent on real work, two cycles saved from noise. That's the deployable property: the failure mode is "escalation with reasoning," not "confident wrong answer."

## Run it yourself

See [README.md](README.md). `docker compose up --build`. Dashboard at localhost:8000.

- **Mock mode** (default): `docker compose exec app python -m app.cli scan` populates the dashboard with fixtures + simulated Devin sessions. Full end-to-end flow with realistic timing.
- **Live mode**: set `DEVIN_MODE=live`, `DEVIN_API_KEY`, `GITHUB_TOKEN` in `.env`, then `docker compose exec app python -m app.cli remediate --cve <CVE-ID> [--branch <branch>]`.

## Preview routing without spending ACUs

`POST /api/triage/preview` returns what Sentry WOULD do for a given CVE (routing decision, reasoning, full Devin prompt) without dispatching. Lets customers audit routing policy before production rollout.

```bash
curl -X POST http://localhost:8000/api/triage/preview \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-X","package":"foo","severity":"high","current_version":"1.0","fixed_version":"2.0","manifest_path":"requirements.txt"}'
```

## Screenshots

See `submission-screenshots/` for the full evidence trail — Devin session outputs, Sentry dashboard states, PR diff, and closed issues.
