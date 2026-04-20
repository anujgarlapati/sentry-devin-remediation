# Sentry — Event-Driven Vulnerability Remediation with Devin

> Dependabot tells you there's a problem. Sentry makes Devin fix it.

## Take-home submission (start here)

**[SUBMISSION.md](SUBMISSION.md)** — Cognition write-up: links to this repo and the Superset fork, the three Devin cases (A/B/C), PR and issue URLs, and how reviewers can run or verify the system. **Loom:** [5 min walkthrough](https://www.loom.com/share/b54ed28c3e4041438471160971b635dc).

---

## The thesis

Most designs for a system like this route by severity — critical CVEs get escalated, low-severity ones get ignored. I think that's the wrong axis.

The right axis is **reasoning required**, not urgency.

A critical CVE with a one-line patch bump is Dependabot's job. Dependabot does it well and Devin time costs real money.

A low-severity CVE in a package whose maintainer abandoned the repo is Devin's job. There's no patch. There's no rule that fires. A human has to read the code, decide if the vulnerable path is reachable, and either write a workaround, swap the package, or document accepted risk. That's reasoning, not substitution — and reasoning is what Devin uniquely does.

Sentry's triage engine routes on reasoning-required. That's the whole design.

Everything else — the webhook listener, the parallel session orchestration, the cost-savings dashboard, the structured output schema with reachability analysis and rollback plans, the dry-run triage preview endpoint — falls out of that one choice.

## One more thing worth being explicit about

The PRs Sentry opened on my Apache Superset fork were written by Devin, not by me. I didn't touch the remediation code. I built the system that orchestrates Devin, dispatched three real sessions, and let Devin do the engineering work. That's the submission: not "candidate built a Devin integration," but "Devin remediated vulnerabilities in a real open-source codebase via a system I built to orchestrate it."

Session URLs, PR links, and evidence: **[SUBMISSION.md](SUBMISSION.md)**.

---

Built as a take-home for Cognition. Target repo (fork): [`anujgarlapati/superset`](https://github.com/anujgarlapati/superset) (upstream: [`apache/superset`](https://github.com/apache/superset)).

---

## The problem, in one chart

The industry mean-time-to-remediate a known CVE is ~180 days. Not because the fix is hard — because someone has to sit down, read the advisory, open the repo, figure out if the bump is safe, update the lockfile, run the tests, and open a PR. That work is:

- **High volume** — a medium-sized service has 20–60 open advisories at any time
- **Individually small** — usually 30–90 minutes of focused work
- **Embarrassingly parallel** — CVE A and CVE B almost never block each other
- **Boring** — which is why it sits

This is the exact shape of problem Devin is good at. Sentry is the glue.

## What it does

1. **Listens** for vulnerability events from two sources:
   - GitHub Dependabot webhooks (`repository_vulnerability_alert`) — reactive, fires on new advisories
   - Scheduled scanner runs (`pip-audit` / `osv-scanner`) — proactive, catches what Dependabot misses
2. **Triages** each finding through a routing policy:
   - Trivial patch bumps → route to Dependabot (Sentry stays out of the way)
   - Complex fixes (major bumps, no-patch-available, deprecated deps) → route to Devin
   - Skip rules (test-only deps, dev dependencies in prod manifest, known-false-positives)
3. **Dispatches** parallel Devin sessions — one per finding — with a structured prompt containing CVE context, the dependency graph slice, acceptance criteria, and a `structured_output_schema` so Devin reports back machine-readably
4. **Tracks** every session through a state machine (`queued → running → pr_opened → merged | failed`) with the session ID, PR URL, ACUs consumed, and timing attached to the originating GitHub issue
5. **Reports** via a live dashboard showing throughput, success rate, time-to-remediation, and ACU efficiency — the metrics an engineering leader would actually ask about

## Why Devin and not a rule-based bot

Rule-based bots (Dependabot, Renovate) work when the fix is `bump X from 1.2.3 to 1.2.4`. They fail when:

- The CVE has no fix version and you need a workaround or local patch
- The bump is a major version with breaking API changes that need code updates elsewhere
- The vulnerable package is transitive and the direct parent needs to bump too
- The test suite relies on behavior the patched version changed
- There's a compatible alternative package but switching requires a small refactor

A human engineer handles these cases today. Devin handles them autonomously because it can read the code, reason about the blast radius, edit multiple files, run the tests, and iterate on failures. Sentry's job is to identify which findings *require* that reasoning and hand them off with enough context to succeed.

## Architecture

```
┌─────────────────┐   ┌──────────────────┐   ┌─────────────────┐
│ GitHub webhook  │   │ pip-audit (cron) │   │  osv-scanner    │
│ (Dependabot)    │   │                  │   │  (cron)         │
└────────┬────────┘   └────────┬─────────┘   └────────┬────────┘
         │                     │                      │
         └─────────────────────┼──────────────────────┘
                               ▼
                   ┌───────────────────────┐
                   │   Ingestion (FastAPI) │
                   │   - dedupe by CVE+pkg │
                   │   - normalize schema  │
                   └───────────┬───────────┘
                               ▼
                   ┌───────────────────────┐
                   │     Triage engine     │
                   │   Dependabot ◄─ skip  │
                   │     Devin    ◄─ route │
                   │     Ignore   ◄─ skip  │
                   └───────────┬───────────┘
                               ▼
                   ┌───────────────────────┐
                   │   Devin orchestrator  │
                   │  - create session     │
                   │  - poll every 30s     │
                   │  - reconcile PR       │
                   └───────────┬───────────┘
                               ▼
                   ┌───────────────────────┐
                   │  SQLite event store   │──► Dashboard (FastAPI + HTMX)
                   │  Every state change   │    - Live session feed
                   │  is persisted         │    - Throughput / MTTR
                   └───────────────────────┘    - ACU cost per fix
```

**Key design decisions and the tradeoffs:**

| Decision | Why | Tradeoff accepted |
|---|---|---|
| SQLite, not Postgres | Single-process deploy, simpler demo, <1K events/day is fine | Won't scale past one worker; acceptable for V1 |
| Poll, don't webhook back from Devin | Devin v1 doesn't push session status; polling is honest | 30s lag in dashboard; fine for a 30-minute session |
| `structured_output_schema` in every prompt | Gets typed back from Devin vs. scraping text | Devin occasionally doesn't populate it; we fall back to PR URL |
| Dry-run mode by default | Candidates shouldn't burn ACUs on demo | Need an explicit flag to run live |

## Running it

### Quickstart (dry-run, no Devin API key needed)

```bash
git clone https://github.com/anujgarlapati/sentry-devin-remediation.git
cd sentry-devin-remediation
docker compose up --build
# open http://localhost:8000
```

This boots the full stack with a mock Devin client that simulates session lifecycle (queued → running → pr_opened) with realistic timing. The dashboard will show fixture vulnerabilities being remediated in real time.

### Running against the real Devin API

```bash
cp .env.example .env
# edit .env: set DEVIN_API_KEY, GITHUB_TOKEN, TARGET_REPO
# set DEVIN_MODE=live
docker compose up --build
```

Then trigger either path:
```bash
# Path A: simulate a Dependabot webhook
./scripts/fire-webhook.sh fixtures/dependabot-alert-example.json

# Path B: run a scan now (vs waiting for cron)
docker compose exec app python -m app.workers.scanner
```

### One-off: remediate a fixture CVE (live mode)

```bash
docker compose exec app python -m app.cli remediate --cve CVE-2023-46136
# optional: target a branch other than your default (e.g. demo branch)
docker compose exec app python -m app.cli remediate --cve CVE-2023-46136 --branch demo-vulnerable-werkzeug
```

## Observability — what an engineering leader sees

The dashboard answers four questions at a glance:

1. **Is it working?** Session success rate, PRs merged last 7d
2. **Is it fast?** p50/p95 time-to-PR, time-to-merge
3. **Is it efficient?** ACUs consumed per successful fix, $/CVE
4. **What's in flight right now?** Live session list with status, elapsed time, session URL (deep link to Devin UI)

Every state transition is recorded in an append-only event log — you can replay the history of any CVE from detection to merge.

## Repo layout

```
app/
  core/            # domain models, triage logic, prompt templates
  integrations/    # Devin client, GitHub client, scanner adapters
  workers/         # scanner cron, session poller, webhook handler
  api/             # FastAPI routes (webhooks in, dashboard API out)
  ui/              # HTMX dashboard
  models/          # SQLModel schema
tests/             # unit + integration tests
fixtures/          # sample Dependabot alerts, scanner outputs, CVE data
scripts/           # fire-webhook.sh, seed-db.py, etc.
docs/              # architecture decisions, prompt engineering notes
```

## What I'd build next (V2)

- **Learning loop** — feed merged PRs back as Devin knowledge entries so each successful fix makes the next one faster
- **Batching** — group related CVEs (same package family) into one session instead of N
- **Reviewer assist** — when a Devin PR sits unreviewed > 24h, open a Devin session to address reviewer comments
- **Blast-radius analysis** — before dispatching, have a cheap pre-check session estimate effort and fail fast on "this needs a human"
- **Multi-repo fleet** — one Sentry instance watching every repo in an org, with cross-repo dedupe (same CVE across 12 services = one well-researched fix, then N mechanical applications)

## Submission contents

- **This repo**: the Sentry automation layer — [`anujgarlapati/sentry-devin-remediation`](https://github.com/anujgarlapati/sentry-devin-remediation)
- **Superset fork**: [`anujgarlapati/superset`](https://github.com/anujgarlapati/superset) — evidence (sessions, PRs, issues) is summarized in [`SUBMISSION.md`](SUBMISSION.md)
- **Loom (5 min):** [walkthrough](https://www.loom.com/share/b54ed28c3e4041438471160971b635dc) — problem framing, live session, dashboard tour, V2 roadmap
