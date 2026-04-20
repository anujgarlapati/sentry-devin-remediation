"""
Ad-hoc CLI for operating Sentry from the command line.

Usage:
    python -m app.cli scan                     # run a fixture scan
    python -m app.cli remediate --cve CVE-...  # dispatch a single fixture row
    python -m app.cli reset                    # nuke the DB (demo reset)
    python -m app.cli status                   # print a quick summary
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from sqlmodel import Session, SQLModel, select

from app.core.orchestrator import Orchestrator
from app.models.schema import EventLog, Vulnerability


def _orchestrator(db: Session) -> Orchestrator:
    from app.api.main import TARGET_REPO, get_devin, get_github
    return Orchestrator(
        db=db,
        devin=get_devin(),
        github=get_github(),
        target_repo=TARGET_REPO,
    )


async def cmd_scan(args: argparse.Namespace) -> int:
    from app.api.main import engine
    from app.workers.scanner import scan_and_dispatch

    with Session(engine) as db:
        orch = _orchestrator(db)
        result = await scan_and_dispatch(db, orch, fixtures=True)
        print(json.dumps(result, indent=2))
    return 0


async def cmd_remediate(args: argparse.Namespace) -> int:
    """Dispatch a single vulnerability by CVE id (from fixtures)."""
    from app.api.main import engine
    from app.integrations.scanners import parse_pip_audit, parse_osv_scanner

    fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures"
    candidates: list[Vulnerability] = []
    for name, parser in [
        ("pip-audit-sample.json", parse_pip_audit),
        ("osv-scanner-sample.json", parse_osv_scanner),
    ]:
        path = fixtures_dir / name
        if path.exists():
            candidates.extend(parser(json.loads(path.read_text())))

    match = next((v for v in candidates if v.cve_id == args.cve), None)
    if match and args.branch:
        match.target_branch = args.branch
    if not match:
        available = ", ".join(sorted({v.cve_id for v in candidates}))
        print(f"no fixture vuln with id {args.cve}. available: {available}", file=sys.stderr)
        return 1

    with Session(engine) as db:
        existing = db.exec(
            select(Vulnerability).where(
                Vulnerability.cve_id == match.cve_id,
                Vulnerability.package == match.package,
                Vulnerability.manifest_path == match.manifest_path,
            )
        ).first()
        if existing:
            print(f"already tracked as id={existing.id}, status={existing.status.value}")
            return 0
        orch = _orchestrator(db)
        await orch.handle_new_vulnerability(match)
        # refresh and print
        db.refresh(match)
        print(json.dumps({
            "id": match.id,
            "cve": match.cve_id,
            "status": match.status.value,
            "triage": match.triage_decision.value if match.triage_decision else None,
            "session": match.devin_session_id,
            "issue": match.github_issue_url,
        }, indent=2))
    return 0


async def cmd_status(args: argparse.Namespace) -> int:
    from app.api.main import engine
    from app.core.metrics import compute_metrics

    with Session(engine) as db:
        rows = db.exec(select(Vulnerability)).all()
        metrics = compute_metrics(rows)

    print(f"tracked: {metrics['total']}")
    print(f"  running:    {metrics['running']}")
    print(f"  pr_opened:  {metrics['pr_opened']}")
    print(f"  merged:     {metrics['merged']}")
    print(f"  failed:     {metrics['failed']}")
    if metrics["success_rate"]:
        print(f"success rate: {metrics['success_rate']:.1%}")
    if metrics.get("time_to_pr_p50") is not None:
        print(f"time to pr:   p50={metrics['time_to_pr_p50']:.1f}m  p95={metrics['time_to_pr_p95']:.1f}m")
    if metrics.get("cost_per_success_usd") is not None:
        print(f"cost/fix:     ${metrics['cost_per_success_usd']:.2f}")
    return 0


async def cmd_reset(args: argparse.Namespace) -> int:
    from app.api.main import engine

    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    print("database reset.")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Ensure tables exist — the app's lifespan handler does this at server
    # startup, but CLI entries bypass that.
    from app.api.main import engine
    SQLModel.metadata.create_all(engine)

    parser = argparse.ArgumentParser(prog="sentry", description="Sentry operator CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="run a fixture scan and dispatch new findings")

    p_rem = sub.add_parser("remediate", help="dispatch a single vulnerability by CVE id")
    p_rem.add_argument("--cve", required=True, help="e.g. CVE-2023-47248")
    p_rem.add_argument("--branch", default=None, help="target branch override (default: master)")

    sub.add_parser("status", help="print summary metrics")
    sub.add_parser("reset", help="drop and recreate all tables")

    args = parser.parse_args(argv)
    handlers = {
        "scan": cmd_scan,
        "remediate": cmd_remediate,
        "status": cmd_status,
        "reset": cmd_reset,
    }
    return asyncio.run(handlers[args.cmd](args))


if __name__ == "__main__":
    raise SystemExit(main())
