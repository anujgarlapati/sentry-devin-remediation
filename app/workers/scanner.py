"""
Scanner worker. Either:
  - runs pip-audit/osv-scanner as subprocesses against a checked-out repo, or
  - reads fixture JSON files (for the demo / CI path).

The real implementation in production would clone/pull the target repo and
run the scanner there. For the take-home, we use fixtures by default so the
demo is hermetic and reviewable offline.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from sqlmodel import Session, select

from app.core.orchestrator import Orchestrator
from app.integrations.devin import DevinClient
from app.integrations.github import GitHubClient
from app.integrations.scanners import parse_osv_scanner, parse_pip_audit
from app.models.schema import Vulnerability

log = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


async def scan_and_dispatch(
    db: Session,
    orch: Orchestrator,
    *,
    fixtures: bool = True,
) -> dict:
    """Run a scan pass and dispatch any new findings."""
    vulns: list[Vulnerability] = []

    if fixtures:
        vulns.extend(_load_fixture("pip-audit-sample.json", parse_pip_audit))
        vulns.extend(_load_fixture("osv-scanner-sample.json", parse_osv_scanner))
    else:
        # In live mode, you'd shell out to pip-audit / osv-scanner here.
        raise NotImplementedError(
            "Live scanner mode requires a checked-out target repo; see docs."
        )

    new_count = 0
    for v in vulns:
        # Dedupe against DB
        existing = db.exec(
            select(Vulnerability).where(
                Vulnerability.cve_id == v.cve_id,
                Vulnerability.package == v.package,
                Vulnerability.manifest_path == v.manifest_path,
            )
        ).first()
        if existing:
            continue
        await orch.handle_new_vulnerability(v)
        new_count += 1

    log.info("scan complete: %d total, %d new", len(vulns), new_count)
    return {"total": len(vulns), "new": new_count}


def _load_fixture(name: str, parser) -> list[Vulnerability]:
    path = FIXTURES_DIR / name
    if not path.exists():
        log.warning("fixture %s not found", path)
        return []
    data = json.loads(path.read_text())
    return parser(data)


if __name__ == "__main__":
    # Allow `python -m app.workers.scanner` for one-off runs in docker exec
    from app.api.main import engine, get_devin, get_github, TARGET_REPO

    logging.basicConfig(level=logging.INFO)

    async def _run():
        with Session(engine) as db:
            orch = Orchestrator(
                db=db,
                devin=get_devin(),
                github=get_github(),
                target_repo=TARGET_REPO,
            )
            result = await scan_and_dispatch(db, orch, fixtures=True)
            print(json.dumps(result, indent=2))

    asyncio.run(_run())
