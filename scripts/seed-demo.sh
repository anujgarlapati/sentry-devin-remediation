#!/usr/bin/env bash
# One-shot demo seeder. Run this after `docker compose up` to populate the
# dashboard with the fixture vulnerabilities.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

echo "→ running fixture scan"
docker compose exec -T app python -m app.cli scan

echo "→ firing Dependabot webhook"
./scripts/fire-webhook.sh fixtures/dependabot-alert-example.json

echo ""
echo "dashboard: http://localhost:8000"
