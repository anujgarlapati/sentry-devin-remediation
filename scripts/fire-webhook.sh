#!/usr/bin/env bash
# Fire a simulated Dependabot vulnerability alert at the local Sentry webhook.
# Usage: ./scripts/fire-webhook.sh [fixture.json]
set -euo pipefail

FIXTURE="${1:-fixtures/dependabot-alert-example.json}"
URL="${SENTRY_URL:-http://localhost:8000}/webhooks/github"

if [ ! -f "$FIXTURE" ]; then
  echo "fixture not found: $FIXTURE" >&2
  exit 1
fi

echo "firing $FIXTURE → $URL"
curl -sS \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: repository_vulnerability_alert" \
  -H "X-GitHub-Delivery: $(uuidgen 2>/dev/null || echo "manual-$(date +%s)")" \
  -X POST \
  --data @"$FIXTURE" \
  "$URL" | python3 -m json.tool
