#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <email> [base_url] [admin_password]"
  exit 1
fi

EMAIL="$1"
BASE_URL="${2:-http://127.0.0.1:3000}"
ADMIN_PASSWORD="${3:-admin}"
FLAG_KEY="${PRINTELLECT_FEATURE_KEY:-printellect_device_control}"

echo "Enabling feature flag: $FLAG_KEY"
curl -sS -X POST "$BASE_URL/admin/features/$FLAG_KEY/toggle" \
  -H "Content-Type: application/json" \
  -b "admin_pw=$ADMIN_PASSWORD" \
  -d '{"enabled":true}' >/dev/null

echo "Assigning feature access to: $EMAIL"
curl -sS -X POST "$BASE_URL/admin/features/$FLAG_KEY/allowed-emails" \
  -H "Content-Type: application/json" \
  -b "admin_pw=$ADMIN_PASSWORD" \
  -d "{\"action\":\"add\",\"email\":\"$EMAIL\"}"

echo
echo "Done. $EMAIL can access Printellect user routes."
