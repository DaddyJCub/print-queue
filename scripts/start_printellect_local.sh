#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export DB_PATH="${DB_PATH:-$ROOT_DIR/local_data/app.db}"
export UPLOAD_DIR="${UPLOAD_DIR:-$ROOT_DIR/local_data/uploads}"
export BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
export DEMO_MODE="${DEMO_MODE:-1}"

mkdir -p "$UPLOAD_DIR"

echo "Starting Printellect local server"
echo "DB_PATH=$DB_PATH"
echo "UPLOAD_DIR=$UPLOAD_DIR"
echo "BASE_URL=$BASE_URL"
echo "ADMIN_PASSWORD=$ADMIN_PASSWORD"

exec uvicorn app.main:app --host 0.0.0.0 --port 3000
