#!/usr/bin/env bash
# Production entrypoint for Render (and similar PaaS).
set -euo pipefail

cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-.}"

# Seed / migrate on boot (idempotent — skips if cases already exist).
python -c "from backend.database import init_db; init_db()"

PORT="${PORT:-8000}"
exec uvicorn backend.app:app --host 0.0.0.0 --port "${PORT}"
