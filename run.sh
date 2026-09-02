#!/bin/bash
# Startup script for CUSTODY CHAIN SIH Prototype
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install fastapi uvicorn pydantic
else
    source .venv/bin/activate
fi

echo "Starting Custody Chain Server on http://localhost:8000..."
exec uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
