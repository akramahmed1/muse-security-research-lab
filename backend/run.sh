#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python -m app.seed
exec uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8000}"
