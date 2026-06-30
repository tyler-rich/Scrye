#!/bin/sh
# Scrye container entrypoint: apply database migrations, then start the server.
set -eu

cd /app/backend

# Bring the SQLite schema up to head before serving traffic.
echo "Scrye: applying database migrations..."
alembic upgrade head

echo "Scrye: starting API server..."
exec uvicorn app.main:app \
  --host "${SCRYE_HOST:-0.0.0.0}" \
  --port "${SCRYE_PORT:-8089}"
