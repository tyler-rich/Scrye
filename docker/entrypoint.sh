#!/bin/sh
# Scrye container entrypoint: apply database migrations, then start the server.
set -eu

cd /app/backend

# Bring the SQLite schema up to head before serving traffic.
echo "Scrye: applying database migrations..."
alembic upgrade head

echo "Scrye: starting API server..."
# --proxy-headers makes uvicorn honor X-Forwarded-For/Proto from the fronting
# reverse proxy (Caddy), so request.client.host is the real client IP — the auth
# rate limiter buckets per client instead of collapsing every user onto the
# proxy's address, and the audit log records the true source. This is only safe
# because the app is never exposed directly (loopback-published, behind Caddy);
# --forwarded-allow-ips defaults to trusting the proxy, overridable if the trust
# boundary differs.
exec uvicorn app.main:app \
  --host "${SCRYE_HOST:-0.0.0.0}" \
  --port "${SCRYE_PORT:-8089}" \
  --proxy-headers \
  --forwarded-allow-ips "${SCRYE_FORWARDED_ALLOW_IPS:-*}"
