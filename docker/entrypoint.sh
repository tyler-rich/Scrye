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
# proxy's address, and the audit log records the true source.
#
# --forwarded-allow-ips is the trust boundary: uvicorn only honors X-Forwarded-*
# from hops in this list and takes the first UNTRUSTED address as the client.
# It must NOT be "*": trusting every hop lets a client prepend a forged
# X-Forwarded-For that Caddy then appends the real IP behind — uvicorn would
# treat the forged value as the client, letting an attacker rotate fake IPs to
# bypass the auth rate limiter and forge audit-log source IPs. Default instead
# to the private Docker bridge range Caddy connects from (172.16.0.0/12, which
# uvicorn>=0.30 accepts as CIDR). Override SCRYE_FORWARDED_ALLOW_IPS for other
# topologies — set it to the reverse proxy's exact container IP/CIDR (or the
# specific Docker network subnet Caddy sits on). Do NOT include the client LAN
# range, or clients could again spoof their address. Never set it back to "*".
exec uvicorn app.main:app \
  --host "${SCRYE_HOST:-0.0.0.0}" \
  --port "${SCRYE_PORT:-8089}" \
  --proxy-headers \
  --forwarded-allow-ips "${SCRYE_FORWARDED_ALLOW_IPS:-172.16.0.0/12}"
