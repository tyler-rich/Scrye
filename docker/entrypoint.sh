#!/bin/sh
# Scrye container entrypoint: apply database migrations, then start the server.
set -eu

cd /app/backend

# Bring the SQLite schema up to head before serving traffic.
echo "Scrye: applying database migrations..."
alembic upgrade head

echo "Scrye: starting API server..."
# --proxy-headers makes uvicorn honor X-Forwarded-For/Proto from the fronting
# reverse proxy, so request.client.host is the real client IP — the auth rate
# limiter buckets per client instead of collapsing every user onto the proxy's
# address, and the audit log records the true source. This is proxy-agnostic:
# it works behind any proxy that sets X-Forwarded-For (Caddy, nginx, Traefik...).
#
# --forwarded-allow-ips is the trust boundary and is REQUIRED per deployment:
# uvicorn only honors X-Forwarded-* when the connecting peer is in this list,
# then takes the first UNTRUSTED address as the client. It must NOT be "*":
# trusting every hop lets a client prepend a forged X-Forwarded-For that the
# proxy then appends the real IP behind — uvicorn would treat the forged value as
# the client, letting an attacker rotate fake IPs to bypass the auth rate limiter
# and forge audit-log source IPs. The default (172.16.0.0/12) only fits Caddy on
# the default Docker bridge; SET SCRYE_FORWARDED_ALLOW_IPS to your proxy's real
# source — e.g. 127.0.0.1 for a host-networked nginx, or the proxy's own Docker
# subnet for Traefik. If it does not match the peer the app FAILS SAFE (X-Fwd-For
# is ignored, raw peer IP used — no spoofing, but per-client IPs won't apply). Do
# NOT include the client LAN range, and never set it back to "*". See the README
# "Security model" for topology-specific examples.
exec uvicorn app.main:app \
  --host "${SCRYE_HOST:-0.0.0.0}" \
  --port "${SCRYE_PORT:-8089}" \
  --proxy-headers \
  --forwarded-allow-ips "${SCRYE_FORWARDED_ALLOW_IPS:-172.16.0.0/12}"
