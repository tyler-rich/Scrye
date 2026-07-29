#!/bin/sh
# Scrye container entrypoint: apply database migrations, then start the server.
set -eu

cd /app/backend

# Preflight: the data directory must be writable by this uid before Alembic
# touches SQLite. Without this, the only symptom is
# `sqlite3.OperationalError: unable to open database file`, which names neither
# the path nor the fix. The usual cause is a bind-mounted host directory whose
# ownership doesn't match the container uid (common on NAS platforms); a named
# volume inherits the right ownership from the image and never hits this.
data_dir="$(dirname "${SCRYE_DATABASE_PATH:-/data/scrye.db}")"
uid="$(id -u)"
gid="$(id -g)"
if [ ! -d "$data_dir" ]; then
  echo "Scrye: FATAL - the data directory $data_dir does not exist." >&2
  echo "Scrye: Mount a volume there (see README 'Where persistent data lives')." >&2
  exit 1
fi
if ! (: >"$data_dir/.scrye-write-probe.$$") 2>/dev/null; then
  echo "Scrye: FATAL - the data directory $data_dir is not writable by uid $uid:$gid." >&2
  echo "Scrye: It holds the SQLite database and, unless you supply a Docker secret," >&2
  echo "Scrye: the generated master key. If it is a bind-mounted host directory, fix" >&2
  echo "Scrye: its ownership on the host:" >&2
  echo "Scrye:     chown -R $uid:$gid <host path>" >&2
  echo "Scrye: or run the container as the directory's owner (Compose 'user:')." >&2
  echo "Scrye: A named Docker volume inherits the correct ownership automatically." >&2
  exit 1
fi
rm -f "$data_dir/.scrye-write-probe.$$"

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
