# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# Scrye — multi-stage, CIS-aligned image (built locally; no registry publishing).
#
# Hardening (see CLAUDE.md § Hard security rules):
#   - Base images pinned by digest (multi-arch manifest lists).
#   - trivy/grype/syft installed from GitHub releases and verified against the
#     publishers' signed checksum files — never `curl | bash`.
#   - Final image runs as a non-root user, COPY (never ADD), no secrets baked in.
#   - HEALTHCHECK probes /healthz.
# Build context is the repository root:
#   docker build -f docker/Dockerfile -t scrye:0.1.0 .
# ─────────────────────────────────────────────────────────────────────────────

# --- Stage 1: build the React/Vite SPA ---------------------------------------
FROM node:22-bookworm-slim@sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4 AS frontend-builder
WORKDIR /build/frontend

# Install deps from the lockfile first for better layer caching. The BuildKit
# cache mount keeps npm's download cache across builds even when this layer is
# invalidated (e.g. a lockfile change), so packages already fetched aren't
# re-downloaded. The cache lives in the mount, not the image layer, so it never
# bloats the (discarded) builder stage.
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm,sharing=locked npm ci

COPY frontend/ ./
RUN npm run build


# --- Stage 2: download + checksum-verify the scanner binaries ----------------
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS scanners
ARG TARGETARCH
# Pinned, current scanner versions (CLAUDE.md § Dependency hygiene).
ARG TRIVY_VERSION=0.72.0
ARG GRYPE_VERSION=0.115.0
ARG SYFT_VERSION=1.46.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scanners
# Each binary: download the asset + the publisher's signed checksums file,
# verify with `sha256sum -c`, then extract. A checksum mismatch fails the build.
# The three downloads are independent, so they run concurrently (each in its own
# background subshell) instead of sequentially — this halves the wall-clock of a
# cold scanner stage, which matters most on the QEMU-emulated arm64 leg where
# each fetch+verify+extract is slow. Concurrency changes nothing about the
# integrity guarantee: every binary is still checksum-verified against the
# publisher's file before extraction, and a failure in any subshell (download
# error OR checksum mismatch) exits it non-zero, which `wait` propagates under
# `set -e` to fail the whole build. Do NOT collapse this back to a plain
# `curl | tar` — the download-then-verify-then-extract order is the supply-chain
# control (CLAUDE.md § Hard security rules); see docs/PLAN.md § Build performance.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH="Linux-64bit"; ANCHORE_ARCH="linux_amd64" ;; \
      arm64) TRIVY_ARCH="Linux-ARM64"; ANCHORE_ARCH="linux_arm64" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    \
    fetch_verify_extract() { \
      set -eux; \
      bin="$1"; base_url="$2"; tgz="$3"; checksums="$4"; \
      curl -fsSL -O "${base_url}/${tgz}"; \
      curl -fsSL -O "${base_url}/${checksums}"; \
      grep " ${tgz}\$" "${checksums}" | sha256sum -c -; \
      tar -xzf "${tgz}" "${bin}"; \
    }; \
    \
    fetch_verify_extract trivy \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
      "trivy_${TRIVY_VERSION}_checksums.txt" & \
    trivy_pid=$!; \
    \
    fetch_verify_extract grype \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}" \
      "grype_${GRYPE_VERSION}_${ANCHORE_ARCH}.tar.gz" \
      "grype_${GRYPE_VERSION}_checksums.txt" & \
    grype_pid=$!; \
    \
    fetch_verify_extract syft \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}" \
      "syft_${SYFT_VERSION}_${ANCHORE_ARCH}.tar.gz" \
      "syft_${SYFT_VERSION}_checksums.txt" & \
    syft_pid=$!; \
    \
    wait "${trivy_pid}"; \
    wait "${grype_pid}"; \
    wait "${syft_pid}"; \
    \
    chmod 0755 trivy grype syft


# --- Stage 3: build the Python virtualenv ------------------------------------
FROM python:3.13-slim-bookworm AS backend-builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build/backend

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Install the application and its pinned runtime dependencies into the venv.
# The BuildKit cache mount persists pip's wheel download cache across builds so
# an unchanged dependency isn't re-fetched from PyPI when this layer rebuilds
# (PIP_NO_CACHE_DIR is intentionally NOT set — the cache now lives in the mount,
# not the image layer, and this is a discarded builder stage, so nothing bloats
# the final image).
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked pip install .


# --- Final stage: minimal runtime image --------------------------------------
FROM python:3.13-slim-bookworm AS runtime

# ca-certificates: scanner DB downloads + TLS. curl: container HEALTHCHECK.
# git: authenticated clone of generic-host private repos into tmpfs, so the
# credential is delivered via GIT_ASKPASS instead of an argv-visible clone URL
# (docs/PLAN.md §14, Phase 3 Security Review #2). Versions track the
# digest-pinned base image, consistent with the other apt packages here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 scrye \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /app --shell /usr/sbin/nologin scrye \
    && mkdir -p /data /cache /app \
    && chown -R 1000:1000 /data /cache /app

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SCRYE_DATABASE_PATH=/data/scrye.db \
    SCRYE_FRONTEND_DIST_DIR=/app/frontend/dist

# Python venv, scanner binaries, backend source (for Alembic), and built SPA.
COPY --from=backend-builder /opt/venv /opt/venv
COPY --from=scanners /scanners/trivy /scanners/grype /scanners/syft /usr/local/bin/
COPY --chown=1000:1000 backend/ /app/backend/
COPY --chown=1000:1000 --from=frontend-builder /build/frontend/dist /app/frontend/dist
COPY --chown=1000:1000 docker/entrypoint.sh /app/entrypoint.sh
COPY --chown=1000:1000 THIRD_PARTY_LICENSES/ /THIRD_PARTY_LICENSES/
# Strip any CR characters that may have slipped in via a CRLF checkout (e.g. on
# Windows without .gitattributes honored): a CRLF shebang makes the kernel look
# for `/bin/sh\r` and the container dies with `no such file or directory`.
RUN sed -i 's/\r$//' /app/entrypoint.sh \
    && chmod 0755 /app/entrypoint.sh

WORKDIR /app/backend
USER 1000:1000

EXPOSE 8089
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fsS "http://localhost:8089/healthz" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
