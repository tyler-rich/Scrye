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

# Install deps from the lockfile first for better layer caching.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# --- Stage 2: download + checksum-verify the scanner binaries ----------------
FROM debian:bookworm-slim@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS scanners
ARG TARGETARCH
# Pinned, current scanner versions (CLAUDE.md § Dependency hygiene).
ARG TRIVY_VERSION=0.71.2
ARG GRYPE_VERSION=0.115.0
ARG SYFT_VERSION=1.46.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scanners
# Each binary: download the asset + the publisher's checksums file, verify with
# `sha256sum -c`, then extract. A checksum mismatch fails the build.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH="Linux-64bit"; ANCHORE_ARCH="linux_amd64" ;; \
      arm64) TRIVY_ARCH="Linux-ARM64"; ANCHORE_ARCH="linux_arm64" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    \
    TRIVY_TGZ="trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz"; \
    curl -fsSL -O "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_TGZ}"; \
    curl -fsSL -O "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " ${TRIVY_TGZ}\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "${TRIVY_TGZ}" trivy; \
    \
    GRYPE_TGZ="grype_${GRYPE_VERSION}_${ANCHORE_ARCH}.tar.gz"; \
    curl -fsSL -O "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${GRYPE_TGZ}"; \
    curl -fsSL -O "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_checksums.txt"; \
    grep " ${GRYPE_TGZ}\$" "grype_${GRYPE_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "${GRYPE_TGZ}" grype; \
    \
    SYFT_TGZ="syft_${SYFT_VERSION}_${ANCHORE_ARCH}.tar.gz"; \
    curl -fsSL -O "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${SYFT_TGZ}"; \
    curl -fsSL -O "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt"; \
    grep " ${SYFT_TGZ}\$" "syft_${SYFT_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "${SYFT_TGZ}" syft; \
    \
    chmod 0755 trivy grype syft


# --- Stage 3: build the Python virtualenv ------------------------------------
FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS backend-builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build/backend

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Install the application and its pinned runtime dependencies into the venv.
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install .


# --- Final stage: minimal runtime image --------------------------------------
FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS runtime

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
RUN chmod 0755 /app/entrypoint.sh

WORKDIR /app/backend
USER 1000:1000

EXPOSE 8089
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fsS "http://localhost:8089/healthz" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
