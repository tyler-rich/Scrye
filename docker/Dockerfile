# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
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
FROM node:22-bookworm-slim@sha256:53ada149d435c38b14476cb57e4a7da73c15595aba79bd6971b547ceb6d018bf AS frontend-builder
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

# cosign, pinned by digest from the official ko-built Sigstore image (SC-8). Used
# below to verify the upstream projects' cosign signature over each checksums.txt
# before the sha256sum check — upgrading the guarantee from "matches what GitHub
# serves" (a same-origin checksum an attacker who replaced the tarball could
# regenerate) to "signed by the upstream project's own GitHub Actions release
# pipeline" (keyless Fulcio identity + Rekor transparency-log inclusion).
COPY --from=ghcr.io/sigstore/cosign/cosign:v2.6.1@sha256:68839b7f13dac5a6744a5d8818e984dd39183374e37855c19e14d623d9bc9037 \
    /ko-app/cosign /usr/local/bin/cosign

WORKDIR /scanners
# Each binary: download the asset + the publisher's signed checksums file, verify
# the publisher's cosign signature over the checksums file (keyless, identity
# pinned to the upstream repo's release workflow + the GitHub Actions OIDC
# issuer), then verify the tarball with `sha256sum -c`, then extract. A signature
# OR checksum mismatch fails the build. The two publishers sign differently, so
# fetch_verify_extract takes a style: Anchore (grype/syft) ships a detached
# certificate (.pem) + signature (.sig), while Aqua (trivy) ships a Sigstore
# protobuf bundle (checksums.txt.sigstore.json) verified with `--bundle
# --new-bundle-format`.
# The three downloads are independent, so they run concurrently (each in its own
# background subshell) instead of sequentially — this halves the wall-clock of a
# cold scanner stage, which matters most on the QEMU-emulated arm64 leg where
# each fetch+verify+extract is slow. Concurrency changes nothing about the
# integrity guarantee: every binary is still cosign- AND checksum-verified before
# extraction, and a failure in any subshell (download error, bad signature, OR
# checksum mismatch) exits it non-zero, which `wait` propagates under `set -e` to
# fail the whole build. Do NOT collapse this back to a plain `curl | tar` — the
# download-then-verify-then-extract order is the supply-chain control (CLAUDE.md
# § Hard security rules); see docs/ARCHIVE.md § Build performance.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH="Linux-64bit"; ANCHORE_ARCH="linux_amd64" ;; \
      arm64) TRIVY_ARCH="Linux-ARM64"; ANCHORE_ARCH="linux_arm64" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    \
    fetch_verify_extract() { \
      set -eux; \
      bin="$1"; base_url="$2"; tgz="$3"; checksums="$4"; identity="$5"; sig_style="$6"; \
      curl -fsSL -O "${base_url}/${tgz}"; \
      curl -fsSL -O "${base_url}/${checksums}"; \
      if [ "${sig_style}" = "bundle" ]; then \
        curl -fsSL -O "${base_url}/${checksums}.sigstore.json"; \
        cosign verify-blob \
          --bundle "${checksums}.sigstore.json" \
          --new-bundle-format \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
          --certificate-identity-regexp "${identity}" \
          "${checksums}"; \
      else \
        curl -fsSL -O "${base_url}/${checksums}.sig"; \
        curl -fsSL -O "${base_url}/${checksums}.pem"; \
        cosign verify-blob \
          --certificate "${checksums}.pem" \
          --signature "${checksums}.sig" \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
          --certificate-identity-regexp "${identity}" \
          "${checksums}"; \
      fi; \
      grep " ${tgz}\$" "${checksums}" | sha256sum -c -; \
      tar -xzf "${tgz}" "${bin}"; \
    }; \
    \
    fetch_verify_extract trivy \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
      "trivy_${TRIVY_VERSION}_checksums.txt" \
      "^https://github\.com/aquasecurity/trivy/\.github/workflows/.+@refs/tags/v[0-9.]+$" \
      bundle & \
    trivy_pid=$!; \
    \
    fetch_verify_extract grype \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}" \
      "grype_${GRYPE_VERSION}_${ANCHORE_ARCH}.tar.gz" \
      "grype_${GRYPE_VERSION}_checksums.txt" \
      "^https://github\.com/anchore/grype/\.github/workflows/.+@refs/tags/v[0-9.]+$" \
      certsig & \
    grype_pid=$!; \
    \
    fetch_verify_extract syft \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}" \
      "syft_${SYFT_VERSION}_${ANCHORE_ARCH}.tar.gz" \
      "syft_${SYFT_VERSION}_checksums.txt" \
      "^https://github\.com/anchore/syft/\.github/workflows/.+@refs/tags/v[0-9.]+$" \
      certsig & \
    syft_pid=$!; \
    \
    wait "${trivy_pid}"; \
    wait "${grype_pid}"; \
    wait "${syft_pid}"; \
    \
    chmod 0755 trivy grype syft


# --- Stage 3: build the Python virtualenv ------------------------------------
FROM python:3.13-slim-bookworm@sha256:fcbd8dfc2605ba7c2eca646846c5e892b2931e41f6227985154a596f26ab8ed7 AS backend-builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build/backend

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Install the pinned, hash-verified runtime dependencies BEFORE copying app
# code, so a code-only change doesn't invalidate this (slow) dependency layer.
# requirements.lock is the fully-resolved transitive closure of pyproject.toml,
# generated with `uv pip compile --generate-hashes` (see CONTRIBUTING.md
# § Backend dependency lock). `--require-hashes` makes pip refuse to install any
# artifact whose hash isn't pinned in the lock, so every transitive package is
# verified at build time and two builds of the same commit resolve identically
# — closing the unpinned-transitive supply-chain gap (SC-1).
# The BuildKit cache mount persists pip's wheel download cache across builds so
# an unchanged dependency isn't re-fetched from PyPI when this layer rebuilds
# (PIP_NO_CACHE_DIR is intentionally NOT set — the cache now lives in the mount,
# not the image layer, and this is a discarded builder stage, so nothing bloats
# the final image).
COPY backend/pyproject.toml backend/requirements.lock ./
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --require-hashes -r requirements.lock

# Install the application package itself. Its runtime dependencies are already
# present (installed and hash-verified from the lock above), so --no-deps keeps
# the resolver from reaching back out to PyPI for an unpinned copy.
COPY backend/app ./app
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked pip install --no-deps .


# --- Final stage: minimal runtime image --------------------------------------
FROM python:3.13-slim-bookworm@sha256:fcbd8dfc2605ba7c2eca646846c5e892b2931e41f6227985154a596f26ab8ed7 AS runtime

# ca-certificates: scanner DB downloads + TLS. curl: container HEALTHCHECK.
# git: authenticated clone of generic-host private repos into tmpfs, so the
# credential is delivered via GIT_ASKPASS instead of an argv-visible clone URL
# (docs/PLAN.md §14, Phase 3 Security Review #2). Versions track the
# digest-pinned base image, consistent with the other apt packages here.
# curl/libcurl3-gnutls/libcurl4 are explicitly pinned to 7.88.1-10+deb12u15,
# the Debian bookworm-security fix for CVE-2026-5773, rather than tracking the
# base image's snapshot (see docs/ARCHIVE.md § Deviations).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
        curl=7.88.1-10+deb12u15 \
        libcurl3-gnutls=7.88.1-10+deb12u15 \
        libcurl4=7.88.1-10+deb12u15 \
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
