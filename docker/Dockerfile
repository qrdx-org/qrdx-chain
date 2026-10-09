# syntax=docker/dockerfile:1.7
# =============================================================================
# QRDX Node — container image, built REPRODUCIBLY
#
# Anyone can rebuild a release from its tagged source and get the same image: the same image
# config digest, byte for byte (docs/RELEASES.md). Every input is pinned:
#
#   * the base image by digest;
#   * Debian packages through a fixed snapshot.debian.org timestamp;
#   * liboqs by release tag AND commit (checked);
#   * every Python package by version AND sha256 (release/requirements.lock), and the build
#     backends for the few that ship only as source (release/build-requirements.lock);
#   * time: SOURCE_DATE_EPOCH (the release commit's time) drives every timestamp — file times
#     inside wheels and, with BuildKit's rewrite-timestamp, the image layers.
#
# What would otherwise differ between two builds is removed: no bytecode (.pyc) is baked in,
# compiled C is built from fixed paths without debug info, apt/dpkg logs and caches are
# deleted, file modes are normalised, and the user database carries no "password last changed"
# date.
#
# Build with scripts/release/build-image.sh (it sets SOURCE_DATE_EPOCH, the build args and the
# exporter options a reproducible build needs). A plain build still works for development:
#   docker build -f docker/Dockerfile -t qrdx-node:local .          # context = repo root
#
# Stages: base (pinned apt) → liboqs (PQ crypto C library) → wheels (Python dependencies) →
#         app (application files, normalised) → runtime (no compilers).
# =============================================================================

# python:3.11.17-slim-bookworm (multi-arch index digest).
ARG BASE_IMAGE=python:3.11.17-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89
# Debian archive state every apt-get in this file installs from. Must be no older than the base
# image (it was built 2026-10-06): an older snapshot lacks the versions the image already has,
# and apt refuses. Bump the two together.
ARG DEBIAN_SNAPSHOT=20261008T000000Z
# liboqs C library: the post-quantum implementation every node signs and verifies with.
ARG LIBOQS_VERSION=0.15.0
ARG LIBOQS_COMMIT=97f6b86b1b6d109cfd43cf276ae39c2e776aed80
# Reproducibility clock (the release commit's time); 0 for an unpinned development build.
ARG SOURCE_DATE_EPOCH=0
# Release identity, recorded in labels and reported by the node.
ARG QRDX_VERSION=dev
ARG QRDX_GIT_COMMIT=unknown

# -----------------------------------------------------------------------------
# base — the pinned base image with apt pointed at a fixed Debian snapshot
# -----------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS base
ARG DEBIAN_SNAPSHOT
RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" \
      'Suites: bookworm bookworm-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}" \
      'Suites: bookworm-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      'Acquire::Check-Valid-Until "false";' \
      'Acquire::Retries "5";' \
      'APT::Install-Recommends "false";' \
      > /etc/apt/apt.conf.d/10-reproducible; \
    printf '%s\n' '#!/bin/sh' \
      '# Remove what apt/dpkg/ldconfig write that differs between two otherwise identical builds.' \
      'rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb \' \
      '       /var/log/apt /var/log/dpkg.log /var/log/alternatives.log \' \
      '       /var/cache/ldconfig/aux-cache /var/cache/debconf/*-old /var/lib/dpkg/*-old' \
      > /usr/local/sbin/apt-clean-reproducible; \
    chmod 0755 /usr/local/sbin/apt-clean-reproducible

# -----------------------------------------------------------------------------
# liboqs — the post-quantum crypto C library, from a verified commit
# -----------------------------------------------------------------------------
FROM base AS liboqs
ARG LIBOQS_VERSION
ARG LIBOQS_COMMIT
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
RUN apt-get update && apt-get install -y \
        build-essential cmake ninja-build git libssl-dev ca-certificates \
    && apt-clean-reproducible
RUN set -eux; \
    git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs /src/liboqs; \
    test "$(git -C /src/liboqs rev-parse HEAD)" = "${LIBOQS_COMMIT}" \
      || { echo "liboqs ${LIBOQS_VERSION} is not commit ${LIBOQS_COMMIT}" >&2; exit 1; }; \
    cmake -S /src/liboqs -B /src/liboqs/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        -DCMAKE_C_FLAGS="-ffile-prefix-map=/src/liboqs=. -g0"; \
    ninja -C /src/liboqs/build install

# -----------------------------------------------------------------------------
# wheels — every Python dependency, hash-verified; source-only ones built deterministically
# -----------------------------------------------------------------------------
FROM base AS wheels
ARG SOURCE_DATE_EPOCH
# SOURCE_DATE_EPOCH fixes the file times inside built wheels; -g0 keeps build paths out of
# compiled extensions; a fixed hash seed keeps setup.py iteration order stable.
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    CFLAGS="-g0 -O2" \
    LDFLAGS="-Wl,--build-id=sha1"
RUN apt-get update && apt-get install -y build-essential libgmp-dev \
    && apt-clean-reproducible

WORKDIR /build
COPY release/requirements.lock release/build-requirements.lock ./
# Build backends, pinned — never whatever is newest at build time.
RUN pip install --no-compile --require-hashes --no-deps -r build-requirements.lock
# Every dependency, each checked against its locked sha256: wheels where the project publishes
# them for this platform, otherwise the source distribution.
RUN pip download --require-hashes --no-deps -r requirements.lock -d /dl
# Wheels are used as downloaded. Source distributions are unpacked at fixed paths and built in
# place, so nothing random (a temporary directory name) reaches the compiled output.
RUN set -eux; mkdir -p /wheels /build/src; \
    cp /dl/*.whl /wheels/; \
    for sdist in /dl/*.tar.gz; do \
      [ -e "$sdist" ] || continue; \
      name="$(basename "$sdist" .tar.gz)"; \
      tar -xzf "$sdist" -C /build/src; \
      pip wheel --no-deps --no-build-isolation --wheel-dir /wheels "/build/src/${name}"; \
    done
# The QRDX EVM fork (package qrdx-evm, import name `eth`), from the py-evm submodule.
COPY py-evm /build/py-evm
RUN pip wheel --no-deps --no-build-isolation --wheel-dir /wheels /build/py-evm

# -----------------------------------------------------------------------------
# app — the application files, normalised: a checkout's file modes follow its umask and its
# file times depend on when and how it was updated, so neither may reach the image. Every file
# gets the release time (BuildKit's rewrite-timestamp only lowers times NEWER than it; an older
# checkout file would keep its own).
# -----------------------------------------------------------------------------
FROM base AS app
ARG SOURCE_DATE_EPOCH
COPY qrdx /app/qrdx
COPY run_node.py /app/
COPY docker/docker-entrypoint.sh docker/docker-healthcheck.py docker/testnet-init.py \
     docker/validator-init.py docker/genesis-init.py /app/docker/
RUN set -eux; \
    find /app -type d -exec chmod 0755 {} +; \
    find /app -type f -exec chmod 0644 {} +; \
    chmod 0755 /app/docker/docker-entrypoint.sh /app/docker/docker-healthcheck.py \
        /app/docker/testnet-init.py /app/docker/validator-init.py /app/docker/genesis-init.py; \
    find /app -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# -----------------------------------------------------------------------------
# runtime — no compilers: the wheels, liboqs.so and the application
# -----------------------------------------------------------------------------
FROM base AS runtime
ARG QRDX_VERSION
ARG QRDX_GIT_COMMIT
ARG LIBOQS_VERSION

# OQS_INSTALL_PATH tells liboqs-python where the shared object lives, so it never falls back to
# building liboqs at import time. PYTHONWARNINGS=ignore silences the liboqs / liboqs-python
# version-skew notice (the wrapper and the C library release on independent cadences).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    OQS_INSTALL_PATH=/usr/local \
    PYTHONWARNINGS=ignore \
    QRDX_BUILD_VERSION=${QRDX_VERSION} \
    QRDX_BUILD_COMMIT=${QRDX_GIT_COMMIT}

# Runtime shared libraries only.
#   libgmp10        : fastecdsa (P256 legacy curve)
#   libssl3         : liboqs
#   openssh-client  : optional Pinggy reverse tunnel (ENABLE_PINGGY_TUNNEL)
#   curl            : convenience for operators debugging the node from inside
RUN apt-get update && apt-get install -y libgmp10 libssl3 openssh-client curl ca-certificates \
    && apt-clean-reproducible

COPY --from=liboqs /opt/liboqs/lib/ /usr/local/lib/
COPY --from=liboqs /opt/liboqs/include/oqs /usr/local/include/oqs
RUN ldconfig && apt-clean-reproducible

# Install from the wheels stage without copying them into a layer. --no-compile: bytecode
# would embed build-time state; Python compiles in memory at import instead.
RUN --mount=type=bind,from=wheels,source=/wheels,target=/wheels \
    pip install --no-compile --no-index --no-deps /wheels/*.whl

WORKDIR /app
# Owned by the runtime user (created below with this uid/gid) in the same layer that adds it.
COPY --from=app --chown=1000:1000 /app /app

# Fail the BUILD (not production) if the post-quantum stack is not usable: ML-DSA-65 must be
# present and importing oqs must not trigger a source build.
RUN python -c "\
import oqs;\
mechs = oqs.get_enabled_sig_mechanisms();\
assert 'ML-DSA-65' in mechs, 'ML-DSA-65 missing from liboqs build';\
print('liboqs', oqs.oqs_version(), '| liboqs-python', oqs.oqs_python_version(), '| ML-DSA-65 OK')" \
    && python -c "from eth.vm.forks.qrdx import QRDXVM; print('py-evm QRDXVM OK')" \
    && python -c "import qrdx.constants; print('qrdx package OK')"

# Non-root runtime user. UID/GID 1000 matches the default `user:` in the compose files so
# bind-mounted data directories stay writable. /testnet exists in the image so that a named
# volume mounted there inherits the qrdx ownership (a volume whose mount point is absent from
# the image is created root-owned). useradd records today's date as the password's last change;
# that field is blanked so the image does not depend on the day it was built.
RUN groupadd --gid 1000 qrdx \
    && useradd --uid 1000 --gid 1000 --no-create-home --no-log-init --shell /usr/sbin/nologin qrdx \
    && sed -i -E 's/^(qrdx:[^:]*:)[0-9]*:/\1:/' /etc/shadow \
    && rm -f /etc/passwd- /etc/group- /etc/shadow- /etc/gshadow- \
    && mkdir -p /app/data /shared/node-registry /testnet \
    && chown qrdx:qrdx /app /app/data /shared /shared/node-registry /testnet
USER qrdx

LABEL org.opencontainers.image.title="qrdx-node" \
      org.opencontainers.image.source="https://github.com/qrdx-org/qrdx-chain" \
      org.opencontainers.image.version="${QRDX_VERSION}" \
      org.opencontainers.image.revision="${QRDX_GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      org.qrdx.liboqs.version="${LIBOQS_VERSION}"

# Default node port (QRDX_NODE_PORT). The HTTP API, JSON-RPC (/rpc), Prometheus metrics
# (/metrics), health probes (/healthz, /readyz) and the optional WebSocket/SSE stream
# (/ws, /stream) are ALL served on this one port.
EXPOSE 3007

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
    CMD ["python", "/app/docker/docker-healthcheck.py"]

ENTRYPOINT ["/app/docker/docker-entrypoint.sh"]
