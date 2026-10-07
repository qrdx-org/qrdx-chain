# syntax=docker/dockerfile:1.7
# =============================================================================
# QRDX Node — container image
#
# Three stages:
#   1. liboqs   — builds the liboqs C library from source (post-quantum crypto).
#                 qrdx/crypto/pq/dilithium.py imports `oqs` with NO fallback, so
#                 a node without liboqs cannot start. The pip package is only a
#                 ctypes wrapper; without the shared object it tries to cmake-build
#                 liboqs at first import, which fails in a slim runtime image.
#   2. wheels   — compiles every Python dependency (fastecdsa needs libgmp,
#                 netifaces needs a compiler) into wheels.
#   3. runtime  — slim image with no compilers: just the wheels, liboqs.so and
#                 the application code.
#
# Build:
#   docker build -f docker/Dockerfile -t qrdx-node:local .          # context = repo root
# =============================================================================

ARG PYTHON_VERSION=3.11
# liboqs C library. 0.15.0 is the newest tagged release and matches the version
# the development environment builds against — keep these in lockstep so node
# identities / Dilithium keys are derived by the same implementation.
ARG LIBOQS_VERSION=0.15.0

# -----------------------------------------------------------------------------
# Stage 1 — liboqs (post-quantum crypto C library)
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS liboqs
ARG LIBOQS_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        git \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" \
        https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
    && ninja -C /tmp/liboqs/build install \
    && rm -rf /tmp/liboqs

# -----------------------------------------------------------------------------
# Stage 2 — Python wheels
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS wheels

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libgmp-dev \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements-v3.txt .
# py-evm is the QRDX EVM fork (package name `qrdx-evm`, import name `eth`).
# Installing it properly removes the need for any sys.path manipulation at runtime.
COPY py-evm ./py-evm

RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements-v3.txt \
    && pip wheel --no-cache-dir --wheel-dir /wheels ./py-evm

# -----------------------------------------------------------------------------
# Stage 3 — runtime
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

# OQS_INSTALL_PATH tells liboqs-python where the shared object lives, so it never
# falls back to building liboqs from source at import time.
# PYTHONWARNINGS=ignore suppresses the cosmetic liboqs / liboqs-python version-skew
# UserWarning (the two projects release on independent cadences).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    OQS_INSTALL_PATH=/usr/local \
    PYTHONWARNINGS=ignore

# Runtime shared libraries only — no compilers in the final image.
#   libgmp10        : fastecdsa (P256 legacy curve)
#   libssl3         : liboqs
#   openssh-client  : optional Pinggy reverse tunnel (ENABLE_PINGGY_TUNNEL)
#   curl            : convenience for operators debugging the node from inside
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgmp10 \
        libssl3 \
        openssh-client \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# liboqs shared object + ldconfig so ctypes can find it
COPY --from=liboqs /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=liboqs /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

# Python dependencies from locally built wheels (no network, no compilers)
COPY --from=wheels /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl \
    && rm -rf /wheels

WORKDIR /app

# Application code
COPY qrdx ./qrdx
COPY run_node.py ./
COPY docker/docker-entrypoint.sh docker/docker-healthcheck.py \
     docker/testnet-init.py docker/validator-init.py docker/genesis-init.py ./docker/

# Fail the BUILD (not production) if the post-quantum stack is not usable:
# ML-DSA-65 must be present, and importing oqs must not trigger a source build.
RUN chmod +x ./docker/docker-entrypoint.sh ./docker/docker-healthcheck.py \
        ./docker/testnet-init.py ./docker/validator-init.py ./docker/genesis-init.py \
    && python -c "\
import oqs;\
mechs = oqs.get_enabled_sig_mechanisms();\
assert 'ML-DSA-65' in mechs, 'ML-DSA-65 missing from liboqs build';\
print('liboqs', oqs.oqs_version(), '| liboqs-python', oqs.oqs_python_version(), '| ML-DSA-65 OK')" \
    && python -c "from eth.vm.forks.qrdx import QRDXVM; print('py-evm QRDXVM OK')" \
    && python -c "import qrdx.constants; print('qrdx package OK')"

# Non-root runtime user. UID/GID 1000 matches the default `user:` in the
# compose files so bind-mounted data directories stay writable.
# /testnet exists in the image so that a named volume mounted there inherits the
# qrdx ownership. A volume whose mount point is absent from the image is created
# root-owned, which an unprivileged container cannot write to.
RUN groupadd --gid 1000 qrdx \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin qrdx \
    && mkdir -p /app/data /shared/node-registry /testnet \
    && chown -R qrdx:qrdx /app /shared /testnet
USER qrdx

# Default node port (QRDX_NODE_PORT). The HTTP API, JSON-RPC (/rpc),
# Prometheus metrics (/metrics), health probes (/healthz, /readyz) and the
# optional WebSocket/SSE stream (/ws, /stream) are ALL served on this one port.
EXPOSE 3007

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
    CMD ["python", "/app/docker/docker-healthcheck.py"]

ENTRYPOINT ["/app/docker/docker-entrypoint.sh"]
