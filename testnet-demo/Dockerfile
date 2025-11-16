# QR-PoS Trinity Node Dockerfile
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs (post-quantum cryptography library)
WORKDIR /tmp
RUN git clone --depth 1 --branch 0.15.0-rc1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf liboqs

# Create app directory
WORKDIR /app

# Copy only requirements first for better caching
COPY setup.py ./setup.py
COPY pyproject.toml ./pyproject.toml
COPY README.md ./README.md

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    setuptools \
    liboqs-python \
    blake3 \
    bech32 \
    eth-hash[pycryptodome] \
    eth-utils \
    eth-typing \
    eth-keys \
    eth-enr \
    rlp \
    py-ecc \
    "trie>=2.0.0,<4" \
    trio \
    async-service \
    lahja \
    cytoolz \
    coincurve \
    cached-property \
    lru-dict \
    ckzg \
    plyvel

# Copy Trinity source code and py-evm
COPY trinity ./trinity
COPY p2p ./p2p
COPY py-evm/eth ./eth
COPY eth-bloom/eth_bloom ./eth_bloom
COPY setup.py ./setup.py
COPY Makefile ./Makefile

# Don't install Trinity as a package - we'll run it directly from source
# Just ensure core dependencies are present
RUN pip install --no-cache-dir \
    "rlp>=2.0.0,<3" \
    "eth-keys>=0.3.3,<0.4.0" \
    "eth-utils>=1.9.0,<2.0.0" \
    "eth-typing>=2.0.0,<3.0.0" \
    "eth-hash[pycryptodome]>=0.3.1,<0.4.0"

# Create data directories
RUN mkdir -p /data/validator

# Expose ports (RPC, WebSocket, P2P)
EXPOSE 8545 8546 30303

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import sys; sys.path.insert(0, '/app'); from trinity.crypto.pq.dilithium import DilithiumPrivateKey; print('OK')" || exit 1

# Default command - run Trinity via Python module
CMD ["python", "-m", "trinity", "--help"]
