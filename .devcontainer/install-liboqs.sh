#!/bin/bash
# The development container's liboqs: the same release the node image ships (docker/Dockerfile),
# built from its tag and checked against its commit, with the matching Python wrapper. Every node
# also proves at startup that the library computes FIPS 204/203 (qrdx/crypto/pq/algorithms.py).
set -euo pipefail

LIBOQS_VERSION=0.16.0
LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
LIBOQS_PYTHON_VERSION=0.16.0.1

echo "Installing liboqs ${LIBOQS_VERSION} and liboqs-python ${LIBOQS_PYTHON_VERSION}..."

sudo apt-get update
sudo apt-get install -y cmake gcc ninja-build libssl-dev python3-dev python3-pip git

src="$(mktemp -d)"
git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git "${src}"
if [ "$(git -C "${src}" rev-parse HEAD)" != "${LIBOQS_COMMIT}" ]; then
    echo "liboqs ${LIBOQS_VERSION} is not commit ${LIBOQS_COMMIT}" >&2
    exit 1
fi
cmake -S "${src}" -B "${src}/build" -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release
ninja -C "${src}/build"
sudo ninja -C "${src}/build" install
sudo ldconfig
rm -rf "${src}"

pip3 install --user "liboqs-python==${LIBOQS_PYTHON_VERSION}"

python3 -c "import oqs; print('liboqs', oqs.oqs_version(), '| liboqs-python', oqs.oqs_python_version())"
echo "liboqs and Python bindings installed successfully!"
