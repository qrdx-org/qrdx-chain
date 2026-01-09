#!/bin/bash
set -e

echo "Installing liboqs and Python bindings..."

# Install dependencies
sudo apt-get update
sudo apt-get install -y cmake gcc ninja-build libssl-dev python3-dev python3-pip git

# Clone and build liboqs
cd /tmp
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install

# Update library cache
sudo ldconfig

# Install Python bindings
pip3 install --user liboqs-python

echo "liboqs and Python bindings installed successfully!"
