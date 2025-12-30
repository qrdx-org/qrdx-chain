#!/bin/bash
set -e

cd ../liboqs
mkdir -p build && cd build
cmake -GNinja .. \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Release
ninja
ninja install
ldconfig

# Export environment variables
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
export OQS_INSTALL_PATH=/usr/local

echo "liboqs installed successfully to /usr/local"