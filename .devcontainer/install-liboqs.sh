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

# Verify ninja is available
if ! command -v ninja &> /dev/null; then
    echo "Error: ninja not found in PATH"
    exit 1
fi

# Configure with cmake
echo "Running cmake..."
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
if [ $? -ne 0 ]; then
    echo "Error: cmake configuration failed"
    exit 1
fi

# Build with ninja
echo "Building with ninja..."
ninja
if [ $? -ne 0 ]; then
    echo "Error: ninja build failed"
    exit 1
fi

# Install
echo "Installing liboqs..."
sudo ninja install

# Update library cache
sudo ldconfig

# Install Python bindings
pip3 install --user liboqs-python

echo "liboqs and Python bindings installed successfully!"
