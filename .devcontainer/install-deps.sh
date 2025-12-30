#!/bin/bash
set -e

pip install --no-cache-dir -e ./eth-utils
pip install --no-cache-dir -e ./eth-typing
pip install --no-cache-dir -e ./eth-hash[pycryptodome]
pip install --no-cache-dir -e ./eth-keys
pip install --no-cache-dir -e ./pyrlp
pip install --no-cache-dir -e ./eth-abi
pip install --no-cache-dir -e ./eth-bloom
pip install --no-cache-dir -e ./eth-enr

# Async utilities
pip install --no-cache-dir -e ./async-service
pip install --no-cache-dir -e ./asyncio-run-in-process
pip install --no-cache-dir -e ./lahja
# Sometimes lahja is retarded. install manually with: cd /workspaces/qrdx-chain/lahja && pip3 install -e .

# Core EVM (without dev extras to avoid dependency conflicts)
pip install --no-cache-dir -e ./py-evm

# Install pytest (required by eth.tools.fixtures imported by trinity RPC modules)
pip install --no-cache-dir pytest>=7.0.0

# Testing utilities (without py-evm extra since we already installed it locally)
pip install --no-cache-dir -e ./eth-tester

# Account management
pip install --no-cache-dir -e ./eth-account

# Web3.py (without dev extras to avoid dependency conflicts)
pip install --no-cache-dir -e ./web3.py

# Finally, install QRDX Chain (Trinity with QR-PoS)
# Local modules already installed, this will install remaining trinity dependencies
pip install --no-cache-dir -e .

echo "All dependencies installed successfully in editable mode"