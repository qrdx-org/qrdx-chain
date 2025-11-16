#!/bin/bash
set -e

# Quick Start Script for QR-PoS Single Validator Node
# This script sets up a simple single-validator testnet for development

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "QR-PoS Quick Start"
echo "========================================"
echo ""
echo "Setting up single-validator testnet..."
echo ""

# Create testnet with 1 validator
cd "$PROJECT_ROOT"
python3 scripts/setup_testnet.py \
    --validators 1 \
    --chain-id 1337 \
    --output ./quickstart \
    --prefunded 3

echo ""
echo "========================================"
echo "✓ Setup complete!"
echo "========================================"
echo ""
echo "Quick start commands:"
echo ""
echo "  # Start the validator"
echo "  cd quickstart && ./start-testnet.sh"
echo ""
echo "  # Check status"
echo "  docker-compose logs -f"
echo ""
echo "  # Stop"
echo "  cd quickstart && ./stop-testnet.sh"
echo ""
echo "RPC endpoint: http://localhost:8545"
echo ""
