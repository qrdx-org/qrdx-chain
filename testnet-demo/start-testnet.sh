#!/bin/bash
set -e

echo "Starting QR-PoS Testnet..."
echo "=========================="
echo ""

# Build Docker image if needed
if [[ "$(docker images -q qrdx-chain:latest 2> /dev/null)" == "" ]]; then
    echo "Building Docker image..."
    docker build -f Dockerfile -t qrdx-chain:latest ..
fi

# Start all validators
echo "Starting validators..."
docker-compose up -d

echo ""
echo "✓ Testnet started!"
echo ""
echo "Validators:"
echo "  Validator 0: http://localhost:8545 (RPC), ws://localhost:8546 (WS)"
echo "  Validator 1: http://localhost:8555 (RPC), ws://localhost:8556 (WS)"
echo "  Validator 2: http://localhost:8557 (RPC), ws://localhost:8558 (WS)"
echo "  Validator 3: http://localhost:8559 (RPC), ws://localhost:8560 (WS)"

echo ""
echo "View logs: docker-compose logs -f"
echo "Stop testnet: ./stop-testnet.sh"
