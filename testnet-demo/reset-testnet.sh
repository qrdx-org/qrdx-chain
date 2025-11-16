#!/bin/bash
set -e

echo "Resetting QR-PoS Testnet..."
echo "WARNING: This will delete all blockchain data!"
read -p "Continue? (y/N) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose down -v
    rm -rf data/
    echo "✓ Testnet reset complete"
    echo "Run ./start-testnet.sh to restart"
fi
