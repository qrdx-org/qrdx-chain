# QR-PoS Testnet Setup on Windows

## Prerequisites

1. **Docker Desktop for Windows** installed and running
2. **Git Bash** or **WSL2** (Windows Subsystem for Linux)

## Important: File Location

The testnet expects to be run from the repository root structure:

```
QRDX-Chain/
├── trinity/
├── py-evm/
├── p2p/
├── setup.py
├── pyproject.toml
├── README.md
└── testnet-demo/
    ├── Dockerfile
    ├── docker-compose.yml
    ├── start-testnet.sh
    └── ...
```

## Setup Steps

### Option 1: Run from Repository Root (Recommended)

If you copied only the `testnet-demo/` directory, you need the full repository:

```bash
# From your QRDX-Chain repository root
cd D:\GitHub\QRDX-Chain

# Make sure you have all the source files
ls trinity/  # Should show Trinity source
ls py-evm/   # Should show py-evm source

# Start the testnet
cd testnet-demo
bash start-testnet.sh
```

### Option 2: Standalone Setup

If you only have the testnet-demo directory, you need to:

1. Download or clone the full QRDX-Chain repository
2. Place the `testnet-demo/` directory inside it
3. Follow Option 1 above

## Troubleshooting

### Error: "open Dockerfile: no such file or directory"

**Cause:** The Dockerfile must be in the `testnet-demo/` directory, and the script must be run with the parent directory as the build context.

**Solution:** Make sure you're in the `testnet-demo/` directory and the Dockerfile exists there.

### Error: "COPY failed: file not found"

**Cause:** The Docker build context is the parent directory (`..`), so it expects to find `trinity/`, `py-evm/`, etc. in the parent.

**Solution:** Ensure the full repository structure exists:
```bash
cd D:\GitHub\QRDX-Chain
ls  # Should show: trinity/, py-evm/, p2p/, testnet-demo/
```

### Docker Build is Slow

The first build will take 5-10 minutes because it:
- Installs system dependencies
- Builds liboqs (post-quantum crypto library) from source
- Installs Python dependencies
- Compiles Trinity

Subsequent builds will be faster due to Docker layer caching.

## Starting the Testnet

```bash
# From testnet-demo directory
bash start-testnet.sh
```

This will:
1. Build the Docker image (first time only)
2. Start 4 validator nodes
3. Each node will have its own RPC endpoint

## Endpoints

Once running, you can connect to:

- **Validator 0:** http://localhost:8545 (RPC), ws://localhost:8546 (WebSocket)
- **Validator 1:** http://localhost:8546 (RPC), ws://localhost:8547 (WebSocket)
- **Validator 2:** http://localhost:8547 (RPC), ws://localhost:8548 (WebSocket)
- **Validator 3:** http://localhost:8548 (RPC), ws://localhost:8549 (WebSocket)

## Monitoring

```bash
# View all logs
docker-compose logs -f

# View specific validator logs
docker-compose logs -f validator_0

# Check node status (from parent directory)
python ../scripts/check_testnet.py --rpc http://localhost:8545
```

## Stopping the Testnet

```bash
bash stop-testnet.sh
```

## Resetting the Testnet

To start fresh (removes all blockchain data):

```bash
bash reset-testnet.sh
```

## Common Issues

### Port Already in Use

If ports 8545-8549 are already in use, edit `docker-compose.yml` to use different ports.

### Docker Not Running

Make sure Docker Desktop is running. Check with:
```bash
docker ps
```

### Permission Denied

On Windows with Git Bash, you might need to run:
```bash
chmod +x start-testnet.sh stop-testnet.sh reset-testnet.sh
```

## Next Steps

After the testnet is running:

1. **Send transactions:** Use Web3.py or web3.js to connect to any validator
2. **Monitor consensus:** Watch logs to see block proposals and attestations
3. **Test PQ addresses:** Generate and use Dilithium-based addresses
4. **Validate finality:** Observe Casper FFG checkpoints every 32 slots

See `../TESTNET_SETUP_GUIDE.md` for detailed usage examples.
