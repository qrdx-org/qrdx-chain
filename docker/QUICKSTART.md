# Quick Reference: Docker Build

## Build Locally
```bash
docker build -f docker/Dockerfile -t qrdx-chain:latest .
```

## Test Image
```bash
# Show help
docker run --rm qrdx-chain:latest --help

# Run node (testnet)
docker run -d \
  --name qrdx-node \
  -p 30303:30303 \
  -p 8545:8545 \
  -p 8546:8546 \
  -v qrdx-data:/root/.local/share/trinity \
  qrdx-chain:latest \
  --network-id 1234
```

## GitHub Action
1. Navigate to **Actions** → **Build Docker Image**
2. Click **Run workflow**
3. Configure:
   - **tag**: Image tag (default: `latest`)
   - **push**: `true` to push to ghcr.io, `false` to build only
4. Click **Run workflow** button

## Pull from Registry (if pushed)
```bash
docker pull ghcr.io/OWNER/REPO:latest
```

## Key Files
- `docker/Dockerfile` - Multi-stage build with all modules
- `docker/.dockerignore` - Build context optimization
- `docker/README.md` - Detailed documentation
- `.github/workflows/docker-build.yml` - CI/CD workflow

## Image Details
- **Base**: python:3.12-slim
- **Size**: ~1.23GB
- **Platform**: linux/amd64
- **Includes**: All 16 local Ethereum modules + liboqs

## Troubleshooting

### Build fails with dependency conflicts
- Check that setup.py modifications are in place (commented dependencies)
- Ensure all local module directories exist

### Trinity command not found
- Verify qrdx-chain installed correctly: `docker run --rm qrdx-chain:latest which trinity`

### liboqs error
- Should show warning about version mismatch (0.15.0 vs 0.14.1) but still work
- If fails to load, check LD_LIBRARY_PATH includes /usr/local/lib

### Pytest import error
- Verify pytest installed after py-evm in Dockerfile
- Check trinity.rpc.modules can import eth.tools.fixtures
