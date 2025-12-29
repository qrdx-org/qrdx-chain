# QRDX Chain Docker

Docker image for running QRDX Chain (Trinity with QR-PoS consensus).

## Building the Image

### Using Docker directly

```bash
docker build -f docker/Dockerfile -t qrdx-chain:latest .
```

### Using GitHub Actions

1. Go to the **Actions** tab in your GitHub repository
2. Select **Build Docker Image** workflow
3. Click **Run workflow**
4. Configure options:
   - **tag**: Image tag (default: `latest`)
   - **push**: Whether to push to GitHub Container Registry (default: `false`)

The workflow will:
- Build the Docker image with all local modules
- Optionally push to `ghcr.io/qrdx-org/qrdx-chain`
- Use layer caching for faster builds

## Running the Container

### Basic usage

```bash
# Show help
docker run --rm qrdx-chain:latest

# Run a node
docker run -d \
  --name qrdx-node \
  -p 30303:30303 \
  -p 30303:30303/udp \
  -p 8545:8545 \
  -p 8546:8546 \
  -v qrdx-data:/root/.local/share/trinity \
  qrdx-chain:latest \
  --network-id 1337 \
  --sync-mode full
```

### Run with validator

```bash
# First, generate validator keys on host
mkdir -p ./validator-keys
# ... copy validator keystores to ./validator-keys ...

# Run validator node
docker run -d \
  --name qrdx-validator \
  -p 30303:30303 \
  -p 30303:30303/udp \
  -p 8545:8545 \
  -v qrdx-data:/root/.local/share/trinity \
  -v $(pwd)/validator-keys:/validator-keys:ro \
  qrdx-chain:latest \
  --network-id 1337 \
  --sync-mode full \
  --enable-http-apis=eth,net,web3
```

### Interactive shell

```bash
docker run -it --rm qrdx-chain:latest /bin/bash
```

## Ports

- `30303/tcp` - P2P networking
- `30303/udp` - P2P discovery
- `8545/tcp` - HTTP RPC API
- `8546/tcp` - WebSocket RPC API

## Environment Variables

The container uses the standard Trinity environment variables:

- `TRINITY_DATA_DIR` - Data directory (default: `/root/.local/share/trinity`)
- `TRINITY_LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)

## Docker Compose Example

```yaml
version: '3.8'

services:
  qrdx-node:
    image: ghcr.io/qrdx-org/qrdx-chain:latest
    container_name: qrdx-node
    ports:
      - "30303:30303"
      - "30303:30303/udp"
      - "8545:8545"
      - "8546:8546"
    volumes:
      - qrdx-data:/root/.local/share/trinity
    command:
      - --network-id=1337
      - --sync-mode=full
      - --enable-http-apis=eth,net,web3
      - --http-listen-address=0.0.0.0
    restart: unless-stopped

volumes:
  qrdx-data:
```

## Multi-Stage Build (Future)

For production use, consider creating a multi-stage Dockerfile:
1. Builder stage: Compile and install all dependencies
2. Runtime stage: Copy only necessary files

This would significantly reduce the final image size.

## Notes

- The image is built with all development dependencies included
- Python 3.12 is used for maximum compatibility with QR-PoS features
- All local modules (py-evm, lahja, trinity, etc.) are installed from source
- Layer caching is enabled in GitHub Actions for faster subsequent builds

## Troubleshooting

### Build fails with dependency errors

Ensure all git submodules are properly initialized:
```bash
git submodule update --init --recursive
```

### Container exits immediately

Check logs:
```bash
docker logs qrdx-node
```

Common issues:
- Missing genesis file
- Port conflicts
- Insufficient permissions for data directory
