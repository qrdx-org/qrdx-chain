# QRDX Chain
[![Language](https://img.shields.io/badge/Language-Python%203.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20or%20WSL2-brightgreen.svg)]()
[![License: AGPLv3](https://img.shields.io/badge/License-AGPLv3-yellow.svg)](https://opensource.org/license/agpl-v3)

**QRDX Chain** is a quantum-resistant decentralized blockchain built entirely in Python and utilizes PostgreSQL for blockchain data. It offers a blockchain implementation that developers can understand and extend without the complexity often found in traditional cryptocurrency codebases. Additionally, it can serve as a foundation for developers that are interested in creating their own quantum-resistant cryptocurrency.

<details>
<summary><b>Features:</b></summary>
<dl><dd>

* Proof-of-Work blockchain using SHA256 hashing with dynamic difficulty adjustment every 512 blocks. Blocks are limited to 2MB and can process approximately 3,800 transactions (~21 transactions per second).
  
* Peer-to-peer network with cryptographic node identity, ECDSA-based request signing, and automatic blockchain synchronization. Includes reputation management, rate limiting, and security measures for network protection.
  
* Transaction system supporting up to 6 decimal places with ECDSA signature verification. Transactions can include up to 255 inputs and outputs, with optimized signature schemes and optional messages.
  
* PostgreSQL database backend with indexed queries, connection pooling, and integrated transaction validation for efficient blockchain storage and retrieval.
  
* Consensus versioning system enabling clean protocol upgrades with support for both soft and hard forks through activation height scheduling.
  
* RESTful API interface built on FastAPI providing comprehensive blockchain interaction, transaction submission, and network queries with background task processing and CORS support.

</details>
</dl></dd>

<details>
<summary><b>Monetary Policy:</b></summary>
<dl><dd>
  
  **QRDX's monetary policy has been chosen for its optimal balance of a scarce total supply, frequent halving events, and long-term emission lifespan.**
  
  * Initial Reward Per Block: **64 QRDX**
  * Halving Interval: **262,144 blocks**.
    * Targets ~2.5 years per halving.
  * Maximum halvings: **64**
  * Estimated Emission Lifespan: **~160 years**.
  * Maximum Total Supply: **33,554,432 QRDX**

</details>
</dl></dd>

---

## Node Setup

**Automated configuration and deployment of a QRDX node can be achieved by using either the `setup.sh` script or `Docker`. Both methods ensure that all prerequisites for operating a QRDX node are met and properly configured according to the user's preference.**

<details>
<summary><b>Setup via setup.sh:</b></summary>

<dl><dd>

The `setup.sh` script is designed for traditional configuration and deployment of a single QRDX node. It automatically handles system package updates, manages environment variables, configures the PostgreSQL database, sets up a Python virtual environment, installs the required Python dependencies, and runs the QRDX node.


**Quick Start:**

<dl><dd>

  ```bash
  # Clone the QRDX repository to your local machine.
  git clone https://github.com/The-Sycorax/qrdx-chain-denaro.git
  
  # Change directory to the cloned repository.
  cd qrdx-chain-denaro
  
  # Make the setup script executable.
  chmod +x setup.sh
  
  # Execute the setup script with optional arguments if needed.
  ./setup.sh [--skip-prompts] [--setup-db] [--skip-package-install]
  ```
</dl></dd>

<dl><dd>

<details>
<summary><b>CLI Arguments:</b></summary>

<dl><dd>
<dl><dd>

- `--skip-prompts`: Executes the setup script in an automated manner without requiring user input, bypassing all interactive prompts.
  
- `--setup-db`: Limits the setup script's actions to only configure the PostgreSQL database, excluding the execution of other operations such as virtual environment setup and dependency installation.

- `--skip-package-install`: Skips `apt` package installation. This argument can be used for Linux distributions that do not utilize `apt` as a package manager. However, it is important that the required system packages are installed prior to running the setup script (For more details refer to: *Installation for Non-Debian Based Systems*).

</dd></dl>
</details>

<details>
<summary><b>Installation for Non-Debian Based Systems:</b></summary>

<dl><dd>
<dl><dd>

 The setup script is designed for Linux distributions that utilize `apt` as their package manager (e.g. Debian/Ubuntu). If system package installation is unsuccessful, it is most likely due to the absence of `apt` on your system. This is generally the case for Non-Debian Linux distributions. Therefore, the required system packages must be installed manually.

<details>
<summary><b>Required Packages:</b></summary>
<dl><dd>

*Note: It is nessessary to ensure that the package names specified are adjusted to correspond with those recognized by your package manager.*

- `gcc`
- `libgmp-dev`
- `libpq-dev`
- `postgresql-15`
- `python3`
- `python3-venv`
- `sudo`
  
</dd></dl>
</details>

Once the required packages have been installed, the `--skip-package-install` argument can be used with the setup script to bypass operations that require `apt`. This should mitigate any unsucessful execution related to package installation, allowing the setup script to proceed.

</dd></dl>
</dd></dl>
</details>

</dd></dl>
</dd></dl>
</details>

<details>
<summary><b>Setup via Docker:</b></summary>

<dl><dd>

The Docker setup provides a containerized deployment option for QRDX nodes. Unlike the `setup.sh` script, it encapsulates everything needed to run a QRDX node — including the **liboqs** post-quantum library and the **py-evm** QRDX fork, both built into the image — in an isolated container. This avoids installing dependencies on the host and prevents conflicts with system packages. It also supports multi-node deployments, which `setup.sh` does not.

The image is built from `docker/Dockerfile` in three stages: liboqs is compiled from source, every Python dependency is built into wheels, and the final runtime image ships neither compilers nor build tools. The build fails fast if ML-DSA-65, py-evm or the `qrdx` package cannot be imported. The container runs as the unprivileged user `qrdx` (UID 1000).

At runtime, `docker/docker-entrypoint.sh` applies container defaults for the `QRDX_*` environment, creates the writable data and key directories, optionally resolves a bootstrap peer, and then `exec`s the node. `docker/docker-healthcheck.py` probes the node's own `/healthz` and `/readyz` endpoints, so `depends_on: { condition: service_healthy }` means "this peer can actually serve chain data".

To test public node behavior over the Internet, the Docker setup includes optional support for exposing a node via an SSH reverse tunnel through [Pinggy.io's free tunneling service](https://www.pinggy.io) (`ENABLE_PINGGY_TUNNEL: 'true'`).

**One port serves everything.** The REST API, JSON-RPC (`/rpc`), Prometheus metrics (`/metrics`), health probes (`/healthz`, `/readyz`) and the optional realtime feeds (`/ws`, `/stream`) are all served on `QRDX_NODE_PORT` (default `3007`). There is no separate `8545` / `9090` listener.

**Compose files:**

| File | Purpose |
| --- | --- |
| `docker/docker-compose.yml` | Single node — development / joining an existing network |
| `docker/docker-compose.testnet.yml` | Self-contained 4-node local testnet (3 validators + 1 full node) |
| `docker/docker-compose.prod.yml` | Production node + Prometheus + Grafana |
| `docker/docker-compose.tunnel.yml` | Public **genesis validator** behind a Cloudflare Tunnel: starts its own chain, no inbound ports |
| `docker/docker-compose.tunnel-wallet.yml` | Overlay for `tunnel.yml`: supply your own validator wallet |
| `docker/docker-compose.prod-secrets.yml` | Overlay for `prod.yml`: mount TLS certs / validator wallet |

**Quick Start:**

<dl><dd>

```bash
# Clone the QRDX repository (py-evm is a submodule and is required for the build).
git clone --recurse-submodules https://github.com/The-Sycorax/qrdx-chain-denaro.git
cd qrdx-chain-denaro

# Single node, joining the public network.
docker compose -f docker/docker-compose.yml up --build -d
docker compose -f docker/docker-compose.yml logs -f

curl http://localhost:3007/healthz
curl http://localhost:3007/readyz

# Stop. Add -v to also delete the chain data volume.
docker compose -f docker/docker-compose.yml down
```

To run a standalone node that creates its own genesis instead of dialing the public seed, set `QRDX_BOOTSTRAP_NODE=self`.

</dl></dd>

<dl><dd>
<details>
<summary><b>Local Testnet (4 nodes):</b></summary>

<dl><dd>

`docker-compose.testnet.yml` is self-contained: an `init` service generates the validator wallets and `genesis_config.json` inside the shared volume before any node starts, so no host Python, liboqs or jq is required. The generation is idempotent — restarting the stack reuses the existing genesis.

```bash
docker compose -f docker/docker-compose.testnet.yml up --build -d

# node0 3007 (validator, bootstrap) | node1 3008 | node2 3009 (validators) | node3 3010 (full node)
docker compose -f docker/docker-compose.testnet.yml ps
docker compose -f docker/docker-compose.testnet.yml logs -f node0

# All four nodes should report the same height.
for p in 3007 3008 3009 3010; do curl -s http://localhost:$p/readyz; echo; done

# Tear down and wipe the chain.
docker compose -f docker/docker-compose.testnet.yml down -v
```

> **Warning:** the generated validator wallets use well-known passwords (`testnet_validator_<i>`). For local testing only.

</dd></dl>
</details>

<details>
<summary><b>Production Stack:</b></summary>

<dl><dd>

```bash
# Node configuration must exist before the stack starts.
cp config.example.toml docker/config.toml
# Edit docker/config.toml for production values.

# Secrets come from the environment, never from the image.
export QRDX_VALIDATOR_PASSWORD='...'
export GRAFANA_ADMIN_PASSWORD='...'

docker compose -f docker/docker-compose.prod.yml up -d
docker compose -f docker/docker-compose.prod.yml ps
```

Prometheus scrapes `qrdx-node:3007/metrics` and is published on `${PROMETHEUS_PORT:-9091}`; Grafana on `${GRAFANA_PORT:-3000}`. Alert rules live in `docker/alert-rules.yml`. See [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) for the full checklist.

</dd></dl>
</details>

<details>
<summary><b>Public Node via Cloudflare Tunnel:</b></summary>

<dl><dd>

`docker-compose.tunnel.yml` runs a **validator** node alongside a `cloudflared` sidecar, so the node is reachable on a real hostname over HTTPS with **no inbound port open on the host**. Both services use `restart: unless-stopped`, so they survive crashes and host reboots and run until you stop them.

The node **starts its own chain** — it is the genesis node, not a node that joins an existing network. On first start:

1. `validator-init` generates an ML-DSA-65 validator keypair into the data volume (or validates the wallet you mounted) and logs its address. It never overwrites an existing wallet, so restarts reuse the same identity.
2. `genesis-init` writes `genesis_config.json` onto the same volume. It funds `QRDX_GENESIS_ALLOCATIONS` (default: `0xPQ4Bd03Abf07B8302EA2547c881F597530638848a3d245296da543A40F8b05884C` = **1,000,000,000 QRDX**) and makes this node's validator the genesis validator with `QRDX_GENESIS_VALIDATOR_STAKE` (default 100,000 QRDX).
3. The node creates block 0 from that file and proposes from block 1. No `STAKE_DEPOSIT` is needed.

`QRDX_GENESIS_ALLOCATIONS` takes `address:amount[,address:amount...]`, with amounts in QRDX. Addresses must be checksummed (mixed case, exactly as the wallet shows them).

The stack uses **named volumes only — no host bind mounts**, so it starts identically on Linux, Docker Desktop and WSL. To supply your own validator wallet instead, add the wallet overlay:

```bash
mkdir -p /secure/path && cp my-validator.json /secure/path/   # must exist first
export QRDX_VALIDATOR_WALLET_DIR=/secure/path
export QRDX_VALIDATOR_WALLET=/app/wallet/my-validator.json

docker compose -f docker/docker-compose.tunnel.yml \
               -f docker/docker-compose.tunnel-wallet.yml up -d
```

One-time setup in Cloudflare Zero Trust -> Networks -> Tunnels: create a Cloudflared tunnel, copy its token, then under **Public Hostname** route your hostname to service type `HTTP`, URL `node:3007` (the compose service name and port).

```bash
export CLOUDFLARE_TUNNEL_TOKEN='eyJhIjoi...'
export QRDX_PUBLIC_HOSTNAME='node.example.com'

docker compose -f docker/docker-compose.tunnel.yml up --build -d

# The validator address, the genesis hash and the funded allocations.
docker compose -f docker/docker-compose.tunnel.yml logs validator-init genesis-init
docker compose -f docker/docker-compose.tunnel.yml logs -f

# The node's host port is bound to 127.0.0.1 — the tunnel is the only public path.
curl http://127.0.0.1:3007/readyz
curl http://127.0.0.1:2000/ready      # cloudflared's own status

docker compose -f docker/docker-compose.tunnel.yml down
```

`QRDX_PUBLIC_HOSTNAME` must match the hostname you routed: it becomes `QRDX_SELF_URL`, the address this node advertises to peers. Both variables are required — Compose fails with an explanatory message if either is unset.

> **Genesis is fixed once the chain exists.** `genesis-init` writes it once and never regenerates it. If you change `QRDX_GENESIS_ALLOCATIONS` later, it only logs a warning. A different genesis needs a fresh chain: `down -v`, which **also deletes the validator key** on the volume, so back that up first. Every other node joining this chain must start from the same file: copy it out with `docker compose -f docker/docker-compose.tunnel.yml cp node:/app/data/genesis_config.json .` and place it two directories above that node's `QRDX_DATABASE_PATH`. A node that builds its own default genesis has a different block 0 and rejects this chain's blocks.

> **Key custody:** the wallet format this node loads is **unencrypted** — the Dilithium secret key is plain hex in the JSON, and `QRDX_VALIDATOR_PASSWORD` is accepted by the loader but never used to encrypt it. The `node-data` volume therefore holds a live private key: back it up, restrict host access, and keep it off shared storage.

> **Exposure:** the routed hostname publishes the node's entire HTTP surface, including `/rpc`, `/metrics` and the realtime feeds. Use a Cloudflare WAF rule or Access policy to restrict paths you do not want public, and set `QRDX_RPC_ADMIN_TOKEN` if admin RPC methods are enabled.

</dd></dl>
</details>

<details>
<summary><b>Adding Nodes to a Compose File:</b></summary>

<dl><dd>

```yaml
  node-3008:
    <<: *qrdx-node
    hostname: node-3008
    ports: ["3008:3008"]
    volumes:
      # Only the data directory is a volume. Mounting one over /app would shadow
      # the application code baked into the image.
      - node_3008_data:/app/data
      - node-registry:/shared/node-registry
    depends_on:
      node: { condition: service_healthy }
    environment:
      NODE_NAME: 'node-3008'
      QRDX_NODE_HOST: '0.0.0.0'
      QRDX_NODE_PORT: '3008'
      QRDX_DATABASE_PATH: '/app/data/qrdx.db'
      QRDX_NODE_KEY_DIR: '/app/data/keys'

      # Bootstrap peer selection:
      #   'self'     — use this node's own address (standalone / local genesis)
      #   'discover' — pick a peer from the shared registry volume
      #   <url>      — an explicit peer, e.g. http://node:3007
      QRDX_BOOTSTRAP_NODE: 'http://node:3007'

      # Publicly reachable address of this node. Defaults to
      # http://${NODE_NAME}:${QRDX_NODE_PORT} when left empty. Overridden by the
      # Pinggy URL when ENABLE_PINGGY_TUNNEL is 'true'.
      QRDX_SELF_URL: ''

      # Optional public tunnel via Pinggy.io, up to 60 minutes.
      #ENABLE_PINGGY_TUNNEL: 'true'
```

</dd></dl>
</details>

</dd></dl>

<details>
<summary><b>Troubleshooting:</b></summary>

<dl><dd>

**`error while creating mount source path ... file exists`** (Docker Desktop / WSL, usually while a container is "Starting")

A bind mount whose source directory does not exist on the host. Docker tries to create it, and Docker Desktop's WSL bind-mount shim fails when two services mount the same missing path. The shipped stacks avoid this — `tunnel.yml` uses named volumes only, and the optional TLS/wallet mounts live in overlay files — so if you hit it:

```bash
# Clear the half-created stack, then retry.
docker compose -f docker/docker-compose.tunnel.yml down -v
docker compose -f docker/docker-compose.tunnel.yml up -d
```

If it persists, a stale shim directory is cached; restart Docker Desktop. When you do add a bind mount of your own, create the host directory first (`mkdir -p`) and prefer a path inside the WSL filesystem over one on a mounted Windows drive (`/mnt/c`, `/mnt/d`).

**`config.toml` parsed as a directory** (prod stack)

`docker-compose.prod.yml` bind-mounts `./config.toml`, which must exist before `up`. If it does not, Docker creates a *directory* at that path. Run `cp config.example.toml docker/config.toml` first, and `rm -rf docker/config.toml` if a directory was already created.

**Validator never proposes a block**

On a node joining an existing chain, this is expected until the validator address holds at least 100,000 QRDX of stake. `docker compose ... logs validator-init` prints the address; check it is funded and that a `STAKE_DEPOSIT` has been submitted. The tunnel stack's validator is a genesis validator and proposes from block 1. If it does not, check `logs genesis-init` and look for `Found genesis configuration` in the node log.

</dd></dl>
</details>

<details>
<summary><b>Important Notes:</b></summary>

<dl><dd>

***This documents the requirements for custom Docker configurations. The shipped compose files already satisfy them.***

- **Environment variable names are UPPERCASE.** The node reads `QRDX_NODE_PORT`, `QRDX_SELF_URL`, `QRDX_BOOTSTRAP_NODE` and so on. A lowercase `qrdx_*` spelling is silently ignored, which leaves the node bound to `127.0.0.1` and unreachable from outside the container.

- **Mount volumes at `/app/data`, never at `/app`.** A volume over `/app` shadows the application code baked into the image and goes stale on every rebuild. Give each node its own data volume; sharing one between nodes corrupts the database.

- **Persist the node identity.** `QRDX_NODE_KEY_DIR` must point inside the data volume (`/app/data/keys`). Left at its default, the node writes `node_key.pq` into the image layer and loses its identity on redeploy.

- **An empty `QRDX_BOOTSTRAP_NODE` is not "no bootstrap."** `qrdx/constants.py` treats an empty string as unset and falls back to the public seed node. Use `'self'` for a node that must not dial out.

- Each node service needs a unique `NODE_NAME` and `QRDX_NODE_PORT`.

- Mount the shared `node-registry` volume on every node that uses `QRDX_BOOTSTRAP_NODE: 'discover'` or the Pinggy tunnel; it is unused otherwise.

- In multi-node deployments use `depends_on` with `condition: service_healthy` so Compose waits for an upstream peer to be able to serve chain data before starting dependents.

</dd></dl>
</details>

</dd></dl>

</dd></dl>
</details>

---


## Running a QRDX Node

*Note: This section dose not apply to nodes deployed using Docker.*

A QRDX node can be started manually if you have already executed the `setup.sh` script and chose not to start the node immediately, or if you need to start the node in a new terminal session. If the setup script was used with the `--setup-db` argument or manual installation was performed, it is reccomended that a Python virtual environment is created and that the required Python packages are installed prior to starting a node.

**Commands to manually start a node:**

<dl><dd>

```bash
# Navigate to the QRDX directory.
cd path/to/qrdx-chain-denaro

# Create a Python virtual environment (Optional).
sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate

# Install the required packages if needed.
pip install -r requirements.txt

# Start the QRDX Node
python3 run_node.py

# Manualy start the QRDX node via uvicorn (Optional).
uvicorn qrdx.node.main:app --host 127.0.0.1 --port 3006 

# To stop the node, press Ctrl+C in the terminal.
```

</dl></dd>

**To exit a Python virtual environment:**

<dl><dd>

```bash
deactivate
```

</dl></dd>

---

## Nodeless Wallet Setup
To setup a nodeless wallet, use [QRDX Wallet Client GUI](https://github.com/The-Sycorax/QRDXWalletClient-GUI).

---

## Mining

**QRDX** adopts a Proof of Work (PoW) system for mining using SHA256 hashing, with dynamic difficulty adjustment every 512 blocks to maintain a target block time of 180 seconds (3 minutes).

<details>
<summary><b>Mining Details:</b></summary>

<dl><dd>

- **Block Hashing**:
  - Utilizes the SHA256 algorithm for block hashing.
  - The hash of a block must begin with the last `difficulty` hexadecimal characters of the hash from the previously mined block.
  - `difficulty` can have decimal digits, which restricts the `difficulty + 1`st character of the derived hash to have a limited set of values.

    ```python
    from math import ceil

    difficulty = 6.3
    decimal = difficulty % 1

    charset = '0123456789abcdef'
    count = ceil(16 * (1 - decimal))
    allowed_characters = charset[:count]
    ```

- **Difficulty Adjustment**:
  - Difficulty adjusts every 512 blocks based on the actual block time versus the target block time of 180 seconds (3 minutes).
  - Starting difficulty is 6.0.

- **Block Size and Capacity**:
  - Maximum block size is 2MB (raw bytes), equivalent to 4MB in hexadecimal format.
  - Transaction data is limited to approximately 1.9MB hex characters per block.

- **Rewards**:
  - Block rewards start at 64 QRDX and decrease by half every 262,144 blocks until they reach zero.

</dd></dl>
</details>

<details>
<summary><b>Mining Software:</b></summary>

<dl><dd>

- **CPU Mining**:

  The CPU miner script (`./miner/cpu_miner.py`) can be used to mine QRDX.
          
  <details>
  <summary><b>Usage:</b></summary>
  <dl><dd>
  
  - **Syntax**:
      ```bash
      python3 miner/cpu_miner.py [-h] [-a ADDRESS] [-n NODE] [-w WORKERS] [-m MAX_BLOCKS]
      ```
  
  - **Arguments**:
        
      * `--address`, `-a` (Required): Your public QRDX wallet address where mining rewards will be sent.

      * `--node`, `-n` (Optional): The URL or IP address of the QRDX node to connect to. Defaults to `http://127.0.0.1:3006/`.

      * `--workers`, `-w` (Optional): The number of parallel processes to run. It's recommended to set this to the number of CPU cores you want to use for mining. Defaults to 1.

      * `--max-blocks`, `-m` (Optional): Maximum number of blocks to mine before exiting. If not specified, the miner will continue indefinitely.

      * `--help`, `-h`: Shows the help message.

  <details>
  <summary><b>Examples:</b></summary>
  <dl><dd>
  
  - #### Basic Mining (Single Core)    
    ```bash
    python3 miner/cpu_miner.py --address WALLET_ADDRESS
    ```
  
  - #### Mining while connected to a Remote Node    
    ```bash
    python3 miner/cpu_miner.py --address WALLET_ADDRESS --node http://a-public-node.com:3006
    ```
  
  - #### Mining with Multiple Cores    
    ```bash
    python3 miner/cpu_miner.py --address WALLET_ADDRESS --workers 8
    ```
  
  *(Replace `WALLET_ADDRESS` with your actual QRDX address)*
    
  </dd></dl>
  </dd></dl>
  </details>

- **GPU Mining**:

  For GPU mining please refer to [QRDX CUDA Miner Setup and Usage](https://github.com/The-Sycorax/qrdx-chain-denaro/tree/main/miner).

</dd></dl>
</details>

---

## Blockchain Synchronization

**QRDX** nodes maintain synchronization with the network through automatic peer discovery and chain validation mechanisms that ensure all nodes converge on the longest valid chain. Additionally nodes can also be manually synchronized.

<details>
<summary><b>Automatic Synchronization:</b></summary>

<dl><dd>

Nodes automatically detect and synchronize with longer chains through two mechanisms:

- **Handshake Synchronization**: When connecting to a peer, nodes exchange chain state information. If the peer has a longer valid chain, synchronization is triggered immediately.

- **Periodic Chain Discovery**: A background task polls 2 random peers every 60 seconds to check for longer chains, ensuring the node remains synchronized even without new connections.

</dd></dl>
</details>

<details>
<summary><b>Manual Synchronization:</b></summary>

<dl><dd>

To manually initiate blockchain synchronization, a request can be sent to a node's `/sync_blockchain` endpoint:

<dl><dd>

```bash
curl http://127.0.0.1:3006/sync_blockchain
```

</dl></dd>

<dl><dd>

The endpoint accepts an optional `node_id` parameter to sync from a specific peer. The node ID of a peer can be found in the `./qrdx/node/nodes.json` file:

<dl><dd>

```bash
curl "http://127.0.0.1:3006/sync_blockchain?node_id=NODE_ID"
```

</dl></dd>
<dl><dd>
The endpoint returns an error if a sync operation is already in progress.

</dd></dl>
</details>

---

## License
QRDX is released under the terms of the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for more information or goto https://www.gnu.org/licenses/agpl-3.0.en.html






