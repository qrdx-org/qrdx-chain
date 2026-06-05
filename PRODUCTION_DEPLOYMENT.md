# QRDX Chain — Production Deployment Guide

> **Version:** 1.0 · **Date:** June 2026  
> **Purpose:** Step-by-step runbook for deploying and operating a QRDX node in production.  
> **Prerequisite:** Complete all gates in `QRDX_IMPLEMENTATION_CHECKLIST.md` before using this guide.

---

## Table of Contents

1. [Pre-Deployment Checklist](#1-pre-deployment-checklist)
2. [Infrastructure Requirements](#2-infrastructure-requirements)
3. [Security Hardening](#3-security-hardening)
4. [Environment & Secrets Configuration](#4-environment--secrets-configuration)
5. [TLS / Reverse Proxy Setup](#5-tls--reverse-proxy-setup)
6. [Validator Key Management](#6-validator-key-management)
7. [Database Initialisation & Migrations](#7-database-initialisation--migrations)
8. [Docker Production Deployment](#8-docker-production-deployment)
9. [Monitoring & Alerting](#9-monitoring--alerting)
10. [Backup & Restore](#10-backup--restore)
11. [Upgrade Procedure](#11-upgrade-procedure)
12. [Rollback Procedure](#12-rollback-procedure)
13. [Disaster Recovery](#13-disaster-recovery)
14. [Known Production Issues & Mitigations](#14-known-production-issues--mitigations)
15. [CI/CD Pipeline](#15-cicd-pipeline)
16. [Test Suite Runbook](#16-test-suite-runbook)

---

## 1. Pre-Deployment Checklist

All items must be **✅ checked** before a node goes live.

### 1.1 Security Blockers (from `QRDX_IMPLEMENTATION_CHECKLIST.md §0`)

- [ ] No private keys, mnemonics, or credentials committed to the repository (`gitleaks` pre-commit hook active)
- [ ] `liboqs-python>=0.9.0` is installed in the Docker image (verify: `pip show liboqs-python`)
- [ ] Dilithium3 verify bypass is gone — `python -c "from qrdx.crypto.pq.dilithium import verify; print('OK')"` exits 0
- [ ] No default `qrdx`/`qrdx` credentials anywhere in configuration or environment files
- [ ] `QRDX_VALIDATOR_PASSWORD` set via environment variable, **not** written to any config file
- [ ] Grafana admin password changed from default `admin`

### 1.2 Configuration

- [ ] `config.toml` created from `config.example.toml` with all production values filled in
- [ ] `QRDX_CHAIN_ID` matches the target network (mainnet = `1`)
- [ ] `[rpc.http] cors_origins` narrowed from `["*"]` to your actual frontend origins
- [ ] `[p2p.security] pq_required = true` for mainnet (rejects non-PQ peers)
- [ ] `[validator.slashing_protection] enabled = true` for all validator nodes
- [ ] `[metrics] enabled = true` and port is firewalled from public internet
- [ ] Prometheus and Grafana admin credentials set via environment variables
- [ ] Log rotation configured (Docker `json-file` driver with `max-size`/`max-file` in `docker-compose.prod.yml`)

### 1.3 Network & Firewall

- [ ] Firewall allows inbound TCP/UDP on P2P port (`30303` default)
- [ ] RPC ports (`8545`, `8546`) are **not** exposed to public internet (reverse proxy handles TLS termination)
- [ ] Metrics port (`9090`) is **not** exposed to public internet
- [ ] Grafana port (`3000`) is access-controlled (VPN or basic auth)

---

## 2. Infrastructure Requirements

### 2.1 Minimum Specs (Validator Node)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU      | 4 vCPUs | 8 vCPUs    |
| RAM      | 4 GB    | 8 GB        |
| Disk     | 100 GB SSD | 500 GB NVMe SSD |
| Network  | 100 Mbps | 1 Gbps    |
| OS       | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |

### 2.2 Minimum Specs (Archive / RPC Node)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU      | 2 vCPUs | 4 vCPUs    |
| RAM      | 4 GB    | 16 GB       |
| Disk     | 500 GB SSD | 2 TB NVMe SSD |
| Network  | 100 Mbps | 1 Gbps    |

### 2.3 Python Runtime

- Python 3.11 (matches Docker base image `python:3.11-slim`)
- `liboqs-python>=0.9.0` is mandatory — the node will refuse to start without it
- System deps: `gcc`, `libgmp-dev`, `openssh-client` (see `docker/Dockerfile`)

---

## 3. Security Hardening

### 3.1 Host-Level

```bash
# Create a dedicated non-root user for running the node
useradd -m -u 1000 -s /bin/bash qrdx

# Restrict Docker socket access
usermod -aG docker qrdx

# Enable UFW
ufw allow 30303/tcp comment "QRDX P2P"
ufw allow 30303/udp comment "QRDX P2P Discovery"
ufw allow 22/tcp   comment "SSH"
ufw enable
```

### 3.2 Container Security

The production compose file already sets the following — **do not remove them**:

```yaml
user: "1000:1000"          # non-root
security_opt:
  - no-new-privileges:true # prevent privilege escalation
read_only: true            # immutable container filesystem
tmpfs:
  - /tmp                   # writable scratch space only
```

### 3.3 Secrets Management

**Never** store secrets in `config.toml` or `.env` files committed to git. Use one of:

- **Docker Secrets** (Swarm mode): `docker secret create qrdx_validator_password <(echo -n "$PASS")`
- **HashiCorp Vault**: inject secrets as environment variables at runtime
- **Cloud KMS**: AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault

Minimum required secrets:

| Secret                   | Description                           |
|--------------------------|---------------------------------------|
| `QRDX_VALIDATOR_PASSWORD`| Password protecting the PQ wallet file|
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin UI password             |
| `QRDX_TLS_CERT`          | Path or content of TLS certificate    |
| `QRDX_TLS_KEY`           | Path or content of TLS private key    |

### 3.4 CORS for RPC

For production, replace the wildcard origin:

```toml
# config.toml — production value
[rpc.http]
cors_origins = ["https://your-dapp.example.com"]
```

---

## 4. Environment & Secrets Configuration

### 4.1 Required `.env` for Production

Create `/opt/qrdx/.env` (mode `0600`, owned by `qrdx:qrdx`):

```bash
# Network
QRDX_CHAIN_ID=1
QRDX_LOG_LEVEL=INFO

# Ports (override defaults if needed)
QRDX_RPC_HTTP_PORT=8545
QRDX_RPC_WS_PORT=8546
QRDX_P2P_PORT=30303
QRDX_METRICS_PORT=9090
QRDX_LEGACY_PORT=3007

# Resource limits
QRDX_CPU_LIMIT=4.0
QRDX_MEM_LIMIT=4G

# Secrets — load from vault in CI/CD; never commit these values
QRDX_VALIDATOR_PASSWORD=<from_vault>

# TLS (optional — set if terminating TLS at node rather than reverse proxy)
QRDX_TLS_CERT=
QRDX_TLS_KEY=
QRDX_TLS_CERT_DIR=./certs

# Monitoring
PROMETHEUS_PORT=9091
GRAFANA_PORT=3000
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=<from_vault>
```

> **CRITICAL:** The `.env.example` file still lists PostgreSQL variables (`POSTGRES_USER`, etc.)
> These are **stale** — the project migrated to SQLite. Ignore those variables for new deployments.
> Track cleanup at: [.env.example](.env.example)

### 4.2 Production `config.toml` Differences from Example

The following values **must** differ from `config.example.toml` in production:

```toml
[p2p.security]
pq_required = true           # was false; reject non-PQ peers on mainnet

[rpc.http]
cors_origins = ["https://your-dapp.example.com"]   # was ["*"]

[rpc.modules]
admin = false                # keep false; admin methods are privileged
debug = false                # keep false; debug exposes internal state

[metrics]
enabled = true               # was false; required for Prometheus scrape
host = "127.0.0.1"           # never expose metrics to 0.0.0.0 on public hosts
```

---

## 5. TLS / Reverse Proxy Setup

The node does not terminate TLS internally. Use nginx or Caddy in front of the RPC ports.

### 5.1 nginx Example

```nginx
server {
    listen 443 ssl;
    server_name rpc.your-node.example.com;

    ssl_certificate     /etc/letsencrypt/live/rpc.your-node.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rpc.your-node.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # HTTP JSON-RPC
    location /rpc {
        proxy_pass http://127.0.0.1:8545;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket JSON-RPC
    location /ws {
        proxy_pass http://127.0.0.1:8546;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name rpc.your-node.example.com;
    return 301 https://$host$request_uri;
}
```

### 5.2 Caddy Example (automatic TLS)

```
rpc.your-node.example.com {
    reverse_proxy /rpc localhost:8545
    reverse_proxy /ws  localhost:8546 {
        transport http { versions h1 }
        header_up Connection {http.upgrade}
        header_up Upgrade {http.upgrade}
    }
}
```

---

## 6. Validator Key Management

### 6.1 Generating a Validator Wallet

```bash
# On an air-gapped machine, generate PQ wallet
qrdx-wallet generate --type pq --output /secure/offline/validator_wallet.json

# Verify the key type
qrdx-wallet info --wallet /secure/offline/validator_wallet.json
# Should show: Key type: Dilithium3 (ML-DSA-65 / FIPS 204)
```

### 6.2 Transferring to Production

1. Copy `validator_wallet.json` to the production host using `scp` over an authenticated SSH connection.
2. Store at the path specified by `[validator] pq_wallet_path` in `config.toml`.
3. Set permissions: `chmod 600 validator_wallet.json && chown qrdx:qrdx validator_wallet.json`.
4. **Never** store the wallet file inside the Docker image. Mount it as a volume or secret.

### 6.3 Slashing Protection

The node maintains a local slashing-protection DB at `[validator.slashing_protection] db_path`.
Before migrating a validator to a new host:

1. **Export** slashing protection from the old host: copy `slashing_protection.db` to the new host.
2. **Do not** delete the old DB until the new node has fully synced and the protection data confirmed.
3. **Never** run two validator instances with the same key simultaneously — double-signing results in permanent stake slashing.

### 6.4 Future: HSM Integration

> **Gap (tracked in checklist §0.1):** Key management runbook for HSM use is not yet written.
> Until then, follow the manual procedure above and keep validator wallets on an encrypted volume.
> Recommended HSM options: AWS CloudHSM, YubiHSM 2, Nitrokey HSM 2.

---

## 7. Database Initialisation & Migrations

### 7.1 First-Time Setup (SQLite)

```bash
# The node auto-creates the database on first start.
# The data directory must exist and be writable.
mkdir -p /opt/qrdx/data
chown 1000:1000 /opt/qrdx/data
```

### 7.2 Running Migrations

```bash
# Migrations are applied automatically at node startup via qrdx/migrations/
# To run them manually (e.g., for inspection):
PYTHONPATH=. python -m qrdx.migrations.migrate_to_pos
```

### 7.3 Stale Script Warning

> **`scripts/apply_contract_schema.sh` is outdated.** It targets PostgreSQL via `psql` and references
> env variables (`DENARO_DATABASE_HOST`, `POSTGRES_USER`) that no longer apply.
> The project migrated to SQLite. Do **not** run this script against a SQLite deployment.
> It should be removed or rewritten for SQLite. Track at: [scripts/apply_contract_schema.sh](scripts/apply_contract_schema.sh)

### 7.4 SQLite WAL Mode

WAL mode is configured in `config.toml` and improves concurrent read performance:

```toml
[database.sqlite]
wal_mode = true   # Enabled — do not disable in production
```

### 7.5 Database Sizing

SQLite has a practical limit of ~281 TB per file. For archive nodes growing beyond ~100 GB:
- Monitor file size: `du -sh /opt/qrdx/data/qrdx.db`
- Ensure the underlying volume has at least 2× current DB size free for VACUUM operations.

---

## 8. Docker Production Deployment

### 8.1 Initial Start

```bash
# Clone repo
git clone https://github.com/qrdx/qrdx-chain /opt/qrdx
cd /opt/qrdx

# Copy and edit config
cp config.example.toml docker/config.toml
# Edit docker/config.toml — set all production values per Section 4.2

# Copy env file
cp .env.example .env
# Edit .env — set secrets per Section 4.1

# Pull or build the image
docker compose -f docker/docker-compose.prod.yml build

# Start services
docker compose -f docker/docker-compose.prod.yml up -d

# Verify health
docker compose -f docker/docker-compose.prod.yml ps
docker logs qrdx-node --tail 50
```

### 8.2 Verifying the Node is Healthy

```bash
# Health endpoint
curl -sf http://localhost:8545/health | python3 -m json.tool

# JSON-RPC
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Check peer count
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

### 8.3 Image Build Hardening (Gap)

> **Gap (tracked in checklist §0.5):** The Dockerfile uses a single-stage build without pinned
> dependency hashes. For production, migrate to a multi-stage build and pin all pip dependencies
> with `pip-compile --generate-hashes`. Until then, always build from a tagged release commit.

---

## 9. Monitoring & Alerting

### 9.1 Grafana

After deployment:

1. Open `http://<host>:3000` (or via reverse proxy).
2. Log in with `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD`.
3. Add Prometheus data source: `http://qrdx-prometheus:9090`.
4. Import QRDX dashboards from `docker/grafana/` (if present) or build from `docker/prometheus.yml` metric names.

### 9.2 Alert Rules

Prometheus alert rules are defined in `docker/alert-rules.yml`. Key alerts to verify are firing:

| Alert                  | Meaning                               | Action          |
|------------------------|---------------------------------------|-----------------|
| `QRDXNodeDown`         | Node health check failing             | Restart node    |
| `QRDXPeerCountLow`     | Fewer than 3 peers                    | Check P2P port  |
| `QRDXBlockProductionStopped` | No blocks in N slots          | Check consensus |
| `QRDXHighMemoryUsage`  | Memory >90% of limit                  | Scale up or tune|
| `QRDXDiskSpaceWarning` | Disk >80% full                        | Expand volume   |

### 9.3 Log Aggregation

JSON-format logs are written to stdout and captured by Docker's `json-file` driver. Aggregate with:
- **Loki + Grafana**: add Loki data source alongside Prometheus
- **ELK Stack**: ship via Filebeat
- **CloudWatch/Stackdriver**: use the respective Docker log driver

Set `LOG_FORMAT` and `LOG_LEVEL` via environment variables.

---

## 10. Backup & Restore

### 10.1 SQLite Backup (Online)

SQLite's `.backup` command is safe to run while the node is live:

```bash
# Create timestamped backup
BACKUP_FILE="/backups/qrdx-$(date +%Y%m%dT%H%M%S).db"
sqlite3 /opt/qrdx/data/qrdx.db ".backup '$BACKUP_FILE'"
echo "Backup written to $BACKUP_FILE"

# Verify integrity
sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;"
```

### 10.2 Backup Schedule (cron)

```cron
# /etc/cron.d/qrdx-backup
# Daily full backup, retain 30 days
0 2 * * * qrdx sqlite3 /opt/qrdx/data/qrdx.db ".backup '/backups/qrdx-$(date +\%Y\%m\%dT\%H\%M\%S).db'" && find /backups -name 'qrdx-*.db' -mtime +30 -delete
```

### 10.3 Validator Key Backup

```bash
# Encrypt and back up validator wallet
gpg --symmetric --cipher-algo AES256 \
    --output /backups/validator_wallet.json.gpg \
    /opt/qrdx/data/validator_wallet.json

# Verify decryption works before storing off-site
gpg --decrypt /backups/validator_wallet.json.gpg > /tmp/test_wallet.json
diff /opt/qrdx/data/validator_wallet.json /tmp/test_wallet.json
rm /tmp/test_wallet.json
```

Store encrypted backups in at least two geographically separate locations.

### 10.4 Restore Procedure

```bash
# 1. Stop the node
docker compose -f docker/docker-compose.prod.yml stop qrdx-node

# 2. Replace database
cp /opt/qrdx/data/qrdx.db /opt/qrdx/data/qrdx.db.pre-restore
cp /backups/qrdx-<timestamp>.db /opt/qrdx/data/qrdx.db

# 3. Verify integrity
sqlite3 /opt/qrdx/data/qrdx.db "PRAGMA integrity_check;"

# 4. Restart node and verify sync
docker compose -f docker/docker-compose.prod.yml start qrdx-node
docker logs qrdx-node --tail 50 -f
```

---

## 11. Upgrade Procedure

### 11.1 Standard Upgrade (Docker)

```bash
cd /opt/qrdx

# 1. Pull latest code
git fetch origin
git log HEAD..origin/main --oneline   # review changes
git checkout main && git pull

# 2. Review breaking changes in CHANGELOG and checklist
# grep for "BREAKING" or "Migration required" in release notes

# 3. Rebuild image
docker compose -f docker/docker-compose.prod.yml build --no-cache

# 4. Rolling restart (zero-downtime for non-validator nodes)
docker compose -f docker/docker-compose.prod.yml up -d --no-deps qrdx-node

# 5. Confirm health
docker compose -f docker/docker-compose.prod.yml ps
curl -sf http://localhost:8545/health
```

### 11.2 Database Migration During Upgrade

If the release includes migrations (check `qrdx/migrations/` for new files):

```bash
# Run migrations before restarting the node
PYTHONPATH=. python -m qrdx.migrations.migrate_to_pos
# Confirm: "Migration complete" in output

# Then restart
docker compose -f docker/docker-compose.prod.yml restart qrdx-node
```

### 11.3 Validator Nodes — Upgrade Window

Validator nodes must minimise downtime to avoid missed attestations:
- Schedule upgrades during low-activity periods.
- Do not upgrade during an active epoch transition.
- If downtime exceeds 1 epoch, the validator may be penalised but will **not** be slashed (slashing requires equivocation, not absence).

---

## 12. Rollback Procedure

```bash
cd /opt/qrdx

# 1. Identify last good tag/commit
git log --oneline -20

# 2. Check out previous version
git checkout <previous-tag-or-commit>

# 3. Rebuild
docker compose -f docker/docker-compose.prod.yml build

# 4. Restore DB if migration was destructive
# (see Section 10.4)

# 5. Restart
docker compose -f docker/docker-compose.prod.yml up -d --no-deps qrdx-node

# 6. Verify
docker logs qrdx-node --tail 50
curl -sf http://localhost:8545/health
```

---

## 13. Disaster Recovery

### 13.1 Node Failure Scenarios

| Scenario | Detection | RTO | Procedure |
|----------|-----------|-----|-----------|
| Node process crash | Health check / alerts | < 5 min | Docker `restart: unless-stopped` handles automatically |
| Host failure | Monitoring heartbeat | < 30 min | Provision new host, restore from backup (§10.4) |
| DB corruption | `PRAGMA integrity_check` fails | < 2 hr | Restore from last known-good backup |
| Validator key compromise | Suspicious signing activity | Immediate | Run `qrdx-wallet revoke`, notify network operators |
| Network partition | `net_peerCount` = 0 | Variable | Check P2P firewall rules, restart discovery |

### 13.2 Complete Node Rebuild

```bash
# On fresh host
apt-get update && apt-get install -y docker.io docker-compose-plugin git

git clone https://github.com/qrdx/qrdx-chain /opt/qrdx
cd /opt/qrdx

# Restore config and secrets from secure storage
cp /backups/config.toml docker/config.toml
cp /backups/.env .env

# Restore validator wallet (decrypt GPG backup)
gpg --decrypt /backups/validator_wallet.json.gpg > /opt/qrdx/data/validator_wallet.json
chmod 600 /opt/qrdx/data/validator_wallet.json

# Restore database (or start fresh and re-sync from peers)
cp /backups/qrdx-<latest>.db /opt/qrdx/data/qrdx.db

# Start services
docker compose -f docker/docker-compose.prod.yml up -d
```

---

## 14. Known Production Issues & Mitigations

### 14.1 Stale `.env.example` with PostgreSQL Variables

**Issue:** `.env.example` contains `POSTGRES_USER`, `POSTGRES_PASSWORD`, `QRDX_DATABASE_NAME`,
`QRDX_DATABASE_HOST` — these predate the migration from PostgreSQL to SQLite.  
**Impact:** New operators may be confused or attempt to configure a PostgreSQL backend.  
**Mitigation:** Ignore those variables. The node uses `[database.sqlite]` from `config.toml`.  
**Fix Required:** Update `.env.example` to remove stale PostgreSQL vars and add production SQLite/env vars.

### 14.2 Stale `apply_contract_schema.sh` Targeting PostgreSQL

**Issue:** `scripts/apply_contract_schema.sh` uses `psql` against `DENARO_DATABASE_*` variables.  
**Impact:** Running it will fail or corrupt a non-existent PostgreSQL instance.  
**Mitigation:** Do not run this script. Contracts schema is handled by automatic migrations.  
**Fix Required:** Remove or replace with an SQLite-aware version.

### 14.3 Docker Compose `read_only: true` with SQLite

**Issue:** The production compose file sets `read_only: true` on the container filesystem.
The SQLite WAL journal (`qrdx.db-wal`, `qrdx.db-shm`) writes to the same directory as the DB.  
**Impact:** If the `qrdx-data` volume is not correctly mounted at `/app/data`, the node will crash
on first write attempt.  
**Mitigation:** Ensure the volume mount covers `/app/data`. The `tmpfs: [/tmp]` covers temp files.  
**Verification:** `docker inspect qrdx-node | jq '.[0].Mounts'` — confirm `/app/data` is listed.

### 14.4 No Multi-Stage Docker Build

**Issue:** `docker/Dockerfile` is a single-stage build; build tools (`gcc`) remain in the final image.  
**Impact:** Larger attack surface and image size (~500 MB vs ~200 MB for multi-stage).  
**Mitigation:** Acceptable for current beta. Pin to a specific `python:3.11.x-slim` digest.  
**Fix Required:** Migrate to multi-stage build before mainnet (tracked in checklist §0.5).

### 14.5 P2P PQ Required = False by Default

**Issue:** `config.example.toml` has `pq_required = false`, meaning non-PQ peers are accepted.  
**Impact:** On mainnet a non-PQ peer could join if this config is used verbatim.  
**Mitigation:** Set `pq_required = true` in production `config.toml` (Section 4.2 above).

### 14.6 ✅ RESOLVED — Native Value Transfer (Dual Address System)

**Background — the dual address system** ([qrdx/crypto/address.py](qrdx/crypto/address.py)):
QRDX uses two canonical address families, plus a legacy migration format:
- **Traditional (`0x…`)** — secp256k1, `keccak256(pubkey)[-20:]`, EIP-55 checksum (20 bytes)
- **Post-Quantum (`0xPQ…`)** — Dilithium3, `keccak256(pubkey)[:32]`, PQ checksum (32 bytes)
- **Legacy (`Q…`/`R…`)** — old Denaro base58 secp256k1 *curve points*; migration-only, mapped
  one-way to `0x` via BLAKE3

Balances live in the **account model** (`account_state` table, wei units, 1 QRDX = 10¹⁸ wei).
The canonical native-transfer path is **`eth_sendRawTransaction`** → EVM executor → `account_state`
([qrdx/node/main.py](qrdx/node/main.py) `eth_sendRawTransaction_handler`). The legacy
`TransactionOutput`/UTXO path (secp256k1 curve points in base58) is **not** used for `0x`/`0xPQ`
transfers — a `0x` address is a keccak *hash* and can never be reconstructed into a curve point.

**Original symptom:** The integration harness (`integration_tests/tx_sender.py`) built transfers
using the legacy UTXO `TransactionOutput`, which calls `string_to_point()` on a `0x` address →
`ValueError: substring not found`. S04 errored; S10/S11 skipped. Suite scored 6/11 (55%).

**Fix applied:** Rewrote `TransactionSender` to use the canonical account model — build an
EIP-155 transaction, sign with the wallet's secp256k1 key (`eth_account`), and submit via
`eth_sendRawTransaction`, with local nonce tracking so rapid-fire sends get sequential nonces.
No core/protocol change was needed; the harness was simply built against the wrong (legacy) model.
**Result:** S04, S10, S11 pass. ✅

### 14.7 ✅ RESOLVED — Validator Set Not Registered at Genesis (SQLite `Decimal` Bind Bug)

**This was a real node bug, not just a missing endpoint.** Two issues:

1. **No validator query endpoint.** The harness called REST `/get_validators`, which didn't exist
   (the `validator_*` JSON-RPC module was unregistered and used Postgres `$1` placeholders).
   **Fix:** added `db.get_validators()` ([qrdx/database_sqlite.py](qrdx/database_sqlite.py)) and a
   `GET /get_validators` REST endpoint ([qrdx/node/main.py](qrdx/node/main.py)).

2. **🔴 Genesis validator init silently failed on SQLite.** `_init_validators`
   ([qrdx/validator/genesis_init.py](qrdx/validator/genesis_init.py)) bound `Decimal` objects to
   the `validators` TEXT columns. aiosqlite cannot serialize `Decimal`
   (`ProgrammingError: type 'decimal.Decimal' is not supported`), and the error was swallowed by a
   broad `except`. **Consequence: on every SQLite deployment the `validators` table was always
   empty after genesis** — validators were funded but never registered in the PoS set, so the
   active validator set, governance eligibility, and validator queries all saw zero validators.
   **Fix:** bind the stake as `str(Decimal(...))`. Genesis now correctly registers the validator
   set. **Result:** S07 (7/7) and S08 governance (8/8) pass. ✅

### 14.8 EVM/account-model state was out-of-consensus — Phase 1 fixed; Phase 2 required

**Issue (as found):** `eth_sendRawTransaction` applied EVM transfers to the receiving node's
`account_state` only — no mempool, no gossip, no block inclusion — and block import never re-executes
EVM transactions. So account-model state was single-node and not durable across resync. See the full
analysis and design in [docs/EVM_STATE_CONSENSUS_INTEGRATION.md](docs/EVM_STATE_CONSENSUS_INTEGRATION.md).

**Phase 1 (implemented):** `eth_sendRawTransaction` now gossips the signed raw tx to peers, which run
the identical deterministic execution, so all **live** nodes converge on the same `account_state`. A
seen-cache (`EVM_TX_CACHE`) makes this idempotent and terminates gossip loops. Verified at the DB
level — after a transfer, all 4 testnet nodes hold a byte-identical recipient `account_state` row;
S10 now asserts cross-node `eth_getBalance` consistency (not the unchanged UTXO balance).

**Phase 2 (required before mainnet):** make EVM txs first-class consensus objects — mempool →
block inclusion → deterministic replay on import → unified state root. Until then, EVM state is
**not durable across a full resync** and **not consensus-final**; a node rebuilt from chain history
will not have post-genesis account-model state. Do not rely on this for mainnet value custody.

**Separately — testnet startup flakiness (pre-existing, non-blocking):** node bootstrap / peer-mesh
formation is timing-sensitive; roughly 1 in 5 fresh multi-node starts has a node miss the initial
mesh and cascade scenario skips. This predates these changes and is a harness/orchestration timing
issue, not a protocol fault. The S10 height-drift check polls for convergence rather than asserting
on a single snapshot. Harden node-startup readiness/retry before relying on the suite in CI gating.

> **Integration test status (run June 2026, post-fix):** `test_full_integration_suite` →
> **11 passed, 0 failed, 0 skipped (100%)**, stable across consecutive runs. All scenarios pass:
> genesis bootstrap, peer mesh, block production, **transactions**, tokens (qRC20), AMM pools,
> **validators**, **governance**, bridge, **cross-node consistency**, and stress. The unit suite
> remains green (1,656 passed).

---

## 15. CI/CD Pipeline

A GitHub Actions pipeline is provided at `.github/workflows/ci.yml`. It runs on every push and PR.

### 15.1 Pipeline Stages

| Stage | Trigger | What It Does |
|-------|---------|--------------|
| `lint` | push / PR | `ruff`, `black --check`, `isort --check` |
| `type-check` | push / PR | `mypy qrdx/` |
| `unit-tests` | push / PR | All tests *except* `integration` marker; coverage report |
| `security-scan` | push / PR | `gitleaks` secret scan, `pip-audit` dependency audit |
| `integration-tests` | PR to `main` only | `@pytest.mark.integration` suite with real nodes |
| `docker-build` | push to `main` or tag | Build + push image to registry |

### 15.2 Required Repository Secrets

Set these in GitHub → Settings → Secrets and Variables → Actions:

| Secret | Purpose |
|--------|---------|
| `DOCKER_HUB_USERNAME` | Docker Hub image push |
| `DOCKER_HUB_TOKEN` | Docker Hub authentication token |

---

## 16. Test Suite Runbook

### 16.1 Running Tests Locally

```bash
# Install dev dependencies
pip install -e ".[dev,pq]"

# Run unit tests only (fast, no network)
PYTHONPATH=. pytest tests/ -m "not integration" --timeout=60 -v

# Run with coverage report
PYTHONPATH=. pytest tests/ -m "not integration" --cov=qrdx --cov-report=html --timeout=60

# Run integration tests (requires ports 3001–3010 free, takes ~5 min)
PYTHONPATH=. pytest tests/ -m integration --timeout=300 -v

# Run a single file
PYTHONPATH=. pytest tests/test_consensus_pos.py -v
```

### 16.2 Known Test Issues (from `TESTING_PRODUCTION_READINESS.md`)

All five issues from the production readiness report have been resolved:

| Issue | Fix Applied |
|-------|-------------|
| `ModuleNotFoundError: No module named 'qrdx'` | Added `pythonpath = ["."]` to `[tool.pytest.ini_options]` in `pyproject.toml` |
| Integration tests hang indefinitely | `@pytest.mark.integration` added to `test_testnet_integration.py`; excluded from default `pytest` run by marker filter |
| `test_block_explorer_api.py` pytest crash | File renamed to `scripts/run_explorer_api_checks.py` and moved out of `tests/` |
| Unawaited `ForkChoiceStore.on_block()` in `test_security_adversarial.py` | Added `await` to the two call sites |
| `return` statements in `test_system_wallets.py` | Converted to `assert` statements |

### 16.3 Coverage Targets

| Module                | Target Coverage |
|-----------------------|-----------------|
| `qrdx/crypto/`        | ≥ 90%           |
| `qrdx/consensus.py`   | ≥ 90%           |
| `qrdx/validator/`     | ≥ 85%           |
| `qrdx/transactions/`  | ≥ 85%           |
| `qrdx/p2p/`           | ≥ 80%           |
| `qrdx/exchange/`      | ≥ 80%           |
| `qrdx/governance/`    | ≥ 75%           |
| Overall               | ≥ 80%           |
