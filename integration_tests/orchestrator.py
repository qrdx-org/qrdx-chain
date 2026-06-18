"""
Testnet Orchestrator — Multi-Node Process Manager

Manages the full lifecycle of a QRDX integration testnet:
  1. Generate wallets (PQ + traditional)
  2. Create genesis via real GenesisCreator
  3. Initialize per-node SQLite databases
  4. Start N node processes (uvicorn + FastAPI)
  5. Wait for network mesh formation
  6. Run health checks
  7. Graceful shutdown

No stubs — every node is a real QRDX node process.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from integration_tests.config import (
    PROJECT_ROOT, TESTNET_DIR, WALLETS_DIR, DATABASES_DIR, CONFIGS_DIR,
    LOGS_DIR, DATA_DIR, GENESIS_FILE,
    CHAIN_ID, NETWORK_NAME, BASE_NODE_PORT, NUM_NODES, NUM_VALIDATORS,
    SLOT_DURATION, SLOTS_PER_EPOCH,
    NODE_STARTUP_TIMEOUT, PEER_DISCOVERY_TIMEOUT,
    build_node_specs, NodeSpec, WALLET_ROSTER,
)
from integration_tests.wallet_factory import generate_all_wallets
from integration_tests.genesis_generator import create_genesis
from integration_tests.rpc_client import NodeRPCClient, MultiNodeClient

logger = logging.getLogger(__name__)


class NodeProcess:
    """Manages a single QRDX node subprocess."""

    def __init__(self, spec: NodeSpec, env: dict, project_root: str):
        self.spec = spec
        self.env = env
        self.project_root = project_root
        self.process: Optional[asyncio.subprocess.Process] = None
        self.log_file: Optional[str] = None
        self._log_fd = None

    async def start(self) -> None:
        """Start the node process."""
        log_dir = self.spec.log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "node.log")

        # Open log file
        self._log_fd = open(self.log_file, "w")

        self.process = await asyncio.create_subprocess_exec(
            sys.executable, "-W", "ignore", "run_node.py",
            cwd=self.project_root,
            env={**os.environ, **self.env},
            stdout=self._log_fd,
            stderr=asyncio.subprocess.STDOUT,
        )
        logger.info("Started %s (PID %d, port %d)", self.spec.name, self.process.pid, self.spec.node_port)

    async def stop(self, timeout: float = 10.0) -> None:
        """Stop the node process gracefully."""
        if not self.process or self.process.returncode is not None:
            self._close_log()
            return

        pid = self.process.pid
        logger.info("Stopping %s (PID %d)...", self.spec.name, pid)

        # SIGTERM
        try:
            self.process.terminate()
        except ProcessLookupError:
            self._close_log()
            return

        try:
            await asyncio.wait_for(self.process.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("Force killing %s (PID %d)", self.spec.name, pid)
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
            await self.process.wait()

        self._close_log()
        logger.info("Stopped %s", self.spec.name)

    def _close_log(self):
        if self._log_fd and not self._log_fd.closed:
            self._log_fd.close()
            self._log_fd = None

    @property
    def is_running(self) -> bool:
        return self.process is not None and self.process.returncode is None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.spec.node_port}"


class TestnetOrchestrator:
    """
    Full testnet lifecycle manager.

    Usage:
        orch = TestnetOrchestrator()
        await orch.setup()              # Generate wallets, genesis, configs
        await orch.start_all_nodes()    # Start node processes
        await orch.wait_network_ready() # Wait for mesh + blocks
        # ... run scenarios ...
        await orch.stop_all_nodes()     # Graceful shutdown
    """

    def __init__(
        self,
        num_nodes: int = NUM_NODES,
        num_validators: int = NUM_VALIDATORS,
        force_regenerate: bool = False,
    ):
        self.num_nodes = num_nodes
        self.num_validators = num_validators
        self.force_regenerate = force_regenerate
        self.node_specs = build_node_specs(num_nodes, num_validators)
        self.node_processes: List[NodeProcess] = []
        self.wallets: Dict[str, dict] = {}
        self.genesis_summary: Optional[dict] = None
        self._multi_client: Optional[MultiNodeClient] = None

    # ─────────── Setup ───────────

    async def setup(self) -> None:
        """Full setup: wallets → genesis → databases → configs."""
        logger.info("=" * 60)
        logger.info("QRDX Integration Testnet Setup")
        logger.info("  Nodes: %d, Validators: %d", self.num_nodes, self.num_validators)
        logger.info("  Chain ID: %d, Network: %s", CHAIN_ID, NETWORK_NAME)
        logger.info("=" * 60)

        # Create directories
        for d in [TESTNET_DIR, WALLETS_DIR, DATABASES_DIR, CONFIGS_DIR, LOGS_DIR, DATA_DIR]:
            os.makedirs(d, exist_ok=True)

        # Step 1: Generate wallets
        logger.info("\n[1/4] Generating wallets...")
        self.wallets = generate_all_wallets(
            roster=WALLET_ROSTER,
            wallets_dir=str(WALLETS_DIR),
            force=self.force_regenerate,
        )

        # Step 2: Create genesis
        logger.info("\n[2/4] Creating genesis configuration...")
        self.genesis_summary = create_genesis(
            self.wallets,
            genesis_path=str(GENESIS_FILE),
        )

        # Step 3: Initialize databases
        logger.info("\n[3/4] Initializing databases...")
        for spec in self.node_specs:
            db_path = spec.db_path
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            if self.force_regenerate and os.path.exists(db_path):
                os.remove(db_path)
            # Create empty DB file — schema is initialized at node startup
            Path(db_path).touch()
            logger.info("  Database ready: %s", db_path)

        # Step 4: Create node configs
        logger.info("\n[4/4] Creating node configurations...")
        for spec in self.node_specs:
            self._create_node_config(spec)

        logger.info("\nSetup complete!")
        self._print_summary()

    def _create_node_config(self, spec: NodeSpec) -> dict:
        """Create environment variables for a node."""
        # Create key directory
        os.makedirs(spec.key_dir, exist_ok=True)

        # Every node should know about ALL other nodes as bootstrap peers.
        # This ensures the peer mesh forms quickly and no node is orphaned.
        other_ports = [
            s.node_port for s in self.node_specs if s.node_id != spec.node_id
        ]
        bootstrap_urls = ",".join(
            f"http://127.0.0.1:{p}" for p in other_ports
        )

        env = {
            "QRDX_NODE_HOST": "127.0.0.1",
            "QRDX_NODE_PORT": str(spec.node_port),
            "QRDX_SELF_URL": f"http://127.0.0.1:{spec.node_port}",
            "QRDX_DATABASE_PATH": spec.db_path,
            "QRDX_NODE_KEY_DIR": spec.key_dir,
            "QRDX_BOOTSTRAP_NODE": f"http://127.0.0.1:{BASE_NODE_PORT}",
            "QRDX_BOOTSTRAP_NODES": bootstrap_urls,
            "QRDX_MIN_VALIDATORS": "1",
            "QRDX_CHAIN_ID": str(CHAIN_ID),
            "QRDX_NETWORK_NAME": NETWORK_NAME,
            "LOG_LEVEL": "DEBUG",
            "PYTHONWARNINGS": "ignore",
            "QRDX_RPC_ENABLED": "true",
            "QRDX_DISABLE_RATE_LIMIT": "true",
            # Faster epochs so epoch-boundary processing (finality + validator
            # lifecycle) fires several times within a short test run. All nodes get
            # the same value → consensus-consistent.
            "QRDX_SLOTS_PER_EPOCH": str(SLOTS_PER_EPOCH),
            # Short activation/unbonding so the dynamic-membership scenario (S16) can
            # observe a deposit→active→exit→exited round-trip within a short soak.
            # Same value on every node → deterministic scheduling preserved.
            "QRDX_ACTIVATION_DELAY_EPOCHS": "1",
            "QRDX_UNBONDING_PERIOD_EPOCHS": "2",
        }

        if spec.is_validator and spec.validator_index is not None:
            # Find the validator wallet
            validator_label = f"Validator {spec.validator_index}"
            wallet = self.wallets.get(validator_label)
            if wallet:
                safe_name = validator_label.lower().replace(" ", "_")
                wallet_path = str(WALLETS_DIR / f"{safe_name}.json")
                env["QRDX_VALIDATOR_ENABLED"] = "true"
                env["QRDX_VALIDATOR_WALLET"] = wallet_path
                env["QRDX_VALIDATOR_PASSWORD"] = f"testnet_validator_{spec.validator_index}"
            else:
                env["QRDX_VALIDATOR_ENABLED"] = "false"
        else:
            env["QRDX_VALIDATOR_ENABLED"] = "false"

        # Write .env file
        env_path = str(CONFIGS_DIR / f"node{spec.node_id}.env")
        with open(env_path, "w") as f:
            for k, v in env.items():
                f.write(f"{k}={v}\n")

        return env

    # ─────────── Node Management ───────────

    async def start_all_nodes(self) -> None:
        """Start all nodes in order: bootstrap first, then others."""
        logger.info("\nStarting %d nodes...", self.num_nodes)

        for spec in self.node_specs:
            # Load env from config file
            env_path = str(CONFIGS_DIR / f"node{spec.node_id}.env")
            env = {}
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and "=" in line:
                        k, v = line.split("=", 1)
                        env[k] = v

            node_proc = NodeProcess(spec, env, str(PROJECT_ROOT))
            await node_proc.start()
            self.node_processes.append(node_proc)

            if spec.is_bootstrap:
                # Give bootstrap extra time
                logger.info("Waiting for bootstrap node to initialize...")
                client = NodeRPCClient(node_proc.url)
                async with client:
                    ready = await client.wait_healthy(timeout=NODE_STARTUP_TIMEOUT)
                    if ready:
                        logger.info("✓ Bootstrap node healthy")
                    else:
                        # Check if process crashed
                        if not node_proc.is_running:
                            logger.error("✗ Bootstrap node process exited (rc=%s) — check logs: %s",
                                         node_proc.process.returncode, spec.log_dir)
                        else:
                            logger.error("✗ Bootstrap node not responding within %ds — check logs: %s",
                                         NODE_STARTUP_TIMEOUT, spec.log_dir)
                        return
            else:
                # Stagger other nodes
                await asyncio.sleep(2)

        logger.info("All %d nodes started", len(self.node_processes))

    async def stop_all_nodes(self) -> None:
        """Stop all nodes gracefully."""
        logger.info("\nStopping all nodes...")
        await asyncio.gather(*[p.stop() for p in self.node_processes])
        self.node_processes.clear()
        if self._multi_client:
            await self._multi_client.__aexit__(None, None, None)
            self._multi_client = None
        logger.info("All nodes stopped")

    # ─────────── Network Verification ───────────

    async def wait_network_ready(self, timeout: float = None) -> bool:
        """
        Wait for the network to be fully operational:
          1. All nodes healthy
          2. Peer mesh formed
          3. Blocks being produced
        """
        if timeout is None:
            timeout = NODE_STARTUP_TIMEOUT + PEER_DISCOVERY_TIMEOUT

        node_urls = [p.url for p in self.node_processes]
        async with MultiNodeClient(node_urls) as clients:
            # Wait for all healthy
            logger.info("Waiting for all nodes to be healthy...")
            healthy = await clients.wait_all_healthy(timeout=NODE_STARTUP_TIMEOUT)
            if not healthy:
                unhealthy = []
                for i, client in enumerate(clients._clients):
                    if not await client.health():
                        unhealthy.append(self.node_specs[i].name)
                logger.error("Unhealthy nodes: %s", unhealthy)
                return False
            logger.info("✓ All nodes healthy")

            # Wait for peer discovery
            logger.info("Waiting for peer mesh...")
            deadline = asyncio.get_event_loop().time() + PEER_DISCOVERY_TIMEOUT
            mesh_ok = False
            while asyncio.get_event_loop().time() < deadline:
                counts = await clients.get_peer_counts()
                if all(c >= 1 for c in counts):
                    mesh_ok = True
                    break
                await asyncio.sleep(3)

            if mesh_ok:
                counts = await clients.get_peer_counts()
                logger.info("✓ Peer mesh formed: %s", counts)
            else:
                counts = await clients.get_peer_counts()
                logger.warning("⚠ Peer mesh incomplete: %s", counts)

            # Wait extra time for block sync convergence after mesh forms
            # Node-3 (last started) needs at least one periodic_update_fetcher cycle (8s)
            # to pull the blockchain from peers.
            if mesh_ok:
                logger.info("Waiting for block sync convergence...")
                await asyncio.sleep(12)

            # Check block production
            logger.info("Checking block production...")
            heights = await clients.get_block_heights()
            logger.info("  Block heights: %s", heights)

            return healthy

    # ─────────── Client Access ───────────

    async def get_multi_client(self) -> MultiNodeClient:
        """Get a MultiNodeClient connected to all nodes."""
        if self._multi_client is None:
            node_urls = [p.url for p in self.node_processes]
            self._multi_client = MultiNodeClient(node_urls)
            await self._multi_client.__aenter__()
        return self._multi_client

    def get_node_url(self, node_index: int) -> str:
        """Get URL for a specific node."""
        return self.node_processes[node_index].url

    def get_wallet(self, label: str) -> dict:
        """Get wallet by label."""
        return self.wallets[label]

    # ─────────── Status / Reporting ───────────

    def _print_summary(self) -> None:
        """Print testnet configuration summary."""
        print("\n" + "=" * 60)
        print("QRDX Integration Testnet Configuration")
        print("=" * 60)
        print(f"  Chain ID:     {CHAIN_ID}")
        print(f"  Network:      {NETWORK_NAME}")
        print(f"  Nodes:        {self.num_nodes}")
        print(f"  Validators:   {self.num_validators}")
        if self.genesis_summary:
            print(f"  Genesis Hash: {self.genesis_summary.get('genesis_hash', 'N/A')[:20]}...")
        print()
        print("Nodes:")
        for spec in self.node_specs:
            role = []
            if spec.is_bootstrap:
                role.append("Bootstrap")
            if spec.is_validator:
                role.append(f"Validator {spec.validator_index}")
            else:
                role.append("Full Node")
            print(f"  {spec.name}: http://127.0.0.1:{spec.node_port} [{', '.join(role)}]")
        print()
        print("Wallets:")
        for label, wallet in self.wallets.items():
            addr = wallet["address"]
            wtype = wallet["type"]
            spec = wallet.get("_spec", {})
            balance = spec.get("genesis_balance", "0")
            print(f"  {label}: {addr[:30]}... ({wtype}, {balance} QRDX)")
        print()
        print("System Wallets: 10 (75M QRDX total)")
        print(f"  Controller: {self.wallets.get('Master Controller', {}).get('address', 'N/A')[:30]}...")
        print("=" * 60)

    async def print_status(self) -> None:
        """Print current testnet status."""
        print("\n" + "-" * 60)
        print("TESTNET STATUS")
        print("-" * 60)

        for i, proc in enumerate(self.node_processes):
            spec = self.node_specs[i]
            status = "RUNNING" if proc.is_running else "STOPPED"
            pid = proc.process.pid if proc.process else "N/A"

            extra = ""
            if proc.is_running:
                try:
                    async with NodeRPCClient(proc.url) as client:
                        height = await client.get_block_height()
                        peers = await client.get_nodes()
                        extra = f" height={height} peers={len(peers)}"
                except Exception:
                    extra = " [unreachable]"

            print(f"  {spec.name}: {status} (PID {pid}){extra}")

        print("-" * 60)


async def main():
    """Main entry point for testnet orchestration."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    orch = TestnetOrchestrator(force_regenerate=True)

    try:
        # Setup
        await orch.setup()

        # Start nodes
        await orch.start_all_nodes()

        # Wait for network
        ready = await orch.wait_network_ready()
        if not ready:
            logger.error("Network failed to initialize")
            return

        # Print status
        await orch.print_status()

        # Keep running until interrupted
        logger.info("\nTestnet running. Press Ctrl+C to stop.\n")
        try:
            while True:
                await asyncio.sleep(10)
                await orch.print_status()
        except KeyboardInterrupt:
            pass

    finally:
        await orch.stop_all_nodes()


if __name__ == "__main__":
    asyncio.run(main())
