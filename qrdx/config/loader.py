"""
QRDX Unified TOML Configuration Loader

Loads all sections of config.toml at startup with environment variable overrides.
Follows the same pattern as qrdx/validator/config.py (dataclass + from_dict + from_file).

Environment variable mapping:
    [node] chain_id → QRDX_CHAIN_ID
    [rpc.http] port  → QRDX_RPC_HTTP_PORT
    ...

Sensitive values (passwords, keys) MUST come from env vars, never TOML.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib as tomli  # Python 3.11+
except ImportError:
    try:
        import tomli  # type: ignore[no-redef]
    except ImportError:
        tomli = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Subsection dataclasses — mirror every [section] of config.example.toml
# ---------------------------------------------------------------------------


@dataclass
class NodeSectionConfig:
    """[node] section."""
    node_id: str = ""
    chain_id: int = 1
    network_name: str = "qrdx-mainnet"
    data_dir: str = "./data"
    log_level: str = "INFO"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NodeSectionConfig":
        return cls(
            node_id=data.get("node_id", ""),
            chain_id=data.get("chain_id", 1),
            network_name=data.get("network_name", "qrdx-mainnet"),
            data_dir=data.get("data_dir", "./data"),
            log_level=data.get("log_level", "INFO"),
        )

    def apply_env(self) -> None:
        """Override from environment variables."""
        if v := os.environ.get("QRDX_CHAIN_ID"):
            self.chain_id = int(v)
        if v := os.environ.get("QRDX_NETWORK_NAME"):
            self.network_name = v
        if v := os.environ.get("QRDX_DATA_DIR"):
            self.data_dir = v
        if v := os.environ.get("QRDX_LOG_LEVEL"):
            self.log_level = v


# -- P2P ---------------------------------------------------------------

@dataclass
class DiscoveryConfig:
    """[p2p.discovery]."""
    enabled: bool = True
    bootnodes: List[str] = field(default_factory=lambda: [
        "http://node.qrdx.network:3007",
        "http://node2.qrdx.network:3007",
        "http://node3.qrdx.network:3007",
    ])
    dns_discovery: bool = False
    dns_networks: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveryConfig":
        return cls(
            enabled=data.get("enabled", True),
            bootnodes=data.get("bootnodes", cls.__dataclass_fields__["bootnodes"].default_factory()),
            dns_discovery=data.get("dns_discovery", False),
            dns_networks=data.get("dns_networks", []),
        )

    def apply_env(self) -> None:
        if v := os.environ.get("QRDX_BOOTSTRAP_NODES"):
            self.bootnodes = [n.strip() for n in v.split(",") if n.strip()]


@dataclass
class P2PSecurityConfig:
    """[p2p.security]."""
    post_quantum_enabled: bool = True
    pq_kem_algorithm: str = "Kyber768"
    pq_sig_algorithm: str = "Dilithium3"
    pq_required: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "P2PSecurityConfig":
        return cls(
            post_quantum_enabled=data.get("post_quantum_enabled", True),
            pq_kem_algorithm=data.get("pq_kem_algorithm", "Kyber768"),
            pq_sig_algorithm=data.get("pq_sig_algorithm", "Dilithium3"),
            pq_required=data.get("pq_required", False),
        )


@dataclass
class P2PConfig:
    """[p2p] section."""
    enabled: bool = True
    listen_addr: str = "0.0.0.0"
    listen_port: int = 30303
    discovery_port: int = 30303
    max_peers: int = 50
    max_pending_peers: int = 25
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    security: P2PSecurityConfig = field(default_factory=P2PSecurityConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "P2PConfig":
        discovery_data = data.get("discovery", {})
        security_data = data.get("security", {})
        return cls(
            enabled=data.get("enabled", True),
            listen_addr=data.get("listen_addr", "0.0.0.0"),
            listen_port=data.get("listen_port", 30303),
            discovery_port=data.get("discovery_port", 30303),
            max_peers=data.get("max_peers", 50),
            max_pending_peers=data.get("max_pending_peers", 25),
            discovery=DiscoveryConfig.from_dict(discovery_data),
            security=P2PSecurityConfig.from_dict(security_data),
        )

    def apply_env(self) -> None:
        if v := os.environ.get("QRDX_P2P_PORT"):
            self.listen_port = int(v)
        if v := os.environ.get("QRDX_MAX_PEERS"):
            self.max_peers = int(v)
        self.discovery.apply_env()


# -- Database -----------------------------------------------------------

@dataclass
class SQLiteConfig:
    """[database.sqlite]."""
    path: str = "data/qrdx.db"
    wal_mode: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SQLiteConfig":
        return cls(
            path=data.get("path", "data/qrdx.db"),
            wal_mode=data.get("wal_mode", True),
        )

    def apply_env(self) -> None:
        if v := os.environ.get("QRDX_DB_PATH"):
            self.path = v


@dataclass
class DatabaseConfig:
    """[database] section."""
    type: str = "sqlite"
    sqlite: SQLiteConfig = field(default_factory=SQLiteConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatabaseConfig":
        sqlite_data = data.get("sqlite", {})
        return cls(
            type=data.get("type", "sqlite"),
            sqlite=SQLiteConfig.from_dict(sqlite_data),
        )

    def apply_env(self) -> None:
        self.sqlite.apply_env()


# -- Genesis ------------------------------------------------------------

@dataclass
class GenesisConfig:
    """[genesis] section."""
    chain_id: int = 1
    network_name: str = "qrdx-mainnet"
    initial_supply: int = 100_000_000
    genesis_time: int = 0
    prefunded_accounts: Dict[str, list] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GenesisConfig":
        return cls(
            chain_id=data.get("chain_id", 1),
            network_name=data.get("network_name", "qrdx-mainnet"),
            initial_supply=data.get("initial_supply", 100_000_000),
            genesis_time=data.get("genesis_time", 0),
            prefunded_accounts=data.get("prefunded_accounts", {}),
        )


# -- Consensus ----------------------------------------------------------

@dataclass
class PoSConfig:
    """[consensus.pos]."""
    slot_duration: int = 2
    slots_per_epoch: int = 32
    attestation_threshold: float = 0.667

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PoSConfig":
        return cls(
            slot_duration=data.get("slot_duration", 2),
            slots_per_epoch=data.get("slots_per_epoch", 32),
            attestation_threshold=data.get("attestation_threshold", 0.667),
        )


@dataclass
class ConsensusConfig:
    """[consensus] section."""
    mechanism: str = "pos"
    pos: PoSConfig = field(default_factory=PoSConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConsensusConfig":
        pos_data = data.get("pos", {})
        return cls(
            mechanism=data.get("mechanism", "pos"),
            pos=PoSConfig.from_dict(pos_data),
        )


# -- Sync ---------------------------------------------------------------

@dataclass
class SyncConfig:
    """[sync] section."""
    mode: str = "full"
    batch_size: int = 128

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SyncConfig":
        return cls(
            mode=data.get("mode", "full"),
            batch_size=data.get("batch_size", 128),
        )


# -- Metrics / Health ---------------------------------------------------

@dataclass
class MetricsConfig:
    """[metrics] section."""
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 9090

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MetricsConfig":
        return cls(
            enabled=data.get("enabled", False),
            host=data.get("host", "127.0.0.1"),
            port=data.get("port", 9090),
        )

    def apply_env(self) -> None:
        if v := os.environ.get("QRDX_METRICS_ENABLED"):
            self.enabled = v.lower() in ("1", "true", "yes")
        if v := os.environ.get("QRDX_METRICS_PORT"):
            self.port = int(v)


@dataclass
class HealthConfig:
    """[health] section."""
    enabled: bool = True
    path: str = "/health"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HealthConfig":
        return cls(
            enabled=data.get("enabled", True),
            path=data.get("path", "/health"),
        )


# -- TLS ----------------------------------------------------------------

@dataclass
class TLSConfig:
    """TLS configuration for all external interfaces."""
    enabled: bool = False
    cert_file: str = ""
    key_file: str = ""
    ca_file: str = ""
    # Minimum TLS version (1.2 or 1.3)
    min_version: str = "1.2"
    # Require client certificate
    client_auth: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TLSConfig":
        return cls(
            enabled=data.get("enabled", False),
            cert_file=data.get("cert_file", ""),
            key_file=data.get("key_file", ""),
            ca_file=data.get("ca_file", ""),
            min_version=data.get("min_version", "1.2"),
            client_auth=data.get("client_auth", False),
        )

    def apply_env(self) -> None:
        if v := os.environ.get("QRDX_TLS_CERT"):
            self.cert_file = v
        if v := os.environ.get("QRDX_TLS_KEY"):
            self.key_file = v
        if v := os.environ.get("QRDX_TLS_CA"):
            self.ca_file = v

    def validate(self) -> None:
        """Validate TLS config if enabled."""
        if not self.enabled:
            return
        if not self.cert_file:
            raise ValueError("TLS enabled but cert_file not set")
        if not self.key_file:
            raise ValueError("TLS enabled but key_file not set")
        if self.min_version not in ("1.2", "1.3"):
            raise ValueError(f"Invalid TLS min_version: {self.min_version}")
        if not Path(self.cert_file).exists():
            raise ValueError(f"TLS cert file not found: {self.cert_file}")
        if not Path(self.key_file).exists():
            raise ValueError(f"TLS key file not found: {self.key_file}")
        if self.ca_file and not Path(self.ca_file).exists():
            raise ValueError(f"TLS CA file not found: {self.ca_file}")


# -----------------------------------------------------------------------
# Top-level unified config
# -----------------------------------------------------------------------

@dataclass
class NodeConfig:
    """
    Unified node configuration.

    Loads every section of config.toml and applies environment variable
    overrides.  This is the single source of truth at runtime.
    """
    node: NodeSectionConfig = field(default_factory=NodeSectionConfig)
    p2p: P2PConfig = field(default_factory=P2PConfig)
    rpc: Optional[Any] = None          # qrdx.rpc.config.RPCConfig
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    genesis: GenesisConfig = field(default_factory=GenesisConfig)
    consensus: ConsensusConfig = field(default_factory=ConsensusConfig)
    validator: Optional[Any] = None    # qrdx.validator.config.ValidatorConfig
    sync: SyncConfig = field(default_factory=SyncConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    health: HealthConfig = field(default_factory=HealthConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)

    # --- factories --------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NodeConfig":
        """Create NodeConfig from a parsed TOML dict."""
        # Lazy imports to avoid circular dependencies
        from qrdx.rpc.config import RPCConfig
        from qrdx.validator.config import ValidatorConfig

        rpc_data = data.get("rpc", {})
        validator_data = data.get("validator", {})

        return cls(
            node=NodeSectionConfig.from_dict(data.get("node", {})),
            p2p=P2PConfig.from_dict(data.get("p2p", {})),
            rpc=RPCConfig.from_dict(rpc_data),
            database=DatabaseConfig.from_dict(data.get("database", {})),
            genesis=GenesisConfig.from_dict(data.get("genesis", {})),
            consensus=ConsensusConfig.from_dict(data.get("consensus", {})),
            validator=ValidatorConfig.from_dict(validator_data),
            sync=SyncConfig.from_dict(data.get("sync", {})),
            metrics=MetricsConfig.from_dict(data.get("metrics", {})),
            health=HealthConfig.from_dict(data.get("health", {})),
            tls=TLSConfig.from_dict(data.get("tls", {})),
        )

    @classmethod
    def from_file(cls, config_path: str) -> "NodeConfig":
        """
        Load configuration from a TOML file.

        Args:
            config_path: Path to config.toml

        Returns:
            NodeConfig instance
        """
        if tomli is None:
            raise ImportError(
                "tomli is required for TOML config loading. "
                "Install it: pip install tomli"
            )

        path = Path(config_path)
        if not path.exists():
            logger.warning("Config file not found: %s — using defaults", config_path)
            cfg = cls()
            cfg.apply_env()
            return cfg

        with open(path, "rb") as f:
            raw = tomli.load(f)

        cfg = cls.from_dict(raw)
        cfg.apply_env()
        return cfg

    # --- env overrides ----------------------------------------------------

    def apply_env(self) -> None:
        """Apply environment variable overrides to all sections."""
        self.node.apply_env()
        self.p2p.apply_env()
        self.database.apply_env()
        self.metrics.apply_env()
        self.tls.apply_env()

        # RPC env overrides
        if v := os.environ.get("QRDX_RPC_HTTP_PORT"):
            if self.rpc:
                self.rpc.http.port = int(v)
        if v := os.environ.get("QRDX_RPC_WS_PORT"):
            if self.rpc:
                self.rpc.websocket.port = int(v)

    # --- validation -------------------------------------------------------

    def validate(self) -> bool:
        """
        Validate all configuration sections.

        Returns:
            True if all valid

        Raises:
            ValueError: on invalid config
        """
        if self.node.chain_id < 1:
            raise ValueError("chain_id must be >= 1")
        if self.node.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"Invalid log_level: {self.node.log_level}")
        if self.p2p.max_peers < 1:
            raise ValueError("max_peers must be >= 1")
        if self.database.type != "sqlite":
            raise ValueError("Only 'sqlite' database type is supported")
        self.tls.validate()
        return True

    # --- serialisation ----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict (for diagnostics, NOT for re-creating TOML)."""
        result: Dict[str, Any] = {
            "node": {
                "chain_id": self.node.chain_id,
                "network_name": self.node.network_name,
                "data_dir": self.node.data_dir,
                "log_level": self.node.log_level,
            },
            "p2p": {
                "enabled": self.p2p.enabled,
                "listen_port": self.p2p.listen_port,
                "max_peers": self.p2p.max_peers,
                "security": {
                    "post_quantum_enabled": self.p2p.security.post_quantum_enabled,
                    "pq_kem_algorithm": self.p2p.security.pq_kem_algorithm,
                    "pq_sig_algorithm": self.p2p.security.pq_sig_algorithm,
                },
            },
            "database": {
                "type": self.database.type,
                "sqlite": {
                    "path": self.database.sqlite.path,
                    "wal_mode": self.database.sqlite.wal_mode,
                },
            },
            "consensus": {
                "mechanism": self.consensus.mechanism,
            },
            "sync": {
                "mode": self.sync.mode,
                "batch_size": self.sync.batch_size,
            },
            "metrics": {
                "enabled": self.metrics.enabled,
                "host": self.metrics.host,
                "port": self.metrics.port,
            },
            "health": {
                "enabled": self.health.enabled,
                "path": self.health.path,
            },
            "tls": {
                "enabled": self.tls.enabled,
                "min_version": self.tls.min_version,
            },
        }
        return result


# -----------------------------------------------------------------------
# Convenience function
# -----------------------------------------------------------------------

def load_config(path: Optional[str] = None) -> NodeConfig:
    """
    Load node configuration.

    Resolution order:
        1. Explicit *path* argument
        2. QRDX_CONFIG env var
        3. ./config.toml in current directory
        4. Defaults (with env overrides)
    """
    if path is None:
        path = os.environ.get("QRDX_CONFIG", "config.toml")

    return NodeConfig.from_file(path)
