"""
The QRDX node: the FastAPI app, the node's state and its startup and shutdown.

The node's behaviour lives in modules by concern (docs/NODE_LAYOUT.md): block import
(block_import), fork choice, sync, peers, discovery, the EVM runtime, derived state, chain
identity, request security, and the REST API (qrdx/node/api/). They read the state defined
here (the database, the HTTP client, the EVM and exchange runtimes, this node's identity) at
call time, as ``_node.<name>``: startup rebinds it, and tests replace it.
"""

import asyncio
import json
import os
import re
import time
import traceback
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.background import BackgroundTasks
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request

from qrdx import fastjson
from qrdx.constants import (
    CHAIN_SPEC,
    CHAIN_SPEC_ENV_CONFLICTS,
    CHAIN_SPEC_FILE,
    CONNECTION_TIMEOUT,
    DENARO_DATABASE_PATH,
    DENARO_NODE_HOST,
    DENARO_NODE_PORT,
    DENARO_SELF_URL,
    LOG_INCLUDE_REQUEST_CONTENT,
    LOG_INCLUDE_RESPONSE_CONTENT,
    LOG_MAX_PATH_LENGTH,
    NODE_VERSION,
)
from qrdx.database_sqlite import DatabaseSQLite as Database
from qrdx.helpers import sha256
from qrdx.logger import get_logger
from qrdx.manager import create_block
from qrdx.node.identity import get_node_id, initialize_identity
from qrdx.node.nodes_manager import NodeInterface, NodesManager
from qrdx.node.security import SecureNodeComponents, TimeBasedCache, rate_limit_key_func

# Kademlia DHT integration
from qrdx.p2p.config import DiscoveryConfig
from qrdx.p2p.discovery import KademliaDiscovery
from qrdx.p2p.dns_seeds import DNSSeedDiscovery

logger = get_logger(__name__)


# ============================================================================
# APPLICATION SETUP
# ============================================================================

# Both set at startup, before the app serves a request.
db: Database = None  # type: ignore[assignment]
self_node_id: str = None  # type: ignore[assignment]
self_is_public: bool = False

app_servers = [{"url": str(DENARO_SELF_URL)}] if DENARO_SELF_URL else []
app = FastAPI(
    servers=app_servers,
    title="QRDX Node",
    description="Full node for the QRDX blockchain.",
    version=NODE_VERSION,
)

limiter = Limiter(key_func=rate_limit_key_func)
# Allow testnet / integration-test environments to disable rate limiting
# so that automated test clients can exercise endpoints without hitting 429s.
if os.environ.get("QRDX_DISABLE_RATE_LIMIT", "").lower() in ("1", "true", "yes"):
    limiter.enabled = False
app.state.limiter = limiter
# slowapi types its handler for RateLimitExceeded; Starlette's signature says Exception.
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Initialize security components
security = SecureNodeComponents()

# Track startup time
startup_time = time.time()

# ─── Operational-readiness surface: health / metrics / realtime streaming ─────────────
# Monitoring (health + Prometheus metrics) is ALWAYS on; the realtime WebSocket/SSE stream is
# TOGGLEABLE (opt-in per operator) via QRDX_ENABLE_STREAMING. The stream is fed by a consensus-
# decoupled poller (reads chain tip/finality only) so it can never stall or diverge block import.
from qrdx.node.observability import (
    CHAIN_CHANGED,
    EVENT_HUB,
    METRICS,
    SignallingLock,
    chain_event_poller,
)

STREAMING_ENABLED = os.environ.get("QRDX_ENABLE_STREAMING", "").lower() in ("1", "true", "yes")
_chain_poller_task: Optional[asyncio.Task] = None


# Connection pool for HTTP requests
# Created at startup (and closed at shutdown); every peer call runs in between.
http_client: httpx.AsyncClient = None  # type: ignore[assignment]

# Kademlia DHT subsystem
dht_discovery: Optional[KademliaDiscovery] = None
dht_dns_seeds: Optional[DNSSeedDiscovery] = None
dht_config: DiscoveryConfig = DiscoveryConfig()

# ---- Always-on JSON-RPC server (required for DHT inter-node protocol) ----
from qrdx.rpc.modules.dht import DHTModule
from qrdx.rpc.modules.p2p import P2PModule
from qrdx.rpc.server import RPCServer, rpc_caller, rpc_caller_meta

# Calls a second: from one address, from all public callers together, from one peer, and from all
# of this node's peers together. Node-local operator settings; integration_tests/load.py raises the
# public two, since all its load comes from one address.
rpc_server = RPCServer(
    per_client_rps=int(os.environ.get("QRDX_RPC_CLIENT_RPS", "50")),
    global_rps=int(os.environ.get("QRDX_RPC_GLOBAL_RPS", "500")),
    # Peers gossip every transaction to each other, a call each: at the protocol's 2,000
    # transfers a second, about 2,000 calls a second from each peer (docs/PERFORMANCE.md).
    per_peer_rps=int(os.environ.get("QRDX_RPC_PEER_RPS", "4000")),
    peer_rps=int(os.environ.get("QRDX_RPC_PEER_POOL_RPS", "16000")),
)

# Register DHT module unconditionally — it's core networking, not optional
dht_rpc_module = DHTModule()
rpc_server.register_module(dht_rpc_module)

# Register P2P module unconditionally — block/tx propagation over JSON-RPC
p2p_rpc_module = P2PModule()
rpc_server.register_module(p2p_rpc_module)


# Exchange + perps JSON-RPC (exchange_* / perp_*), unconditionally: wallets need them on any node,
# and exchange_sendTransaction is also how nodes gossip exchange transactions to each other.
class _ExchangeRPCContext:
    """Resolved at call time: ``db`` and the HTTP client exist only after startup."""

    @property
    def db(self):
        return db

    @property
    def submitter(self):
        return _get_exchange_submitter()


from qrdx.rpc.modules.exchange import ExchangeModule, MarketModule, PerpModule

exchange_rpc_module = ExchangeModule()
exchange_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(exchange_rpc_module)
perp_rpc_module = PerpModule()
perp_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(perp_rpc_module)
market_rpc_module = MarketModule()
market_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(market_rpc_module)
from qrdx.rpc.modules.exchange import AccountModule, QnsModule

account_rpc_module = AccountModule()
account_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(account_rpc_module)
qns_rpc_module = QnsModule()
qns_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(qns_rpc_module)
from qrdx.rpc.modules.history import HistoryModule

history_rpc_module = HistoryModule()
history_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(history_rpc_module)
from qrdx.rpc.modules.history import TradingHistoryModule

trading_history_rpc_module = TradingHistoryModule()
trading_history_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(trading_history_rpc_module)
# State proofs against signed state roots (state_*, docs/STATE_PROOFS.md).
from qrdx.rpc.modules.state import StateModule

state_rpc_module = StateModule()
state_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(state_rpc_module)
# On-chain governance reads (governance_*); its writes are exchange transactions.
from qrdx.rpc.modules.governance import GovernanceModule

governance_rpc_module = GovernanceModule()
governance_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(governance_rpc_module)
# Consensus bridge reads (bridge_*, docs/BRIDGE.md); withdrawals are exchange transactions.
from qrdx.rpc.modules.bridge_ledger import BridgeLedgerModule

bridge_rpc_module = BridgeLedgerModule()
bridge_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(bridge_rpc_module)
# Staking and delegation pools (staking_*, docs/STAKING.md); writes are exchange transactions.
from qrdx.rpc.modules.staking import StakingModule

staking_rpc_module = StakingModule()
staking_rpc_module.context = _ExchangeRPCContext()
rpc_server.register_module(staking_rpc_module)


def _rpc_auth_error(request_body: Any, message: str) -> Response:
    rid = request_body.get("id") if isinstance(request_body, dict) else None
    payload = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32099, "message": message}}
    return Response(content=json.dumps(payload), media_type="application/json")


@app.post("/rpc")
async def rpc_endpoint(request: Request):
    """JSON-RPC 2.0 endpoint. A signed request (x-node-id / x-public-key / x-signature over the
    exact body, timestamp and nonce) is attributed to the verified node (``rpc_caller``); a
    signature that does not hold is refused outright. Methods marked ``@peer_only`` (blocks,
    transactions, attestations, the handshake) are refused by the RPC server without a verified
    caller; reads may come unsigned — what they return is verified by whoever uses it."""
    raw = await request.body()
    try:
        parsed = fastjson.loads(raw)
    except ValueError:
        parsed = None  # handle_request answers with the JSON-RPC parse error

    caller: Optional[str] = None
    if request.headers.get("x-signature"):
        caller = await _peers.get_verified_sender(request)
        if caller is None:
            return _rpc_auth_error(parsed, "invalid or replayed peer signature")

    token = rpc_caller.set(caller)
    meta_token = rpc_caller_meta.set(
        {
            "pubkey": request.headers.get("x-public-key"),
            "url": request.headers.get("x-peer-url"),
            "ip": request.client.host if request.client else None,
        }
        if caller
        else None
    )
    try:
        # One of this node's peers draws on the peers' pool, by its node id. Anyone else is limited
        # by address, signed or not: a fresh key per request would otherwise be a fresh limit.
        ip = request.client.host if request.client else "anonymous"
        peer_id = caller if caller and NodesManager.get_peer(caller) is not None else None
        is_peer = peer_id is not None
        # (parsed once: what failed to parse goes as it came, for the parse error)
        result = await rpc_server.handle_request(
            parsed if parsed is not None else raw, client_id=peer_id or ip, peer=is_peer
        )
    finally:
        rpc_caller.reset(token)
        rpc_caller_meta.reset(meta_token)
    if result is None:
        return Response(status_code=204)
    # handle_request returns a JSON string; send it raw to avoid double-encoding
    return Response(content=result, media_type="application/json")


# Held by every path that changes the chain. Releasing it raises CHAIN_CHANGED, which wakes the
# realtime publishers (qrdx/node/observability.py): a flag, never awaited.
block_processing_lock = SignallingLock(CHAIN_CHANGED)

# Seen-cache for EVM / account-model transactions (keyed by keccak(raw_tx)).
# Prevents double execution and terminates gossip loops in Phase 1 cross-node
# convergence. See docs/archive/EVM_STATE_CONSENSUS_INTEGRATION.md.
EVM_TX_CACHE = TimeBasedCache(max_size=4096, ttl_seconds=600)

# Exchange-transaction admission mempool (Phase D1). Lazily created so the
# exchange module is only imported when an exchange tx is actually submitted.
# See docs/EXCHANGE_PRODUCTION_READINESS.md §4 Phase D1.
EXCHANGE_MEMPOOL = None


def _get_exchange_mempool():
    global EXCHANGE_MEMPOOL
    if EXCHANGE_MEMPOOL is None:
        from qrdx.exchange import ExchangeMempool

        EXCHANGE_MEMPOOL = ExchangeMempool()
    return EXCHANGE_MEMPOOL


# The one exchange write path (REST, JSON-RPC, CLI wallet): admit to the mempool, then gossip what
# is new to peers over exchange_sendTransaction, so any validator can include it — not only the
# node a wallet happened to submit to. See qrdx/exchange/submission.py.
EXCHANGE_SUBMITTER = None


def _get_exchange_submitter():
    global EXCHANGE_SUBMITTER
    if EXCHANGE_SUBMITTER is None:
        from qrdx.exchange.submission import ExchangeSubmitter

        def _peer_urls():
            return [p.get("url") for p in NodesManager.get_propagate_peers()]

        async def _forward(url, tx_dict):
            return await NodeInterface(url, client=http_client, db=db)._rpc_call(
                "exchange_sendTransaction", [tx_dict, True]
            )

        async def _forward_batch(url, tx_dicts):
            return await NodeInterface(url, client=http_client, db=db)._rpc_batch(
                [("exchange_sendTransaction", [tx, True]) for tx in tx_dicts]
            )

        async def _forward_batch_to_all(urls, tx_dicts):
            prepared = await NodeInterface.prepare_batch(
                [("exchange_sendTransaction", [tx, True]) for tx in tx_dicts]
            )
            await asyncio.gather(
                *[
                    NodeInterface(u, client=http_client, db=db).post_prepared_batch(prepared)
                    for u in urls
                ],
                return_exceptions=True,
            )

        async def _announce(url, hashes):
            ni = NodeInterface(url, client=http_client, db=db)
            reply = ni._unwrap(await ni._rpc_call("exchange_announceTransactions", [hashes]))
            return reply.get("result") if reply and reply.get("ok") else []

        async def _balance(address):
            return await db.get_address_balance(address)

        async def _balances(addresses):
            return await db.get_address_balances(addresses)

        EXCHANGE_SUBMITTER = ExchangeSubmitter(
            _get_exchange_mempool,
            _peer_urls,
            _forward,
            get_balance=_balance,
            forward_batch=_forward_batch,
            announce=_announce,
            get_balances=_balances,
            forward_batch_to_all=_forward_batch_to_all,
        )
    return EXCHANGE_SUBMITTER


# EVM/account consensus path (Phase 2 / E-D3). The executor + state manager are
# set when the contract RPC system initializes; the mempool admits eth txs for
# block inclusion. EVM_PENDING_NONCE tracks each sender's next expected account
# nonce for mempool admission (updated as txs are applied).
EVM_EXECUTOR = None
EVM_STATE_MANAGER = None
EVM_MEMPOOL = None
EVM_PENDING_NONCE: Dict[str, int] = {}


def _get_evm_mempool():
    global EVM_MEMPOOL
    if EVM_MEMPOOL is None:
        from qrdx.contracts.evm_mempool import EVMMempool

        EVM_MEMPOOL = EVMMempool(nonce_provider=lambda addr: EVM_PENDING_NONCE.get(addr.lower(), 0))
    return EVM_MEMPOOL


def _warn_slow_crypto() -> None:
    """Without coincurve (a release dependency), eth-keys recovers each EVM transaction's sender
    in pure Python — ~15 ms instead of ~0.1 ms — and this node falls behind any block carrying
    many (docs/BLOCK_LIMITS.md). Same results, so it is a warning, not a refusal."""
    try:
        from eth_keys.backends import get_backend

        backend = type(get_backend()).__name__
    except Exception as e:
        backend = f"unavailable ({e})"
    if "CoinCurve" not in backend:
        logger.error(
            f"secp256k1 runs on the {backend} backend, not coincurve: install the release "
            "dependencies (release/requirements.lock) — this node verifies EVM transactions ~100x "
            "slower and will fall behind full blocks"
        )


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Access log of every HTTP request, at DEBUG. Peers call each other constantly, and two
    INFO lines per request through the rich console handler cost a validator a measurable
    share of its event loop; with DEBUG off this returns straight away."""
    import logging as _logging
    import time

    if not logger.isEnabledFor(_logging.DEBUG):
        return await call_next(request)

    start_time = time.time()

    # Get client IP
    client_ip = request.client.host if request.client else "unknown"

    # Build request path with query params
    method = request.method
    path = request.url.path
    query_params = str(request.query_params) if request.query_params else ""
    full_path = f"{path}?{query_params}" if query_params else path

    # Truncate very long paths to prevent log spam from malicious requests
    if len(full_path) > LOG_MAX_PATH_LENGTH:
        full_path = full_path[:LOG_MAX_PATH_LENGTH] + "...[TRUNCATED]"

    # Extract and format request body if present
    body = None
    body_bytes = None
    if LOG_INCLUDE_REQUEST_CONTENT:
        try:
            # Check if request has a body
            content_length = request.headers.get("content-length")

            if content_length and int(content_length) > 0:
                # Read body bytes (this consumes the body, so we'll restore it)
                body_bytes = await request.body()

                if body_bytes:
                    # Try to parse as JSON
                    try:
                        body_str = body_bytes.decode("utf-8")
                        parsed_value = json.loads(body_str)

                        # Skip empty collections
                        if isinstance(parsed_value, (dict, list)) and len(parsed_value) == 0:
                            body = None
                        else:
                            # Format as pretty JSON
                            body = json.dumps(parsed_value, indent=2)
                    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                        # Not JSON or not valid UTF-8, use raw string
                        body_str = body_bytes.decode("utf-8", errors="replace")
                        if len(body_str) > 0:
                            body = body_str
                        else:
                            body = None
        except Exception:
            # Silently fail body extraction to not break request processing
            body = None
            body_bytes = None

    # Restore request body if we read it (so endpoints can still access it)
    if body_bytes is not None:

        async def receive():
            return {"type": "http.request", "body": body_bytes}

        request._receive = receive

    # Log incoming request
    request_body_log = f"\n\nIncoming Request:\n{body}\n" if body else ""
    logger.debug(f'<-- {client_ip} - "{method} {full_path} HTTP/1.1"{request_body_log}')

    # Process request
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        status_code = response.status_code

        # Extract and format response body if present
        response_body = None
        if LOG_INCLUDE_RESPONSE_CONTENT and hasattr(response, "body_iterator"):
            try:
                # Read response body
                response_body_bytes = b""
                async for chunk in response.body_iterator:
                    response_body_bytes += chunk

                # Always recreate response with the body so client still receives it
                # (body_iterator is consumed after reading)
                response = Response(
                    content=response_body_bytes,
                    status_code=status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                )

                # Format body for logging
                if response_body_bytes:
                    try:
                        response_body_str = response_body_bytes.decode("utf-8")
                        parsed_value = json.loads(response_body_str)

                        # Skip empty collections
                        if isinstance(parsed_value, (dict, list)) and len(parsed_value) == 0:
                            response_body = None
                        else:
                            # Format as pretty JSON
                            response_body = json.dumps(parsed_value, indent=2)
                    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                        # Not JSON or not valid UTF-8, use raw string
                        response_body_str = response_body_bytes.decode("utf-8", errors="replace")
                        if len(response_body_str) > 0:
                            response_body = response_body_str
                        else:
                            response_body = None
            except Exception:
                # Silently fail response body extraction, return original response
                response_body = None

        # Log response
        response_body_log = f"\n\nOutgoing Response:\n{response_body}\n" if response_body else ""
        logger.debug(
            f'--> {client_ip} - "{method} {full_path} HTTP/1.1" {status_code}⁢ ({process_time:.3f}s){response_body_log}'
        )

        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(
            f'--> {client_ip} - "{method} {full_path} HTTP/1.1" ERROR ({process_time:.3f}s){request_body_log}: {e}'
        )
        raise


# ============================================================================
# CHAIN IDENTITY — chain spec, genesis, fork id (docs/PROTOCOL_UPGRADES.md)
# ============================================================================

# This chain's genesis block hash, set once startup has verified the database against the
# chain spec. With the spec, it is the identity every peer must share.
GENESIS_BLOCK_HASH: Optional[str] = None


# ============================================================================
# APPLICATION STARTUP/SHUTDOWN
# ============================================================================


@app.on_event("startup")
async def startup():
    global db, self_node_id, http_client, EVM_EXECUTOR, EVM_STATE_MANAGER, GENESIS_BLOCK_HASH

    logger.info("Starting Denaro Node Server...")

    # Consensus comes from the chain spec alone on a non-dev network. An environment setting that
    # tries to change it would make this node apply different rules from its network.
    if CHAIN_SPEC_ENV_CONFLICTS:
        for problem in CHAIN_SPEC_ENV_CONFLICTS:
            logger.critical(f"[chain-spec] {problem}")
        raise _identity.ChainIdentityError(
            f"{len(CHAIN_SPEC_ENV_CONFLICTS)} environment setting(s) conflict with the "
            f"{CHAIN_SPEC.network} chain spec ({CHAIN_SPEC_FILE}); remove them to start"
        )
    logger.info(
        f"[chain-spec] network {CHAIN_SPEC.network} (chain id {CHAIN_SPEC.chain_id}"
        f"{', dev' if CHAIN_SPEC.dev else ''}), spec {CHAIN_SPEC.genesis_hash()[:16]}… from "
        f"{CHAIN_SPEC_FILE or 'the environment (no genesis file)'}; "
        f"{len(CHAIN_SPEC.forks)} scheduled fork(s)"
    )

    # Initialize the shared HTTP client for the application's lifespan
    http_client = httpx.AsyncClient(timeout=CONNECTION_TIMEOUT)
    logger.info("Shared HTTP client initialized.")

    # Initialize security components
    await security.startup()

    os.makedirs(_discovery._p2p_state_dir(), exist_ok=True)
    NodesManager.db_path = os.path.join(_discovery._p2p_state_dir(), "nodes.json")
    NodesManager.purge_peers()
    initialize_identity()
    self_node_id = get_node_id()
    NodesManager.init(self_node_id)

    # Initialize SQLite database
    db_path = str(DENARO_DATABASE_PATH) if DENARO_DATABASE_PATH else "data/qrdx.db"
    logger.info(f"Using SQLite database: {db_path}")

    # Ensure the database directory exists
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)

    db = await Database.create(db_path=db_path)

    logger.info("Clearing pending transaction pool.")
    await db.remove_all_pending_transactions()
    logger.info("Pending transaction pool cleared.")

    # Initialize genesis if needed (PoS). The genesis file is the one the chain spec was loaded
    # from (QRDX_GENESIS_FILE, or genesis_config.json two levels above the database); without
    # one this is a dev network. Any failure stops startup — there is no fallback genesis.
    logger.info("Checking genesis state...")
    from ..validator.genesis_init import initialize_genesis_if_needed

    if CHAIN_SPEC_FILE:
        logger.info(f"Genesis configuration: {CHAIN_SPEC_FILE}")
    genesis_created = await initialize_genesis_if_needed(
        db, genesis_file=CHAIN_SPEC_FILE, chain_spec=CHAIN_SPEC
    )
    if genesis_created:
        logger.info("Genesis block created for PoS network")
    else:
        logger.info("Genesis block already exists")

    # The database must belong to this chain spec before anything applies a block to it.
    GENESIS_BLOCK_HASH = await _identity._verify_chain_identity()
    _warn_slow_crypto()
    await _identity._verify_trusted_checkpoints()
    try:  # a full node's history window (qrdx/history_pruning.py): refuse a bad one at once
        from ..history_pruning import retention as _history_retention

        _window = _history_retention()
    except ValueError as e:
        raise SystemExit(f"[startup] {e}") from e
    if _window:
        logger.info(f"[history] full node: block bodies kept for {_window} blocks below finality")
    _next = CHAIN_SPEC.next_fork(max(0, await db.get_next_block_id() - 1))
    logger.info(
        f"[chain-spec] genesis {GENESIS_BLOCK_HASH[:16]}… verified; "
        + (
            f"next fork {_next['name']} at height {_next['height']} "
            f"(features: {', '.join(_next['features']) or '—'})"
            if _next
            else "no fork scheduled"
        )
    )

    # Contract system (EVM executor + account-state manager). Initialised here, ahead of
    # the RPC modules that also use it, because the startup rebuild below replays EVM
    # sections through it — and because block production and sync, which start before the
    # RPC modules are registered, must never run with EVM state uninitialised.
    if os.getenv("QRDX_RPC_ENABLED", "false").lower() == "true":
        try:
            from ..contracts import ContractStateManager, QRDXEVMExecutor

            logger.info("Initializing contract execution system...")
            EVM_STATE_MANAGER = ContractStateManager(db)
            EVM_EXECUTOR = QRDXEVMExecutor(EVM_STATE_MANAGER)
            # Writers that change account_state directly (the exchange's balance flush,
            # withdrawals) make the manager forget its cached copy of that account.
            db.account_write_listeners = [EVM_STATE_MANAGER.invalidate]
            logger.info("✅ Contract system initialized")
        except Exception as e:
            EVM_STATE_MANAGER = EVM_EXECUTOR = None
            logger.error(f"Contract system initialization failed: {e}")

    # Derived state (exchange in memory; account_state + token ledger durable) rebuilt from
    # the canonical chain, so it survives a restart / fresh resync with the network's
    # accept/reject decisions (see _rebuild_derived_state_on_startup).
    await _derived._rebuild_derived_state_on_startup()

    # Bring the chain index (qrdx/chain_index.py) up to the tip now, once, before the validator
    # starts — not inside a slot. It persists, so this is quick after the first start.
    try:
        from ..chain_index import sync as _sync_chain_index

        _t0 = time.time()
        _indexed = await _sync_chain_index(db)
        await db.connection.commit()
        logger.info("Chain index up to height %d (%.1fs)", _indexed, time.time() - _t0)
    except Exception as e:
        logger.warning(f"Chain index warm-up skipped: {e}")

    # Initialize PoS validator if enabled
    validator_node = None
    validator_enabled = os.getenv("QRDX_VALIDATOR_ENABLED", "false").lower() == "true"
    if validator_enabled:
        logger.info("🔷 PoS Validator Mode Enabled")
        validator_wallet_path = os.getenv("QRDX_VALIDATOR_WALLET")
        from ..validator.keystore import ValidatorKeyError, read_password

        # QRDX_VALIDATOR_PASSWORD_FILE, else QRDX_VALIDATOR_PASSWORD (removed from the
        # environment once read).
        validator_password = read_password() or ""

        if validator_wallet_path and os.path.exists(validator_wallet_path):
            try:
                from ..validator.node_integration import initialize_validator_node

                validator_node = await initialize_validator_node(
                    db,
                    validator_wallet_path,
                    validator_password,
                    broadcast_callback=_peers.propagate,  # Pass propagate function for block broadcasting
                )

                if validator_node:
                    logger.info(f"✅ Validator node started: {validator_node.wallet.address}")
                    # Store globally for access in endpoints
                    app.state.validator = validator_node

                    def _validator_proof(wallet=validator_node.wallet):
                        from qrdx.rpc.modules.p2p import validator_peer_message

                        signature = wallet.sign(validator_peer_message(get_node_id()))
                        return {"address": wallet.address, "signature": bytes(signature).hex()}

                    NodeInterface.validator_proof_provider = _validator_proof
                    # Bind attestation gossip: without this the manager warns
                    # "attestation stays local" and per-epoch attester coverage
                    # collapses to the proposer set → finality stalls. See
                    # _ENABLE_ATTESTATION_GOSSIP.
                    try:
                        if validator_node.manager is not None:
                            validator_node.manager.set_attestation_broadcast_fn(
                                _peers._broadcast_attestation
                            )
                            logger.info("✅ Attestation gossip broadcast fn bound")
                    except Exception as e:
                        logger.warning(f"Could not bind attestation broadcast fn: {e}")
                    # Phase D2.2: let the proposer include admitted exchange txs.
                    try:
                        validator_node.set_exchange_tx_source(_get_exchange_mempool())
                        validator_node.set_exchange_submitter(_get_exchange_submitter())
                    except Exception as e:
                        logger.warning(f"Could not attach exchange tx source: {e}")
                    # E-D3b: let the proposer include admitted EVM txs (execute-on-
                    # mine). The producer reads the EVM globals lazily, so it works
                    # once the EVM system finishes initializing below.
                    try:
                        validator_node.set_evm_tx_source(_get_evm_mempool())
                        validator_node.set_evm_section_producer(_evm._produce_evm_section)
                        # Block production must never interleave with an import or a
                        # derived-state rebuild: share the lock they hold.
                        validator_node.set_block_processing_lock(block_processing_lock)
                        validator_node.set_proposal_guard(_sync._validator_wait_reason)
                        validator_node.set_restore_hook(_derived._restore_after_rejected_block)
                    except Exception as e:
                        logger.warning(f"Could not attach EVM tx source/producer: {e}")
                else:
                    logger.error("❌ Failed to initialize validator node")
            except ValidatorKeyError as e:
                # Running on without the validator the operator configured would only hide
                # the problem: stop, saying why.
                logger.critical(f"❌ Validator key: {e}")
                raise SystemExit(f"validator key: {e}") from e
            except Exception as e:
                logger.error(f"❌ Validator initialization error: {e}", exc_info=True)
        else:
            logger.warning(f"⚠️  Validator wallet not found: {validator_wallet_path}")

    # ---- Validator-lifecycle unification: consensus validator-set epoch processing ----
    # Runs on EVERY node (validator or full) so the `validators` table converges
    # network-wide as a deterministic function of finalized epochs (Phase 2d). A full
    # node verifies proposer eligibility off this table, so it must evolve identically.
    try:
        from ..validator.epoch_loop import epoch_validator_update_loop

        app.state.epoch_validator_task = asyncio.create_task(
            epoch_validator_update_loop(db, lock=block_processing_lock)
        )
        logger.info("✅ Consensus epoch validator-update loop scheduled (all nodes)")
    except Exception as e:
        logger.warning(f"Could not start epoch validator-update loop: {e}")

    # ---- Operational-readiness: realtime chain-event poller (feeds /metrics + /ws + /stream) ----
    # READ-ONLY (chain tip, peer count, finalized/justified epoch from the `epochs` table) — never
    # touches the import path, so it cannot stall or diverge consensus. Runs on every node.
    try:
        global _chain_poller_task
        # HELP text for the RPC/p2p layer counters (incremented in their own modules).
        METRICS.describe("qrdx_rpc_requests_total", "JSON-RPC requests handled, by method")
        METRICS.describe("qrdx_rpc_errors_total", "JSON-RPC requests that errored, by method")
        METRICS.describe(
            "qrdx_rpc_ratelimited_total", "JSON-RPC requests rejected by the rate limiter"
        )
        METRICS.describe("qrdx_p2p_blocks_received_total", "Blocks accepted from peers via p2p")
        METRICS.describe("qrdx_reorgs_total", "Chain reorganizations handled")

        async def _poll_tip():
            return (await db.get_next_block_id()) - 1

        async def _poll_hashes(lo, hi):
            return await db.get_block_hashes(lo, hi)

        async def _poll_finality():
            try:
                cur = await db.connection.execute(
                    "SELECT COALESCE(MAX(CASE WHEN finalized=1 THEN epoch END), -1), "
                    "COALESCE(MAX(CASE WHEN justified=1 THEN epoch END), -1), "
                    "COALESCE(MAX(epoch), -1) FROM epochs"
                )
                row = await cur.fetchone()
                return {
                    "finalized_epoch": int(row[0]),
                    "justified_epoch": int(row[1]),
                    "max_epoch": int(row[2]),
                }
            except Exception:
                return {}

        async def _poll_gauges():
            # The tip's age, the validator's signing state, the bridge's guardrails, oracle ages
            # (qrdx/node/health_gauges.py), for docker/alert-rules.yml.
            from qrdx.exchange import ExchangeStateManager

            from . import health_gauges

            return await health_gauges.collect(
                db, getattr(app.state, "validator", None), ExchangeStateManager.get_instance()
            )

        async def _poll_mempool():
            try:
                return int(await db.get_pending_transaction_count())
            except Exception:
                return 0

        def _poll_peers():
            try:
                return len(NodesManager.peers) if hasattr(NodesManager, "peers") else 0
            except Exception:
                return 0

        async def _poll_slashing():
            try:
                cur = await db.connection.execute("SELECT COUNT(*) FROM slashing_events")
                return int((await cur.fetchone())[0])
            except Exception:
                return 0

        METRICS.describe(
            "qrdx_slashing_events", "Recorded slashing events (0 on an honest network)"
        )
        METRICS.describe(
            "qrdx_finality_lag_epochs", "Epochs the tip is ahead of the finalized boundary"
        )
        METRICS.describe("qrdx_mempool_pending", "Pending transactions in the mempool")
        _chain_poller_task = asyncio.create_task(
            chain_event_poller(
                EVENT_HUB,
                METRICS,
                get_tip=_poll_tip,
                get_hashes=_poll_hashes,
                signal=CHAIN_CHANGED,
                get_peer_count=_poll_peers,
                get_finality=_poll_finality,
                get_slashing_count=_poll_slashing,
                get_mempool_depth=_poll_mempool,
                get_gauges=_poll_gauges,
                interval=2.0,
            )
        )
        app.state.chain_poller_task = _chain_poller_task
        # Publishing snapshots for nodes joining by checkpoint sync (QRDX_SNAPSHOT_DIR): a
        # poller, off the block path, like the one above.
        from qrdx import snapshot_publisher

        publish_dir = snapshot_publisher.configured()
        if publish_dir:
            app.state.snapshot_task = asyncio.create_task(
                snapshot_publisher.run(
                    str(DENARO_DATABASE_PATH) if DENARO_DATABASE_PATH else "data/qrdx.db",
                    publish_dir,
                )
            )
            logger.info(f"Publishing snapshots from {publish_dir} at /snapshot/")
        if STREAMING_ENABLED:
            # Perps channels (qrdx/exchange/stream.py): read-only, like the chain poller.
            from qrdx.exchange import ExchangeStateManager
            from qrdx.exchange.stream import perp_stream_poller

            app.state.perp_poller_task = asyncio.create_task(
                perp_stream_poller(
                    EVENT_HUB,
                    get_manager=ExchangeStateManager.get_instance,
                    interval=1.0,
                    signal=CHAIN_CHANGED,
                )
            )
        logger.info(
            "✅ Observability chain-event poller scheduled (streaming %s)",
            "ENABLED" if STREAMING_ENABLED else "disabled — /metrics + health still on",
        )
    except Exception as e:
        logger.warning(f"Could not start observability poller: {e}")

    # ---- Transaction index (qrdx/tx_index.py): wallet history + latest transactions ----
    if os.getenv("QRDX_TX_INDEX", "1").strip().lower() not in ("0", "false", "no", "off"):
        try:
            from qrdx.exchange import ExchangeStateManager
            from qrdx.tx_index import tx_index_poller

            app.state.tx_index_task = asyncio.create_task(
                tx_index_poller(
                    lambda: db,
                    block_processing_lock,
                    get_journal=lambda: ExchangeStateManager.get_instance().journal,
                    interval=1.0,
                )
            )
            logger.info("✅ Transaction indexer scheduled")
        except Exception as e:
            logger.warning(f"Could not start the transaction indexer: {e}")
    # Trading history (qrdx/trading_history.py): the journal's trades, order events, funding and
    # market samples, written to the database behind the tip. QRDX_TRADING_HISTORY=0: off (the
    # journal then drops the oldest waiting blocks past its limit).
    if os.getenv("QRDX_TRADING_HISTORY", "1").strip().lower() not in ("0", "false", "no", "off"):
        try:
            from qrdx.exchange import ExchangeStateManager
            from qrdx.trading_history import history_poller

            app.state.trading_history_task = asyncio.create_task(
                history_poller(
                    lambda: db,
                    block_processing_lock,
                    get_journal=lambda: ExchangeStateManager.get_instance().journal,
                    interval=1.0,
                )
            )
            logger.info("✅ Trading history indexer scheduled")
        except Exception as e:
            logger.warning(f"Could not start the trading history indexer: {e}")

    # ---- Wire module-level RPC server into app.state ----
    app.state.dht_rpc_module = dht_rpc_module
    app.state.rpc_server = rpc_server

    # ---- Wire P2P RPC module with live node context ----
    p2p_rpc_module.set_node_context(
        db=db,
        security=security,
        propagate_fn=_peers.propagate,
        process_and_create_block=_import.process_and_create_block,
        create_block=create_block,
        block_processing_lock=block_processing_lock,
        nodes_manager=NodesManager,
        self_node_id=self_node_id,
        sync_blockchain=_sync._sync_blockchain,
        follow_up_sync=_sync._follow_up_sync,
        evm_apply_section=_evm._apply_evm_section_on_import,  # E-D3b importer hook
        exchange_apply_section=_import._apply_exchange_section_on_import,  # D3/Phase E importer hook (flushes collateral)
        verify_unified_root=_import._verify_unified_state_root,  # E-D4 importer hook
        check_parent_continuity=_import._check_parent_continuity,  # parent-continuity observe hook
        tiebreak_rollback=_forks._tiebreak_rollback,  # fork-choice mechanism-2 rollback hook
        restore_after_rejected_block=_derived._restore_after_rejected_block,  # undo a rejected block's effects
        enforce_equal_height_tiebreak=_forks._ENFORCE_EQUAL_HEIGHT_TIEBREAK,  # mechanism-2 gate
        enforce_proposer_eligibility=_import._ENFORCE_PROPOSER_ELIGIBILITY,  # slot-eligibility gate
        add_remote_attestation=_peers._add_remote_attestation,  # attestation-gossip receive hook
        network_identity=_identity._local_network_identity,  # chain spec: advertised in handshake/status
        check_peer_identity=_identity._check_peer_identity,  # chain spec: refuse other networks / fork histories
        verify_chain_rules=_import._verify_chain_rules,  # slot progression + FFG votes
        on_fork=_forks.schedule_fork_resolution,  # a block off our tip: run fork choice now
        admit_peer=_peers._admit_handshaken_peer,  # the peer table's rules (NodesManager.admit_peer)
        block_relay=_relay,  # compact blocks: rebuilt from the mempool (qrdx/node/block_relay.py)
    )
    NodeInterface.network_identity_provider = _identity._local_network_identity

    logger.info(
        f"✅ JSON-RPC server initialized (dht_* + p2p_* always-on): {len(rpc_server.get_methods())} methods"
    )
    logger.info(f"   RPC endpoint: http://{DENARO_NODE_HOST}:{DENARO_NODE_PORT}/rpc")

    # ---- Optional EVM / chain RPC modules (gated by QRDX_RPC_ENABLED) ----
    rpc_enabled = os.getenv("QRDX_RPC_ENABLED", "false").lower() == "true"
    if rpc_enabled:
        logger.info("🔷 EVM / chain JSON-RPC modules enabled")
        try:
            from ..rpc.modules.eth import EthModule
            from ..rpc.modules.net import NetModule
            from ..rpc.modules.qrdx import QRDXModule

            # The contract system was initialised before the startup rebuild; the RPC
            # modules share that instance with the EVM consensus path (proposer inclusion
            # + import replay, E-D3), so both execute against the same state.
            if EVM_STATE_MANAGER is None or EVM_EXECUTOR is None:
                raise RuntimeError("contract system is not initialized")
            state_manager = EVM_STATE_MANAGER
            evm_executor = EVM_EXECUTOR

            # Anti-replay: restore the mempool's per-sender nonce expectations from the
            # durable account nonces, so a restart does not reset them to 0 and let an
            # already-executed transaction back in.
            await _evm._rehydrate_evm_pending_nonces()

            # Create context for modules
            from dataclasses import dataclass

            @dataclass
            class RPCContext:
                db: Any
                config: Any = None
                helpers: Any = None
                state_manager: Any = None
                evm_executor: Any = None

            context = RPCContext(db=db, state_manager=state_manager, evm_executor=evm_executor)

            # Register Ethereum module (standard eth_* methods)
            eth_module = EthModule()
            eth_module.context = context
            rpc_server.register_module(eth_module)

            # Register web3 utility module
            from ..rpc.modules.web3 import Web3Module

            web3_module = Web3Module()
            web3_module.context = context
            rpc_server.register_module(web3_module)

            # Register contract methods manually (not a full module)
            # There is deliberately no eth_sendTransaction handler here. The one that stood
            # here executed a signed call straight against the EVM state manager — no block, no
            # mempool, no nonce check. Its writes sat in the manager's cache as dirty entries
            # and the next block's EVM flush committed them, so any RPC client could push
            # off-chain effects into this node's account_state (diverging it from the network)
            # and replay the same parameters indefinitely. It also silently overrode
            # EthModule.sendTransaction, which correctly refuses and points callers at
            # eth_sendRawTransaction — the one write path, through the mempool and a block.

            async def eth_call_handler(call_params, block_number="latest"):
                """Read-only contract call (``_eth_call``). Takes the standard
                ``[transaction, block]`` params — it used to accept the transaction alone, so
                every web3 client's eth_call (which always sends the block tag) failed with an
                internal error."""
                return await _evm._eth_call(evm_executor, call_params)

            async def eth_sendRawTransaction_handler(raw_tx_hex, _propagated=False):
                """
                Submit a pre-signed raw EVM transaction (E-D3b: execute-on-mine).

                Web3-standard semantics: this ADMITS the tx to the EVM mempool and
                returns its hash immediately — it does NOT execute it. Execution
                happens when a proposer includes the tx in a block (the section is
                executed + the account_state_root declared), and every node applies
                it deterministically on import. Account balances therefore change on
                block inclusion, not at RPC time; clients poll
                ``eth_getTransactionReceipt`` for the result.

                The tx is gossiped to peers' mempools so whichever node proposes
                next can include it. ``_propagated`` suppresses re-broadcast.
                """
                try:
                    from eth_hash.auto import keccak
                    from eth_utils import decode_hex, encode_hex

                    raw_tx = decode_hex(raw_tx_hex)
                    _evm_tx_hash = encode_hex(keccak(raw_tx))
                    # Idempotent: skip txs already admitted (also stops gossip loops). Only an
                    # admitted transaction is remembered (below): one refused used to be
                    # remembered first, so sending it again answered its hash as if admitted,
                    # and it could not be sent again once its account could pay.
                    if await EVM_TX_CACHE.contains(_evm_tx_hash):
                        return _evm_tx_hash

                    # Admission control (standard mempool semantics): recover the
                    # sender, enforce the nonce window + DoS caps. A stale-nonce /
                    # unrecoverable / far-future tx is rejected here. The tx then
                    # waits in the mempool to be included by a proposer.
                    # Authorise a delegated (system-wallet) spend before admission. The
                    # block-import path checks this independently — neither trusts the
                    # other — but refusing here keeps an unauthorised transaction out of
                    # the mempool and off the gossip network in the first place.
                    from ..contracts.evm_mempool import verify_delegated_spend

                    deleg_ok, deleg_err = await verify_delegated_spend(db, raw_tx_hex)
                    if not deleg_ok:
                        raise Exception(f"rejected: {deleg_err}")

                    # The standard refusal wallets understand: the sender cannot cover what
                    # it offers (gas at its highest price plus the value).
                    from ..contracts.evm_mempool import parse_eth_raw_tx

                    sm = EVM_STATE_MANAGER
                    if sm is not None:
                        parsed = parse_eth_raw_tx(raw_tx_hex)
                        cost = int(parsed["gas"]) * int(parsed["gas_price"])
                        if (parsed.get("spend_from") or parsed["sender"]).lower() == str(
                            parsed["sender"]
                        ).lower():
                            cost += int(parsed["value"])
                        if int(await sm.get_balance(parsed["sender"])) < cost:
                            raise Exception("rejected: insufficient funds for gas * price + value")

                    mp = _get_evm_mempool()
                    admit_ok, admit_err, _ = mp.admit(raw_tx_hex)
                    if not admit_ok and "duplicate" not in (admit_err or ""):
                        raise Exception(f"rejected: {admit_err}")
                    await EVM_TX_CACHE.put(_evm_tx_hash, True)

                    # Propagate to peers' mempools so the next proposer (which may be
                    # any node) can include it.
                    if not _propagated:
                        asyncio.create_task(_evm._gossip_evm_raw_tx(raw_tx_hex))

                    # Web3 contract: always return the tx hash (the receipt — incl.
                    # any created contract address — is available after inclusion).
                    return _evm_tx_hash
                except Exception as e:
                    # A refusal is the sender's error, not the node's: at DEBUG, without a
                    # traceback (anyone can send refused transactions as fast as the node takes
                    # them, and an ERROR with a traceback each filled the log and cost the
                    # event loop — integration_tests/adversarial.py, the flood).
                    logger.debug("eth_sendRawTransaction refused: %s", e)
                    raise Exception(f"Transaction failed: {str(e)}") from e

            rpc_server.register_method("eth_call", eth_call_handler)
            rpc_server.register_method("eth_sendRawTransaction", eth_sendRawTransaction_handler)

            # Register QRDX-specific module
            qrdx_module = QRDXModule()
            qrdx_module.context = context
            rpc_server.register_module(qrdx_module)

            # Register network module
            net_module = NetModule()
            net_module.context = context
            rpc_server.register_module(net_module)

            logger.info(
                f"✅ EVM / chain RPC modules registered: {len(rpc_server.get_methods())} total methods"
            )

        except Exception as e:
            logger.error(f"❌ RPC server initialization error: {e}", exc_info=True)

    logger.info("Starting background tasks.")
    asyncio.create_task(_peers.check_own_reachability())
    asyncio.create_task(_discovery.periodic_peer_discovery())
    asyncio.create_task(_sync.periodic_update_fetcher())

    # Initialize Kademlia DHT subsystem (non-blocking, non-fatal)
    await _discovery._init_dht()

    logger.info(f"Denaro node server started on http://{DENARO_NODE_HOST}:{DENARO_NODE_PORT}")
    logger.info("Application startup complete.")


@app.on_event("shutdown")
async def shutdown():
    """Clean shutdown"""
    # Stop Kademlia DHT (persists routing table to disk)
    if dht_discovery is not None:
        dht_discovery.stop()
        logger.info("Kademlia DHT stopped and routing table persisted.")

    # Stop validator if running
    if hasattr(app.state, "validator") and app.state.validator:
        await app.state.validator.stop()
        logger.info("Validator stopped.")

    # Close the shared HTTP client
    if http_client:
        await http_client.aclose()
        logger.info("Shared HTTP client closed.")

    snapshot_task = getattr(app.state, "snapshot_task", None)
    if snapshot_task is not None:
        snapshot_task.cancel()

    # Stop the observability poller.
    if _chain_poller_task is not None:
        _chain_poller_task.cancel()
        try:
            await _chain_poller_task
        except (asyncio.CancelledError, Exception):
            pass

    await security.shutdown()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")

    traceback.print_exc()

    await security.security_monitor.log_event(
        "unhandled_exception", {"endpoint": request.url.path, "error": str(exc)}
    )

    return JSONResponse(status_code=500, content={"ok": False, "error": "Internal Server Error"})


# ============================================================================
# MIDDLEWARE
# ============================================================================


async def propagate_old_transactions(propagate_txs):
    await db.update_pending_transactions_propagation_time(
        [sha256(tx_hex) for tx_hex in propagate_txs]
    )
    for tx_hex in propagate_txs:
        await _peers.propagate("push_tx", {"tx_hex": tx_hex})


_PROPAGATION_CHECK_SECONDS = 5.0
_propagation_checked_at = float("-inf")


@app.middleware("http")
async def middleware(request: Request, call_next):
    """Simple middleware to handle URL normalization and attach background tasks"""
    path = request.scope["path"]
    normalized_path = re.sub("/+", "/", path)
    if normalized_path != path:
        new_url = str(request.url.replace(path=normalized_path))
        return RedirectResponse(url=new_url)

    try:
        # (At most every few seconds: it was a database query on every request, a node's
        # every peer call included — and a flood's every request.)
        global _propagation_checked_at
        propagate_txs = None
        now = time.monotonic()
        if now - _propagation_checked_at >= _PROPAGATION_CHECK_SECONDS:
            _propagation_checked_at = now
            propagate_txs = await db.get_need_propagate_transactions()
        response = await call_next(request)

        if propagate_txs:
            existing_background = response.background or BackgroundTasks()
            existing_background.add_task(propagate_old_transactions, propagate_txs)
            response.background = existing_background

        return response
    except Exception:
        raise


class _FastRPC:
    """``POST /rpc`` straight to the JSON-RPC handler, past the HTTP middleware above (the
    outermost user middleware, so added last). Two of those layers spawn tasks and wrap the
    body of every request; for a peer's gossip batch, a hundred 10 KB transactions, they cost a
    loaded node more of its event loop than the batch's own admission (docs/PERFORMANCE.md).
    What they did for /rpc is done here: the periodic re-propagation check, the CORS header,
    the access log at DEBUG, and a 500 for an error nothing else caught."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if not (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/rpc"
        ):
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        try:
            response = await rpc_endpoint(request)
        except Exception as exc:
            logger.error(f"Unhandled exception: {exc}")
            response = JSONResponse(
                status_code=500, content={"ok": False, "error": "Internal Server Error"}
            )
        if request.headers.get("origin"):
            response.headers["access-control-allow-origin"] = "*"
        logger.debug(f'<-- {request.client.host if request.client else "unknown"} "POST /rpc"')
        await response(scope, receive, send)
        _propagation_due()


def _propagation_due() -> None:
    """The re-propagation check the request middleware runs, for requests that skip it."""
    global _propagation_checked_at
    now = time.monotonic()
    if now - _propagation_checked_at < _PROPAGATION_CHECK_SECONDS or db is None:
        return
    _propagation_checked_at = now

    async def check():
        txs = await db.get_need_propagate_transactions()
        if txs:
            await propagate_old_transactions(txs)

    asyncio.ensure_future(check())


app.add_middleware(_FastRPC)


# The node's behaviour, by concern (each reads the node state above at call time).
from qrdx.node import (  # noqa: E402
    block_import as _import,
    block_relay as _relay,
    chain_identity as _identity,
    derived_state as _derived,
    discovery as _discovery,
    evm_runtime as _evm,
    fork_choice as _forks,
    peers as _peers,
    sync as _sync,
)
from qrdx.node.api import (  # noqa: E402,F401  (registers the REST routes)
    accounts,
    blocks,
    chain,
    exchange,
    observability,
    transactions,
)
