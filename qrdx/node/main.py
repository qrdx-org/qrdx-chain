# denaro/node/main.py - SECURE IMPLEMENTATION
import random
import asyncio
from asyncio import gather, Lock
from collections import deque, defaultdict
import os
import re
import json
from decimal import Decimal
from datetime import datetime, timedelta
import hashlib
import hmac
import traceback
import time
from typing import Optional, Set, Dict, List, Tuple, Any
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import ipaddress
import socket
import sqlite3
from urllib.parse import urlparse

from fastapi import FastAPI, Body, Query, Depends, HTTPException, status 
from fastapi.responses import RedirectResponse, Response

import httpx
from httpx import TimeoutException
from icecream import ic
from starlette.background import BackgroundTasks, BackgroundTask
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from qrdx.helpers import timestamp, sha256, transaction_to_json
from qrdx.logger import get_logger

from qrdx.manager import (
    create_block, get_difficulty, Manager, get_transactions_merkle_tree, 
    calculate_difficulty, clear_pending_transactions, block_to_bytes, split_block_content
)

from qrdx.node.nodes_manager import NodesManager, NodeInterface
from qrdx.node.utils import ip_is_local
from qrdx.node.bootstrap import BootstrapManager, get_bootstrap_manager, init_bootstrap_manager
from qrdx.transactions import Transaction, CoinbaseTransaction
from qrdx.transactions.contract_transaction import ContractTransaction
from qrdx.database_sqlite import DatabaseSQLite as Database
from qrdx.constants import (
    MAX_MINING_CANDIDATES, NODE_VERSION, MAX_BLOCKS_PER_SUBMISSION,
    MAX_BLOCK_CONTENT_SIZE, MAX_PEERS, MAX_CONCURRENT_SYNCS,
    MAX_TX_FETCH_LIMIT, MAX_MEMPOOL_SIZE, CONNECTION_TIMEOUT,
    MAX_BATCH_BYTES, VALID_HEX_PATTERN, VALID_ADDRESS_PATTERN,
    DENARO_BOOTSTRAP_NODE, DENARO_SELF_URL,
    DENARO_DATABASE_PATH, MAX_TX_DATA_SIZE, DENARO_NODE_HOST, 
    DENARO_NODE_PORT, MAX_REORG_DEPTH,
    LOG_INCLUDE_REQUEST_CONTENT, LOG_INCLUDE_RESPONSE_CONTENT, LOG_MAX_PATH_LENGTH,
    BOOTSTRAP_NODES
)
from qrdx.node.identity import (
    initialize_identity, get_node_id, get_public_key_hex,
    verify_signature, get_canonical_json_bytes, sign_message,
    get_public_key_bytes,
)
from qrdx.validator.block_verification import verify_pos_block_proposer, verify_proposer_eligibility

# Slot-proposer eligibility gate. Enabled after the validator-set convergence fix:
# with a consistent validator set + correct identities, every node reconstructs the
# same slot proposer — observed 0 mismatches across a 3-run soak (all import paths,
# incl. sync) — so out-of-turn proposals are now rejected.
_ENFORCE_PROPOSER_ELIGIBILITY = True

# Finality reorg guard (link 5): refuse reorgs that would roll back below the
# irreversibly finalized block height. Enabled after observe-mode showed
# legitimate reorgs never cross finality (0 crossings; deterministic boundary).
_ENFORCE_FINALITY_REORG_GUARD = True

# Kademlia DHT integration
from qrdx.p2p.node import Node as P2PNode, Address as P2PAddress, hex_to_node_id as p2p_hex_to_node_id
from qrdx.p2p.routing import RoutingTable, KBucketEntry
from qrdx.p2p.discovery import KademliaDiscovery
from qrdx.p2p.dns_seeds import DNSSeedDiscovery
from qrdx.p2p.config import DiscoveryConfig

logger = get_logger(__name__)

# ============================================================================
# SECURITY COMPONENTS
# ============================================================================

class TimeBasedCache:
    """Thread-safe cache with automatic expiration"""
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._access_order = deque(maxlen=max_size)
        self._lock = asyncio.Lock()
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        
    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self.ttl_seconds:
                    return value
                else:
                    del self._cache[key]
            return None
    

    async def put(self, key: str, value: Any):
        async with self._lock:
            current_time = time.time()
            
            # If the cache is full and we're adding a new key, we need to make space.
            # This loop handles both size enforcement and cleaning of old items in one pass.
            while len(self._cache) >= self.max_size and key not in self._cache:
                if not self._access_order:
                    # Should not happen if cache is not empty, but a safeguard.
                    break
                
                # Get the oldest key from the access queue
                oldest_key = self._access_order.popleft()
                
                # If this key is still in the cache, remove it.
                # This check resolves the race condition, as the key might have
                # been removed by another operation or expired.
                if oldest_key in self._cache:
                    del self._cache[oldest_key]
            
            # Now that there is space, add the new item.
            self._cache[key] = (value, current_time)
            self._access_order.append(key)

    async def contains(self, key: str) -> bool:
        return await self.get(key) is not None
    
    async def clean(self):
        """Manual cleanup of expired entries"""
        async with self._lock:
            current_time = time.time()
            expired_keys = [
                k for k, (_, ts) in self._cache.items() 
                if current_time - ts >= self.ttl_seconds
            ]
            for k in expired_keys:
                del self._cache[k]


class HandshakeChallengeManager:
    """Secure challenge management with automatic cleanup"""
    def __init__(self, ttl_seconds: int = 300):
        self._challenges: Dict[str, float] = {}
        self._lock = asyncio.Lock()
        self.ttl_seconds = ttl_seconds
        self._cleanup_task = None
        
    async def start(self):
        """Start periodic cleanup task"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        
    async def stop(self):
        """Stop cleanup task"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            
    async def _periodic_cleanup(self):
        """Remove expired challenges every 60 seconds"""
        while True:
            await asyncio.sleep(60)
            await self.cleanup()
            
    async def cleanup(self):
        """Remove expired challenges"""
        async with self._lock:
            current_time = time.time()
            expired = [
                challenge for challenge, timestamp in self._challenges.items()
                if current_time - timestamp > self.ttl_seconds
            ]
            for challenge in expired:
                del self._challenges[challenge]
                
    async def create_challenge(self) -> str:
        """Create a new challenge"""
        challenge = os.urandom(32).hex()
        
        async with self._lock:
            # Prevent unlimited growth
            if len(self._challenges) > 10000:
                # Remove oldest half
                sorted_challenges = sorted(self._challenges.items(), key=lambda x: x[1])
                for challenge_to_remove, _ in sorted_challenges[:5000]:
                    del self._challenges[challenge_to_remove]
                    
            self._challenges[challenge] = time.time()
            
        return challenge
        
    async def verify_and_consume_challenge(self, challenge: str) -> bool:
        """Verify challenge exists and immediately consume it"""
        async with self._lock:
            if challenge in self._challenges:
                timestamp = self._challenges[challenge]
                current_time = time.time()
                
                # Check if expired
                if current_time - timestamp > self.ttl_seconds:
                    del self._challenges[challenge]
                    return False
                    
                # Valid challenge - consume it immediately
                del self._challenges[challenge]
                return True
                
            return False


class BoundedPeerSyncTracker:
    """Track peer sync operations with size limits"""
    def __init__(self, max_peers: int = MAX_PEERS):
        self._peers_in_sync: Set[str] = set()
        self._sync_timestamps: Dict[str, float] = {}
        self._lock = asyncio.Lock()
        self.max_peers = max_peers
        
    async def add_peer(self, peer_id: str) -> bool:
        """Add peer to sync set if not at limit"""
        async with self._lock:
            if peer_id in self._peers_in_sync:
                return False
                
            if len(self._peers_in_sync) >= self.max_peers:
                # Remove oldest peer
                if self._sync_timestamps:
                    oldest_peer = min(self._sync_timestamps.items(), key=lambda x: x[1])[0]
                    self._peers_in_sync.discard(oldest_peer)
                    del self._sync_timestamps[oldest_peer]
                    
            self._peers_in_sync.add(peer_id)
            self._sync_timestamps[peer_id] = time.time()
            return True
            
    async def remove_peer(self, peer_id: str):
        """Remove peer from sync set"""
        async with self._lock:
            self._peers_in_sync.discard(peer_id)
            self._sync_timestamps.pop(peer_id, None)
            
    async def is_syncing(self, peer_id: str) -> bool:
        """Check if peer is currently syncing"""
        async with self._lock:
            return peer_id in self._peers_in_sync


class SyncStateManager:
    """Thread-safe synchronization state management"""
    def __init__(self, max_concurrent_syncs: int = MAX_CONCURRENT_SYNCS):
        self.is_syncing = False
        self.active_sync_count = 0
        self.max_concurrent_syncs = max_concurrent_syncs
        self._sync_lock = asyncio.Lock()
        self._count_lock = asyncio.Lock()
        
    @asynccontextmanager
    async def acquire_sync(self):
        """Context manager for sync operations"""
        acquired = False
        try:
            async with self._sync_lock:
                if self.is_syncing:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Node is already synchronizing"
                    )
                    
                async with self._count_lock:
                    if self.active_sync_count >= self.max_concurrent_syncs:
                        raise HTTPException(
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Maximum concurrent syncs reached"
                        )
                    
                    self.is_syncing = True
                    self.active_sync_count += 1
                    acquired = True
                    
            yield
            
        finally:
            if acquired:
                async with self._sync_lock:
                    self.is_syncing = False
                async with self._count_lock:
                    self.active_sync_count = max(0, self.active_sync_count - 1)


class InputValidator:
    """Comprehensive input validation"""
    
    @staticmethod
    def validate_hex(hex_string: str, min_length: int = 1, max_length: int = None) -> bool:
        """Validate hex string format and length"""
        if not hex_string:
            return False
            
        if max_length and len(hex_string) > max_length:
            return False
            
        if len(hex_string) < min_length:
            return False
            
        try:
            # Ensure even length
            if len(hex_string) % 2 != 0:
                return False
                
            # Try to decode
            bytes.fromhex(hex_string)
            return True
        except ValueError:
            return False
            
    @staticmethod
    async def validate_block_height(height: int, db, max_ahead: int = 10) -> bool:
        """Validate block height is reasonable"""
        if height < 0:
            return False
            
        current_height = await db.get_next_block_id() - 1
        
        # Don't accept blocks too far in the future
        if height > current_height + max_ahead:
            return False
            
        return True
        
    @staticmethod
    def validate_address(address: str) -> bool:
        """Validate address format using canonical pattern"""
        if not address:
            return False

        # Supported address formats:
        # - Traditional QRDX (Q/R prefix): 45 chars
        # - Ethereum (0x prefix): 42 chars
        # - PQ addresses (0xPQ prefix): 68 chars
        if len(address) < 40 or len(address) > 128:
            return False

        return bool(VALID_ADDRESS_PATTERN.match(address))
        
    @staticmethod
    def validate_transaction_data(tx_hex: str) -> Tuple[bool, Optional[str]]:
        """Comprehensive transaction validation"""
        if not tx_hex:
            return False, "Empty transaction"
            
        if len(tx_hex) > 2_075_000:
            return False, "Transaction too large"
            
        if not InputValidator.validate_hex(tx_hex):
            return False, "Invalid hex format"
            
        # Additional validation could go here
        return True, None


class AuthenticatedRequestValidator:
    """Validate request signatures with timestamp checks"""
    
    def __init__(self, max_age_seconds: int = 300):
        self.max_age_seconds = max_age_seconds
        self._nonce_cache = TimeBasedCache(max_size=10000, ttl_seconds=max_age_seconds)
        
    async def validate_request(self, request: Request) -> Optional[str]:
        """
        Validates the request signature, timestamp, and nonce.
        Returns the verified node_id on success, or None on failure.
        """
        node_id = request.headers.get('x-node-id')
        pubkey = request.headers.get('x-public-key')
        signature = request.headers.get('x-signature')
        timestamp_header = request.headers.get('x-timestamp')
        nonce = request.headers.get('x-nonce')
        
        if not all([node_id, pubkey, signature, timestamp_header, nonce]):
            return None
            
        # 1. Validate timestamp
        try:
            request_time = int(timestamp_header)
            current_time = int(time.time())
            if abs(current_time - request_time) > self.max_age_seconds:
                return None
        except (ValueError, TypeError):
            return None
            
        # 2. Check nonce for replay attacks
        nonce_key = f"{node_id}:{nonce}"
        if await self._nonce_cache.contains(nonce_key):
            return None
        
        # 3. Verify the cryptographic signature
        try:
            request_body_bytes = await request.body()
            
            # Start with the base payload
            payload_to_verify = {
                "body": request_body_bytes.decode('utf-8'),
                "timestamp": request_time,
                "nonce": nonce
            }

            # Reconstruct the full payload by looking for our custom signed headers.
            # The client signed these, so we MUST include them for verification.
            for key, value in request.headers.items():
                if key.lower().startswith('x-denaro-'):
                    # The client added this key without the prefix to the signed dict.
                    # e.g., 'x-denaro-height' -> 'height'
                    original_key = key.lower().replace('x-denaro-', '')
                    # Attempt to convert numeric values back to numbers for a perfect match
                    try:
                        # Check if it looks like a number (int or float)
                        if '.' in value:
                             payload_to_verify[original_key] = float(value)
                        else:
                             payload_to_verify[original_key] = int(value)
                    except ValueError:
                        # It's not a number, treat it as a string.
                        # Handle 'None' string specifically.
                        if value == 'None':
                            payload_to_verify[original_key] = None
                        else:
                            payload_to_verify[original_key] = value
            
            canonical_bytes = get_canonical_json_bytes(payload_to_verify)
            
            if not verify_signature(pubkey, signature, canonical_bytes):
                # The reconstructed signature does not match.
                logger.error(f"Signature verification failed for peer {node_id}.")
                return None

        except Exception as e:
            logger.error(f"Error during signature validation: {e}")
            return None

        # All checks passed. Store the nonce and return the verified node_id.
        await self._nonce_cache.put(nonce_key, True)
        
        return node_id


class DNSSafeHTTPClient:
    """HTTP client with DNS rebinding protection"""
    
    def __init__(self, timeout: float = 10.0):
        self._dns_cache: Dict[str, Tuple[str, float]] = {}
        self._cache_ttl = 300  # 5 minutes
        self._lock = asyncio.Lock()
        self.timeout = timeout
        
    async def validate_and_resolve(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL and resolve with caching"""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                return False, None
                
            hostname = parsed.hostname
            if not hostname:
                return False, None
                
            async with self._lock:
                # Check cache
                if hostname in self._dns_cache:
                    cached_ip, cache_time = self._dns_cache[hostname]
                    if time.time() - cache_time < self._cache_ttl:
                        return True, cached_ip
                        
                # Resolve
                loop = asyncio.get_event_loop()
                addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
                resolved_ip = addr_info[0][4][0]
                
                # Validate IP
                ip_obj = ipaddress.ip_address(resolved_ip)
                if not ip_obj.is_global and not ip_obj.is_private:
                    return False, None
                    
                # Cache resolution
                self._dns_cache[hostname] = (resolved_ip, time.time())
                
                return True, resolved_ip
                
        except Exception:
            return False, None


@dataclass
class PeerViolation:
    timestamp: float
    violation_type: str
    severity: int  # 1-10
    details: Optional[str] = None


class PeerReputationManager:
    """Track peer behavior and ban malicious peers"""
    
    def __init__(self, ban_threshold: int = -100, violation_ttl: int = 86400):
        self._peer_scores: Dict[str, int] = defaultdict(int)
        self._violations: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._banned_peers: Set[str] = set()
        self._lock = asyncio.Lock()
        self.ban_threshold = ban_threshold
        self.violation_ttl = violation_ttl
        
    async def record_violation(self, peer_id: str, violation_type: str, 
                             severity: int = 5, details: str = None):
        """Record a violation and update peer score"""
        async with self._lock:
            violation = PeerViolation(
                timestamp=time.time(),
                violation_type=violation_type,
                severity=severity,
                details=details
            )
            
            self._violations[peer_id].append(violation)
            
            # Update score
            score_penalty = severity * 10
            self._peer_scores[peer_id] -= score_penalty
            
            # Check if should ban
            if self._peer_scores[peer_id] <= self.ban_threshold:
                self._banned_peers.add(peer_id)
                
    async def record_good_behavior(self, peer_id: str, points: int = 1):
        """Reward good behavior"""
        async with self._lock:
            self._peer_scores[peer_id] = min(100, self._peer_scores[peer_id] + points)
            
    async def is_banned(self, peer_id: str) -> bool:
        """Check if peer is banned"""
        async with self._lock:
            return peer_id in self._banned_peers
            
    async def get_score(self, peer_id: str) -> int:
        """Get current peer score"""
        async with self._lock:
            return self._peer_scores.get(peer_id, 0)
            
    async def cleanup_old_violations(self):
        """Remove old violations"""
        async with self._lock:
            current_time = time.time()
            
            for peer_id, violations in list(self._violations.items()):
                # Remove old violations
                while violations and current_time - violations[0].timestamp > self.violation_ttl:
                    violations.popleft()
                    
                # Remove peer data if no violations
                if not violations and peer_id not in self._banned_peers:
                    del self._violations[peer_id]
                    if peer_id in self._peer_scores and self._peer_scores[peer_id] >= 0:
                        del self._peer_scores[peer_id]


class QueryCostCalculator:
    """Calculate and limit database query costs"""
    
    def __init__(self, max_cost_per_hour: int = 1000):
        self._costs: Dict[str, float] = defaultdict(float)
        self._reset_times: Dict[str, float] = defaultdict(time.time)
        self._lock = asyncio.Lock()
        self.max_cost_per_hour = max_cost_per_hour
        
    async def check_and_update_cost(self, identifier: str, offset: int, limit: int):
        """Check if query is allowed and update cost"""
        async with self._lock:
            current_time = time.time()
            
            # Reset if hour has passed
            if current_time - self._reset_times[identifier] > 3600:
                self._costs[identifier] = 0
                self._reset_times[identifier] = current_time
                
            # Calculate cost (higher offset = higher cost)
            cost = (offset / 100) + (limit / 50)
            
            if self._costs[identifier] + cost > self.max_cost_per_hour:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Query cost limit exceeded. Try again later."
                )
                
            self._costs[identifier] += cost


class SecurityMonitor:
    """Monitor and log security events"""
    
    def __init__(self):
        self._metrics = {
            'failed_validations': defaultdict(int),
            'rate_limit_hits': defaultdict(int),
            'banned_peers': 0,
            'replay_attempts': 0,
            'dns_rebinding_attempts': 0,
            'resource_exhaustion_attempts': 0
        }
        self._lock = asyncio.Lock()
        
    async def log_event(self, event_type: str, details: dict):
        """Log security event"""
        async with self._lock:
            # Update metrics
            if event_type in self._metrics:
                if isinstance(self._metrics[event_type], dict):
                    key = details.get('subtype', 'default')
                    self._metrics[event_type][key] += 1
                else:
                    self._metrics[event_type] += 1
                    
    async def get_metrics(self) -> dict:
        """Get current security metrics"""
        async with self._lock:
            return dict(self._metrics)
            
    async def check_thresholds(self):
        """Check if any security thresholds are exceeded"""
        async with self._lock:
            alerts = []
            
            # Check for high rate of failures
            for event_type, counts in self._metrics.items():
                if isinstance(counts, dict):
                    total = sum(counts.values())
                    if total > 1000:  # Threshold
                        alerts.append({
                            'type': event_type,
                            'count': total,
                            'severity': 'high'
                        })
                        
            return alerts


class SafeTransactionPool:
    """Thread-safe transaction pool with atomic operations"""
    
    def __init__(self, max_size: int = 10000):
        self._pool: Dict[str, Any] = {}  # tx_hash -> transaction
        self._lock = asyncio.Lock()
        self.max_size = max_size
        self._insertion_time: Dict[str, float] = {}
        
    async def add_transaction(self, tx_hash: str, transaction: Any, db) -> bool:
        """Add transaction atomically"""
        async with self._lock:
            if tx_hash in self._pool:
                return False
                
            if len(self._pool) >= self.max_size:
                # Remove oldest transactions
                sorted_txs = sorted(self._insertion_time.items(), key=lambda x: x[1])
                for old_hash, _ in sorted_txs[:self.max_size // 10]:  # Remove 10%
                    del self._pool[old_hash]
                    del self._insertion_time[old_hash]
                    
            # Add to pool
            self._pool[tx_hash] = transaction
            self._insertion_time[tx_hash] = time.time()
            
            # Add to database
            try:
                success = await db.add_pending_transaction(transaction)
                if not success:
                    # Rollback
                    del self._pool[tx_hash]
                    del self._insertion_time[tx_hash]
                    return False
                    
                return True
                
            except Exception:
                # Rollback on any error
                del self._pool[tx_hash]
                del self._insertion_time[tx_hash]
                raise
                
    async def remove_transactions(self, tx_hashes: List[str]):
        """Remove transactions atomically"""
        async with self._lock:
            for tx_hash in tx_hashes:
                self._pool.pop(tx_hash, None)
                self._insertion_time.pop(tx_hash, None)


class SecureNodeComponents:
    """Initialize all security components"""
    
    def __init__(self):
        # Caches
        self.transaction_cache = TimeBasedCache(max_size=1000, ttl_seconds=300)
        self.block_cache = TimeBasedCache(max_size=500, ttl_seconds=600)
        self.reachability_cache = TimeBasedCache(max_size=1000, ttl_seconds=300)
        
        # Managers
        self.handshake_manager = HandshakeChallengeManager()
        self.peer_sync_tracker = BoundedPeerSyncTracker(max_peers=MAX_PEERS)
        self.sync_state_manager = SyncStateManager(max_concurrent_syncs=MAX_CONCURRENT_SYNCS)
        
        # Validation
        self.input_validator = InputValidator()
        self.auth_validator = AuthenticatedRequestValidator()
        
        # Security
        self.dns_client = DNSSafeHTTPClient()
        self.reputation_manager = PeerReputationManager()
        self.query_calculator = QueryCostCalculator()
        self.security_monitor = SecurityMonitor()
        
        # Safety
        self.transaction_pool = SafeTransactionPool()
        
        # Semaphore for propagation
        self.propagation_semaphore = asyncio.Semaphore(50)
        
    async def startup(self):
        """Initialize all components"""
        await self.handshake_manager.start()
        
        # Start periodic cleanup tasks
        asyncio.create_task(self._periodic_cleanup())
        
    async def shutdown(self):
        """Cleanup all components"""
        await self.handshake_manager.stop()
        
    async def _periodic_cleanup(self):
        """Periodic cleanup of all components"""
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            
            # Clean caches
            await self.transaction_cache.clean()
            await self.block_cache.clean()
            await self.reachability_cache.clean()
            
            # Clean reputation data
            await self.reputation_manager.cleanup_old_violations()
            
            # Check security thresholds
            alerts = await self.security_monitor.check_thresholds()
            if alerts:
                logger.warning(f"SECURITY ALERTS: {alerts}")

# ============================================================================
# RATE LIMITING KEY FUNCTION
# ============================================================================

def rate_limit_key_func(request: Request) -> str:
    """
    Determines the rate-limiting key.
    - For authenticated requests, it uses the peer's node_id.
    - For unauthenticated requests, it falls back to the client's IP address.
    """
    # Prefer the node_id from the header if it exists. This correctly attributes
    # requests to a specific peer identity, even if their IP changes.
    node_id = request.headers.get('x-node-id')
    if node_id:
        return node_id
    
    # For all other requests (e.g., from wallets, miners), use the remote address.
    return get_remote_address(request)

# ============================================================================
# APPLICATION SETUP
# ============================================================================

db: Database = None
self_node_id: str = None
self_is_public: bool = False 

app_servers = [{"url": str(DENARO_SELF_URL)}] if DENARO_SELF_URL else []
app = FastAPI(servers=app_servers, title="Denaro Node", description="Full node for the Denaro blockchain.", version=NODE_VERSION)

limiter = Limiter(key_func=rate_limit_key_func)
# Allow testnet / integration-test environments to disable rate limiting
# so that automated test clients can exercise endpoints without hitting 429s.
if os.environ.get("QRDX_DISABLE_RATE_LIMIT", "").lower() in ("1", "true", "yes"):
    limiter.enabled = False
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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

# Connection pool for HTTP requests
http_client: Optional[httpx.AsyncClient] = None

# Kademlia DHT subsystem
dht_discovery: Optional[KademliaDiscovery] = None
dht_dns_seeds: Optional[DNSSeedDiscovery] = None
dht_config: DiscoveryConfig = DiscoveryConfig()

# ---- Always-on JSON-RPC server (required for DHT inter-node protocol) ----
from qrdx.rpc.server import RPCServer
from qrdx.rpc.modules.dht import DHTModule
from qrdx.rpc.modules.p2p import P2PModule

rpc_server = RPCServer()

# Register DHT module unconditionally — it's core networking, not optional
dht_rpc_module = DHTModule()
rpc_server.register_module(dht_rpc_module)

# Register P2P module unconditionally — block/tx propagation over JSON-RPC
p2p_rpc_module = P2PModule()
rpc_server.register_module(p2p_rpc_module)

@app.post("/rpc")
async def rpc_endpoint(body: dict = Body(...)):
    """JSON-RPC 2.0 endpoint"""
    result = await rpc_server.handle_request(body)
    if result is None:
        return Response(status_code=204)
    # handle_request returns a JSON string; send it raw to avoid double-encoding
    return Response(content=result, media_type="application/json")

LAST_PENDING_TRANSACTIONS_CLEAN = [0]
block_processing_lock = asyncio.Lock()

# Seen-cache for EVM / account-model transactions (keyed by keccak(raw_tx)).
# Prevents double execution and terminates gossip loops in Phase 1 cross-node
# convergence. See docs/EVM_STATE_CONSENSUS_INTEGRATION.md.
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

# EVM/account consensus path (Phase 2 / E-D3). The executor + state manager are
# set when the contract RPC system initializes; the mempool admits eth txs for
# block inclusion. EVM_PENDING_NONCE tracks each sender's next expected account
# nonce for mempool admission (updated as txs are applied).
EVM_EXECUTOR = None
EVM_STATE_MANAGER = None
EVM_MEMPOOL = None
EVM_PENDING_NONCE = {}


def _get_evm_mempool():
    global EVM_MEMPOOL
    if EVM_MEMPOOL is None:
        from qrdx.contracts.evm_mempool import EVMMempool
        EVM_MEMPOOL = EVMMempool(
            nonce_provider=lambda addr: EVM_PENDING_NONCE.get(addr.lower(), 0)
        )
    return EVM_MEMPOOL


async def _execute_evm_raw_tx(raw_tx_hex, block_height, block_hash, block_timestamp,
                              defer_commit=False):
    """
    Execute a signed raw EVM transaction against EVM/account state (E-D3 core).

    Shared by the RPC handler, the block proposer, and import replay so all three
    apply the identical deterministic state transition. Commits or reverts
    atomically via ExecutionContext.

    ``defer_commit`` (E-D3b): when True, a successful tx's account changes are
    kept in the EVM cache instead of being flushed to the DB per-tx, so a block
    validator can execute the whole EVM section and then flush-read-decide the
    block's ``account_state_root`` atomically (see
    ``qrdx.contracts.evm_block_apply.apply_block_evm_section``).

    Returns a dict: {success, tx_hash, sender, nonce, created_address, error}.
    """
    from eth_utils import decode_hex, encode_hex
    from eth_keys import keys
    import rlp
    from eth_hash.auto import keccak
    from ..contracts.state_sync import StateSyncManager, ExecutionContext

    evm_executor = EVM_EXECUTOR
    state_manager = EVM_STATE_MANAGER
    if evm_executor is None or state_manager is None:
        return {"success": False, "error": "EVM system not initialized", "tx_hash": None}

    # Decode + recover sender (recovery binds the sender).
    try:
        raw_tx = decode_hex(raw_tx_hex)
        tx_data = rlp.decode(raw_tx)
        nonce = int.from_bytes(tx_data[0], 'big') if tx_data[0] else 0
        gas_price_wei = int.from_bytes(tx_data[1], 'big') if tx_data[1] else 0
        gas = int.from_bytes(tx_data[2], 'big') if tx_data[2] else 21000
        to_bytes = tx_data[3]
        value_wei = int.from_bytes(tx_data[4], 'big') if tx_data[4] else 0
        data = tx_data[5]
        v_int = int.from_bytes(tx_data[6], 'big')
        r_int = int.from_bytes(tx_data[7], 'big')
        s_int = int.from_bytes(tx_data[8], 'big')
        if v_int >= 35:  # EIP-155
            chain_id = (v_int - 35) // 2
            recovery_id = v_int - (chain_id * 2 + 35)
            unsigned_data = [tx_data[i] for i in range(6)] + [
                chain_id.to_bytes((chain_id.bit_length() + 7) // 8, 'big'), b'', b'']
        else:
            recovery_id = v_int - 27
            unsigned_data = [tx_data[i] for i in range(6)]
        message_hash = keccak(rlp.encode(unsigned_data))
        signature = keys.Signature(r_int.to_bytes(32, 'big') + s_int.to_bytes(32, 'big') + bytes([recovery_id]))
        sender = signature.recover_public_key_from_msg_hash(message_hash).to_canonical_address()
        sender_hex = encode_hex(sender)
        to_hex = encode_hex(to_bytes) if to_bytes else None
        tx_hash_hex = encode_hex(keccak(raw_tx))
    except Exception as e:
        return {"success": False, "error": f"decode/recover failed: {e}", "tx_hash": None}

    sync_manager = StateSyncManager(db, state_manager)
    await sync_manager.ensure_tables_exist()
    context_exec = ExecutionContext(
        block_height=block_height, block_hash=block_hash, block_timestamp=block_timestamp,
        db=db, evm_state=state_manager, sync_manager=sync_manager,
    )
    await context_exec.prepare_execution(sender_hex)
    if to_hex:
        await sync_manager.sync_address_to_evm(address=to_hex, block_height=block_height, block_hash=block_hash)

    try:
        result = evm_executor.execute(sender, to_bytes if to_bytes else None, value_wei, data, gas, gas_price_wei)
        await context_exec.finalize_execution(
            sender=sender_hex, tx_hash=tx_hash_hex, success=result.success,
            gas_used=result.gas_used, gas_price=gas_price_wei, value=value_wei,
            defer_commit=defer_commit,
        )
        if not result.success:
            return {"success": False, "error": result.error, "tx_hash": tx_hash_hex,
                    "sender": sender_hex, "nonce": nonce}
        created = encode_hex(result.created_address) if result.created_address else None
        EVM_PENDING_NONCE[sender_hex.lower()] = max(EVM_PENDING_NONCE.get(sender_hex.lower(), 0), nonce + 1)
        return {"success": True, "tx_hash": tx_hash_hex, "sender": sender_hex,
                "nonce": nonce, "created_address": created}
    except Exception as e:
        await context_exec.finalize_execution(
            sender=sender_hex, tx_hash=tx_hash_hex, success=False, gas_used=0, gas_price=0, value=0,
        )
        return {"success": False, "error": str(e), "tx_hash": tx_hash_hex,
                "sender": sender_hex, "nonce": nonce}


async def _apply_exchange_section_on_import(block_height, block_timestamp,
                                            ex_section, declared_root):
    """
    Importer hook for the exchange section, with the same strict/trust split as
    the EVM one (E-D3b). Strict (declared root present, live broadcast): validate
    + reject-on-mismatch. Trust-replay (no root, sync of canonical history):
    replay + adopt, like ``rebuild_exchange_state_from_chain``. Returns
    ``(ok, error)``; trust-replay never halts sync of a canonical block.
    """
    if not ex_section:
        return True, ""
    from ..exchange.block_processor import (
        decode_exchange_txs, preload_sender_balances, flush_exchange_balance_deltas,
        flush_token_balance_deltas, ENFORCE_EXCHANGE_COLLATERAL, ENFORCE_SPOT_SETTLEMENT,
    )
    from ..exchange.state_manager import ExchangeStateManager
    mgr = ExchangeStateManager.get_instance()
    mgr.enforce_collateral = ENFORCE_EXCHANGE_COLLATERAL
    mgr.enforce_spot_settlement = ENFORCE_SPOT_SETTLEMENT
    # Phase E: pre-load senders' real balances so the collateral check can read
    # them during the sync section processing.
    try:
        await preload_sender_balances(db, decode_exchange_txs(ex_section), mgr)
    except Exception as e:
        logger.debug(f"exchange balance pre-load skipped at block {block_height}: {e}")

    if declared_root:
        from ..exchange.block_processor import apply_block_exchange_section
        ok, err = apply_block_exchange_section(
            block_height, float(block_timestamp or 0), ex_section, declared_root,
        )
        if ok:
            # Phase E: flush margin debits to account_state + token moves to the
            # token ledger (before the E-D4 root check, so both domains reflect).
            await flush_exchange_balance_deltas(db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
            await flush_token_balance_deltas(db, mgr)
        return ok, err
    # Trust-replay (sync): adopt the canonical section's computed root.
    try:
        from ..exchange.block_processor import process_exchange_transactions
        txs = decode_exchange_txs(ex_section)
        ok, err, _root = process_exchange_transactions(
            block_height, float(block_timestamp or 0), txs, mgr,
        )
        if ok:
            mgr.commit_block()
            await flush_exchange_balance_deltas(db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
            await flush_token_balance_deltas(db, mgr)
        else:
            logger.warning(f"Exchange section trust-replay failed at block {block_height}: {err}")
        return True, ""
    except Exception as e:
        logger.warning(f"Exchange section trust-replay error at block {block_height}: {e}")
        return True, ""


# E-D4 rollout flag. Enabled after validator-set convergence: the live-broadcast
# paths (p2p/REST) recompute the unified state root and observed 0 mismatches
# across a 3-run soak (reorgs now ~0, so no transient divergence). With True, a
# live-broadcast block whose recomputed unified root != the signed root is
# REJECTED. NOTE: the check is intentionally NOT run on the bulk-sync path (a
# catching-up node can still transiently differ mid-reorg), only on stable
# live-broadcast import — see _verify_unified_state_root.
_ED4_ENFORCE_UNIFIED_ROOT = True


async def _verify_unified_state_root(block_content, enforce: Optional[bool] = None) -> Tuple[bool, str]:
    """
    E-D4: recompute the post-block unified state root (UTXO + account + exchange)
    and compare it to the block's signed ``state_root`` (in block_content).

    Must be called AFTER the block's protocol sections have been replayed but
    BEFORE the native block is applied — the same point the proposer computed it
    (UTXO pre-native-apply, account/exchange post-section). Returns ``(ok, err)``.

    ``enforce`` overrides the global gate: the live-broadcast paths use the global
    ``_ED4_ENFORCE_UNIFIED_ROOT`` (enforce); the bulk-sync path passes
    ``enforce=False`` (observe), because a catching-up node can transiently differ
    mid-reorg and must not reject canonical history.
    """
    if enforce is None:
        enforce = _ED4_ENFORCE_UNIFIED_ROOT
    from ..crypto.hashing import unified_state_root
    from ..validator.block_verification import _parse_block_content
    try:
        bc = _parse_block_content(block_content)
        declared = bc.get("state_root")
    except Exception:
        return True, ""  # malformed content is the proposer-sig check's job
    if not declared:
        return True, ""

    try:
        utxo_root = await db.get_unspent_outputs_hash()
    except Exception:
        utxo_root = "0" * 64
    try:
        account_root = await db.get_account_state_root()
    except Exception:
        account_root = "0" * 128
    try:
        from ..exchange.state_manager import ExchangeStateManager
        exchange_root = ExchangeStateManager.get_instance().compute_state_root()
    except Exception:
        exchange_root = "0" * 128

    # Token domain bound at zero (default) until token state is a consensus object
    # (Phase E spot inc4) — see _compute_unified_state_root for why.
    computed = unified_state_root(utxo_root or "0" * 64, account_root, exchange_root)
    if computed != declared:
        msg = (f"unified state root mismatch: declared {str(declared)[:16]}..., "
               f"computed {computed[:16]}...")
        if enforce:
            return False, msg
        logger.warning(f"[E-D4 observe] {msg}")
        return True, ""
    return True, ""


def _evm_defer_execute():
    """An execute_tx callable bound to the live executor, deferring per-tx commit."""
    async def _execute(raw, h, bh, bt):
        return await _execute_evm_raw_tx(raw, h, bh, bt, defer_commit=True)
    return _execute


async def _produce_evm_section(block_height, block_hash, block_timestamp, raw_txs):
    """
    Proposer hook (E-D3b execute-on-mine): execute the selected EVM section
    against live EVM state and return ``(account_state_root, included_raw_txs)``.

    ``(None, [])`` when EVM is disabled, there are no txs, or the section could
    not be produced (the proposer then ships the block without an EVM section).
    """
    if EVM_STATE_MANAGER is None or not raw_txs:
        return None, []
    from ..contracts.evm_block_apply import produce_block_evm_section
    return await produce_block_evm_section(
        block_height, block_hash, block_timestamp, raw_txs,
        db, EVM_STATE_MANAGER, _evm_defer_execute(),
    )


async def _apply_evm_section_on_import(block_height, block_hash, block_timestamp,
                                       evm_section, declared_root):
    """
    Importer hook (E-D3b): validate + replay a block's EVM section, rejecting on
    any mismatch (local state left untouched). Returns ``(ok, error)``.

    Two modes:
      - **Strict (live broadcast):** a declared ``account_state_root`` is present,
        so replay and REJECT on mismatch — real-time defense against a malicious
        proposer.
      - **Trust-replay (sync):** no root is bound to the block (the sync-serving
        endpoints attach the section but not a root, and pre-D4 the root is not
        bound into the block hash). The block is canonical history already
        accepted by the network, so replay and ADOPT the computed root, exactly
        like ``rebuild_account_state_from_chain``. Best-effort: a replay failure
        is logged but does not halt sync of a canonical block.

    Backward-compatible: an empty/absent section is accepted. If this node does
    not run the EVM system it accepts without applying (stored for later rebuild).
    """
    if not evm_section:
        return True, ""
    if EVM_STATE_MANAGER is None:
        logger.warning("EVM section present but EVM disabled on this node — storing without applying")
        return True, ""
    if declared_root:
        from ..contracts.evm_block_apply import apply_block_evm_section
        return await apply_block_evm_section(
            block_height, block_hash, block_timestamp, evm_section, declared_root,
            db, EVM_STATE_MANAGER, _evm_defer_execute(),
        )
    # Trust-replay (sync): adopt the canonical section's computed root.
    from ..contracts.evm_block_apply import produce_block_evm_section
    try:
        root, included = await produce_block_evm_section(
            block_height, block_hash, block_timestamp, evm_section,
            db, EVM_STATE_MANAGER, _evm_defer_execute(),
        )
        if root is None:
            logger.warning(f"EVM section trust-replay produced no root at block {block_height}")
        return True, ""
    except Exception as e:
        logger.warning(f"EVM section trust-replay failed at block {block_height}: {e}")
        return True, ""


async def _gossip_evm_raw_tx(raw_tx_hex: str):
    """
    Best-effort propagate a signed EVM raw transaction to peers' mempools.

    Under execute-on-mine (E-D3b) ``eth_sendRawTransaction`` is admit-only, so
    this gossip is **mempool propagation**: each peer admits the tx to its own
    EVM mempool so whichever node proposes the next block can include it. The
    peer's EVM_TX_CACHE stops the gossip from looping. (Previously this drove
    Phase-1 live execution convergence; that role is retired.)
    """
    try:
        peers = NodesManager.get_propagate_peers()
    except Exception as e:
        logger.debug("EVM gossip: could not list peers: %s", e)
        return
    for peer in peers:
        url = peer.get('url')
        if not url:
            continue
        try:
            ni = NodeInterface(url, client=http_client, db=db)
            # _propagated=True so the receiving peer does not re-broadcast on our behalf.
            await ni._rpc_call('eth_sendRawTransaction', [raw_tx_hex, True])
        except Exception as e:
            logger.debug("EVM tx gossip to %s failed: %s", url, e)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming HTTP requests using the logger."""
    import time
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
            content_length = request.headers.get('content-length')
            
            if content_length and int(content_length) > 0:
                # Read body bytes (this consumes the body, so we'll restore it)
                body_bytes = await request.body()
                
                if body_bytes:
                    # Try to parse as JSON
                    try:
                        body_str = body_bytes.decode('utf-8')
                        parsed_value = json.loads(body_str)
                        
                        # Skip empty collections
                        if isinstance(parsed_value, (dict, list)) and len(parsed_value) == 0:
                            body = None
                        else:
                            # Format as pretty JSON
                            body = json.dumps(parsed_value, indent=2)
                    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                        # Not JSON or not valid UTF-8, use raw string
                        body_str = body_bytes.decode('utf-8', errors='replace')
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
            return {'type': 'http.request', 'body': body_bytes}
        request._receive = receive
    
    # Log incoming request
    request_body_log = f"\n\nIncoming Request:\n{body}\n" if body else ""
    logger.info(f"<-- {client_ip} - \"{method} {full_path} HTTP/1.1\"{request_body_log}")
    
    # Process request
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        status_code = response.status_code
        
        # Extract and format response body if present
        response_body = None
        if LOG_INCLUDE_RESPONSE_CONTENT and hasattr(response, 'body_iterator'):
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
                    media_type=response.media_type
                )
                
                # Format body for logging
                if response_body_bytes:
                    try:
                        response_body_str = response_body_bytes.decode('utf-8')
                        parsed_value = json.loads(response_body_str)
                        
                        # Skip empty collections
                        if isinstance(parsed_value, (dict, list)) and len(parsed_value) == 0:
                            response_body = None
                        else:
                            # Format as pretty JSON
                            response_body = json.dumps(parsed_value, indent=2)
                    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                        # Not JSON or not valid UTF-8, use raw string
                        response_body_str = response_body_bytes.decode('utf-8', errors='replace')
                        if len(response_body_str) > 0:
                            response_body = response_body_str
                        else:
                            response_body = None
            except Exception:
                # Silently fail response body extraction, return original response
                response_body = None
        
        # Log response
        response_body_log = f"\n\nOutgoing Response:\n{response_body}\n" if response_body else ""
        logger.info(f"--> {client_ip} - \"{method} {full_path} HTTP/1.1\" {status_code}⁢ ({process_time:.3f}s){response_body_log}")
        
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"--> {client_ip} - \"{method} {full_path} HTTP/1.1\" ERROR ({process_time:.3f}s){request_body_log}: {e}")
        raise

async def validate_url_for_connection(url: str) -> bool:
    """Validate URL is safe for outbound connections with DNS rebinding protection"""
    if not url:
        return False
    is_valid, resolved_ip = await security.dns_client.validate_and_resolve(url)
    if not is_valid:
        return False 
    try:
        ip_obj = ipaddress.ip_address(resolved_ip)
        # Block connections to loopback, link-local, or reserved IPs
        if not ip_obj.is_global and not ip_obj.is_private:
             logger.warning(f"Blocked connection to reserved/loopback/link-local IP: {resolved_ip}")
             return False
        # If the node itself is public, it must not initiate connections to private networks
        if self_is_public and ip_obj.is_private:
            logger.warning(f"Public node blocked connection attempt to private IP: {resolved_ip}")
            return False
        return True
    except Exception as e:
        logger.error(f"Unexpected error while validating Address: {url} - {e}")
        return False


async def propagate(path: str, data: dict, ignore_node_id: str = None, db: Database = None):
    """Propagates a message with reputation tracking and rate limiting"""
    async with security.propagation_semaphore:
        all_peers = NodesManager.get_propagate_peers()
        
        # Filter out banned peers
        non_banned_peers = []
        for peer in all_peers:
            if not await security.reputation_manager.is_banned(peer['node_id']):
                non_banned_peers.append(peer)
            
        # Limit number of peers
        max_peers_to_propagate = min(len(non_banned_peers), 20)
        if len(non_banned_peers) > max_peers_to_propagate:
            all_peers = random.sample(non_banned_peers, max_peers_to_propagate)
        else:
            all_peers = non_banned_peers
        
        tasks = []

        for peer in all_peers:
            if peer['node_id'] == ignore_node_id:
                continue
            
            async def communication_task(peer_info: dict, p: str, d: dict):
                peer_id = peer_info.get('node_id', 'Unknown')
                peer_url = peer_info.get('url')

                try:
                    ni = NodeInterface(peer_info['url'], client=http_client, db=db)
                    
                    if p == 'submit_block':
                        response = await ni.submit_block(d)
                    elif p == 'push_tx':
                        response = await ni.push_tx(d['tx_hex'])
                    
                    if response and response.get('error') == 'sync_required':
                        if not db:
                            logger.warning(f"Received sync_required from {peer_id} but no DB connection available.")
                            return

                        # Use secure peer sync tracker
                        if await security.peer_sync_tracker.add_peer(peer_id):
                            remote_info = response.get('result', {})
                            next_block_needed = remote_info.get('next_block_expected')

                            if next_block_needed is not None:
                                asyncio.create_task(_push_sync_to_peer(peer_info, next_block_needed, db, d))
                        return

                    # Track successful propagation
                    await security.reputation_manager.record_good_behavior(peer_id)
                    logger.debug(f'propagate response from {peer_id}: {response}')
                
                except httpx.RequestError:
                    # The peer is unreachable (timeout, connection refused, etc.).
                    # This is a network failure, not a protocol violation. Remove them non-punitively.
                    await handle_unreachable_peer(peer_id, peer_url, "propagation")

                except Exception as e:
                    # Track failed propagation
                    await security.reputation_manager.record_violation(
                        peer_id, 'propagation_failure', severity=1, details=str(e)
                    )
                    logger.warning(f'propagate EXCEPTION from {peer_id}: {e}')

            tasks.append(communication_task(peer, path, data))

        await gather(*tasks)


async def _push_sync_to_peer(peer_info: dict, start_block: int, db_conn: Database, trigger_data: dict):
    """Push missing blocks to a lagging peer with proper resource management."""
    peer_id = peer_info.get('node_id', 'Unknown')
    peer_url = peer_info.get('url')
    sync_successful = False
    try:
        target_block_id = trigger_data.get('id')
        if target_block_id is None:
            logger.warning(f"[PUSH-SYNC] Aborted for {peer_id}: No target block ID in trigger data.")
            return

        logger.info(f"[PUSH-SYNC] Starting for {peer_id}. They need blocks from {start_block} up to (but not including) {target_block_id}.")
        
        # Pass the db object to the interface
        node_interface = NodeInterface(peer_info['url'], client=http_client, db=db_conn)
        current_block_to_send = start_block

        while current_block_to_send < target_block_id:
            remaining_blocks = target_block_id - current_block_to_send
            batch_size_limit = min(MAX_REORG_DEPTH, remaining_blocks)
            
            structured_blocks_to_send = await db_conn.get_blocks(current_block_to_send, batch_size_limit)
            if not structured_blocks_to_send:
                logger.warning(f"[PUSH-SYNC] to {peer_id} halted. Local DB has no more blocks in the required range.")
                sync_successful = False
                break

            payload_batch = []
            current_batch_bytes = 0

            for raw_block in structured_blocks_to_send:
                # db.get_blocks() returns raw row dicts — normalise into
                # the {block, transactions} structure the rest of the code expects.
                if isinstance(raw_block, dict) and 'block' in raw_block:
                    block_record = raw_block['block']
                    tx_list = raw_block.get('transactions', [])
                else:
                    block_record = raw_block
                    block_hash = block_record.get('hash') or block_record.get('block_hash')
                    try:
                        tx_list = await db_conn.get_block_transactions(block_hash, hex_only=True) if block_hash else []
                    except Exception:
                        tx_list = []
                block_size_estimate = len(block_record.get('content','')) + sum(len(str(tx)) for tx in tx_list)

                if payload_batch and current_batch_bytes + block_size_estimate > MAX_BATCH_BYTES:
                    break

                payload_item = {
                    'id': block_record['id'],
                    'block_content': block_record['content'],
                    'txs': tx_list
                }
                # Attach protocol sections so the syncing peer reconstructs
                # exchange + EVM/account state (E-D3b). Trust-replayed there.
                _bh = block_record.get('hash') or block_record.get('block_hash')
                if _bh:
                    try:
                        _ex = await db_conn.get_block_exchange_txs(_bh)
                        if _ex:
                            payload_item['exchange_transactions'] = _ex
                    except Exception:
                        pass
                    try:
                        _evm = await db_conn.get_block_evm_txs(_bh)
                        if _evm:
                            payload_item['evm_transactions'] = _evm
                    except Exception:
                        pass
                payload_batch.append(payload_item)
                current_batch_bytes += block_size_estimate
            
            if not payload_batch:
                logger.warning(f"[PUSH-SYNC] Could not form a batch for {peer_id} without exceeding size limits. Halting.")
                return

            response = await node_interface.submit_blocks(payload_batch)
            
            if not response or not response.get('ok'):
                error_msg = response.get('error', '')
                if 'Block sequence out of order' in error_msg or 'sequence desynchronized' in error_msg:
                    logger.info(f"[PUSH-SYNC] to {peer_id} ceded. Peer's state changed, another node is likely already syncing them.")
                else:
                    logger.warning(f"[PUSH-SYNC] to {peer_id} failed. Peer responded with an unexpected error: {response}")
                    await security.reputation_manager.record_violation(
                        peer_id, 'sync_rejection', severity=3
                    )
                return

            batch_len = len(payload_batch)
            logger.debug(f"[PUSH-SYNC] Peer {peer_id} accepted batch of {batch_len} blocks.")
            current_block_to_send += len(payload_batch)
            await asyncio.sleep(0.1)

        if current_block_to_send >= target_block_id:
            logger.info(f"[PUSH-SYNC] to {peer_id} complete. Sent all blocks up to {target_block_id - 1}.")
            sync_successful = True 
    
    except httpx.RequestError:
        await handle_unreachable_peer(peer_id, peer_url, "push-sync")
        
    except Exception as e:
        logger.error(f"Error during BULK push-sync to {peer_id}: {e}")
        traceback.print_exc()
        
    finally:
        await security.peer_sync_tracker.remove_peer(peer_id)
            
        
        # Only attempt to resubmit if the trigger_data was a full block payload,
        # which we can check by looking for 'block_content'.
        if sync_successful and trigger_data and 'block_content' in trigger_data:
            logger.info(f"[PUSH-SYNC] Sync for {peer_id} complete. Retrying submission of triggering block {trigger_data.get('id')}...")
            try:
                # Recreate the interface to be safe within the finally block
                final_interface = NodeInterface(peer_info['url'], client=http_client, db=db_conn)
                final_response = await final_interface.submit_block(trigger_data)
                logger.debug(f"[PUSH-SYNC] Final submission response for block {trigger_data.get('id')} from {peer_id}: {final_response}")
            
            except httpx.RequestError:
                await handle_unreachable_peer(peer_id, peer_url, "push-sync final submission")

            except Exception as e:
                logger.error(f"[PUSH-SYNC] Error during final submission for {peer_id}: {e}")
        

        logger.debug(f"Push-sync task for peer {peer_id} has finished.")


async def _follow_up_sync(sender_node_id: str):
    """
    Immediately after accepting a block, check whether the sending peer has
    even more blocks we haven't seen yet.  This eliminates the up-to-60-second
    gap between poll cycles and keeps non-validator nodes tightly in sync.
    """
    if security.sync_state_manager.is_syncing:
        return  # Don't pile on if a full sync is already running

    peer_info = NodesManager.get_peer(sender_node_id)
    if not peer_info or not peer_info.get('url'):
        return

    try:
        interface = NodeInterface(peer_info['url'], client=http_client, db=db)
        remote_status = await interface.get_status()
        if not (remote_status and remote_status.get('ok')):
            return

        remote_height = remote_status['result']['height']
        local_height = await db.get_next_block_id() - 1

        if remote_height > local_height:
            logger.info(
                f"[FOLLOW-UP] Still behind peer {sender_node_id} "
                f"(local={local_height}, remote={remote_height}). Triggering immediate sync."
            )
            await _sync_blockchain(node_id=sender_node_id)
    except Exception as e:
        logger.debug(f"[FOLLOW-UP] Check failed for {sender_node_id}: {e}")


async def check_peer_and_sync(peer_info: dict):
    """
    Checks a given peer's chain status and triggers a sync if their chain is longer.
    This is a core component of the trustless sync mechanism.
    """
    if security.sync_state_manager.is_syncing:
        # Don't start a new sync if one is already in progress to avoid race conditions.
        return

    peer_id = peer_info.get('node_id', 'Unknown')
    peer_url = peer_info.get('url')
    
    try:
        # Ensure the peer is connectable
        if not peer_info.get('url'):
            return
            
        interface = NodeInterface(peer_info['url'], client=http_client, db=db)
        remote_status_resp = await interface.get_status()
        
        if not (remote_status_resp and remote_status_resp.get('ok')):
            logger.warning(f"Could not get status from peer {peer_id} during check.")
            await security.reputation_manager.record_violation(
                peer_id, 'status_unavailable', severity=1
            )
            return

        remote_height = remote_status_resp['result']['height']
        local_height = await db.get_next_block_id() - 1

        if remote_height > local_height:
            logger.info(f"Discovered longer chain on peer {peer_id} (Remote: {remote_height} > Local: {local_height}). Initiating sync.")
            # Trigger the main sync logic, targeting this specific peer
            await _sync_blockchain(node_id=peer_id)
        # If their chain is not longer, there's nothing to do.
    
    except httpx.RequestError:
        await handle_unreachable_peer(peer_id, peer_url, "periodic status check")

    except Exception as e:
        logger.error(f"Error during status check with peer {peer_id}: {e}")


async def get_verified_sender(request: Request):
    """Verifies a request's signature with timestamp validation and reputation tracking"""
    # First check if peer is banned
    is_monitor_request = request.headers.get('x-monitor-request', 'false').lower() == 'true'

    # 2. Perform standard validation and banning checks for ALL requests.
    node_id = request.headers.get('x-node-id')
    if node_id and await security.reputation_manager.is_banned(node_id):
        await security.security_monitor.log_event('banned_peer_attempt', {
            'peer_id': node_id,
            'endpoint': request.url.path
        })
        return None
    
    peer_id = await security.auth_validator.validate_request(request)
    
    if not peer_id:
        return None

    # 3. If it's a monitor request, stop here and return the ID.
    # We have successfully verified them, but we will not treat them as a peer.
    if is_monitor_request:
        if not node_id: # A monitor must still identify itself
            return None
        #print(f"Verified monitor request from node {node_id}. Skipping peer list update.")
        return peer_id

    # 4. If it's a REGULAR peer request, proceed with the normal logic.
    peer_count = len(NodesManager.peers) if hasattr(NodesManager, 'peers') else 0
    if peer_count >= MAX_PEERS:
        NodesManager.update_peer_last_seen(peer_id)
        return peer_id
    
    peer_url = request.headers.get('x-peer-url')
    pubkey = request.headers.get('x-public-key')
    
    is_unknown = NodesManager.get_peer(peer_id) is None
    
    if is_unknown and pubkey:
        is_peer_public = False
        url_to_store = None

        if peer_url:
            if await validate_url_for_connection(peer_url):
                url_to_store = peer_url
                is_peer_public = not await is_url_local(peer_url)
            else:
                logger.warning(f"Rejected peer URL {peer_url} due to security validation")
                await security.reputation_manager.record_violation(
                    peer_id, 'invalid_url', severity=3
                )
        
        if NodesManager.add_or_update_peer(peer_id, pubkey, url_to_store, is_peer_public):
            logger.info(f"Discovered new {'public' if is_peer_public else 'private'} peer {peer_id} from their incoming request.")

    NodesManager.update_peer_last_seen(peer_id)
    await security.reputation_manager.record_good_behavior(peer_id)
    
    return peer_id


async def do_handshake_with_peer(peer_url_to_connect: str):
    """
    Performs a cryptographic handshake and state negotiation with a peer. This is the
    client-side of the handshake negotiation.
    """
    peer_id = None

    if not peer_url_to_connect or peer_url_to_connect == DENARO_SELF_URL:
        return

    if not await validate_url_for_connection(peer_url_to_connect):
        logger.warning(f"Skipping handshake with unsafe URL: {peer_url_to_connect}")
        return

    if NodesManager.self_is_public and await is_url_local(peer_url_to_connect):
        logger.debug(f"Public node skipping handshake attempt to private URL: {peer_url_to_connect}")
        return

    logger.info(f"Attempting handshake with {peer_url_to_connect}")
    try:
        interface = NodeInterface(peer_url_to_connect, client=http_client, db=db)
        
        # 1. Get Challenge from peer (which includes their chain state)
        challenge_resp = await interface.handshake_challenge()
        if not (challenge_resp and challenge_resp.get('ok')):
            logger.warning(f"Handshake failed: Did not receive challenge from {peer_url_to_connect}.")
            return

        challenge_data = challenge_resp['result']
        challenge = challenge_data.get('challenge')
        peer_id = challenge_data.get('node_id')
        peer_pubkey = challenge_data.get('pubkey')
        peer_is_public = challenge_data.get('is_public')
        peer_advertised_url = challenge_data.get('url')
        peer_height = challenge_data.get('height', -1)

        if not all([challenge, peer_id, peer_pubkey, peer_is_public is not None]):
            logger.warning(f"Handshake failed: Incomplete challenge data from {peer_url_to_connect}.")
            return
                   
        # Add or update the peer in our manager AS SOON as we have their info.
        # This makes them "known" before we attempt any sync logic.
        url_to_store = peer_advertised_url if peer_is_public and peer_advertised_url else peer_url_to_connect
        if NodesManager.add_or_update_peer(peer_id, peer_pubkey, url_to_store, peer_is_public):
            logger.info(f"Handshake Phase 1: Discovered and added new {'public' if peer_is_public else 'private'} peer {peer_id}")
        else:
            logger.debug(f"Handshake Phase 1: Discovered and updated {'public' if peer_is_public else 'private'} peer {peer_id}")
        

        # 2. Respond to Challenge
        response_resp = await interface.handshake_response(challenge)
        
        # 3. Handle the peer's response. Now we are guaranteed to find the peer in our manager.
        
        # Case A: Peer told us that WE are behind ('sync_required'). We must PULL.
        if response_resp and response_resp.get('error') == 'sync_required':
            logger.info(f"Peer {peer_id} reported that WE are out of sync. Initiating PULL-sync.")
            await _sync_blockchain(node_id=peer_id)
            return
            
        # Case B: Peer is behind and REQUESTED that we PUSH blocks to THEM ('sync_requested').
        if response_resp and response_resp.get('result') == 'sync_requested':
            logger.info(f"Peer {peer_id} is behind and requested a PUSH-sync from us.")
            sync_details = response_resp.get('detail', {})
            start_block = sync_details.get('start_block')
            target_block = sync_details.get('target_block')
            if start_block is not None and target_block is not None:
                peer_info = NodesManager.get_peer(peer_id)
                peer_info['node_id'] = peer_id
                trigger_data = {'id': target_block}
                asyncio.create_task(_push_sync_to_peer(peer_info, start_block, db, trigger_data))
            return

        # Case C: Other failure
        if not (response_resp and response_resp.get('ok')):
            logger.warning(f"Handshake failed: Peer {peer_id} rejected our response: {response_resp}")
            return

        # Case D: Handshake was successful and no sync instruction was given.
        logger.info(f"Handshake SUCCESS with peer {peer_id}.")

        # Fallback PULL trigger: If peer didn't respond with instructions but we see they are ahead.
        local_height = await db.get_next_block_id() - 1
        if peer_height > local_height:
             logger.info(f"Peer {peer_id} has longer chain ({peer_height} > {local_height}). Initiating PULL-sync.")
             await _sync_blockchain(node_id=peer_id)
        
        # 4. Perform peer exchange
        logger.debug(f"Performing peer exchange with {peer_id}")
        peers_resp = await interface.get_peers()
        if peers_resp and peers_resp.get('ok'):
            for discovered_peer in peers_resp['result']['peers']:
                if discovered_peer.get('url') and discovered_peer['node_id'] not in NodesManager.peers and discovered_peer['node_id'] != self_node_id:
                    if len(NodesManager.peers) < MAX_PEERS:
                        logger.info(f"Found node {discovered_peer['node_id']} via exchange. Attempting handshake.")
                        asyncio.create_task(do_handshake_with_peer(discovered_peer['url']))
    
    except httpx.RequestError:
        peer_id = NodesManager.find_peer_by_url(peer_url_to_connect)
        if peer_id:
            await handle_unreachable_peer(peer_id, peer_url_to_connect, "handshake")
        else:
            # If we don't know them, we can't remove them, just log it.
            logger.warning(f"Failed to connect to unknown or new peer at {peer_url_to_connect} during handshake.")

    except Exception as e:
        logger.error(f"Error during handshake with {peer_url_to_connect}: {e}")
        traceback.print_exc()
        await security.security_monitor.log_event('handshake_failure', {
            'url': peer_url_to_connect,
            'error': str(e)
        })


# ============================================================================
# KADEMLIA DHT BRIDGE
# ============================================================================


async def _dht_bridge_sync() -> None:
    """
    Bidirectional sync between Kademlia DHT routing table and NodesManager.

    - Push NodesManager peers into the DHT routing table
    - Pull DHT-discovered peers into NodesManager via handshake
    """
    if dht_discovery is None:
        return

    # --- Push: NodesManager → DHT routing table ---
    pushed = 0
    for peer_id, peer_data in list(NodesManager.peers.items()):
        url = peer_data.get('url', '')
        if not url:
            continue
        try:
            parsed = urlparse(url)
            host = parsed.hostname or 'localhost'
            port = parsed.port or 30303
            # Derive a node_id from the peer_id string if it looks like qx-hex
            if peer_id.startswith('qx') and len(peer_id) >= 42:
                nid = p2p_hex_to_node_id(peer_id)
            else:
                # Use a hash of the peer_id as a fallback node ID
                nid = hashlib.blake2b(peer_id.encode(), digest_size=20).digest()

            entry = KBucketEntry(
                node_id=nid,
                node_id_hex=peer_id if peer_id.startswith('qx') else 'qx' + nid.hex(),
                host=host,
                port=port,
                public_key_hex=peer_data.get('pubkey', ''),
                at_schema='',
                last_seen=time.monotonic(),
                added_at=time.monotonic(),
                is_inbound=False,
            )
            added, _ = dht_discovery.routing_table._buckets[
                dht_discovery.routing_table._bucket_index(nid)
            ].add_or_update(entry, rate_limit=False)
            if added:
                pushed += 1
        except Exception:
            pass  # Skip malformed peers silently

    # --- Pull: DHT routing table → NodesManager ---
    pulled = 0
    for bucket in dht_discovery.routing_table._buckets:
        for entry in bucket.entries:
            entry_node_id = entry.node_id_hex
            if entry_node_id not in NodesManager.peers and entry_node_id != self_node_id:
                if len(NodesManager.peers) < MAX_PEERS and entry.host:
                    peer_url = f"http://{entry.host}:{entry.port}"
                    asyncio.create_task(do_handshake_with_peer(peer_url))
                    pulled += 1
                    if pulled >= 10:  # Limit handshake burst per sync cycle
                        break
        if pulled >= 10:
            break

    if pushed or pulled:
        logger.debug(f"DHT bridge sync: pushed {pushed} peers to DHT, pulled {pulled} for handshake")


async def _periodic_dht_bridge() -> None:
    """Periodically sync DHT routing table with NodesManager."""
    await asyncio.sleep(10)  # Quick DHT start
    while True:
        try:
            await _dht_bridge_sync()
        except Exception as e:
            logger.error(f"DHT bridge sync error: {e}")
        await asyncio.sleep(30)  # DHT sync every 30s


async def _init_dht() -> None:
    """
    Initialize the Kademlia DHT subsystem during node startup.

    - Creates the local P2P Node from the existing identity
    - Loads or creates the routing table (with disk persistence)
    - Initializes DNS seed discovery
    - Bootstraps the DHT from DNS seeds + hardcoded bootstrap nodes
    - Starts the periodic refresh loop
    - Starts the DHT ↔ NodesManager bridge
    """
    global dht_discovery, dht_dns_seeds, dht_config

    try:
        # Build the local P2P Node from existing identity
        pub_key = get_public_key_bytes()
        listen_host = DENARO_NODE_HOST or '0.0.0.0'
        listen_port = int(DENARO_NODE_PORT) if DENARO_NODE_PORT else 30303
        local_addr = P2PAddress(ip=listen_host, tcp_port=listen_port)
        local_node = P2PNode(public_key=pub_key, address=local_addr)

        logger.info(f"DHT local node: {local_node.node_id_hex} @ {listen_host}:{listen_port}")

        # Load or create routing table with disk persistence
        persist_dir = dht_config.routing_table_path
        os.makedirs(persist_dir, exist_ok=True)

        rt_path = os.path.join(persist_dir, 'routing_table.json')
        if os.path.exists(rt_path):
            routing_table = RoutingTable.load(local_node.node_id, persist_dir)
            logger.info(f"Loaded persisted routing table: {routing_table.total_nodes} nodes")
        else:
            routing_table = RoutingTable(local_node.node_id, persist_path=persist_dir)
            logger.info("Created fresh routing table")

        # Create KademliaDiscovery instance
        dht_discovery = KademliaDiscovery(
            local_node=local_node,
            routing_table=routing_table,
            http_client=http_client,
        )

        # Initialize DNS seed discovery
        if dht_config.dns_enabled:
            dht_dns_seeds = DNSSeedDiscovery(
                seed_domains=dht_config.dns_seeds,
                require_signatures=dht_config.dns_require_signatures,
            )
            logger.info(f"DNS seed discovery enabled: {dht_config.dns_seeds}")

        # Collect bootstrap seeds: DNS seeds → hardcoded bootstrap nodes
        seed_nodes: List[Tuple[str, int]] = []

        # Try DNS seeds first
        if dht_dns_seeds is not None:
            try:
                dns_addrs = await dht_dns_seeds.discover_with_fallback(
                    hardcoded_bootstrap=[str(url) for url in BOOTSTRAP_NODES],
                )
                for addr in dns_addrs:
                    # Parse @-schema addresses or HTTP URLs
                    if '@' in addr and addr.count('@') == 2:
                        # @-schema: algo@id@host:port
                        parts = addr.split('@')
                        host_port = parts[2]
                        host, port_str = host_port.rsplit(':', 1)
                        seed_nodes.append((host, int(port_str)))
                    elif '://' in addr:
                        parsed = urlparse(addr)
                        host = parsed.hostname or 'localhost'
                        port = parsed.port or 30303
                        seed_nodes.append((host, port))
                logger.info(f"DNS seed discovery returned {len(dns_addrs)} addresses")
            except Exception as e:
                logger.warning(f"DNS seed discovery failed: {e}")

        # Always include hardcoded bootstrap nodes as fallback
        for url in BOOTSTRAP_NODES:
            try:
                parsed = urlparse(str(url).strip().rstrip('/'))
                host = parsed.hostname or 'localhost'
                port = parsed.port or 30303
                if (host, port) not in seed_nodes:
                    seed_nodes.append((host, port))
            except Exception:
                pass

        # Bootstrap the DHT
        if seed_nodes:
            discovered = await dht_discovery.bootstrap(seed_nodes)
            logger.info(f"DHT bootstrap discovered {discovered} nodes")
        else:
            logger.warning("No DHT seed nodes available — DHT will rely on incoming connections")

        # Start the periodic refresh loop
        dht_discovery.start()

        # Wire DHT into the module-level RPC module so dht_message / dht_getStats etc. work
        dht_rpc_module.set_discovery(dht_discovery, dht_dns_seeds)
        logger.info("DHT wired into RPC module (dht_* methods live)")

        # Start the bridge sync loop
        asyncio.create_task(_periodic_dht_bridge())

        logger.info("✅ Kademlia DHT subsystem initialized")

    except Exception as e:
        logger.error(f"❌ Failed to initialize DHT subsystem: {e}", exc_info=True)
        # DHT failure is non-fatal — node continues with HTTP gossip only
        dht_discovery = None
        dht_dns_seeds = None


async def bootstrap_from_all_nodes():
    """
    Bootstrap from all configured bootstrap nodes.
    
    This attempts handshakes with all bootstrap nodes to ensure
    maximum peer discovery at startup.
    """
    logger.info(f"Bootstrapping from {len(BOOTSTRAP_NODES)} configured bootstrap nodes...")
    
    successful = 0
    for node_url in BOOTSTRAP_NODES:
        node_url = node_url.strip().rstrip('/')
        if not node_url:
            continue
        
        try:
            logger.info(f"Attempting bootstrap from {node_url}")
            await do_handshake_with_peer(node_url)
            successful += 1
        except Exception as e:
            logger.warning(f"Failed to bootstrap from {node_url}: {e}")
        
        # Small delay between bootstrap attempts
        await asyncio.sleep(1)
    
    logger.info(
        f"Bootstrap complete: {successful}/{len(BOOTSTRAP_NODES)} nodes successful, "
        f"{len(NodesManager.peers)} total peers"
    )
    return successful


async def periodic_peer_discovery():
    """
    Periodically discovers new peers via gossip and verifies them via handshake.
    This version is now resilient to unreachable peers and supports multiple bootstrap nodes.
    """
    await asyncio.sleep(5)  # Start peer discovery quickly
    
    # Initial bootstrap from all configured nodes
    await bootstrap_from_all_nodes()

    # Immediately check peers for a longer chain after bootstrapping.
    # This prevents newly-started nodes from waiting a full periodic_update_fetcher
    # cycle (8s) before discovering they are behind.
    try:
        all_peers = NodesManager.get_all_peers()
        connectable = [p for p in all_peers if p.get('url')]
        if connectable:
            logger.info(f"Post-bootstrap sync check: probing {len(connectable)} peer(s) for longer chain")
            for peer_info in connectable[:3]:
                await check_peer_and_sync(peer_info)
                await asyncio.sleep(0.5)
    except Exception as e:
        logger.warning(f"Post-bootstrap sync check failed: {e}")

    while True:
        await asyncio.sleep(30)  # Refresh peers every 30s
        logger.debug("Running periodic peer discovery...")
        
        if not NodesManager.peers:
            logger.info("Peer list is empty. Re-bootstrapping from configured nodes.")
            await bootstrap_from_all_nodes()
            continue

        connectable_peers_tuples = [
            (node_id, peer_data) for node_id, peer_data in NodesManager.peers.items() if peer_data.get('url')
        ]

        if not connectable_peers_tuples:
            logger.debug("No connectable peers to ask for discovery. Waiting for new inbound connections.")
            continue

        
        # Define peer_id and peer_url here so they are in scope for the entire loop iteration.
        peer_id, peer_data_to_ask = random.choice(connectable_peers_tuples)
        peer_url = peer_data_to_ask['url']
        
        
        logger.debug(f"Asking peer {peer_id} for their peer list")
        try:
            # Use the correctly scoped variables
            interface = NodeInterface(peer_url, client=http_client, db=db)
            peers_resp = await interface.get_peers()
            
            if not (peers_resp and peers_resp.get('ok')):
                # Peer responded but with an error. This is a minor protocol violation.
                await security.reputation_manager.record_violation(peer_id, 'get_peers_failed', 1)
                continue
            
            discovered_peers = peers_resp['result']['peers']
            logger.debug(f"Discovered {len(discovered_peers)} peers from {peer_id}.")
            for discovered_peer in discovered_peers:
                if discovered_peer['node_id'] not in NodesManager.peers and discovered_peer['node_id'] != self_node_id:
                    if len(NodesManager.peers) < MAX_PEERS and discovered_peer.get('url'):
                        logger.info(f"Found new peer {discovered_peer['node_id']} via exchange. Attempting handshake.")
                        asyncio.create_task(do_handshake_with_peer(discovered_peer['url']))
        
        except httpx.RequestError:
            await handle_unreachable_peer(peer_id, peer_url, "peer discovery")

        except Exception as e:
            # Use the correctly scoped variable in the log message
            logger.error(f"Error during peer discovery with {peer_url}: {e}")

        # Supplement with DHT iterative lookup for our own node ID
        if dht_discovery is not None and len(NodesManager.peers) < MAX_PEERS:
            try:
                from qrdx.p2p.node import derive_node_id as _dni
                local_nid = _dni(get_public_key_bytes())
                dht_found = await dht_discovery.iterative_find_node(local_nid, count=10)
                for entry in dht_found:
                    if entry.node_id_hex not in NodesManager.peers and entry.node_id_hex != self_node_id:
                        if len(NodesManager.peers) < MAX_PEERS and entry.host:
                            peer_url_dht = f"http://{entry.host}:{entry.port}"
                            asyncio.create_task(do_handshake_with_peer(peer_url_dht))
            except Exception as e:
                logger.debug(f"DHT peer discovery supplement error: {e}")


async def is_url_local(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname
        if not hostname: return False
        addr_info = await asyncio.get_event_loop().getaddrinfo(hostname, None, family=socket.AF_INET)
        ip_obj = ipaddress.ip_address(addr_info[0][4][0])
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except (socket.gaierror, ValueError, IndexError):
        return False


async def check_own_reachability():
    """
    A one-time startup task to determine if the node is publicly reachable.
    Tries multiple bootstrap nodes for verification.
    """
    global self_is_public
    await asyncio.sleep(3)  # Brief startup delay

    if not DENARO_SELF_URL:
        logger.info("DENARO_SELF_URL not set. Assuming this is a private node.")
        NodesManager.set_public_status(False)
        return

    if await is_url_local(DENARO_SELF_URL):
        logger.info(f"DENARO_SELF_URL is a local address ({DENARO_SELF_URL}). Operating as a private node.")
        self_is_public = False
        NodesManager.set_public_status(False)
        return

    logger.info(f"Potential public URL is {DENARO_SELF_URL}. Asking bootstrap nodes to verify")
    
    # Try each bootstrap node until one can verify reachability
    for bootstrap_url in BOOTSTRAP_NODES:
        bootstrap_url = bootstrap_url.strip().rstrip('/')
        if not bootstrap_url:
            continue
            
        logger.debug(f"Checking reachability via {bootstrap_url}")
        bootstrap_interface = NodeInterface(bootstrap_url, client=http_client, db=db)
        
        try:
            is_reachable = await bootstrap_interface.check_peer_reachability(DENARO_SELF_URL)
            if is_reachable:
                self_is_public = True
                NodesManager.set_public_status(True)
                logger.info(f"SUCCESS: Node confirmed to be publicly reachable at {DENARO_SELF_URL}")
                return
            else:
                logger.debug(f"Bootstrap node {bootstrap_url} reports us as not reachable")

        except httpx.RequestError:
            logger.debug(f"Bootstrap node at {bootstrap_url} is unreachable, trying next...")
            continue
        
        except Exception as e:
            logger.debug(f"Error checking reachability via {bootstrap_url}: {e}")
            continue
    
    # None of the bootstrap nodes could verify us
    self_is_public = False
    NodesManager.set_public_status(False)
    logger.warning(
        f"DENARO_SELF_URL is set to {DENARO_SELF_URL}, but no bootstrap node could verify reachability. "
        f"Operating as a private node."
    )


async def periodic_update_fetcher():
    """
    A background task that runs for ALL nodes to discover new blocks and transactions.
    It periodically polls random peers to ensure the node is on the heaviest chain
    and to learn about new unconfirmed transactions.
    """
    await asyncio.sleep(5)  # Fast start — begin polling almost immediately

    logger.info("Starting periodic update fetcher for this node...")
    while True:
        await asyncio.sleep(8)  # Poll every 8s for fast chain convergence
        
        # 1. CHECK FOR LONGER CHAINS (BLOCK SYNC)
        if not security.sync_state_manager.is_syncing:
            all_peers = NodesManager.get_all_peers()
            connectable_peers = [p for p in all_peers if p.get('url')]

            if connectable_peers:
                # Probe up to 2 random peers to find a potentially longer chain
                peers_to_probe = random.sample(connectable_peers, k=min(len(connectable_peers), 2))
                logger.debug(f"Probing {len(peers_to_probe)} peer(s) for a longer chain")
                for peer_info in peers_to_probe:
                    await check_peer_and_sync(peer_info)
                    await asyncio.sleep(1) # Small delay between probes
        
        # 2. CHECK FOR NEW TRANSACTIONS (MEMPOOL SYNC)
        all_peers = NodesManager.get_all_peers()
        connectable_peers = [p for p in all_peers if p.get('url')]

        if not connectable_peers:
            continue

        # Ask one random peer for their mempool
        peer_to_ask = random.choice(connectable_peers)
        interface = NodeInterface(peer_to_ask['url'], client=http_client, db=db)
        peer_id = peer_to_ask['node_id']
        peer_url = peer_to_ask['url']
        
        logger.debug(f"Polling peer {peer_id} for new transactions")
        try:
            mempool_hashes_resp = await interface.get_mempool_hashes()
            
            if mempool_hashes_resp is None or not mempool_hashes_resp.get('ok'):
                logger.warning(f"Could not get mempool hashes from {peer_id}. Skipping transaction sync.")
                continue 

            remote_hashes = set(mempool_hashes_resp['result'])
            local_hashes = set(await db.get_all_pending_transaction_hashes())
            needed_hashes = list(remote_hashes - local_hashes)

            if needed_hashes:
                logger.debug(f"Discovered {len(needed_hashes)} new transaction(s) from {peer_id}. Fetching...")
                
                for i in range(0, len(needed_hashes), MAX_TX_FETCH_LIMIT):
                    batch = needed_hashes[i:i+MAX_TX_FETCH_LIMIT]
                    fetched_txs_resp = await interface.get_transactions_by_hash(batch)
                    
                    if fetched_txs_resp and fetched_txs_resp.get('ok'):
                        transactions_to_propagate = []
                        for tx_hex in fetched_txs_resp['result']:
                            try:
                                is_valid, error_msg = security.input_validator.validate_transaction_data(tx_hex)
                                if not is_valid:
                                    logger.warning(f"Skipping invalid transaction from peer: {error_msg}")
                                    continue
                                    
                                tx = await Transaction.from_hex(tx_hex)
                                if await security.transaction_pool.add_transaction(tx.hash(), tx, db):
                                    logger.debug(f"  -> Accepted new pending transaction {tx.hash()[:10]}")
                                    transactions_to_propagate.append(tx_hex)
                            except Exception as e:
                                logger.error(f"Error processing fetched transaction: {e}")
                        
                        if transactions_to_propagate:
                            logger.debug(f"Propagating {len(transactions_to_propagate)} newly learned transactions...")
                            for tx_hex in transactions_to_propagate:
                                asyncio.create_task(
                                    propagate('push_tx', {'tx_hex': tx_hex}, ignore_node_id=peer_to_ask['node_id'])
                                )
                    else:
                        logger.warning(f"Failed to fetch full transaction data for batch.")
        
        except httpx.RequestError:
            await handle_unreachable_peer(peer_id, peer_url, "periodic mempool fetch")

        except Exception as e:
            logger.error(f"An unexpected error occurred during periodic fetch from {peer_id}: {e}")
            traceback.print_exc()


async def process_and_create_block(block_info: dict) -> bool:
    """Processes a single block dictionary with validation.
    
    Supports both PoW blocks (hex content → manager.create_block) and
    PoS blocks (already-committed dict data → direct DB insert).
    """
    block = block_info['block']
    txs_hex = block_info.get('transactions', [])
    block_content = block.get('content', '')

    block_height = block.get('id') or block.get('block_height', 0)
    block_hash = block.get('hash') or block.get('block_hash', '')
    validator_address = block.get('address') or block.get('validator_address', '')

    # ---- PoS fast-path ----
    # If we already have a block_hash (produced by a validator) we store it
    # directly rather than running the PoW validation pipeline.
    if block_hash and validator_address:
        # Security: basic sanity checks even during sync
        if not isinstance(block_hash, str) or len(block_hash) < 16:
            logger.warning(f"[SYNC] Rejecting block with malformed hash at height {block_height}")
            return False

        # Security: block height must be exactly the next expected
        expected_height = await db.get_next_block_id()
        if block_height != expected_height:
            logger.warning(
                f"[SYNC] Rejecting PoS block: height {block_height} != expected {expected_height}"
            )
            return False

        # Security: authenticate the proposer — verify the carried public key
        # derives to the claimed validator address (identity binding) and the
        # Dilithium signature over the signed header is valid. Without this an
        # imported block is only "from a registered address", not proven to be
        # produced by that validator.
        ok_prop, prop_err = verify_pos_block_proposer(block_content, validator_address)
        if not ok_prop:
            logger.warning(f"[SYNC] Rejecting PoS block {block_height}: proposer auth failed: {prop_err}")
            return False

        # Security: verify the proposer is the validator selected for this slot
        # (catches signature-valid but out-of-turn proposals). Observe-first.
        ok_elig, elig_err = await verify_proposer_eligibility(
            db, block_content, enforce=_ENFORCE_PROPOSER_ELIGIBILITY,
        )
        if not ok_elig:
            logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {elig_err}")
            return False

        # D3/E-D3b: replay the exchange section (if any) before storing. Strict
        # (reject-on-mismatch) when a root is declared (live broadcast); trust-
        # replay (adopt) when syncing canonical history with no bound root.
        ex_section = block.get('exchange_transactions') or block_info.get('exchange_transactions')
        if ex_section:
            declared = block.get('exchange_state_root') or block_info.get('exchange_state_root')
            ok, verr = await _apply_exchange_section_on_import(
                block_height, block.get('timestamp', 0) or 0, ex_section, declared,
            )
            if not ok:
                logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {verr}")
                return False

        # E-D3b: validate + replay the EVM section (execute-on-mine) before
        # storing — reject any block whose account_state_root doesn't match.
        evm_section = block.get('evm_transactions') or block_info.get('evm_transactions')
        if evm_section:
            ts_evm = block.get('timestamp', 0) or 0
            if hasattr(ts_evm, 'timestamp'):
                ts_evm = int(ts_evm.timestamp())
            declared_acc = block.get('account_state_root') or block_info.get('account_state_root')
            ok_evm, verr_evm = await _apply_evm_section_on_import(
                block_height, block_hash, int(ts_evm), evm_section, declared_acc,
            )
            if not ok_evm:
                logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {verr_evm}")
                return False

        # E-D4 (link 5b): run the unified-state-root check on the bulk-sync path in
        # OBSERVE mode (enforce=False) — warn on mismatch but never reject, because
        # a catching-up node can transiently differ mid-reorg and must not drop
        # canonical history. This gives visibility into sync-path state consistency
        # (now that reorgs are ~0 + finality bounds them) to decide whether sync
        # enforcement is safe; the live-broadcast paths still enforce.
        try:
            await _verify_unified_state_root(block_content, enforce=False)
        except Exception as e:
            logger.debug(f"[SYNC] E-D4 observe check skipped for block {block_height}: {e}")

        try:
            timestamp_val = block.get('timestamp', 0)
            await db.add_block(
                block_hash=block_hash,
                block_height=block_height,
                block_content=block_content or '',
                validator_address=validator_address,
                timestamp=timestamp_val,
            )
            # Store accompanying transactions
            for tx_hex in (txs_hex or []):
                try:
                    tx = await Transaction.from_hex(tx_hex)
                    await db.add_transaction(tx, block_hash)
                except Exception:
                    pass  # Non-critical during sync
            # D2.2b: persist the (now-validated) exchange section so a node rebuilt
            # from peers carries the same protocol-level state.
            if ex_section:
                try:
                    await db.add_block_exchange_txs(block_hash, ex_section)
                except Exception as e:
                    logger.warning(f"[SYNC] Failed to store exchange section for block {block_height}: {e}")
            # E-D3b: persist the (now-validated) EVM section for durability/rebuild.
            if evm_section:
                try:
                    await db.add_block_evm_txs(block_hash, evm_section)
                except Exception as e:
                    logger.warning(f"[SYNC] Failed to store EVM section for block {block_height}: {e}")
            # Finality (observe): record this block's attestation votes + recompute
            # justified/finalized. Best-effort; never blocks block storage.
            try:
                from ..validator.finality import record_finality_from_block
                await record_finality_from_block(db, block_content)
            except Exception as e:
                logger.debug(f"[SYNC] finality record skipped for block {block_height}: {e}")
            logger.debug(f"[SYNC] Stored PoS block {block_height} ({block_hash[:16]}...) validator={validator_address[:20]}")
            return True
        except Exception as e:
            logger.error(f"[SYNC] Failed to store PoS block {block_height}: {e}")
            return False

    # ---- Legacy PoW path ----
    if not block_content:
        logger.warning(f"Sync failed: No block content for block {block_height}.")
        return False

    # Validate block content size
    if len(block_content) > MAX_BLOCK_CONTENT_SIZE:
        logger.warning(f"Sync failed: Block content too large for block {block_height}.")
        return False
    
    try:
        transactions = []
        for tx_hex in txs_hex:
            is_valid, error_msg = security.input_validator.validate_transaction_data(tx_hex)
            if not is_valid:
                logger.warning(f"Sync failed: Invalid transaction in block {block_height}: {error_msg}")
                return False
            transactions.append(await Transaction.from_hex(tx_hex))

    except Exception as e:
        logger.error(f"Sync failed: Could not deserialize transactions for block {block_height}: {e}")
        return False

    if not await create_block(block_content, transactions):
        logger.warning(f"Sync failed: Invalid block received from peer at height {block_height}.")
        return False
        
    return True


async def handle_reorganization(node_interface: NodeInterface, local_height: int):
    """Handles blockchain reorganization with proper validation"""
    logger.warning(f"[REORG] Fork detected! Starting reorganization process from local height {local_height}.")

    last_common_block_id = -1
    check_height = local_height

    # Find the last common block
    while check_height >= 0:
        local_block = await db.get_block_by_id(check_height)
        if not local_block:
            logger.error(f"[REORG] Error: Could not retrieve local block at height {check_height}. Halting search.")
            break

        try:
            remote_block_info = await node_interface.get_block(str(check_height))
            if remote_block_info and remote_block_info.get('ok'):
                remote_hash = remote_block_info['result']['block']['hash']
                if remote_hash == local_block['hash']:
                    last_common_block_id = check_height
                    logger.info(f"[REORG] Found common ancestor at block height: {last_common_block_id}")
                    break
            else:
                logger.warning(f"[REORG] Could not get remote block at height {check_height}. Aborting search.")
                return None
        
        except httpx.RequestError:
            logger.warning(f"[REORG] Peer became unreachable during common ancestor search. Aborting.")
            # Let the caller handle the peer removal.
            return None

        except Exception as e:
            logger.error(f"[REORG] Network error while finding common ancestor at height {check_height}: {e}")
            return None

        if (local_height - check_height) > 200:
            logger.warning("[REORG] Reorganization depth exceeds 200 blocks. Aborting for safety.")
            return None
        
        check_height -= 1

    if last_common_block_id == -1:
        logger.warning("[REORG] Could not find a common ancestor. Local chain appears invalid. Will perform a full rollback.")

    logger.info(f"[REORG] Collecting transactions from orphaned blocks between {last_common_block_id + 1} and {local_height}.")
    orphaned_txs = []
    orphaned_exchange_sections = []
    orphaned_evm_sections = []
    for height in range(last_common_block_id + 1, local_height + 1):
        block = await db.get_block_by_id(height)
        if block:
            block_txs = await db.get_block_transactions(block['hash'], hex_only=False)
            orphaned_txs.extend([tx for tx in block_txs if not isinstance(tx, CoinbaseTransaction)])
            # Capture orphaned exchange sections so their txs can be re-queued.
            try:
                section = await db.get_block_exchange_txs(block['hash'])
                if section:
                    orphaned_exchange_sections.append(section)
            except Exception:
                pass
            # Capture orphaned EVM sections so their txs can be re-queued (E-D3b).
            try:
                evm_sec = await db.get_block_evm_txs(block['hash'])
                if evm_sec:
                    orphaned_evm_sections.append(evm_sec)
            except Exception:
                pass

    # Finality guard (link 5 — ENFORCED): a reorg must never roll back below an
    # irreversibly finalized block (≥2/3 stake attested at least that deep).
    # Refusing such a reorg bounds reorg depth to the finality lag and rejects any
    # peer chain that conflicts with finality. Enabled after observe-mode soak
    # showed legitimate reorgs never cross finality (0 crossings, deterministic
    # boundary across nodes). Gated for revertibility.
    if _ENFORCE_FINALITY_REORG_GUARD:
        try:
            from ..validator.finality import finalized_block_height
            _final_h = await finalized_block_height(db)
        except Exception as e:
            logger.debug(f"[REORG] finality guard check skipped: {e}")
            _final_h = -1
        if _final_h >= 0 and last_common_block_id < _final_h:
            logger.error(
                f"[REORG][finality] REFUSING reorg: would roll back to "
                f"{last_common_block_id}, below finalized height {_final_h}. The "
                f"peer chain conflicts with finality (>1/3 stake would have "
                f"equivocated) — keeping our finalized chain."
            )
            return None  # caller aborts the sync cycle; local finalized chain kept

    logger.info(f"[REORG] Rolling back local chain to block {last_common_block_id}.")
    await db.remove_blocks(last_common_block_id + 1)

    # E-D3b reorg safety: account_state is durable, so a rolled-back block's
    # account changes remain committed — rebuild EVM/account state to the new
    # canonical tip (clears account_state, reseeds genesis, replays canonical EVM
    # sections). This runs FIRST so the durable ledger is reset to a clean
    # genesis+EVM base BEFORE the exchange rebuild below re-applies its collateral
    # debits on top (a flush before this clear would be wiped). When EVM is
    # disabled, clear+reseed genesis directly so the same clean base exists.
    if EVM_STATE_MANAGER is not None:
        try:
            from ..contracts.evm_block_apply import rebuild_account_state_from_chain
            await rebuild_account_state_from_chain(db, EVM_STATE_MANAGER, _evm_defer_execute())
        except Exception as e:
            logger.error(f"[REORG] EVM/account state rebuild failed: {e}")
    else:
        try:
            await db.clear_account_state()
            await db.seed_genesis_account_state()
            await db.connection.commit()
        except Exception as e:
            logger.error(f"[REORG] account_state genesis reseed failed: {e}")

    # Phase E spot reorg safety: clear the durable token ledger so the exchange
    # rebuild below re-applies the canonical token deploys/transfers onto a clean
    # base (the registry is re-created idempotently). Mirrors the account_state
    # clear+reseed above.
    try:
        await db.clear_token_balances()
    except Exception as e:
        logger.error(f"[REORG] token ledger clear failed: {e}")

    # D3 + Phase E reorg safety: rebuild exchange state to the new canonical tip so
    # the orphaned blocks' exchange effects are dropped, AND re-flush each canonical
    # block's collateral debits onto the freshly reseeded account_state ledger (it
    # was just cleared above, so the live debits are gone and must be replayed) +
    # its token moves onto the freshly cleared token ledger.
    try:
        from ..exchange.block_processor import rebuild_exchange_state_from_chain
        await rebuild_exchange_state_from_chain(db, flush_to_account_state=True)
    except Exception as e:
        logger.error(f"[REORG] Exchange state rebuild failed: {e}")

    logger.info(f"[REORG] Re-adding {len(orphaned_txs)} orphaned transactions to the pending pool.")
    for tx in orphaned_txs:
        try:
            await security.transaction_pool.add_transaction(tx.hash(), tx, db)
        except Exception as e:
            logger.error(f"[REORG] Could not re-add orphaned transaction {tx.hash()}: {e}")

    # Re-queue orphaned exchange txs to the exchange mempool (re-verified on admit)
    # so they can be re-included on the new canonical chain.
    if orphaned_exchange_sections:
        try:
            from ..exchange.block_processor import decode_exchange_txs
            mp = _get_exchange_mempool()
            requeued = 0
            for section in orphaned_exchange_sections:
                for tx in decode_exchange_txs(section):
                    ok, _err = mp.admit(tx)
                    if ok:
                        requeued += 1
            logger.info(f"[REORG] Re-queued {requeued} orphaned exchange tx(s)")
        except Exception as e:
            logger.error(f"[REORG] Could not re-queue orphaned exchange txs: {e}")

    # Re-queue orphaned EVM txs to the EVM mempool (re-verified on admit) so they
    # can be re-included on the new canonical chain (E-D3b).
    if orphaned_evm_sections:
        try:
            from ..contracts.evm_block import decode_evm_txs
            mp = _get_evm_mempool()
            requeued = 0
            for section in orphaned_evm_sections:
                for raw in decode_evm_txs(section):
                    ok, _err, _h = mp.admit(raw)
                    if ok:
                        requeued += 1
            logger.info(f"[REORG] Re-queued {requeued} orphaned EVM tx(s)")
        except Exception as e:
            logger.error(f"[REORG] Could not re-queue orphaned EVM txs: {e}")

    return last_common_block_id


async def _sync_blockchain(node_id: str = None): 
    """Synchronizes the local blockchain with proper state management"""
    # Bail out early if a sync is already running — don't raise an exception.
    if security.sync_state_manager.is_syncing:
        logger.debug("[SYNC] Skipping: another sync operation is already in progress.")
        return

    try:
        async with security.sync_state_manager.acquire_sync():
            logger.info('[SYNC] Starting blockchain synchronization process...')

            peer_to_sync_from = None
            if node_id:
                peer_to_sync_from = NodesManager.get_peer(node_id)
                if peer_to_sync_from:
                    peer_to_sync_from['node_id'] = node_id
            else:
                active_peers = NodesManager.get_propagate_peers(limit=1)
                if active_peers:
                    peer_to_sync_from = active_peers[0]

            if not peer_to_sync_from:
                logger.warning("[SYNC] Aborting: No known (or specified) peer to sync from.")
                return

            peer_url = peer_to_sync_from['url']
            peer_id = peer_to_sync_from['node_id']
            logger.info(f"[SYNC] Attempting to sync with peer {peer_id} at {peer_url}")
            
            node_interface = NodeInterface(peer_url, client=http_client, db=db)

            last_local_block = await db.get_last_block()
            local_height = last_local_block['id'] if last_local_block else -1
            
            remote_status_resp = await node_interface.get_status()

            if not (remote_status_resp and remote_status_resp.get('ok')):
                logger.warning(f"[SYNC] Failed to get chain status from {peer_url}. Aborting.")
                return
                
            remote_status = remote_status_resp['result']
            remote_height = remote_status['height']
            
            logger.info(f"[SYNC] Local height: {local_height}, Remote height: {remote_height}")

            if remote_height <= local_height:
                logger.debug("[SYNC] Local chain is at or ahead of remote. No sync needed.")
                return

            logger.info("[SYNC] Remote chain is longer.")
            
            fork_detected = False
            if local_height > -1:
                local_last_hash = last_local_block['hash']
                remote_block_resp = await node_interface.get_block(str(local_height))
                
                if not (remote_block_resp and remote_block_resp.get('ok')):
                    logger.warning("[SYNC] Could not fetch remote block for integrity check. Aborting.")
                    return
                
                remote_block_at_our_height = remote_block_resp['result']
                if remote_block_at_our_height['block']['hash'] != local_last_hash:
                    logger.warning(f"[SYNC] Fork detected. Our tip is on a shorter fork.")
                    fork_detected = True
            else:
                logger.info("[SYNC] Local chain is empty. Beginning initial block download.")

            if fork_detected:
                reorg_result = await handle_reorganization(node_interface, local_height)
                if reorg_result is None:
                    logger.error("[SYNC] Reorganization failed. Aborting sync cycle.")
                    return
            
            logger.info("[SYNC] Starting block fetching process.")
            while True:
                start_block_id = await db.get_next_block_id()

                if start_block_id > remote_height:
                    logger.info("[SYNC] Local height now meets or exceeds remote height. Sync appears complete.")
                    break

                logger.debug(f"[SYNC] Fetching {MAX_REORG_DEPTH} blocks starting from block {start_block_id}...")
                
                blocks_resp = await node_interface.get_blocks(start_block_id, MAX_REORG_DEPTH)
                
                if not (blocks_resp and blocks_resp.get('ok')):
                    logger.warning("[SYNC] Failed to fetch a batch of blocks from peer. Aborting sync cycle.")
                    break
                
                blocks_batch = blocks_resp['result']
                if not blocks_batch:
                    logger.info('[SYNC] No more blocks returned by peer. Sync presumed complete.')
                    break
                
                for block_data in blocks_batch:
                    if not await process_and_create_block(block_data):
                        logger.error("[SYNC] FATAL ERROR: Failed to create blocks during sync. Aborting.")
                        await security.reputation_manager.record_violation(
                            peer_to_sync_from['node_id'], 'invalid_sync_block', severity=8
                        )
                        return
                    await asyncio.sleep(0)

                NodesManager.update_peer_last_seen(peer_to_sync_from['node_id'])
    

    except httpx.RequestError:
        if peer_to_sync_from:
            await handle_unreachable_peer(peer_to_sync_from.get('node_id', 'unknown'),  peer_to_sync_from.get('url'), "blockchain sync")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SYNC] An unexpected error occurred during the sync process: {e}")
        import traceback
        traceback.print_exc()
    finally:
        logger.info('[SYNC] Synchronization process finished.')


async def handle_unreachable_peer(peer_id: str, peer_url: str, context: str):
    """
    Centralized handler for when a peer is unreachable.
    This action is NOT punitive. It simply removes the peer from the active
    list for this session to prevent wasting resources. The peer can be re-discovered later.
    """
    logger.warning(f"Peer {peer_id} at {peer_url} is unreachable ({context}). Removing from active peer list.")
    NodesManager.remove_peer(peer_id)



# ============================================================================
# APPLICATION STARTUP/SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup():
    global db, self_node_id, http_client  # Add http_client here
    
    logger.info("Starting Denaro Node Server...")

    # Initialize the shared HTTP client for the application's lifespan
    http_client = httpx.AsyncClient(timeout=CONNECTION_TIMEOUT)
    logger.info("Shared HTTP client initialized.")
    
    # Initialize security components
    await security.startup()
    
    NodesManager.purge_peers()
    initialize_identity()
    self_node_id = get_node_id()
    NodesManager.init(self_node_id)

    # Initialize SQLite database
    db_path = str(DENARO_DATABASE_PATH) if DENARO_DATABASE_PATH else 'data/qrdx.db'
    logger.info(f"Using SQLite database: {db_path}")

    # Ensure the database directory exists
    import os
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)

    db = await Database.create(db_path=db_path)
    
    logger.info("Clearing pending transaction pool.")
    await db.remove_all_pending_transactions()
    logger.info("Pending transaction pool cleared.")
    
    # Initialize genesis if needed (PoS)
    logger.info("Checking genesis state...")
    from ..validator.genesis_init import initialize_genesis_if_needed
    
    # Look for genesis configuration file in testnet directory
    genesis_file = None
    if DENARO_DATABASE_PATH:
        # Extract directory from database path
        db_dir = os.path.dirname(DENARO_DATABASE_PATH)
        testnet_dir = os.path.dirname(db_dir)  # Go up one level from databases/
        potential_genesis = os.path.join(testnet_dir, 'genesis_config.json')
        if os.path.exists(potential_genesis):
            genesis_file = potential_genesis
            logger.info(f"Found genesis configuration: {genesis_file}")
    
    genesis_created = await initialize_genesis_if_needed(db, genesis_file=genesis_file)
    if genesis_created:
        logger.info("Genesis block created for PoS network")
    else:
        logger.info("Genesis block already exists")

    # D3 durability: rebuild exchange state from the stored canonical block
    # sections so it survives a restart / fresh resync (no-op on a fresh chain).
    try:
        from ..exchange.block_processor import rebuild_exchange_state_from_chain
        root = await rebuild_exchange_state_from_chain(db)
        logger.info(f"Exchange state initialized from chain (root={root[:16]}...)")
    except Exception as e:
        logger.warning(f"Exchange state rebuild on startup skipped: {e}")

    # Initialize PoS validator if enabled
    validator_node = None
    validator_enabled = os.getenv('QRDX_VALIDATOR_ENABLED', 'false').lower() == 'true'
    if validator_enabled:
        logger.info("🔷 PoS Validator Mode Enabled")
        validator_wallet_path = os.getenv('QRDX_VALIDATOR_WALLET')
        validator_password = os.getenv('QRDX_VALIDATOR_PASSWORD', '')
        
        if validator_wallet_path and os.path.exists(validator_wallet_path):
            try:
                from ..validator.node_integration import initialize_validator_node
                validator_node = await initialize_validator_node(
                    db, 
                    validator_wallet_path, 
                    validator_password,
                    broadcast_callback=propagate  # Pass propagate function for block broadcasting
                )
                
                if validator_node:
                    logger.info(f"✅ Validator node started: {validator_node.wallet.address}")
                    # Store globally for access in endpoints
                    app.state.validator = validator_node
                    # Phase D2.2: let the proposer include admitted exchange txs.
                    try:
                        validator_node.set_exchange_tx_source(_get_exchange_mempool())
                    except Exception as e:
                        logger.warning(f"Could not attach exchange tx source: {e}")
                    # E-D3b: let the proposer include admitted EVM txs (execute-on-
                    # mine). The producer reads the EVM globals lazily, so it works
                    # once the EVM system finishes initializing below.
                    try:
                        validator_node.set_evm_tx_source(_get_evm_mempool())
                        validator_node.set_evm_section_producer(_produce_evm_section)
                    except Exception as e:
                        logger.warning(f"Could not attach EVM tx source/producer: {e}")
                else:
                    logger.error("❌ Failed to initialize validator node")
            except Exception as e:
                logger.error(f"❌ Validator initialization error: {e}", exc_info=True)
        else:
            logger.warning(f"⚠️  Validator wallet not found: {validator_wallet_path}")
    
    # ---- Wire module-level RPC server into app.state ----
    app.state.dht_rpc_module = dht_rpc_module
    app.state.rpc_server = rpc_server

    # ---- Wire P2P RPC module with live node context ----
    p2p_rpc_module.set_node_context(
        db=db,
        security=security,
        propagate_fn=propagate,
        process_and_create_block=process_and_create_block,
        create_block=create_block,
        block_processing_lock=block_processing_lock,
        nodes_manager=NodesManager,
        self_node_id=self_node_id,
        sync_blockchain=_sync_blockchain,
        follow_up_sync=_follow_up_sync,
        evm_apply_section=_apply_evm_section_on_import,  # E-D3b importer hook
        exchange_apply_section=_apply_exchange_section_on_import,  # D3/Phase E importer hook (flushes collateral)
        verify_unified_root=_verify_unified_state_root,  # E-D4 importer hook
        enforce_proposer_eligibility=_ENFORCE_PROPOSER_ELIGIBILITY,  # slot-eligibility gate
    )

    logger.info(f"✅ JSON-RPC server initialized (dht_* + p2p_* always-on): {len(rpc_server.get_methods())} methods")
    logger.info(f"   RPC endpoint: http://{DENARO_NODE_HOST}:{DENARO_NODE_PORT}/rpc")

    # ---- Optional EVM / chain RPC modules (gated by QRDX_RPC_ENABLED) ----
    rpc_enabled = os.getenv('QRDX_RPC_ENABLED', 'false').lower() == 'true'
    if rpc_enabled:
        logger.info("🔷 EVM / chain JSON-RPC modules enabled")
        try:
            from ..rpc.modules.eth import EthModule
            from ..rpc.modules.qrdx import QRDXModule
            from ..rpc.modules.net import NetModule
            from ..contracts import ContractStateManager, QRDXEVMExecutor
            
            # Initialize contract system first
            logger.info("Initializing contract execution system...")
            state_manager = ContractStateManager(db)
            evm_executor = QRDXEVMExecutor(state_manager)
            # Expose for the EVM consensus path (proposer inclusion + import replay,
            # E-D3) so block production / import can execute EVM txs with the same
            # executor + state manager as the live RPC handler.
            global EVM_EXECUTOR, EVM_STATE_MANAGER
            EVM_EXECUTOR = evm_executor
            EVM_STATE_MANAGER = state_manager
            logger.info("✅ Contract system initialized")
            
            # Create context for modules
            from dataclasses import dataclass
            @dataclass
            class RPCContext:
                db: Any
                config: Any = None
                helpers: Any = None
                state_manager: Any = None
                evm_executor: Any = None
            
            context = RPCContext(
                db=db,
                state_manager=state_manager,
                evm_executor=evm_executor
            )
            
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
            async def eth_sendTransaction_handler(tx_params):
                """Deploy or call a contract (requires signed transaction)."""
                try:
                    from eth_utils import to_canonical_address, encode_hex, decode_hex
                    from eth_keys import keys
                    from eth_account._utils.signing import serializable_unsigned_transaction_from_dict, encode_transaction
                    from eth_account._utils.legacy_transactions import Transaction as LegacyTransaction
                    from decimal import Decimal
                    import rlp
                    
                    if not tx_params:
                        raise Exception("Missing transaction parameters")
                    
                    # Extract signature components
                    r = tx_params.get('r')
                    s = tx_params.get('s')
                    v = tx_params.get('v')
                    
                    if not r or not s or not v:
                        raise Exception("Transaction must be signed (missing r, s, or v)")
                    
                    # Extract transaction parameters
                    to_hex = tx_params.get('to', '')
                    data_hex = tx_params.get('data', '0x')
                    gas = int(tx_params.get('gas', '1000000'))
                    gas_price_wei = int(tx_params.get('gasPrice', '1000000000'))
                    value_wei = int(tx_params.get('value', '0'))
                    nonce = int(tx_params.get('nonce', '0'))
                    
                    # Build unsigned transaction for signature recovery
                    unsigned_tx = LegacyTransaction(
                        nonce=nonce,
                        gas_price=gas_price_wei,
                        gas=gas,
                        to=decode_hex(to_hex) if to_hex else b'',
                        value=value_wei,
                        data=decode_hex(data_hex)
                    )
                    
                    # Convert r, s, v to integers
                    r_int = int(r, 16) if isinstance(r, str) else r
                    s_int = int(s, 16) if isinstance(s, str) else s
                    v_int = int(v, 16) if isinstance(v, str) else v
                    
                    # Recover sender from signature
                    # v is chain_id * 2 + 35 or 36 for EIP-155, or 27/28 for legacy
                    if v_int >= 35:
                        # EIP-155
                        chain_id = (v_int - 35) // 2
                        recovery_id = v_int - (chain_id * 2 + 35)
                    else:
                        # Legacy
                        recovery_id = v_int - 27
                        chain_id = None
                    
                    # Hash the unsigned transaction
                    if chain_id is not None:
                        # EIP-155 signing hash
                        tx_for_hash = LegacyTransaction(
                            nonce=nonce,
                            gasPrice=gas_price_wei,  # camelCase!
                            gas=gas,
                            to=decode_hex(to_hex) if to_hex else b'',
                            value=value_wei,
                            data=decode_hex(data_hex)
                        )
                        msg_hash = rlp.encode(list(tx_for_hash) + [chain_id, 0, 0])
                    else:
                        msg_hash = rlp.encode(unsigned_tx)
                    
                    from eth_hash.auto import keccak
                    message_hash = keccak(msg_hash)
                    
                    # Recover public key and address
                    signature_bytes = r_int.to_bytes(32, 'big') + s_int.to_bytes(32, 'big')
                    signature = keys.Signature(signature_bytes=signature_bytes)
                    
                    public_key = signature.recover_public_key_from_msg_hash(message_hash)
                    sender = public_key.to_canonical_address()
                    sender_hex = encode_hex(sender)
                    
                    logger.info(f"eth_sendTransaction: from={sender_hex}, to={to_hex}, data_len={len(data_hex)}, signed=True")
                    
                    to = decode_hex(to_hex) if to_hex else None
                    data = decode_hex(data_hex)
                    
                    # Convert wei to QRDX (1 QRDX = 10^18 wei for Ethereum compatibility)
                    value_qrdx = Decimal(value_wei) / Decimal(10**18)
                    gas_price_qrdx = Decimal(gas_price_wei) / Decimal(10**18)
                    
                    logger.info(f"Executing EVM: sender={sender_hex}, to={encode_hex(to) if to else 'CONTRACT_DEPLOY'}, data_len={len(data)}, value={value_qrdx} QRDX")
                    
                    result = evm_executor.execute(
                        sender,
                        to,
                        int(value_qrdx * Decimal(10**18)),  # Convert back to wei
                        data,
                        gas,
                        int(gas_price_qrdx * Decimal(10**18))  # Convert back to wei
                    )
                    
                    logger.info(f"EVM result: success={result.success}, gas_used={result.gas_used}")
                    
                    if not result.success:
                        logger.error(f"EVM execution failed: {result.error}")
                        raise Exception(f"Execution failed: {result.error}")
                    
                    if result.created_address:
                        contract_addr = encode_hex(result.created_address)
                        logger.info(f"✅ Contract deployed at: {contract_addr}")
                        return contract_addr
                    else:
                        output = encode_hex(result.output)
                        logger.info(f"✅ Call output: {output}")
                        return output
                        
                except Exception as e:
                    logger.error(f"eth_sendTransaction error: {e}", exc_info=True)
                    raise Exception(f"Transaction failed: {str(e)}")
            
            async def eth_call_handler(call_params):
                """Read-only contract call."""
                from eth_utils import to_canonical_address, encode_hex, decode_hex
                
                sender_hex = call_params.get('from', '0x' + '0' * 40)
                to_hex = call_params['to']
                data_hex = call_params.get('data', '0x')
                
                sender = to_canonical_address(sender_hex)
                to = to_canonical_address(to_hex)
                data = decode_hex(data_hex)
                
                result = evm_executor.call(
                    sender=sender,
                    to=to,
                    data=data,
                    value=0,
                    gas=10000000
                )
                
                if not result.success:
                    raise Exception(f"Call failed: {result.error}")
                
                return encode_hex(result.output)
            
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
                    from eth_utils import decode_hex, encode_hex
                    from eth_hash.auto import keccak

                    raw_tx = decode_hex(raw_tx_hex)
                    _evm_tx_hash = encode_hex(keccak(raw_tx))
                    # Idempotent: skip txs already admitted (also stops gossip loops).
                    if await EVM_TX_CACHE.contains(_evm_tx_hash):
                        return _evm_tx_hash
                    await EVM_TX_CACHE.put(_evm_tx_hash, True)

                    # Admission control (standard mempool semantics): recover the
                    # sender, enforce the nonce window + DoS caps. A stale-nonce /
                    # unrecoverable / far-future tx is rejected here. The tx then
                    # waits in the mempool to be included by a proposer.
                    mp = _get_evm_mempool()
                    admit_ok, admit_err, _ = mp.admit(raw_tx_hex)
                    if not admit_ok and "duplicate" not in (admit_err or ""):
                        raise Exception(f"rejected: {admit_err}")

                    # Propagate to peers' mempools so the next proposer (which may be
                    # any node) can include it.
                    if not _propagated:
                        asyncio.create_task(_gossip_evm_raw_tx(raw_tx_hex))

                    # Web3 contract: always return the tx hash (the receipt — incl.
                    # any created contract address — is available after inclusion).
                    return _evm_tx_hash
                except Exception as e:
                    logger.error(f"eth_sendRawTransaction error: {e}", exc_info=True)
                    raise Exception(f"Transaction failed: {str(e)}")
            
            rpc_server.register_method('eth_sendTransaction', eth_sendTransaction_handler)
            rpc_server.register_method('eth_call', eth_call_handler)
            rpc_server.register_method('eth_sendRawTransaction', eth_sendRawTransaction_handler)
            
            # Register QRDX-specific module
            qrdx_module = QRDXModule()
            qrdx_module.context = context
            rpc_server.register_module(qrdx_module)
            
            # Register network module
            net_module = NetModule()
            net_module.context = context
            rpc_server.register_module(net_module)
            
            logger.info(f"✅ EVM / chain RPC modules registered: {len(rpc_server.get_methods())} total methods")
            
        except Exception as e:
            logger.error(f"❌ RPC server initialization error: {e}", exc_info=True)
    
    logger.info("Starting background tasks.")
    asyncio.create_task(check_own_reachability())
    asyncio.create_task(periodic_peer_discovery())
    asyncio.create_task(periodic_update_fetcher())

    # Initialize Kademlia DHT subsystem (non-blocking, non-fatal)
    await _init_dht()

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
    if hasattr(app.state, 'validator') and app.state.validator:
        await app.state.validator.stop()
        logger.info("Validator stopped.")
    
    # Close the shared HTTP client
    if http_client:
        await http_client.aclose()
        logger.info("Shared HTTP client closed.")
        
    await security.shutdown()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    import traceback
    traceback.print_exc()
    
    await security.security_monitor.log_event('unhandled_exception', {
        'endpoint': request.url.path,
        'error': str(exc)
    })
    
    return JSONResponse(status_code=500, content={"ok": False, "error": "Internal Server Error"})


# ============================================================================
# MIDDLEWARE
# ============================================================================

async def propagate_old_transactions(propagate_txs):
    await db.update_pending_transactions_propagation_time([sha256(tx_hex) for tx_hex in propagate_txs])
    for tx_hex in propagate_txs:
        await propagate('push_tx', {'tx_hex': tx_hex})


@app.middleware("http")
async def middleware(request: Request, call_next):
    """Simple middleware to handle URL normalization and attach background tasks"""
    path = request.scope['path']
    normalized_path = re.sub('/+', '/', path)
    if normalized_path != path:
        new_url = str(request.url.replace(path=normalized_path))
        return RedirectResponse(url=new_url)

    try:
        propagate_txs = await db.get_need_propagate_transactions()
        response = await call_next(request)
        
        if propagate_txs:
            existing_background = response.background or BackgroundTasks()
            existing_background.add_task(propagate_old_transactions, propagate_txs)
            response.background = existing_background
            
        return response
    except Exception:
        raise


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    return {"node_version": NODE_VERSION, "unspent_outputs_hash": await db.get_unspent_outputs_hash()}


@app.post("/push_tx")
@limiter.limit("100/minute")
async def push_tx(
    request: Request,
    background_tasks: BackgroundTasks,
    body: dict = Body(...),
    verified_sender: str = Depends(get_verified_sender)
):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    tx_hex = body.get('tx_hex')
    if not tx_hex:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "'tx_hex' not found in body.")

    is_valid, error_msg = security.input_validator.validate_transaction_data(tx_hex)
    if not is_valid:
        await security.reputation_manager.record_violation(
            verified_sender, 'invalid_transaction', severity=2, details=error_msg
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, error_msg)

    # Try to deserialize as Contract or Regular transaction
    try:
        tx = await ContractTransaction.from_hex(tx_hex)
    except Exception:
        # Fall back to regular transaction
        tx = await Transaction.from_hex(tx_hex)
    
    
    # Verify the transaction before accepting it into the mempool.
    try:
        if not await tx.verify():
            await security.reputation_manager.record_violation(
                verified_sender, 'invalid_transaction_content', severity=5, details="Transaction failed full verification"
            )
            return {'ok': False, 'error': 'Transaction verification failed'}
    except Exception as e:
        await security.reputation_manager.record_violation(
            verified_sender, 'invalid_transaction_content', severity=5, details=f"Verification error: {e}"
        )
        return {'ok': False, 'error': f'Transaction verification failed: {e}'}
    

    if await security.transaction_cache.contains(tx.hash()):
        return {'ok': False, 'error': 'Transaction just added'}
    
    pending_count = await db.get_pending_transaction_count()
    if pending_count >= MAX_MEMPOOL_SIZE:
        await security.security_monitor.log_event('mempool_full', {
            'peer_id': verified_sender,
            'pending_count': pending_count
        })
        return {'ok': False, 'error': 'Mempool is full'}
    
    try:
        if await security.transaction_pool.add_transaction(tx.hash(), tx, db):
            background_tasks.add_task(
                propagate, 'push_tx', {'tx_hex': tx_hex}, 
                ignore_node_id=verified_sender
            )
            await security.transaction_cache.put(tx.hash(), True)
            return {'ok': True, 'result': 'Transaction has been accepted'}
        else:
            return {'ok': False, 'error': 'Transaction has not been added'}
    except sqlite3.IntegrityError:
        return {'ok': False, 'error': 'Transaction already present'}
    except Exception as e:
        await security.security_monitor.log_event('transaction_error', {
            'peer_id': verified_sender,
            'error': str(e)
        })
        return {'ok': False, 'error': 'Transaction rejected'}


@app.post("/submit_tx")
@limiter.limit("30/minute") 
async def submit_tx(
    request: Request, 
    background_tasks: BackgroundTasks,
    body: dict = Body(...)
):
    tx_hex = body.get('tx_hex')
    if not tx_hex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="'tx_hex' not found in body.")

    is_valid, error_msg = security.input_validator.validate_transaction_data(tx_hex)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    try:
        # Try contract transaction first
        try:
            tx = await ContractTransaction.from_hex(tx_hex)
        except Exception:
            # Fall back to regular transaction
            tx = await Transaction.from_hex(tx_hex)
        
        # Verify the transaction before accepting it.
        if not await tx.verify():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Transaction verification failed.")
        
    except HTTPException:
        raise
    except Exception as e:
        # Catch verification errors or deserialization errors
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid transaction: {e}")

    if await security.transaction_cache.contains(tx.hash()):
        return {'ok': False, 'error': 'Transaction recently seen'}

    pending_count = await db.get_pending_transaction_count()
    if pending_count >= MAX_MEMPOOL_SIZE:
        return {'ok': False, 'error': 'Mempool is full'}

    try:
        if await security.transaction_pool.add_transaction(tx.hash(), tx, db):
            logger.info(f"Accepted transaction {tx.hash()} from external client. Propagating to network...")
            background_tasks.add_task(propagate, 'push_tx', {'tx_hex': tx_hex}, ignore_node_id=None)
            await security.transaction_cache.put(tx.hash(), True)
            return {'ok': True, 'result': 'Transaction has been accepted'}
        else:
            return {'ok': False, 'error': 'Transaction failed validation'}
    except sqlite3.IntegrityError:
        return {'ok': False, 'error': 'Transaction already present in pending pool'}
    except Exception as e:
        return {'ok': False, 'error': 'Transaction rejected'}


@app.post("/submit_exchange_tx")
@limiter.limit("30/minute")
async def submit_exchange_tx(request: Request, body: dict = Body(...)):
    """
    Admit an exchange transaction to the local admission mempool (Phase D1).

    Authentication (PQ signature + sender binding), nonce window, dedup, and
    capacity are enforced by ``ExchangeMempool.admit`` before the transaction is
    queued. This endpoint does NOT yet include the transaction in a block or
    gossip it to peers — block inclusion + deterministic import replay are
    Phase D2/D3 (see docs/EXCHANGE_PRODUCTION_READINESS.md).
    """
    tx_hex = body.get('tx_hex')
    if not tx_hex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="'tx_hex' not found in body.")

    try:
        mempool = _get_exchange_mempool()
        ok, error, tx_hash = mempool.admit_hex(tx_hex)
    except Exception as e:
        logger.error(f"submit_exchange_tx error: {e}")
        return {'ok': False, 'error': 'Exchange transaction rejected'}

    if not ok:
        return {'ok': False, 'error': error}
    return {'ok': True, 'result': {'tx_hash': tx_hash, 'mempool_size': mempool.size()}}


@app.get("/get_exchange_state_root")
async def get_exchange_state_root():
    """
    Return this node's current exchange state root (Whitepaper §3.6 BLAKE3-512).

    Read-only view of the protocol-level exchange state. All honest nodes that
    have imported the same blocks must report an identical root — the cross-node
    consistency guarantee enforced by D3 import replay.
    """
    try:
        from qrdx.exchange import ExchangeStateManager
        mgr = ExchangeStateManager.get_instance()
        return {'ok': True, 'result': {
            'exchange_state_root': mgr.compute_state_root(),
            'pools': mgr.pool_count,
            'pairs': mgr.pair_count,
        }}
    except Exception as e:
        logger.error(f"get_exchange_state_root error: {e}")
        return {'ok': False, 'error': str(e)}


@app.get("/get_unified_state_root")
async def get_unified_state_root():
    """
    Return the unified block state root (Whitepaper §3.6): a BLAKE3-512 commitment
    over all state domains — UTXO set, account/EVM state, exchange state, and the
    QRC-20 token ledger.

    Phase D4 primitive. NOTE: this is computed/observable but not yet *enforced*
    in consensus. Enforcing it requires every committed domain to be
    deterministically re-executed on import; the exchange domain is (D3), but the
    account/EVM domain still applies via gossip rather than consensus replay, so
    its root can differ across nodes until the EVM domain receives the same D1–D3
    treatment. See docs/EXCHANGE_PRODUCTION_READINESS.md.
    """
    try:
        from qrdx.exchange import ExchangeStateManager
        from qrdx.crypto.hashing import unified_state_root
        utxo_root = await db.get_unspent_outputs_hash()
        account_root = await db.get_account_state_root()
        exchange_root = ExchangeStateManager.get_instance().compute_state_root()
        # token_root is reported for visibility but bound at zero in the consensus
        # root until token state is a consensus object (Phase E spot inc4).
        token_root = await db.get_token_balances_root()
        root = unified_state_root(utxo_root, account_root, exchange_root)
        return {'ok': True, 'result': {
            'unified_state_root': root,
            'utxo_root': utxo_root,
            'account_root': account_root,
            'exchange_root': exchange_root,
            'token_root': token_root,
            'token_root_bound': False,
            'enforced': False,
        }}
    except Exception as e:
        logger.error(f"get_unified_state_root error: {e}")
        return {'ok': False, 'error': str(e)}


@app.post("/push_block")
@limiter.limit("12/minute")
async def push_block(
    request: Request,
    background_tasks: BackgroundTasks,
    body: dict = Body(...),
):
    """Unauthenticated endpoint for miners with heavy validation"""
    
    block_content = body.get('block_content')
    if not block_content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing block_content.")

    # Validate block content size
    if len(block_content) > MAX_BLOCK_CONTENT_SIZE:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Block content too large.")

    block_identifier = sha256(block_content.encode())
    
    # Use time-based cache
    if await security.block_cache.contains(block_identifier):
        return {'ok': False, 'error': 'Block recently seen'}
    
    # Check sync state
    if security.sync_state_manager.is_syncing:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={'ok': False, 'error': 'Node is busy synchronizing, please try again later.'}
        )

    # Block processing lock prevents race conditions
    async with block_processing_lock:
        txs_data = body.get('txs', [])
        block_no = body.get('id') or body.get('block_no')

        if not all([txs_data is not None, block_no is not None]):
             raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing block data.")

        # Validate block height
        if not await security.input_validator.validate_block_height(block_no, db, max_ahead=1):
            return {'ok': False, 'error': 'Invalid block height'}

        next_block_id = await db.get_next_block_id()
        
        # Only accept blocks that build directly on our current chain tip
        if next_block_id != block_no:
            return {'ok': False, 'error': f'Invalid block height. Expected {next_block_id}, got {block_no}. This may be a stale block.'}
        
        await security.block_cache.put(block_identifier, True)

        final_transactions = []
        tx_hashes_to_find = []
        if isinstance(txs_data, str):
            txs_data = txs_data.split(',') if txs_data else []
        for tx_hex in txs_data:
            if isinstance(tx_hex, str) and len(tx_hex) == 64:
                tx_hashes_to_find.append(tx_hex)
            else:
                is_valid, error_msg = security.input_validator.validate_transaction_data(tx_hex)
                if not is_valid:
                    raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"Transaction data within block is invalid: {error_msg}")
                final_transactions.append(await Transaction.from_hex(tx_hex))

        if tx_hashes_to_find:
            db_results = await db.get_pending_transactions_by_hash(tx_hashes_to_find)
            if len(db_results) < len(tx_hashes_to_find):
                return {'ok': False, 'error': 'One or more transaction hashes not found in pending pool.'}

            tx_map = {tx.hash(): tx for tx in db_results}
            ordered_txs = [tx_map.get(tx_hash) for tx_hash in tx_hashes_to_find]
            final_transactions.extend(ordered_txs)
        
        if not await create_block(block_content, final_transactions):
            return {'ok': False, 'error': 'Block failed validation.'}

        miner_ip = request.client.host
        logger.info(f"Accepted block {block_no} from miner at {miner_ip}. Propagating to network...")
        
        # Propagate to all peers
        background_tasks.add_task(propagate, 'submit_block', body, ignore_node_id=None, db=db) 
        return {'ok': True, 'result': f'Block {block_no} accepted.'}


@app.post("/submit_block")
@limiter.limit("2/second")
async def submit_block(
    request: Request,
    background_tasks: BackgroundTasks,
    body: dict = Body(...),
    verified_sender: str = Depends(get_verified_sender)
):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    block_content = body.get('block_content')
    if not block_content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing block_content.")

    # Validate block content size
    if len(block_content) > MAX_BLOCK_CONTENT_SIZE:
        await security.reputation_manager.record_violation(
            verified_sender, 'oversized_block', severity=3
        )
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Block content too large.")

    block_identifier = sha256(block_content.encode())
    
    # Use time-based cache
    if await security.block_cache.contains(block_identifier):
        return {'ok': False, 'error': 'Block recently seen'}
    
    # Check sync state
    if security.sync_state_manager.is_syncing:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={'ok': False, 'error': 'Node is busy synchronizing, please try again later.'}
        )

    async with block_processing_lock:
        block_no = body.get('id') or body.get('block_no')
        if block_no is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing block ID.")
        
        # Validate block height
        if not await security.input_validator.validate_block_height(block_no, db):
            await security.reputation_manager.record_violation(
                verified_sender, 'invalid_block_height', severity=4
            )
            return {'ok': False, 'error': 'Invalid block height'}
        
        next_block_id = await db.get_next_block_id()
        if next_block_id > block_no:
            return {'ok': False, 'error': 'Too old block'}
        
        if next_block_id < block_no:
            # Check if peer is already syncing
            if await security.peer_sync_tracker.is_syncing(verified_sender):
                return {'ok': False, 'error': 'Already syncing to this peer'}
                
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    'ok': False, 
                    'error': 'sync_required',
                    'result': {
                        'next_block_expected': next_block_id
                    }
                }
            )
        
        await security.block_cache.put(block_identifier, True)
        
        # --- PoS fast-path: if the body includes a validator_address & block_hash,
        # this is a PoS block produced by a validator.  Store it directly. ---
        block_hash = body.get('block_hash')
        validator_address = body.get('validator_address')
        if block_hash and validator_address:
            # Security: validate block_hash is well-formed hex
            if not security.input_validator.validate_hex(block_hash, min_length=16, max_length=128):
                await security.reputation_manager.record_violation(
                    verified_sender, 'malformed_block_hash', severity=5
                )
                return {'ok': False, 'error': 'Invalid block hash format'}

            # Security: block_no must be exactly the next expected height
            if block_no != next_block_id:
                return {'ok': False, 'error': 'Block height does not match expected next block'}

            # Security: verify the claimed validator is registered
            validator_info = await db.get_validator_info(validator_address)
            if not validator_info:
                await security.reputation_manager.record_violation(
                    verified_sender, 'unknown_validator', severity=6
                )
                return {'ok': False, 'error': 'Validator address not registered'}

            # Security: authenticate the proposer (pubkey↔address binding +
            # Dilithium signature over the signed header). Registration alone does
            # not prove the block was produced by that validator.
            ok_prop, prop_err = verify_pos_block_proposer(block_content, validator_address)
            if not ok_prop:
                await security.reputation_manager.record_violation(
                    verified_sender, 'invalid_proposer_signature', severity=8
                )
                return {'ok': False, 'error': f'Proposer authentication failed: {prop_err}'}

            # Security: proposer must be eligible for the block's slot. Observe-first.
            ok_elig, elig_err = await verify_proposer_eligibility(
                db, block_content, enforce=_ENFORCE_PROPOSER_ELIGIBILITY,
            )
            if not ok_elig:
                await security.reputation_manager.record_violation(
                    verified_sender, 'ineligible_proposer', severity=8
                )
                return {'ok': False, 'error': f'Proposer ineligible: {elig_err}'}

            # D3: if the block carries an exchange section, securely validate +
            # replay it (verify signatures, re-execute, match declared root)
            # BEFORE storing. Reject the block on any mismatch — local exchange
            # state is left untouched by a rejected block.
            ex_section = body.get('exchange_transactions')
            if ex_section:
                try:
                    # Phase E: route through the importer hook so the collateral
                    # flush (margin debit → account_state) runs on this REST
                    # live-broadcast path too, deterministically with proposer/sync.
                    ok, verr = await _apply_exchange_section_on_import(
                        block_no, float(body.get('timestamp', 0) or 0),
                        ex_section, body.get('exchange_state_root'),
                    )
                except Exception as e:
                    ok, verr = False, f"exchange validation error: {e}"
                if not ok:
                    await security.reputation_manager.record_violation(
                        verified_sender, 'invalid_exchange_section', severity=6
                    )
                    return {'ok': False, 'error': f'Invalid exchange section: {verr}'}

            # E-D3b: validate + replay the EVM section (execute-on-mine) before
            # storing; reject on account_state_root mismatch.
            evm_section = body.get('evm_transactions')
            if evm_section:
                ok_evm, verr_evm = await _apply_evm_section_on_import(
                    block_no, block_hash, int(body.get('timestamp', 0) or 0),
                    evm_section, body.get('account_state_root'),
                )
                if not ok_evm:
                    await security.reputation_manager.record_violation(
                        verified_sender, 'invalid_evm_section', severity=6
                    )
                    return {'ok': False, 'error': f'Invalid EVM section: {verr_evm}'}

            # E-D4: verify the recomputed unified state root against the signed root.
            ok_root, root_err = await _verify_unified_state_root(block_content)
            if not ok_root:
                await security.reputation_manager.record_violation(
                    verified_sender, 'invalid_state_root', severity=8
                )
                return {'ok': False, 'error': f'Invalid state root: {root_err}'}

            try:
                await db.add_block(
                    block_hash=block_hash,
                    block_height=block_no,
                    block_content=block_content or '',
                    validator_address=validator_address,
                    timestamp=body.get('timestamp', 0),
                )
                # D2.2b: persist the (now-validated) exchange section for durability.
                if ex_section:
                    try:
                        await db.add_block_exchange_txs(block_hash, ex_section)
                    except Exception as e:
                        logger.warning(f"Failed to store exchange section for block {block_no}: {e}")
                # E-D3b: persist the (now-validated) EVM section for durability/rebuild.
                if evm_section:
                    try:
                        await db.add_block_evm_txs(block_hash, evm_section)
                    except Exception as e:
                        logger.warning(f"Failed to store EVM section for block {block_no}: {e}")
                # Finality (observe): record attestation votes + recompute.
                try:
                    from ..validator.finality import record_finality_from_block
                    await record_finality_from_block(db, block_content)
                except Exception as e:
                    logger.debug(f"finality record skipped for block {block_no}: {e}")
                await security.reputation_manager.record_good_behavior(verified_sender, points=5)
                logger.info(f"Accepted PoS block {block_no} from {verified_sender}. Propagating...")
                background_tasks.add_task(
                    propagate, 'submit_block', body,
                    ignore_node_id=verified_sender, db=db
                )
                # Immediate follow-up: check if we're still behind and need more blocks
                background_tasks.add_task(_follow_up_sync, verified_sender)
                return {'ok': True, 'result': f'Block {block_no} accepted.'}
            except Exception as e:
                logger.error(f"Failed to store PoS block {block_no}: {e}")
                return {'ok': False, 'error': 'Failed to store block'}

        # --- Legacy PoW path ---
        # Process transactions with validation
        txs_data = body.get('txs', [])
        final_transactions = []
        tx_hashes_to_find = []
        
        if isinstance(txs_data, str):
            txs_data = txs_data.split(',') if txs_data else []
            
        for tx_hex in txs_data:
            if isinstance(tx_hex, str) and len(tx_hex) == 64 and VALID_HEX_PATTERN.match(tx_hex):
                tx_hashes_to_find.append(tx_hex)
            else:
                is_valid, error_msg = security.input_validator.validate_transaction_data(tx_hex)
                if not is_valid:
                    await security.reputation_manager.record_violation(
                        verified_sender, 'invalid_block_transaction', severity=5
                    )
                    return {'ok': False, 'error': f'Invalid transaction in block: {error_msg}'}
                    
                final_transactions.append(await Transaction.from_hex(tx_hex))
                
        if tx_hashes_to_find:
            db_results = await db.get_pending_transactions_by_hash(tx_hashes_to_find)
            if len(db_results) < len(tx_hashes_to_find):
                return {'ok': False, 'error': 'Transaction hash not found.'}
                
            tx_map = {tx.hash(): tx for tx in db_results}
            ordered_txs = [tx_map.get(tx_hash) for tx_hash in tx_hashes_to_find]
            final_transactions.extend(ordered_txs)
        
        if not await create_block(block_content, final_transactions):
            await security.reputation_manager.record_violation(
                verified_sender, 'invalid_block', severity=7
            )
            return {'ok': False, 'error': 'Block failed validation.'}

        # Record successful block
        await security.reputation_manager.record_good_behavior(verified_sender, points=5)
        
        logger.info(f"Accepted block {block_no} from {verified_sender}. Propagating to network...")
        background_tasks.add_task(
            propagate, 'submit_block', body, 
            ignore_node_id=verified_sender, db=db
        )
        # Immediate follow-up: check if we're still behind and need more blocks
        background_tasks.add_task(_follow_up_sync, verified_sender)
        return {'ok': True, 'result': f'Block {block_no} accepted.'}
        

@app.post("/submit_blocks")
@limiter.limit("30/minute")
async def submit_blocks(
    request: Request,
    body: list = Body(...),
    verified_sender: str = Depends(get_verified_sender)
):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    if not isinstance(body, list) or not body:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Request body must be a non-empty list.")

    if len(body) > MAX_BLOCKS_PER_SUBMISSION:
        await security.reputation_manager.record_violation(
            verified_sender, 'too_many_blocks', severity=3
        )
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request limit exceeded. You can only submit up to {MAX_BLOCKS_PER_SUBMISSION} blocks at a time."
        )
    
    try:
        async with security.sync_state_manager.acquire_sync():
            async with block_processing_lock:
                blocks_to_process = sorted(body, key=lambda x: x['id'])
                
                # Verify continuity
                for i in range(1, len(blocks_to_process)):
                    if blocks_to_process[i]['id'] != blocks_to_process[i-1]['id'] + 1:
                        await security.reputation_manager.record_violation(
                            verified_sender, 'non_continuous_blocks', severity=4
                        )
                        return {'ok': False, 'error': 'Block sequence must be continuous'}
                
                next_block_id = await db.get_next_block_id()
                if blocks_to_process[0]['id'] != next_block_id:
                    return {'ok': False, 'error': f'Block sequence out of order. Expected {next_block_id}, got {blocks_to_process[0]["id"]}.'}

                for block_payload in blocks_to_process:
                    block_no = block_payload.get('id')
                    
                    current_expected_id = await db.get_next_block_id()
                    if current_expected_id != block_no:
                        return {'ok': False, 'error': f'Block sequence desynchronized during batch. Expected {current_expected_id}, got {block_no}.'}
                    
                    block_content = block_payload.get('block_content')
                    txs_data = block_payload.get('txs', [])

                    if not block_content:
                        return {'ok': False, 'error': f'Invalid block data for block {block_no}: missing content.'}

                    # Validate block content size
                    if len(block_content) > MAX_BLOCK_CONTENT_SIZE:
                        await security.reputation_manager.record_violation(
                            verified_sender, 'oversized_bulk_block', severity=3
                        )
                        return {'ok': False, 'error': f'Block {block_no} content too large.'}

                    block_identifier = sha256(block_content.encode())
                    if await security.block_cache.contains(block_identifier):
                        continue
                    
                    final_transactions = []
                    for tx_hex in txs_data:
                        is_valid, error_msg = security.input_validator.validate_transaction_data(tx_hex)
                        if not is_valid:
                            await security.reputation_manager.record_violation(
                                verified_sender, 'invalid_bulk_transaction', severity=5
                            )
                            return {'ok': False, 'error': f'Block {block_no} contains an invalid transaction: {error_msg}'}
                        final_transactions.append(await Transaction.from_hex(tx_hex))
                    
                    if not await create_block(block_content, final_transactions):
                        await security.reputation_manager.record_violation(
                            verified_sender, 'invalid_bulk_block', severity=7
                        )
                        return {'ok': False, 'error': f'Block {block_no} failed validation. Halting.'}
                    
                    await security.block_cache.put(block_identifier, True)
                    logger.info(f"Accepted block {block_no} from {verified_sender} via bulk sync.")

                # Reward successful bulk submission
                await security.reputation_manager.record_good_behavior(
                    verified_sender, points=len(blocks_to_process) * 2
                )

                return {'ok': True, 'result': f'Successfully processed {len(blocks_to_process)} blocks.'}
        
    except HTTPException:
        raise
    except Exception as e:
        await security.security_monitor.log_event('bulk_sync_error', {
            'peer_id': verified_sender,
            'error': str(e)
        })
        raise


@app.post("/get_peers")
async def get_peers(verified_sender: str = Depends(get_verified_sender)):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")
    
    peers_list = [
        {'node_id': peer_id, **peer_data} 
        for peer_id, peer_data in NodesManager.peers.items()
        # Only share peers that haven't been banned
        if not await security.reputation_manager.is_banned(peer_id)
    ]
    return {"ok": True, "result": {"peers": peers_list}}


@app.get("/handshake/challenge")
@limiter.limit("30/minute")
async def handshake_challenge(request: Request):
    """
    Provides a challenge and also advertises this node's current chain state.
    """
    challenge = await security.handshake_manager.create_challenge()
    
    # Get our current chain state to send to the peer.
    height = await db.get_next_block_id() - 1
    last_block = await db.get_block_by_id(height) if height > -1 else None
    
    # Handle different database implementations (PostgreSQL uses 'hash', SQLite uses 'block_hash')
    last_hash = None
    if last_block:
        last_hash = last_block.get('hash') or last_block.get('block_hash')
    
    return {
        "ok": True, 
        "result": {
            "challenge": challenge,
            "node_id": get_node_id(),
            "pubkey": get_public_key_hex(),
            "is_public": NodesManager.self_is_public,
            "url": DENARO_SELF_URL,
            "height": height,
            "last_hash": last_hash
        }
    }


@app.post("/handshake/response")
@limiter.limit("30/minute")
async def handshake_response(
    request: Request,
    body: dict = Body(...),
    verified_sender: str = Depends(get_verified_sender)
):
    """
    Verifies a handshake response and uses the peer's advertised chain state to
    negotiate a sync. This is the server-side of the handshake negotiation.
    """
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    # --- Read data from request ---
    challenge = body.get('challenge')
    try:
        peer_height = int(request.headers.get('x-denaro-height', -1))
    except (ValueError, TypeError):
        peer_height = -1
    peer_hash = request.headers.get('x-denaro-last_hash')

    if not challenge:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing challenge.")

    # --- Verify challenge ---
    if not await security.handshake_manager.verify_and_consume_challenge(challenge):
        await security.reputation_manager.record_violation(verified_sender, 'invalid_handshake', severity=6)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid or expired challenge.")
    
    logger.info(f"Received handshake from {verified_sender} (Height: {peer_height})")

    # --- Compare Chain States and Determine Action ---
    local_height = await db.get_next_block_id() - 1
    
    if peer_height > local_height:
        # CASE 1: We are behind.
        # We must ask the connecting peer (who has the longer chain) to PUSH blocks to us.
        # This is critical for NAT traversal (e.g., an empty public node learning from a private node).
        logger.info(f"Our chain is behind. Requesting peer {verified_sender} to PUSH-sync to us.")
        return JSONResponse(
            status_code=200, # A successful response that contains instructions
            content={
                'ok': True,
                'result': 'sync_requested', # Special status telling the client to initiate a push
                'detail': {
                    'start_block': local_height + 1,
                    'target_block': peer_height + 1
                }
            }
        )
        
    elif local_height > peer_height:
        # CASE 2: The connecting peer is behind.
        # We tell them they need to sync, and it's their responsibility to act.
        # We respond with a 409 Conflict to signal a state mismatch they need to resolve.
        logger.info(f"Our chain is longer. Informing peer {verified_sender} a sync is required.")
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                'ok': False, 
                'error': 'sync_required',
                'result': {'next_block_expected': peer_height + 1}
            }
        )
    
    # CASE 3: Heights are equal. We assume they are in sync.
    # (A more advanced implementation could compare hashes here to detect forks).
    logger.info(f"Handshake complete for peer {verified_sender}. Chains appear to be in sync.")
    return {"ok": True, "result": "Handshake successful."}


@app.get("/sync_blockchain")
@limiter.limit("10/minute")
async def sync(request: Request, node_id: str = None): 
    """Initiates a blockchain synchronization process"""
    if security.sync_state_manager.is_syncing:
        return {'ok': False, 'error': 'Node is already syncing'}
    
    background_tasks = BackgroundTasks()
    background_tasks.add_task(_sync_blockchain, node_id=node_id)
    
    return JSONResponse(
        content={'ok': True, 'result': 'Synchronization process has been initiated.'},
        background=background_tasks
    )


@app.get("/get_mining_info")
@limiter.limit("15/minute")
async def get_mining_info(
    request: Request,
    background_tasks: BackgroundTasks,
    pretty: bool = False,
    debug: bool = False,
):
    """
    Build a block template from the full mempool:
      - Load ALL pending transaction hashes from the DB (no hidden filters).
      - Deserialize those transactions.
      - Topologically select valid, non-conflicting txs (parents first), so
        multiple independent txs and parent+child chains can be included in
        the same block.
      - Return selected tx hexes and hashes, merkle root, and optional debug.
    """

    # Recompute difficulty/tip
    Manager.difficulty = None
    difficulty, last_block = await get_difficulty()
    
    next_block_height = (last_block['id'] + 1) if last_block else 0

    # Guard mempool size (same as before)
    pending_count = await db.get_pending_transaction_count()
    if pending_count > MAX_MEMPOOL_SIZE:
        logger.warning(f"Mempool size ({pending_count}) exceeds limit of ({MAX_MEMPOOL_SIZE}). Triggering cleanup.")
        await clear_pending_transactions([])

    # === Load ALL mempool transactions by hash, then hydrate ===
    # This avoids whatever filtering/ordering get_pending_transactions_limit() was doing.
    try:
        all_hashes = await db.get_all_pending_transaction_hashes()  # returns List[str]
    except Exception as e:
        logger.error(f"Error fetching mempool hashes: {e}")
        all_hashes = []

    # Optionally cap to something huge to avoid pathological mempools
    if len(all_hashes) > MAX_MINING_CANDIDATES:
        all_hashes = all_hashes[:MAX_MINING_CANDIDATES]

    # Preserve DB-provided order (whatever it is), and create a stable index
    order_index = {h: i for i, h in enumerate(all_hashes)}

    # Fetch full tx objects for these hashes
    # This DB API exists in your code (used in /submit_block, etc.)
    pending_tx_objects = await db.get_pending_transactions_by_hash(all_hashes)

    # Build a hash -> Transaction map and drop unknowns (shouldn't happen, but be safe)
    tx_by_hash = {}
    for tx in pending_tx_objects:
        try:
            tx_by_hash[tx.hash()] = tx
        except Exception:
            # If a deserialization glitch happens, skip the tx
            continue

    # Only keep hashes we could hydrate
    candidate_hashes = [h for h in all_hashes if h in tx_by_hash]
    logger.debug(f"Building block template from full mempool. Candidates: {len(candidate_hashes)}")

    # Fast-path: nothing pending
    if not candidate_hashes:
        merkle_root = get_transactions_merkle_tree([], next_block_height)
        result = {
            'ok': True,
            'result': {
                'difficulty': difficulty,
                'last_block': last_block,
                'pending_transactions': [],
                'pending_transactions_hashes': [],
                'merkle_root': merkle_root,
            }
        }
        return Response(content=json.dumps(result, indent=4, cls=CustomJSONEncoder), media_type="application/json") if pretty else result

    # Debug info per tx
    debug_rows = {}  # h -> dict

    # Memoize chain prev-tx lookups
    chain_tx_cache = {}

    async def chain_tx(prev_hash: str):
        if prev_hash in chain_tx_cache:
            return chain_tx_cache[prev_hash]
        data = await db.get_nice_transaction(prev_hash)
        chain_tx_cache[prev_hash] = data
        return data

    # Dependency graph
    deps = {h: set() for h in candidate_hashes}   # child -> set(parent hashes in mempool)
    children = defaultdict(set)                   # parent -> set(children)
    prevouts = {}                                 # h -> set("txhash:index")
    invalid = set()                               # bad references / failed verify

    # First pass: validate inputs, build deps, record prevouts
    for h in candidate_hashes:
        tx = tx_by_hash[h]
        info = {
            'hash': h,
            'selected': False,
            'reason': None,
            'deps': [],
            'prevouts': [],
            'indegree_initial': None,
            'indegree_final': None,
            'parents_not_selected': [],
        }

        # Record prevouts for in-block double-spend checks
        my_prevouts = set(f"{inp.tx_hash}:{inp.index}" for inp in tx.inputs)
        prevouts[h] = my_prevouts
        info['prevouts'] = list(my_prevouts)

        try:
            ok = True
            for inp in tx.inputs:
                p = inp.tx_hash

                # If the parent is also pending, register dependency
                if p in tx_by_hash:
                    deps[h].add(p)
                    continue

                # Otherwise the parent must exist on-chain and index be valid
                src = await chain_tx(p)
                if src is None:
                    logger.debug(f"Tx {h[:10]} references unknown prev tx {p[:10]}")
                    info['reason'] = f"invalid_input_unknown_parent:{p}"
                    ok = False
                    break

                if 'outputs' in src and inp.index >= len(src['outputs']):
                    logger.debug(f"Tx {h[:10]} references out-of-range output {inp.index} in {p[:10]}")
                    info['reason'] = f"invalid_input_out_of_range:{p}:{inp.index}"
                    ok = False
                    break

            if not ok:
                invalid.add(h)
                debug_rows[h] = info
                continue

            # Full signature/script verification
            if not await tx.verify():
                logger.debug(f"Tx {h[:10]} failed verification")
                info['reason'] = "verify_failed"
                invalid.add(h)
                debug_rows[h] = info
                continue

        except Exception as e:
            logger.debug(f"Tx {h[:10]} verification error: {e}")
            info['reason'] = f"verify_exception:{e}"
            invalid.add(h)
            debug_rows[h] = info
            continue

        info['deps'] = list(deps[h])
        debug_rows[h] = info

    # Build children edges (ignore invalid parents)
    for child_h, parents in deps.items():
        if child_h in invalid:
            continue
        for parent_h in parents:
            if parent_h not in invalid:
                children[parent_h].add(child_h)

    # Compute indegrees
    indegree = {}
    for h in candidate_hashes:
        if h in invalid:
            continue
        indegree[h] = sum(1 for p in deps[h] if p not in invalid)
        debug_rows[h]['indegree_initial'] = indegree[h]

    # Queue of zero-dep txs in stable order (DB order)
    zero_dep = [h for h, d in indegree.items() if d == 0]
    zero_dep.sort(key=lambda k: order_index.get(k, 1_000_000))
    queue = deque(zero_dep)

    # Selection loop
    selected = []
    selected_hashes = set()
    spent_prevouts = set()
    total_size = 0
    size_hard_stop = False

    while queue:
        h = queue.popleft()
        if h in selected_hashes or h in invalid:
            continue

        tx = tx_by_hash[h]
        tx_hex = tx.hex()

        # Ensure we don't exceed size target
        if total_size + len(tx_hex) > MAX_TX_DATA_SIZE:
            logger.debug("Reached MAX_TX_DATA_SIZE while assembling block template.")
            size_hard_stop = True
            break

        # In-block double-spend check
        if not prevouts[h].isdisjoint(spent_prevouts):
            if debug:
                debug_rows[h]['reason'] = "double_spend_conflict_in_block"
            continue

        # Accept tx
        selected.append(tx)
        selected_hashes.add(h)
        spent_prevouts.update(prevouts[h])
        total_size += len(tx_hex)
        debug_rows[h]['selected'] = True

        # Relax children indegrees
        for c in children.get(h, ()):
            if c in indegree:
                indegree[c] -= 1
                if indegree[c] == 0:
                    queue.append(c)

    # Annotate non-selected reasons
    for h, d in indegree.items():
        debug_rows[h]['indegree_final'] = d
        if not debug_rows[h]['selected'] and h not in invalid and debug_rows[h]['reason'] is None:
            if d > 0:
                blocked_by = [p for p in deps[h] if p not in invalid and p not in selected_hashes]
                debug_rows[h]['reason'] = "blocked_by_unselected_parents"
                debug_rows[h]['parents_not_selected'] = blocked_by
            else:
                if size_hard_stop:
                    debug_rows[h]['reason'] = "size_limit_reached"
                else:
                    debug_rows[h]['reason'] = "skipped_for_conflict_or_unknown"

    # Purge invalids
    if invalid:
        logger.info(f"Removing {len(invalid)} invalid tx(s) from mempool")
        for h in invalid:
            try:
                await db.remove_pending_transaction(h)
                await security.transaction_pool.remove_transactions([h])
            except Exception as e:
                logger.error(f"Error removing invalid tx {h[:10]}: {e}")

    # Compose response
    selected_hex = [tx.hex() for tx in selected]
    selected_hashes_list = [tx.hash() for tx in selected]
    merkle_root = get_transactions_merkle_tree(selected_hashes_list, next_block_height)
    
    # Periodic cleanup (unchanged)
    if LAST_PENDING_TRANSACTIONS_CLEAN[0] < timestamp() - 600:
        logger.debug("Clearing old pending transactions")
        LAST_PENDING_TRANSACTIONS_CLEAN[0] = timestamp()
        # Feed the cleaner the full set we loaded (not just selected)
        try:
            # If you want to pass hex, hydrate:
            all_loaded_hex = [tx_by_hash[h].hex() for h in candidate_hashes]
            background_tasks.add_task(clear_pending_transactions, all_loaded_hex)
        except Exception:
            pass

    payload = {
        'ok': True,
        'result': {
            'difficulty': difficulty,
            'last_block': last_block,
            'pending_transactions': selected_hex,
            'pending_transactions_hashes': selected_hashes_list,
            'merkle_root': merkle_root,
        }
    }

    if debug:
        dbg = []
        for h, row in debug_rows.items():
            dbg.append({
                'hash': h,
                'selected': row['selected'],
                'reason': row['reason'],
                'deps': row['deps'],
                'prevouts': row['prevouts'],
                'indegree_initial': row['indegree_initial'],
                'indegree_final': row['indegree_final'],
                'parents_not_selected': row['parents_not_selected'],
            })
        payload['debug'] = dbg

    return Response(content=json.dumps(payload, indent=4, cls=CustomJSONEncoder), media_type="application/json") if pretty else payload



@app.get("/get_address_info")
@limiter.limit("8/second")
async def get_address_info(
    request: Request, 
    address: str, 
    transactions_count_limit: int = Query(default=5, le=50), 
    page: int = Query(default=1, ge=1), 
    show_pending: bool = False, 
    verify: bool = False, 
    pretty: bool = False
):
    # Validate address format
    if not security.input_validator.validate_address(address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid address format")
    
    # Check query cost
    offset = (page - 1) * transactions_count_limit
    await security.query_calculator.check_and_update_cost(
        address, offset, transactions_count_limit
    )
    
    outputs = await db.get_spendable_outputs(address)
    # Headline balance comes from the canonical reader (account_state first, UTXO
    # fallback) — in the unified ledger genesis + exchange-settled funds live in
    # account_state, so summing only the UTXO outputs would under-report (return 0
    # for an account_state-funded address). ``spendable_outputs`` below still
    # lists the UTXO entries available for legacy-style spends.
    balance = await db.get_address_balance(address)

    transactions = await db.get_address_transactions(
        address, limit=transactions_count_limit, 
        offset=offset, check_signatures=True
    ) if transactions_count_limit > 0 else []

    result = {'ok': True, 'result': {
        'balance': "{:f}".format(balance),
        'spendable_outputs': [
            {'amount': "{:f}".format(output.amount), 
             'tx_hash': output.tx_hash, 
             'index': output.index} 
            for output in outputs
        ],
        'transactions': [
            await db.get_nice_transaction(tx.hash(), address if verify else None) 
            for tx in transactions
        ],
        'pending_transactions': [
            await db.get_nice_transaction(tx.hash(), address if verify else None) 
            for tx in await db.get_address_pending_transactions(address, True)
        ] if show_pending else None,
        'pending_spent_outputs': await db.get_address_pending_spent_outputs(address) if show_pending else None
    }}
    
    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder), 
            media_type="application/json"
        )
    return result


@app.get("/get_nodes")
async def get_nodes(pretty: bool = False):
    # Return all active, non-banned peers (both public and private)
    # Redact private peer URLs unless QRDX_SELF_URL is also private
    all_peers = []
    for p in NodesManager.get_recent_nodes()[:100]:
        if await security.reputation_manager.is_banned(p['node_id']):
            continue
        all_peers.append({
            'node_id': p['node_id'],
            'is_public': p.get('is_public', False),
            'url': p.get('url', ''),
            'reputation_score': await security.reputation_manager.get_score(p['node_id'])
        })
    result = {'ok': True, 'result': all_peers}
    return Response(content=json.dumps(result, indent=4, cls=CustomJSONEncoder), media_type="application/json") if pretty else result


@app.get("/get_pending_transactions")
async def get_pending_transactions(pretty: bool = False):
    result = {'ok': True, 'result': [tx.hex() for tx in await db.get_pending_transactions_limit(1024)]}
    return Response(content=json.dumps(result, indent=4, cls=CustomJSONEncoder), media_type="application/json") if pretty else result


@app.get("/get_validators")
async def get_validators(status: str = None, pretty: bool = False):
    """
    Return the PoS validator set from the validators table.

    Validators are populated at genesis and updated through the staking
    lifecycle. The ``validators`` key is included alongside the standard
    ``{ok, result}`` envelope for client compatibility.
    """
    try:
        validators = await db.get_validators(status=status)
    except Exception as e:
        logger.error(f"get_validators error: {e}")
        validators = []
    result = {'ok': True, 'result': validators, 'validators': validators}
    return Response(content=json.dumps(result, indent=4, cls=CustomJSONEncoder), media_type="application/json") if pretty else result


@app.get("/get_address_tokens")
@limiter.limit("8/second")
async def get_address_tokens(
    request: Request,
    address: str,
    token_type: str = Query(default=None),
    pretty: bool = False
):
    """
    Get all QRC-20, QRC-721, and QRC-1155 tokens owned by an address
    """
    # Validate address format
    if not security.input_validator.validate_address(address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid address format")
    
    # Normalize address to checksummed format
    try:
        from eth_utils import to_checksum_address
        normalized_address = to_checksum_address(address) if address.startswith('0x') and len(address) == 42 else address
    except (ImportError, ValueError):
        normalized_address = address
    
    # ERC20 Transfer event signature: Transfer(address,address,uint256)
    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    
    try:
        if hasattr(db, 'pool'):
            # PostgreSQL implementation
            async with db.pool.acquire() as conn:
                # Format address as 32-byte hex for topic matching
                address_topic = "0x" + normalized_address.lower().replace("0x", "").zfill(64)
                
                # Get all tokens received by this address
                tokens = await conn.fetch("""
                    SELECT DISTINCT 
                        cl.contract_address,
                        cm.name,
                        cm.symbol,
                        COALESCE(cm.verified, false) as verified
                    FROM contract_logs cl
                    LEFT JOIN contract_metadata cm ON cl.contract_address = cm.contract_address
                    WHERE cl.topic0 = $1
                      AND cl.topic2 = $2
                      AND cl.removed = false
                """, transfer_topic, address_topic)
                
                result_tokens = []
                for token in tokens:
                    # Get transfer count for this token
                    balance_info = await conn.fetchrow("""
                        SELECT COUNT(*) as received
                        FROM contract_logs
                        WHERE contract_address = $1
                          AND topic0 = $2
                          AND topic2 = $3
                          AND removed = false
                    """, token['contract_address'], transfer_topic, address_topic)
                    
                    if balance_info and balance_info['received'] > 0:
                        result_tokens.append({
                            'contract_address': token['contract_address'],
                            'name': token['name'],
                            'symbol': token['symbol'],
                            'verified': token['verified'],
                            'type': 'QRC-20',
                            'transfer_count': int(balance_info['received'])
                        })
        else:
            # SQLite implementation
            tokens = await db.get_address_tokens(normalized_address, transfer_topic)
            result_tokens = [
                {
                    'contract_address': token['contract_address'],
                    'name': token['name'],
                    'symbol': token['symbol'],
                    'verified': bool(token['verified']),
                    'type': 'QRC-20',
                    'transfer_count': token['transfer_count']
                }
                for token in tokens
            ]
        
        result = {
            'ok': True,
            'result': {
                'address': normalized_address,
                'tokens': result_tokens,
                'total_tokens': len(result_tokens)
            }
        }
    
    except Exception as e:
        logger.error(f"Error fetching address tokens: {e}")
        result = {
            'ok': False,
            'error': 'Error fetching token information'
        }
    
    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json"
        )
    return result


@app.get("/get_token_info")
@limiter.limit("8/second")
async def get_token_info(
    request: Request,
    token_address: str,
    pretty: bool = False
):
    """
    Get detailed information about a specific token contract
    """
    # Validate address format
    if not security.input_validator.validate_address(token_address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid token address format")
    
    try:
        from eth_utils import to_checksum_address
        normalized_address = to_checksum_address(token_address) if token_address.startswith('0x') and len(token_address) == 42 else token_address
    except (ImportError, ValueError):
        normalized_address = token_address
    
    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    
    try:
        if hasattr(db, 'pool'):
            # PostgreSQL implementation
            async with db.pool.acquire() as conn:
                # Get contract metadata
                metadata = await conn.fetchrow("""
                    SELECT 
                        cm.*,
                        ac.balance,
                        ac.created_at,
                        cc.bytecode,
                        cc.deployed_at,
                        cc.deployer
                    FROM contract_metadata cm
                    LEFT JOIN account_state ac ON cm.contract_address = ac.address
                    LEFT JOIN contract_code cc ON ac.code_hash = cc.code_hash
                    WHERE cm.contract_address = $1
                """, normalized_address)
                
                if not metadata:
                    result = {'ok': False, 'error': 'Token contract not found'}
                else:
                    # Get transfer count
                    transfer_count = await conn.fetchval("""
                        SELECT COUNT(*) FROM contract_logs
                        WHERE contract_address = $1 AND topic0 = $2 AND removed = false
                    """, normalized_address, transfer_topic)
                    
                    # Get holder count
                    holder_count = await conn.fetchval("""
                        SELECT COUNT(DISTINCT topic2) FROM contract_logs
                        WHERE contract_address = $1 AND topic0 = $2 AND removed = false
                    """, normalized_address, transfer_topic)
                    
                    result = {
                        'ok': True,
                        'result': {
                            'contract_address': normalized_address,
                            'name': metadata['name'],
                            'symbol': metadata['symbol'],
                            'verified': metadata['verified'],
                            'compiler_version': metadata['compiler_version'],
                            'deployer': metadata.get('deployer'),
                            'deployed_at': metadata.get('deployed_at'),
                            'total_transfers': transfer_count,
                            'total_holders': holder_count,
                            'abi': metadata['abi'] if metadata['verified'] else None
                        }
                    }
        else:
            # SQLite implementation
            token_info = await db.get_token_info(normalized_address, transfer_topic)
            
            if not token_info:
                result = {'ok': False, 'error': 'Token contract not found'}
            else:
                result = {
                    'ok': True,
                    'result': {
                        'contract_address': normalized_address,
                        'name': token_info.get('name'),
                        'symbol': token_info.get('symbol'),
                        'verified': bool(token_info.get('verified', False)),
                        'total_transfers': token_info.get('total_transfers', 0),
                        'total_holders': token_info.get('total_holders', 0),
                        'abi': token_info.get('abi') if token_info.get('verified') else None
                    }
                }
    
    except Exception as e:
        logger.error(f"Error fetching token info: {e}")
        result = {'ok': False, 'error': 'Error fetching token information'}
    
    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json"
        )
    return result


@app.get("/get_top_addresses")
@limiter.limit("5/minute")
async def get_top_addresses(
    request: Request,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    order_by: str = Query(default="balance"),  # balance, transactions, tokens
    pretty: bool = False
):
    """
    Get top addresses by balance or activity
    """
    # Validate order_by parameter
    valid_orders = ["balance", "transactions", "tokens"]
    if order_by not in valid_orders:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid order_by. Must be one of: {valid_orders}")
    
    try:
        if hasattr(db, 'pool'):
            # PostgreSQL implementation
            async with db.pool.acquire() as conn:
                if order_by == "balance":
                    # Get top addresses by balance (sum of unspent outputs)
                    query = """
                        SELECT 
                            address,
                            SUM(amount) as balance,
                            COUNT(*) as output_count
                        FROM (
                            SELECT 
                                uo.address,
                                CAST(COALESCE(t.outputs_amounts[uo.index + 1], 0) AS NUMERIC) / 1000000.0 as amount
                            FROM unspent_outputs uo
                            JOIN transactions t ON uo.tx_hash = t.tx_hash
                            WHERE uo.address IS NOT NULL
                        ) as balances
                        GROUP BY address
                        ORDER BY balance DESC
                        LIMIT $1 OFFSET $2
                    """
                    addresses = await conn.fetch(query, limit, offset)
                    
                    result_addresses = [
                        {
                            'address': addr['address'],
                            'balance': "{:f}".format(addr['balance']),
                            'output_count': addr['output_count']
                        }
                        for addr in addresses
                    ]
                
                elif order_by == "transactions":
                    # Get most active addresses by transaction count
                    query = """
                        SELECT 
                            address,
                            COUNT(*) as tx_count
                        FROM (
                            SELECT UNNEST(inputs_addresses) as address FROM transactions
                            UNION ALL
                            SELECT UNNEST(outputs_addresses) as address FROM transactions
                        ) as all_addresses
                        WHERE address IS NOT NULL
                        GROUP BY address
                        ORDER BY tx_count DESC
                        LIMIT $1 OFFSET $2
                    """
                    addresses = await conn.fetch(query, limit, offset)
                    
                    result_addresses = [
                        {
                            'address': addr['address'],
                            'transaction_count': addr['tx_count']
                        }
                        for addr in addresses
                    ]
                
                else:  # tokens
                    # Get addresses with most token holdings
                    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    query = """
                        SELECT 
                            topic2 as address_topic,
                            COUNT(DISTINCT contract_address) as token_count,
                            COUNT(*) as transfer_count
                        FROM contract_logs
                        WHERE topic0 = $1 AND removed = false
                        GROUP BY topic2
                        ORDER BY token_count DESC
                        LIMIT $2 OFFSET $3
                    """
                    addresses = await conn.fetch(query, transfer_topic, limit, offset)
                    
                    result_addresses = [
                        {
                            'address': addr['address_topic'],
                            'token_count': addr['token_count'],
                            'transfer_count': addr['transfer_count']
                        }
                        for addr in addresses
                    ]
        else:
            # SQLite implementation
            if order_by == "balance":
                addresses = await db.get_top_addresses_by_balance(limit, offset)
                result_addresses = [
                    {
                        'address': addr['address'],
                        'balance': str(addr['balance']),
                        'output_count': addr.get('output_count', 0)
                    }
                    for addr in addresses
                ]
            elif order_by == "transactions":
                addresses = await db.get_top_addresses_by_transactions(limit, offset)
                result_addresses = [
                    {
                        'address': addr['address'],
                        'transaction_count': addr['tx_count']
                    }
                    for addr in addresses
                ]
            else:  # tokens
                transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                addresses = await db.get_top_addresses_by_tokens(limit, offset, transfer_topic)
                result_addresses = [
                    {
                        'address': addr['address'],
                        'token_count': addr['token_count'],
                        'transfer_count': addr.get('transfer_count', 0)
                    }
                    for addr in addresses
                ]
        
        result = {
            'ok': True,
            'result': {
                'addresses': result_addresses,
                'count': len(result_addresses),
                'order_by': order_by
            }
        }
    
    except Exception as e:
        logger.error(f"Error fetching top addresses: {e}")
        result = {'ok': False, 'error': 'Error fetching address rankings'}
    
    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json"
        )
    return result


@app.get("/get_recent_transactions")
@limiter.limit("10/minute")
async def get_recent_transactions(
    request: Request,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    include_contract_txs: bool = Query(default=True),
    pretty: bool = False
):
    """
    Get most recent transactions across the chain
    """
    try:
        if hasattr(db, 'pool'):
            # PostgreSQL implementation
            async with db.pool.acquire() as conn:
                # Get recent regular transactions
                txs_query = """
                SELECT 
                    t.tx_hash,
                    t.block_hash,
                    b.id as block_number,
                    b.timestamp,
                    t.fees,
                    COALESCE(array_length(t.outputs_addresses, 1), 0) as output_count
                FROM transactions t
                JOIN blocks b ON t.block_hash = b.hash
                ORDER BY b.id DESC
                LIMIT $1 OFFSET $2
            """
            
            recent_txs = await conn.fetch(txs_query, limit, offset)
            
            result_txs = []
            for tx in recent_txs:
                result_txs.append({
                    'tx_hash': tx['tx_hash'],
                    'block_number': tx['block_number'],
                    'timestamp': tx['timestamp'].isoformat() if tx['timestamp'] else None,
                    'fees': "{:f}".format(tx['fees']) if tx['fees'] else "0",
                    'output_count': tx['output_count'],
                    'type': 'regular'
                })
            
            # Get recent contract transactions if requested
            if include_contract_txs:
                contract_txs_query = """
                    SELECT 
                        ct.tx_hash,
                        ct.block_number,
                        ct.from_address,
                        ct.to_address,
                        ct.value,
                        ct.gas_used,
                        ct.status,
                        b.timestamp
                    FROM contract_transactions ct
                    JOIN blocks b ON ct.block_number = b.id
                    ORDER BY ct.block_number DESC
                    LIMIT $1 OFFSET $2
                """
                
                contract_txs = await conn.fetch(contract_txs_query, min(limit, 100), 0)
                
                for tx in contract_txs:
                    result_txs.append({
                        'tx_hash': tx['tx_hash'],
                        'block_number': tx['block_number'],
                        'timestamp': tx['timestamp'].isoformat() if tx['timestamp'] else None,
                        'from': tx['from_address'],
                        'to': tx['to_address'],
                        'value': tx['value'],
                        'gas_used': tx['gas_used'],
                        'status': 'success' if tx['status'] == 1 else 'failed',
                        'type': 'contract'
                    })
                
                # Sort all transactions by block number
                result_txs.sort(key=lambda x: x['block_number'], reverse=True)
                result_txs = result_txs[:limit]
        else:
            # SQLite implementation
            transactions = await db.get_recent_transactions_with_blocks(limit)
            result_txs = [
                {
                    'tx_hash': tx['tx_hash'],
                    'block_number': tx.get('height', 0),
                    'block_hash': tx.get('block_hash', ''),
                    'timestamp': tx.get('timestamp', ''),
                    'fees': str(tx.get('fee', 0)),
                    'output_count': tx.get('output_count', 0),
                    'type': 'regular'
                }
                for tx in transactions
            ]
            
            if include_contract_txs:
                contract_txs = await db.get_recent_contract_transactions(min(limit, 100))
                for ctx in contract_txs:
                    result_txs.append({
                        'tx_hash': ctx['tx_hash'],
                        'block_number': ctx.get('height', 0),
                        'timestamp': ctx.get('timestamp', ''),
                        'from': ctx['sender'],
                        'to': ctx['contract_address'],
                        'value': str(ctx['value']),
                        'gas_used': ctx['gas_used'],
                        'status': ctx['status'],
                        'type': 'contract'
                    })
                
                # Sort all by timestamp and limit
                result_txs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                result_txs = result_txs[:limit]
            
            result = {
                'ok': True,
                'result': {
                    'transactions': result_txs,
                    'count': len(result_txs)
                }
            }
    
    except Exception as e:
        logger.error(f"Error fetching recent transactions: {e}")
        result = {'ok': False, 'error': 'Error fetching recent transactions'}
    
    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json"
        )
    return result


@app.get("/get_recent_blocks")
@limiter.limit("10/minute")
async def get_recent_blocks(
    request: Request,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    include_validator_info: bool = Query(default=True),
    pretty: bool = False
):
    """
    Get most recent blocks with validator information
    """
    try:
        if hasattr(db, 'pool'):
            # PostgreSQL implementation
            async with db.pool.acquire() as conn:
                # Get recent blocks with validator information
                blocks_query = """
                SELECT 
                    b.id,
                    b.hash,
                    b.address,
                    b.slot,
                    b.epoch,
                    b.proposer_address,
                    b.attestations_included,
                    b.reward,
                    b.timestamp,
                    (SELECT COUNT(*) FROM transactions WHERE block_hash = b.hash) as tx_count
                FROM blocks b
                ORDER BY b.id DESC
                LIMIT $1 OFFSET $2
            """
            
            recent_blocks = await conn.fetch(blocks_query, limit, offset)
            
            result_blocks = []
            for block in recent_blocks:
                block_data = {
                    'block_number': block['id'],
                    'block_hash': block['hash'],
                    'timestamp': block['timestamp'].isoformat() if block['timestamp'] else None,
                    'reward': "{:f}".format(block['reward']) if block['reward'] else "0",
                    'tx_count': block['tx_count']
                }
                
                # Add PoS-specific data if available
                if block['slot'] is not None:
                    block_data.update({
                        'slot': block['slot'],
                        'epoch': block['epoch'],
                        'proposer': block['proposer_address'],
                        'attestations': block['attestations_included']
                    })
                    
                    # Get validator info if requested
                    if include_validator_info and block['proposer_address']:
                        validator = await conn.fetchrow("""
                            SELECT address, stake, effective_stake, status
                            FROM validators
                            WHERE address = $1
                        """, block['proposer_address'])
                        
                        if validator:
                            block_data['validator'] = {
                                'address': validator['address'],
                                'stake': str(validator['stake']),
                                'effective_stake': str(validator['effective_stake']),
                                'status': validator['status']
                            }
                else:
                    # Legacy PoW block
                    block_data['miner'] = block['address']
                
                result_blocks.append(block_data)
        else:
            # SQLite implementation
            recent_blocks = await db.get_recent_blocks_with_validators(limit)
            result_blocks = []
            
            for block in recent_blocks:
                block_data = {
                    'block_number': block.get('block_height', 0),
                    'block_hash': block.get('block_hash', ''),
                    'timestamp': block.get('timestamp', ''),
                    'tx_count': block.get('tx_count', 0)
                }
                
                if include_validator_info:
                    validator_info = await db.get_validator_info(block.get('validator'))
                    if validator_info:
                        block_data['validator'] = {
                            'address': validator_info['address'],
                            'stake': str(validator_info.get('stake', 0)),
                            'status': validator_info.get('status', 'unknown')
                        }
                else:
                    block_data['validator'] = block.get('validator')
                
                result_blocks.append(block_data)
            
            result = {
                'ok': True,
                'result': {
                    'blocks': result_blocks,
                    'count': len(result_blocks)
                }
            }
    
    except Exception as e:
        logger.error(f"Error fetching recent blocks: {e}")
        result = {'ok': False, 'error': 'Error fetching recent blocks'}
    
    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json"
        )
    return result


@app.get("/get_attestations")
@limiter.limit("10/minute")
async def get_attestations(
    request: Request,
    slot: int = Query(default=None),
    epoch: int = Query(default=None),
    validator_address: str = Query(default=None),
    block_hash: str = Query(default=None),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    pretty: bool = False
):
    """
    Get attestations by slot, epoch, validator, or block
    """
    # Validate inputs if provided
    if validator_address and not security.input_validator.validate_address(validator_address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid validator address format")
    
    if block_hash and not security.input_validator.validate_hex(block_hash, min_length=64, max_length=64):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid block hash format")
    
    try:
        if hasattr(db, 'pool'):
            # PostgreSQL implementation
            # Build query based on provided filters
            filters = []
            params = []
            param_count = 0
            
            if slot is not None:
                param_count += 1
                filters.append(f"slot = ${param_count}")
                params.append(slot)
            
            if epoch is not None:
                param_count += 1
                filters.append(f"epoch = ${param_count}")
                params.append(epoch)
            
            if validator_address:
                param_count += 1
                filters.append(f"validator_address = ${param_count}")
                params.append(validator_address)
            
            if block_hash:
                param_count += 1
                filters.append(f"block_hash = ${param_count}")
                params.append(block_hash)
            
            async with db.pool.acquire() as conn:
                where_clause = " AND ".join(filters) if filters else "1=1"
                
                attestations_query = f"""
                    SELECT 
                        a.id,
                        a.slot,
                        a.epoch,
                        a.block_hash,
                        a.validator_address,
                        a.validator_index,
                        a.source_epoch,
                        a.target_epoch,
                        a.included_in_block,
                        a.inclusion_slot,
                        a.created_at,
                        v.stake,
                        v.effective_stake,
                        v.status as validator_status
                    FROM attestations a
                    LEFT JOIN validators v ON a.validator_address = v.address
                    WHERE {where_clause}
                    ORDER BY a.slot DESC, a.validator_index ASC
                    LIMIT ${param_count + 1} OFFSET ${param_count + 2}
                """
                
                params.extend([limit, offset])
                attestations = await conn.fetch(attestations_query, *params)
                
                result_attestations = []
                for att in attestations:
                    result_attestations.append({
                        'id': att['id'],
                        'slot': att['slot'],
                        'epoch': att['epoch'],
                        'block_hash': att['block_hash'],
                        'validator': {
                            'address': att['validator_address'],
                            'index': att['validator_index'],
                            'stake': str(att['stake']) if att['stake'] else None,
                            'effective_stake': str(att['effective_stake']) if att['effective_stake'] else None,
                            'status': att['validator_status']
                        },
                        'checkpoint': {
                            'source_epoch': att['source_epoch'],
                            'target_epoch': att['target_epoch']
                        },
                        'inclusion': {
                            'block_hash': att['included_in_block'],
                            'slot': att['inclusion_slot']
                        } if att['included_in_block'] else None,
                        'created_at': att['created_at'].isoformat() if att['created_at'] else None
                    })
        else:
            # SQLite implementation
            filters = {
                'slot': slot,
                'epoch': epoch,
                'validator_address': validator_address,
                'block_hash': block_hash
            }
            attestations = await db.get_attestations_filtered(filters, limit, offset)
            
            result_attestations = []
            for att in attestations:
                result_attestations.append({
                    'id': att.get('id'),
                    'slot': att.get('slot'),
                    'epoch': att.get('epoch'),
                    'block_hash': att.get('block_hash'),
                    'validator': {
                        'address': att.get('validator_address'),
                        'index': att.get('validator_index'),
                        'stake': str(att.get('stake', 0)),
                        'status': att.get('validator_status')
                    },
                    'checkpoint': {
                        'source_epoch': att.get('source_epoch'),
                        'target_epoch': att.get('target_epoch')
                    },
                    'inclusion': {
                        'block_hash': att.get('included_in_block'),
                        'slot': att.get('inclusion_slot')
                    } if att.get('included_in_block') else None
                })
            
            result = {
                'ok': True,
                'result': {
                    'attestations': result_attestations,
                    'count': len(result_attestations),
                    'filters': {
                        'slot': slot,
                        'epoch': epoch,
                        'validator': validator_address,
                        'block_hash': block_hash
                    }
                }
            }
    
    except Exception as e:
        logger.error(f"Error fetching attestations: {e}")
        result = {'ok': False, 'error': 'Error fetching attestations'}
    
    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json"
        )
    return result


@app.get("/get_transaction")
@limiter.limit("8/second")
async def get_transaction(request: Request, tx_hash: str, verify: bool = False, pretty: bool = False):
    # Validate transaction hash format
    if not security.input_validator.validate_hex(tx_hash, min_length=64, max_length=64):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid transaction hash format")
        
    tx = await db.get_nice_transaction(tx_hash)
    if tx is None:
        result = {'ok': False, 'error': 'Not found'}
    else:
        result = {'ok': True, 'result': tx}
    return Response(content=json.dumps(result, indent=4, cls=CustomJSONEncoder), media_type="application/json") if pretty else result


@app.get("/get_block")
@limiter.limit("8/second")
async def get_block(request: Request, block: str, full_transactions: bool = False, pretty: bool = False):
    # Validate block parameter
    block_info = None
    block_hash = None

    # Validate block parameter
    if block.isdecimal():
        block_id = int(block)
        if not await security.input_validator.validate_block_height(block_id, db, max_ahead=0):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid block height")
        
        block_info = await db.get_block_by_id(block_id)
        if block_info:
            block_hash = block_info['hash']

    else:
        if not security.input_validator.validate_hex(block, min_length=64, max_length=64):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid block hash format")
        
        block_hash = block
        block_info = await db.get_block(block_hash)
        
    if block_info:
        result = {'ok': True, 'result': {
            'block': block_info,
            'transactions': await db.get_block_transactions(block_hash, hex_only=True) if not full_transactions else None,
            'full_transactions': await db.get_block_nice_transactions(block_hash) if full_transactions else None
        }}
    else:
        result = {'ok': False, 'error': 'Not found'}
    
    if pretty:
        return Response(content=json.dumps(result, indent=4, cls=CustomJSONEncoder), media_type="application/json")
    return result


@app.get("/get_blocks")
@limiter.limit("4/second")
async def get_blocks(
    request: Request, 
    offset: int = Query(default=..., ge=0), 
    limit: int = Query(default=..., le=512), 
    pretty: bool = False
):
    # Use QueryCostCalculator to prevent abuse of pagination
    client_ip = get_remote_address(request)
    await security.query_calculator.check_and_update_cost(client_ip, offset, limit)

    blocks = await db.get_blocks(offset, limit)

    # Return structured block data including transactions so that
    # syncing peers can reconstruct the chain.
    structured_blocks = []
    for block in blocks:
        block_hash = block.get('hash') or block.get('block_hash')
        txs = await db.get_block_transactions(block_hash, hex_only=True) if block_hash else []
        # Attach protocol sections so a syncing node reconstructs exchange + EVM/
        # account state (E-D3b); trust-replayed on the consume side.
        if block_hash:
            try:
                ex_section = await db.get_block_exchange_txs(block_hash)
                if ex_section:
                    block['exchange_transactions'] = ex_section
            except Exception:
                pass
            try:
                evm_section = await db.get_block_evm_txs(block_hash)
                if evm_section:
                    block['evm_transactions'] = evm_section
            except Exception:
                pass
        structured_blocks.append({
            'block': block,
            'transactions': txs or []
        })

    result = {'ok': True, 'result': structured_blocks}
    
    if pretty:
        return Response(content=json.dumps(result, indent=4, cls=CustomJSONEncoder), media_type="application/json")
    return result


@app.api_route("/get_status", methods=["GET", "HEAD"])
async def get_status():
    """
    Returns the current block height, last block hash, and the node's ID.
    """
    try:
        height = await db.get_next_block_id() - 1

        # Create a base response object that always includes the node's ID.
        response_data = {
            'height': height,
            'last_block_hash': None,
            'node_id': self_node_id # This is the key addition
        }
        
        if height >= 0:
            last_block = await db.get_block_by_id(height)
            if last_block:
                # If a block exists, add its hash to the response.
                response_data['last_block_hash'] = last_block['hash']
            else:
                # This handles a rare edge case where the DB might be inconsistent.
                # We report height as -1 to signal a non-ready state.
                response_data['height'] = -1

        return {'ok': True, 'result': response_data}
        
    except Exception as e:
        logger.error(f"Error in /get_status: {e}")
        await security.security_monitor.log_event('get_status_error', {'error': str(e)})
        return {'ok': False, 'error': 'Internal server error'}


@app.post("/check_reachability")
@limiter.limit("2/minute")
async def check_reachability(
    request: Request,
    body: dict = Body(...),
    verified_sender: str = Depends(get_verified_sender)
):
    """
    A SECURED endpoint for a peer to ask us to check if they are reachable at a given URL.
    This endpoint is secured against SSRF, anonymous abuse, and DoS amplification.
    """
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    url_to_check = body.get('url_to_check')
    if not url_to_check:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Body must contain 'url_to_check'.")

    cached_result = await security.reachability_cache.get(url_to_check)
    if cached_result is not None:
        logger.debug(f"Returning cached reachability for {url_to_check} for peer {verified_sender}")
        return {"ok": True, "result": {"reachable": cached_result, "cached": True}}

    is_valid, resolved_ip = await security.dns_client.validate_and_resolve(url_to_check)
    if not is_valid:
        return {"ok": False, "error": "Invalid or unresolvable URL"}

    ip_obj = ipaddress.ip_address(resolved_ip)
    if not ip_obj.is_global:
        return {"ok": False, "error": "IP address is not globally routable and cannot be checked."}

    is_reachable = False
    try:
        # Use the single, shared, and persistent http_client
        response = await http_client.get(url_to_check)
        if response.status_code > 0:
            is_reachable = True
    except httpx.RequestError as e:
        logger.warning(f"Reachability check failed for {url_to_check}: {e}")
        is_reachable = False

    await security.reachability_cache.put(url_to_check, is_reachable)
    return {"ok": True, "result": {"reachable": is_reachable, "cached": False}}


@app.post("/get_mempool_hashes")
async def get_mempool_hashes(verified_sender: str = Depends(get_verified_sender)):
    """
    Returns a list of all transaction hashes currently in the pending pool.
    """
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")
    
    hashes = await db.get_all_pending_transaction_hashes()
    return {"ok": True, "result": hashes}


@app.post("/get_transactions_by_hash")
@limiter.limit("20/minute")
async def get_transactions_by_hash(
    request: Request,
    body: dict = Body(...),
    verified_sender: str = Depends(get_verified_sender)
):
    """
    Accepts a list of transaction hashes and returns the full transaction data.
    """
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")
    
    hashes_to_find = body.get('hashes')
    if not isinstance(hashes_to_find, list):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Body must contain a 'hashes' list.")
    
    if len(hashes_to_find) > MAX_TX_FETCH_LIMIT:
        await security.reputation_manager.record_violation(
            verified_sender, 'tx_fetch_limit_exceeded', severity=2
        )
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, 
            f"Request limit exceeded. Maximum {MAX_TX_FETCH_LIMIT} transactions per request."
        )

    # Validate all hashes using the secure validator
    for hash_str in hashes_to_find:
        if not security.input_validator.validate_hex(hash_str, min_length=64, max_length=64):
            await security.reputation_manager.record_violation(
                verified_sender, 'invalid_tx_hash_format', severity=3
            )
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid transaction hash format for hash: {hash_str}")

    found_txs = await db.get_pending_transactions_by_hash(hashes_to_find)
    tx_hex_list = [tx.hex() for tx in found_txs]
    
    return {"ok": True, "result": tx_hex_list}


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            # Format Decimal as a string to preserve precision
            return "{:f}".format(o)
        if isinstance(o, datetime):
            # Format datetime to a standard ISO string
            return o.isoformat()
        return super().default(o)

