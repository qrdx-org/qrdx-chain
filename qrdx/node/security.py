"""
Request and peer security for the node: challenge handshakes, request signatures,
input validation, peer reputation and rate-limit keys.
"""

import asyncio
import hashlib
import ipaddress
import os
import socket
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from fastapi import HTTPException, status
from slowapi.util import get_remote_address
from starlette.requests import Request

from qrdx.constants import MAX_CONCURRENT_SYNCS, MAX_PEERS, VALID_ADDRESS_PATTERN
from qrdx.logger import get_logger
from qrdx.node.identity import get_canonical_json_bytes, node_id_for_public_key, verify_signature

logger = get_logger(__name__)


class TimeBasedCache:
    """Thread-safe cache with automatic expiration"""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._access_order: "deque[str]" = deque(maxlen=max_size)
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
                k for k, (_, ts) in self._cache.items() if current_time - ts >= self.ttl_seconds
            ]
            for k in expired_keys:
                del self._cache[k]


class HandshakeChallengeManager:
    """Secure challenge management with automatic cleanup"""

    def __init__(self, ttl_seconds: int = 300):
        self._challenges: Dict[str, float] = {}
        # challenge -> the verified node it was issued to (None: issued without a caller)
        self._issued_to: Dict[str, Optional[str]] = {}
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
                challenge
                for challenge, timestamp in self._challenges.items()
                if current_time - timestamp > self.ttl_seconds
            ]
            for challenge in expired:
                del self._challenges[challenge]
                self._issued_to.pop(challenge, None)

    async def create_challenge(self, issued_to: Optional[str] = None) -> str:
        """Create a new challenge"""
        challenge = os.urandom(32).hex()

        async with self._lock:
            # Prevent unlimited growth
            if len(self._challenges) > 10000:
                # Remove oldest half
                sorted_challenges = sorted(self._challenges.items(), key=lambda x: x[1])
                for challenge_to_remove, _ in sorted_challenges[:5000]:
                    del self._challenges[challenge_to_remove]
                    self._issued_to.pop(challenge_to_remove, None)

            self._challenges[challenge] = time.time()
            self._issued_to[challenge] = issued_to

        return challenge

    async def verify_and_consume_challenge(
        self, challenge: str, caller: Optional[str] = None
    ) -> bool:
        """Verify challenge exists and immediately consume it. A challenge issued to a verified
        node is answerable only by that node: another caller cannot complete its handshake."""
        async with self._lock:
            if challenge in self._challenges:
                timestamp = self._challenges[challenge]
                issued_to = self._issued_to.get(challenge)
                current_time = time.time()

                # Check if expired
                if current_time - timestamp > self.ttl_seconds:
                    del self._challenges[challenge]
                    self._issued_to.pop(challenge, None)
                    return False

                if issued_to is not None and caller != issued_to:
                    return False  # not consumed: the node it was issued to may still answer

                # Valid challenge - consume it immediately
                del self._challenges[challenge]
                self._issued_to.pop(challenge, None)
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
                        detail="Node is already synchronizing",
                    )

                async with self._count_lock:
                    if self.active_sync_count >= self.max_concurrent_syncs:
                        raise HTTPException(
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Maximum concurrent syncs reached",
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
    def validate_hex(
        hex_string: str, min_length: int = 1, max_length: Optional[int] = None
    ) -> bool:
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
        node_id = request.headers.get("x-node-id")
        pubkey = request.headers.get("x-public-key")
        signature = request.headers.get("x-signature")
        timestamp_header = request.headers.get("x-timestamp")
        nonce = request.headers.get("x-nonce")

        if not node_id or not pubkey or not signature or not timestamp_header or not nonce:
            return None

        # A node id is BLAKE3(public key): one the key does not stand for is a false claim,
        # whatever the signature says (it only proves the key, not the id).
        if node_id_for_public_key(pubkey) != node_id:
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

            # Start with the base payload. A request signed in the hash form (x-body-hash:
            # sha256) signed the body's SHA-256, not the body: canonicalizing a block's body to
            # sign it cost as much as sending it (docs/PERFORMANCE.md). The plain form is still
            # accepted from nodes that sign that way.
            if request.headers.get("x-body-hash") == "sha256":
                payload_to_verify = {
                    "body_sha256": hashlib.sha256(request_body_bytes).hexdigest(),
                    "timestamp": request_time,
                    "nonce": nonce,
                }
            else:
                payload_to_verify = {
                    "body": request_body_bytes.decode("utf-8"),
                    "timestamp": request_time,
                    "nonce": nonce,
                }

            # Reconstruct the full payload by looking for our custom signed headers.
            # The client signed these, so we MUST include them for verification.
            for key, value in request.headers.items():
                if key.lower().startswith("x-denaro-"):
                    # The client added this key without the prefix to the signed dict.
                    # e.g., 'x-denaro-height' -> 'height'
                    original_key = key.lower().replace("x-denaro-", "")
                    # Attempt to convert numeric values back to numbers for a perfect match
                    try:
                        # Check if it looks like a number (int or float)
                        if "." in value:
                            payload_to_verify[original_key] = float(value)
                        else:
                            payload_to_verify[original_key] = int(value)
                    except ValueError:
                        # It's not a number, treat it as a string.
                        # Handle 'None' string specifically.
                        if value == "None":
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
            if parsed.scheme not in ["http", "https"]:
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

    async def record_violation(
        self, peer_id: str, violation_type: str, severity: int = 5, details: Optional[str] = None
    ):
        """Record a violation and update peer score"""
        async with self._lock:
            violation = PeerViolation(
                timestamp=time.time(),
                violation_type=violation_type,
                severity=severity,
                details=details,
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
                    detail="Query cost limit exceeded. Try again later.",
                )

            self._costs[identifier] += cost


class SecurityMonitor:
    """Monitor and log security events"""

    def __init__(self):
        self._metrics = {
            "failed_validations": defaultdict(int),
            "rate_limit_hits": defaultdict(int),
            "banned_peers": 0,
            "replay_attempts": 0,
            "dns_rebinding_attempts": 0,
            "resource_exhaustion_attempts": 0,
        }
        self._lock = asyncio.Lock()

    async def log_event(self, event_type: str, details: dict):
        """Log security event"""
        async with self._lock:
            # Update metrics
            if event_type in self._metrics:
                if isinstance(self._metrics[event_type], dict):
                    key = details.get("subtype", "default")
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
                        alerts.append({"type": event_type, "count": total, "severity": "high"})

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
                for old_hash, _ in sorted_txs[: self.max_size // 10]:  # Remove 10%
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
    node_id = request.headers.get("x-node-id")
    if node_id:
        return node_id

    # For all other requests (e.g., from wallets, miners), use the remote address.
    return get_remote_address(request)
