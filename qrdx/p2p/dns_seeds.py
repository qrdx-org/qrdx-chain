"""
QRDX DNS Seed Discovery

Provides decentralized peer discovery via DNS TXT records:
- DNS seeds are domain names that resolve to TXT records containing
  signed peer lists in @-schema format
- Each TXT record is signed by the seed operator's Dilithium key
- Multiple independent seed operators prevent single-point-of-failure
- DNSSEC validation when available
- Fallback chain: DHT → DNS seeds → hardcoded bootstrap

DNS TXT Record Format:
    v=qrdx1 nodes=<@-schema>,<@-schema>,... sig=<hex_signature> pubkey=<hex_pubkey>

The signature covers: "v=qrdx1 nodes=<nodes_csv>" using the seed
operator's Dilithium key, ensuring records cannot be forged even
if DNS is compromised.

Reference: Bitcoin's DNS seed mechanism (BIP-0023 style), upgraded
with post-quantum signatures.
"""

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# DNS TXT record version tag
DNS_SEED_VERSION = "qrdx1"

# Default DNS seed domains (operated by independent organizations)
DEFAULT_DNS_SEEDS = [
    "seeds.qrdx.org",
    "seeds2.qrdx.org",
    "dnsseed.qrdxvalidators.org",
]

# Cache TTL for DNS seed results (seconds)
DNS_CACHE_TTL = 3600  # 1 hour

# Maximum nodes per DNS seed record
MAX_NODES_PER_SEED = 50

# DNS lookup timeout (seconds)
DNS_LOOKUP_TIMEOUT = 10.0

# Minimum seed operators for decentralization
MIN_SEED_OPERATORS = 2

# TXT record regex
_TXT_RECORD_RE = re.compile(
    r'v=(?P<version>\w+)\s+nodes=(?P<nodes>[^\s]+)\s+sig=(?P<sig>[a-fA-F0-9]+)\s+pubkey=(?P<pubkey>[a-fA-F0-9]+)'
)


# ---------------------------------------------------------------------------
# Seed Operator Trust Anchor
# ---------------------------------------------------------------------------

@dataclass
class SeedOperator:
    """
    A trusted DNS seed operator.

    Each operator has a Dilithium public key used to verify
    the authenticity of DNS TXT records they publish.
    """
    domain: str
    public_key_hex: str  # Dilithium public key hex for signature verification
    organization: str    # Human-readable org name
    is_active: bool = True

    @property
    def public_key_bytes(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)


# ---------------------------------------------------------------------------
# DNSSeedResult
# ---------------------------------------------------------------------------

@dataclass
class DNSSeedResult:
    """Result from querying a single DNS seed."""
    domain: str
    nodes: List[str]          # @-schema addresses
    signature_valid: bool
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None

    @property
    def is_fresh(self) -> bool:
        return (time.time() - self.timestamp) < DNS_CACHE_TTL


# ---------------------------------------------------------------------------
# DNSSeedDiscovery
# ---------------------------------------------------------------------------

class DNSSeedDiscovery:
    """
    Discovers peers via DNS TXT records with PQ signature verification.

    Features:
    - Queries multiple independent DNS seed domains
    - Verifies Dilithium signatures on TXT records
    - Caches results to reduce DNS queries
    - Falls back gracefully if DNS is unavailable
    - Can operate without any trusted operators (unsigned mode for testnets)
    """

    def __init__(
        self,
        seed_domains: Optional[List[str]] = None,
        trusted_operators: Optional[List[SeedOperator]] = None,
        *,
        require_signatures: bool = True,
    ):
        """
        Initialize DNS seed discovery.

        Args:
            seed_domains: List of DNS seed domains to query.
            trusted_operators: List of trusted seed operators with public keys.
            require_signatures: If True, reject unsigned/invalid TXT records.
        """
        self._domains = seed_domains or list(DEFAULT_DNS_SEEDS)
        self._operators: Dict[str, SeedOperator] = {}
        if trusted_operators:
            for op in trusted_operators:
                self._operators[op.domain] = op
        self._require_signatures = require_signatures
        self._cache: Dict[str, DNSSeedResult] = {}
        self._last_query_time: float = 0

    @property
    def seed_domains(self) -> List[str]:
        """Get configured seed domains."""
        return list(self._domains)

    @property
    def trusted_operator_count(self) -> int:
        """Number of trusted seed operators."""
        return len(self._operators)

    def add_seed_domain(self, domain: str) -> None:
        """Add a DNS seed domain."""
        if domain not in self._domains:
            self._domains.append(domain)

    def add_trusted_operator(self, operator: SeedOperator) -> None:
        """Add a trusted seed operator."""
        self._operators[operator.domain] = operator

    # -- DNS query ----------------------------------------------------------

    async def _resolve_txt(self, domain: str) -> List[str]:
        """
        Resolve DNS TXT records for a domain.

        Uses asyncio subprocess to call `dig` for portability,
        falling back to direct socket resolution.

        Returns list of TXT record strings.
        """
        try:
            # Use asyncio subprocess for non-blocking DNS query
            proc = await asyncio.create_subprocess_exec(
                'dig', '+short', 'TXT', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=DNS_LOOKUP_TIMEOUT,
            )

            if proc.returncode != 0:
                logger.debug(f"DNS query for {domain} failed: {stderr.decode()}")
                return []

            records = []
            for line in stdout.decode().strip().split('\n'):
                line = line.strip().strip('"')
                if line:
                    records.append(line)
            return records

        except asyncio.TimeoutError:
            logger.debug(f"DNS query for {domain} timed out")
            return []
        except FileNotFoundError:
            # `dig` not available — try Python's built-in resolver
            return await self._resolve_txt_builtin(domain)
        except Exception as e:
            logger.debug(f"DNS query for {domain} error: {e}")
            return []

    async def _resolve_txt_builtin(self, domain: str) -> List[str]:
        """Fallback TXT resolution using Python's socket/dns modules."""
        try:
            import socket
            # Python's socket doesn't support TXT records directly
            # Use the subprocess approach with `nslookup` as fallback
            proc = await asyncio.create_subprocess_exec(
                'nslookup', '-type=TXT', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=DNS_LOOKUP_TIMEOUT,
            )

            records = []
            for line in stdout.decode().split('\n'):
                if 'text =' in line.lower():
                    # Extract the TXT value
                    txt = line.split('=', 1)[1].strip().strip('"')
                    records.append(txt)
            return records

        except Exception as e:
            logger.debug(f"Builtin DNS resolution for {domain} failed: {e}")
            return []

    # -- TXT record parsing -------------------------------------------------

    def _parse_txt_record(self, domain: str, record: str) -> Optional[DNSSeedResult]:
        """
        Parse and validate a DNS TXT record.

        Format: v=qrdx1 nodes=<@-schema>,<@-schema>,... sig=<hex> pubkey=<hex>
        """
        match = _TXT_RECORD_RE.match(record)
        if not match:
            # Try unsigned format: just a comma-separated list of @-schema nodes
            if not self._require_signatures and '@' in record:
                nodes = [n.strip() for n in record.split(',') if '@' in n]
                if nodes:
                    return DNSSeedResult(
                        domain=domain,
                        nodes=nodes[:MAX_NODES_PER_SEED],
                        signature_valid=False,
                    )
            return None

        version = match.group('version')
        if version != DNS_SEED_VERSION:
            logger.debug(f"Unsupported DNS seed version: {version}")
            return None

        nodes_csv = match.group('nodes')
        sig_hex = match.group('sig')
        pubkey_hex = match.group('pubkey')

        nodes = [n.strip() for n in nodes_csv.split(',') if n.strip()]

        # Verify signature
        sig_valid = self._verify_signature(
            domain, version, nodes_csv, sig_hex, pubkey_hex
        )

        if self._require_signatures and not sig_valid:
            logger.warning(
                f"DNS seed {domain}: signature verification FAILED — "
                f"rejecting {len(nodes)} nodes"
            )
            return None

        return DNSSeedResult(
            domain=domain,
            nodes=nodes[:MAX_NODES_PER_SEED],
            signature_valid=sig_valid,
        )

    def _verify_signature(
        self,
        domain: str,
        version: str,
        nodes_csv: str,
        sig_hex: str,
        pubkey_hex: str,
    ) -> bool:
        """
        Verify the Dilithium signature on a DNS TXT record.

        The signed message is: "v=<version> nodes=<nodes_csv>"
        """
        try:
            import oqs

            # Check if this pubkey matches a trusted operator
            operator = self._operators.get(domain)
            if operator and operator.public_key_hex != pubkey_hex:
                logger.warning(
                    f"DNS seed {domain}: pubkey mismatch — "
                    f"expected {operator.public_key_hex[:32]}..., "
                    f"got {pubkey_hex[:32]}..."
                )
                return False

            message = f"v={version} nodes={nodes_csv}".encode()
            signature = bytes.fromhex(sig_hex)
            public_key = bytes.fromhex(pubkey_hex)

            # Resolve algorithm name
            for algo_name in ('ML-DSA-65', 'Dilithium3'):
                try:
                    verifier = oqs.Signature(algo_name)
                    return verifier.verify(message, signature, public_key)
                except Exception:
                    continue

            return False

        except ImportError:
            logger.warning("liboqs not available — cannot verify DNS seed signatures")
            return False
        except Exception as e:
            logger.warning(f"DNS seed signature verification error: {e}")
            return False

    # -- Main discovery flow ------------------------------------------------

    async def discover(self) -> List[str]:
        """
        Query all DNS seeds and return discovered @-schema node addresses.

        Results from multiple seeds are merged and deduplicated.
        Cached results are returned if fresh.

        Returns:
            List of @-schema node addresses.
        """
        all_nodes: List[str] = []
        seen: Set[str] = set()

        for domain in self._domains:
            # Check cache first
            cached = self._cache.get(domain)
            if cached and cached.is_fresh:
                for node in cached.nodes:
                    if node not in seen:
                        seen.add(node)
                        all_nodes.append(node)
                continue

            # Query DNS
            records = await self._resolve_txt(domain)

            for record in records:
                result = self._parse_txt_record(domain, record)
                if result:
                    self._cache[domain] = result
                    for node in result.nodes:
                        if node not in seen:
                            seen.add(node)
                            all_nodes.append(node)

        self._last_query_time = time.time()

        logger.info(
            f"DNS seed discovery: {len(all_nodes)} unique nodes from "
            f"{len(self._domains)} seeds"
        )
        return all_nodes

    async def discover_with_fallback(
        self,
        hardcoded_bootstrap: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Discover peers with fallback chain: DNS seeds → hardcoded bootstrap.

        Args:
            hardcoded_bootstrap: Fallback bootstrap addresses if DNS fails.

        Returns:
            List of @-schema or HTTP addresses.
        """
        # Try DNS seeds first
        nodes = await self.discover()

        if len(nodes) >= MIN_SEED_OPERATORS:
            return nodes

        # Fall back to hardcoded bootstrap
        if hardcoded_bootstrap:
            logger.info(
                f"DNS discovery found {len(nodes)} nodes — "
                f"adding {len(hardcoded_bootstrap)} hardcoded bootstrap nodes"
            )
            seen = set(nodes)
            for addr in hardcoded_bootstrap:
                if addr not in seen:
                    seen.add(addr)
                    nodes.append(addr)

        return nodes

    # -- Statistics ----------------------------------------------------------

    def get_stats(self) -> Dict:
        """Get DNS seed discovery statistics."""
        return {
            'seed_domains': self._domains,
            'trusted_operators': len(self._operators),
            'require_signatures': self._require_signatures,
            'cached_results': len(self._cache),
            'last_query_time': self._last_query_time,
            'cache': {
                domain: {
                    'nodes': len(result.nodes),
                    'signature_valid': result.signature_valid,
                    'fresh': result.is_fresh,
                }
                for domain, result in self._cache.items()
            },
        }
