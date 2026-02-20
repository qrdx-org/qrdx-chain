"""
QRDX System Wallets Module

Implements system-owned wallets that are:
1. Off-curve (no private key exists)
2. Pre-funded in genesis
3. Controlled by a single PQ wallet or m-of-n multisig keyset defined in genesis
4. Have custom 0x0000...000X addresses

Multisig Support (Whitepaper §6.1):
    Each system wallet can be optionally governed by a MultisigKeySet.
    When a multisig keyset is assigned, spending requires m-of-n threshold
    Dilithium signatures instead of a single controller signature.

These wallets provide decentralized system functionality with secure,
quantum-resistant control via a designated controller wallet.
"""

import hashlib
from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, List, Optional, Union
from enum import Enum

from .hashing import sha256
from ..logger import get_logger

logger = get_logger(__name__)


# System wallet address range (0x0000...0001 through 0x0000...00FF)
SYSTEM_WALLET_MIN = 0x0000000000000000000000000000000000000001
SYSTEM_WALLET_MAX = 0x00000000000000000000000000000000000000FF


class SystemWalletType(Enum):
    """Types of system wallets."""
    GARBAGE_COLLECTOR = "garbage_collector"
    COMMUNITY_GRANTS = "community_grants"
    DEVELOPER_FUND = "developer_fund"
    ECOSYSTEM_FUND = "ecosystem_fund"
    STAKING_REWARDS = "staking_rewards"
    MARKETING = "marketing"
    LIQUIDITY_RESERVE = "liquidity_reserve"
    TREASURY_MULTISIG = "treasury_multisig"
    BUG_BOUNTY = "bug_bounty"
    AIRDROP = "airdrop"


@dataclass
class SystemWallet:
    """
    Represents a system-owned wallet.
    
    Attributes:
        address: The 0x0000...000X address
        name: Human-readable name
        description: Purpose of this wallet
        wallet_type: Type of system wallet
        genesis_balance: Initial balance in genesis (in QRDX)
        is_burner: If True, funds sent here are permanently burned
        category: Categorization (system, treasury, defi, distribution, security)
    """
    address: str
    name: str
    description: str
    wallet_type: SystemWalletType
    genesis_balance: Decimal
    is_burner: bool = False
    category: str = "system"
    
    def __post_init__(self):
        """Validate system wallet configuration."""
        if not self.address.startswith("0x"):
            raise ValueError(f"System wallet address must start with 0x: {self.address}")
        
        # Validate address is in system range
        addr_int = int(self.address, 16)
        if not (SYSTEM_WALLET_MIN <= addr_int <= SYSTEM_WALLET_MAX):
            raise ValueError(
                f"System wallet address {self.address} outside valid range "
                f"0x{'0'*39}1 - 0x{'0'*38}FF"
            )
        
        # Validate genesis balance
        if self.genesis_balance < 0:
            raise ValueError(f"Genesis balance cannot be negative: {self.genesis_balance}")
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "address": self.address,
            "name": self.name,
            "description": self.description,
            "type": self.wallet_type.value,
            "genesis_balance": str(self.genesis_balance),
            "is_burner": self.is_burner,
            "category": self.category,
        }


class SystemWalletManager:
    """
    Manages system wallets and their controller.

    Supports two controller modes:
      1. Single PQ Key: original mode — one PQ address authorises all spends
      2. Multisig KeySet: upgraded mode — m-of-n threshold Dilithium signatures
         required to authorise spends

    Per-wallet multisig overrides are also supported: individual system wallets
    can have their own MultisigKeySet (e.g. Treasury at 5-of-9 while others
    stay at the default controller).

    Provides:
    - System wallet creation and validation
    - Controller wallet verification (single-key and multisig)
    - Transaction authorization checks
    """

    def __init__(self, controller_pq_address: str):
        """
        Initialize system wallet manager.

        Args:
            controller_pq_address: The PQ address that controls all system wallets
        """
        from .address import is_pq_address, is_valid_address
        from .threshold_dilithium import is_multisig_address

        # Accept PQ addresses or multisig addresses as controller
        valid = is_valid_address(controller_pq_address) or is_multisig_address(controller_pq_address)
        if not valid:
            raise ValueError(f"Invalid controller address: {controller_pq_address}")

        # Must be PQ or multisig — not a traditional ECDSA address
        if not (is_pq_address(controller_pq_address) or is_multisig_address(controller_pq_address)):
            raise ValueError(
                f"Controller must be a post-quantum (0xPQ) or multisig (0xPQMS) address: "
                f"{controller_pq_address}"
            )

        self.controller_address = controller_pq_address
        self._system_wallets: Dict[str, SystemWallet] = {}

        # Per-wallet multisig keysets (optional overrides)
        self._wallet_multisigs: Dict[str, 'MultisigKeySet'] = {}

        # Global multisig keyset (optional — replaces single-key controller)
        self._global_multisig: Optional['MultisigKeySet'] = None

        logger.info(f"System wallet manager initialized with controller: {controller_pq_address}")

    # ── Multisig Configuration ──────────────────────────────────────

    def set_global_multisig(self, keyset: 'MultisigKeySet') -> None:
        """
        Upgrade the global controller to a multisig keyset.

        After this, all wallets without per-wallet overrides require
        m-of-n threshold signatures.

        Args:
            keyset: MultisigKeySet to use as global controller
        """
        self._global_multisig = keyset
        self.controller_address = keyset.address
        logger.info(
            f"Global multisig set: {keyset.config} at {keyset.address}"
        )

    def set_wallet_multisig(self, wallet_address: str, keyset: 'MultisigKeySet') -> None:
        """
        Assign a per-wallet multisig keyset.

        This wallet will require its own m-of-n threshold to spend,
        independent of the global controller.

        Args:
            wallet_address: System wallet address
            keyset: MultisigKeySet specific to this wallet
        """
        if not self.is_system_wallet(wallet_address):
            raise ValueError(f"Not a registered system wallet: {wallet_address}")
        self._wallet_multisigs[wallet_address] = keyset
        logger.info(
            f"Wallet-level multisig set for {wallet_address}: "
            f"{keyset.config} at {keyset.address}"
        )

    def get_wallet_multisig(self, wallet_address: str) -> Optional['MultisigKeySet']:
        """Get the effective multisig keyset for a wallet (per-wallet or global)."""
        return self._wallet_multisigs.get(wallet_address, self._global_multisig)

    def is_multisig_controlled(self, wallet_address: Optional[str] = None) -> bool:
        """Check if a wallet (or the global controller) uses multisig."""
        if wallet_address and wallet_address in self._wallet_multisigs:
            return True
        return self._global_multisig is not None

    # ── Registration & Query ────────────────────────────────────────

    def register_system_wallet(self, wallet: SystemWallet) -> None:
        """
        Register a system wallet.

        Args:
            wallet: SystemWallet instance to register
        """
        if wallet.address in self._system_wallets:
            raise ValueError(f"System wallet already registered: {wallet.address}")

        self._system_wallets[wallet.address] = wallet
        logger.info(
            f"Registered system wallet: {wallet.name} at {wallet.address} "
            f"with balance {wallet.genesis_balance} QRDX"
        )

    def get_system_wallet(self, address: str) -> Optional[SystemWallet]:
        """Get system wallet by address."""
        return self._system_wallets.get(address)

    def is_system_wallet(self, address: str) -> bool:
        """Check if an address is a registered system wallet."""
        return address in self._system_wallets

    def is_burner_wallet(self, address: str) -> bool:
        """Check if an address is a burner wallet (funds are destroyed)."""
        wallet = self.get_system_wallet(address)
        return wallet is not None and wallet.is_burner

    # ── Spending Authorization ──────────────────────────────────────

    def can_spend_from(self, system_wallet_address: str, spender_address: str) -> bool:
        """
        Check if a spender can spend from a system wallet (single-key mode).

        For multisig-controlled wallets use ``verify_multisig_spend`` instead;
        this method returns ``False`` for them when a non-controller address is
        used, but ``True`` when the spender matches the (possibly multisig)
        controller address.

        Args:
            system_wallet_address: The system wallet address
            spender_address: The address attempting to spend

        Returns:
            True if spender is the effective controller, False otherwise
        """
        if not self.is_system_wallet(system_wallet_address):
            return False  # Not a system wallet

        # Per-wallet multisig overrides
        wallet_ms = self._wallet_multisigs.get(system_wallet_address)
        if wallet_ms:
            return spender_address == wallet_ms.address

        # Global controller (could be single PQ key or global multisig address)
        return spender_address == self.controller_address

    def verify_multisig_spend(
        self,
        system_wallet_address: str,
        message: bytes,
        multisig_signature: 'MultisigSignature',
    ) -> tuple[bool, str]:
        """
        Verify a multisig threshold signature for a system wallet spend.

        This is the primary authorization path for multisig-controlled wallets.

        Args:
            system_wallet_address: The system wallet address
            message: The transaction message that was signed
            multisig_signature: The m-of-n MultisigSignature

        Returns:
            Tuple of (is_valid, reason)
        """
        from .threshold_dilithium import verify_multisig as _verify_ms

        if not self.is_system_wallet(system_wallet_address):
            return False, f"Not a system wallet: {system_wallet_address}"

        wallet = self.get_system_wallet(system_wallet_address)
        if wallet and wallet.is_burner:
            return False, f"Cannot spend from burner wallet: {system_wallet_address}"

        keyset = self.get_wallet_multisig(system_wallet_address)
        if keyset is None:
            return False, (
                f"No multisig keyset configured for {system_wallet_address}; "
                f"use single-key can_spend_from() instead"
            )

        if _verify_ms(keyset, message, multisig_signature):
            return True, "OK"
        return False, "Multisig verification failed"

    def validate_system_transaction(
        self,
        from_address: str,
        signer_address: str,
    ) -> tuple[bool, str]:
        """
        Validate a transaction involving a system wallet (single-key mode).

        For multisig wallets, use ``verify_multisig_spend`` instead.

        Args:
            from_address: Address sending funds
            signer_address: Address that signed the transaction

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if spending from a system wallet
        if not self.is_system_wallet(from_address):
            return True, "OK"  # Not a system wallet, no special validation needed

        # Check if transaction is from burner wallet (should never spend)
        wallet = self.get_system_wallet(from_address)
        if wallet and wallet.is_burner:
            return False, f"Cannot spend from burner wallet: {from_address}"

        # Check per-wallet multisig
        wallet_ms = self._wallet_multisigs.get(from_address)
        if wallet_ms:
            if signer_address == wallet_ms.address:
                return True, "OK"
            return False, (
                f"System wallet {from_address} requires multisig {wallet_ms.address}, "
                f"not {signer_address}"
            )

        # Verify signer is the controller
        if signer_address != self.controller_address:
            return False, (
                f"System wallet {from_address} can only be spent by controller "
                f"{self.controller_address}, not {signer_address}"
            )

        return True, "OK"

    # ── Aggregate Queries ───────────────────────────────────────────

    def get_all_wallets(self) -> List[SystemWallet]:
        """Get all registered system wallets."""
        return list(self._system_wallets.values())

    def get_total_genesis_balance(self) -> Decimal:
        """Calculate total balance across all system wallets."""
        return sum(w.genesis_balance for w in self._system_wallets.values())

    def export_genesis_allocations(self) -> Dict[str, tuple[Decimal, str]]:
        """
        Export system wallet allocations for genesis.

        Returns:
            Dict of {address: (balance, label)}
        """
        return {
            wallet.address: (wallet.genesis_balance, wallet.name)
            for wallet in self._system_wallets.values()
        }


def is_system_wallet_address(address: str) -> bool:
    """
    Check if an address is in the system wallet range.
    
    Args:
        address: Address to check
        
    Returns:
        True if address is in system wallet range (0x0000...0001 - 0x0000...00FF)
    """
    if not address.startswith("0x"):
        return False
    
    try:
        addr_int = int(address, 16)
        return SYSTEM_WALLET_MIN <= addr_int <= SYSTEM_WALLET_MAX
    except ValueError:
        return False


def is_address_off_curve(address: str) -> bool:
    """
    Check if an address is off-curve (not derivable from a private key).
    
    For system wallets, we define off-curve as:
    - Addresses in the reserved system range (0x0000...0001 - 0x0000...00FF)
    - Addresses that cannot be generated from secp256k1 or Dilithium keys
    
    Args:
        address: Address to check
        
    Returns:
        True if address is off-curve
    """
    # System wallet addresses are off-curve by definition
    if is_system_wallet_address(address):
        return True
    
    # Check for other reserved ranges (precompiles, etc.)
    # Reserved: 0x0000...0100 - 0x0000...0FFF for future use
    if not address.startswith("0x"):
        return False
    
    try:
        addr_int = int(address, 16)
        # Extended reserved range for future system contracts
        RESERVED_MIN = 0x0000000000000000000000000000000000000100
        RESERVED_MAX = 0x0000000000000000000000000000000000000FFF
        return RESERVED_MIN <= addr_int <= RESERVED_MAX
    except ValueError:
        return False


def generate_system_wallet_address(index: int) -> str:
    """
    Generate a system wallet address from an index.
    
    Args:
        index: Index in range [1, 255]
        
    Returns:
        System wallet address (e.g., "0x0000000000000000000000000000000000000001")
    """
    if not (1 <= index <= 255):
        raise ValueError(f"System wallet index must be 1-255, got {index}")
    
    # Create address with leading zeros
    return f"0x{index:040x}"


def create_default_system_wallets() -> List[SystemWallet]:
    """
    Create the default set of system wallets.
    
    Returns:
        List of SystemWallet instances
    """
    return [
        SystemWallet(
            address="0x0000000000000000000000000000000000000001",
            name="Garbage Collector",
            description="Automated garbage collection wallet that burns unclaimed tokens and fees",
            wallet_type=SystemWalletType.GARBAGE_COLLECTOR,
            genesis_balance=Decimal("0"),  # Burner wallets start with 0
            is_burner=True,
            category="system",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000002",
            name="Community Grant Wallet",
            description="Distributes grants to community projects and ecosystem development initiatives",
            wallet_type=SystemWalletType.COMMUNITY_GRANTS,
            genesis_balance=Decimal("5000000"),  # 5M QRDX
            category="treasury",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000003",
            name="Developer Fund",
            description="Core development team funding wallet for protocol maintenance and improvements",
            wallet_type=SystemWalletType.DEVELOPER_FUND,
            genesis_balance=Decimal("10000000"),  # 10M QRDX
            category="treasury",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000004",
            name="Ecosystem Fund",
            description="Strategic investments in projects building on the QRDX network",
            wallet_type=SystemWalletType.ECOSYSTEM_FUND,
            genesis_balance=Decimal("8000000"),  # 8M QRDX
            category="treasury",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000005",
            name="Staking Rewards Pool",
            description="Distributes staking rewards to network validators and delegators",
            wallet_type=SystemWalletType.STAKING_REWARDS,
            genesis_balance=Decimal("15000000"),  # 15M QRDX
            category="system",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000006",
            name="Marketing & Partnerships",
            description="Funds marketing initiatives, partnerships, and ecosystem growth campaigns",
            wallet_type=SystemWalletType.MARKETING,
            genesis_balance=Decimal("3000000"),  # 3M QRDX
            category="treasury",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000007",
            name="Liquidity Pool Reserve",
            description="Reserve funds for maintaining liquidity across DEX pools",
            wallet_type=SystemWalletType.LIQUIDITY_RESERVE,
            genesis_balance=Decimal("7000000"),  # 7M QRDX
            category="defi",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000008",
            name="Treasury Multisig",
            description="Main protocol treasury controlled by multi-signature governance",
            wallet_type=SystemWalletType.TREASURY_MULTISIG,
            genesis_balance=Decimal("20000000"),  # 20M QRDX
            category="treasury",
        ),
        SystemWallet(
            address="0x0000000000000000000000000000000000000009",
            name="Bug Bounty Program",
            description="Rewards security researchers for finding and reporting vulnerabilities",
            wallet_type=SystemWalletType.BUG_BOUNTY,
            genesis_balance=Decimal("1000000"),  # 1M QRDX
            category="security",
        ),
        SystemWallet(
            address="0x000000000000000000000000000000000000000a",
            name="Airdrop Distribution",
            description="Manages community airdrops and token distribution campaigns",
            wallet_type=SystemWalletType.AIRDROP,
            genesis_balance=Decimal("6000000"),  # 6M QRDX
            category="distribution",
        ),
    ]


def initialize_system_wallets(controller_pq_address: str) -> SystemWalletManager:
    """
    Initialize system wallet manager with default wallets.
    
    Args:
        controller_pq_address: PQ address that will control all system wallets
        
    Returns:
        Configured SystemWalletManager instance
    """
    manager = SystemWalletManager(controller_pq_address)
    
    # Register all default system wallets
    for wallet in create_default_system_wallets():
        manager.register_system_wallet(wallet)
    
    total = manager.get_total_genesis_balance()
    logger.info(f"Initialized {len(manager.get_all_wallets())} system wallets")
    logger.info(f"Total system wallet allocation: {total} QRDX")
    
    return manager
