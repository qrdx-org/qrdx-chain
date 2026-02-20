"""
QRDX Prefunded Wallet Manager

Implements the Prefunded Wallet Architecture (Whitepaper §6.2) and
Institutional Custody Model (§6.3).

Architecture:
  Master PQ Wallet
    ├── Sub-Wallet A (Operations) — budget: 1000, daily: 100, scope: transfer
    ├── Sub-Wallet B (Trading)    — budget: 5000, daily: 500, scope: swap
    ├── Sub-Wallet C (Staking)    — budget: 50k,  daily: N/A, scope: stake
    └── Sub-Wallet D (Bridge)     — budget: 10k,  daily: 2000, scope: bridge

Key Properties:
  - Master Control: only master wallet can create/destroy/freeze sub-wallets
  - Budget Limits: total and optional daily spending caps
  - Scope Restrictions: bitmask (transfer, swap, stake, bridge)
  - Delegated Keys: each sub-wallet has own Dilithium keypair
  - Freeze/Reclaim: master can freeze instantly and reclaim funds
"""

import time
from dataclasses import dataclass, field
from decimal import Decimal
from enum import IntFlag
from typing import Dict, List, Optional, Tuple

from ..crypto.pq.dilithium import PQPublicKey


# ═══════════════════════════════════════════════════════════════════════
# SPENDING SCOPE
# ═══════════════════════════════════════════════════════════════════════

class SpendingScope(IntFlag):
    """
    Bitmask for allowed sub-wallet operations.
    Matches Whitepaper §6.2 scope field.
    """
    NONE     = 0
    TRANSFER = 1    # Basic token transfers
    SWAP     = 2    # Exchange/DEX operations
    STAKE    = 4    # Staking deposits/withdrawals
    BRIDGE   = 8    # Cross-chain bridge operations
    ALL      = 15   # TRANSFER | SWAP | STAKE | BRIDGE


# ═══════════════════════════════════════════════════════════════════════
# SPENDING POLICY
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class SpendingPolicy:
    """
    Spending constraints for a sub-wallet.

    Attributes:
        total_budget: Maximum total spend over lifetime (in QRDX)
        daily_limit: Maximum daily spend (Decimal('0') = unlimited)
        allowed_scopes: Bitmask of allowed operation types
    """
    total_budget: Decimal
    daily_limit: Decimal = Decimal('0')  # 0 = unlimited
    allowed_scopes: SpendingScope = SpendingScope.ALL

    def __post_init__(self):
        if self.total_budget < 0:
            raise ValueError(f"total_budget cannot be negative: {self.total_budget}")
        if self.daily_limit < 0:
            raise ValueError(f"daily_limit cannot be negative: {self.daily_limit}")

    def is_scope_allowed(self, scope: SpendingScope) -> bool:
        """Check if a spending scope is allowed by this policy."""
        return bool(self.allowed_scopes & scope)

    def to_dict(self) -> Dict:
        return {
            "total_budget": str(self.total_budget),
            "daily_limit": str(self.daily_limit),
            "allowed_scopes": int(self.allowed_scopes),
        }


# ═══════════════════════════════════════════════════════════════════════
# AUTO-REFILL RULE
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AutoRefillRule:
    """
    Automatic refill configuration for a sub-wallet.

    When balance drops below `trigger_below`, refill to `refill_to` from master.

    Attributes:
        trigger_below: Refill when balance drops below this (QRDX)
        refill_to: Target balance after refill (QRDX)
        enabled: Whether the rule is active
    """
    trigger_below: Decimal
    refill_to: Decimal
    enabled: bool = True

    def __post_init__(self):
        if self.trigger_below < 0:
            raise ValueError("trigger_below must be non-negative")
        if self.refill_to < self.trigger_below:
            raise ValueError("refill_to must be >= trigger_below")

    def needs_refill(self, current_balance: Decimal) -> bool:
        """Check if a refill is needed."""
        return self.enabled and current_balance < self.trigger_below

    def refill_amount(self, current_balance: Decimal) -> Decimal:
        """Calculate how much to refill."""
        if not self.needs_refill(current_balance):
            return Decimal('0')
        return self.refill_to - current_balance


# ═══════════════════════════════════════════════════════════════════════
# SUB-WALLET
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class SubWallet:
    """
    A prefunded sub-wallet controlled by a master PQ wallet.

    Attributes:
        address: Unique address for this sub-wallet
        name: Human-readable name
        delegate_key: Dilithium public key for this sub-wallet's signing
        policy: Spending constraints
        balance: Current balance (QRDX)
        spent_total: Lifetime total spent (QRDX)
        spent_today: Amount spent in current day (QRDX)
        last_reset_day: Day number of last daily reset (unix_timestamp // 86400)
        frozen: If True, all spending is blocked
        auto_refill: Optional auto-refill configuration
    """
    address: str
    name: str
    delegate_key: PQPublicKey
    policy: SpendingPolicy
    balance: Decimal = Decimal('0')
    spent_total: Decimal = Decimal('0')
    spent_today: Decimal = Decimal('0')
    last_reset_day: int = 0
    frozen: bool = False
    auto_refill: Optional[AutoRefillRule] = None

    def _reset_daily_if_needed(self, current_day: int) -> None:
        """Reset daily spending if a new day has started."""
        if current_day > self.last_reset_day:
            self.spent_today = Decimal('0')
            self.last_reset_day = current_day

    def check_spending_allowed(
        self,
        amount: Decimal,
        scope: SpendingScope,
        current_timestamp: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Check if a spending operation is allowed.

        Args:
            amount: Amount to spend (QRDX)
            scope: Type of operation
            current_timestamp: Unix timestamp (defaults to now)

        Returns:
            (allowed, reason) tuple
        """
        if self.frozen:
            return False, "Sub-wallet is frozen"

        if not self.policy.is_scope_allowed(scope):
            return False, f"Operation scope {scope.name} not allowed by policy"

        if amount <= 0:
            return False, "Amount must be positive"

        if amount > self.balance:
            return False, f"Insufficient balance: have {self.balance}, need {amount}"

        if self.spent_total + amount > self.policy.total_budget:
            return False, (
                f"Would exceed total budget: spent {self.spent_total} + {amount} "
                f"> budget {self.policy.total_budget}"
            )

        if self.policy.daily_limit > 0:
            ts = current_timestamp if current_timestamp is not None else int(time.time())
            current_day = ts // 86400
            self._reset_daily_if_needed(current_day)

            if self.spent_today + amount > self.policy.daily_limit:
                return False, (
                    f"Would exceed daily limit: spent today {self.spent_today} + {amount} "
                    f"> daily limit {self.policy.daily_limit}"
                )

        return True, "OK"

    def record_spend(
        self,
        amount: Decimal,
        current_timestamp: Optional[int] = None,
    ) -> None:
        """
        Record a successful spend.

        Args:
            amount: Amount spent
            current_timestamp: Unix timestamp
        """
        ts = current_timestamp if current_timestamp is not None else int(time.time())
        current_day = ts // 86400
        self._reset_daily_if_needed(current_day)

        self.balance -= amount
        self.spent_total += amount
        self.spent_today += amount

    def to_dict(self) -> Dict:
        return {
            "address": self.address,
            "name": self.name,
            "delegate_key": self.delegate_key.to_hex(),
            "policy": self.policy.to_dict(),
            "balance": str(self.balance),
            "spent_total": str(self.spent_total),
            "spent_today": str(self.spent_today),
            "frozen": self.frozen,
        }


# ═══════════════════════════════════════════════════════════════════════
# PREFUNDED WALLET MANAGER
# ═══════════════════════════════════════════════════════════════════════

class PrefundedWalletManager:
    """
    Manages prefunded sub-wallets controlled by a master PQ wallet.

    Only the master wallet address can create, fund, freeze, or reclaim
    sub-wallets. Each sub-wallet has its own Dilithium delegate key for
    independent transaction signing.
    """

    def __init__(self, master_address: str, master_pubkey: PQPublicKey):
        """
        Initialize prefunded wallet manager.

        Args:
            master_address: PQ address of the master wallet
            master_pubkey: Dilithium public key of the master wallet
        """
        self.master_address = master_address
        self.master_pubkey = master_pubkey
        self._sub_wallets: Dict[str, SubWallet] = {}

    @property
    def sub_wallet_count(self) -> int:
        return len(self._sub_wallets)

    def create_sub_wallet(
        self,
        address: str,
        name: str,
        delegate_key: PQPublicKey,
        policy: SpendingPolicy,
        initial_balance: Decimal = Decimal('0'),
        auto_refill: Optional[AutoRefillRule] = None,
    ) -> SubWallet:
        """
        Create a new sub-wallet.

        Args:
            address: Unique address for the sub-wallet
            name: Human-readable name
            delegate_key: Dilithium key for this sub-wallet
            policy: Spending constraints
            initial_balance: Starting balance (funded from master)
            auto_refill: Optional auto-refill configuration

        Returns:
            Created SubWallet

        Raises:
            ValueError: If address already exists
        """
        if address in self._sub_wallets:
            raise ValueError(f"Sub-wallet already exists at {address}")

        wallet = SubWallet(
            address=address,
            name=name,
            delegate_key=delegate_key,
            policy=policy,
            balance=initial_balance,
            auto_refill=auto_refill,
        )
        self._sub_wallets[address] = wallet
        return wallet

    def get_sub_wallet(self, address: str) -> Optional[SubWallet]:
        """Get sub-wallet by address."""
        return self._sub_wallets.get(address)

    def list_sub_wallets(self) -> List[SubWallet]:
        """List all sub-wallets."""
        return list(self._sub_wallets.values())

    def freeze_sub_wallet(self, address: str) -> None:
        """
        Freeze a sub-wallet (master only).

        Frozen wallets cannot spend. Unfreezing requires a new call.
        """
        wallet = self._sub_wallets.get(address)
        if wallet is None:
            raise ValueError(f"Sub-wallet not found: {address}")
        wallet.frozen = True

    def unfreeze_sub_wallet(self, address: str) -> None:
        """Unfreeze a previously frozen sub-wallet."""
        wallet = self._sub_wallets.get(address)
        if wallet is None:
            raise ValueError(f"Sub-wallet not found: {address}")
        wallet.frozen = False

    def reclaim_funds(self, address: str) -> Decimal:
        """
        Reclaim all funds from a sub-wallet back to master.

        Freezes the wallet and returns the reclaimed amount.

        Args:
            address: Sub-wallet address

        Returns:
            Amount reclaimed (QRDX)
        """
        wallet = self._sub_wallets.get(address)
        if wallet is None:
            raise ValueError(f"Sub-wallet not found: {address}")

        reclaimed = wallet.balance
        wallet.balance = Decimal('0')
        wallet.frozen = True
        return reclaimed

    def fund_sub_wallet(self, address: str, amount: Decimal) -> None:
        """
        Add funds to a sub-wallet from master.

        Args:
            address: Sub-wallet address
            amount: Amount to add (QRDX)
        """
        if amount <= 0:
            raise ValueError("Fund amount must be positive")

        wallet = self._sub_wallets.get(address)
        if wallet is None:
            raise ValueError(f"Sub-wallet not found: {address}")

        wallet.balance += amount

    def destroy_sub_wallet(self, address: str) -> Decimal:
        """
        Destroy a sub-wallet, reclaiming all remaining funds.

        Args:
            address: Sub-wallet address

        Returns:
            Amount reclaimed
        """
        wallet = self._sub_wallets.get(address)
        if wallet is None:
            raise ValueError(f"Sub-wallet not found: {address}")

        reclaimed = wallet.balance
        del self._sub_wallets[address]
        return reclaimed

    def check_auto_refills(self) -> List[Tuple[str, Decimal]]:
        """
        Check all sub-wallets for auto-refill triggers.

        Returns:
            List of (address, refill_amount) for wallets needing refill
        """
        refills = []
        for addr, wallet in self._sub_wallets.items():
            if wallet.auto_refill and not wallet.frozen:
                amount = wallet.auto_refill.refill_amount(wallet.balance)
                if amount > 0:
                    refills.append((addr, amount))
        return refills

    def execute_auto_refills(self, master_balance: Decimal) -> List[Tuple[str, Decimal]]:
        """
        Execute pending auto-refills from master balance.

        Args:
            master_balance: Available master wallet balance

        Returns:
            List of (address, amount) actually refilled
        """
        pending = self.check_auto_refills()
        executed = []
        remaining = master_balance

        for addr, amount in pending:
            if amount <= remaining:
                self.fund_sub_wallet(addr, amount)
                remaining -= amount
                executed.append((addr, amount))

        return executed

    def total_sub_wallet_balance(self) -> Decimal:
        """Total balance across all sub-wallets."""
        return sum(w.balance for w in self._sub_wallets.values())

    def to_dict(self) -> Dict:
        return {
            "master_address": self.master_address,
            "sub_wallets": {
                addr: w.to_dict() for addr, w in self._sub_wallets.items()
            },
        }
