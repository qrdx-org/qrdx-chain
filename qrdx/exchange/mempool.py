"""
Exchange mempool — admission gate for exchange transactions (Phase D1).

This is the first stage of consensus integration: it decides which exchange
transactions are *eligible* to enter a block. It does NOT include them in blocks
or execute them (that is Phase D2/D3) — keeping it additive and independently
testable.

Admission enforces, in order:
  1. **Authentication** — structural validity + a valid post-quantum signature
     bound to ``sender`` (via ``verify_exchange_tx``). Nothing unsigned or
     spoofed gets in.
  2. **Replay/dedup** — a transaction hash is admitted at most once; a
     ``(sender, nonce)`` pair cannot be queued twice.
  3. **Nonce window** — reject stale nonces (already consumed by committed
     state) and nonces too far ahead of the sender's expected next nonce.
  4. **Capacity** — global and per-sender caps for DoS resistance.

``select_for_block`` returns a deterministic, gap-free, per-sender-ordered set —
the canonical selection the proposer will use in D2. Determinism here is
consensus-relevant, so the ordering is fixed (sender address, then nonce).

The "expected next nonce" for a sender is supplied by an injectable
``nonce_provider`` (defaults to the live ``ExchangeStateManager`` singleton), so
the mempool is testable without any node or database.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional, Set, Tuple

from .transactions import ExchangeTransaction
from .block_processor import verify_exchange_tx

logger = logging.getLogger(__name__)

# Defaults (DoS resistance + bounded queuing)
DEFAULT_MAX_MEMPOOL = 8192       # total admitted txs
DEFAULT_MAX_PER_SENDER = 64      # queued txs per sender
DEFAULT_MAX_NONCE_GAP = 64       # how far ahead of expected a nonce may be

# address -> next expected nonce
NonceProvider = Callable[[str], int]


def _default_nonce_provider(address: str) -> int:
    from .state_manager import ExchangeStateManager
    return ExchangeStateManager.get_instance().get_nonce(address)


class ExchangeMempool:
    """In-memory admission queue for exchange transactions."""

    def __init__(
        self,
        max_size: int = DEFAULT_MAX_MEMPOOL,
        max_per_sender: int = DEFAULT_MAX_PER_SENDER,
        max_nonce_gap: int = DEFAULT_MAX_NONCE_GAP,
        nonce_provider: Optional[NonceProvider] = None,
    ):
        self.max_size = max_size
        self.max_per_sender = max_per_sender
        self.max_nonce_gap = max_nonce_gap
        self._nonce_provider = nonce_provider or _default_nonce_provider
        self._txs: Dict[str, ExchangeTransaction] = {}        # tx_hash -> tx
        self._by_sender: Dict[str, Set[str]] = {}             # sender -> {tx_hash}

    # ── Admission ──────────────────────────────────────────────────────

    def admit(self, tx: ExchangeTransaction) -> Tuple[bool, str]:
        """
        Attempt to admit a transaction. Returns (ok, error). ``error`` is empty
        on success. Never raises.
        """
        # 1. Authentication (structure + PQ signature + sender binding).
        ok, err = verify_exchange_tx(tx)
        if not ok:
            return False, err

        tx_hash = tx.tx_hash()

        # 2. Replay / dedup.
        if tx_hash in self._txs:
            return False, "duplicate: transaction already in mempool"

        # 3. Capacity (global + per-sender).
        if len(self._txs) >= self.max_size:
            return False, "mempool full"
        sender_hashes = self._by_sender.get(tx.sender, set())
        if len(sender_hashes) >= self.max_per_sender:
            return False, "per-sender mempool limit reached"

        # 4. Nonce window.
        expected = self._nonce_provider(tx.sender)
        if tx.nonce < expected:
            return False, f"nonce too low: {tx.nonce} < expected {expected} (stale/replay)"
        if tx.nonce > expected + self.max_nonce_gap:
            return False, (
                f"nonce too far ahead: {tx.nonce} > expected {expected} "
                f"+ gap {self.max_nonce_gap}"
            )
        # No nonce replacement in D1: one tx per (sender, nonce).
        for h in sender_hashes:
            if self._txs[h].nonce == tx.nonce:
                return False, f"nonce {tx.nonce} already queued for sender"

        # Admit.
        self._txs[tx_hash] = tx
        self._by_sender.setdefault(tx.sender, set()).add(tx_hash)
        return True, ""

    def admit_hex(self, hex_str: str) -> Tuple[bool, str, Optional[str]]:
        """Admit from wire form. Returns (ok, error, tx_hash|None)."""
        try:
            tx = ExchangeTransaction.from_hex(hex_str)
        except Exception as e:
            return False, f"malformed exchange tx: {e}", None
        ok, err = self.admit(tx)
        return ok, err, (tx.tx_hash() if ok else None)

    # ── Queries ────────────────────────────────────────────────────────

    def contains(self, tx_hash: str) -> bool:
        return tx_hash in self._txs

    def get(self, tx_hash: str) -> Optional[ExchangeTransaction]:
        return self._txs.get(tx_hash)

    def size(self) -> int:
        return len(self._txs)

    def sender_txs(self, sender: str) -> List[ExchangeTransaction]:
        """All queued txs for a sender, ordered by nonce."""
        hashes = self._by_sender.get(sender, set())
        return sorted((self._txs[h] for h in hashes), key=lambda t: t.nonce)

    # ── Selection (canonical, deterministic) ───────────────────────────

    def select_for_block(self, limit: int = 256) -> List[ExchangeTransaction]:
        """
        Deterministically select an executable set for block inclusion.

        For each sender, include a *gap-free* run of nonces starting at the
        sender's expected next nonce (expected, expected+1, …). Senders are
        ordered by address and the runs concatenated, capped at ``limit``.

        The result is the canonical ordering every validator would compute from
        the same mempool contents + committed state — the basis for D2.
        """
        selected: List[ExchangeTransaction] = []
        for sender in sorted(self._by_sender.keys()):
            by_nonce = {self._txs[h].nonce: self._txs[h] for h in self._by_sender[sender]}
            n = self._nonce_provider(sender)
            while n in by_nonce and len(selected) < limit:
                selected.append(by_nonce[n])
                n += 1
            if len(selected) >= limit:
                break
        return selected

    # ── Removal (after inclusion / on revert) ──────────────────────────

    def remove(self, tx_hashes: List[str]) -> int:
        """Remove included/invalidated txs. Returns the number removed."""
        removed = 0
        for h in tx_hashes:
            tx = self._txs.pop(h, None)
            if tx is None:
                continue
            removed += 1
            s = self._by_sender.get(tx.sender)
            if s is not None:
                s.discard(h)
                if not s:
                    del self._by_sender[tx.sender]
        return removed

    def prune_stale(self) -> int:
        """
        Drop txs whose nonce is now below the sender's expected nonce (e.g. a
        competing tx for that nonce was committed). Returns the number pruned.
        """
        to_remove: List[str] = []
        for sender, hashes in self._by_sender.items():
            expected = self._nonce_provider(sender)
            for h in hashes:
                if self._txs[h].nonce < expected:
                    to_remove.append(h)
        return self.remove(to_remove)
