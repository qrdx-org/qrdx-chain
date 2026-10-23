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

from .block_processor import verify_exchange_tx
from .transactions import ExchangeOpType, ExchangeTransaction

logger = logging.getLogger(__name__)

# Defaults (DoS resistance + bounded queuing)
DEFAULT_MAX_MEMPOOL = 8192  # total admitted txs
DEFAULT_MAX_PER_SENDER = 64  # queued txs per sender
DEFAULT_MAX_NONCE_GAP = 64  # how far ahead of expected a nonce may be

# nonce lane (``ExchangeTransaction.nonce_key``: the account, or account|signer) -> next nonce
NonceProvider = Callable[[str], int]
# why a transaction's signer may not act for its sender ("" if it may)
SignerCheck = Callable[[ExchangeTransaction], str]


def _default_nonce_provider(address: str) -> int:
    from .state_manager import ExchangeStateManager

    return ExchangeStateManager.get_instance().get_nonce(address)


def _default_signer_check(tx: ExchangeTransaction) -> str:
    from .state_manager import ExchangeStateManager

    return ExchangeStateManager.get_instance().signer_error(tx)


def _default_vote_seq_provider(address: str) -> int:
    from .state_manager import ExchangeStateManager

    return ExchangeStateManager.get_instance().oracle_vote_seq(address)


class ExchangeMempool:
    """In-memory admission queue for exchange transactions."""

    def __init__(
        self,
        max_size: int = DEFAULT_MAX_MEMPOOL,
        max_per_sender: int = DEFAULT_MAX_PER_SENDER,
        max_nonce_gap: int = DEFAULT_MAX_NONCE_GAP,
        nonce_provider: Optional[NonceProvider] = None,
        vote_seq_provider: Optional[NonceProvider] = None,
        signer_check: Optional[SignerCheck] = None,
    ):
        self.max_size = max_size
        self.max_per_sender = max_per_sender
        self.max_nonce_gap = max_nonce_gap
        self._nonce_provider = nonce_provider or _default_nonce_provider
        self._vote_seq = vote_seq_provider or _default_vote_seq_provider
        self._signer_check = signer_check or _default_signer_check
        self._txs: Dict[str, ExchangeTransaction] = {}  # tx_hash -> tx
        # nonce lane -> {tx_hash}: the account's own transactions, and each agent's (or a
        # sub-account master's) for it, are separate nonce sequences (``nonce_key``).
        self._by_sender: Dict[str, Set[str]] = {}
        # Oracle votes: their own lane, the newest per voter. A vote's nonce is its own
        # sequence (state_manager: not the account nonce), so it neither waits in a sender's
        # nonce run nor moves the validator's exchange nonce.
        self._votes: Dict[str, ExchangeTransaction] = {}  # voter (lower) -> tx

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
        # 1b. A gas price of at least the floor (whole wei) — execution refuses anything less.
        try:
            tx.validate_fee()
        except ValueError as e:
            return False, str(e)

        # More gas than a block may carry: it could never be included (docs/BLOCK_LIMITS.md).
        from ..constants import BLOCK_EXCHANGE_GAS_LIMIT

        if int(tx.gas_limit) > BLOCK_EXCHANGE_GAS_LIMIT:
            return False, (
                f"gas limit {tx.gas_limit} exceeds the block's exchange gas limit "
                f"{BLOCK_EXCHANGE_GAS_LIMIT}"
            )

        tx_hash = tx.tx_hash()

        if tx.op_type == ExchangeOpType.ORACLE_VOTE:
            return self._admit_vote(tx)

        # 1c. A signer acting for the account must be one it authorized now, and a key the
        #     account turned off signs nothing (execution checks again: either can change before
        #     the transaction runs).
        refused = self._signer_check(tx)
        if refused:
            return False, refused
        lane = tx.nonce_key()

        # 2. Replay / dedup.
        if tx_hash in self._txs:
            return False, "duplicate: transaction already in mempool"

        # 3. Capacity (global + per-sender). Exchange transactions are gossiped, so every node
        #    holds copies of transactions another validator has since included; those are
        #    stale once their nonce is consumed. Drop them before counting, or a busy sender
        #    (and eventually the whole pool) would be locked out by its own history.
        self._prune_sender(lane)
        if len(self._txs) >= self.max_size:
            self.prune_stale()
        if len(self._txs) >= self.max_size:
            return False, "mempool full"
        sender_hashes = self._by_sender.get(lane, set())
        if len(sender_hashes) >= self.max_per_sender:
            return False, "per-sender mempool limit reached"

        # 4. Nonce window.
        expected = self._nonce_provider(lane)
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
        self._by_sender.setdefault(lane, set()).add(tx_hash)
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
        return self.get(tx_hash) is not None

    def get(self, tx_hash: str) -> Optional[ExchangeTransaction]:
        tx = self._txs.get(tx_hash)
        if tx is None:
            tx = next((t for t in self._votes.values() if t.tx_hash() == tx_hash), None)
        return tx

    def size(self) -> int:
        return len(self._txs) + len(self._votes)

    def sender_txs(self, sender: str) -> List[ExchangeTransaction]:
        """All queued txs of a nonce lane (an account, or account|signer), ordered by nonce."""
        hashes = self._by_sender.get(sender, set())
        return sorted((self._txs[h] for h in hashes), key=lambda t: t.nonce)

    # ── Selection (canonical, deterministic) ───────────────────────────

    def _admit_vote(self, tx: ExchangeTransaction) -> Tuple[bool, str]:
        voter = tx.sender.lower()
        if tx.nonce <= self._vote_seq(voter):
            return False, f"oracle vote {tx.nonce} is not newer than the voter's last applied one"
        held = self._votes.get(voter)
        if held is not None:
            if held.tx_hash() == tx.tx_hash():
                return False, "duplicate: transaction already in mempool"
            if held.nonce >= tx.nonce:
                return False, "a newer oracle vote from this voter is already queued"
        self._votes[voter] = tx  # replaces the voter's older pending vote
        return True, ""

    def votes(self) -> List[ExchangeTransaction]:
        """Pending oracle votes newer than what each voter last had applied, by voter."""
        self._votes = {v: t for v, t in self._votes.items() if t.nonce > self._vote_seq(v)}
        return [self._votes[v] for v in sorted(self._votes)]

    def select_for_block(
        self, limit: int = 256, gas_limit: Optional[int] = None, min_price: int = 0
    ) -> List[ExchangeTransaction]:
        """
        Deterministically select an executable set for block inclusion.

        For each sender, include a *gap-free* run of nonces starting at the
        sender's expected next nonce (expected, expected+1, …). Senders are
        ordered by address and the runs concatenated, capped at ``limit`` operations and
        ``gas_limit`` declared gas (default ``BLOCK_EXCHANGE_GAS_LIMIT``, docs/BLOCK_LIMITS.md),
        offering at least ``min_price`` (the block's exchange base fee; oracle votes are exempt);
        a sender's run stops at the first operation that does not fit or pays too little.
        Oracle votes go first.

        The result is the canonical ordering every validator would compute from
        the same mempool contents + committed state — the basis for D2.
        """
        if gas_limit is None:
            from ..constants import BLOCK_EXCHANGE_GAS_LIMIT

            gas_limit = BLOCK_EXCHANGE_GAS_LIMIT
        self.prune_stale()
        selected: List[ExchangeTransaction] = []
        gas = 0
        for vote in self.votes():  # prices first
            if len(selected) >= limit or gas + int(vote.gas_limit) > gas_limit:
                break
            selected.append(vote)
            gas += int(vote.gas_limit)
        for sender in sorted(self._by_sender.keys()):
            by_nonce = {self._txs[h].nonce: self._txs[h] for h in self._by_sender[sender]}
            n = self._nonce_provider(sender)
            while n in by_nonce and len(selected) < limit:
                if gas + int(by_nonce[n].gas_limit) > gas_limit:
                    break
                if int(by_nonce[n].gas_price) < min_price:
                    break
                selected.append(by_nonce[n])
                gas += int(by_nonce[n].gas_limit)
                n += 1
            if len(selected) >= limit:
                break
        return selected

    # ── Removal (after inclusion / on revert) ──────────────────────────

    def remove(self, tx_hashes: List[str]) -> int:
        """Remove included/invalidated txs. Returns the number removed."""
        removed = 0
        hashes = set(tx_hashes)
        for voter in [v for v, t in self._votes.items() if t.tx_hash() in hashes]:
            del self._votes[voter]
            removed += 1
        for h in tx_hashes:
            tx = self._txs.pop(h, None)
            if tx is None:
                continue
            removed += 1
            lane = tx.nonce_key()
            s = self._by_sender.get(lane)
            if s is not None:
                s.discard(h)
                if not s:
                    del self._by_sender[lane]
        return removed

    def _prune_sender(self, sender: str) -> int:
        hashes = self._by_sender.get(sender)
        if not hashes:
            return 0
        expected = self._nonce_provider(sender)
        return self.remove([h for h in hashes if self._txs[h].nonce < expected])

    def prune_stale(self) -> int:
        """
        Drop txs whose nonce is now below the sender's expected nonce (e.g. a
        competing tx for that nonce was committed). Returns the number pruned.
        """
        import time as _time

        to_remove: List[str] = []
        now = _time.time()  # (local hygiene only: blocks judge expiry by their own time)
        for sender, hashes in list(self._by_sender.items()):
            expected = self._nonce_provider(sender)
            for h in hashes:
                tx = self._txs[h]
                expires = tx.expires_at() if hasattr(tx, "expires_at") else None
                if tx.nonce < expected or (expires is not None and float(expires) < now):
                    to_remove.append(h)
        return self.remove(to_remove)
