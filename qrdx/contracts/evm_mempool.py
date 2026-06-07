"""
EVM transaction mempool — admission gate for account-model (eth) transactions.

This is the EVM/account analog of ``qrdx.exchange.mempool.ExchangeMempool`` and
the first step (E-D1) of giving the account domain the same consensus integration
the exchange domain received (see docs/EVM_STATE_CONSENSUS_INTEGRATION.md §6).

Admission decides which signed EVM transactions are *eligible* to enter a block.
It does NOT execute them or include them in blocks (E-D2/E-D3) — keeping it
additive and independently testable.

Authentication is intrinsic to EVM transactions: the sender is *recovered* from
the ECDSA signature (you cannot produce a valid signature that recovers to a
victim's address without their key), so successful recovery binds the sender —
no separate signature check is needed (unlike exchange txs, whose sender is
declared and must be bound). Admission then enforces a nonce window, dedup, and
DoS caps.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

DEFAULT_MAX_MEMPOOL = 8192
DEFAULT_MAX_PER_SENDER = 64
DEFAULT_MAX_NONCE_GAP = 64

# address (0x-hex, lowercased) -> next expected account nonce
NonceProvider = Callable[[str], int]


def parse_eth_raw_tx(raw_tx_hex: str) -> Dict[str, object]:
    """
    Decode a signed legacy / EIP-155 RLP transaction and recover its sender.

    Returns a dict: ``sender`` (0x-hex), ``nonce``, ``to`` (0x-hex or None),
    ``value`` (wei int), ``data`` (bytes), ``gas``, ``gas_price``, ``chain_id``,
    and ``tx_hash`` (0x-hex, keccak of the raw bytes).

    Raises ValueError on malformed input, an unsupported (typed) transaction, or
    a signature that cannot be recovered.
    """
    from eth_utils import decode_hex, encode_hex
    from eth_keys import keys
    from eth_hash.auto import keccak
    import rlp

    try:
        raw_tx = decode_hex(raw_tx_hex)
    except Exception as e:
        raise ValueError(f"malformed hex: {e}")
    if not raw_tx:
        raise ValueError("empty transaction")
    # Typed transactions (EIP-2718) start with a type byte < 0x80; the node's
    # execution path only supports legacy/EIP-155 (9-field) txs.
    if raw_tx[0] < 0x80:
        raise ValueError("unsupported typed transaction (only legacy/EIP-155)")

    try:
        tx = rlp.decode(raw_tx)
    except Exception as e:
        raise ValueError(f"malformed RLP: {e}")
    if len(tx) != 9:
        raise ValueError(f"expected 9 RLP fields, got {len(tx)}")

    nonce = int.from_bytes(tx[0], "big") if tx[0] else 0
    gas_price = int.from_bytes(tx[1], "big") if tx[1] else 0
    gas = int.from_bytes(tx[2], "big") if tx[2] else 0
    to_bytes = tx[3]
    value = int.from_bytes(tx[4], "big") if tx[4] else 0
    data = tx[5]
    v_int = int.from_bytes(tx[6], "big") if tx[6] else 0
    r_int = int.from_bytes(tx[7], "big") if tx[7] else 0
    s_int = int.from_bytes(tx[8], "big") if tx[8] else 0

    if r_int == 0 or s_int == 0:
        raise ValueError("missing signature (r/s zero)")

    if v_int >= 35:  # EIP-155
        chain_id = (v_int - 35) // 2
        recovery_id = v_int - (chain_id * 2 + 35)
        unsigned = [tx[i] for i in range(6)] + [
            chain_id.to_bytes((chain_id.bit_length() + 7) // 8, "big"), b"", b"",
        ]
    else:  # pre-EIP-155
        chain_id = None
        recovery_id = v_int - 27
        unsigned = [tx[i] for i in range(6)]

    if recovery_id not in (0, 1):
        raise ValueError(f"invalid recovery id {recovery_id}")

    message_hash = keccak(rlp.encode(unsigned))
    try:
        sig = keys.Signature(r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big") + bytes([recovery_id]))
        pub = sig.recover_public_key_from_msg_hash(message_hash)
        sender = pub.to_canonical_address()
    except Exception as e:
        raise ValueError(f"signature recovery failed: {e}")

    return {
        "sender": encode_hex(sender),
        "nonce": nonce,
        "to": encode_hex(to_bytes) if to_bytes else None,
        "value": value,
        "data": data,
        "gas": gas,
        "gas_price": gas_price,
        "chain_id": chain_id,
        "tx_hash": encode_hex(keccak(raw_tx)),
    }


def _default_nonce_provider(address: str) -> int:
    """Next expected account nonce from the live EVM state (best-effort, 0)."""
    return 0


class EVMMempool:
    """In-memory admission queue for signed EVM (account-model) transactions."""

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
        # tx_hash -> {raw, sender, nonce}
        self._txs: Dict[str, Dict[str, object]] = {}
        self._by_sender: Dict[str, Set[str]] = {}

    # ── Admission ──────────────────────────────────────────────────────

    def admit(self, raw_tx_hex: str) -> Tuple[bool, str, Optional[str]]:
        """
        Attempt to admit a signed raw EVM transaction.

        Returns (ok, error, tx_hash). On success ``error`` is "" and ``tx_hash``
        is set. Never raises.
        """
        try:
            parsed = parse_eth_raw_tx(raw_tx_hex)
        except ValueError as e:
            return False, f"invalid evm tx: {e}", None

        tx_hash = parsed["tx_hash"]
        sender = str(parsed["sender"]).lower()
        nonce = int(parsed["nonce"])

        # Replay / dedup.
        if tx_hash in self._txs:
            return False, "duplicate: transaction already in mempool", None

        # Capacity (global + per-sender).
        if len(self._txs) >= self.max_size:
            return False, "mempool full", None
        sender_hashes = self._by_sender.get(sender, set())
        if len(sender_hashes) >= self.max_per_sender:
            return False, "per-sender mempool limit reached", None

        # Nonce window.
        expected = self._nonce_provider(sender)
        if nonce < expected:
            return False, f"nonce too low: {nonce} < expected {expected} (stale/replay)", None
        if nonce > expected + self.max_nonce_gap:
            return False, f"nonce too far ahead: {nonce} > expected {expected} + gap {self.max_nonce_gap}", None
        for h in sender_hashes:
            if int(self._txs[h]["nonce"]) == nonce:
                return False, f"nonce {nonce} already queued for sender", None

        self._txs[tx_hash] = {"raw": raw_tx_hex, "sender": sender, "nonce": nonce}
        self._by_sender.setdefault(sender, set()).add(tx_hash)
        return True, "", tx_hash

    # ── Queries ────────────────────────────────────────────────────────

    def contains(self, tx_hash: str) -> bool:
        return tx_hash in self._txs

    def size(self) -> int:
        return len(self._txs)

    def get_raw(self, tx_hash: str) -> Optional[str]:
        entry = self._txs.get(tx_hash)
        return str(entry["raw"]) if entry else None

    # ── Selection (canonical, deterministic) ───────────────────────────

    def select_for_block(self, limit: int = 256) -> List[str]:
        """
        Deterministically select executable raw txs for block inclusion.

        For each sender, include a gap-free run of nonces starting at the
        sender's expected next nonce; senders ordered by address; capped at
        ``limit``. Identical mempool + state ⇒ identical selection on every node.
        """
        selected: List[str] = []
        for sender in sorted(self._by_sender.keys()):
            by_nonce = {int(self._txs[h]["nonce"]): self._txs[h] for h in self._by_sender[sender]}
            n = self._nonce_provider(sender)
            while n in by_nonce and len(selected) < limit:
                selected.append(str(by_nonce[n]["raw"]))
                n += 1
            if len(selected) >= limit:
                break
        return selected

    # ── Removal / pruning ──────────────────────────────────────────────

    def remove(self, tx_hashes: List[str]) -> int:
        removed = 0
        for h in tx_hashes:
            entry = self._txs.pop(h, None)
            if entry is None:
                continue
            removed += 1
            s = self._by_sender.get(str(entry["sender"]))
            if s is not None:
                s.discard(h)
                if not s:
                    del self._by_sender[str(entry["sender"])]
        return removed

    def prune_stale(self) -> int:
        """Drop txs whose nonce is now below the sender's expected nonce."""
        to_remove: List[str] = []
        for sender, hashes in self._by_sender.items():
            expected = self._nonce_provider(sender)
            for h in hashes:
                if int(self._txs[h]["nonce"]) < expected:
                    to_remove.append(h)
        return self.remove(to_remove)
