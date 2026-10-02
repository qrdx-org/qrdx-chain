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


# Intrinsic gas for the legacy/EIP-155 envelope (Ethereum's own schedule). The PQ
# envelope has its own, larger floor in qrdx.transactions.pq_tx.
_LEGACY_BASE_GAS = 21_000
_LEGACY_CREATE_GAS = 32_000
_GAS_TXDATA_ZERO = 4
_GAS_TXDATA_NONZERO = 16


def intrinsic_gas_legacy(data: bytes, is_create: bool = False) -> int:
    """
    Minimum gas a legacy transaction must pay before execution begins.

    This executor runs py-evm's ``apply_message``, which does no transaction-level
    gas accounting (that lives in ``apply_transaction``) — so for a plain
    EOA-to-EOA transfer the VM reports ``gas_used == 0``. Without this floor a
    native transfer would be entirely free, which is both wrong and a spam vector.
    """
    gas = _LEGACY_BASE_GAS + (_LEGACY_CREATE_GAS if is_create else 0)
    for byte in data or b"":
        gas += _GAS_TXDATA_ZERO if byte == 0 else _GAS_TXDATA_NONZERO
    return gas


async def verify_delegated_spend(db, raw_tx_hex: str) -> Tuple[bool, str]:
    """
    Authorise a delegated spend: may the signer move value out of ``on_behalf_of``?

    Only system wallets are delegable, and only to their registered controller (a PQ
    address or an m-of-n multisig). The registry is the genesis-populated
    ``system_wallets`` table, which every node holds identically — so admission and block
    import reach the same verdict, and the decision is deterministic.

    Returns ``(True, "")`` immediately for an ordinary (non-delegated) transaction, so
    callers can apply it unconditionally.

    **Deliberately async and db-backed rather than a module-level cache.** A cache would
    have a load-order failure mode — and because this check FAILS CLOSED, an unloaded
    cache would silently refuse every delegated spend. Reading the table is cheap and has
    no such state.

    Fails closed on any error: a delegated spend is exactly the operation that must never
    be waved through on a check that did not run.
    """
    from eth_utils import decode_hex

    from ..transactions.pq_tx import PQ_TX_TYPE, decode_pq_tx

    try:
        raw = decode_hex(raw_tx_hex)
    except Exception:
        return True, ""          # malformed hex is the parser's business, not ours
    if not raw or raw[0] != PQ_TX_TYPE:
        return True, ""          # legacy envelope cannot delegate

    try:
        tx = decode_pq_tx(raw)
    except Exception:
        return True, ""          # structural failure is the parser's business
    if not tx.is_delegated():
        return True, ""

    source, signer = tx.spend_from(), tx.sender()
    try:
        cur = await db.connection.execute(
            "SELECT controller_address FROM system_wallets WHERE LOWER(address) = LOWER(?)",
            (source,))
        row = await cur.fetchone()
    except Exception as e:
        return False, f"system-wallet registry unreadable ({e})"

    if not row:
        # Also accept the registry's display-address form: system wallets are recorded
        # under the address genesis created them with, which may be a 0xPQ form whose
        # account id is what the transaction names.
        try:
            from ..crypto.account_id import to_account_id
            cur = await db.connection.execute("SELECT address, controller_address FROM system_wallets")
            row = None
            for addr, controller in await cur.fetchall():
                try:
                    if to_account_id(addr) == source:
                        row = (controller,)
                        break
                except ValueError:
                    continue
        except Exception as e:
            return False, f"system-wallet registry unreadable ({e})"

    if not row:
        return False, f"{source[:20]} is not a system wallet"

    controller = row[0]
    try:
        from ..crypto.account_id import to_account_id
        authorised = to_account_id(controller) == signer
    except ValueError:
        authorised = str(controller).lower() == signer.lower()

    if not authorised:
        return False, (f"signer {signer[:20]} is not the controller of {source[:20]} "
                       f"(controller {str(controller)[:20]})")
    return True, ""


def _parse_pq_raw_tx(raw_tx: bytes) -> Dict[str, object]:
    """
    Decode **and authenticate** a type-0x51 post-quantum transaction.

    Returns the same dict shape as a legacy transaction, with ``sender`` set to the
    canonical 20-byte account id derived from the embedded Dilithium public key.
    Because that id is 20 bytes, every downstream consumer — mempool, executor,
    EVM, receipts — treats it exactly like a secp256k1 sender.

    Authentication happens HERE, not later, because this function is the choke
    point ``apply_block_evm_section`` uses to authenticate a block's whole EVM
    section before touching state. A legacy tx authenticates implicitly (the
    sender IS whatever the signature recovers to); a PQ tx must therefore have its
    signature checked explicitly at the same point, or a proposer could smuggle an
    unsigned transaction spending someone else's account.
    """
    from eth_utils import encode_hex
    from eth_hash.auto import keccak

    from ..transactions.pq_tx import decode_pq_tx, PQ_TX_TYPE

    try:
        tx = decode_pq_tx(raw_tx)
    except Exception as e:
        raise ValueError(f"malformed PQ transaction: {e}")

    if not tx.verify():
        raise ValueError("PQ signature verification failed")

    # Intrinsic gas is a VALIDITY rule, not a revert condition (as in Ethereum): a
    # transaction supplying less than its floor is invalid, so a block carrying one
    # is rejected outright rather than executing it as a revert. Raising here —
    # inside the shared authentication choke point — gets that for free on both the
    # mempool and the block-import path.
    floor = tx.intrinsic_gas()
    if tx.gas_limit < floor:
        raise ValueError(
            f"intrinsic gas too low: gas_limit {tx.gas_limit} < required {floor} "
            f"(PQ envelope is {len(tx.public_key) + len(tx.signature)} bytes)"
        )

    return {
        "sender": tx.sender(),
        "spend_from": tx.spend_from(),
        "nonce": tx.nonce,
        "to": encode_hex(tx.to) if tx.to else None,
        "value": tx.value,
        "data": tx.data,
        "gas": tx.gas_limit,
        "gas_price": tx.gas_price,
        "chain_id": tx.chain_id or None,
        "tx_hash": encode_hex(keccak(raw_tx)),
        "tx_type": PQ_TX_TYPE,
        "intrinsic_gas": tx.intrinsic_gas(),
        "pq_address": tx.pq_address(),
    }


def parse_eth_raw_tx(raw_tx_hex: str) -> Dict[str, object]:
    """
    Decode a signed transaction and establish its sender.

    Handles two envelopes, both of which end up with a 20-byte sender:

      * **legacy / EIP-155** — sender recovered from ``(v, r, s)``.
      * **type 0x51 (PQ)** — sender derived from an embedded ML-DSA-65 public key,
        signature verified here (see ``_parse_pq_raw_tx``).

    Returns a dict: ``sender`` (0x-hex), ``nonce``, ``to`` (0x-hex or None),
    ``value`` (wei int), ``data`` (bytes), ``gas``, ``gas_price``, ``chain_id``,
    ``tx_hash`` (0x-hex, keccak of the raw bytes), and ``tx_type``.

    Raises ValueError on malformed input, an unsupported transaction type, or a
    signature that cannot be recovered / verified.
    """
    from eth_utils import decode_hex, encode_hex
    from eth_keys import keys
    from eth_hash.auto import keccak
    import rlp

    from ..transactions.pq_tx import PQ_TX_TYPE

    try:
        raw_tx = decode_hex(raw_tx_hex)
    except Exception as e:
        raise ValueError(f"malformed hex: {e}")
    if not raw_tx:
        raise ValueError("empty transaction")

    # Typed transactions (EIP-2718) start with a type byte < 0x80.
    if raw_tx[0] == PQ_TX_TYPE:
        return _parse_pq_raw_tx(raw_tx)
    if raw_tx[0] < 0x80:
        raise ValueError(
            f"unsupported typed transaction 0x{raw_tx[0]:02x} "
            f"(supported: legacy/EIP-155, 0x{PQ_TX_TYPE:02x} post-quantum)"
        )

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
        "tx_type": 0,
        "spend_from": encode_hex(sender),
        "intrinsic_gas": intrinsic_gas_legacy(data, is_create=not to_bytes),
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

        # A native token's address has no EVM code: a wallet's "send token" there would run as
        # a no-op that still costs gas while the tokens never move (qrdx/exchange/erc20_view.py).
        try:
            from ..exchange.erc20_view import refuse_transaction_to
            refusal = refuse_transaction_to(parsed.get("to"))
        except Exception:
            refusal = None
        if refusal:
            return False, refusal, None

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

    def next_nonce(self, sender: str, base: int) -> int:
        """
        The next nonce a sender should sign, accounting for queued transactions.

        ``base`` is the sender's confirmed on-chain nonce. Walking the queued set
        upward from it gives the "pending" nonce every web3 client expects from
        ``eth_getTransactionCount(addr, "pending")`` — without it a client that
        sends twice before the next block signs the same nonce twice and its second
        transaction is rejected as already queued.
        """
        queued = {
            int(self._txs[h]["nonce"])
            for h in self._by_sender.get(str(sender).lower(), set())
        }
        nonce = base
        while nonce in queued:
            nonce += 1
        return nonce

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
