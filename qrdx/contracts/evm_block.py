"""
EVM block-body codec (E-D2).

The account/EVM analog of the exchange block-body codec
(`qrdx.exchange.block_processor`). EVM transactions ride in a dedicated,
backward-compatible block-body section:

    block["evm_transactions"] = ["0x<raw rlp>", ...]

in the proposer's canonical order (`EVMMempool.select_for_block`). A block with
no EVM activity simply omits the key. These helpers are the wire codec the
proposer (E-D2) and importing nodes (E-D3) will share; they do NOT execute
transactions or touch live block production.

Because an EVM transaction is already a fully self-describing, signed RLP blob,
its wire form is just the raw hex string — encode/decode are validating
pass-throughs. Authenticity survives the round trip intrinsically: the sender is
recovered from the signature on the far side (see `parse_eth_raw_tx`).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

BLOCK_EVM_TXS_KEY = "evm_transactions"


def _is_hex_str(s: Any) -> bool:
    if not isinstance(s, str) or not s:
        return False
    body = s[2:] if s.startswith("0x") else s
    if not body:
        return False
    try:
        bytes.fromhex(body)
        return True
    except ValueError:
        return False


def encode_evm_txs(raw_txs: List[str]) -> List[str]:
    """
    Encode an ordered list of raw EVM transactions for the block body.

    Order is preserved exactly (consensus-relevant — the proposer's canonical
    selection order). Each entry must be a hex string; non-hex entries are
    rejected so a malformed section never reaches the body.
    """
    out: List[str] = []
    for tx in raw_txs:
        if not _is_hex_str(tx):
            raise ValueError(f"EVM tx is not a hex string: {tx!r}")
        out.append(tx if tx.startswith("0x") else "0x" + tx)
    return out


def decode_evm_txs(items: Optional[List[str]]) -> List[str]:
    """Decode the block-body EVM section. Missing/empty ⇒ empty list."""
    if not items:
        return []
    return [tx if tx.startswith("0x") else "0x" + tx for tx in items if _is_hex_str(tx)]


def evm_txs_canonical_bytes(raw_txs: List[str]) -> bytes:
    """
    Deterministic digest of the EVM section, for hashing / equality.

    Uses each transaction's keccak hash in order, so any reordering or mutation
    changes the result. BLAKE3 per Whitepaper §3.6.
    """
    import blake3
    from eth_hash.auto import keccak
    from eth_utils import decode_hex

    h = blake3.blake3()
    for tx in raw_txs:
        h.update(keccak(decode_hex(tx if tx.startswith("0x") else "0x" + tx)))
    return h.digest(length=32)


def extract_evm_transactions_from_dict(block: Dict[str, Any]) -> List[str]:
    """
    Recover the EVM section from a serialized block dict (the wire form).

    Reads ``block[BLOCK_EVM_TXS_KEY]``; absent ⇒ empty list. Counterpart of the
    exchange `extract_exchange_transactions_from_dict`.
    """
    if not isinstance(block, dict):
        return []
    return decode_evm_txs(block.get(BLOCK_EVM_TXS_KEY))
