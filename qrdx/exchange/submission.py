"""
Submitting an exchange transaction — the one write path shared by the REST endpoint, the
``exchange_sendTransaction`` JSON-RPC method and the CLI wallet.

Admission (PQ signature + sender binding, nonce window, dedup, capacity) is the mempool's. This
adds the wire handling — a transaction may arrive as a JSON object or its string form
(``ExchangeTransaction.to_hex()`` is JSON) — and **gossip**: a newly admitted transaction is
forwarded to every peer, which admits and forwards it in turn, so whichever validator proposes
next can include it. Echoes stop at the first node that already holds the transaction
(``duplicate``) or has seen its nonce consumed (``nonce too low``), so the flood terminates.

``signing_payload`` serves wallets that do not run this codebase: the bytes a sender signs
contain Python's JSON rendering of the params, which is easy to get subtly wrong elsewhere, so
the node returns the exact bytes (and the resulting transaction hash) for the fields given.
"""
from __future__ import annotations

import asyncio
import json
import logging
from decimal import Decimal
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Tuple

from .transactions import ExchangeOpType, ExchangeTransaction

logger = logging.getLogger(__name__)


def _op(value) -> ExchangeOpType:
    if isinstance(value, ExchangeOpType):
        return value
    if isinstance(value, str) and not value.strip().isdigit():
        return ExchangeOpType[value.strip().upper()]
    return ExchangeOpType(int(value))


def parse_exchange_tx(tx: Any) -> ExchangeTransaction:
    """An ExchangeTransaction from an object, a dict, or the JSON string ``to_hex()`` makes.
    ``op_type`` may be the number or the name ("PERP_ORDER"); ``signature`` and
    ``public_key`` are hex."""
    if isinstance(tx, ExchangeTransaction):
        return tx
    if isinstance(tx, (bytes, bytearray)):
        tx = tx.decode()
    if isinstance(tx, str):
        tx = json.loads(tx)
    if not isinstance(tx, dict):
        raise ValueError("an exchange transaction is a JSON object")
    data = dict(tx)
    data["op_type"] = int(_op(data.get("op_type")))
    for key in ("signature", "public_key"):
        if isinstance(data.get(key), str):
            data[key] = data[key].removeprefix("0x")
    return ExchangeTransaction.from_dict(data)


def signing_payload(fields: Dict[str, Any]) -> Dict[str, Any]:
    """The exact bytes a sender must sign for these fields, the hash the transaction will have,
    and the normalized unsigned transaction to submit once ``signature`` and ``public_key``
    (both hex) are added."""
    unsigned = {k: v for k, v in dict(fields).items() if k not in ("signature", "public_key")}
    unsigned.setdefault("gas_limit", 100_000)
    from .. import constants
    unsigned.setdefault("gas_price", str(constants.EXCHANGE_MIN_GAS_PRICE_WEI))   # wei per gas
    tx = parse_exchange_tx(unsigned)
    body = tx.to_dict()
    for key in ("signature", "public_key", "timestamp", "tx_hash"):
        body.pop(key, None)
    return {"signing_bytes": tx.signing_bytes().hex(), "tx_hash": tx.tx_hash(), "tx": body}


class ExchangeSubmitter:
    """Admit to the local exchange mempool and gossip what is new."""

    def __init__(self, get_mempool: Callable[[], Any],
                 get_peer_urls: Callable[[], Iterable[str]],
                 forward: Callable[[str, Dict[str, Any]], Awaitable[Any]]):
        self._get_mempool = get_mempool
        self._get_peer_urls = get_peer_urls
        self._forward = forward

    async def submit(self, tx: Any, propagated: bool = False) -> Tuple[bool, str, Optional[str]]:
        """Returns (ok, error, tx_hash). Re-submitting a transaction the mempool already holds
        is not an error (it is idempotent) and is not gossiped again."""
        try:
            tx = parse_exchange_tx(tx)
        except Exception as e:
            return False, f"malformed exchange tx: {e}", None
        tx_hash = tx.tx_hash()
        ok, err = self._get_mempool().admit(tx)
        if not ok:
            if err.startswith("duplicate"):
                return True, "", tx_hash
            return False, err, None
        asyncio.ensure_future(self._gossip(tx.to_dict(), origin="peer" if propagated else "local"))
        return True, "", tx_hash

    async def _gossip(self, tx_dict: Dict[str, Any], origin: str) -> None:
        try:
            urls = [u for u in self._get_peer_urls() if u]
        except Exception as e:
            logger.debug("exchange gossip: no peer list: %s", e)
            return
        for url in urls:
            try:
                await self._forward(url, tx_dict)
            except Exception as e:
                logger.debug("exchange gossip to %s failed: %s", url, e)
