"""
Submitting an exchange transaction — the one write path shared by the REST endpoint, the
``exchange_sendTransaction`` JSON-RPC method and the CLI wallet.

Admission (PQ signature + sender binding, nonce window, dedup, capacity) is the mempool's. This
adds the fee payer's balance: a transaction that pays gas is admitted only if its payer holds
``gas_limit × gas_price`` now (a block may carry only what its payer can pay for — chain-spec
feature ``exchange_inclusion``; the proposer judges the payer's whole share of a block again).
And the wire handling — a transaction may arrive as a JSON object or its string form
(``ExchangeTransaction.to_hex()`` is JSON) — and **gossip**: a newly admitted transaction is
forwarded to every peer, so whichever validator proposes next can include it. The node a wallet
submitted to pushes the transaction whole to its peers; a node that got it from a peer only
announces its hash (``exchange_announceTransactions``), and sends it to the peers that answer
that they lack it. Re-sending every transaction whole to every peer made each node receive each
one once from every peer: from four peers, three copies to parse for nothing
(docs/PERFORMANCE.md).

``signing_payload`` serves wallets that do not run this codebase: the bytes a sender signs
contain Python's JSON rendering of the params, which is easy to get subtly wrong elsewhere, so
the node returns the exact bytes (and the resulting transaction hash) for the fields given.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from decimal import Decimal
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from .transactions import ExchangeOpType, ExchangeTransaction

logger = logging.getLogger(__name__)

# The most transactions one gossip request carries (the RPC server's MAX_BATCH_SIZE).
GOSSIP_BATCH = 100
# The most hashes one announcement carries.
ANNOUNCE_BATCH = 4096
# Hashes of the transactions this node handled lately: an announcement of one is not answered.
SEEN_HASHES = 262_144


def _op(value) -> ExchangeOpType:
    if isinstance(value, ExchangeOpType):
        return value
    try:
        if isinstance(value, str) and not value.strip().isdigit():
            return ExchangeOpType[value.strip().upper()]
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise TypeError(value)
        return ExchangeOpType(int(value))
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"unknown operation type {value!r}") from None


def parse_exchange_tx(tx: Any) -> ExchangeTransaction:
    """An ExchangeTransaction from an object, a dict, or the JSON string ``to_hex()`` makes.
    ``op_type`` may be the number or the name ("PERP_ORDER"); ``signature`` and
    ``public_key`` are hex."""
    if isinstance(tx, ExchangeTransaction):
        return tx
    if isinstance(tx, (bytes, bytearray)):
        if tx[:1] == b"\x01":  # (the binary form: qrdx/exchange/wire.py)
            return ExchangeTransaction.from_wire(bytes(tx))
        tx = tx.decode()
    if isinstance(tx, str):
        if not tx.lstrip().startswith("{"):  # (the binary form's text)
            return ExchangeTransaction.from_any(tx)
        tx = json.loads(tx)
    if not isinstance(tx, dict):
        raise ValueError("an exchange transaction is a JSON object")
    data = dict(tx)
    data["op_type"] = int(_op(data.get("op_type")))
    for key in ("signature", "public_key"):
        if isinstance(data.get(key), str):
            data[key] = data[key].removeprefix("0x")
    return ExchangeTransaction.from_dict(data)


def free_action_error(tx: ExchangeTransaction) -> str:
    from .state_manager import ExchangeStateManager

    return ExchangeStateManager.get_instance().free_action_error(tx)


def signing_payload(fields: Dict[str, Any]) -> Dict[str, Any]:
    """The exact bytes a sender must sign for these fields, the hash the transaction will have,
    and the normalized unsigned transaction to submit once ``signature`` and ``public_key``
    (both hex) are added."""
    unsigned = {k: v for k, v in dict(fields).items() if k not in ("signature", "public_key")}
    unsigned.setdefault("gas_limit", 100_000)
    from .. import chain_spec, constants

    unsigned.setdefault("chain_id", chain_spec.active().chain_id)  # sign for this network
    if "gas_price" not in unsigned:
        # A trading operation its account may send free now goes in the free lane; anything else
        # offers the floor (wei per gas).
        unsigned["gas_price"] = "0"
        probe = parse_exchange_tx(unsigned)
        if not probe.free_eligible() or free_action_error(probe):
            unsigned["gas_price"] = str(constants.EXCHANGE_MIN_GAS_PRICE_WEI)
    tx = parse_exchange_tx(unsigned)
    body = tx.to_dict()
    for key in ("signature", "public_key", "timestamp", "tx_hash"):
        body.pop(key, None)
    return {"signing_bytes": tx.signing_bytes().hex(), "tx_hash": tx.tx_hash(), "tx": body}


class _Coalesced:
    """Balances read concurrently, read in one query: each call waits for the reads that arrived
    with it, then gets its own."""

    def __init__(self, get_many: Callable[[List[str]], Awaitable[Dict[str, Any]]]):
        self._get_many = get_many
        self._waiting: Dict[str, List["asyncio.Future[Any]"]] = {}
        self._reader: Optional[asyncio.Future] = None

    async def __call__(self, address: str) -> Any:
        future: "asyncio.Future[Any]" = asyncio.get_running_loop().create_future()
        self._waiting.setdefault(address, []).append(future)
        if self._reader is None or self._reader.done():
            self._reader = asyncio.ensure_future(self._read())
        return await future

    async def _read(self) -> None:
        while self._waiting:
            await asyncio.sleep(0)
            waiting, self._waiting = self._waiting, {}
            try:
                found = await self._get_many(list(waiting))
            except Exception as e:
                for futures in waiting.values():
                    for f in futures:
                        if not f.done():
                            f.set_exception(e)
                continue
            for address, futures in waiting.items():
                for f in futures:
                    if not f.done():
                        f.set_result(found.get(address, 0))


class ExchangeSubmitter:
    """Admit to the local exchange mempool and gossip what is new."""

    def __init__(
        self,
        get_mempool: Callable[[], Any],
        get_peer_urls: Callable[[], Iterable[str]],
        forward: Callable[[str, Dict[str, Any]], Awaitable[Any]],
        get_balance: Optional[Callable[[str], Awaitable[Any]]] = None,
        forward_batch: Optional[Callable[[str, List[Dict[str, Any]]], Awaitable[Any]]] = None,
        gossip_interval: float = 0.05,
        announce: Optional[Callable[[str, List[str]], Awaitable[Optional[List[str]]]]] = None,
        get_balances: Optional[Callable[[List[str]], Awaitable[Dict[str, Any]]]] = None,
        forward_batch_to_all: Optional[
            Callable[[List[str], List[Dict[str, Any]]], Awaitable[Any]]
        ] = None,
        yield_to: Optional[Callable[[], Awaitable[None]]] = None,
    ):
        self._get_mempool = get_mempool
        self._get_peer_urls = get_peer_urls
        self._forward = forward
        # An account's QRDX now (account_state); None: the payer's balance is not checked.
        # ``get_balances`` reads many at once: what arrives together (a peer's gossip batch,
        # a hundred calls at once) is read in one query, not one database round trip each.
        self._get_balance = get_balance
        if get_balance is not None and get_balances is not None:
            self._get_balance = _Coalesced(get_balances)
        self._verify_queue: List[Tuple[ExchangeTransaction, "asyncio.Future[None]"]] = []
        self._verifier: Optional[asyncio.Future] = None
        # The native peer transport's relay (qrdx/node/netd.py), when it runs: what is admitted
        # goes to peers through it, not as signed HTTP batches.
        self._transport: Optional[Callable[[List[Tuple[str, Any, bool, Any]]], Any]] = None
        self._to_relay: List[Tuple[str, Any, bool, Any]] = []
        # Gossip in batches (integration_tests/load.py): what was admitted in the last
        # ``gossip_interval`` goes to each peer in one signed request. One request a transaction
        # a peer — a signature to make and one to check, each time — kept a loaded node's event
        # loop busy enough that blocks reached their peers late, and proposers built on stale
        # parents.
        self._forward_batch = forward_batch
        self._gossip_interval = gossip_interval
        # Asks a peer which of some hashes it lacks (exchange_announceTransactions); None: what
        # a peer sent is forwarded whole, as what a wallet sent is.
        self._announce = announce
        # The same batch to every peer, encoded and signed once (each peer's own encoding of a
        # megabyte batch was a share of a loaded node's event loop).
        self._forward_batch_to_all = forward_batch_to_all
        self._outbox: List[Any] = []  # (each its binary form's text)
        self._announcements: List[str] = []
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        self._flusher: Optional[asyncio.Future] = None
        # Awaited before admitting: until no block is being imported or built (the node's
        # block-processing lock). Admitting a batch queues hundreds of steps on the event loop,
        # and every step of a block import waited behind them.
        self._yield_to = yield_to

    def use_transport(self, relay: Callable[[List[Tuple[str, Any, bool, Any]]], Any]) -> None:
        """Relay through the native peer transport from now on (qrdx/node/netd.py)."""
        self._transport = relay

    async def submit(
        self, tx: Any, propagated: bool = False, origin: Optional[str] = None, raw: Any = None
    ) -> Tuple[bool, str, Optional[str]]:
        """Returns (ok, error, tx_hash). Re-submitting a transaction the mempool already holds
        is not an error (it is idempotent) and is not gossiped again. ``origin``: the peer it
        came from, over the native transport; ``raw``: its bytes, when the transport does not
        hold them."""
        try:
            tx = parse_exchange_tx(tx)
        except Exception as e:
            return False, f"malformed exchange tx: {e}", None
        tx_hash = tx.tx_hash()
        mempool = self._get_mempool()
        if mempool.contains(tx_hash):
            return True, "", tx_hash  # (a peer's echo: nothing to read or forward)
        if self._yield_to is not None:
            await self._yield_to()
        self._saw(tx_hash)
        await self._preverify(tx)
        if self._yield_to is not None:
            # (blocks first again: a block that arrived while the batch's signatures were checked
            # would otherwise wait for the whole batch's admission at its every step)
            await self._yield_to()
        short = await self._unaffordable(tx)
        if short:
            return False, short, None
        ok, err = mempool.admit(tx)
        if not ok:
            if err.startswith("duplicate"):
                return True, "", tx_hash
            return False, err, None
        if self._transport is not None:
            if not propagated and raw is None:
                raw = tx.to_wire()  # (the binary form: half the bytes of its JSON)
            self._to_relay.append((tx_hash, raw, not propagated, origin))
            if len(self._to_relay) == 1:  # (what is admitted together goes in one call)
                asyncio.get_running_loop().call_soon(self._relay_now)
            return True, "", tx_hash
        if self._forward_batch is not None:
            if propagated and self._announce is not None:
                self._announcements.append(tx_hash)
            else:
                self._outbox.append(tx.to_text())
            if self._flusher is None or self._flusher.done():
                self._flusher = asyncio.ensure_future(self._flush_outbox())
        else:
            asyncio.ensure_future(
                self._gossip(tx.to_text(), origin="peer" if propagated else "local")
            )
        return True, "", tx_hash

    async def _unaffordable(self, tx: ExchangeTransaction) -> str:
        """Why the transaction's payer cannot pay for its gas now, or why it is malformed ("" if
        it can, it pays none — the free lane, judged by the mempool — or balances are not
        checked)."""
        if self._get_balance is None:
            return ""
        try:  # (its form first: the checks below read its params and its price)
            tx.validate_basic()
            if tx.free_eligible():
                return ""
            tx.validate_fee()
        except ValueError as e:
            return str(e)
        from .state_manager import ExchangeStateManager

        payer = ExchangeStateManager.get_instance().fee_payer(tx)
        need = tx.max_fee()
        held = Decimal(await self._get_balance(payer))
        if held < need:
            return (
                f"insufficient QRDX for gas: {payer[:16]}… holds {held}; the transaction may "
                f"cost {need} (gas_limit × gas_price)"
            )
        return ""

    def _relay_now(self) -> None:
        items, self._to_relay = self._to_relay, []
        if items and self._transport is not None:
            try:
                self._transport(items)
            except Exception as e:  # (a relay must never fail an admission)
                logger.warning("exchange relay through the transport failed: %s", e)

    async def _preverify(self, tx: ExchangeTransaction) -> None:
        """Check this transaction's signature with the others arriving now (a peer's gossip
        batch): one batch on the native module's threads, off the event loop, instead of one at
        a time on it. The mempool's own check then finds it checked
        (``block_processor.is_verified``); one that failed is refused there, as before."""
        from .. import native

        if not native.AVAILABLE:
            return
        future: "asyncio.Future[None]" = asyncio.get_running_loop().create_future()
        self._verify_queue.append((tx, future))
        if self._verifier is None or self._verifier.done():
            self._verifier = asyncio.ensure_future(self._verify_queued())
        await future

    async def _verify_queued(self) -> None:
        from .block_processor import verify_exchange_txs

        while self._verify_queue:
            await asyncio.sleep(0)  # (the rest of what arrived together joins)
            batch, self._verify_queue = self._verify_queue, []
            try:
                await verify_exchange_txs([tx for tx, _ in batch])
            except Exception as e:  # (the mempool checks each again)
                logger.debug("exchange admission: batch verification skipped: %s", e)
            for _tx, future in batch:
                if not future.done():
                    future.set_result(None)

    def _saw(self, tx_hash: str) -> None:
        self._seen[tx_hash] = None
        if len(self._seen) > SEEN_HASHES:
            self._seen.popitem(last=False)

    def wanted(self, hashes: Iterable[Any]) -> List[str]:
        """Which of these announced hashes this node lacks and has not handled lately."""
        mempool = self._get_mempool()
        return [
            h
            for h in hashes
            if isinstance(h, str) and h not in self._seen and not mempool.contains(h)
        ]

    async def _flush_outbox(self) -> None:
        """Every ``gossip_interval``, what was admitted since, to every peer at once: what wallets
        sent, whole; what peers sent, announced."""
        while self._outbox or self._announcements:
            await asyncio.sleep(self._gossip_interval)
            push, self._outbox = self._outbox, []
            announce, self._announcements = self._announcements, []
            try:
                urls = [u for u in self._get_peer_urls() if u]
            except Exception as e:
                logger.debug("exchange gossip: no peer list: %s", e)
                continue
            sends = []
            if push and self._forward_batch_to_all is not None:
                for at in range(0, len(push), GOSSIP_BATCH):
                    sends.append(self._forward_batch_to_all(urls, push[at : at + GOSSIP_BATCH]))
                push = []
            results = await asyncio.gather(
                *sends,
                *[self._gossip_to(url, push, announce) for url in urls],
                return_exceptions=True,
            )
            urls = ["(all peers)"] * len(sends) + urls
            for url, r in zip(urls, results, strict=True):
                if isinstance(r, Exception):
                    logger.debug("exchange gossip to %s failed: %s", url, r)

    async def _gossip_to(self, url: str, push: List[Any], announce: List[str]) -> None:
        assert self._forward_batch is not None
        for at in range(0, len(push), GOSSIP_BATCH):
            await self._forward_batch(url, push[at : at + GOSSIP_BATCH])
        if not announce or self._announce is None:
            return
        mempool = self._get_mempool()
        for at in range(0, len(announce), ANNOUNCE_BATCH):
            chunk = announce[at : at + ANNOUNCE_BATCH]
            asked = set(await self._announce(url, chunk) or ())
            txs = [mempool.get(h) for h in chunk if h in asked]
            wanted = [t.to_text() for t in txs if t is not None]
            for start in range(0, len(wanted), GOSSIP_BATCH):
                await self._forward_batch(url, wanted[start : start + GOSSIP_BATCH])

    async def _gossip(self, tx_dict: Any, origin: str) -> None:
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
