"""
Exchange gossip: pushed by the node a wallet sent to, announced by the nodes that relay it
(qrdx/exchange/submission.py; docs/PERFORMANCE.md).

Every node re-sent every transaction whole to every peer, so each node received each one once
from every peer: in a mesh of four, three copies to parse for nothing. And a node forwarded at
most 64 transactions per peer every 50 ms, about 1,280 a second. What must hold:

* a transaction a wallet sent is pushed whole to every peer;
* a transaction a peer sent is announced by hash, and sent only to the peers that lack it;
* a node asks for nothing it holds or handled lately;
* a flush sends everything waiting, in batches the RPC server accepts.
"""

import asyncio
import json

import pytest

from qrdx.constants import CHAIN_ID
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType, ExchangeTransaction
from qrdx.exchange.mempool import ExchangeMempool
from qrdx.exchange.submission import GOSSIP_BATCH, ExchangeSubmitter
from qrdx.rpc.server import MAX_BATCH_SIZE


def _signed(key, nonce):
    t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=key.public_key.to_address(),
                            nonce=nonce, params={"token_address": "QRDX", "to": "0xPQ" + "c" * 64,
                                                 "amount": "1"},
                            gas_limit=40_000, gas_price=10 ** 9, chain_id=CHAIN_ID)
    t.public_key = key.public_key.to_bytes()
    t.signature = key.sign(t.signing_bytes()).to_bytes()
    return t


class _Net:
    def __init__(self, lacking=()):
        self.pushed = {}       # url -> [tx dicts]
        self.announced = {}    # url -> [hashes]
        self.lacking = dict(lacking)  # url -> set of hashes that peer lacks

    async def forward_batch(self, url, txs):
        assert len(txs) <= MAX_BATCH_SIZE
        self.pushed.setdefault(url, []).extend(txs)

    async def announce(self, url, hashes):
        self.announced.setdefault(url, []).extend(hashes)
        return [h for h in hashes if h in self.lacking.get(url, ())]


def _submitter(net, urls=("http://a", "http://b")):
    pool = ExchangeMempool(nonce_provider=lambda a: 0)

    async def forward(url, tx):  # (the per-transaction path: unused with batches)
        raise AssertionError("not batched")

    return pool, ExchangeSubmitter(lambda: pool, lambda: list(urls), forward,
                                   forward_batch=net.forward_batch, gossip_interval=0.01,
                                   announce=net.announce)


async def _flushed(sub):
    for _ in range(100):
        await asyncio.sleep(0.02)
        if not sub._outbox and not sub._announcements and (sub._flusher is None or sub._flusher.done()):
            return


async def test_a_wallets_transaction_is_pushed_whole_to_every_peer():
    net = _Net()
    _pool, sub = _submitter(net)
    t = _signed(PQPrivateKey.generate(), 0)
    assert (await sub.submit(t.to_dict()))[0]
    await _flushed(sub)
    assert [d["nonce"] for d in net.pushed["http://a"]] == [0] == [d["nonce"] for d in net.pushed["http://b"]]
    assert net.announced == {}


async def test_a_relayed_transaction_is_announced_and_sent_only_where_it_is_lacking():
    t = _signed(PQPrivateKey.generate(), 0)
    net = _Net(lacking={"http://b": {t.tx_hash()}})
    _pool, sub = _submitter(net)
    assert (await sub.submit(t.to_dict(), propagated=True))[0]
    await _flushed(sub)
    assert net.announced == {"http://a": [t.tx_hash()], "http://b": [t.tx_hash()]}
    assert "http://a" not in net.pushed                       # it had it
    assert [d["nonce"] for d in net.pushed["http://b"]] == [0]


async def test_a_node_asks_for_nothing_it_holds_or_handled_lately():
    net = _Net()
    pool, sub = _submitter(net)
    held = _signed(PQPrivateKey.generate(), 0)
    assert pool.admit(held)[0]
    refused = _signed(PQPrivateKey.generate(), 5_000)         # (its nonce: far past the window)
    assert not (await sub.submit(refused.to_dict()))[0]
    new = _signed(PQPrivateKey.generate(), 0)
    assert sub.wanted([held.tx_hash(), refused.tx_hash(), new.tx_hash(), 7]) == [new.tx_hash()]


async def test_a_flush_sends_everything_waiting():
    """At most 64 a peer every 50 ms used to go: about 1,280 transactions a second."""
    net = _Net()
    _pool, sub = _submitter(net, urls=("http://a",))
    keys = [PQPrivateKey.generate() for _ in range(3 * GOSSIP_BATCH // 4 + 1)]
    for k in keys:
        for n in range(2):
            assert (await sub.submit(_signed(k, n).to_dict()))[0]
    await _flushed(sub)
    assert len(net.pushed["http://a"]) == 2 * len(keys) > GOSSIP_BATCH


async def test_what_arrives_together_is_checked_and_read_together(monkeypatch):
    """A peer's gossip batch is a hundred calls at once. Each used to check its signature on the
    event loop and read its payer's balance in a database round trip of its own."""
    from decimal import Decimal

    from qrdx import native
    from qrdx.exchange import block_processor

    if not native.AVAILABLE:
        pytest.skip("the native module is not installed")
    checked, read = [], []
    real = block_processor.verify_exchange_txs

    async def counting(txs):
        checked.append(len(txs))
        return await real(txs)

    async def balances(addresses):
        read.append(len(addresses))
        return {a: Decimal(10) for a in addresses}

    async def one_balance(address):
        raise AssertionError("read one at a time")

    monkeypatch.setattr(block_processor, "verify_exchange_txs", counting)
    pool = ExchangeMempool(nonce_provider=lambda a: 0)
    net = _Net()
    sub = ExchangeSubmitter(lambda: pool, lambda: [], None, get_balance=one_balance,
                            get_balances=balances, forward_batch=net.forward_batch,
                            gossip_interval=0.01, announce=net.announce)
    txs = [_signed(PQPrivateKey.generate(), 0) for _ in range(20)]
    forged = json.loads(json.dumps(txs[3].to_dict()))   # (a copy: to_dict shares the params)
    forged["params"]["amount"] = "7"                     # (its signature no longer holds)
    results = await asyncio.gather(*[sub.submit(t.to_dict()) for t in txs], sub.submit(forged))
    assert [ok for ok, _, _ in results] == [True] * 20 + [False]
    assert checked == [21] and read == [20]


async def test_admission_waits_for_block_processing():
    """``yield_to`` (the node's block lock, ``until_free``) is awaited before a transaction is
    admitted: admission yields to a block being imported or built. An echo of one the mempool
    holds is answered without waiting."""
    net = _Net()
    pool, _ = _submitter(net)
    gate = asyncio.Event()
    waited = []

    async def yield_to():
        waited.append(True)
        await gate.wait()

    sub = ExchangeSubmitter(lambda: pool, lambda: [], None, forward_batch=net.forward_batch,
                            announce=net.announce, yield_to=yield_to)
    t = _signed(PQPrivateKey.generate(), 0)
    admitting = asyncio.ensure_future(sub.submit(t.to_dict()))
    await asyncio.sleep(0.05)
    assert waited and not admitting.done() and not pool.contains(t.tx_hash())
    gate.set()
    assert (await admitting)[0] and pool.contains(t.tx_hash())
    waited.clear()
    assert (await sub.submit(t.to_dict()))[0] and not waited       # (an echo: no wait)
