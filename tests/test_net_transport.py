"""
The peer-to-peer transport (native/qrdx-native/src/net; docs/NETWORK.md), between live services
in this process. What must hold:

* the handshake binds each side to its node key (the node id is the key's) and to the chain;
  another chain, a connection to itself, and a peer the node did not admit are refused;
* a wallet's transaction goes whole to every peer; a peer's is announced to the others, which
  ask for it and get it; a duplicate is not passed on twice;
* what the transport reads of a transaction is exactly what Python reads: the signed bytes
  and the hash are Python's own, the verdict is liboqs's, and what it does not reproduce (a
  float in the params) is handed to Python unread;
* a peer that sends garbage, or invalid signatures, harms nothing but its own connection.
"""

import json
import random
import socket
import time

import pytest

N = pytest.importorskip("qrdx_native")

from qrdx.constants import CHAIN_ID  # noqa: E402
from qrdx.crypto.pq.dilithium import PQPrivateKey  # noqa: E402
from qrdx.exchange import ExchangeOpType, ExchangeTransaction  # noqa: E402

GENESIS = "ab" * 32


def _service(chain_id=CHAIN_ID, genesis=GENESIS):
    pk, sk = N.mldsa65_keypair()
    svc = N.NetService("127.0.0.1:0", sk, pk, chain_id, genesis, threads=2)
    addr = svc.start()
    return svc, addr


def _wait(svc, want, timeout=10.0):
    """Drain ``svc`` until ``want(events)`` holds; the events seen."""
    events = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events.extend(svc.drain())
        if want(events):
            return events
        time.sleep(0.01)
    raise AssertionError(f"timed out; saw {events!r}")


def _ups(events):
    return {e[1] for e in events if e[0] == "up"}


def _txs(events):
    return [t for e in events if e[0] == "txs" for t in e[2]]


def _tx(key=None, nonce=0, params=None):
    key = key or PQPrivateKey.generate()
    t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER,
                            sender=key.public_key.to_address(), nonce=nonce,
                            params=params or {"token_address": "QRDX", "to": "0xPQ" + "c" * 64,
                                              "amount": "1"},
                            gas_limit=40_000, gas_price=10 ** 9, chain_id=CHAIN_ID)
    t.public_key = key.public_key.to_bytes()
    t.signature = key.sign(t.signing_bytes()).to_bytes()
    return t


def _raw(t):
    return json.dumps(t.to_dict()).encode()


def test_two_nodes_connect_as_their_keys():
    a, _ = _service()
    b, b_addr = _service()
    a.connect(b_addr, b.node_id)
    assert b.node_id in _ups(_wait(a, lambda ev: b.node_id in _ups(ev)))
    assert a.node_id in _ups(_wait(b, lambda ev: a.node_id in _ups(ev)))
    assert [p[0] for p in a.peers()] == [b.node_id]
    from qrdx.node.identity import _derive_node_id

    assert a.node_id.startswith("qx") and len(a.node_id) == 42
    pk, sk = N.mldsa65_keypair()
    c = N.NetService("127.0.0.1:0", sk, pk, CHAIN_ID, GENESIS)
    assert c.node_id == _derive_node_id(bytes(pk))                # (the node id Python derives)


def test_another_chain_itself_and_a_stranger_are_refused():
    a, a_addr = _service()
    other, _ = _service(chain_id=CHAIN_ID + 1)
    other.connect(a_addr)
    other_genesis, _ = _service(genesis="cd" * 32)
    other_genesis.connect(a_addr)
    a.connect(a_addr)                                                # (itself)
    time.sleep(1.0)
    assert a.peers() == [] and other.peers() == [] and other_genesis.peers() == []
    assert a.stats()["handshakes_failed"] >= 2

    b, _ = _service()
    a.allow([])                                                      # (no one admitted)
    b.connect(a_addr)
    time.sleep(1.0)
    assert a.peers() == [] and b.peers() == []
    a.allow([b.node_id])
    b.connect(a_addr, a.node_id)
    _wait(a, lambda ev: b.node_id in _ups(ev))


def test_the_connection_dials_only_the_node_it_expects():
    a, _ = _service()
    b, b_addr = _service()
    a.connect(b_addr, "qx" + "00" * 20)
    time.sleep(1.0)
    assert a.peers() == []


def test_a_wallets_transaction_reaches_peers_whole_and_once():
    a, _ = _service()
    b, b_addr = _service()
    a.connect(b_addr, b.node_id)
    _wait(b, lambda ev: a.node_id in _ups(ev))
    t = _tx()
    [(h, signed, verdict, reason)] = a.check([_raw(t)])
    assert (h, bytes(signed), verdict, reason) == (t.tx_hash(), t.signing_bytes(), True, None)
    a.relay([(h, None, True, None)])
    got = _txs(_wait(b, lambda ev: _txs(ev)))
    assert [(x[1], bytes(x[2]), x[3]) for x in got] == [(t.tx_hash(), t.signing_bytes(), True)]
    assert json.loads(bytes(got[0][0])) == t.to_dict()
    a.relay([(h, None, True, None)])                                 # (again: not passed on)
    time.sleep(0.5)
    assert _txs(b.drain()) == []


def test_a_relayed_transaction_is_announced_and_fetched():
    a, _ = _service()
    b, b_addr = _service()
    c, c_addr = _service()
    a.connect(b_addr, b.node_id)
    c.connect(b_addr, b.node_id)
    _wait(b, lambda ev: {a.node_id, c.node_id} <= _ups(ev))
    t = _tx()
    [(h, _s, _v, _r)] = a.check([_raw(t)])
    a.relay([(h, None, True, None)])
    got = _txs(_wait(b, lambda ev: _txs(ev)))
    b.relay([(got[0][1], None, False, a.node_id)])                   # b admitted it: announces
    got_c = _txs(_wait(c, lambda ev: _txs(ev)))
    assert [x[1] for x in got_c] == [t.tx_hash()] and got_c[0][3] is True
    assert b.stats()["frames_out"] >= 2                              # (the announcement, the push)


def test_an_invalid_signature_is_not_passed_on_and_costs_the_peer():
    a, _ = _service()
    b, b_addr = _service()
    a.connect(b_addr, b.node_id)
    _wait(b, lambda ev: a.node_id in _ups(ev))
    bad = []
    for _ in range(3):
        d = _tx().to_dict()
        d["params"]["amount"] = "2"                                  # (signed for "1")
        bad.append(json.dumps(d).encode())
    hashes = [r[0] for r in a.check(bad)]
    a.relay([(h, raw, True, None) for h, raw in zip(hashes, bad)])   # (a misbehaving peer)
    time.sleep(1.0)
    assert _txs(b.drain()) == []
    assert b.stats()["txs_invalid"] == 3 and b.peers() == []         # (three strikes)


def test_relaying_while_peers_announce_does_not_deadlock():
    """Python relaying (from its thread, which holds the GIL) while the transport's threads
    handle a peer's announcements: both touch what the transport remembers. They once took two
    locks in opposite orders and the node froze within seconds."""
    import threading

    a, _ = _service()
    b, b_addr = _service()
    a.connect(b_addr, b.node_id)
    _wait(b, lambda ev: a.node_id in _ups(ev))
    rng = random.Random(7)

    def hashes(n):
        return ["%064x" % rng.getrandbits(256) for _ in range(n)]

    done = threading.Event()

    def announce():
        while not done.is_set():
            a.relay([(h, None, False, "qx" + "22" * 20) for h in hashes(500)])

    t = threading.Thread(target=announce, daemon=True)
    t.start()
    deadline = time.monotonic() + 3.0
    try:
        while time.monotonic() < deadline:
            finished = threading.Event()

            def relay():
                b.relay([(h, None, False, a.node_id) for h in hashes(500)])
                finished.set()

            threading.Thread(target=relay, daemon=True).start()
            assert finished.wait(5.0), "relay did not return: deadlocked"
    finally:
        done.set()
        t.join(5.0)
    assert b.stats()["frames_in"] > 10                                 # (announcements arrived)


def test_garbage_on_the_socket_harms_nothing():
    a, a_addr = _service()
    host, port = a_addr.rsplit(":", 1)
    for junk in (b"GET / HTTP/1.1\r\n\r\n", b"\x00\x00\x00\x05hello", b"\xff" * 64,
                 b"\x7f\xff\xff\xff"):
        s = socket.create_connection((host, int(port)))
        s.sendall(junk)
        s.close()
    b, _ = _service()
    b.connect(a_addr, a.node_id)
    _wait(a, lambda ev: b.node_id in _ups(ev))


def _random_params(rng):
    def value(depth=0):
        k = rng.choice(["str", "int", "bool", "none"] + (["dict", "list"] if depth < 3 else []))
        if k == "str":
            return "".join(rng.choice(["a", "Z", "é", "😀", '"', "\\", "\n", "/", " "])
                           for _ in range(rng.randint(0, 6)))
        if k == "int":
            return rng.choice([0, 7, -3, 2 ** 70, -(10 ** 25)])
        if k == "bool":
            return rng.random() < 0.5
        if k == "none":
            return None
        if k == "dict":
            return {value(9) if False else f"k{i}{rng.choice('aé😀')}": value(depth + 1)
                    for i in range(rng.randint(0, 4))}
        return [value(depth + 1) for _ in range(rng.randint(0, 4))]
    return {"token_address": "QRDX", "to": "0xPQ" + "c" * 64, "amount": "1", "x": value()}


@pytest.mark.parametrize("seed", range(6))
def test_the_signed_bytes_and_hash_are_pythons(seed):
    rng = random.Random(seed)
    svc, _ = _service()
    key = PQPrivateKey.generate()
    txs = [_tx(key, nonce=n, params=_random_params(rng)) for n in range(25)]
    signer = txs[3].to_dict()
    signer["signer"] = PQPrivateKey.generate().public_key.to_address()   # (another's agent)
    forms = [t.to_dict() for t in txs] + [signer]
    forms[5]["gas_price"] = "0001000000000"                              # (leading zeros)
    forms[6]["chain_id"] = str(CHAIN_ID)                                  # (a chain id as text)
    forms[7]["signer"] = forms[7]["sender"]                               # (itself: no signer)
    for form, (h, signed, verdict, reason) in zip(forms, svc.check(
            [json.dumps(f).encode() for f in forms])):
        ref = ExchangeTransaction.from_dict(json.loads(json.dumps(form)))
        assert reason is None, reason
        assert bytes(signed) == ref.signing_bytes() and h == ref.tx_hash()


def test_what_it_does_not_reproduce_goes_to_python_unread():
    svc, _ = _service()
    t = _tx(params={"token_address": "QRDX", "to": "0xPQ" + "c" * 64, "amount": "1",
                    "leverage": 2.5})
    named = _tx().to_dict()
    named["op_type"] = "TOKEN_TRANSFER"
    no_price = _tx().to_dict()
    del no_price["gas_price"]
    results = svc.check([_raw(t), json.dumps(named).encode(), json.dumps(no_price).encode(),
                         b"not json"])
    assert [r[0] for r in results] == [None, None, None, None]
    assert all(r[3] for r in results)


async def test_python_takes_a_verdict_only_for_the_bytes_it_signs_itself(monkeypatch):
    """qrdx/node/netd.py: the transport's verdict stands in for liboqs only when the bytes it
    checked are the transaction's signed bytes as Python computes them. Told "valid" for other
    bytes, Python checks the signature itself, and a forgery is refused."""
    from qrdx.exchange.block_processor import is_verified
    from qrdx.node import main as node_main
    from qrdx.node import netd

    seen = []

    class _Submitter:
        async def submit(self, tx, propagated=False, origin=None, raw=None):
            seen.append((tx, is_verified(tx), origin))
            return True, "", tx.tx_hash()

    monkeypatch.setattr(node_main, "_get_exchange_submitter", lambda: _Submitter())
    good = _tx()
    forged = _tx().to_dict()
    forged["params"]["amount"] = "9"                                     # (signed for "1")
    items = [
        (_raw(good), good.tx_hash(), good.signing_bytes(), True, None),
        # a transport that checked other bytes and says "valid": not believed
        (json.dumps(forged).encode(), "00" * 32, b"other bytes", True, None),
    ]
    await netd._admit("qx" + "11" * 20, items)
    assert [(v, o) for _t, v, o in seen] == [(True, "qx" + "11" * 20), (False, "qx" + "11" * 20)]
    assert not seen[1][0].verify()                                       # (it is a forgery)


def test_lookup_reads_the_pool_by_hash():
    a, _ = _service()
    t = _tx()
    [(h, _s, _v, _r)] = a.check([_raw(t)])
    found = a.lookup([h, "00" * 32, "not hex"])
    assert json.loads(bytes(found[0])) == t.to_dict() and found[1:] == [None, None]


# ── blocks and votes (docs/NETWORK.md) ───────────────────────────────────────────────────


def _mesh(n):
    """``n`` services, each connected to every other."""
    svcs = [_service() for _ in range(n)]
    for i, (a, _) in enumerate(svcs):
        for b, b_addr in svcs[i + 1:]:
            a.connect(b_addr, b.node_id)
    for a, _ in svcs:
        others = {b.node_id for b, _ in svcs if b is not a}
        _wait(a, lambda ev, others=others: others <= {p[0] for p in a.peers()})
    return [s for s, _ in svcs]


def _of(events, kind):
    return [e for e in events if e[0] == kind]


def test_a_block_reaches_every_peer_once():
    a, b, c = _mesh(3)
    block = json.dumps({"id": 7, "block_content": "x" * 5000}).encode()
    assert set(a.send_block(block)) == {b.node_id, c.node_id}
    for svc in (b, c):
        got = _of(_wait(svc, lambda ev: _of(ev, "block")), "block")
        assert got == [("block", a.node_id, block)]
    # relayed on by b (the node it came from excepted): c has it, a sent it: neither again
    assert b.send_block(block, a.node_id) == [c.node_id]
    a.send_block(block)
    time.sleep(0.5)
    assert _of(b.drain() + c.drain() + a.drain(), "block") == []
    assert c.stats()["blocks_in"] == 3 and c.stats()["blocks_new"] == 1


def test_votes_reach_peers_and_copies_are_set_aside():
    a, b = _mesh(2)
    votes = [json.dumps({"validator_address": f"0xPQ{i:064x}", "slot": 9}).encode()
             for i in range(5)]
    assert a.send_votes(votes[:3]) == [b.node_id]
    got = _of(_wait(b, lambda ev: _of(ev, "votes")), "votes")
    assert got == [("votes", a.node_id, votes[:3])]
    a.send_votes(votes)                                   # (three again, two new)
    got = _of(_wait(b, lambda ev: _of(ev, "votes")), "votes")
    assert got == [("votes", a.node_id, votes[3:])]
    with pytest.raises(ValueError):
        a.send_votes([b""])
    with pytest.raises(ValueError):
        a.send_votes([b"x" * (16 * 1024 + 1)])


def test_a_blocks_operations_are_asked_of_its_sender():
    a, b = _mesh(2)
    held = [_tx() for _ in range(3)]
    for t in held[:2]:
        a.check([_raw(t)])                                 # (a wallet's: in a's pool)
    a.hold([(held[2].tx_hash(), _raw(held[2]))])           # (a block's, held to be asked for)
    unknown = "ee" * 32
    hashes = [t.tx_hash() for t in held] + [unknown]
    assert a.missing(hashes) == [unknown]
    request = b.ask_block_txs(a.node_id, hashes)
    assert request is not None
    got = _of(_wait(b, lambda ev: _of(ev, "block_txs")), "block_txs")
    assert got == [("block_txs", a.node_id, request, [_raw(t) for t in held] + [None])]
    assert b.ask_block_txs("qx" + "00" * 20, hashes) is None   # (not connected)
    with pytest.raises(ValueError):
        b.ask_block_txs(a.node_id, [])
    with pytest.raises(ValueError):
        b.ask_block_txs(a.node_id, ["zz"])


def test_a_peer_flooding_blocks_is_cut_to_its_budget():
    a, b = _mesh(2)
    for i in range(300):
        a.send_block(json.dumps({"id": i}).encode())
    time.sleep(1.0)
    got = _of(b.drain(), "block")
    # (a burst of twice the rate a second, then the rate: never all of them)
    assert 64 <= len(got) < 200
    assert b.stats()["dropped_in"] > 0
    assert [p[0] for p in b.peers()] == [a.node_id]         # (dropped, not disconnected)


def test_a_block_is_bounded():
    a, _b = _mesh(2)
    with pytest.raises(ValueError):
        a.send_block(b"")
    with pytest.raises(ValueError):
        a.send_block(b"x" * (15 * 1024 * 1024 + 1))
