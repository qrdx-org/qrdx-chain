"""
Plain QRDX transfers judged and run natively (qrdx/exchange/transfer_lane.py,
native/qrdx-native/src/lane.rs), held to Python's own path.

Random blocks go through two exchanges side by side, one with the native lane and one without:
plain transfers (some overdrawing, some from accounts with no balance loaded, with memos, to
themselves, to new addresses) mixed with what Python must handle or refuse (another token, a
deploy, a bad amount or recipient, a nonce out of sequence, a gas limit too low). After every
block everything must be the same: the judgment and its refusals, the block's outcome and root,
every result (success, gas, data, error, fee) and transaction field, the nonces, the balance
deltas — values and the order addresses entered them — the available balances and the block's
fees; and the block must still be taken back out by its undo record.
"""

import random
from decimal import Decimal

import pytest

pytest.importorskip("qrdx_native")

from qrdx.crypto.pq.dilithium import PQPrivateKey  # noqa: E402
from qrdx.exchange import ExchangeOpType, ExchangeTransaction  # noqa: E402
from qrdx.exchange import block_processor as BP  # noqa: E402
from qrdx.exchange import balance_plane, block_undo, transfer_lane  # noqa: E402
from qrdx.exchange.state_manager import ExchangeStateManager  # noqa: E402

KEYS = [PQPrivateKey.generate() for _ in range(6)]
ADDRS = [k.public_key.to_address() for k in KEYS]
PK = KEYS[0].public_key.to_bytes()
STRANGERS = ["0xPQ" + f"{i:064x}" for i in range(1, 4)]


def _tx(op, sender, nonce, params, gas_limit=60_000, gas_price=10 ** 9):
    t = ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params,
                            gas_limit=gas_limit, gas_price=gas_price)
    t.public_key, t.signature = PK, b"\x01" * 3309
    return t


def _block(rng, nonces, mode="any"):
    """``mode``: "plain" (only plain transfers), "mixed" (with other tokens and deploys, nothing
    refused: the block runs, lane runs between Python's operations), "any" (refusals too)."""
    plain_only = mode == "plain"
    refusals = mode == "any"
    txs = []
    for _ in range(rng.randint(1, 40)):
        s = rng.randrange(len(ADDRS))
        sender = ADDRS[s]
        k = rng.random()
        to = rng.choice(ADDRS + STRANGERS + [sender])
        amount = rng.choice(["0.000001", "1", "2.5", "100", "999999", "0.123456789012345678",
                             "50.10", str(rng.randint(1, 3000))])
        params = {"token_address": rng.choice(["QRDX", "qrdx"]), "to": to, "amount": amount}
        if rng.random() < 0.2:
            params["memo"] = "ref-" + str(rng.randint(0, 99))
        nonce = nonces[sender]
        gas_limit, gas_price = rng.choice([40_000, 60_000, 200_000]), rng.choice([10 ** 9, 3 * 10 ** 9])
        if refusals and k < 0.06:
            params["amount"] = rng.choice(["abc", "-1", "0", "1.0000000000000000001"])
        elif refusals and k < 0.09:
            params["to"] = "not an address"
        elif refusals and k < 0.11:
            nonce += 1                                     # (out of sequence: refused)
        elif refusals and k < 0.13:
            gas_limit = 1000                               # (too low: refused)
        elif not plain_only and k < 0.2:
            params["token_address"] = "0xTOK" + "0" * 40   # (another token: Python's)
        elif not plain_only and k < 0.24:
            txs.append(_tx(ExchangeOpType.TOKEN_DEPLOY, sender, nonce,
                           {"name": "T", "symbol": "T" + str(rng.randint(0, 999)),
                            "total_supply": "1000", "decimals": 18}, gas_limit=2_000_000))
            nonces[sender] += 1
            continue
        txs.append(_tx(ExchangeOpType.TOKEN_TRANSFER, sender, nonce, params, gas_limit, gas_price))
        nonces[sender] = nonce + 1
    return txs


def _snapshot(mgr, txs, out, errors):
    results = [(r.success, r.gas_used, r.data, r.error, r.fee) for r in mgr._block_results]
    fields = [(t.gas_used, t.success, t.result, t.error) for t in mgr._block_exchange_txs]
    return {
        "judged": errors,
        "out": out,
        "results": results,
        "fields": fields,
        "nonces": sorted(dict.items(mgr._nonces)),
        "deltas": [(a, str(v)) for a, v in mgr._balance_deltas.items()],   # (order counts)
        "available": sorted((a, str(v)) for a, v in mgr._available_balances.items()),
        "fees": str(mgr._block_fees),
        "root": mgr.compute_state_root(),
    }


def _fresh(plane=False):
    mgr = ExchangeStateManager()
    mgr.use_plane(plane)
    assert (mgr._plane is not None) == (plane and balance_plane.enabled())
    BP.apply_enforcement(mgr)
    return mgr


def _run_block(mgr, height, txs, balances, lane, monkeypatch):
    monkeypatch.setattr(transfer_lane, "enabled", lambda: lane)
    mgr.clear_available_balances()
    for a, b in balances.items():
        mgr.set_available_balance(a, Decimal(b))
    errors = mgr.section_errors(txs, height, 1_800_000_000.0 + height)
    opened = block_undo.open_block(mgr, height)
    root_before = mgr.compute_state_root()
    try:
        out = BP.process_exchange_transactions(height, 1_800_000_000.0 + height, txs, mgr)
        snap = _snapshot(mgr, txs, out, errors)
    finally:
        block_undo.close_block(opened, applied=True)
    if out[0]:
        mgr.commit_block()
    return snap, root_before


@pytest.mark.parametrize("seed", range(12))
def test_random_blocks_are_judged_and_run_as_python_does(seed, monkeypatch):
    rng = random.Random(seed)
    # Python's path on dicts; the native lane on dicts, and on the balance plane
    # (qrdx/exchange/balance_plane.py) — the lane's own path there, in place.
    py, native, planar = _fresh(), _fresh(), _fresh(plane=True)
    nonces = {a: 0 for a in ADDRS}
    block_undo.invalidate()
    ran_natively = 0
    for height in range(1, 30):
        txs = _block(rng, nonces, mode=("plain", "mixed", "any")[seed % 3])
        balances = {a: rng.choice(["0", "5", "1000", "1000000.000000000000000001", "3.333"])
                    for a in ADDRS if rng.random() < 0.85}

        def copy():
            out = [ExchangeTransaction.from_dict(t.to_dict()) for t in txs]
            for c, t in zip(out, txs):
                c.public_key, c.signature = t.public_key, t.signature
            return out

        copies, planar_copies = copy(), copy()
        a, _ = _run_block(py, height, txs, balances, False, monkeypatch)
        c, _ = _run_block(planar, height, planar_copies, balances, True, monkeypatch)
        assert a == c, f"seed {seed} block {height} (plane): {[k for k in a if a[k] != c[k]]}"
        b, root_before = _run_block(native, height, copies, balances, True, monkeypatch)
        assert a == b, f"seed {seed} block {height}: {[k for k in a if a[k] != b[k]]}"
        ran_natively += sum(1 for p in transfer_lane.prepare_all(copies) if p is not None)
        if not a["out"][0]:
            # (refused before anything ran: its nonces are not used)
            nonces = {addr: py._nonces.get(addr, 0) for addr in ADDRS}
        else:
            # every block still undoes: take it back out, compare, run it again
            assert block_undo.take_back(native, height - 1) == 1
            assert native.compute_state_root() == root_before
            block_undo.invalidate()
            again, _ = _run_block(native, height, [ExchangeTransaction.from_dict(t.to_dict())
                                                   for t in txs], balances, True, monkeypatch)
            assert again["root"] == a["root"] and again["deltas"] == a["deltas"]
    assert ran_natively > 100


def test_without_its_floor_check_the_lane_would_differ(monkeypatch):
    """(The test above holds the fee floor too — ``two_block_deferral``, qrdx/post_state.py: a
    lane that skipped its check would run transfers Python refuses.)"""
    monkeypatch.setattr(transfer_lane, "_above_floors", lambda mgr, txs, prepared: True)
    differed = 0
    for seed in range(4):
        try:
            test_random_blocks_are_judged_and_run_as_python_does(seed, monkeypatch)
        except AssertionError:
            differed += 1
    assert differed


def test_what_is_not_a_plain_transfer_is_left_to_python():
    good = _tx(ExchangeOpType.TOKEN_TRANSFER, ADDRS[0], 0,
               {"token_address": "QRDX", "to": ADDRS[1], "amount": "1"})
    assert transfer_lane.prepare(good) is not None
    cases = [
        {"token_address": "0xTOK" + "0" * 40, "to": ADDRS[1], "amount": "1"},
        {"token_address": "QRDX", "to": ADDRS[1], "amount": "1", "expires_at": 5},
        {"token_address": "QRDX", "to": ADDRS[1], "amount": "1e999"},
        {"token_address": "QRDX", "to": "nope", "amount": "1"},
        {"token_address": "QRDX", "to": ADDRS[1], "amount": "1", "memo": "x" * 10_000},
    ]
    for params in cases:
        assert transfer_lane.prepare(_tx(ExchangeOpType.TOKEN_TRANSFER, ADDRS[0], 0, params)) is None
    agent = _tx(ExchangeOpType.TOKEN_TRANSFER, ADDRS[0], 0, dict(good.params))
    agent.signer = ADDRS[2]
    free = _tx(ExchangeOpType.TOKEN_TRANSFER, ADDRS[0], 0, dict(good.params), gas_price=0)
    multisig = _tx(ExchangeOpType.TOKEN_TRANSFER, ADDRS[0], 0, dict(good.params))
    multisig.public_key = b'{"keys": []}'
    for t in (agent, free, multisig):
        assert transfer_lane.prepare(t) is None


def test_values_past_its_decimals_bail_to_python(monkeypatch):
    """A balance too large for 128-bit decimals: the lane bails and Python runs the run."""
    big = "1" + "0" * 40
    txs = [_tx(ExchangeOpType.TOKEN_TRANSFER, ADDRS[0], 0,
               {"token_address": "QRDX", "to": ADDRS[1], "amount": "1"})]
    py, native = _fresh(), _fresh()
    a, _ = _run_block(py, 1, txs, {ADDRS[0]: big}, False, monkeypatch)
    b, _ = _run_block(native, 1, [ExchangeTransaction.from_dict(t.to_dict()) for t in txs],
                      {ADDRS[0]: big}, True, monkeypatch)
    assert a == b and a["out"][0]
