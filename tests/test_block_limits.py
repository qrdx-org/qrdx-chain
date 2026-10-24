"""
What one block may carry (qrdx/block_limits.py, docs/BLOCK_LIMITS.md).

Every node executes every block within the slot clock, so a block is bounded by what a node can
execute, not only by its size in bytes: its EVM transactions' declared gas, its exchange
operations' declared gas, its votes and its slashing proofs. There was no such bound: a block
could carry 1.9 MB of EVM transactions with any gas limits, as many exchange operations as fit,
and any number of votes, each a Dilithium signature to verify. Every import path now checks
the bound before it verifies or applies anything, the proposer fills blocks to it, and the
mempools refuse what could never fit. eth_call runs no more than a block could carry.
"""
import pytest
from eth_account import Account

from qrdx import constants
from qrdx.block_limits import (
    MAX_SLASHING_EVIDENCE_PER_BLOCK,
    block_resource_error,
    exchange_section_gas_error,
)
from qrdx.constants import CHAIN_ID
from qrdx.contracts.evm_block_apply import section_gas_error
from qrdx.contracts.evm_mempool import EVMMempool
from qrdx.exchange import ExchangeOpType, ExchangeTransaction
from qrdx.exchange.mempool import ExchangeMempool


def _raw(i, nonce=0, gas=21_000):
    key = "0x" + f"{i:064x}"
    acct = Account.from_key(key)
    tx = {"nonce": nonce, "gasPrice": 10 ** 9, "gas": gas, "to": acct.address, "value": 0,
          "data": b"", "chainId": CHAIN_ID}
    signed = Account.sign_transaction(tx, key)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    return "0x" + bytes(raw).hex()


def _op(gas_limit, sender="0xPQ" + "a" * 64, nonce=0):
    return ExchangeTransaction(op_type=ExchangeOpType.CANCEL_ORDER, sender=sender, nonce=nonce,
                               params={"order_id": "x"}, gas_limit=gas_limit, gas_price=10 ** 9)


@pytest.fixture
def limits(monkeypatch):
    monkeypatch.setattr(constants, "BLOCK_GAS_LIMIT", 100_000)
    monkeypatch.setattr(constants, "BLOCK_EXCHANGE_GAS_LIMIT", 1_000_000)
    monkeypatch.setattr(constants, "BIG_BLOCK_INTERVAL", 0)  # (big blocks: test_big_blocks.py)


# ── the rule ─────────────────────────────────────────────────────────────────

def test_an_evm_section_may_declare_at_most_the_block_gas_limit(limits):
    assert section_gas_error([_raw(1, gas=50_000), _raw(2, gas=50_000)]) == ""
    err = section_gas_error([_raw(1, gas=50_000), _raw(2, gas=50_001)])
    assert "exceeds the block gas limit" in err
    assert "failed verification" in section_gas_error(["0xdeadbeef"])


def test_an_exchange_section_may_declare_at_most_the_exchange_gas_limit(limits):
    assert exchange_section_gas_error([_op(500_000).to_dict(), _op(500_000).to_dict()]) == ""
    assert "exceeds" in exchange_section_gas_error([_op(500_000).to_dict(),
                                                    _op(500_001).to_dict()])
    assert "malformed" in exchange_section_gas_error([{"gas_limit": "lots"}])


def test_a_block_may_carry_a_bounded_number_of_votes_and_slashing_proofs(limits):
    many = constants.MAX_ATTESTATIONS_PER_BLOCK
    assert block_resource_error({"attestations": [{}] * many}) == ""
    assert "attestations" in block_resource_error({"attestations": [{}] * (many + 1)})
    assert "slashing" in block_resource_error(
        {"slashing_evidence": [{}] * (MAX_SLASHING_EVIDENCE_PER_BLOCK + 1)})


def test_the_sections_are_read_from_beside_the_block_when_they_travel_there(limits):
    big = [_raw(1, gas=60_000), _raw(2, gas=60_000)]
    assert block_resource_error({}, evm_section=big)
    assert block_resource_error({"evm_transactions": big})
    assert block_resource_error({}, exchange_section=[_op(1_000_001).to_dict()])


async def test_every_import_path_refuses_an_oversized_block_before_anything_runs(
        limits, monkeypatch):
    """_verify_chain_rules is what the sync, push and REST import paths call before applying a
    block: it refuses an oversized one without verifying a single vote or slot."""
    from qrdx.node import main as node_main

    async def must_not_run(*a, **k):
        raise AssertionError("verified a block that carries too much")

    from qrdx.validator.block_verification import body_root

    monkeypatch.setattr("qrdx.validator.block_verification.verify_slot_progression", must_not_run)
    evm = [_raw(1, gas=100_001)]
    block = {"slot": 5, "attestations": []}
    block["body_root"] = body_root(block, [], evm)            # honest: the body is as signed
    ok, err = await node_main._verify_chain_rules(repr(block), 3, None, evm)
    assert not ok and "block gas limit" in err


# ── the proposer and the mempools ──────────────────────────────────────────

def test_the_evm_mempool_refuses_what_no_block_could_carry(limits):
    pool = EVMMempool(nonce_provider=lambda a: 0)
    ok, err, _ = pool.admit(_raw(1, gas=100_001))
    assert not ok and "gas limit" in err
    assert pool.admit(_raw(1, gas=100_000))[0]


def test_the_proposer_fills_a_block_up_to_the_gas_limit(limits):
    pool = EVMMempool(nonce_provider=lambda a: 0)
    for i in range(1, 6):                       # five senders, 30,000 gas each
        assert pool.admit(_raw(i, gas=30_000))[0]
    picked = pool.select_for_block()
    assert len(picked) == 3                      # 90,000 fits; a fourth would not
    assert section_gas_error(picked) == ""


def test_a_senders_run_stops_at_its_first_transaction_that_does_not_fit(limits):
    pool = EVMMempool(nonce_provider=lambda a: 0)
    assert pool.admit(_raw(1, nonce=0, gas=60_000))[0]
    assert pool.admit(_raw(1, nonce=1, gas=60_000))[0]   # would exceed: nonce 1 waits
    assert len(pool.select_for_block()) == 1


def _signed_op(key, nonce, gas_limit):
    tx = _op(gas_limit, sender=key.public_key.to_address(), nonce=nonce)
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def test_the_exchange_mempool_refuses_what_no_block_could_carry_and_packs_by_gas(limits):
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    pool = ExchangeMempool(nonce_provider=lambda a: 0)
    keys = [PQPrivateKey.generate() for _ in range(3)]
    ok, err = pool.admit(_signed_op(keys[0], 0, 1_000_001))
    assert not ok and "exchange gas limit" in err
    for key in keys:
        assert pool.admit(_signed_op(key, 0, 400_000))[0]
    picked = pool.select_for_block()
    assert len(picked) == 2 and sum(t.gas_limit for t in picked) == 800_000


# ── eth_call ───────────────────────────────────────────────────────────────

async def test_eth_call_runs_no_more_than_a_block_could_carry(tmp_path):
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
    from qrdx.contracts.evm_world import EvmWorld, run
    from qrdx.contracts.state import ContractStateManager
    from qrdx.database_sqlite import DatabaseSQLite

    db = await DatabaseSQLite.create(db_path=str(tmp_path / "c.db"))
    try:
        sm = ContractStateManager(db)
        ex = QRDXEVMExecutor(sm)
        loop = bytes.fromhex("5b600056")                  # JUMPDEST PUSH1 0 JUMP: forever
        target = bytes(19) + b"\x99"
        sm.set_code_sync("0x" + target.hex(), loop)
        await sm.commit(1)
        world = EvmWorld(sm)
        r = await run(world, lambda: ex.call(bytes(20), target, b"", gas=10 ** 9, world=world),
                      preload=[target])
        # A call may use what the largest block carries (a big block's: estimating a deploy).
        from qrdx.block_limits import max_evm_tx_gas

        assert not r.success and r.gas_used == max_evm_tx_gas()
    finally:
        await db.close()


# ── precompiles priced for what they cost here ─────────────────────────────

async def test_bn128_precompiles_are_charged_what_they_cost_in_python(tmp_path):
    """py-evm runs bn128 in pure Python: at Ethereum's prices a block of pairings took ~6 s.
    They are surcharged to run no slower per unit of gas than the cheapest instructions."""
    from qrdx.contracts import evm_world as W
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
    from qrdx.contracts.state import ContractStateManager
    from qrdx.database_sqlite import DatabaseSQLite

    db = await DatabaseSQLite.create(db_path=str(tmp_path / "p.db"))
    try:
        sm = ContractStateManager(db)
        ex = QRDXEVMExecutor(sm)
        g1 = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
        cases = [(W.BN128_MUL_ADDRESS, g1 + (3).to_bytes(32, "big"), 6_000 + W.BN128_MUL_SURCHARGE),
                 (W.BN128_PAIRING_ADDRESS, b"", 45_000)]        # no pairs: no surcharge
        for address, data, want in cases:
            world = W.EvmWorld(sm)
            r = await W.run(world, lambda: ex.call(bytes(20), address, data, world=world),
                            preload=[address])
            assert r.success and r.gas_used == want, (address.hex(), r.gas_used, r.error)
    finally:
        await db.close()
