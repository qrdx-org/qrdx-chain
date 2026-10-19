"""
Block base fees (qrdx/fee_market.py, docs/BLOCK_LIMITS.md).

A block's gas used to cost the same however full blocks were — and EVM gas had no floor at all
(a gas price of 0 executed for free): one sender could fill every block for nothing, slowing
the chain to what a node can execute. Each block's signed header now carries an EVM and an
exchange base fee, set by its parent as Ethereum sets it (±1/8 around half the limit, never
under the floor). Every transaction must offer at least it; validators' oracle votes are exempt.
"""
import os
import tempfile

import pytest
from eth_account import Account

from qrdx import constants
from qrdx import fee_market as F
from qrdx.constants import CHAIN_ID
from qrdx.contracts.evm_mempool import EVMMempool
from qrdx.exchange import ExchangeOpType, ExchangeTransaction

GWEI = 10 ** 9


def _raw(i, nonce=0, gas=21_000, price=GWEI):
    key = "0x" + f"{i:064x}"
    acct = Account.from_key(key)
    signed = Account.sign_transaction(
        {"nonce": nonce, "gasPrice": price, "gas": gas, "to": acct.address, "value": 0,
         "data": b"", "chainId": CHAIN_ID}, key)
    return "0x" + bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction).hex()


def _op(price, op=ExchangeOpType.CANCEL_ORDER, gas_limit=100_000):
    return ExchangeTransaction(op_type=op, sender="0xPQ" + "a" * 64, nonce=0,
                               params={"order_id": "x"}, gas_limit=gas_limit,
                               gas_price=price).to_dict()


# ── the rule ─────────────────────────────────────────────────────────────────

def test_the_fee_moves_an_eighth_at_most_around_half_the_limit():
    assert F.next_base_fee(800, 500, 1000, 1) == 800                 # at target: unchanged
    assert F.next_base_fee(800, 1000, 1000, 1) == 900                # full: +1/8
    assert F.next_base_fee(800, 0, 1000, 1) == 700                   # empty: −1/8
    assert F.next_base_fee(800, 750, 1000, 1) == 850                 # halfway: half as much
    assert F.next_base_fee(8, 0, 1000, 10) == 10                     # never under the floor
    assert F.next_base_fee(0, 1000, 1000, 0) == 1                    # rises even from zero


def test_a_run_of_full_blocks_prices_a_flood_out_within_seconds():
    fee = GWEI
    for _ in range(120):                                             # 30 s at 250 ms slots
        fee = F.next_base_fee(fee, 1_000_000, 1_000_000, GWEI)
    assert fee > 1_000_000 * GWEI
    for _ in range(400):                                             # then it comes back down
        fee = F.next_base_fee(fee, 0, 1_000_000, GWEI)
    assert fee == GWEI


def test_oracle_votes_neither_pay_the_base_fee_nor_raise_it():
    vote = _op(1, op=ExchangeOpType.ORACLE_VOTE, gas_limit=10 ** 7)
    assert F.fee_gas([vote], [])[1] == 0
    block = {"base_fee": GWEI, "exchange_base_fee": 5 * GWEI}
    assert F.block_fee_error(block, [vote], [], (GWEI, 5 * GWEI)) == ""


def test_a_block_must_declare_its_parents_fees_and_carry_only_what_pays_them():
    block = {"base_fee": 2 * GWEI, "exchange_base_fee": 3 * GWEI}
    expected = (2 * GWEI, 3 * GWEI)
    assert F.block_fee_error(block, [_op(3 * GWEI)], [_raw(1, price=2 * GWEI)], expected) == ""
    assert "not the parent's" in F.block_fee_error(block, [], [], (GWEI, 3 * GWEI))
    assert "under the base fee" in F.block_fee_error(block, [], [_raw(1, price=GWEI)], expected)
    assert "under the base fee" in F.block_fee_error(block, [_op(GWEI)], [], expected)
    assert "no base fees" in F.block_fee_error({}, [], [], expected)


def test_evm_gas_has_a_floor():
    pool = EVMMempool(nonce_provider=lambda a: 0)
    ok, err, _ = pool.admit(_raw(1, price=0))
    assert not ok and "under the minimum" in err
    assert pool.admit(_raw(1, price=constants.EVM_MIN_GAS_PRICE_WEI))[0]


def test_the_proposer_takes_only_what_pays_the_base_fee():
    pool = EVMMempool(nonce_provider=lambda a: 0)
    assert pool.admit(_raw(1, price=GWEI))[0]
    assert pool.admit(_raw(2, price=3 * GWEI))[0]
    assert len(pool.select_for_block(min_price=2 * GWEI)) == 1
    assert len(pool.select_for_block(min_price=GWEI)) == 2


# ── on the stored chain ────────────────────────────────────────────────────

@pytest.fixture
async def db():
    from qrdx.database_sqlite import DatabaseSQLite

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    d = await DatabaseSQLite.create(path)
    yield d
    await d.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


async def _store(db, height, fees, evm=()):
    content = {"number": height, "slot": height, "base_fee": fees[0],
               "exchange_base_fee": fees[1]}
    bh = f"{height:064x}"
    await db.connection.execute(
        "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
        (bh, height, repr(content)))
    await db.connection.commit()
    if evm:
        await db.add_block_evm_txs(bh, list(evm))


async def test_each_blocks_fees_follow_from_its_parent(db, monkeypatch):
    monkeypatch.setattr(constants, "BLOCK_GAS_LIMIT", 100_000)
    floors = F.floors()
    assert await F.base_fees_at(db, 1) == floors                     # genesis's child: the floors
    await _store(db, 0, floors)
    await _store(db, 1, floors, evm=[_raw(i, gas=25_000) for i in range(1, 5)])  # full
    evm_fee, exchange_fee = await F.base_fees_at(db, 2)
    assert evm_fee == floors[0] + floors[0] // 8 and exchange_fee == floors[1]
    await _store(db, 2, (evm_fee, exchange_fee))                     # empty: back down
    assert (await F.base_fees_at(db, 3))[0] == max(floors[0], evm_fee - evm_fee // 8)


async def test_a_proposed_block_signs_its_fees_and_an_importer_checks_them(db, monkeypatch):
    """The fees are in the signed header: a relayer cannot change them without breaking the
    block's signature and hash."""
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.validator.block_verification import block_integrity_error, verify_pos_block_proposer
    from qrdx.validator.manager import PoSBlock

    key = PQPrivateKey.generate()
    b = PoSBlock(number=1, parent_hash="ab" * 32, state_root="cd" * 32,
                 transactions_root="ef" * 32, timestamp=1, proposer_address=key.public_key.to_address(),
                 proposer_public_key=key.public_key.to_bytes(), proposer_signature=b"", slot=1,
                 epoch=0, randao_reveal=b"", base_fee=7 * GWEI, exchange_base_fee=GWEI)
    b.commit_body()
    b.proposer_signature = key.sign(b.signing_root).to_bytes()
    content = b.to_dict()
    pk = key.public_key.to_bytes()
    assert verify_pos_block_proposer(str(content), b.proposer_address, pk)[0]
    forged = dict(content, base_fee=GWEI)
    assert not verify_pos_block_proposer(str(forged), b.proposer_address, pk)[0]
    assert "is not its header's" in block_integrity_error(forged, [], [], b.hash)


async def test_the_basefee_opcode_reads_the_executing_blocks_base_fee(db, monkeypatch):
    """BASEFEE (EIP-3198) reads the block's base fee, the same on the proposer, every importer
    and a rebuild from history — not a constant 1 gwei."""
    from qrdx.contracts import evm_block_apply as A
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
    from qrdx.contracts.evm_world import EvmWorld, run
    from qrdx.contracts.state import ContractStateManager

    await _store(db, 0, F.floors())
    await _store(db, 1, (5 * GWEI, GWEI))
    want = F.next_base_fee(5 * GWEI, 0, constants.BLOCK_GAS_LIMIT, F.floors()[0])
    seen = []

    async def execute(raw, height, block_hash, ts):
        seen.append(F.current_evm_base_fee())
        return {"tx_hash": "0x01"}

    sm = ContractStateManager(db)
    await A.produce_block_evm_section(2, "h", 1, [_raw(1)], db, sm, execute)
    await A.apply_block_evm_section(2, "h", 1, [_raw(1)], "x" * 128, db, sm, execute)
    assert seen == [want, want] and F.current_evm_base_fee() == F.floors()[0]

    ex = QRDXEVMExecutor(sm)
    target = bytes(19) + b"\x48"
    sm.set_code_sync("0x" + target.hex(), bytes.fromhex("4860005260206000f3"))  # return BASEFEE
    await sm.commit(3)
    token = F.CURRENT_EVM_BASE_FEE.set(want)
    try:
        world = EvmWorld(sm)
        r = await run(world, lambda: ex.call(bytes(20), target, b"", world=world), preload=[target])
    finally:
        F.CURRENT_EVM_BASE_FEE.reset(token)
    assert int.from_bytes(r.output, "big") == want
