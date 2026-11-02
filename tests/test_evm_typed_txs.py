"""
The transactions wallets send by default: EIP-1559 (type 0x02) and EIP-2930 (type 0x01).

MetaMask, ethers and viem build a type-2 transaction whenever a block reports a base fee, and the
EVM used to refuse every typed envelope but QRDX's own 0x51. Now both parse, authenticate and
execute (qrdx/contracts/evm_mempool.py), paying ``min(max fee, base fee + tip)`` per gas, all of
it burned. One transaction has one valid encoding (canonical integers, low ``s``), and a payer who
cannot cover its gas at its highest price runs nothing.
"""

import os
import tempfile
from decimal import Decimal

import pytest
import rlp
from eth_account import Account as EthAccount
from eth_hash.auto import keccak
from eth_utils import to_checksum_address

from qrdx.constants import CHAIN_ID
from qrdx.contracts import evm_mempool as M
from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.fee_market import CURRENT_EVM_BASE_FEE
from qrdx.node import main as node_main

GWEI = 10**9
WEI = 10**18
KEY = "0x" + "c4" * 32
SENDER = EthAccount.from_key(KEY).address
RECIPIENT = "0x" + "cd" * 20
SLOT = "0x" + "00" * 31 + "07"


def _sign(tx: dict) -> str:
    base = {
        "nonce": 0,
        "gas": 50_000,
        "to": to_checksum_address(RECIPIENT),
        "value": 1,
        "data": b"",
        "chainId": CHAIN_ID,
    }
    signed = EthAccount.sign_transaction({**base, **tx}, KEY)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return "0x" + bytes(raw).hex()


def _type2(**kw) -> str:
    return _sign({"type": 2, "maxFeePerGas": 3 * GWEI, "maxPriorityFeePerGas": GWEI, **kw})


def _fields(raw: str):
    data = bytes.fromhex(raw[2:])
    return data[0], rlp.decode(data[1:])


def _encode(tx_type: int, fields) -> str:
    return "0x" + (bytes([tx_type]) + rlp.encode(fields)).hex()


# ── parsing ─────────────────────────────────────────────────────────────────────


def test_an_eip_1559_transaction_parses_to_its_signer_and_its_fee_cap():
    raw = _type2()
    p = M.parse_eth_raw_tx(raw)
    assert p["sender"].lower() == SENDER.lower() and p["tx_type"] == 2
    assert (p["gas_price"], p["max_fee_per_gas"], p["max_priority_fee_per_gas"]) == (
        3 * GWEI,
        3 * GWEI,
        GWEI,
    )
    assert p["tx_hash"] == "0x" + keccak(bytes.fromhex(raw[2:])).hex()
    assert p["intrinsic_gas"] == 21_000 and p["chain_id"] == CHAIN_ID


def test_an_access_list_is_charged_up_front():
    access = [{"address": to_checksum_address(RECIPIENT), "storageKeys": [SLOT, "0x" + "11" * 32]}]
    for tx in (
        {"type": 1, "gasPrice": 2 * GWEI, "accessList": access},
        {"type": 2, "maxFeePerGas": 3 * GWEI, "maxPriorityFeePerGas": GWEI, "accessList": access},
    ):
        p = M.parse_eth_raw_tx(_sign(tx))
        assert p["sender"].lower() == SENDER.lower()
        assert p["intrinsic_gas"] == 21_000 + 2_400 + 2 * 1_900
        assert p["access_list"][0][0] == bytes.fromhex(RECIPIENT[2:])
    assert M.parse_eth_raw_tx(_sign({"type": 1, "gasPrice": 2 * GWEI}))["gas_price"] == 2 * GWEI


def test_the_price_paid_is_the_cap_or_base_fee_plus_tip_whichever_is_lower():
    p = M.parse_eth_raw_tx(_type2())
    assert M.effective_gas_price(p, GWEI) == 2 * GWEI
    assert M.effective_gas_price(p, 5 * GWEI) == 3 * GWEI
    legacy = M.parse_eth_raw_tx(_sign({"gasPrice": 2 * GWEI}))
    assert M.effective_gas_price(legacy, 9 * GWEI) == 2 * GWEI


def test_a_transaction_has_exactly_one_valid_encoding():
    tx_type, f = _fields(_type2())
    # s in the upper half of the curve order (the same signature, malleated)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    high = list(f)
    s = int.from_bytes(f[11], "big")
    high[11] = (n - s).to_bytes(32, "big").lstrip(b"\x00")
    high[9] = b"" if f[9] == b"\x01" else b"\x01"
    with pytest.raises(ValueError, match="EIP-2"):
        M.parse_eth_raw_tx(_encode(tx_type, high))
    # an integer with a leading zero byte
    padded = list(f)
    padded[1] = b"\x00" + f[1] if f[1] else b"\x00"
    with pytest.raises(ValueError, match="leading zero"):
        M.parse_eth_raw_tx(_encode(tx_type, padded))
    with pytest.raises(ValueError, match="expected 12 RLP fields"):
        M.parse_eth_raw_tx(_encode(tx_type, f[:-1]))


def test_another_chains_or_an_inconsistent_transaction_is_refused():
    with pytest.raises(ValueError, match="chain id"):
        M.parse_eth_raw_tx(_type2(chainId=CHAIN_ID + 1))
    tx_type, f = _fields(_type2())
    bad = list(f)
    bad[2] = (4 * GWEI).to_bytes(4, "big")  # tip above the cap
    with pytest.raises(ValueError, match="exceeds max fee"):
        M.parse_eth_raw_tx(_encode(tx_type, bad))
    with pytest.raises(ValueError, match="unsupported typed transaction 0x03"):
        M.parse_eth_raw_tx("0x03" + _type2()[4:])


def test_the_mempool_admits_a_type_2_transaction():
    pool = M.EVMMempool()
    ok, err, tx_hash = pool.admit(_type2())
    assert ok, err
    assert pool.select_for_block(min_price=3 * GWEI) == [pool.get_raw(tx_hash)]
    assert pool.select_for_block(min_price=3 * GWEI + 1) == []  # the cap is under the base fee


# ── execution ───────────────────────────────────────────────────────────────────


async def _env(funding: str):
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    await db.apply_account_balance_delta(to_account_id(SENDER), Decimal(funding))
    await db.connection.commit()
    sm = ContractStateManager(db)
    saved = (
        node_main.db,
        node_main.EVM_STATE_MANAGER,
        node_main.EVM_EXECUTOR,
        dict(node_main.EVM_PENDING_NONCE),
    )
    node_main.db, node_main.EVM_STATE_MANAGER = db, sm
    node_main.EVM_EXECUTOR = QRDXEVMExecutor(sm)
    node_main.EVM_PENDING_NONCE.clear()
    return db, sm, saved


async def _close(db, saved):
    node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR, pending = saved
    node_main.EVM_PENDING_NONCE.clear()
    node_main.EVM_PENDING_NONCE.update(pending)
    path = db.db_path
    await db.close()
    os.remove(path)


async def _execute(raw, base_fee=GWEI, height=1):
    token = CURRENT_EVM_BASE_FEE.set(base_fee)
    try:
        return await node_main._execute_evm_raw_tx(
            raw, height, f"{height:064x}", 1_700_000_000 + height
        )
    finally:
        CURRENT_EVM_BASE_FEE.reset(token)


async def test_a_type_2_transfer_pays_base_fee_plus_tip_and_moves_its_value():
    db, sm, saved = await _env("10")
    try:
        before = await sm.get_balance(to_account_id(SENDER))
        res = await _execute(_type2(value=WEI), base_fee=GWEI)
        assert res["success"], res
        after = await sm.get_balance(to_account_id(SENDER))
        assert before - after == WEI + 21_000 * 2 * GWEI  # base fee 1 + tip 1 gwei
        assert await sm.get_balance(to_account_id(RECIPIENT)) == WEI
        assert await sm.get_nonce(to_account_id(SENDER)) == 1
    finally:
        await _close(db, saved)


async def test_an_access_list_transaction_executes_with_its_slots_warm():
    db, sm, saved = await _env("10")
    try:
        access = [{"address": to_checksum_address(RECIPIENT), "storageKeys": [SLOT]}]
        res = await _execute(
            _sign({"type": 1, "gasPrice": 2 * GWEI, "accessList": access, "value": 5})
        )
        assert res["success"], res
        assert await sm.get_balance(to_account_id(RECIPIENT)) == 5
    finally:
        await _close(db, saved)


async def test_a_payer_who_cannot_cover_its_gas_runs_nothing_and_pays_nothing():
    db, sm, saved = await _env("0.00001")  # 10^13 wei, under 50,000 gas x 3 gwei
    try:
        before = await sm.get_balance(to_account_id(SENDER))
        res = await _execute(_type2(value=0))
        assert not res["success"] and "insufficient funds" in res["error"]
        assert await sm.get_balance(to_account_id(SENDER)) == before  # never negative
        assert await sm.get_nonce(to_account_id(SENDER)) == 0
    finally:
        await _close(db, saved)
