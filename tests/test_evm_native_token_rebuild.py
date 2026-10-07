"""
The EVM writes the token ledger now (native tokens are ERC-20s inside it) and contract storage
is account state, so the derived-state rebuild must reproduce both exactly. This drives the
node's REAL executor (``_execute_evm_raw_tx`` through ``produce_block_evm_section``) forward
over a chain — an exchange-deployed token, an EVM token transfer, a contract writing its
storage, a reverted transfer — then rebuilds from the chain on a fresh state manager and
executor (as after a reorg or a restart) and requires the token root, the account root (which
covers storage) and the balances to match.
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from decimal import Decimal

from eth_account import Account as EthAccount
from eth_utils import to_checksum_address

from qrdx.contracts.evm_block_apply import produce_block_evm_section
from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
from qrdx.exchange import (
    ExchangeOpType, ExchangeStateManager, ExchangeTransaction, encode_exchange_txs)
from qrdx.exchange import block_processor as BP
from qrdx.node import main as node_main

TS0 = 1_700_000_000
ALICE = EthAccount.from_key("0x" + "a1" * 32)
BOB = "0x" + "b0" * 20
STORE_RUNTIME = bytes.fromhex("36600f5760005460005260206000f35b60003560005500")


def _deploy_code(runtime):
    n = len(runtime)
    return bytes.fromhex("60%02x600c60003960%02x6000f3" % (n, n)) + runtime


def _legacy(nonce, to, data=b"", gas=300_000):
    tx = {"nonce": nonce, "gasPrice": 10 ** 9, "gas": gas, "value": 0, "data": data,
          "chainId": 88888}
    if to is not None:
        tx["to"] = to_checksum_address(to)
    signed = EthAccount.sign_transaction(tx, ALICE.key)
    return "0x" + bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction).hex()


def _transfer(to, units):
    return bytes.fromhex("a9059cbb") + bytes(12) + bytes.fromhex(to[2:]) + units.to_bytes(32, "big")


async def _add_block(db, h, ex=None, evm=None, alloc=None):
    bh = f"{h:064x}"
    ts = datetime.fromtimestamp(TS0, tz=timezone.utc) if h == 0 else TS0 + h
    await db.add_block(block_hash=bh, block_height=h, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=ts)
    for i, (r, a) in enumerate(alloc or []):
        await db.add_transaction(tx_hash=f"alloc-{i}", block_hash=bh, tx_hex=json.dumps(
            {"type": "genesis_allocation", "recipient": r, "amount": str(a)}))
    if ex:
        await db.add_block_exchange_txs(bh, ex)
    if evm:
        await db.add_block_evm_txs(bh, evm)


def _use(db, sm):
    node_main.db = db
    node_main.EVM_STATE_MANAGER = sm
    node_main.EVM_EXECUTOR = QRDXEVMExecutor(sm)


async def test_forward_and_rebuild_agree_on_evm_token_moves_and_storage(monkeypatch):
    monkeypatch.setattr(node_main, "EVM_PENDING_NONCE", {})
    saved = node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        issuer_key = PQPrivateKey.generate()
        issuer = issuer_key.public_key.to_address()
        token = ExchangeStateManager.derive_token_address(issuer, 0, "qUSD")

        def ex(nonce, op, params):
            t = ExchangeTransaction(op_type=op, sender=issuer, nonce=nonce, params=params,
                                    gas_limit=1_000_000)
            t.public_key = issuer_key.public_key.to_bytes()
            t.signature = issuer_key.sign(t.signing_bytes()).to_bytes()
            return t

        contract = "0x" + QRDXEVMExecutor(None)._compute_create_address(
            bytes.fromhex(ALICE.address[2:]), 2).hex()
        await _add_block(db, 0, alloc=[(ALICE.address, 1000), (issuer, 1000)])
        await _add_block(db, 1, ex=encode_exchange_txs([
            ex(0, ExchangeOpType.TOKEN_DEPLOY, {"name": "Quantum USD", "symbol": "qUSD",
                                                "decimals": 6, "total_supply": "1000"}),
            ex(1, ExchangeOpType.TOKEN_TRANSFER, {"token_address": token, "to": ALICE.address,
                                                  "amount": "300"})]))
        await _add_block(db, 2, evm=[
            _legacy(0, token, _transfer(BOB, 100 * 10 ** 6)),       # moves 100 qUSD
            _legacy(1, token, _transfer(BOB, 10 ** 12))])             # more than Alice holds
        await _add_block(db, 3, evm=[
            _legacy(2, None, _deploy_code(STORE_RUNTIME)),
            _legacy(3, contract, (42).to_bytes(32, "big"))])
        tip = 3

        # ── forward, as an importer applies each block ──
        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(mgr)
        sm = ContractStateManager(db)
        _use(db, sm)
        execute = node_main._evm_defer_execute()
        for h in range(1, tip + 1):
            bh = f"{h:064x}"
            section = await db.get_block_exchange_txs(bh)
            if section:
                txs = BP.decode_exchange_txs(section)
                await BP.preload_sender_balances(db, txs, mgr)
                await BP.preload_token_balances(db, txs, mgr)
                ok, err, _ = BP.process_exchange_transactions(h, float(TS0 + h), txs, mgr)
                assert ok, err
                assert len(mgr._block_results) == len(txs), "refused before it ran"
                assert all(r.success for r in mgr._block_results), [r.error for r in mgr._block_results]
                mgr.commit_block()
                await BP.flush_exchange_balance_deltas(db, mgr, enforce=True)
                await BP.flush_token_balance_deltas(db, mgr)
            else:
                BP.run_exchange_tick(h, float(TS0 + h), mgr)   # every block ticks
            evm = await db.get_block_evm_txs(bh)
            if evm:
                root, included = await produce_block_evm_section(h, bh, TS0 + h, evm, db, sm,
                                                                 execute)
                assert root is not None and len(included) == len(evm)
        await db.connection.commit()

        # the chain did what it says
        assert await db.get_token_balance(token, BOB) == Decimal(100)
        assert await db.get_token_balance(token, ALICE.address) == Decimal(200)
        rows = await (await db.connection.execute(
            "SELECT storage_value FROM contract_storage WHERE contract_address = ?",
            (contract,))).fetchall()
        assert [int(r[0], 16) for r in rows] == [42]
        forward = (await db.get_token_balances_root(), await db.get_account_state_root(),
                   ExchangeStateManager.get_instance().compute_state_root())

        # every executed transaction has its receipt (what eth_getTransactionReceipt serves),
        # and the token transfer its Transfer log
        async def receipts():
            rows = await (await db.connection.execute(
                "SELECT block_number, tx_index, status, contract_address FROM "
                "contract_transactions ORDER BY block_number, tx_index")).fetchall()
            logs = await (await db.connection.execute(
                "SELECT contract_address, topic0, topic2 FROM contract_logs")).fetchall()
            return [tuple(r) for r in rows], [tuple(r) for r in logs]
        forward_receipts = await receipts()
        rows, logs = forward_receipts
        assert [(r[0], r[1], r[2]) for r in rows] == [(2, 0, 1), (2, 1, 0), (3, 0, 1), (3, 1, 1)]
        assert rows[2][3] == contract
        from qrdx.contracts.native_token_evm import TRANSFER_TOPIC
        assert logs == [(token, "0x%064x" % TRANSFER_TOPIC, "0x" + BOB[2:].rjust(64, "0"))]

        # ── rebuild from the chain on a fresh manager and executor ──
        sm2 = ContractStateManager(db)
        _use(db, sm2)
        res = await rebuild_derived_state_interleaved(db, sm2, node_main._evm_defer_execute())
        assert res["evm"] == 2
        rebuilt = (await db.get_token_balances_root(), await db.get_account_state_root(),
                   ExchangeStateManager.get_instance().compute_state_root())
        assert rebuilt == forward
        assert await receipts() == forward_receipts
    finally:
        node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR = saved
        ExchangeStateManager.reset_instance()
        await db.close()
        os.remove(path)
