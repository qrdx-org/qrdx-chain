"""
The transaction index (qrdx/tx_index.py): a wallet's history and the chain's latest
transactions across every kind — genesis allocations, exchange operations, EVM transactions —
built from a real chain applied by the node's real executors, filed under every account a
transaction touched (makers whose orders it filled, token Transfer parties), the same for an
account's 0x and 0xPQ forms, paged by cursor, and cut back / re-indexed with a reorg.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx import tx_index
from qrdx.contracts.evm_block_apply import produce_block_evm_section
from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction, encode_exchange_txs
from qrdx.exchange import block_processor as BP
from qrdx.node import main as node_main
from eth_account import Account as EthAccount
from eth_utils import to_checksum_address
from test_evm_native_token_rebuild import ALICE, BOB, TS0, _add_block, _legacy, _transfer, _use

D = Decimal


def _pay(nonce, to, wei):
    """Alice sends ``wei`` QRDX to ``to``."""
    signed = EthAccount.sign_transaction(
        {"nonce": nonce, "gasPrice": 10 ** 9, "gas": 21_000, "value": wei, "data": b"",
         "to": to_checksum_address(to), "chainId": 88888}, ALICE.key)
    return "0x" + bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction).hex()


class Signer:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()
        self.nonce = 0

    def tx(self, op, **params):
        t = ExchangeTransaction(op_type=op, sender=self.addr, nonce=self.nonce, params=params,
                                gas_limit=1_000_000)
        self.nonce += 1
        t.public_key = self.key.public_key.to_bytes()
        t.signature = self.key.sign(t.signing_bytes()).to_bytes()
        return t


async def _apply(db, sm, mgr, h):
    """Apply block ``h`` as an importer does: exchange section, then EVM section."""
    bh = f"{h:064x}"
    section = await db.get_block_exchange_txs(bh)
    if section:
        txs = BP.decode_exchange_txs(section)
        await BP.preload_sender_balances(db, txs, mgr)
        await BP.preload_token_balances(db, txs, mgr)
        ok, err, _ = BP.process_exchange_transactions(h, float(TS0 + h), txs, mgr)
        assert ok, err
        assert len(mgr._block_results) == len(txs)
        mgr.commit_block()
        await BP.flush_exchange_balance_deltas(db, mgr, enforce=True)
        await BP.flush_token_balance_deltas(db, mgr)
    else:
        BP.run_exchange_tick(h, float(TS0 + h), mgr)
    evm = await db.get_block_evm_txs(bh)
    if evm:
        root, included = await produce_block_evm_section(h, bh, TS0 + h, evm, db, sm,
                                                         node_main._evm_defer_execute())
        assert root is not None and len(included) == len(evm)
    await db.connection.commit()


@pytest.fixture
async def chain(monkeypatch):
    monkeypatch.setattr(node_main, "EVM_PENDING_NONCE", {})
    saved = node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    issuer, maker = Signer(), Signer()
    tok = ExchangeStateManager.derive_token_address(issuer.addr, 0, "TOK")
    await _add_block(db, 0, alloc=[(ALICE.address, 1000), (issuer.addr, 1_000_000),
                                   (maker.addr, 1_000_000)])
    await _add_block(db, 1, ex=encode_exchange_txs([
        issuer.tx(ExchangeOpType.TOKEN_DEPLOY, name="Token", symbol="TOK", decimals=6,
                  total_supply="1000000"),
        issuer.tx(ExchangeOpType.TOKEN_TRANSFER, token_address=tok, to=ALICE.address,
                  amount="300"),
        issuer.tx(ExchangeOpType.CREATE_POOL, token0="QRDX", token1=tok, fee_tier=3000,
                  pool_type="STANDARD", initial_price="2", stake_amount="10000")]))
    await _add_block(db, 2, ex=encode_exchange_txs([
        maker.tx(ExchangeOpType.PLACE_ORDER, pair=f"{tok}:QRDX", side="buy",
                 order_type="limit", price="2", amount="50")]))
    await _add_block(db, 3, ex=encode_exchange_txs([
        issuer.tx(ExchangeOpType.PLACE_ORDER, pair=f"QRDX:{tok}", side="sell",
                  order_type="limit", price="2", amount="20")]),
        evm=[_legacy(0, tok, _transfer(BOB, 100 * 10 ** 6)),
             _pay(1, BOB, 5 * 10 ** 18)])
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    BP.apply_enforcement(mgr)
    sm = ContractStateManager(db)
    _use(db, sm)
    for h in (1, 2, 3):
        await _apply(db, sm, mgr, h)
    try:
        yield db, sm, mgr, issuer, maker, tok
    finally:
        node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR = saved
        ExchangeStateManager.reset_instance()
        await db.close()
        os.remove(path)


def _ops(page):
    return [(t["kind"], t["op"], t["block_height"]) for t in page["transactions"]]


async def test_every_kind_of_transaction_is_in_its_accounts_histories(chain):
    db, _, mgr, issuer, maker, tok = chain
    assert await tx_index.sync_index(db, mgr.journal) == 4          # blocks 0–3
    assert await db.tx_index_head() == 3

    # the issuer: its allocation, its three operations, its order that filled the maker's
    page = await tx_index.history(db, issuer.addr)
    assert _ops(page) == [("exchange", "PLACE_ORDER", 3), ("exchange", "CREATE_POOL", 1),
                          ("exchange", "TOKEN_TRANSFER", 1), ("exchange", "TOKEN_DEPLOY", 1),
                          ("genesis", "GENESIS_ALLOCATION", 0)]
    sell, pool, transfer, deploy, alloc = page["transactions"]
    assert sell["status"] == "success" and D(sell["fee"]) > 0 and sell["roles"] == ["sender"]
    assert (transfer["asset"], transfer["target"], transfer["amount"]) == (tok, ALICE.address, "300")
    assert deploy["detail"]["token_address"] == tok
    assert alloc["amount"] == "1000000" and alloc["roles"] == ["recipient"]

    # the maker sees the order that filled its resting bid, as the maker
    page = await tx_index.history(db, maker.addr)
    assert _ops(page)[:2] == [("exchange", "PLACE_ORDER", 3), ("exchange", "PLACE_ORDER", 2)]
    assert page["transactions"][0]["roles"] == ["maker"]
    assert page["transactions"][0]["sender"] == issuer.addr

    # Alice: received tokens (exchange), sent them on and paid Bob (EVM), her allocation
    page = await tx_index.history(db, ALICE.address)
    assert _ops(page) == [("evm", "TRANSFER", 3), ("evm", "TOKEN_TRANSFER", 3),
                          ("exchange", "TOKEN_TRANSFER", 1), ("genesis", "GENESIS_ALLOCATION", 0)]
    pay, token_send, received, _ = page["transactions"]
    assert pay["status"] == "success" and pay["asset"] == "QRDX" and D(pay["fee"]) > 0
    assert D(pay["amount"]) == 5
    assert set(token_send["roles"]) == {"sender", "token_from"}
    assert token_send["asset"] == tok and token_send["target"] == BOB
    assert token_send["detail"]["token_transfers"][0]["value"] == str(100 * 10 ** 6)
    assert received["roles"] == ["to"]

    # Bob never sent anything, but has both
    page = await tx_index.history(db, BOB)
    assert [(t["op"], t["roles"]) for t in page["transactions"]] == \
        [("TRANSFER", ["to"]), ("TOKEN_TRANSFER", ["token_to"])]


async def test_0x_and_0xpq_forms_share_a_history_and_pages_chain(chain):
    db, _, mgr, issuer, _, _ = chain
    await tx_index.sync_index(db, mgr.journal)
    by_pq = await tx_index.history(db, issuer.addr)
    by_id = await tx_index.history(db, to_account_id(issuer.addr))
    assert by_pq["transactions"] == by_id["transactions"] and by_pq["account"] == by_id["account"]

    first = await tx_index.history(db, issuer.addr, limit=2)
    assert len(first["transactions"]) == 2 and first["next_cursor"]
    second = await tx_index.history(db, issuer.addr, limit=2, cursor=first["next_cursor"])
    third = await tx_index.history(db, issuer.addr, limit=2, cursor=second["next_cursor"])
    seen = [t["tx_hash"] for p in (first, second, third) for t in p["transactions"]]
    assert seen == [t["tx_hash"] for t in by_pq["transactions"]]
    assert third["next_cursor"] is None

    only_genesis = await tx_index.history(db, issuer.addr, kinds=["genesis"])
    assert _ops(only_genesis) == [("genesis", "GENESIS_ALLOCATION", 0)]


async def test_latest_transactions_and_lookup(chain):
    db, _, mgr, issuer, maker, tok = chain
    await tx_index.sync_index(db, mgr.journal)
    latest = await tx_index.recent(db, limit=3)
    assert _ops(latest) == [("evm", "TRANSFER", 3), ("evm", "TOKEN_TRANSFER", 3),
                            ("exchange", "PLACE_ORDER", 3)]
    evm_only = await tx_index.recent(db, kinds=["evm"])
    assert len(evm_only["transactions"]) == 2

    sell = latest["transactions"][2]
    found = await tx_index.lookup(db, sell["tx_hash"])
    assert found["op"] == "PLACE_ORDER"
    assert found["accounts"] == {to_account_id(issuer.addr): ["sender"],
                                 to_account_id(maker.addr): ["maker"]}
    assert (await tx_index.lookup(db, "0x" + sell["tx_hash"]))["tx_hash"] == sell["tx_hash"]
    assert await tx_index.lookup(db, "ab" * 32) is None


async def test_a_reorg_cuts_the_index_and_reindexes(chain):
    db, sm, mgr, issuer, _, _ = chain
    await tx_index.sync_index(db, mgr.journal)
    # rollback through the database: the index goes with the blocks
    await db.remove_blocks(3)
    assert await db.tx_index_head() == 2
    assert _ops(await tx_index.history(db, BOB)) == []
    # a different block 3 on the new branch
    await _add_block(db, 3, evm=[_pay(2, BOB, 10 ** 18)])   # (state is not rolled back here)
    bh = f"{3:064x}"
    await produce_block_evm_section(3, bh, TS0 + 3, await db.get_block_evm_txs(bh), db, sm,
                                    node_main._evm_defer_execute())
    await db.connection.commit()
    assert await tx_index.sync_index(db, mgr.journal) == 1
    assert _ops(await tx_index.history(db, BOB)) == [("evm", "TRANSFER", 3)]

    # a block replaced without remove_blocks (a hash change at an indexed height) is noticed
    await db.connection.execute("UPDATE blocks SET block_hash = ? WHERE block_height = 2",
                                ("ff" * 32,))
    await db.connection.commit()
    assert await tx_index.sync_index(db, mgr.journal) == 2           # heights 2 and 3 again
    assert (await db.tx_index_blocks_from(2))[0] == (2, "ff" * 32)


async def test_the_tip_waits_for_its_receipts(chain):
    """A tip block whose EVM receipts are not written yet (still applying) is not indexed
    half-done: the indexer stops there and picks it up on a later pass."""
    db, _, mgr, *_ = chain
    await db.connection.execute("DELETE FROM contract_transactions WHERE block_number = 3")
    await db.connection.commit()
    assert await tx_index.sync_index(db, mgr.journal) == 3
    assert await db.tx_index_head() == 2
    # once it is below the tip, it is indexed from the transactions themselves
    await _add_block(db, 4)
    assert await tx_index.sync_index(db, mgr.journal) == 2
    rows = (await tx_index.recent(db, kinds=["evm"]))["transactions"]
    assert [r["status"] for r in rows] == ["unknown", "unknown"]
    assert rows[0]["sender"].lower() == ALICE.address.lower()


async def test_the_poller_follows_the_tip(chain):
    import asyncio
    db, _, mgr, *_ = chain
    lock = asyncio.Lock()
    await tx_index.tx_index_poller(lambda: db, lock, get_journal=lambda: mgr.journal,
                                   interval=0, _max_iterations=1)
    assert await db.tx_index_head() == 3
