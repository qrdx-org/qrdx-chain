"""
The rollback rebuild must replay derived state in the same ORDER forward import applies it.

Forward import applies each block as exchange → EVM → withdrawals, then the next block.
The by-domain rebuild replayed every EVM section first, then every exchange section, then
every withdrawal. A transaction whose outcome depends on an earlier block's effect in
another domain therefore replayed differently, and the reorged node disagreed with the
network at equal tip.

Each chain below is built so that ordering decides a transaction's outcome:

  * stake → EVM: a STAKE_DEPOSIT at block 1 leaves too little for block 2's EVM spend.
    Forward: the deposit is debited, the spend fails. By-domain: the spend runs first
    against the undebited balance and succeeds, then the deposit is REJECTED as
    unaffordable — the staker ends up with the spent funds and no stake.
  * withdrawal → EVM: a withdrawal paid at block 1 funds block 2's EVM spend. Forward:
    the spend succeeds. By-domain: it runs before any withdrawal is re-credited and fails.

For each chain the test asserts that (a) the interleaved rebuild reproduces the forward
roots and balances exactly, and (b) the by-domain rebuild does NOT — so the chain really
exercises ordering and (a) cannot pass vacuously.

The EVM executor is a faithful stand-in for a value transfer: it loads balances through
the real ``StateSyncManager.sync_address_to_evm`` (as ``_execute_evm_raw_tx`` does), so it
sees exactly the account_state an importer's EVM would, and it succeeds or fails on that.
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from decimal import Decimal

from exchange_fees import fee_of

from eth_account import Account as EthAccount

from qrdx.constants import MIN_VALIDATOR_STAKE
from qrdx.contracts.evm_block_apply import (
    produce_block_evm_section, rebuild_account_state_from_chain,
)
from qrdx.contracts.evm_mempool import parse_eth_raw_tx
from qrdx.contracts.state import ContractStateManager
from qrdx.contracts.state_sync import StateSyncManager
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
from qrdx.exchange import (
    ExchangeOpType, ExchangeStateManager, ExchangeTransaction, encode_exchange_txs,
)
from qrdx.exchange import block_processor as BP
from qrdx.transactions.pq_tx import PQTransaction
from qrdx.validator import withdrawals as WD
from qrdx.constants import CHAIN_ID  # the network's chain id (chain spec)

WEI = 10 ** 18
TS0 = 1_700_000_000
RECIPIENT = EthAccount.from_key("0x" + "77" * 32).address


# ── chain construction ────────────────────────────────────────────────────

async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


async def _add_block(db, height, ex_section=None, evm_section=None, genesis_alloc=None):
    bh = f"{height:064x}"
    # Genesis stores a datetime, exactly as validator/genesis_init.py does; later blocks store
    # their integer slot timestamp. A rebuild that parsed every timestamp as an int once
    # crashed at height 0 — after it had already cleared account_state.
    ts = datetime.fromtimestamp(TS0, tz=timezone.utc) if height == 0 else TS0 + height
    await db.add_block(block_hash=bh, block_height=height, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=ts)
    for i, (recipient, amount) in enumerate(genesis_alloc or []):
        await db.add_transaction(
            tx_hash=f"alloc-{height}-{i}",
            tx_hex=json.dumps({"type": "genesis_allocation",
                               "recipient": recipient, "amount": str(amount)}),
            block_hash=bh)
    if ex_section:
        await db.add_block_exchange_txs(bh, ex_section)
    if evm_section:
        await db.add_block_evm_txs(bh, evm_section)
    return bh


def _stake_deposit(key, nonce=0):
    addr = key.public_key.to_address()
    tx = ExchangeTransaction(
        op_type=ExchangeOpType.STAKE_DEPOSIT, sender=addr, nonce=nonce,
        params={"validator_public_key": key.public_key.to_hex(),
                "stake_amount": str(MIN_VALIDATOR_STAKE)},
        gas_limit=2_000_000, gas_price=10**9)
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return encode_exchange_txs([tx])


def _pq_spend(key, qrdx, nonce=0):
    """A signed type-0x51 value transfer from ``key``'s account to RECIPIENT."""
    tx = PQTransaction(chain_id=CHAIN_ID, nonce=nonce, gas_price=0, gas_limit=300_000,
                       to=bytes.fromhex(RECIPIENT[2:]), value=int(qrdx) * WEI, data=b"")
    return "0x" + tx.sign(key).encode().hex()


def _executor(db, sm):
    """Value transfer with the importer's balance view (see module docstring)."""
    sync = StateSyncManager(db, sm)

    async def execute_tx(raw, height, block_hash, _ts):
        await sync.ensure_tables_exist()
        p = parse_eth_raw_tx(raw)
        sender, to, value = p["sender"], p["to"], int(p["value"])
        await sync.sync_address_to_evm(address=sender, block_height=height, block_hash=block_hash)
        await sync.sync_address_to_evm(address=to, block_height=height, block_hash=block_hash)
        src = await sm.get_account(sender)
        ok = src.balance >= value
        if ok:
            dst = await sm.get_account(to)
            dst.balance += value
            await sm.set_account(dst)
            src.balance -= value
        src.nonce = int(p["nonce"]) + 1
        await sm.set_account(src)
        return {"success": ok, "tx_hash": p["tx_hash"], "sender": sender, "nonce": p["nonce"]}
    return execute_tx


def _set_flags(mgr):
    """The production enforcement set, through the one function every path uses."""
    BP.apply_enforcement(mgr)


# ── the three paths ───────────────────────────────────────────────────────

async def _forward(db, tip, withdrawals_at=None):
    """A node that never reorged: per block, exchange → EVM → withdrawals (the importer order)."""
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    _set_flags(mgr)
    sm = ContractStateManager(db)
    execute = _executor(db, sm)
    for h in range(tip + 1):
        bh = f"{h:064x}"
        section = await db.get_block_exchange_txs(bh)
        if section:
            txs = BP.decode_exchange_txs(section)
            await BP.preload_sender_balances(db, txs, mgr)
            await BP.preload_token_balances(db, txs, mgr)
            ok, err, _ = BP.process_exchange_transactions(h, float(TS0 + h), txs, mgr)
            assert ok, err
            mgr.commit_block()
            await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
            await BP.flush_token_balance_deltas(db, mgr)
        evm = await db.get_block_evm_txs(bh)
        if evm:
            root, _ = await produce_block_evm_section(h, bh, TS0 + h, evm, db, sm, execute)
            assert root is not None
        if withdrawals_at and h in withdrawals_at:
            await WD.apply_withdrawals(db, withdrawals_at[h], h)
    await db.connection.commit()
    return await db.get_account_state_root()


async def _by_domain(db):
    """The rebuild this replaces: all EVM, then all exchange, then all withdrawals."""
    sm = ContractStateManager(db)
    await rebuild_account_state_from_chain(db, sm, _executor(db, sm))
    await db.clear_token_balances()
    ExchangeStateManager.reset_instance()
    await BP.rebuild_exchange_state_from_chain(db, flush_to_account_state=True)
    await WD.reapply_withdrawal_ledger(db)
    await db.connection.commit()
    return await db.get_account_state_root()


async def _interleaved(db):
    sm = ContractStateManager(db)
    res = await rebuild_derived_state_interleaved(db, sm, _executor(db, sm))
    assert res["account_root"] == await db.get_account_state_root()
    return res["account_root"]


async def _balances(db, *addrs):
    return tuple([await db.get_address_balance(a) for a in addrs])


# ── chains ────────────────────────────────────────────────────────────────

STAKE_GAS = fee_of(ExchangeOpType.STAKE_DEPOSIT)


async def _stake_then_spend_chain(db):
    """Genesis 150k; block 1 stakes 100k; block 2 tries to EVM-spend 120k."""
    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    await _add_block(db, 0, genesis_alloc=[(addr, "150000")])
    await _add_block(db, 1, ex_section=_stake_deposit(key))
    await _add_block(db, 2, evm_section=[_pq_spend(key, 120_000)])
    return addr


async def _withdrawal_then_spend_chain(db):
    """Genesis 1k; block 1 pays a 100k withdrawal; block 2 EVM-spends 50k of it."""
    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    await _add_block(db, 0, genesis_alloc=[(addr, "1000")])
    await _add_block(db, 1)
    await _add_block(db, 2, evm_section=[_pq_spend(key, 50_000)])
    return addr, {1: [(addr, 3, MIN_VALIDATOR_STAKE)]}


async def test_stake_debit_then_evm_spend_rebuilds_like_forward():
    db, path = await _db()
    try:
        addr = await _stake_then_spend_chain(db)
        fwd_root = await _forward(db, 2)
        fwd = await _balances(db, addr, RECIPIENT)
        # Forward semantics: the stake is locked (and its gas paid), so the 120k spend
        # cannot be covered.
        assert fwd == (Decimal("50000") - STAKE_GAS, Decimal("0")), fwd

        assert await _interleaved(db) == fwd_root, "interleaved rebuild diverges from forward"
        assert await _balances(db, addr, RECIPIENT) == fwd
    finally:
        await db.close()
        os.remove(path)


async def test_withdrawal_then_evm_spend_rebuilds_like_forward():
    db, path = await _db()
    try:
        addr, paid = await _withdrawal_then_spend_chain(db)
        fwd_root = await _forward(db, 2, withdrawals_at=paid)
        fwd = await _balances(db, addr, RECIPIENT)
        # Forward semantics: the withdrawal funds the spend.
        assert fwd == (Decimal("51000"), Decimal("50000")), fwd

        assert await _interleaved(db) == fwd_root, "interleaved rebuild diverges from forward"
        assert await _balances(db, addr, RECIPIENT) == fwd
    finally:
        await db.close()
        os.remove(path)


async def test_by_domain_rebuild_diverges_on_the_stake_chain():
    """Sensitivity: this chain really depends on ordering (the bug the fix removes)."""
    db, path = await _db()
    try:
        addr = await _stake_then_spend_chain(db)
        fwd_root = await _forward(db, 2)
        fwd = await _balances(db, addr, RECIPIENT)
        assert await _by_domain(db) != fwd_root
        # The by-domain replay let the spend through and then rejected the stake.
        assert await _balances(db, addr, RECIPIENT) != fwd
    finally:
        await db.close()
        os.remove(path)


async def test_by_domain_rebuild_diverges_on_the_withdrawal_chain():
    db, path = await _db()
    try:
        addr, paid = await _withdrawal_then_spend_chain(db)
        fwd_root = await _forward(db, 2, withdrawals_at=paid)
        assert await _by_domain(db) != fwd_root
    finally:
        await db.close()
        os.remove(path)


async def test_interleaved_rebuild_is_idempotent():
    """Rebuilding twice gives the same state — nothing is applied on top of the last run."""
    db, path = await _db()
    try:
        addr, paid = await _withdrawal_then_spend_chain(db)
        await _forward(db, 2, withdrawals_at=paid)
        first = await _interleaved(db)
        assert await _interleaved(db) == first
    finally:
        await db.close()
        os.remove(path)


async def test_interleaved_rebuild_without_evm_orders_exchange_and_withdrawals():
    """
    A node running without EVM has the same ordering hazard between exchange ops and
    withdrawals: a withdrawal paid at block 1 funds a STAKE_DEPOSIT at block 2. The old
    EVM-less rebuild ran every exchange section before re-crediting any withdrawal, so the
    deposit was rejected on rebuild but accepted forward.
    """
    db, path = await _db()
    try:
        key = PQPrivateKey.generate()
        addr = key.public_key.to_address()
        await _add_block(db, 0, genesis_alloc=[(addr, "10000")])
        await _add_block(db, 1)
        await _add_block(db, 2, ex_section=_stake_deposit(key))
        fwd_root = await _forward(db, 2, withdrawals_at={1: [(addr, 3, MIN_VALIDATOR_STAKE)]})
        assert await db.get_address_balance(addr) == Decimal("10000") - STAKE_GAS, (
            "forward: the withdrawal funds the deposit, which then locks it again")

        res = await rebuild_derived_state_interleaved(db)
        assert res["account_root"] == fwd_root
        assert res["evm"] == 0
    finally:
        await db.close()
        os.remove(path)


def test_account_ids_are_what_the_ledger_keys():
    """The chain helpers rely on PQ senders and ledger rows sharing one key."""
    key = PQPrivateKey.generate()
    tx = parse_eth_raw_tx(_pq_spend(key, 1))
    assert to_account_id(tx["sender"]) == to_account_id(key.public_key.to_address())


async def test_the_real_rollback_hook_replays_in_forward_order():
    """
    Drives ``_rebuild_derived_state_after_rollback`` — what the reorg, tie-break and
    rejected-block paths all call — on an EVM-less node, rather than the module alone.

    Chain: a withdrawal paid at block 1 funds a STAKE_DEPOSIT at block 2; block 3 paid a
    second withdrawal and is then rolled back. The hook must (a) drop block 3's orphaned
    withdrawal, (b) re-credit block 1's exactly once, and (c) replay it BEFORE block 2's
    deposit so the deposit is accepted again — the old by-domain rebuild rejected it.
    """
    from qrdx.node import main as node_main

    db, path = await _db()
    try:
        key = PQPrivateKey.generate()
        addr = key.public_key.to_address()
        await _add_block(db, 0, genesis_alloc=[(addr, "10000")])
        await _add_block(db, 1)
        await _add_block(db, 2, ex_section=_stake_deposit(key))
        await _add_block(db, 3)
        paid = {1: [(addr, 3, MIN_VALIDATOR_STAKE)], 3: [(addr, 4, Decimal("5000"))]}
        await _forward(db, 3, withdrawals_at=paid)
        assert await db.get_address_balance(addr) == Decimal("15000") - STAKE_GAS

        await db.remove_blocks(3)
        await db.connection.commit()

        saved = node_main.db, node_main.EVM_STATE_MANAGER
        node_main.db, node_main.EVM_STATE_MANAGER = db, None
        try:
            await node_main._rebuild_derived_state_after_rollback()
        finally:
            node_main.db, node_main.EVM_STATE_MANAGER = saved

        cur = await db.connection.execute(
            "SELECT block_height FROM validator_withdrawals ORDER BY block_height")
        assert [r[0] for r in await cur.fetchall()] == [1], "orphaned withdrawal survived"
        # 10k genesis + 100k withdrawal − 100k stake − its gas: the deposit was accepted again.
        assert await db.get_address_balance(addr) == Decimal("10000") - STAKE_GAS
    finally:
        await db.close()
        os.remove(path)
