"""
Reorg-safety: the rebuild path must reproduce the SAME derived state as incremental
forward application, byte-for-byte.

A node that never reorgs builds account_state + token_balances by applying each block's
exchange section INCREMENTALLY as it arrives (preload → process → flush, never cleared).
A node that reorgs instead CLEARS those ledgers, reseeds genesis, and REBUILDS from the
canonical chain (rebuild_exchange_state_from_chain + the account reseed). For the SAME
canonical chain the two paths MUST yield the identical account_state root + token root —
otherwise a reorged node diverges from the network at equal tip (the recurring
"equal-tip derived-state divergence", E-D4=0 because block history matches).

This test drives BOTH paths over one deterministic chain (no network, no reorg timing)
and asserts the roots match. It is the deterministic reproducer for that divergence:
  * FAIL  → a real determinism bug in the rebuild logic (root cause, right here).
  * PASS  → the rebuild logic is equivalent; any field divergence is a concurrency/race
            during rollback→reseed→reflush, not a replay-nondeterminism.
"""

import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import (
    ExchangeStateManager, ExchangeTransaction, ExchangeOpType, encode_exchange_txs,
)
from qrdx.exchange.amm import FeeTier, PoolType
from qrdx.exchange import block_processor as BP


# --- helpers ---------------------------------------------------------------

async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


def _sign(tx, key):
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def _tx(op, sender, nonce, params):
    return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params,
                               gas_limit=2_000_000, gas_price=Decimal("1"))


async def _add_block(db, height, ex_section=None, genesis_alloc=None):
    bh = f"{height:064x}"
    await db.add_block(block_hash=bh, block_height=height, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000 + height)
    if genesis_alloc:
        for i, (recipient, amount) in enumerate(genesis_alloc):
            await db.add_transaction(
                tx_hash=f"alloc-{i}-{recipient[:8]}",
                tx_hex=json.dumps({"type": "genesis_allocation", "recipient": recipient,
                                   "amount": str(amount)}),
                block_hash=bh)
    if ex_section:
        await db.add_block_exchange_txs(bh, ex_section)
    return bh


async def _build_chain(db, k1, k2):
    """A rich but HONEST activity chain: token deploy/transfer (cross-holder token
    moves), a perp market traded on its order book (deposits move real QRDX into the
    clearinghouse holder), pool create+liquidity (pool stake debit + token escrow). Every op
    is affordable (canonical)."""
    t1, t2 = k1.public_key.to_address(), k2.public_key.to_address()
    tokenA = ExchangeStateManager.derive_token_address(t1, 0, "AAA")
    tokenB = ExchangeStateManager.derive_token_address(t1, 5, "BBB")
    pair = ":".join(sorted([tokenA, tokenB]))
    sqrtp = "79228162514264337593543950336"  # 1.0 in Q96

    await _add_block(db, 0, genesis_alloc=[(t1, "1000000"), (t2, "1000000")])
    await _add_block(db, 1, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.TOKEN_DEPLOY, t1, 0,
        {"name": "A", "symbol": "AAA", "total_supply": "1000000", "decimals": 18}), k1)]))
    await _add_block(db, 2, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.TOKEN_TRANSFER, t1, 1,
        {"token_address": tokenA, "to": t2, "amount": "100000"}), k1)]))
    # t2 is the configured oracle reporter (see _equivalence): a perp market cannot trade
    # until it has an oracle price.
    await _add_block(db, 3, encode_exchange_txs([
        _sign(_tx(ExchangeOpType.CREATE_MARKET, t1, 2,
                  {"base_token": "BTC", "max_leverage": "10", "initial_margin_rate": "0.1",
                   "maintenance_margin_rate": "0.05"}), k1),
        _sign(_tx(ExchangeOpType.UPDATE_ORACLE, t2, 0,
                  {"pair": "BTC:QRDX", "price": "30000"}), k2)]))
    await _add_block(db, 4, encode_exchange_txs([
        _sign(_tx(ExchangeOpType.PERP_DEPOSIT, t1, 3, {"amount": "10000"}), k1),
        _sign(_tx(ExchangeOpType.PERP_DEPOSIT, t2, 1, {"amount": "10000"}), k2),
        _sign(_tx(ExchangeOpType.PERP_ORDER, t2, 2,
                  {"market_id": "BTC-QRDX-PERP", "side": "sell", "size": "1",
                   "price": "30000"}), k2),
        _sign(_tx(ExchangeOpType.PERP_ORDER, t1, 4,
                  {"market_id": "BTC-QRDX-PERP", "side": "buy", "size": "1",
                   "price": "30000"}), k1)]))
    await _add_block(db, 5, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.TOKEN_DEPLOY, t1, 5,
        {"name": "B", "symbol": "BBB", "total_supply": "1000000", "decimals": 18}), k1)]))
    await _add_block(db, 6, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.CREATE_POOL, t1, 6,
        {"token0": tokenA, "token1": tokenB, "fee_tier": int(FeeTier.MEDIUM),
         "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": sqrtp,
         "stake_amount": "10000"}), k1)]))
    await _add_block(db, 7, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.ADD_LIQUIDITY, t1, 7,
        {"pool_id": "", "token0": tokenA, "token1": tokenB, "amount": "1000",
         "tick_lower": "-887220", "tick_upper": "887220"}), k1)]))
    return 7


def _set_flags(mgr):
    """
    Match the production FORWARD import path's enforcement set — EXACTLY.

    Every flag the forward path sets must be set here, because the whole point of
    these tests is that the rebuild's flag set equals the forward path's. A flag
    missing from one side is the divergence bug this file exists to catch (it is how
    the enforce_spot_settlement asymmetry was found).
    """
    mgr.enforce_collateral = BP.ENFORCE_EXCHANGE_COLLATERAL
    mgr.enforce_spot_settlement = BP.ENFORCE_SPOT_SETTLEMENT
    mgr.enforce_orderbook_settlement = BP.ENFORCE_ORDERBOOK_SETTLEMENT
    mgr.enforce_pool_stake = BP.ENFORCE_POOL_STAKE
    mgr.enforce_validator_stake = BP.ENFORCE_VALIDATOR_STAKE


def _forward_flag_names():
    """The flags the production forward path sets, for the coverage guard below."""
    return (
        "enforce_collateral",
        "enforce_spot_settlement",
        "enforce_orderbook_settlement",
        "enforce_pool_stake",
        "enforce_validator_stake",
    )


def test_rebuild_sets_every_forward_enforce_flag():
    """
    Guard against the recurring bug directly: the rebuild must set the SAME flags the
    forward path does. Reads both source sites rather than behaviour, so a newly added
    gate that is wired into only one path fails here immediately instead of surfacing as
    an equal-tip state divergence in a soak.
    """
    import inspect
    import pathlib
    import re

    from qrdx import derived_state_rebuild

    # The forward set is read from the importer itself, so a gate added there and nowhere
    # else is caught — not just one that is missing from a hardcoded list.
    main_src = (pathlib.Path(BP.__file__).parents[1] / "node" / "main.py").read_text()
    start = main_src.index("async def _apply_exchange_section_on_import(")
    body = main_src[start:main_src.index("\nasync def ", start + 1)]
    forward = set(re.findall(r"mgr\.(enforce_\w+) =", body))
    assert forward == set(_forward_flag_names()), (
        f"forward importer sets {sorted(forward)}; update _forward_flag_names")

    for fn in (BP.rebuild_exchange_state_from_chain,
               derived_state_rebuild.rebuild_derived_state_interleaved):
        rebuild_src = inspect.getsource(fn)
        for flag in forward:
            assert f"mgr.{flag} =" in rebuild_src, (
                f"{fn.__name__} does not set {flag!r} — a canonical op the forward path "
                f"rejected could be ACCEPTED on rebuild, diverging the reorged node at "
                f"equal tip")


async def _run_forward(db, tip):
    """Incremental forward application (mirrors _apply_exchange_section_on_import's
    trust-replay branch per block): the non-reorg node's path."""
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    _set_flags(mgr)
    for h in range(0, tip + 1):
        bh = f"{h:064x}"
        section = await db.get_block_exchange_txs(bh)
        if not section:
            continue
        txs = BP.decode_exchange_txs(section)
        await BP.preload_sender_balances(db, txs, mgr)
        await BP.preload_token_balances(db, txs, mgr)
        ok, err, _root = BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, mgr)
        assert ok, f"forward block {h} failed: {err}"
        mgr.commit_block()
        await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
        await BP.flush_token_balance_deltas(db, mgr)
    await db.connection.commit()
    return await db.get_account_state_root(), await db.get_token_balances_root()


async def _run_rebuild(db):
    """Reorg rebuild (mirrors _rebuild_derived_state_after_rollback, EVM-less branch):
    clear+reseed account_state, clear token ledger, then rebuild exchange on top."""
    await db.clear_account_state()
    await db.seed_genesis_account_state()
    await db.connection.commit()
    await db.clear_token_balances()
    ExchangeStateManager.reset_instance()
    await BP.rebuild_exchange_state_from_chain(db, flush_to_account_state=True)
    await db.connection.commit()
    return await db.get_account_state_root(), await db.get_token_balances_root()


# --- tests -----------------------------------------------------------------

async def _equivalence(monkeypatch, pool_stake: bool):
    if pool_stake:
        monkeypatch.setattr(BP, "ENFORCE_POOL_STAKE", True)
    db, path = await _db()
    try:
        k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        from qrdx import constants
        monkeypatch.setattr(constants, "ORACLE_REPORTERS", (k2.public_key.to_address(),))
        tip = await _build_chain(db, k1, k2)

        fwd_acct, fwd_tok = await _run_forward(db, tip)
        # The chain must actually DO what it claims. It once carried a CREATE_MARKET without
        # its required base_token and an ADD_LIQUIDITY without pool_id: both failed
        # non-critically on both paths, the roots still matched, and the perp-margin and
        # liquidity paths went untested behind a green result.
        mgr = ExchangeStateManager.get_instance()
        ch = mgr.clearinghouse
        assert ch.net_size("BTC-QRDX-PERP") == 0 and ch.markets["BTC-QRDX-PERP"].open_interest == 1, (
            "the perp trade never happened")
        assert any(p.state.liquidity > 0 for p in mgr.pool_manager._pools.values()), (
            "liquidity never added")
        rb_acct, rb_tok = await _run_rebuild(db)

        assert fwd_tok == rb_tok, (
            f"TOKEN root diverges: forward={fwd_tok[:16]} rebuild={rb_tok[:16]} "
            f"(pool_stake={pool_stake})")
        assert fwd_acct == rb_acct, (
            f"ACCOUNT_STATE root diverges: forward={fwd_acct[:16]} rebuild={rb_acct[:16]} "
            f"(pool_stake={pool_stake})")
    finally:
        await db.close()
        os.remove(path)


async def test_rebuild_equivalence_shipped_flags(monkeypatch):
    """Live/shipped enforcement set (collateral+spot+orderbook on, pool_stake off)."""
    await _equivalence(monkeypatch, pool_stake=False)


async def test_rebuild_equivalence_pool_stake_enforced(monkeypatch):
    """Same, with pool-stake enforce also on (the candidate flip)."""
    await _equivalence(monkeypatch, pool_stake=True)


async def test_rebuild_equivalence_with_rejected_spot_op(monkeypatch):
    """A canonical block may contain a spot op the FORWARD path rejects (enforce_spot
    _settlement on). The rebuild currently does NOT set enforce_spot_settlement — if the
    rebuild then ACCEPTS (moves value for) an op forward rejected, the reorged node
    diverges. Probes exactly that shipped asymmetry: an over-spending TOKEN_TRANSFER
    (T2 sends more AAA than it holds) included in a block."""
    db, path = await _db()
    try:
        k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        t1, t2 = k1.public_key.to_address(), k2.public_key.to_address()
        tokenA = ExchangeStateManager.derive_token_address(t1, 0, "AAA")

        await _add_block(db, 0, genesis_alloc=[(t1, "1000000"), (t2, "1000000")])
        await _add_block(db, 1, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.TOKEN_DEPLOY, t1, 0,
            {"name": "A", "symbol": "AAA", "total_supply": "1000000", "decimals": 18}), k1)]))
        await _add_block(db, 2, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.TOKEN_TRANSFER, t1, 1,
            {"token_address": tokenA, "to": t2, "amount": "1000"}), k1)]))
        # T2 holds 1000 AAA but tries to send 5000 → forward (spot enforce) REJECTS.
        await _add_block(db, 3, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.TOKEN_TRANSFER, t2, 0,
            {"token_address": tokenA, "to": t1, "amount": "5000"}), k2)]))

        # Forward tolerates a per-block op failure (the block is not rejected), so don't
        # assert ok on every block here — replicate _run_forward but lenient.
        await db.seed_genesis_account_state(); await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance(); _set_flags(mgr)
        for h in range(0, 4):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            if not section:
                continue
            txs = BP.decode_exchange_txs(section)
            await BP.preload_sender_balances(db, txs, mgr)
            await BP.preload_token_balances(db, txs, mgr)
            BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, mgr)
            mgr.commit_block()
            await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
            await BP.flush_token_balance_deltas(db, mgr)
        await db.connection.commit()
        fwd_tok = await db.get_token_balances_root()

        rb_acct, rb_tok = await _run_rebuild(db)
        assert fwd_tok == rb_tok, (
            f"TOKEN root diverges on a block with a forward-rejected spot op: "
            f"forward={fwd_tok[:16]} rebuild={rb_tok[:16]} — the rebuild must make the "
            f"same accept/reject decision the forward path did")
    finally:
        await db.close()
        os.remove(path)


async def test_rebuild_equivalence_native_token_ops(monkeypatch):
    """The native token standard on both paths: a zero-supply token with mint and freeze
    authorities, mints, an approval spent by transfer_from, a burn, a freeze that refuses a
    transfer, a thaw, and a handed-over mint authority. Forward and rebuild must agree on
    the token root, the registry (supply, authorities, allowances, freezes — exchange state)
    and its DB mirror; and the chain must have done what it says."""
    db, path = await _db()
    try:
        k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        t1, t2 = k1.public_key.to_address(), k2.public_key.to_address()
        tok = ExchangeStateManager.derive_token_address(t1, 0, "qBRG")

        def tx(op, key, sender, nonce, **params):
            return _sign(_tx(op, sender, nonce, params), key)

        await _add_block(db, 0, genesis_alloc=[(t1, "1000000"), (t2, "1000000")])
        await _add_block(db, 1, encode_exchange_txs([
            tx(ExchangeOpType.TOKEN_DEPLOY, k1, t1, 0, name="Bridged", symbol="qBRG",
               decimals=6, total_supply="0", mint_authority=t1, freeze_authority=t1)]))
        await _add_block(db, 2, encode_exchange_txs([
            tx(ExchangeOpType.TOKEN_MINT, k1, t1, 1, token_address=tok, amount="1000", to=t2),
            tx(ExchangeOpType.TOKEN_MINT, k1, t1, 2, token_address=tok, amount="500")]))
        await _add_block(db, 3, encode_exchange_txs([
            tx(ExchangeOpType.TOKEN_APPROVE, k2, t2, 0, token_address=tok, spender=t1,
               amount="300"),
            tx(ExchangeOpType.TOKEN_TRANSFER_FROM, k1, t1, 3, token_address=tok,
               **{"from": t2, "to": t1, "amount": "200"})]))
        await _add_block(db, 4, encode_exchange_txs([
            tx(ExchangeOpType.TOKEN_BURN, k2, t2, 1, token_address=tok, amount="100"),
            tx(ExchangeOpType.TOKEN_FREEZE, k1, t1, 4, token_address=tok, account=t2)]))
        await _add_block(db, 5, encode_exchange_txs([
            tx(ExchangeOpType.TOKEN_TRANSFER, k2, t2, 2, token_address=tok, to=t1,
               amount="10"),                                    # refused: frozen
            tx(ExchangeOpType.TOKEN_THAW, k1, t1, 5, token_address=tok, account=t2),
            tx(ExchangeOpType.TOKEN_TRANSFER, k2, t2, 3, token_address=tok, to=t1,
               amount="10")]))
        await _add_block(db, 6, encode_exchange_txs([
            tx(ExchangeOpType.TOKEN_SET_AUTHORITY, k1, t1, 6, token_address=tok,
               authority="mint", new_authority=t2),
            tx(ExchangeOpType.TOKEN_MINT, k2, t2, 4, token_address=tok, amount="1")]))

        await db.seed_genesis_account_state(); await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance(); _set_flags(mgr)
        results = []
        for h in range(0, 7):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            if not section:
                continue
            txs = BP.decode_exchange_txs(section)
            await BP.preload_sender_balances(db, txs, mgr)
            await BP.preload_token_balances(db, txs, mgr)
            ok, err, _root = BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, mgr)
            assert ok, err
            results += [(t.op_type.name, t.success, t.error) for t in txs]
            mgr.commit_block()
            await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
            await BP.flush_token_balance_deltas(db, mgr)
        await db.connection.commit()

        # The chain did what it says: one refusal (the frozen transfer), everything else landed.
        failed = [r for r in results if not r[1]]
        assert len(failed) == 1 and failed[0][0] == "TOKEN_TRANSFER" and "frozen" in failed[0][2], results
        t = mgr.tokens.get(tok)
        assert t.supply == Decimal("1401") and t.mint_authority == t2
        assert mgr.tokens.allowance(tok, t2, t1) == 100 and not mgr.tokens.frozen
        assert await db.get_token_balance(tok, t2) == Decimal("691")   # 1000 − 200 − 100 − 10 + 1 minted
        assert await db.get_token_balance(tok, t1) == Decimal("710")   # 500 + 200 + 10
        fwd = (await db.get_token_balances_root(), mgr.tokens.state_hash(),
               await (await db.connection.execute(
                   "SELECT * FROM token_registry ORDER BY token_address")).fetchall())

        _rb_acct, rb_tok = await _run_rebuild(db)
        rb_mgr = ExchangeStateManager.get_instance()
        rb = (rb_tok, rb_mgr.tokens.state_hash(),
              await (await db.connection.execute(
                  "SELECT * FROM token_registry ORDER BY token_address")).fetchall())
        assert fwd[0] == rb[0], "token root diverges"
        assert fwd[1] == rb[1], "token registry (exchange state) diverges"
        assert fwd[2] == rb[2], f"registry mirror diverges: {fwd[2]} vs {rb[2]}"
        assert dict(zip(("token_address", "name", "symbol", "decimals", "total_supply"),
                        fwd[2][0][:5]))["total_supply"] == "1401"
    finally:
        await db.close()
        os.remove(path)
