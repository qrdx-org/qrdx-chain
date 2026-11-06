"""
The new trading features through the node's own block paths, end to end: forward application
(sections preloaded and flushed, blocks without exchange transactions ticked through
``tick_and_flush``) must equal the startup rebuild — the same exchange root, the same token ledger.

The chain exercises what runs in the tick of blocks that carry no exchange transactions: a spot
TWAP (its funds escrowed, then swapped slice by slice into a resting bid — real token moves in the
tick) and a perps buy stop placed by an agent key, fired once the mark drifts up to it; and a
token perp listed with liquidity, its oracle read off its token's pool and its vault quoting in
every tick. Plus a batch, an agent approval and an agent-signed transaction (its own nonce lane).
BTC is a genesis market, priced by the genesis validator's vote.
"""
import json
import os
import tempfile
from decimal import Decimal as D

import pytest

pytestmark = pytest.mark.usefixtures("genesis_btc")  # BTC from the first block

T0 = 1_700_000_000
BTC = "BTC-QRDX-PERP"


@pytest.fixture
def keys():
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    return {name: PQPrivateKey.generate() for name in ("rep", "mm", "tr", "bot")}


async def test_trading_features_forward_equal_the_rebuild(monkeypatch, keys):
    from qrdx import constants
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
    from qrdx.exchange import ExchangeOpType as Op
    from qrdx.exchange import ExchangeStateManager, ExchangeTransaction, encode_exchange_txs
    from qrdx.exchange import block_processor as BP

    addr = {n: k.public_key.to_address() for n, k in keys.items()}
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "QRDX")
    # A short spot TWAP and a low depth floor: the token perp's pool is small and young.
    monkeypatch.setattr(constants, "SPOT_ORACLE_TWAP_SECONDS", 60)
    monkeypatch.setattr(constants, "SPOT_ORACLE_MIN_DEPTH", 100)
    nonces = {}

    def vote(prices):
        t = ExchangeTransaction(op_type=Op.ORACLE_VOTE, sender=addr["rep"], nonce=1,
                                params={"prices": prices}, gas_limit=100_000, gas_price=10**9)
        t.public_key = keys["rep"].public_key.to_bytes()
        t.signature = keys["rep"].sign(t.signing_bytes()).to_bytes()
        return t

    def tx(who, op, params, signer=None):
        sender = addr[who]
        lane = f"{sender}|{addr[signer]}" if signer else sender
        t = ExchangeTransaction(op_type=op, sender=sender, nonce=nonces.get(lane, 0),
                                params=params, gas_limit=5_000_000, gas_price=10**9,
                                signer=addr[signer] if signer else "")
        nonces[lane] = nonces.get(lane, 0) + 1
        key = keys[signer or who]
        t.public_key = key.public_key.to_bytes()
        t.signature = key.sign(t.signing_bytes()).to_bytes()
        assert t.verify()
        return t

    tok = ExchangeStateManager.derive_token_address(addr["mm"], 0, "TOK")
    pair = f"{tok}:QRDX"
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        async def add(h, txs=None, alloc=None):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content=json.dumps(
                {"type": "genesis", "validators": 1,              # rep: the genesis validator
                 "validator_set": [{"address": addr["rep"], "stake": "1000"}]}) if h == 0 else "",
                               validator_address="0xPQ" + "00" * 32, timestamp=T0 + 6 * h)
            for i, (r, a) in enumerate(alloc or []):
                await db.add_transaction(tx_hash=f"a{h}{i}", block_hash=bh, tx_hex=json.dumps(
                    {"type": "genesis_allocation", "recipient": r, "amount": a}))
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(txs))

        await add(0, alloc=[(addr["mm"], "10000000"), (addr["rep"], "10000"),
                            (addr["tr"], "1000000")])
        await add(1, [
            vote({"BTC": "30000"}),
            tx("mm", Op.TOKEN_DEPLOY, {"name": "Token", "symbol": "TOK", "decimals": 6,
                                       "total_supply": "1000000"}),
            tx("rep", Op.PERP_DEPOSIT, {"amount": "3000"}),
            tx("mm", Op.PERP_DEPOSIT, {"amount": "1000000"}),
            tx("tr", Op.PERP_DEPOSIT, {"amount": "200000"}),
        ])
        await add(2, [
            tx("mm", Op.CREATE_POOL, {"token0": tok, "token1": "QRDX", "fee_tier": 3000,
                                      "pool_type": "STANDARD", "initial_price": "1",
                                      "stake_amount": "10000"}),
            tx("mm", Op.TOKEN_TRANSFER, {"token_address": tok, "to": addr["tr"],
                                         "amount": "1000"}),
            tx("tr", Op.AGENT_APPROVE, {"agent": addr["bot"], "name": "bot"}),
        ])
        await add(3, [
            tx("mm", Op.PLACE_ORDER, {"pair": pair, "side": "buy", "order_type": "limit",
                                      "price": "0.9", "amount": "1000"}),
            # The book sits over the oracle, so the mark drifts up through the quiet blocks.
            tx("mm", Op.PERP_ORDER, {"market_id": BTC, "side": "buy", "size": "1",
                                     "price": "30500"}),
            tx("mm", Op.PERP_ORDER, {"market_id": BTC, "side": "sell", "size": "5",
                                     "price": "30700"}),
            tx("tr", Op.TWAP_ORDER, {"token_in": tok, "token_out": "QRDX", "amount_in": "300",
                                     "duration": 120, "slices": 4, "max_slippage": "0.1"}),
            tx("tr", Op.PERP_TRIGGER, {"market_id": BTC, "side": "buy", "kind": "sl",
                                       "trigger_price": "30300", "size": "0.5",
                                       "limit_price": "30800"}, signer="bot"),
        ])
        await add(4, [tx("tr", Op.BATCH, {"actions": [
            {"op": "PERP_ORDER", "params": {"market_id": BTC, "side": "buy", "size": "0.1",
                                            "price": "20000"}},
            {"op": "PERP_ORDER", "params": {"market_id": BTC, "side": "buy", "size": "0.1",
                                            "price": "20001"}},
        ]})])
        for h in range(5, 30):                        # quiet blocks: no exchange transactions
            await add(h)
        # A second token and its pool, then (a TWAP's history later) its perp, listed with
        # liquidity: the protocol quotes its vault through the quiet blocks after.
        tk2 = ExchangeStateManager.derive_token_address(addr["mm"], nonces[addr["mm"]], "TK2")
        await add(30, [tx("mm", Op.TOKEN_DEPLOY, {"name": "Two", "symbol": "TK2",
                                                  "total_supply": "1000000"})])
        await add(31, [tx("mm", Op.CREATE_POOL, {"token0": tk2, "token1": "QRDX",
                                                 "fee_tier": 3000, "pool_type": "STANDARD",
                                                 "initial_price": "1", "stake_amount": "25"})])
        await add(32, [tx("mm", Op.ADD_LIQUIDITY, {"pool_id": "", "token0": tk2,
                                                   "token1": "QRDX", "amount": "100000",
                                                   "tick_lower": -60000, "tick_upper": 60000})])
        for h in range(33, 45):
            await add(h)
        await add(45, [tx("rep", Op.CREATE_MARKET, {"token": tk2, "liquidity": "2000"})])
        for h in range(46, 60):
            await add(h)
        tip = 59

        await db.clear_account_state()
        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(mgr)
        for h in range(1, tip + 1):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            ts = float(T0 + 6 * h)
            await BP.ensure_oracle_committee(db, mgr, h)
            if section:
                txs = BP.decode_exchange_txs(section)
                await BP.preload_sender_balances(db, txs, mgr, h)
                await BP.preload_token_balances(db, txs, mgr)
                ok, err, _ = BP.process_exchange_transactions(h, ts, txs, mgr)
                assert ok, err
                failed = [(r.error, t.op_type.name) for t, r in
                          zip(mgr._block_exchange_txs, mgr._block_results, strict=True)
                          if not r.success]
                assert not failed, failed
                mgr.commit_block()
                await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
                await BP.flush_token_balance_deltas(db, mgr)
            else:
                await BP.tick_and_flush(db, h, ts, mgr)
        await db.connection.commit()
        events = [(e["block_height"], e["type"]) for e in mgr.journal.events]

        from qrdx.exchange.clearinghouse import market_maker_address

        # The token perp's oracle follows its pool, and its vault quotes on its book.
        tp = mgr.clearinghouse.markets[f"{tk2}-QRDX-PERP"]
        assert abs(tp.oracle_price - 1) < D("0.01") and tp.spot_depth >= 100
        assert tp.mm_time > 0 and any(o.owner == market_maker_address(tp.id)
                                      for o in tp.orders.values())
        slices = [h for h, kind in events if kind == "twap_slice"]
        fired = [h for h, kind in events if kind == "trigger_fired"]
        assert len(slices) == 4 and all(h >= 5 for h in slices[1:]), events
        assert fired and fired[0] >= 5, events               # in a quiet block
        assert mgr.clearinghouse.accounts[addr["tr"]].positions[BTC].size == D("0.5")
        forward_root = mgr.compute_state_root()
        tr_tok = await db.get_token_balance(tok, addr["tr"])
        tr_qrdx = await db.get_address_balance(addr["tr"])
        escrow_tok = await db.get_token_balance(tok, mgr.orderbook_escrow_address(pair))
        mm_tok = await db.get_token_balance(tok, addr["mm"])
        assert tr_tok == 700                                 # 300 swapped out of its 1,000
        # The bid bought them, less its maker fee (0.02 % of what it received), which went to
        # the treasury less the stakers' share (to the fee holder, in the token); the TWAP paid
        # its taker fee out of the QRDX it received.
        from qrdx.validator.epoch_state import STAKER_FEE_HOLDER

        treasury = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
        maker_fee = D(300) * D("0.0002")
        stakers = maker_fee * D(constants.STAKER_FEE_SHARE_BPS) / 10_000
        assert mm_tok == 1_000_000 - 1000 + 300 - maker_fee
        assert await db.get_token_balance(tok, treasury) == maker_fee - stakers
        assert await db.get_token_balance(tok, STAKER_FEE_HOLDER) == stakers
        assert escrow_tok == 0

        await rebuild_derived_state_interleaved(db)
        mgr = ExchangeStateManager.get_instance()
        assert mgr.compute_state_root() == forward_root
        assert await db.get_token_balance(tok, addr["tr"]) == tr_tok
        assert await db.get_token_balance(tok, addr["mm"]) == mm_tok
        assert await db.get_address_balance(addr["tr"]) == tr_qrdx
    finally:
        ExchangeStateManager.reset_instance()
        path = db.db_path
        await db.close()
        os.remove(path)
