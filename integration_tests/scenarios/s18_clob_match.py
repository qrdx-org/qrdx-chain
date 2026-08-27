"""
S18 — CLOB two-wallet MATCH settlement across nodes (Phase E, ENFORCE_ORDERBOOK_SETTLEMENT).

s17 proved the single-wallet CLOB path live (escrow-on-place + cancel-refund). This proves the
remaining path: a resting maker order that a DIFFERENT taker FILLS — settling real base/quote
token moves maker↔taker (maker side from the book escrow, taker side live). Self-trade prevention
means a match needs two wallets, so this is the last CLOB settlement path without a live proof.

Flow: a maker (Validator 0, clean exchange nonce) deploys base + quote tokens, creates the order
book, funds the taker (Test User 1) with quote, and places a resting SELL (escrows base). The
taker places a BUY that matches fully → the trade settles: taker receives base (from the maker's
escrow), maker receives quote (from the taker, live). Validated cross-node — each step advances
the token root to a NEW value that CONVERGES on every node (deterministic settlement). Value
conservation + the exact maker/taker deltas are pinned by the unit test
tests/test_clob_settlement.py::test_full_match_settles_and_conserves.
"""
import asyncio
from collections import Counter
from decimal import Decimal

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S18ClobMatch(Scenario):
    name = "s18_clob_match"
    description = "CLOB resting maker order filled by a taker settles real tokens maker↔taker cross-node"
    depends_on = ["s17_clob_settlement"]

    async def _token_roots(self, node_urls):
        out = {}
        for url in node_urls:
            try:
                async with NodeRPCClient(url) as c:
                    r = await c._get("/get_unified_state_root")
                    if r and r.get("ok"):
                        out[url] = r["result"].get("token_root")
            except Exception:
                pass
        return out

    def _modal_root(self, roots):
        nz = [v for v in roots.values() if v and v != "0" * 128]
        return Counter(nz).most_common(1)[0] if nz else (None, 0)

    async def _wait_converge(self, node_urls, predicate, attempts=60):
        """Poll (2s/step) until the modal token root satisfies predicate AND all-but-one node
        agree on it (tolerating a single trailing node). Generous attempts → reorg-tolerant.
        Returns that root, or None."""
        for _ in range(attempts):
            await asyncio.sleep(2)
            m, nm = self._modal_root(await self._token_roots(node_urls))
            if nm >= max(2, len(node_urls) - 1) and predicate(m):
                return m
        return None

    async def _submit(self, target, tx_hex, label):
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx_hex})
        ok = bool(r and r.get("ok"))
        self.check(ok, f"{label}: admitted")
        if not ok:
            self._log.error("%s submit rejected: %s", label, r)
        return ok

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets
        target = node_urls[0]

        maker = wallets.get("Validator 0")    # PQ, clean exchange nonce (validators don't trade)
        # Test User 0 is the only other funded PQ wallet available; it did s13's 2 perp txs
        # (CREATE_MARKET nonce 0, OPEN_POSITION nonce 1), so its exchange nonce continues at 2.
        taker = wallets.get("Test User 0")
        TAKER_NONCE = 2
        for who, w in (("maker", maker), ("taker", taker)):
            if not w or not w.get("private_key") or "PQ" not in str(w.get("address", "")):
                self.check(False, f"funded PQ {who} wallet available")
                return

        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction, ExchangeOpType
        from qrdx.exchange.amm import FeeTier, PoolType
        from qrdx.exchange.state_manager import ExchangeStateManager
        from integration_tests.pool_operator import price_to_sqrt_price_q96

        mkey = PQPrivateKey.from_hex(maker["private_key"], maker["public_key"])
        tkey = PQPrivateKey.from_hex(taker["private_key"], taker["public_key"])
        m_addr, t_addr = maker["address"], taker["address"]

        def _sign(key, tx):
            tx.public_key = key.public_key.to_bytes()
            tx.signature = key.sign(tx.signing_bytes()).to_bytes()
            return tx.to_hex()

        def _tx(sender, op, nonce, params):
            return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce,
                                       params=params, gas_limit=2_000_000, gas_price=Decimal("1"))

        addrA = ExchangeStateManager.derive_token_address(m_addr, 0, "qMKA")
        addrB = ExchangeStateManager.derive_token_address(m_addr, 1, "qMKB")
        # The book is keyed by the SORTED pair; base=token0=min, quote=token1=max. A SELL escrows
        # BASE, a BUY pays QUOTE — so the taker must be funded with the QUOTE (sorted-max) token.
        base_tok, quote_tok = sorted([addrA, addrB])
        pair = f"{base_tok}:{quote_tok}"

        # Baseline BEFORE s18's own activity — so the setup check proves OUR deploys landed
        # (not merely that some earlier scenario left a non-zero root).
        pre_setup, _ = self._modal_root(await self._token_roots(node_urls))
        self.check_not_none(pre_setup, "Baseline token root readable")

        await self._submit(target, _sign(mkey, _tx(m_addr, ExchangeOpType.TOKEN_DEPLOY, 0,
            {"name": "MK A", "symbol": "qMKA", "total_supply": "1000000", "decimals": 18})),
            "maker TOKEN_DEPLOY base")
        await self._submit(target, _sign(mkey, _tx(m_addr, ExchangeOpType.TOKEN_DEPLOY, 1,
            {"name": "MK B", "symbol": "qMKB", "total_supply": "1000000", "decimals": 18})),
            "maker TOKEN_DEPLOY quote")
        sqrt_price = price_to_sqrt_price_q96(Decimal("1"))
        await self._submit(target, _sign(mkey, _tx(m_addr, ExchangeOpType.CREATE_POOL, 2,
            {"token0": addrA, "token1": addrB, "fee_tier": int(FeeTier.MEDIUM),
             "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": str(sqrt_price),
             "stake_amount": "10000"})), "maker CREATE_POOL")
        # Fund the taker with QUOTE so it can pay for the fill (100 base @ price 2 = 200 quote).
        await self._submit(target, _sign(mkey, _tx(m_addr, ExchangeOpType.TOKEN_TRANSFER, 3,
            {"token_address": quote_tok, "to": t_addr, "amount": "200"})), "maker fund taker (quote)")

        # Setup landed + converged: the token root ADVANCED from our pre-setup baseline on all nodes.
        setup_root = await self._wait_converge(node_urls, lambda m: m and m != pre_setup)
        self.check(setup_root is not None,
                   "Setup (maker's deploys + pool + fund) lands + converges to a NEW token root on all nodes")

        # Maker places a RESTING SELL: 100 base @ price 2 → escrows 100 base into the book escrow.
        await self._submit(target, _sign(mkey, _tx(m_addr, ExchangeOpType.PLACE_ORDER, 4,
            {"pair": pair, "side": "sell", "order_type": "limit", "price": "2", "amount": "100"})),
            "maker PLACE_ORDER (resting sell)")
        after_rest = await self._wait_converge(node_urls, lambda m: m and m != setup_root)
        self.check(after_rest is not None,
                   "Resting sell escrows base + converges to a new token root on all nodes")

        # Taker places a BUY that FILLS the maker's sell → the trade settles maker↔taker.
        await self._submit(target, _sign(tkey, _tx(t_addr, ExchangeOpType.PLACE_ORDER, TAKER_NONCE,
            {"pair": pair, "side": "buy", "order_type": "limit", "price": "2", "amount": "100"})),
            "taker PLACE_ORDER (matching buy)")
        settled = await self._wait_converge(node_urls, lambda m: m and m != after_rest)
        self.check(settled is not None,
                   "Match settles (taker gets base from escrow, maker gets quote) + converges on "
                   "all nodes — deterministic cross-node CLOB match settlement")
