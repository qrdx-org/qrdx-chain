"""
S19 — A forced perp liquidation and funding, cross-node (docs/PERPS_CLEARINGHOUSE.md, Phases 3–4).

The treasury seeder (the "Oracle Reporter" wallet, configured as QRDX_PERP_VAULT_SEEDERS) seeds
the backstop vault; a depositor adds to it. Test User 0 opens a 10x long against the Perp Trader on
the book; the validators' price feed then moves 10 % down and their votes carry the oracle there. In that block's tick the long is below 2/3 of maintenance with no
book to close into, so the vault takes it over at mark with the margin that was left. Every
node must agree on the result; the depositor then redeems shares worth more than they paid
(fees plus the liquidated margin); and the stablecoin perps settle in (qUSD) is conserved across
everyone involved and the clearinghouse holder.
"""

import asyncio
import time
from decimal import Decimal

from integration_tests.rpc_client import NodeRPCClient
from integration_tests.scenarios.s13_perp_collateral import (
    MARKET, S13PerpCollateral, stablecoin_address,
)


class S19PerpLiquidation(S13PerpCollateral):
    name = "s19_perp_liquidation"
    description = "A leveraged long is liquidated into the backstop vault identically on every node"
    depends_on = ["s13_perp_collateral"]

    async def execute(self) -> None:
        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeOpType

        node_urls = self.ctx.node_urls
        target = node_urls[0]
        wallets = self.ctx.wallets
        alice, bob, rep, lp, issuer = (
            wallets.get("Test User 0"), wallets.get("Perp Trader"), wallets.get("Oracle Reporter"),
            wallets.get("Vault Depositor"), wallets.get("Stablecoin Issuer"))
        for label, w in (("Test User 0", alice), ("Perp Trader", bob), ("Oracle Reporter", rep),
                         ("Vault Depositor", lp), ("Stablecoin Issuer", issuer)):
            if not w or not w.get("private_key") or "PQ" not in str(w.get("address", "")):
                self.check(False, f"{label} wallet available")
                return
        keys = {w["address"]: PQPrivateKey.from_hex(w["private_key"], w["public_key"])
                for w in (alice, bob, rep, lp, issuer)}

        async def submit(w, op, params, label):
            return await self._submit(target, w, keys[w["address"]], op, params, label)

        usd = stablecoin_address(wallets)
        for w, amount, label in ((rep, "1000", "the seeder"), (lp, "10000", "the depositor")):
            if not await submit(issuer, ExchangeOpType.TOKEN_TRANSFER,
                                {"token_address": usd, "to": w["address"], "amount": amount},
                                f"Pay {label} {amount} qUSD"):
                return

        holder = (await self._account(target, alice["address"]) or {}).get("holder_address")
        people = [alice["address"], bob["address"], rep["address"], lp["address"]]
        start = {a: await self._usd(target, a) for a in people + [holder]}
        if not self.check(all(v is not None for v in start.values()),
                          f"Starting qUSD balances readable: {start}"):
            return

        for w, op, params, label in [
            (rep, ExchangeOpType.PERP_DEPOSIT, {"amount": "500"}, "Seeder PERP_DEPOSIT 500"),
            (rep, ExchangeOpType.VAULT_DEPOSIT, {"amount": "500"}, "Treasury seed VAULT_DEPOSIT 500"),
            (lp, ExchangeOpType.PERP_DEPOSIT, {"amount": "5000"}, "Depositor PERP_DEPOSIT 5000"),
            (lp, ExchangeOpType.VAULT_DEPOSIT, {"amount": "5000"}, "Depositor VAULT_DEPOSIT 5000"),
        ]:
            if not await submit(w, op, params, label):
                return
        if not await self._set_price(node_urls, "qBTC", 30000, "Validators price qBTC at 30,000"):
            return
        for w, op, params, label in [
            (alice, ExchangeOpType.PERP_DEPOSIT, {"amount": "3500"}, "Alice PERP_DEPOSIT 3500"),
            (bob, ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"}, "Bob PERP_DEPOSIT 20000"),
            (bob, ExchangeOpType.PERP_ORDER, {"market_id": MARKET, "side": "sell", "size": "1",
                                              "price": "30000"}, "Bob rests a sell"),
            (alice, ExchangeOpType.PERP_ORDER, {"market_id": MARKET, "side": "buy", "size": "1",
                                                "price": "30000"}, "Alice lifts it at 10x"),
        ]:
            if not await submit(w, op, params, label):
                return

        acct = await self._account(target, lp["address"])
        shares = Decimal(acct["vault_shares"]) if acct else Decimal(0)
        protocol = Decimal(acct["vault"]["protocol_shares"]) if acct else Decimal(0)
        self.check(shares > 0, f"Depositor holds vault shares ({shares})")
        self.check(protocol >= Decimal(500),
                   f"The treasury seed is protocol-owned ({protocol} protocol shares)")

        async def opened(url):
            a = await self._account(url, alice["address"])
            return a["positions"].get(MARKET, {}).get("size") if a else None
        size = await self._converged(node_urls, opened, "Alice's long")
        self.check(size is not None and Decimal(size) == 1, f"Alice is long 1 ({size})")

        # 10 % down: equity 3,485 − 3,100 = 385, below 2/3 of the 672.5 maintenance, and no book.
        if not await self._set_price(node_urls, "qBTC", 26900, "Validators price qBTC at 26,900"):
            return

        async def liquidated(url):
            a = await self._account(url, alice["address"])
            if not a or MARKET in a["positions"]:
                return None
            vault_pos = a["vault"]["positions"].get(MARKET, {})
            return (a["collateral"], vault_pos.get("size"), vault_pos.get("entry_price"))
        after = await self._converged(node_urls, liquidated, "Liquidation outcome")
        if after is None:
            self.check(False, "Alice was liquidated")
            return
        collateral, vault_size, vault_entry = after
        self.check(Decimal(collateral) == 0, f"Alice's margin went to the vault ({collateral})")
        self.check(vault_size is not None and Decimal(vault_size) >= 1,
                   f"The vault took the long over ({vault_size} @ {vault_entry})")

        # The depositor redeems some shares: worth more than paid — fees + the liquidated margin.
        # Not before the deposit's lockup has passed in BLOCK time: a redemption included a
        # moment early is refused (it once was, when this scenario ran fast).
        redeem = min(shares, Decimal(1000))
        lp_acct = await self._account(target, lp["address"])
        wait = float(lp_acct.get("vault_unlock_time") or 0) - time.time() + 4
        if wait > 0:
            await asyncio.sleep(wait)
        before = Decimal((await self._account(target, lp["address"]))["collateral"])
        tx_hash = await submit(lp, ExchangeOpType.VAULT_WITHDRAW, {"shares": str(redeem)},
                               f"Depositor VAULT_WITHDRAW {redeem} shares")
        if not tx_hash:
            return
        gained = Decimal((await self._account(target, lp["address"]))["collateral"]) - before
        receipt = None
        if gained <= 0:
            async with NodeRPCClient(target) as c:
                receipt = await c._get("/get_exchange_receipt", params={"tx_hash": tx_hash})
        self.check(gained > redeem, f"Shares redeemed above cost: {redeem} shares → {gained}"
                   + (f" (receipt: {receipt})" if receipt else ""))

        for w, label in ((lp, "Depositor"), (bob, "Bob")):
            out = (await self._account(target, w["address"]))["withdrawable"]
            if Decimal(out) > 0 and not await submit(
                    w, ExchangeOpType.PERP_WITHDRAW, {"amount": out}, f"{label} PERP_WITHDRAW"):
                return

        # Funding is paid every interval of block time between the remaining positions (Bob's
        # short, the vault's long). Every node must have paid the same: one market state.
        async def market(url):
            r = await self._get(url, "/get_perp_market", {"market_id": MARKET})
            return None if not r else (r["funding_time"], r["funding_rate"], r["open_interest"])
        funding = await self._converged(node_urls, market, "Funding state")
        self.check(funding is not None and Decimal(funding[1]) != 0,
                   f"Funding has been paid at block-time boundaries ({funding})")

        async def balances(url):
            vals = [await self._usd(url, a) for a in people + [holder]]
            return None if any(v is None for v in vals) else tuple(str(v) for v in vals)
        final = await self._converged(node_urls, balances, "Final balances")
        if final is None:
            return
        moved = sum(Decimal(f) - Decimal(str(start[a])) for f, a in zip(final, people + [holder]))
        self.check(moved == 0, f"qUSD conserved across the traders, vault depositors and holder "
                               f"(net {moved})")
