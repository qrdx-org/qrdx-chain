"""
S24 — Delegation pools on the live chain (docs/STAKING.md, qrdx/validator/epoch_state.py).

Test User 0 delegates 10,000 QRDX to Validator 0 without running a validator. After the warm-up
every node shows the delegation as shares of Validator 0's pool, counting towards its weight; as
Validator 0 keeps voting, the pool earns the staking rate less its commission and the shares
grow in value, while Validator 0 is paid its own rewards and its commission. Test User 0 then
undelegates everything: after the unbonding period the principal and its rewards come back —
paid once, identically, on every node.
"""

import asyncio
from decimal import Decimal

from integration_tests.rpc_client import NodeRPCClient
from integration_tests.scenarios.s20_native_tokens import S20NativeTokens

AMOUNT = Decimal("10000")


class S24StakingPools(S20NativeTokens):
    name = "s24_staking_pools"
    description = "Delegation pools: delegate, shares grow with rewards, undelegate — cross-node"
    depends_on = []

    async def _rpc(self, url, method, params=None):
        try:
            async with NodeRPCClient(url) as c:
                return await c.json_rpc(method, params or [])
        except Exception:
            return None

    async def _balance(self, url, address):
        async with NodeRPCClient(url) as c:
            return await c.get_balance(address)

    async def _until(self, probe, want, tries=90, every=2.0):
        """Poll every node until ``want(views)`` holds; returns the last views."""
        views = {}
        for _ in range(tries):
            views = {url: await probe(url) for url in self.ctx.node_urls}
            if want(views):
                break
            await asyncio.sleep(every)
        return views

    async def execute(self) -> None:
        from qrdx.exchange import ExchangeOpType

        wallets = self.ctx.wallets
        user, validator = wallets.get("Test User 0"), wallets.get("Validator 0")
        if not (user and user.get("private_key") and validator):
            self.check(False, "Test User 0 and Validator 0 wallets available")
            return
        nodes = self.ctx.node_urls
        v_addr, u_addr = validator["address"], user["address"]

        start = await self._balance(nodes[0], u_addr)
        rec = await self._ok(nodes[0], user, ExchangeOpType.STAKE_DELEGATE,
                             {"validator": v_addr, "amount": str(AMOUNT)},
                             "Test User 0 delegates 10,000 QRDX to Validator 0")
        if not rec:
            return
        after = await self._balance(nodes[0], u_addr)
        self.check(start - after >= AMOUNT, f"The 10,000 QRDX left the delegator ({start} → {after})")

        async def stake(url):
            d = await self._rpc(url, "staking_getDelegations", [u_addr])
            mine = [s for s in (d or {}).get("stakes", []) if s["validator"] == v_addr]
            return mine[0] if mine else None

        views = await self._until(stake, lambda v: all(s and Decimal(s["shares"]) > 0
                                                       for s in v.values()))
        self.check(all(s and Decimal(s["shares"]) == AMOUNT for s in views.values()),
                   f"After the warm-up every node holds the delegation as 10,000 shares ({views})")

        async def validator_row(url):
            rows = await self._rpc(url, "staking_getValidators") or []
            return next((r for r in rows if r["address"] == v_addr), None)

        rows = await self._until(validator_row, lambda v: all(
            r and Decimal(r["delegated"]) >= AMOUNT for r in v.values()))
        self.check(all(r and Decimal(r["weight"]) >= Decimal(r["effective_stake"]) + AMOUNT
                       for r in rows.values()),
                   "The delegation counts towards Validator 0's weight on every node")

        grown = await self._until(stake, lambda v: all(
            s and Decimal(s["value"]) > AMOUNT for s in v.values()))
        self.check(all(s and Decimal(s["value"]) > AMOUNT for s in grown.values()),
                   f"The shares grow with the pool's rewards ({grown})")
        earned = await self._until(validator_row, lambda v: all(
            r and Decimal(r["earned"]) > 0 for r in v.values()))
        self.check(all(r and Decimal(r["earned"]) > 0 for r in earned.values()),
                   "Validator 0 is paid its own rewards and its commission")

        before_exit = await self._balance(nodes[0], u_addr)
        if not await self._ok(nodes[0], user, ExchangeOpType.STAKE_UNDELEGATE,
                              {"validator": v_addr, "shares": "all"},
                              "Test User 0 undelegates everything"):
            return

        async def owed(url):
            d = await self._rpc(url, "staking_getDelegations", [u_addr])
            return [p for p in (d or {}).get("payouts", []) if p["kind"] == "undelegation"]

        due = await self._until(owed, lambda v: all(v.values()))
        amounts = {url: Decimal(p[0]["amount"]) for url, p in due.items() if p}
        self.check(len(set(amounts.values())) == 1 and all(a > AMOUNT for a in amounts.values()),
                   f"Every node owes the delegator the same principal + rewards ({amounts})")
        owed_amount = next(iter(amounts.values()), Decimal(0))

        async def balance(url):
            return await self._balance(url, u_addr)

        paid = await self._until(balance, lambda v: all(
            b >= before_exit + owed_amount - Decimal("1") for b in v.values()), tries=120)
        self.check(len(set(paid.values())) == 1 and all(
            b >= before_exit + owed_amount - Decimal("1") for b in paid.values()),
            f"After unbonding the delegator is paid on every node, once ({paid})")
        await asyncio.sleep(10)
        again = {url: await balance(url) for url in nodes}
        self.check(again == paid or all(again[u] <= paid[u] + Decimal("1") for u in nodes),
                   f"…and not paid again ({again})")
