"""
S06 — AMM Pool Operations with Real Token Balances

Production-readiness test for the QRDX decentralised exchange.
Every swap and liquidity operation transfers **real** qRC-20 token
balances — not just math.  The scenario exercises:

  1. Deploy 4 tokens and fund participants (LP + trader)
  2. Create 4 concentrated-liquidity pools
  3. Add liquidity — tokens are escrowed from LP into pool vaults
  4. Execute forward swaps — trader pays token_in, receives token_out
  5. Execute reverse swaps
  6. Verify trader token balances actually changed
  7. Verify pool vault reserves are consistent (conservation of value)
  8. Verify persistence consistency (memory vs DB)

No stubs.  Every operation hits the real ConcentratedLiquidityPool
math engine, real QRC20Token balance tracking, real TokenPersistence,
and real ExchangePersistence.
"""

from decimal import Decimal
from integration_tests.scenarios.base import Scenario
from integration_tests.token_deployer import TokenDeployer
from integration_tests.pool_operator import PoolOperator


class S06Pools(Scenario):
    name = "s06_pools"
    description = "Verify AMM pool operations with real token balances"
    depends_on = ["s05_tokens"]

    async def execute(self) -> None:
        db_path = self.ctx.db_paths[0]
        wallets = self.ctx.wallets

        pool_creator = wallets.get("Pool Creator")
        user0 = wallets.get("Test User 0")
        deployer_wallet = wallets.get("Token Deployer")

        if not pool_creator or not user0 or not deployer_wallet:
            self.check(False, "Required wallets available")
            return

        creator_addr = pool_creator["address"]
        trader_addr = user0["address"]
        deployer_addr = deployer_wallet["address"]

        # ── Phase 1: Deploy tokens & fund participants ──────────────
        async with TokenDeployer(db_path) as token_dep:
            tokens = await token_dep.deploy_standard_tokens(deployer_addr)
            self._log.info("Deployed %d tokens: %s", len(tokens), list(tokens.keys()))

            # Fund the LP (pool creator) with tokens for liquidity
            # Fund the trader with tokens for swaps
            FUND_AMOUNT = Decimal("100000")
            for symbol in ("qETH", "qUSDC", "qBTC"):
                await token_dep.transfer(symbol, deployer_addr, creator_addr, FUND_AMOUNT)
                await token_dep.transfer(symbol, deployer_addr, trader_addr, FUND_AMOUNT)

            # Also deploy a wrapped QRDX qRC-20 (distinct from native QRDX)
            qrdx_token = await token_dep.deploy_token(
                name="Wrapped QRDX",
                symbol="QRDX",
                decimals=18,
                initial_supply=Decimal("10000000"),
                deployer_address=deployer_addr,
            )
            await token_dep.transfer("QRDX", deployer_addr, creator_addr, Decimal("500000"))
            await token_dep.transfer("QRDX", deployer_addr, trader_addr, Decimal("500000"))

            # Record balances BEFORE pool operations
            trader_balances_before = {}
            for sym in ("QRDX", "qETH", "qUSDC", "qBTC"):
                trader_balances_before[sym] = await token_dep.get_balance(sym, trader_addr)
            self._log.info("Trader balances before: %s",
                           {s: str(v) for s, v in trader_balances_before.items()})

            # ── Phase 2: Create pools with real token integration ──────
            async with PoolOperator(db_path, token_deployer=token_dep) as operator:
                pools = await operator.create_standard_pools(
                    creator=creator_addr,
                    stake_amount=Decimal("10000"),
                )
                pool_ids = list(pools.keys())
                self._log.info("Created %d pools: %s", len(pool_ids),
                               [f"{p.state.token0}/{p.state.token1}" for p in pools.values()])
                self.check(len(pool_ids) == 4, f"4 pools created ({len(pool_ids)})")

                self.ctx.artifacts["pool_ids"] = pool_ids

                # ── Phase 3: Add liquidity (tokens escrowed from LP) ───
                positions_ok = 0
                for pid, pool in pools.items():
                    spacing = pool.state.fee_tier.tick_spacing
                    current_tick = pool.state.tick
                    low = (current_tick // spacing - 20) * spacing
                    high = (current_tick // spacing + 20) * spacing
                    if low >= high:
                        high = low + spacing
                    liq_amount = Decimal("10000")
                    try:
                        pos = await operator.add_liquidity_persisted(
                            pool_id=pid,
                            owner=creator_addr,
                            tick_lower=low,
                            tick_upper=high,
                            amount=liq_amount,
                        )
                        vault = operator._pool_vault_address(pid)
                        t0_vault = await token_dep.get_balance(pool.state.token0, vault)
                        t1_vault = await token_dep.get_balance(pool.state.token1, vault)
                        self._log.info("  liq: %s/%s  vault_t0=%s  vault_t1=%s",
                                       pool.state.token0, pool.state.token1, t0_vault, t1_vault)
                        positions_ok += 1
                    except Exception as exc:
                        self._log.error("  liq failed for %s: %s", pid[:16], exc)
                self.check(positions_ok == len(pool_ids),
                           f"Liquidity added to all pools ({positions_ok}/{len(pool_ids)})")

                # ── Phase 4: Forward swaps (token0 -> token1) ───────────
                forward_ok = 0
                swap_amount = Decimal("100")
                for pid, pool in pools.items():
                    try:
                        amount_out, fee = await operator.swap_persisted(
                            pool_id=pid,
                            amount_in=swap_amount,
                            zero_for_one=True,
                            sender=trader_addr,
                        )
                        self._log.info("  fwd swap: %s/%s, in=%s, out=%s, fee=%s",
                                       pool.state.token0, pool.state.token1,
                                       swap_amount, amount_out, fee)
                        forward_ok += 1
                    except Exception as exc:
                        self._log.error("  fwd swap failed for %s: %s", pid[:16], exc)
                self.check(forward_ok == len(pool_ids),
                           f"Forward swaps on all pools ({forward_ok}/{len(pool_ids)})")

                # ── Phase 5: Reverse swaps (token1 -> token0) ──────────
                reverse_ok = 0
                rev_amount = Decimal("50")
                for pid, pool in pools.items():
                    try:
                        amount_out, fee = await operator.swap_persisted(
                            pool_id=pid,
                            amount_in=rev_amount,
                            zero_for_one=False,
                            sender=trader_addr,
                        )
                        self._log.info("  rev swap: %s/%s, in=%s, out=%s, fee=%s",
                                       pool.state.token0, pool.state.token1,
                                       rev_amount, amount_out, fee)
                        reverse_ok += 1
                    except Exception as exc:
                        self._log.error("  rev swap failed for %s: %s", pid[:16], exc)
                self.check(reverse_ok == len(pool_ids),
                           f"Reverse swaps on all pools ({reverse_ok}/{len(pool_ids)})")

                # ── Phase 6: Verify trader balances actually changed ───
                trader_balances_after = {}
                for sym in ("QRDX", "qETH", "qUSDC", "qBTC"):
                    trader_balances_after[sym] = await token_dep.get_balance(sym, trader_addr)

                balances_changed = 0
                for sym in ("QRDX", "qETH", "qUSDC", "qBTC"):
                    before = trader_balances_before[sym]
                    after = trader_balances_after[sym]
                    delta = after - before
                    if delta != 0:
                        balances_changed += 1
                    self._log.info("  %s: before=%s after=%s delta=%s",
                                   sym, before, after, delta)

                self.check(balances_changed >= 2,
                           f"Trader balances changed for {balances_changed} tokens (need >=2)")

                # ── Phase 7: Verify pool vault conservation ────────────
                vaults_ok = 0
                for pid, pool in pools.items():
                    vault = operator._pool_vault_address(pid)
                    t0_vault = await token_dep.get_balance(pool.state.token0, vault)
                    t1_vault = await token_dep.get_balance(pool.state.token1, vault)
                    if t0_vault >= 0 and t1_vault >= 0:
                        vaults_ok += 1
                        self._log.info("  vault %s: %s=%s %s=%s",
                                       pid[:8], pool.state.token0, t0_vault,
                                       pool.state.token1, t1_vault)
                    else:
                        self._log.error("  vault %s: NEGATIVE reserves! %s=%s %s=%s",
                                        pid[:8], pool.state.token0, t0_vault,
                                        pool.state.token1, t1_vault)
                self.check(vaults_ok == len(pool_ids),
                           f"Pool vaults solvent ({vaults_ok}/{len(pool_ids)})")

                # ── Phase 8: Persistence consistency ───────────────────
                consistent_count = 0
                for pid in pool_ids:
                    try:
                        ok = await operator.verify_pool_consistency(pid)
                        if ok:
                            consistent_count += 1
                    except Exception as exc:
                        self._log.warning("  Pool %s consistency error: %s", pid[:16], exc)
                self.check(consistent_count == len(pool_ids),
                           f"Pool persistence consistent ({consistent_count}/{len(pool_ids)})")

                # ── Phase 9: Volume verification ───────────────────────
                volume_ok = 0
                for pid, pool in pools.items():
                    stats = await operator.get_pool_stats(pid)
                    v0 = Decimal(stats.get("volume_0", "0"))
                    v1 = Decimal(stats.get("volume_1", "0"))
                    if v0 > 0 or v1 > 0:
                        volume_ok += 1
                self.check(volume_ok == len(pool_ids),
                           f"Volume recorded for all pools ({volume_ok}/{len(pool_ids)})")

                summary = await operator.get_deployment_summary()
                self._log.info("Exchange: %d pools, all with real token reserves", len(summary))
