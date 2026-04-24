"""
S06 — AMM Pool Operations

Verifies the real concentrated-liquidity AMM stack end to end:
  1. Create the standard persisted pools
  2. Add real concentrated liquidity to qETH/qUSDC
  3. Execute a persisted swap with token escrow transfers
  4. Verify pool state and DB consistency
"""

from decimal import Decimal

from integration_tests.pool_operator import PoolOperator
from integration_tests.scenarios.base import Scenario
from integration_tests.token_deployer import TokenDeployer


class S06Pools(Scenario):
    name = "s06_pools"
    description = "Verify AMM pool operations"
    depends_on = ["s05_tokens"]

    async def execute(self) -> None:
        db_path = self.ctx.db_paths[0]
        wallets = self.ctx.wallets

        pool_creator = wallets.get("Pool Creator")
        deployer_wallet = wallets.get("Token Deployer")
        trader_wallet = wallets.get("Test User 0")

        if not pool_creator or not deployer_wallet or not trader_wallet:
            self.check(False, "Pool, deployer, and trader wallets available")
            return

        pool_creator_addr = pool_creator["address"]
        deployer_addr = deployer_wallet["address"]
        trader_addr = trader_wallet["address"]

        async with TokenDeployer(db_path) as deployer:
            loaded = await deployer.load_existing_tokens()
            if len(loaded) < 4:
                loaded = await deployer.deploy_standard_tokens(deployer_addr)
            self.check(len(loaded) >= 4, f"Token set available for AMM ({len(loaded)})")

            async with PoolOperator(db_path, token_deployer=deployer) as operator:
                pools = await operator.create_standard_pools(creator=pool_creator_addr)
                self.check(len(pools) >= 4, f"Standard pools created ({len(pools)})")

                target_pool = None
                for pool in pools.values():
                    if pool.state.token0 == "qETH" and pool.state.token1 == "qUSDC":
                        target_pool = pool
                        break

                self.check(target_pool is not None, "qETH/qUSDC pool available")
                if target_pool is None:
                    return

                pool_id = target_pool.state.id
                spacing = target_pool.state.fee_tier.tick_spacing
                center = (target_pool.state.tick // spacing) * spacing
                tick_lower = center - (10 * spacing)
                tick_upper = center + (10 * spacing)
                liquidity = Decimal("5000")

                qeth_needed, qusdc_needed = operator.calculate_token_amounts(
                    pool_id=pool_id,
                    tick_lower=tick_lower,
                    tick_upper=tick_upper,
                    liquidity=liquidity,
                )

                # Seed LP and trader balances for real escrow + swap flows.
                await deployer.transfer("qETH", deployer_addr, pool_creator_addr, qeth_needed + Decimal("100"))
                await deployer.transfer("qUSDC", deployer_addr, pool_creator_addr, qusdc_needed + Decimal("50000"))
                await deployer.transfer("qUSDC", deployer_addr, trader_addr, Decimal("2000"))

                lp_pos = await operator.add_liquidity_persisted(
                    pool_id=pool_id,
                    owner=pool_creator_addr,
                    tick_lower=tick_lower,
                    tick_upper=tick_upper,
                    amount=liquidity,
                )
                self.check(lp_pos is not None, "Liquidity position created")
                self.check(
                    operator.get_pool_liquidity(pool_id) is not None and operator.get_pool_liquidity(pool_id) > 0,
                    "Pool has active liquidity",
                )

                bal_before_in = await deployer.get_balance("qUSDC", trader_addr)
                bal_before_out = await deployer.get_balance("qETH", trader_addr)

                amount_out, fee = await operator.swap_persisted(
                    pool_id=pool_id,
                    amount_in=Decimal("250"),
                    zero_for_one=False,  # qUSDC -> qETH
                    sender=trader_addr,
                    min_amount_out=Decimal("0"),
                )
                self.check(amount_out > 0, f"Swap produced output ({amount_out})")
                self.check(fee >= 0, f"Swap fee recorded ({fee})")

                bal_after_in = await deployer.get_balance("qUSDC", trader_addr)
                bal_after_out = await deployer.get_balance("qETH", trader_addr)

                self.check(bal_after_in < bal_before_in, "Trader input token debited")
                self.check(bal_after_out > bal_before_out, "Trader output token credited")

                consistent = await operator.verify_pool_consistency(pool_id)
                self.check(consistent, "Pool memory/DB consistency verified")

                stats = await operator.get_pool_stats(pool_id)
                self.check(int(stats.get("positions", 0)) >= 1, "At least one LP position tracked")

                self.ctx.artifacts["s06_pool_id"] = pool_id
                self.ctx.artifacts["s06_pool_stats"] = stats
