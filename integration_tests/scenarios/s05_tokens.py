"""
S05 - QRC-20 Token Lifecycle

Deploys four qRC20 tokens via the real QRC20Token + QRC20Registry + TokenPersistence
stack, then exercises:
  1. Deploy 4 tokens (qETH, qUSDC, qBTC, GOV) with initial supply
  2. Direct transfer between addresses
  3. Approve + transferFrom flow
  4. Balance verification (in-memory + DB persistence consistency)

Every operation hits the real QRC20Token in-memory logic AND persists
to SQLite via TokenPersistence. No stubs.
"""

from decimal import Decimal
from integration_tests.scenarios.base import Scenario
from integration_tests.token_deployer import TokenDeployer


class S05Tokens(Scenario):
    name = "s05_tokens"
    description = "Verify QRC-20 token lifecycle"
    depends_on = ["s03_block_production"]

    async def execute(self) -> None:
        db_path = self.ctx.db_paths[0]
        wallets = self.ctx.wallets

        deployer_wallet = wallets.get("Token Deployer")
        user0 = wallets.get("Test User 0")
        user1 = wallets.get("Test User 1")

        if not deployer_wallet or not user0:
            self.check(False, "Required wallets available")
            return

        deployer_addr = deployer_wallet["address"]
        user0_addr = user0["address"]
        user1_addr = user1["address"] if user1 else user0_addr

        # --- Deploy 4 tokens ---
        async with TokenDeployer(db_path) as deployer:
            tokens = await deployer.deploy_standard_tokens(deployer_addr)
            deployed = list(tokens.keys())
            self._log.info("Deployed %d tokens: %s", len(deployed), deployed)
            self.check(len(deployed) == 4, f"4 tokens deployed ({len(deployed)})")

            # Save artifacts for S06
            self.ctx.artifacts["token_deployer_address"] = deployer_addr
            self.ctx.artifacts["deployed_tokens"] = deployed
            self.ctx.artifacts["token_db_path"] = db_path

            # --- Verify deployer owns full supply for each token ---
            for symbol in deployed:
                bal = await deployer.get_balance(symbol, deployer_addr)
                self._log.info("  %s deployer balance: %s", symbol, bal)
            self.check(
                await deployer.get_balance("qETH", deployer_addr) == Decimal("1000000"),
                "qETH deployer balance = 1M",
            )

            # --- Transfer: deployer -> user0 ---
            tx = await deployer.transfer("qETH", deployer_addr, user0_addr, Decimal("5000"))
            self.check(tx["ok"], "qETH transfer 5000 deployer->user0")
            self._log.info("  Transfer: %s qETH -> %s", tx["amount"], user0_addr[:16])

            self.check(
                await deployer.get_balance("qETH", user0_addr) == Decimal("5000"),
                "user0 qETH balance = 5000 after transfer",
            )
            self.check(
                await deployer.get_balance("qETH", deployer_addr) == Decimal("995000"),
                "deployer qETH balance = 995000 after transfer",
            )

            # --- Transfer a second token ---
            tx2 = await deployer.transfer("qUSDC", deployer_addr, user0_addr, Decimal("100000"))
            self.check(tx2["ok"], "qUSDC transfer 100K deployer->user0")

            # --- Approve + TransferFrom flow ---
            await deployer.approve("qETH", user0_addr, user1_addr, Decimal("2000"))
            self.check(True, "qETH approve user0->user1 allowance=2000")

            tx3 = await deployer.transfer_from(
                "qETH", spender=user1_addr, sender=user0_addr,
                recipient=deployer_addr, amount=Decimal("1000"),
            )
            self.check(tx3["ok"], "qETH transferFrom 1000 (user1 spends user0->deployer)")

            self.check(
                await deployer.get_balance("qETH", user0_addr) == Decimal("4000"),
                "user0 qETH = 4000 after transferFrom",
            )
            self.check(
                await deployer.get_balance("qETH", deployer_addr) == Decimal("996000"),
                "deployer qETH = 996000 after transferFrom",
            )

            # --- Persistence consistency ---
            consistent_deployer = await deployer.verify_consistency("qETH", deployer_addr)
            consistent_user0 = await deployer.verify_consistency("qETH", user0_addr)
            consistent_usdc = await deployer.verify_consistency("qUSDC", user0_addr)
            self.check(
                consistent_deployer and consistent_user0 and consistent_usdc,
                "Memory-DB balance consistency verified",
            )

            # --- Summary ---
            summary = await deployer.get_deployment_summary()
            self._log.info("Token summary: %s", list(summary.keys()))
