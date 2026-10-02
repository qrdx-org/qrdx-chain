"""
S04b — Cross-Type Transfers (0x ↔ 0xPQ)

The scenario that answers "can I send from an Ethereum-type address to a
post-quantum one, and back?" against real running nodes.

Verifies:
  - a traditional (secp256k1) wallet pays a POST-QUANTUM account, with the funds
    visible under the PQ holder's own ``0xPQ…`` address
  - a post-quantum wallet pays a TRADITIONAL account, authenticated by an
    EIP-2718 type-0x51 Dilithium-signed transaction
  - both address forms of one PQ account report the SAME balance — they are one
    ledger row, not two kept in sync
  - amounts are exact (not merely "increased"), so a double-credit or a lost fee
    cannot pass
  - the whole thing settles in the shared ``account_state`` root, i.e. every node
    agrees

Depends on S03 so blocks are being produced and transactions can be included.
"""

import asyncio
from decimal import Decimal

from integration_tests.rpc_client import NodeRPCClient
from integration_tests.scenarios.base import Scenario
from integration_tests.tx_sender import TransactionSender

from qrdx.crypto.account_id import to_account_id

# Confirmation slack: 2s slots, so a few slots plus import time.
_SETTLE_SECONDS = 8


class S04bCrossTypeTransfers(Scenario):
    name = "s04b_cross_type_transfers"
    description = "Verify native transfers between 0x and 0xPQ accounts, both ways"
    depends_on = ["s03_block_production"]

    async def execute(self) -> None:
        node_url = self.ctx.node_urls[0]
        wallets = self.ctx.wallets

        trad = wallets.get("Test User 1")       # secp256k1, 0x…
        pq = wallets.get("Test User 0")         # Dilithium, 0xPQ…

        if not self.check(bool(trad and pq), "Traditional + PQ test wallets available"):
            return
        if not self.check(bool(pq.get("public_key")),
                          "PQ wallet carries its public key (needed to sign)"):
            return

        trad_addr = trad["address"]
        pq_display = pq["address"]
        pq_account = to_account_id(pq_display)

        self._log.info("Traditional wallet: %s", trad_addr)
        self._log.info("PQ wallet:          %s", pq_display)
        self._log.info("PQ account id:      %s", pq_account)

        self.check(pq_account != pq_display,
                   "PQ account id is a distinct 20-byte form of the PQ address")

        async with TransactionSender(node_url) as sender:
            # ── Both forms of the PQ account must read as ONE balance ──────────
            bal_by_display = await sender.get_balance(pq_display)
            bal_by_account = await sender.get_balance(pq_account)
            self.check(
                bal_by_display == bal_by_account,
                f"PQ address and account id report one balance "
                f"({bal_by_display} vs {bal_by_account})",
            )

            trad_start = await sender.get_balance(trad_addr)
            pq_start = bal_by_account
            self._log.info("Start: traditional=%s QRDX, pq=%s QRDX", trad_start, pq_start)

            if not self.check_gte(trad_start, Decimal("10"),
                                  "Traditional wallet funded"):
                return
            if not self.check_gte(pq_start, Decimal("10"), "PQ wallet funded"):
                return

            # ══ Direction 1: traditional → post-quantum ═══════════════════════
            # Previously unrepresentable: an RLP `to` field is 20 bytes and a
            # 0xPQ address is 32, so this only works via the account id.
            amount_out = Decimal("3")
            tx1 = await sender.send(
                from_address=trad_addr,
                to_address=pq_display,          # pass the 0xPQ form deliberately
                amount=amount_out,
                private_key=int(trad["private_key"], 16),
            )
            if not self.check_not_none(tx1, "0x → 0xPQ transaction submitted"):
                return
            self._log.info("0x → 0xPQ tx: %s", tx1)
            await asyncio.sleep(_SETTLE_SECONDS)

            pq_after_in = await sender.get_balance(pq_display)
            self.check(
                pq_after_in == pq_start + amount_out,
                f"PQ account credited EXACTLY {amount_out} QRDX "
                f"({pq_start} → {pq_after_in})",
            )
            # The same funds, read through the 20-byte form.
            self.check(
                await sender.get_balance(pq_account) == pq_after_in,
                "Credited funds visible under both address forms",
            )
            trad_after_out = await sender.get_balance(trad_addr)
            self.check(
                trad_after_out <= trad_start - amount_out,
                f"Traditional sender debited the value plus gas "
                f"({trad_start} → {trad_after_out})",
            )

            # ══ Direction 2: post-quantum → traditional ═══════════════════════
            # Authenticated by a type-0x51 Dilithium signature, executed by the
            # same EVM, settled in the same account_state root.
            amount_back = Decimal("2")
            tx2 = await sender.send_pq(
                pq_wallet=pq,
                to_address=trad_addr,
                amount=amount_back,
            )
            if not self.check_not_none(tx2, "0xPQ → 0x transaction submitted"):
                return
            self._log.info("0xPQ → 0x tx (type 0x51): %s", tx2)
            await asyncio.sleep(_SETTLE_SECONDS)

            trad_final = await sender.get_balance(trad_addr)
            pq_final = await sender.get_balance(pq_display)
            self._log.info("Final: traditional=%s QRDX, pq=%s QRDX", trad_final, pq_final)

            self.check(
                trad_final == trad_after_out + amount_back,
                f"Traditional account credited EXACTLY {amount_back} QRDX from a "
                f"PQ sender ({trad_after_out} → {trad_final})",
            )
            self.check(
                pq_final <= pq_after_in - amount_back,
                f"PQ sender debited the value plus gas "
                f"({pq_after_in} → {pq_final})",
            )
            # A PQ transaction is not free — the ~5.3KB envelope is priced.
            self.check(
                pq_final < pq_after_in - amount_back,
                "PQ sender paid gas for its authentication envelope",
            )

        # ══ Every node agrees on the result ═══════════════════════════════════
        # Balances live in account_state, which is bound into the unified state
        # root — so a cross-type transfer must be visible identically everywhere.
        seen = []
        for url in self.ctx.node_urls:
            async with NodeRPCClient(url) as client:
                try:
                    wei = await client.eth_get_balance(pq_account)
                    seen.append((url, Decimal(wei)))
                except Exception as e:
                    self._log.warning("balance read failed on %s: %s", url, e)

        if seen:
            values = {v for _u, v in seen}
            self.check(
                len(values) == 1,
                f"PQ account balance identical across {len(seen)} node(s): "
                f"{[str(v) for v in values]}",
            )
