"""
S22 — On-chain governance on the live chain (qrdx/exchange/governance.py, docs/GOVERNANCE.md).

  1. A validator proposes a treasury spend; the three validators approve it (2/3 of stake —
     with three equal validators that is all three); after the timelock anyone executes it, and
     every node moves exactly the amount out of the system wallet and into the recipient.
  2. A second spend passes and a holder vetoes it by locking QRDX in the escrow: the proposal
     is stopped, can't be executed, and the holder's QRDX comes back (less the veto's fee).
  3. The validators freeze the genesis master controller: every node reports its authority
     ended, and a system-wallet spend it signs is refused at admission.

Runs last: freezing the master is irreversible. Validators submit to their own node (a
validator's exchange nonce also moves with its oracle votes; its own proposer orders its
transactions ahead of them — docs/KNOWN_ISSUES.md).
"""

import asyncio
from decimal import Decimal

import httpx

from integration_tests.config import CHAIN_ID  # exchange txs are signed for the testnet's chain
from integration_tests.rpc_client import NodeRPCClient
from integration_tests.scenarios.base import Scenario

DEV_FUND = "0x0000000000000000000000000000000000000003"
SPEND = Decimal("1234.5")
RECIPIENT = "0x" + "a5" * 20


class S22Governance(Scenario):
    name = "s22_governance"
    description = "Governance: treasury spend, holder veto, master controller freeze — cross-node"
    depends_on = ["s01_genesis_bootstrap"]

    async def _rpc(self, url, method, params=None):
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(f"{url}/rpc", json={"jsonrpc": "2.0", "method": method,
                                                  "params": params or [], "id": 1})
        body = r.json()
        if body.get("error"):
            raise RuntimeError(body["error"].get("message", str(body["error"])))
        return body.get("result")

    async def _get(self, url, path, **params):
        async with NodeRPCClient(url) as c:
            r = await c._get(path, params=params)
        return r["result"] if r and r.get("ok") else None

    async def _balance(self, url, address):
        async with NodeRPCClient(url) as c:
            info = await c.get_address_info(address)
        return Decimal(str(info["balance"])) if info and "balance" in info else None

    async def _send(self, url, wallet, op, params, label, attempts=4):
        """Sign at the sender's next exchange nonce on ``url``, submit there, wait for the
        receipt. Retries when the nonce went stale under us (a validator's oracle vote)."""
        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction
        key = PQPrivateKey.from_hex(wallet["private_key"], wallet["public_key"])
        for _ in range(attempts):
            nonce = int(await self._rpc(url, "exchange_getNonce", [wallet["address"]]))
            tx = ExchangeTransaction(chain_id=CHAIN_ID, op_type=op, sender=wallet["address"],
                                     nonce=nonce, params=params, gas_limit=2_000_000,
                                     gas_price=10 ** 9)
            tx.public_key = key.public_key.to_bytes()
            tx.signature = key.sign(tx.signing_bytes()).to_bytes()
            try:
                tx_hash = await self._rpc(url, "exchange_sendTransaction", [tx.to_dict()])
            except RuntimeError as e:
                if "nonce" in str(e).lower():
                    await asyncio.sleep(2)
                    continue
                self.check(False, f"{label}: admitted ({e})")
                return None
            for _ in range(60):
                rec = await self._rpc(url, "exchange_getTransactionReceipt", [tx_hash])
                if rec:
                    if not rec["success"] and "Invalid nonce" in (rec.get("error") or ""):
                        break                                   # raced an oracle vote: retry
                    return rec
                await asyncio.sleep(2)
            else:
                self.check(False, f"{label}: included in a block")
                return None
        self.check(False, f"{label}: could not land after {attempts} attempts")
        return None

    async def _ok(self, url, wallet, op, params, label):
        rec = await self._send(url, wallet, op, params, label)
        self.check(bool(rec) and rec["success"], f"{label} ({rec and rec['error']})")
        return rec

    async def _eventually(self, probe, timeout=40):
        """Poll ``probe`` (async → (ok, detail)) until it holds: a block reaches every node a
        few seconds apart."""
        ok, detail = False, None
        for _ in range(timeout // 2):
            ok, detail = await probe()
            if ok:
                break
            await asyncio.sleep(2)
        return ok, detail

    async def _height(self, url):
        return int((await self._rpc(url, "governance_getStatus"))["height"])

    async def _wait_height(self, url, target, timeout=240):
        for _ in range(timeout // 2):
            if await self._height(url) >= target:
                return True
            await asyncio.sleep(2)
        return False

    async def _pass(self, validators, nodes, params, label):
        """Propose with validator 0, approve with all three. Returns the proposal."""
        from qrdx.exchange import ExchangeOpType
        rec = await self._ok(nodes[0], validators[0], ExchangeOpType.GOV_PROPOSE, params,
                             f"{label}: proposed")
        if not rec:
            return None
        pid = rec["data"]["proposal_id"]
        for i, v in enumerate(validators):
            await self._ok(nodes[i], v, ExchangeOpType.GOV_VOTE,
                           {"proposal_id": pid, "support": True}, f"{label}: validator {i} votes yes")
        # The last vote may sit in a block another node proposed: give node 0 time to import it.
        for _ in range(15):
            p = await self._rpc(nodes[0], "governance_getProposal", [pid])
            if p["status"] != "voting":
                break
            await asyncio.sleep(2)
        if not self.check(p["status"] == "passed", f"{label}: passed with 2/3 of stake ({p['status']})"):
            return None
        return p

    async def execute(self) -> None:
        from qrdx.exchange import ExchangeOpType
        from qrdx.exchange.governance import veto_escrow_address

        wallets = self.ctx.wallets
        nodes = self.ctx.node_urls
        validators = [wallets.get(f"Validator {i}") for i in range(3)]
        holder = wallets.get("Token Issuer")
        master = wallets.get("Master Controller")
        if not all(w and w.get("private_key") for w in validators + [holder, master]):
            self.check(False, "validator, holder and master controller wallets available")
            return

        status = await self._rpc(nodes[0], "governance_getStatus")
        self.check(status["master_controller"]["authority"],
                   "the master controller starts with authority over the system wallets")

        # ── 1. a treasury spend ─────────────────────────────────────────────────────────
        fund_before = await self._balance(nodes[0], DEV_FUND)
        recipient_before = await self._balance(nodes[0], RECIPIENT) or Decimal(0)
        p = await self._pass(validators, nodes, {"action": "system_spend", "wallet": DEV_FUND,
                                                 "to": RECIPIENT, "amount": str(SPEND),
                                                 "memo": "S22 grant"}, "spend")
        if not p:
            return
        early = await self._send(nodes[0], holder, ExchangeOpType.GOV_EXECUTE,
                                 {"proposal_id": p["id"]}, "spend: early execute")
        if early and early["success"]:
            self.check(False, "spend: refused before its timelock ends")
        else:
            self.check(bool(early) and "timelocked" in early["error"],
                       f"spend: refused before its timelock ends ({early and early['error']})")
        await self._wait_height(nodes[0], p["timelock_ends"])
        await self._ok(nodes[0], holder, ExchangeOpType.GOV_EXECUTE, {"proposal_id": p["id"]},
                       "spend: executed after the timelock")
        for i, url in enumerate(nodes):
            async def moved(url=url):
                fund = await self._balance(url, DEV_FUND)
                got = await self._balance(url, RECIPIENT)
                return (fund == fund_before - SPEND and got == recipient_before + SPEND,
                        (fund, got))
            ok, (fund, got) = await self._eventually(moved)
            self.check(ok, f"node {i}: exactly {SPEND} QRDX moved from the fund to the recipient "
                           f"(fund {fund_before}→{fund}, recipient {recipient_before}→{got})")

        # ── 2. a holder veto ────────────────────────────────────────────────────────────
        threshold = Decimal((await self._rpc(nodes[0], "governance_getStatus"))["params"]["GOV_VETO_THRESHOLD_QRDX"])
        p2 = await self._pass(validators, nodes, {"action": "system_spend", "wallet": DEV_FUND,
                                                  "to": RECIPIENT, "amount": "1"}, "vetoed spend")
        if not p2:
            return
        holder_before = await self._balance(nodes[0], holder["address"])
        veto = await self._ok(nodes[0], holder, ExchangeOpType.GOV_VETO,
                              {"proposal_id": p2["id"], "amount": str(threshold)},
                              f"veto: {threshold} QRDX locked")
        if veto:
            self.check(veto["data"]["status"] == "vetoed", "veto: the threshold stops the proposal")
            await asyncio.sleep(6)
            holder_after = await self._balance(nodes[0], holder["address"])
            fee = Decimal(veto["fee"])
            self.check(holder_after == holder_before - fee,
                       f"veto: the holder's QRDX came back, less the fee "
                       f"({holder_before} → {holder_after}, fee {fee})")
            escrow = await self._balance(nodes[0], veto_escrow_address())
            self.check((escrow or 0) == 0, f"veto: the escrow is empty again ({escrow})")
            await self._wait_height(nodes[0], p2["timelock_ends"])
            late = await self._send(nodes[0], holder, ExchangeOpType.GOV_EXECUTE,
                                    {"proposal_id": p2["id"]}, "vetoed spend: execute")
            self.check(bool(late) and not late["success"] and "vetoed" in late["error"],
                       f"vetoed spend: cannot be executed ({late and late['error']})")

        # ── 3. freezing the master controller ───────────────────────────────────────────
        p3 = await self._pass(validators, nodes, {"action": "freeze_master"}, "freeze")
        if not p3:
            return
        await self._wait_height(nodes[0], p3["timelock_ends"])
        await self._ok(nodes[0], validators[0], ExchangeOpType.GOV_EXECUTE,
                       {"proposal_id": p3["id"]}, "freeze: executed")
        for i, url in enumerate(nodes):
            async def frozen(url=url):
                m = (await self._rpc(url, "governance_getStatus"))["master_controller"]
                return (not m["authority"] and m["frozen_at"] is not None, m)
            ok, m = await self._eventually(frozen)
            self.check(ok, f"node {i}: the master controller's authority has ended "
                           f"({(m or {}).get('reason', '')[:60]})")
        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.transactions.pq_tx import PQTransaction
        key = PQPrivateKey.from_hex(master["private_key"], master["public_key"])
        try:     # admission refuses a frozen controller before it looks at the nonce
            nonce = int(await self._rpc(nodes[0], "eth_getTransactionCount",
                                        [master["address"], "pending"]) or "0x0", 16)
        except Exception:
            nonce = 0
        raw = "0x" + PQTransaction(chain_id=CHAIN_ID, nonce=nonce, gas_price=10 ** 9, gas_limit=500_000,
                                   to=bytes.fromhex(RECIPIENT[2:]), value=10 ** 18, data=b"",
                                   on_behalf_of=bytes.fromhex(DEV_FUND[2:])).sign(key).encode().hex()
        try:
            await self._rpc(nodes[0], "eth_sendRawTransaction", [raw])
            self.check(False, "freeze: a system-wallet spend signed by the master is refused")
        except RuntimeError as e:
            self.check("froze" in str(e), f"freeze: a system-wallet spend signed by the master is "
                                           f"refused ({str(e)[:90]})")
