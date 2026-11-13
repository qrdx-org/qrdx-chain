#!/usr/bin/env python3
"""
Mint a bridge deposit on QRDX by proving it (docs/BRIDGE.md "Proving a deposit"). Anyone may run
this: the depositor, a relayer, an app. Validators do not have to have attested the deposit itself.
They attested the source chain's finalized head, and the lockbox's record of the deposit is
proven against that head's state root.

    python scripts/bridge/prove_deposit.py --qrdx-rpc http://node:3007/rpc \\
        --rpc https://arb1.example/rpc --chain-id 42161 --lockbox 0xLockbox --deposit 17 \\
        --wallet my.keystore.json --password-file pw.txt

1. Reads deposit 17's event from the lockbox, and QRDX's attested heads of the chain
   (``bridge_getHeads``).
2. Picks the newest attested head at or after the deposit's block, and asks the source chain for
   ``eth_getProof`` of the lockbox and of ``deposits[17]`` at that height.
3. Sends ``BRIDGE_PROVE_DEPOSIT``, signed by the wallet (any QRDX account; it pays the gas), and
   waits for the receipt. ``--unsigned`` prints the transaction's parameters instead.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from qrdx.bridge import lockbox as L  # noqa: E402


def _wallet(path: str, password_file):
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.wallet_v2.pq_wallet import PQWallet

    data = json.loads(Path(path).read_text())
    if "crypto" in data:
        if not password_file:
            raise L.LockboxError("the wallet is encrypted: pass --password-file")
        text = Path(password_file).read_text()
        return PQWallet.from_keystore(data, text[:-1] if text.endswith("\n") else text)
    key = PQPrivateKey.from_hex(data["private_key"], public_key_hex=data["public_key"])
    return PQWallet(private_key=key)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--qrdx-rpc", required=True, help="a QRDX node's /rpc URL")
    ap.add_argument("--rpc", required=True, help="the source chain's JSON-RPC URL")
    ap.add_argument("--chain-id", required=True, type=int)
    ap.add_argument("--lockbox", required=True)
    ap.add_argument("--deposit", required=True, type=int, help="the lockbox's deposit id")
    ap.add_argument("--from-block", type=int, default=0, help="where to look for its event")
    ap.add_argument("--wallet", help="a QRDX PQ wallet or keystore to sign with (pays the gas)")
    ap.add_argument("--password-file")
    ap.add_argument("--unsigned", action="store_true", help="print the parameters, send nothing")
    args = ap.parse_args(argv)
    try:
        qrdx, rpc = L.JsonRpc(args.qrdx_rpc), L.JsonRpc(args.rpc)
        if L.chain_id(rpc) != args.chain_id:
            raise L.LockboxError(f"{args.rpc} is not chain {args.chain_id}")
        found = [
            d
            for d in L.deposit_events(
                rpc, args.chain_id, args.lockbox, args.from_block, L.finalized_block(rpc)
            )
            if d.number == args.deposit
        ]
        if not found:
            raise L.LockboxError(f"deposit {args.deposit} is not in a finalized block yet")
        deposit = found[0]
        asset = next(
            (
                a
                for a in L.qrdx_assets(qrdx)
                if int(a["chain"]) == args.chain_id
                and str(a["source_token"]).lower() == deposit.token.lower()
            ),
            None,
        )
        if asset is None:
            raise L.LockboxError(
                f"{deposit.token} is not bridged: the deposit can only be refunded"
            )
        status = qrdx.call("bridge_getDeposit", deposit.deposit_id)
        if status.get("minted"):
            print(f"deposit {deposit.deposit_id} is already minted")
            return 0
        heads = [
            h
            for h in qrdx.call("bridge_getHeads", args.chain_id)
            if int(h["height"]) >= deposit.block
        ]
        if not heads:
            raise L.LockboxError("no attested head at or after the deposit's block yet: retry soon")
        head = heads[-1]
        proof = L.deposit_proof(rpc, args.lockbox, deposit.number, int(head["height"]))
        if str(proof.get("storageHash", "")).lower() == "0x" + "00" * 32:
            raise L.LockboxError("the source chain returned no storage proof")
        params = L.prove_params(
            args.chain_id, deposit, int(asset["decimals"]), int(head["height"]), proof
        )
        if args.unsigned or not args.wallet:
            print(json.dumps({"op_type": "BRIDGE_PROVE_DEPOSIT", "params": params}, indent=1))
            return 0
        from qrdx.exchange import ExchangeOpType, ExchangeTransaction

        wallet = _wallet(args.wallet, args.password_file)
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.BRIDGE_PROVE_DEPOSIT,
            sender=wallet.address,
            nonce=int(qrdx.call("exchange_getNonce", wallet.address)),
            params=params,
            gas_limit=2_000_000,
            gas_price=int(qrdx.call("exchange_gasPrice")),
            chain_id=int(qrdx.call("p2p_getStatus")["network"]["chain_id"]),
        )
        tx.public_key = wallet.public_key
        tx.signature = wallet.sign(tx.signing_bytes())
        tx_hash = qrdx.call("exchange_sendTransaction", tx.to_dict())
        for _ in range(240):
            receipt = qrdx.call("exchange_getTransactionReceipt", tx_hash)
            if receipt:
                break
            time.sleep(0.5)
        else:
            raise L.LockboxError(f"{tx_hash} was not included in time")
        if not receipt.get("success"):
            raise L.LockboxError(str(receipt.get("error")))
        print(
            f"deposit {deposit.deposit_id} minted against head {head['height']}: {receipt.get('data')}"
        )
        return 0
    except L.LockboxError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
