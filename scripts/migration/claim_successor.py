#!/usr/bin/env python3
"""
Bind an Ethereum account's post-quantum successor on QRDX (docs/QUANTUM_MIGRATION.md).

The account registered its successor in QRDXMigrationRegistry on its chain. Anyone can then prove
the commitment on QRDX against the newest finalized head of that chain the validators attested:

    python scripts/migration/claim_successor.py --qrdx-rpc http://node:3007/rpc \\
        --rpc https://eth.example/rpc --chain-id 1 --registry 0xRegistry --account 0xAccount \\
        --wallet my.keystore.json --password-file pw.txt

The wallet signing MIGRATION_CLAIM is any QRDX account (it pays the gas). ``--unsigned`` prints
the transaction's parameters instead.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from qrdx.bridge import lockbox as L  # noqa: E402
from qrdx.exchange.migration import REGISTERED_AT_SLOT, SUCCESSOR_SLOT, mapping_slot  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--qrdx-rpc", required=True)
    ap.add_argument("--rpc", required=True, help="the chain the account registered on")
    ap.add_argument("--chain-id", required=True, type=int)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--account", required=True, help="the 0x account that registered")
    ap.add_argument("--wallet", help="a QRDX PQ wallet or keystore to sign with (pays the gas)")
    ap.add_argument("--password-file")
    ap.add_argument("--unsigned", action="store_true")
    args = ap.parse_args(argv)
    try:
        qrdx, rpc = L.JsonRpc(args.qrdx_rpc), L.JsonRpc(args.rpc)
        if L.chain_id(rpc) != args.chain_id:
            raise L.LockboxError(f"{args.rpc} is not chain {args.chain_id}")
        account = args.account.lower()
        heads = qrdx.call("bridge_getHeads", args.chain_id)
        if not heads:
            raise L.LockboxError(f"no attested head of chain {args.chain_id} yet")
        height = int(heads[-1]["height"])
        slots = [mapping_slot(account, SUCCESSOR_SLOT), mapping_slot(account, REGISTERED_AT_SLOT)]
        proof = rpc.call(
            "eth_getProof", args.registry, ["0x" + s.hex() for s in slots], hex(height)
        )
        successor_word, time_word = (int(p["value"], 16) for p in proof["storageProof"])
        if not successor_word:
            raise L.LockboxError(
                f"the registry holds no commitment for {account} at attested head {height}: "
                "register first, or wait for a newer head"
            )
        params = {
            "chain": args.chain_id,
            "account": account,
            "successor": "0xPQ" + successor_word.to_bytes(32, "big").hex(),
            "time": time_word,
            "height": height,
            "account_proof": list(proof["accountProof"]),
            "successor_proof": list(proof["storageProof"][0]["proof"]),
            "time_proof": list(proof["storageProof"][1]["proof"]),
        }
        if args.unsigned or not args.wallet:
            print(json.dumps({"op_type": "MIGRATION_CLAIM", "params": params}, indent=1))
            return 0
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
        from prove_deposit import _wallet

        from qrdx.exchange import ExchangeOpType, ExchangeTransaction

        wallet = _wallet(args.wallet, args.password_file)
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.MIGRATION_CLAIM,
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
            f"{account} is now controlled by {params['successor']} (head {height}): {receipt.get('data')}"
        )
        return 0
    except L.LockboxError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
