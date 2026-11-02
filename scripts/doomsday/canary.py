#!/usr/bin/env python3
"""
The Doomsday Protocol's canaries (docs/QUANTUM_MIGRATION.md "Doomsday").

    python scripts/doomsday/canary.py address [--label TEXT]
        The canary's address and public key: a secp256k1 key derived from a hash of the label, so
        no one knows its private key. Fund it with the bounty on each bridged chain and name it in
        the chain spec (DOOMSDAY_CANARIES: CHAIN_ID:ADDRESS).

    python scripts/doomsday/canary.py check --rpc URL [--label TEXT]
        Whether the canary has signed on that chain (its nonce above 0), and its balance.

    python scripts/doomsday/canary.py prove --qrdx-rpc URL --rpc URL --chain-id N \\
        --wallet my.keystore.json --password-file pw.txt
        Once it has signed: prove it on QRDX (DOOMSDAY_PROVE) against the newest finalized head
        of that chain the validators attested. Anyone may. ``--unsigned`` prints the parameters.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from qrdx.bridge import lockbox as L  # noqa: E402
from qrdx.exchange.doomsday import canary_address, canary_key  # noqa: E402

LABEL = "QRDX doomsday canary"


def _address(args) -> int:
    print(f"canary address : {canary_address(args.label)}")
    print(f"public key     : 0x04{canary_key(args.label).hex()}")
    print(f"derived from   : sha256({args.label!r}), the first x on secp256k1 at or above it")
    print(f'chain spec     : DOOMSDAY_CANARIES = ["<CHAIN_ID>:{canary_address(args.label)}"]')
    return 0


def _check(args) -> int:
    rpc = L.JsonRpc(args.rpc)
    canary = canary_address(args.label)
    nonce = int(rpc.call("eth_getTransactionCount", canary, "finalized"), 16)
    balance = int(rpc.call("eth_getBalance", canary, "finalized"), 16)
    print(f"{canary} on chain {L.chain_id(rpc)}: nonce {nonce}, balance {balance} wei (finalized)")
    if nonce:
        print("THE CANARY HAS SIGNED: ECDSA is broken. Prove it: canary.py prove …")
        return 3
    return 0


def _prove(args) -> int:
    qrdx, rpc = L.JsonRpc(args.qrdx_rpc), L.JsonRpc(args.rpc)
    if L.chain_id(rpc) != args.chain_id:
        raise L.LockboxError(f"{args.rpc} is not chain {args.chain_id}")
    status = qrdx.call("bridge_getDoomsday")
    canary = status["canaries"].get(str(args.chain_id))
    if canary is None:
        raise L.LockboxError(f"QRDX names no canary for chain {args.chain_id}")
    heads = qrdx.call("bridge_getHeads", args.chain_id)
    if not heads:
        raise L.LockboxError(f"no attested head of chain {args.chain_id} yet")
    height = int(heads[-1]["height"])
    proof = rpc.call("eth_getProof", canary, [], hex(height))
    if int(proof["nonce"], 16) == 0:
        raise L.LockboxError(f"the canary has not signed by attested head {height}")
    params = {
        "chain": args.chain_id,
        "height": height,
        "account_proof": list(proof["accountProof"]),
    }
    if args.unsigned or not args.wallet:
        print(json.dumps({"op_type": "DOOMSDAY_PROVE", "params": params}, indent=1))
        return 0
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
    from prove_deposit import _wallet

    from qrdx.exchange import ExchangeOpType, ExchangeTransaction

    wallet = _wallet(args.wallet, args.password_file)
    tx = ExchangeTransaction(
        op_type=ExchangeOpType.DOOMSDAY_PROVE,
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
    print(f"the Doomsday Protocol is triggered (head {height}): {receipt.get('data')}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("address", "check", "prove"):
        p = sub.add_parser(name)
        p.add_argument("--label", default=LABEL)
        if name in ("check", "prove"):
            p.add_argument("--rpc", required=True, help="the bridged chain's RPC")
        if name == "prove":
            p.add_argument("--qrdx-rpc", required=True)
            p.add_argument("--chain-id", required=True, type=int)
            p.add_argument("--wallet", help="a QRDX PQ wallet or keystore (pays the gas)")
            p.add_argument("--password-file")
            p.add_argument("--unsigned", action="store_true")
    args = ap.parse_args(argv)
    try:
        return {"address": _address, "check": _check, "prove": _prove}[args.command](args)
    except L.LockboxError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
