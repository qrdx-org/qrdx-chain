#!/usr/bin/env python3
"""
Deploy QRDXLockbox on a source chain (docs/BRIDGE.md, "Deploying to a new chain").

    python scripts/bridge/deploy_lockbox.py --rpc https://arb1.example/rpc --chain-id 42161 \\
        --custodian 0xYourSafe --keystore deployer.json --out arbitrum-lockbox.json

What it does, refusing at the first problem:

1. Loads the committed build (contracts/bridge/QRDXLockbox.artifact.json) and checks that it is
   built from the source in the repository; with ``--verify-build`` it also recompiles it with the
   pinned compiler and requires the same bytes.
2. Checks the chain: its id is the one you named, its RPC answers for the ``finalized`` block (the
   validators read deposits only up to it), and the custodian is a contract (a multisig — an
   ordinary account needs ``--allow-eoa-custodian``, for test networks).
3. Shows what it will send and asks (``--yes`` skips the question; ``--dry-run`` stops here).
   ``--unsigned`` prints the creation transaction's data for a wallet that signs elsewhere.
4. Sends the creation, waits for it, and checks the deployed code byte for byte and the custodian.
5. Writes the deployment record (``--out``) and prints the lines the network needs:
   the BRIDGE_ASSETS entry to fill in and each validator's QRDX_BRIDGE_SOURCES and
   QRDX_BRIDGE_FROM_BLOCK_<chain>.

The deployer's key comes from an encrypted keystore (``--keystore``; you are asked for its
password) or from QRDX_DEPLOYER_KEY. It only pays the gas: it has no power over the lockbox.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from qrdx.bridge import lockbox as L  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--rpc", required=True, help="the source chain's JSON-RPC URL")
    ap.add_argument("--chain-id", required=True, type=int, help="the chain id you expect it to be")
    ap.add_argument("--custodian", required=True, help="the custodian: a multisig (a Safe)")
    ap.add_argument(
        "--refund-delay",
        type=int,
        default=8 * 24 * 3600,
        help="seconds after a deposit before it may be refunded (default 8 days): longer than "
        "the QRDX network's deposit window (BRIDGE_DEPOSIT_WINDOW, 7 days by default)",
    )
    ap.add_argument(
        "--qrdx-rpc",
        help="a QRDX node's /rpc: refuse a refund delay that is not a day longer than its window",
    )
    ap.add_argument("--keystore", help="the deployer's encrypted keystore (else QRDX_DEPLOYER_KEY)")
    ap.add_argument("--password", help="the keystore's password (else you are asked)")
    ap.add_argument("--legacy", action="store_true", help="send a legacy (EIP-155) transaction")
    ap.add_argument(
        "--allow-eoa-custodian",
        action="store_true",
        help="allow an ordinary account as custodian (test networks only)",
    )
    ap.add_argument(
        "--verify-build",
        action="store_true",
        help="recompile with the pinned compiler and require the committed bytes",
    )
    ap.add_argument("--dry-run", action="store_true", help="check everything, send nothing")
    ap.add_argument(
        "--unsigned",
        action="store_true",
        help="print the creation transaction's data to sign elsewhere, send nothing",
    )
    ap.add_argument("--yes", action="store_true", help="do not ask before sending")
    ap.add_argument("--out", help="write the deployment record here (JSON)")
    args = ap.parse_args(argv)

    try:
        art = L.load_artifact()
        if args.verify_build:
            built = L.compile_lockbox()
            if (built["bytecode"], built["runtime"]) != (art["bytecode"], art["runtime"]):
                raise L.LockboxError("recompiling does not reproduce the committed artifact")
            print(f"build: reproduced with {art['compiler']} {json.dumps(art['settings'])}")
        rpc = L.JsonRpc(args.rpc)
        cid = L.chain_id(rpc)
        if cid != args.chain_id:
            raise L.LockboxError(f"the RPC is chain {cid}, not {args.chain_id}")
        finalized = L.finalized_block(rpc)
        custodian = L.to_checksum_address(args.custodian)
        if not L.has_code(rpc, custodian):
            if not args.allow_eoa_custodian:
                raise L.LockboxError(
                    f"the custodian {custodian} has no code: use a multisig (a Safe), or pass "
                    "--allow-eoa-custodian on a test network"
                )
            print(f"WARNING: the custodian {custodian} is an ordinary account (test networks only)")
        if args.refund_delay < 24 * 3600:
            raise L.LockboxError("the refund delay must be at least a day")
        if args.qrdx_rpc:
            window = int(L.JsonRpc(args.qrdx_rpc).call("bridge_getGuardrails")["deposit_window"])
            if args.refund_delay < window + 24 * 3600:
                raise L.LockboxError(
                    f"the refund delay ({args.refund_delay} s) must exceed the QRDX deposit "
                    f"window ({window} s) by a day: a refund must never meet a mint"
                )
        data = L.deploy_data(art["bytecode"], custodian, args.refund_delay)
        print(f"chain {cid}: finalized block {finalized}")
        print(
            "QRDXLockbox: runtime code hash "
            f"{L.code_hash(L.deployed_runtime(art, args.refund_delay))}"
        )
        print(f"custodian: {custodian}; refund delay {args.refund_delay} s")
        if args.unsigned:
            print(
                json.dumps(
                    {"chainId": cid, "to": None, "value": "0", "data": "0x" + data.hex()}, indent=1
                )
            )
            return 0
        account = L.load_account(args.keystore, args.password)
        tx = L.build_tx(rpc, account.address, cid, None, data, legacy=args.legacy)
        fee = tx.get("gasPrice") or tx.get("maxFeePerGas")
        print(
            f"deployer: {account.address} (nonce {tx['nonce']}), gas {tx['gas']} at most "
            f"{fee} wei each"
        )
        print(f"it will deploy at {L.create_address(account.address, tx['nonce'])}")
        if args.dry_run:
            print("dry run: nothing sent")
            return 0
        if not args.yes and input("send? [y/N] ").strip().lower() != "y":
            print("not sent")
            return 1
        receipt = L.send(rpc, account, tx)
        address = L.to_checksum_address(receipt["contractAddress"])
        block = int(receipt["blockNumber"], 16)
        code = rpc.call("eth_getCode", address, "latest")
        if str(code).lower() != L.deployed_runtime(art, args.refund_delay).lower():
            raise L.LockboxError(f"the code at {address} is not QRDXLockbox's runtime code")
        if L.custodian_of(rpc, address) != custodian:
            raise L.LockboxError(f"the lockbox at {address} names a different custodian")
        record = {
            "chain_id": cid,
            "lockbox": address,
            "deployment_block": block,
            "deployment_tx": receipt["transactionHash"],
            "custodian": custodian,
            "refund_delay": args.refund_delay,
            "deployer": account.address,
            "runtime_code_hash": L.code_hash(L.deployed_runtime(art, args.refund_delay)),
            "compiler": art["compiler"],
            "settings": art["settings"],
            "source_sha256": art["source_sha256"],
        }
        if args.out:
            Path(args.out).write_text(json.dumps(record, indent=1) + "\n")
        print(
            f"\nQRDXLockbox deployed at {address} in block {block} ({receipt['transactionHash']})"
        )
        print("verified: the deployed code is QRDXLockbox's, and the custodian is the one named")
        print("\nNext (docs/BRIDGE.md):")
        print(f"  BRIDGE_ASSETS entry, per token:  SYMBOL:{cid}:<token address>:<decimals>")
        print(f"  BRIDGE_LOCKBOXES entry:          {cid}:{address}")
        print(f"  each validator:  QRDX_BRIDGE_SOURCES={cid}=<its own RPC URL>@{address}")
        print(f"                   QRDX_BRIDGE_FROM_BLOCK_{cid}={block}")
        print("  verify the source on the chain's explorer with the compiler and settings above")
        return 0
    except L.LockboxError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
