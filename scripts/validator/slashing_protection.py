#!/usr/bin/env python3
"""
Move a validator's slashing-protection record between machines (EIP-3076's interchange format,
QRDX addresses in the ``pubkey`` field).

    # on the old machine, with its validator STOPPED:
    python scripts/validator/slashing_protection.py export --out record.json
    # on the new machine, BEFORE its validator first starts:
    python scripts/validator/slashing_protection.py import record.json
    python scripts/validator/slashing_protection.py show

The record is ``QRDX_SLASHING_PROTECTION_DB`` (by default next to the chain database), on the
network of the node's genesis (``QRDX_GENESIS_FILE``, else the dev network). The tool takes the
record's lock, so it refuses while a validator holds the record.

An import raises the record's watermarks to the highest slot and epochs it names. The new machine
then never signs at or below what the old one signed. Start the new validator only after the old
one has stopped for good; its doppelganger check watches for the old one all the same.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from qrdx.validator.slashing_protection import (  # noqa: E402
    ProtectionStoreError,
    SlashingProtection,
    default_path,
    load_interchange,
    network_key,
)


async def run(args) -> int:
    path = args.db or default_path()
    if args.cmd == "import" and not Path(args.file).exists():
        raise ProtectionStoreError(f"{args.file} does not exist")
    record = await SlashingProtection.open(path, network_key())
    try:
        if args.cmd == "export":
            doc = await record.export(args.validator or None)
            Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")
            print(f"exported {len(doc['data'])} validator(s) from {path} to {args.out}")
        elif args.cmd == "import":
            count = await record.import_interchange(load_interchange(args.file))
            print(f"imported {count} validator(s) into {path}")
        else:
            doc = await record.export()
            print(f"{path} (network {record.network[:16]}…)")
            for entry in doc["data"]:
                blocks, votes = entry["signed_blocks"], entry["signed_attestations"]
                last_slot = max((int(b["slot"]) for b in blocks), default=None)
                last_target = max((int(v["target_epoch"]) for v in votes), default=None)
                print(
                    f"  {entry['pubkey']}: {len(blocks)} block entries (highest slot "
                    f"{last_slot}), {len(votes)} vote entries (highest target {last_target})"
                )
    finally:
        await record.close()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--db",
        help="the record (default: QRDX_SLASHING_PROTECTION_DB or next to the chain database)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("export", help="write the record as interchange JSON")
    p.add_argument("--out", required=True)
    p.add_argument("--validator", action="append", help="only this address (repeatable)")
    p = sub.add_parser("import", help="merge an interchange JSON into the record")
    p.add_argument("file")
    sub.add_parser("show", help="summarize the record")
    args = ap.parse_args(argv)
    try:
        return asyncio.run(run(args))
    except ProtectionStoreError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
