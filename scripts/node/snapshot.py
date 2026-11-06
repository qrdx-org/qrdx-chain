#!/usr/bin/env python3
"""
Checkpoint sync: snapshot a node's database, and start a new node from one, verified
(docs/CHECKPOINT_SYNC.md, qrdx/snapshot.py).

    python scripts/node/snapshot.py create --db /data/qrdx.db --out snapshot-2026-10-28/
        A consistent copy of a node's database (running or not) and a manifest. The node must
        have persisted an exchange checkpoint: every 1,024 finalized blocks.

    python scripts/node/snapshot.py fetch --url https://snapshots.example/qrdx/ --out snapshot/
    python scripts/node/snapshot.py fetch --peer http://node-a:3007 --peer http://node-b:3007 \
        --out snapshot/
        Download a snapshot directory published by any HTTP server, or the newest one any of
        the given nodes publishes (QRDX_SNAPSHOT_DIR, served at /snapshot/). Resumable. Where it
        came from does not matter: the restore trusts none of it.

    python scripts/node/snapshot.py restore --snapshot snapshot-2026-10-28/ --db /data/qrdx.db \\
        --checkpoint 2048123:9f2c…
        Verify the snapshot and write the new node's database. Run it with the node's own
        environment (QRDX_GENESIS_FILE: the network's genesis file). ``--checkpoint``
        (repeatable) is a finalized block you trust, height:hash, at or above the snapshot's
        exchange checkpoint: from an explorer, another operator, your own node. The chain
        spec's checkpoints and QRDX_TRUSTED_CHECKPOINT count too.

The restore trusts nothing in the snapshot: genesis is rebuilt from the genesis file, every
block's hash is recomputed up to the trusted checkpoint, and the state at the exchange
checkpoint must reproduce the state root that block signs. On any failure nothing is written.
The node then starts on the restored database and syncs the blocks above the checkpoint from
its peers.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _checkpoints(values) -> dict:
    from qrdx.checkpoints import ENV, CheckpointError, _parse_env

    try:
        return _parse_env(",".join(values or []))
    except CheckpointError as e:
        raise SystemExit(str(e).replace(ENV, "--checkpoint")) from e


def cmd_create(args) -> int:
    from qrdx.snapshot import SnapshotError, create

    try:
        manifest = create(args.db, args.out)
    except SnapshotError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


def cmd_fetch(args) -> int:
    from qrdx.snapshot import SnapshotError, discover, fetch

    try:
        url = args.url
        if not url:
            if not args.peer:
                raise SnapshotError("give --url, or one or more --peer")
            url, offered = discover(args.peer)
            print(f"{url}: exchange checkpoint {offered['checkpoint']['height']}", flush=True)
        manifest = fetch(url, args.out, progress=lambda m: print(m, flush=True))
    except (SnapshotError, OSError, ValueError, KeyError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


def cmd_restore(args) -> int:
    from qrdx.checkpoints import trusted
    from qrdx.snapshot import SnapshotError, restore

    anchors = trusted()
    for height, block_hash in _checkpoints(args.checkpoint).items():
        if anchors.get(height, block_hash) != block_hash:
            raise SystemExit(f"--checkpoint {height}: the chain spec trusts another hash")
        anchors[height] = block_hash
    genesis = args.genesis or os.environ.get("QRDX_GENESIS_FILE") or None
    try:
        result = asyncio.run(
            restore(
                args.snapshot,
                args.db,
                genesis_file=genesis,
                trusted=anchors,
                progress=lambda message: print(message, flush=True),
            )
        )
    except SnapshotError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    print(
        f"restored {args.db} at block {result['height']} ({result['block_hash'][:16]}…), "
        f"state root {result['state_root'][:16]}… as signed; trusted checkpoint "
        f"{result['trusted_checkpoint']}. Start the node: it syncs from there."
    )
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    c.add_argument("--db", required=True, help="the node's database")
    c.add_argument("--out", required=True, help="a new directory for the snapshot")
    f = sub.add_parser("fetch")
    f.add_argument("--url", help="where a snapshot directory is published")
    f.add_argument("--peer", action="append", help="a node that may publish one (repeatable)")
    f.add_argument("--out", required=True)
    r = sub.add_parser("restore")
    r.add_argument("--snapshot", required=True)
    r.add_argument("--db", required=True, help="the new node's database (must not exist)")
    r.add_argument("--checkpoint", action="append", help="a trusted block, height:hash")
    r.add_argument("--genesis", help="the network's genesis file (default: QRDX_GENESIS_FILE)")
    args = ap.parse_args(argv)
    return {"create": cmd_create, "fetch": cmd_fetch, "restore": cmd_restore}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
