"""
Publishing snapshots (docs/CHECKPOINT_SYNC.md, "Publishing"). A node started with
``QRDX_SNAPSHOT_DIR`` writes a snapshot of its own database each time it persists a newer
exchange checkpoint (every 1,024 finalized blocks), keeps the newest, serves it at
``/snapshot/manifest.json``, ``/snapshot/qrdx.db`` and ``/snapshot/qrdx.db.store`` (range requests:
a cut download resumes),
and advertises it in ``p2p_getStatus``. A joining node finds one with
``scripts/node/snapshot.py fetch --peer URL``.

Nothing here is trusted by the node that downloads it: ``restore`` verifies a snapshot against
its own genesis and a trusted checkpoint, whoever served it (qrdx/snapshot.py). A published
snapshot leaves out what a restore discards anyway — the tables this node keeps for itself
(peers, pending transactions, indexes, display copies) and those a restore recomputes or
rebuilds — so it neither shows them nor costs the bandwidth.

The work runs in a thread, from a poller: off the block path and the event loop. It reads the
database through SQLite's online backup and the store through MDBX's online copy, each a
consistent read while the node keeps writing.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .logger import get_logger
from .snapshot import DATABASE, MANIFEST, STORE, create

logger = get_logger(__name__)

ENV = "QRDX_SNAPSHOT_DIR"
LATEST = "latest.json"  # which directory holds the published snapshot
POLL_SECONDS = 60.0

_ROOT: Dict[str, str] = {}  # the directory this node publishes from, once started


def configured(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """The publishing directory (``QRDX_SNAPSHOT_DIR``), or None: this node publishes nothing."""
    value = (os.environ if environ is None else environ).get(ENV, "").strip()
    return value or None


def latest(root: str) -> Optional[Dict[str, Any]]:
    """The published snapshot under ``root``: {"dir": its directory, "manifest": ...}, or None."""
    try:
        pointer = json.loads((Path(root) / LATEST).read_text())
        directory = Path(root) / str(pointer["dir"])
        manifest = json.loads((directory / MANIFEST).read_text())
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not (directory / DATABASE).is_file() or not (directory / STORE).is_file():
        return None
    return {"dir": str(directory), "manifest": manifest}


def _checkpoint_height(db_path: str) -> Optional[int]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute("SELECT height FROM exchange_checkpoint WHERE id = 1").fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    return None if row is None else int(row[0])


def publish(db_path: str, root: str) -> Optional[Dict[str, Any]]:
    """Write a snapshot when ``db_path`` holds a newer exchange checkpoint than the one
    published under ``root``, make it the published one and delete the older. Returns its
    manifest, or None when there is nothing new. Blocking: run it in a thread."""
    height = _checkpoint_height(db_path)
    current = latest(root)
    if height is None or (
        current is not None and int(current["manifest"]["checkpoint"]["height"]) >= height
    ):
        return None
    base = Path(root)
    base.mkdir(parents=True, exist_ok=True)
    building = base / f".building-{height}"
    shutil.rmtree(building, ignore_errors=True)
    try:
        manifest = create(db_path, str(building), public=True)
    except BaseException:
        shutil.rmtree(building, ignore_errors=True)
        raise
    # The checkpoint may have moved on while the copy was taken: name it by what it holds.
    name = str(int(manifest["checkpoint"]["height"]))
    final = base / name
    shutil.rmtree(final, ignore_errors=True)
    os.rename(building, final)
    pointer = base / (LATEST + ".tmp")
    pointer.write_text(json.dumps({"dir": name}) + "\n")
    os.replace(pointer, base / LATEST)
    for old in base.iterdir():
        # (A download of the replaced snapshot already under way keeps its open file.)
        if old.is_dir() and old.name != name and not old.name.startswith(".building-"):
            shutil.rmtree(old, ignore_errors=True)
    return manifest


def published_file(name: str) -> Optional[str]:
    """The path of the published snapshot's ``manifest.json``, ``qrdx.db`` or ``qrdx.db.store``
    — the only names served — or None when this node publishes none."""
    root = _ROOT.get("root")
    if root is None or name not in (MANIFEST, DATABASE, STORE):
        return None
    current = latest(root)
    if current is None:
        return None
    return str(Path(current["dir"]) / name)


def advertised() -> Optional[Dict[str, Any]]:
    """What ``p2p_getStatus`` says this node publishes: the snapshot's manifest and where it
    is served, or None."""
    root = _ROOT.get("root")
    current = latest(root) if root is not None else None
    if current is None:
        return None
    return {"path": "/snapshot/", **current["manifest"]}


async def run(db_path: str, root: str, interval: float = POLL_SECONDS) -> None:
    """The node's publishing loop (started at startup when ``QRDX_SNAPSHOT_DIR`` is set)."""
    _ROOT["root"] = root
    while True:
        try:
            manifest = await asyncio.to_thread(publish, db_path, root)
            if manifest is not None:
                logger.info(
                    "snapshot published: exchange checkpoint %s, tip %s, %d MB",
                    manifest["checkpoint"]["height"],
                    manifest["tip"],
                    int(manifest["bytes"]) >> 20,
                )
        except Exception as e:  # noqa: BLE001 — publishing must never stop the node
            logger.warning("snapshot publishing failed: %s", e)
        await asyncio.sleep(interval)
