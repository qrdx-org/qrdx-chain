"""
Writing and reading the chain's rows by hand, in tests (the node writes them only through its
database's methods: qrdx/database_sqlite.py, qrdx/store.py). Every write tells the chain index,
as the database's own block writers do.
"""
from typing import Any, Optional

from qrdx import block_codec, chain_index


def put_block(db: Any, height: int, block_hash: str, content: Any = "", timestamp: int = 0,
              **columns: Any) -> None:
    """A block row and its body, uncommitted (as an INSERT INTO blocks was)."""
    db.store["blocks"].put(block_height=int(height), block_hash=block_hash,
                           timestamp=timestamp, **columns)
    if isinstance(content, (bytes, bytearray, memoryview)):
        body = bytes(content)  # (already stored form)
    else:
        body = block_codec.encode(content if isinstance(content, str) else str(content))
    db.store["block_bodies"].put(int(height), body)
    chain_index.blocks_changed(db)


def delete_blocks(db: Any, from_height: int, to_height: Optional[int] = None) -> None:
    """Remove the block rows at heights from_height..to_height (default: every one above)."""
    hi = (2**62,) if to_height is None else (int(to_height) + 1,)
    db.store["blocks"].delete_prefix(lo=(int(from_height),), hi=hi)
    db.store["block_bodies"].delete_prefix(lo=(int(from_height),), hi=hi)
    chain_index.blocks_changed(db)


def set_block(db: Any, height: int, **columns: Any) -> None:
    """Change columns of the block row at ``height`` (as an UPDATE blocks did)."""
    db.store["blocks"].update((int(height),), **columns)
    chain_index.blocks_changed(db)


def block_content(db: Any, height: int) -> Optional[str]:
    """The body stored at ``height``, as text."""
    row = db.store["block_bodies"].get(int(height))
    return block_codec.decode(row.content) if row is not None else None


def put_metadata(db: Any, key: str, value: Any) -> None:
    db.store["chain_metadata"].put(key, str(value))
