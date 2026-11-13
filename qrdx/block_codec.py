"""
How a block body is stored: zlib-compressed.

A block body (the ``content`` column) is a dict literal whose bulk is hex: the proposer's
Dilithium signature and, when RANDAO selection is scheduled, its RANDAO reveal, each 3.3 KB of
bytes written as 6.6 KB of hex. Stored as text that was ~18 KB a block, about 7 GB a day at
250 ms slots. Hex carries 4 bits a character, so compressing it recovers almost exactly the raw
size, without changing the body every other part of the node reads, signs and sends.

``encode`` is applied where a block is written (``DatabaseSQLite.add_block``); ``decode`` wherever
the column is read. A body stored as text (an older database, a test fixture) reads unchanged.
"""

from __future__ import annotations

import zlib
from typing import Any, Optional

_LEVEL = 6


def encode(content: Any) -> Any:
    """The stored form of a block body: its text, compressed. Anything that is not text (None,
    an already-encoded body) is stored as given."""
    if isinstance(content, str):
        return zlib.compress(content.encode("utf-8"), _LEVEL)
    return content


def decode(value: Any) -> Optional[str]:
    """A stored block body as text."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return zlib.decompress(bytes(value)).decode("utf-8")
    return value
