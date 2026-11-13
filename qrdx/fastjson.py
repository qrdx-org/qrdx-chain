"""
JSON for the transport: requests and responses between peers, and JSON-RPC (docs/PERFORMANCE.md).
A loaded node spent a large share of its event loop encoding the transactions it relays, in
Python's ``json``: ``dumps`` here writes with orjson (in Rust), about nine times faster on a
gossip batch. Parsing stays Python's ``json``: it reads a batch's long strings quickly, and
orjson reads an integer beyond 64 bits as a float, losing its digits.

Never for bytes that consensus hashes or signs: those are Python's ``json``
(``ExchangeTransaction``, ``block_verification.body_root``) or the native module's exact copy
of it (qrdx/native.py). What orjson writes differently from Python's ``json``, and how:

* **Integers beyond 64 bits.** orjson refuses them; Python's ``json`` writes the document.
* **Non-ASCII.** Written as UTF-8 rather than ``\\uXXXX``: the same JSON to every reader.
* **Not serializable.** A datetime or dataclass that ``json`` cannot serialize goes to
  ``default``, as with ``json``; a subclass of str, int, dict or list is written as its base,
  as ``json`` writes it.
"""

import json
from typing import Any, Callable, Optional

_orjson: Any
try:
    import orjson as _orjson
except ImportError:  # (the node runs without it, on Python's json)
    _orjson = None

AVAILABLE = _orjson is not None
_OPTIONS = (
    (
        _orjson.OPT_NON_STR_KEYS
        | _orjson.OPT_PASSTHROUGH_DATETIME
        | _orjson.OPT_PASSTHROUGH_DATACLASS
    )
    if _orjson is not None
    else 0
)


def loads(data: Any) -> Any:
    """``json.loads`` (see the module's note)."""
    return json.loads(data)


def dumps(obj: Any, default: Optional[Callable[[Any], Any]] = None) -> str:
    """``json.dumps(obj, separators=(",", ":"), default=default)``, as text."""
    if _orjson is not None:
        try:
            return str(_orjson.dumps(obj, default=default, option=_OPTIONS), "utf-8")
        except TypeError:
            pass  # (an integer past 64 bits, or a value default cannot serialize)
    return json.dumps(obj, separators=(",", ":"), default=default)
