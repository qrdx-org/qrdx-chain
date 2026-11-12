"""
The node's native module (native/qrdx-native, Rust; docs/NATIVE.md), beside the Python it
stands in for.

Each function here returns exactly what its Python path returns, so consensus never depends on
whether the module is installed. A node without it runs the Python path; ``QRDX_NATIVE=0`` turns
it off. (The node's store, qrdx/store.py, is the module's too and has no Python path: the node
needs the module for it.) What the module does:

* ``mldsa65_verify_batch``: ML-DSA-65 signatures, checked by the same liboqs the Python path
  calls, in parallel and without Python's lock (on one core, through Python, a block's
  signatures were checked one at a time even on threads);
* ``body_root``: a block body's canonical JSON, hashed as it is written. Anything the native
  encoder does not reproduce exactly (a float, a key that is not a string) is encoded by
  Python's ``json`` instead.
"""

import hashlib
import json
import os
from typing import Any, Callable, List, Optional, Sequence, Tuple


def _load() -> Any:
    if os.environ.get("QRDX_NATIVE", "1").strip().lower() in ("0", "false", "no", "off"):
        return None  # (turned off)
    try:
        import importlib

        return importlib.import_module("qrdx_native")
    except ImportError:
        return None


_native: Any = _load()

AVAILABLE = _native is not None

# Fewer signatures than this are not worth the hand-off to the module's threads.
BATCH_MIN = 8


def canonical_json(obj: Any, compact: bool = True, default_str: bool = False) -> bytes:
    """``json.dumps(obj, sort_keys=True, ensure_ascii=True)``, encoded: ``separators=(",", ":")``
    when ``compact``, ``default=str`` when ``default_str``."""
    if _native is not None:
        try:
            return bytes(_native.canonical_json(obj, compact, default_str))
        except _native.Unsupported:
            pass
    kwargs: dict = {"sort_keys": True, "ensure_ascii": True}
    if compact:
        kwargs["separators"] = (",", ":")
    if default_str:
        kwargs["default"] = str
    return json.dumps(obj, **kwargs).encode()


def body_root(prefix: bytes, body: Any) -> str:
    """``sha256(prefix + canonical_json(body))``, hex."""
    if _native is not None:
        try:
            return str(_native.body_root_sha256(prefix, body))
        except _native.Unsupported:
            pass
    return hashlib.sha256(prefix + canonical_json(body)).hexdigest()


def mldsa65_verify_batch(items: Sequence[Tuple[bytes, bytes, bytes]]) -> Optional[List[bool]]:
    """Whether each ``(public_key, message, signature)`` is a valid ML-DSA-65 signature, or None
    without the module (the caller checks them one at a time)."""
    if _native is None:
        return None
    return list(_native.mldsa65_verify_batch(list(items)))


def tree_module() -> Optional[Any]:
    """The module, if it has the exchange's in-memory proof trees (qrdx/crypto/smt.py ``m_*``)."""
    if _native is None or not hasattr(_native, "mt_update"):
        return None
    return _native


def lt_mix_entries_function() -> Optional[Callable[..., Any]]:
    """The native ``_apply`` of entries' digests (qrdx/exchange/commitment.py), or None."""
    if _native is None or not hasattr(_native, "lt_mix_entries"):
        return None
    return _native.lt_mix_entries  # type: ignore[no-any-return]


def smt_entries_function() -> Optional[Callable[..., Any]]:
    """The database tree's entries of marked rows (``state_proofs._changes``), natively: each
    item (key, payload) or None where only Python computes it exactly. None without the
    module."""
    if _native is None:
        return None
    return _native.smt_entries  # type: ignore[no-any-return]


def smt_update_into_function() -> Optional[Callable[..., Any]]:
    """The native state-proof tree update over a native node cache (``smt_nodes_cache``),
    returning its writes packed for the store: ``(encoded root, changes, version, nodes) →
    ("ok", root, [(key, value)] of smt_nodes, [(key, b"")] of smt_stale)`` or
    ``("missing", [nkey, ...])``; None without the module."""
    if _native is None or not hasattr(_native, "smt_update_into"):
        return None
    return _native.smt_update_into  # type: ignore[no-any-return]


def smt_nodes_cache(capacity: int) -> Optional[Any]:
    """A native cache of state-tree nodes (``SmtNodes``), or None without the module."""
    if _native is None or not hasattr(_native, "SmtNodes"):
        return None
    return _native.SmtNodes(capacity)


def smt_update_function() -> Optional[Callable[..., Any]]:
    """The native state-proof tree update (qrdx/crypto/smt.py ``Tree.update``), or None without
    the module: ``(encoded root, changes, version, cache) → ("ok", root, writes, stale)`` or
    ``("missing", [nkey, ...])``."""
    if _native is None or not hasattr(_native, "smt_update"):
        return None
    return _native.smt_update  # type: ignore[no-any-return]
