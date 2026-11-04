"""
The node's native module (native/qrdx-native, Rust; docs/NATIVE.md), beside the Python it
stands in for.

Each function here returns exactly what its Python path returns, so consensus never depends on
whether the module is installed. A node without it runs the Python path; ``QRDX_NATIVE=0`` turns
it off. What the module does:

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
from typing import Any, List, Optional, Sequence, Tuple


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
