"""
LtHash — an additive (lattice) hash of a set, updatable one element at a time.

A state root that hashes every row of a domain in order costs O(state) on every block. LtHash
commits to the same set in O(changes): the hash of a set is the lane-wise sum, modulo 2^16, of
its elements' hash vectors, so adding an element adds its vector and removing one subtracts it.
Bellare–Micciancio's construction with the parameters of Lewi et al. ("Securing Update
Propagation with Homomorphic Hashing", 2019): 1024 lanes of 16 bits, each element's vector
taken from an extendable-output hash (BLAKE3 here). Solana commits its accounts the same way.

Representation. A vector is a Python int holding the 1024 lanes in 32-bit slots, little-endian
(lane i in bits 32i..32i+15; the upper 16 bits of every slot are zero). Spreading the lanes
lets one big-integer add or subtract work on all of them at once with no carry crossing into
the next lane, and one mask reduces every lane mod 2^16 — far faster in Python than lane
loops. An element's vector is the low 16 bits of each little-endian u32 of 4096 bytes of
BLAKE3 output: 1024 independent uniform 16-bit lanes. Serialized, a vector is those 4096 bytes.

Only the domain separation matters for security: every caller tags its elements (``entry``'s
``tag``), so an element of one domain or table can never be confused with another's.
"""

from __future__ import annotations

from typing import Optional

import blake3

LANES = 1024
SIZE = 4 * LANES  # serialized bytes: one 32-bit slot per lane

_MASK = int.from_bytes(b"\xff\xff\x00\x00" * LANES, "little")
_BIAS = int.from_bytes(b"\x00\x00\x01\x00" * LANES, "little")  # 2^16 in every lane

ZERO = bytes(SIZE)  # the hash of the empty set

_ROOT_TAG = b"QRDX-LTHASH-ROOT-v1\x00"


def entry(tag: bytes, data: bytes) -> int:
    """The vector of one element: ``tag`` separates domains, ``data`` encodes the element."""
    h = blake3.blake3(tag)
    h.update(len(data).to_bytes(4, "little"))
    h.update(data)
    return int.from_bytes(h.digest(length=SIZE), "little") & _MASK


def mix(acc: bytes, remove: Optional[int] = None, add: Optional[int] = None) -> bytes:
    """``acc`` − ``remove`` + ``add`` (either may be None). Each lane of acc + 2^16 − remove
    stays positive, so the subtraction borrows across no lane; the sum stays below 2^18 per
    lane, inside its 32-bit slot; the mask then reduces every lane mod 2^16."""
    x = int.from_bytes(acc, "little") + _BIAS
    if remove is not None:
        x -= remove
    if add is not None:
        x += add
    return (x & _MASK).to_bytes(SIZE, "little")


class Accumulator:
    """Sum of many vectors, reducing only occasionally (each lane may grow to 2^32 − 1 before
    it must be reduced: 65,537 additions of 16-bit values). For hashing a whole set at once."""

    _REDUCE_EVERY = 32768

    def __init__(self, start: bytes = ZERO) -> None:
        self._x = int.from_bytes(start, "little")
        self._pending = 0
        self.count = 0  # vectors added

    def add(self, vector: int) -> None:
        self._x += vector
        self._pending += 1
        self.count += 1
        if self._pending >= self._REDUCE_EVERY:
            self._x &= _MASK
            self._pending = 0

    def digest(self) -> bytes:
        return (self._x & _MASK).to_bytes(SIZE, "little")


def root(domain: str, acc: bytes, length: int = 64) -> str:
    """The hex state root of a domain's accumulator. The empty set's root is all zeros, as the
    sequential roots it replaces define it, so an empty domain reads the same under both."""
    if acc == ZERO:
        return "0" * (2 * length)
    h = blake3.blake3(_ROOT_TAG)
    h.update(domain.encode())
    h.update(b"\x00")
    h.update(acc)
    return h.digest(length=length).hex()
