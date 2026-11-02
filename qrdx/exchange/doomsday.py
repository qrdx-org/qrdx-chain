"""
The Doomsday Protocol (docs/QUANTUM_MIGRATION.md "Doomsday"): what QRDX does once ECDSA cannot
be trusted.

**The canary.** For each bridged chain the chain spec names a canary (``DOOMSDAY_CANARIES``,
``CHAIN_ID:ADDRESS``). It is an address whose public key was derived from a hash
(``canary_key``), so no one knows its private key, and funded with a bounty only that key can move.
An account's nonce grows only when its key signs. So the canary's nonce above 0, proven against a
finalized head of that chain the validators attested (``DOOMSDAY_PROVE``, sent by anyone), proves
that someone derived an ECDSA private key from its public key: with a quantum computer, or a
mathematical break. Governance can also declare it (``declare_quantum_emergency``).

**What changes, from the block that triggers it.**

* **Every ECDSA key on QRDX stops signing.** EVM transactions signed with secp256k1 are
  refused, and agents an ECDSA account approved act for it no more. An Ethereum account acts only
  through its post-quantum controllers: the successor it bound beforehand (quantum migration), or
  the controller it added with account control. Accounts that bound none wait, untouched, for a
  recovery governance decides.
* **The bridge stops.** Deposits are no longer minted, by attestation or by proof: the source
  chains' own consensus and accounts may be broken. Withdrawals to them are refused.
* **No later commitment counts.** A migration commitment registered at or after the trigger's
  time proves nothing (anyone could have signed it).

The state is a single committed entry (the bridge's flags, in the exchange root), so every node
agrees from the block on, and a reorganization takes it back with the block.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, Optional

_HEX20 = re.compile(r"^0x[0-9a-f]{40}$")
_ECDSA_ACCOUNT = re.compile(r"^0x[0-9a-fA-F]{40}$")

# secp256k1
_P = 2**256 - 2**32 - 977
_B = 7


class DoomsdayError(ValueError):
    """A doomsday proof that does not hold; nothing has changed."""


def canary_key(label: str = "QRDX doomsday canary") -> bytes:
    """A secp256k1 public key (64 bytes, x · y) no one knows the private key of: the first valid
    x at or above sha256(label), with its even y. Anyone can recompute it from the label."""
    x = int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % _P
    while True:
        rhs = (pow(x, 3, _P) + _B) % _P
        y = pow(rhs, (_P + 1) // 4, _P)
        if y * y % _P == rhs:
            if y % 2:
                y = _P - y
            return x.to_bytes(32, "big") + y.to_bytes(32, "big")
        x += 1


def canary_address(label: str = "QRDX doomsday canary") -> str:
    from eth_utils import keccak

    return "0x" + keccak(canary_key(label))[12:].hex()


def parse_canaries(entries: Iterable[str]) -> Dict[int, str]:
    """``DOOMSDAY_CANARIES`` entries, each ``CHAIN_ID:CANARY_ADDRESS``."""
    out: Dict[int, str] = {}
    for entry in entries:
        parts = [p.strip() for p in str(entry).split(":")]
        if len(parts) != 2 or not _HEX20.match(parts[1].lower()):
            raise DoomsdayError(f"doomsday canary {entry!r}: expected CHAIN_ID:0xADDRESS")
        try:
            chain = int(parts[0])
        except ValueError:
            raise DoomsdayError(f"doomsday canary {entry!r}: the chain id is a number") from None
        if chain <= 0 or chain in out:
            raise DoomsdayError(f"doomsday canary {entry!r}: bad or repeated chain id")
        out[chain] = parts[1].lower()
    return out


def configured_canaries() -> Dict[int, str]:
    from .. import constants

    return parse_canaries(constants.DOOMSDAY_CANARIES)


def is_ecdsa_account(address: str) -> bool:
    """A ``0x`` + 40 hex account: one an ECDSA key may have signed for."""
    return bool(_ECDSA_ACCOUNT.match(str(address)))


def verify_canary_spent(
    chain: int, head: Any, canary: Optional[str], account_proof: Any
) -> Optional[str]:
    """Why the proof does not show the canary's nonce above 0 at ``head``, or None if it does."""
    from ..contracts.external_proof_evm import verify
    from .bridge import BridgeError, _proof_nodes

    if canary is None:
        return f"chain {chain} has no canary in DOOMSDAY_CANARIES"
    if head is None:
        return "no attested head of that chain at that height (one of the last 64)"
    try:
        nodes = _proof_nodes(account_proof, "account_proof")
    except BridgeError as e:
        return str(e)
    out = verify(bytes.fromhex(head.state_root[2:]), bytes.fromhex(canary[2:]), nodes, None, [])
    if out is None:
        return "the proof does not hold against the attested head"
    if int.from_bytes(out[1:33], "big") == 0:
        return "the canary has never signed: ECDSA holds"
    return None
