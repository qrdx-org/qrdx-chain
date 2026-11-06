"""
Quantum migration (docs/QUANTUM_MIGRATION.md): an account whose key is ECDSA names, while ECDSA
still holds, the post-quantum account that should control it once ECDSA cannot be trusted.

Two ways to name it, one binding (``AccountAuthority.migrations``) and the same effect: the
post-quantum account becomes a controller of the ``0x`` account on QRDX (account control), so it
can sign for it — and once the account turns its own key off, or the Doomsday Protocol turns every
ECDSA key off, only it can.

* **On QRDX**, the ``0x`` account sends ``ACCOUNT_POLICY`` through the EVM write precompile
  (0x…0401) with its own ECDSA signature: ``add_controller``, then, when it chooses,
  ``own_key: false``. Ordinary account control, nothing special.
* **On Ethereum** (or any bridged EVM chain), before any of it reaches QRDX: the account calls
  ``QRDXMigrationRegistry.register(successor)`` once (contracts/migration/). Anyone then proves
  that commitment on QRDX (``MIGRATION_CLAIM``) with a storage proof against a finalized head of
  that chain the validators attested, as a bridge deposit is proven. The account's address is the
  same on both chains (an externally owned account's address is its key's), so the commitment
  binds the QRDX account with that address.

A commitment made after the Doomsday Protocol triggered proves nothing: by then ECDSA keys may be
broken, and anyone could have registered for anyone (qrdx/exchange/doomsday.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional

SUCCESSOR_SLOT = 0  # QRDXMigrationRegistry.successorOf
REGISTERED_AT_SLOT = 1  # QRDXMigrationRegistry.registeredAt

_HEX20 = re.compile(r"^0x[0-9a-f]{40}$")
_PQ_ACCOUNT = re.compile(r"^0x[Pp][Qq][0-9a-fA-F]{64}$")


class MigrationError(ValueError):
    """A migration claim that cannot bind; nothing has changed."""


def mapping_slot(account: str, slot: int) -> bytes:
    """The storage slot of ``mapping(address => …)[account]`` declared at ``slot``."""
    from eth_utils import keccak

    return keccak(bytes(12) + bytes.fromhex(account[2:]) + int(slot).to_bytes(32, "big"))


def parse_registries(entries: Iterable[str]) -> Dict[int, str]:
    """``MIGRATION_REGISTRIES`` entries, each ``CHAIN_ID:REGISTRY_ADDRESS``."""
    out: Dict[int, str] = {}
    for entry in entries:
        parts = [p.strip() for p in str(entry).split(":")]
        if len(parts) != 2 or not _HEX20.match(parts[1].lower()):
            raise MigrationError(f"migration registry {entry!r}: expected CHAIN_ID:0xADDRESS")
        try:
            chain = int(parts[0])
        except ValueError:
            raise MigrationError(
                f"migration registry {entry!r}: the chain id is a number"
            ) from None
        if chain <= 0 or chain in out:
            raise MigrationError(f"migration registry {entry!r}: bad or repeated chain id")
        out[chain] = parts[1].lower()
    return out


def configured_registries() -> Dict[int, str]:
    from .. import constants

    return parse_registries(constants.MIGRATION_REGISTRIES)


@dataclass(frozen=True)
class Claim:
    chain: int
    account: str  # the 0x account, lowercase
    successor: str  # its post-quantum account, 0xPQ + 64 hex (as given)
    time: int  # when it registered (the source chain's block time)

    @property
    def successor_bytes(self) -> bytes:
        return bytes.fromhex(self.successor[4:])


def parse_claim(p: Dict[str, Any]) -> Claim:
    try:
        chain = int(p["chain"])
        account = str(p["account"]).lower()
        successor = str(p["successor"])
        when = p["time"]
    except (KeyError, TypeError, ValueError) as exc:
        raise MigrationError(f"malformed claim: {exc}") from exc
    if not _HEX20.match(account):
        raise MigrationError("account is the 0x address that registered")
    if not _PQ_ACCOUNT.match(successor):
        raise MigrationError("successor is a post-quantum account, 0xPQ + 64 hex")
    if isinstance(when, bool) or not isinstance(when, int) or not 0 < when < 1 << 63:
        raise MigrationError("time is the registration's block time, in seconds")
    return Claim(chain, account, successor, when)


def verify_claim(
    claim: Claim,
    head: Any,
    registry: Optional[str],
    account_proof: Any,
    successor_proof: Any,
    time_proof: Any,
) -> Optional[str]:
    """Why the proofs do not show ``registry`` holding exactly this commitment at ``head``'s
    state root, or None if they do."""
    from ..contracts.external_proof_evm import verify
    from .bridge import BridgeError, _proof_nodes

    if registry is None:
        return f"chain {claim.chain} has no registry in MIGRATION_REGISTRIES"
    if head is None:
        return "no attested head of that chain at that height (one of the last 64)"
    try:
        account_nodes = _proof_nodes(account_proof, "account_proof")
        proofs = (
            (
                SUCCESSOR_SLOT,
                _proof_nodes(successor_proof, "successor_proof"),
                claim.successor_bytes,
            ),
            (
                REGISTERED_AT_SLOT,
                _proof_nodes(time_proof, "time_proof"),
                claim.time.to_bytes(32, "big"),
            ),
        )
    except BridgeError as e:
        return str(e)
    root = bytes.fromhex(head.state_root[2:])
    registry_bytes = bytes.fromhex(registry[2:])
    for slot, nodes, want in proofs:
        out = verify(root, registry_bytes, account_nodes, mapping_slot(claim.account, slot), nodes)
        if out is None:
            return "the proof does not hold against the attested head"
        if out[-32:] != want:
            return "the registry does not hold this commitment"
    return None
