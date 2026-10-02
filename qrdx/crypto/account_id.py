"""
QRDX Canonical Account Identity
===============================

The **single** key under which every account's state lives, regardless of which
credential secures it.

Why this exists
---------------
QRDX has two credential families: secp256k1 (``0x…``, 20 bytes) and Dilithium /
ML-DSA-65 (``0xPQ…``, 32 bytes).  The EVM — and therefore Solidity's ``address``
type, the ABI, every deployed contract, and every piece of Ethereum tooling — is
irreducibly 20-byte addressed.  A 32-byte account can never be named by a
contract, appear as ``msg.sender``, or be encoded in an RLP ``to`` field.

So the ledger is keyed by a 20-byte **account id**, and the ``0xPQ…`` string is
demoted to what it actually is: a *credential fingerprint* used for display and
for binding a signature to an account.  Both forms name the same single
``account_state`` row.

Derive, never register
----------------------
The account id is a **pure function** of the display address — no lookup table,
no registry row, no resolution step that can be missing.  This is the whole point.
An alias scheme backed by a registry needs a reconciliation path for "contract
paid an alias this node never registered", and reconciliation of two
representations into one row is precisely the class of bug that has repeatedly
broken this chain's reorg rebuild.  A derived id has no second representation to
reconcile: a contract paying the 20-byte form credits the exact row the PQ key
controls, because they *are* the same account.

    traditional  0x + 40 hex   →  itself (identity — existing addresses unchanged)
    post-quantum 0xPQ + 64 hex →  keccak(DOMAIN:pq     ‖ raw32 )[-20:]
    multisig     0xPQMS+38 hex →  keccak(DOMAIN:ms     ‖ raw19 )[-20:]
    legacy       Q/R base58    →  keccak(DOMAIN:legacy ‖ ascii )[-20:]
    pool/escrow  0xPOOL,0xCLOB →  keccak(DOMAIN:internal:TAG ‖ ascii )[-20:]

Security note (deliberate, documented trade-off)
------------------------------------------------
Truncating to 20 bytes puts the account id at ~80 bits of collision resistance:
grinding two Dilithium keypairs whose account ids collide is ~2^80 classical
work, versus ~2^128 for the 32-byte ``0xPQ`` form.  This is *exactly* Ethereum's
own bound and is the unavoidable price of EVM/web3 compatibility — a 32-byte
account simply cannot be expressed to a contract.

Crucially it does **not** weaken the post-quantum property that motivates the PQ
credential: quantum resistance here is about *signature forgery* (Shor breaking
secp256k1 key recovery), and the Dilithium signature still authorises every spend.
Collision grinding is a classical pre-computation attack that buys an attacker
nothing against a *specific* existing account — second-preimage on a 20-byte
truncation is ~2^160.

Do not widen this to 32 bytes "for safety": doing so re-partitions the ledger and
un-does the unification.
"""

from __future__ import annotations

from typing import Union

from .hashing import keccak256

__all__ = [
    "ACCOUNT_ID_DOMAIN",
    "ACCOUNT_ID_LENGTH",
    "to_account_id",
    "to_account_id_bytes",
    "is_account_id",
    "same_account",
]


# Domain separator — keeps account-id derivation from ever colliding with any
# other keccak use in the protocol (contract addresses, tx hashes, storage slots).
ACCOUNT_ID_DOMAIN = b"QRDX-ACCOUNT-ID-v1"

ACCOUNT_ID_LENGTH = 20  # bytes

# Protocol-internal holder prefixes.
#
# These are NOT user credentials and no key can sign for them: they are
# deterministic identifiers the protocol derives for state it owns itself — an AMM
# pool's reserves and a CLOB book's resting-order escrow (see
# ExchangeStateManager.pool_holder_address / orderbook_escrow_address). They hold real
# token balances that are part of the token state root, so they MUST be keyable.
#
# They are enumerated explicitly rather than handled by a permissive "anything that
# isn't hex" fallback. A fallback would make every typo and every malformed
# user-supplied recipient silently keyable, which is exactly the strictness that
# catches an unspendable TOKEN_TRANSFER recipient before it burns the tokens.
# Adding a new protocol-derived holder form means adding it here, deliberately.
SYNTHETIC_HOLDER_PREFIXES = ("0xPOOL", "0xCLOB", "0xPERP")

# 0xPERP is the perps clearinghouse holder (docs/PERPS_CLEARINGHOUSE.md): all perp collateral.
# Every synthetic form is <prefix> + blake2b(digest_size=18).hexdigest() = 36 hex chars.
# Validated, so a malformed one raises like any other bad address rather than being
# hashed into some arbitrary account.
SYNTHETIC_HOLDER_BODY_LENGTH = 36


def _derive(tag: bytes, payload: bytes) -> str:
    """Domain-separated truncated keccak → lowercase 0x account id."""
    digest = keccak256(ACCOUNT_ID_DOMAIN + b":" + tag + b":" + payload)
    return "0x" + digest[-ACCOUNT_ID_LENGTH:].hex()


def is_synthetic_holder(value: object) -> bool:
    """True iff ``value`` is a well-formed protocol holder address (0xPOOL/0xCLOB/0xPERP)."""
    if not isinstance(value, str):
        return False
    for prefix in SYNTHETIC_HOLDER_PREFIXES:
        if value[:len(prefix)].upper() == prefix.upper():
            body = value[len(prefix):]
            if len(body) != SYNTHETIC_HOLDER_BODY_LENGTH:
                return False
            try:
                bytes.fromhex(body)
            except ValueError:
                return False
            return True
    return False


def is_account_id(value: object) -> bool:
    """True iff ``value`` is already a canonical 20-byte ``0x`` account id."""
    if not isinstance(value, str):
        return False
    if len(value) != 2 + 2 * ACCOUNT_ID_LENGTH:
        return False
    if not value.startswith("0x") and not value.startswith("0X"):
        return False
    try:
        bytes.fromhex(value[2:])
    except ValueError:
        return False
    return True


def to_account_id(address: Union[str, bytes, bytearray, memoryview]) -> str:
    """
    Resolve any QRDX address form to its canonical lowercase ``0x`` account id.

    This is the ONLY function that may decide what key an account's state lives
    under.  Every ledger boundary — balance reads, balance deltas, the EVM state
    cache, genesis funding, the token ledger — routes through it, which is what
    makes ``0x`` and ``0xPQ`` the same account rather than two that must be kept
    in sync.

    Idempotent: feeding it an account id returns that id (lowercased), so it is
    safe to apply at every layer without double-derivation.

    Args:
        address: ``0x…`` / ``0xPQ…`` / ``0xPQMS…`` / legacy ``Q``,``R`` string, or
            raw 20 bytes.

    Returns:
        Lowercase ``0x`` + 40 hex account id.

    Raises:
        ValueError: on an unrecognisable address form.  Callers at consensus
            boundaries must NOT swallow this — an unkeyable address is a bug, and
            silently bucketing it would fork state.
    """
    # Raw 20-byte form (the EVM's native currency).
    if isinstance(address, (bytes, bytearray, memoryview)):
        raw = bytes(address)
        if len(raw) != ACCOUNT_ID_LENGTH:
            raise ValueError(
                f"raw account id must be {ACCOUNT_ID_LENGTH} bytes, got {len(raw)}"
            )
        return "0x" + raw.hex()

    if not isinstance(address, str):
        raise ValueError(f"address must be str or bytes, got {type(address).__name__}")

    addr = address.strip()
    if not addr:
        raise ValueError("empty address")

    # Multisig FIRST: "0xPQMS…" also starts with "0xPQ", so order matters.
    if addr.startswith("0xPQMS") or addr.startswith("0xpqms"):
        raw_hex = addr[6:]
        try:
            payload = bytes.fromhex(raw_hex.lower())
        except ValueError as e:
            raise ValueError(f"malformed multisig address {addr!r}: {e}") from e
        return _derive(b"ms", payload)

    if addr.startswith("0xPQ") or addr.startswith("0xpq"):
        raw_hex = addr[4:]
        if len(raw_hex) != 64:
            raise ValueError(
                f"PQ address must be 64 hex chars after 0xPQ, got {len(raw_hex)}"
            )
        try:
            payload = bytes.fromhex(raw_hex.lower())
        except ValueError as e:
            raise ValueError(f"malformed PQ address {addr!r}: {e}") from e
        return _derive(b"pq", payload)

    # Protocol-internal holders (pool reserves, order-book escrow). Keyed by a
    # domain-separated hash of the full identifier, with the prefix inside the tag so
    # a pool and a book can never collide with each other or with a user account.
    for prefix in SYNTHETIC_HOLDER_PREFIXES:
        # Case-insensitive on the whole prefix (note: uppercasing the address would
        # turn its "0x" into "0X", so compare the slice, not an uppercased address).
        if addr[:len(prefix)].upper() == prefix.upper():
            body = addr[len(prefix):].lower()
            if len(body) != SYNTHETIC_HOLDER_BODY_LENGTH:
                raise ValueError(
                    f"{prefix} holder must have {SYNTHETIC_HOLDER_BODY_LENGTH} hex "
                    f"chars after the prefix, got {len(body)}: {addr!r}")
            try:
                bytes.fromhex(body)
            except ValueError as e:
                raise ValueError(f"malformed {prefix} holder {addr!r}: {e}") from e
            return _derive(b"internal:" + prefix[2:].encode("ascii"),
                           body.encode("ascii"))

    if addr.startswith("0x") or addr.startswith("0X"):
        raw_hex = addr[2:]
        if len(raw_hex) != 2 * ACCOUNT_ID_LENGTH:
            raise ValueError(
                f"traditional address must be {2 * ACCOUNT_ID_LENGTH} hex chars, "
                f"got {len(raw_hex)}"
            )
        try:
            bytes.fromhex(raw_hex.lower())
        except ValueError as e:
            raise ValueError(f"malformed address {addr!r}: {e}") from e
        # Identity: a 20-byte address IS its own account id. Existing 0x accounts,
        # contract addresses, and every Ethereum tool keep working untouched.
        return "0x" + raw_hex.lower()

    # Bare 40-hex (no 0x). eth_utils' to_checksum_address accepted this form, and
    # this function replaced it at several call sites, so keep accepting it.
    if len(addr) == 2 * ACCOUNT_ID_LENGTH:
        try:
            bytes.fromhex(addr.lower())
        except ValueError:
            pass
        else:
            return "0x" + addr.lower()

    # Legacy base58 curve-point addresses (migration-only).
    if addr[0] in ("Q", "R"):
        return _derive(b"legacy", addr.encode("ascii", errors="strict"))

    raise ValueError(f"unrecognised address form: {addr!r}")


def to_account_id_bytes(address: Union[str, bytes]) -> bytes:
    """``to_account_id`` as raw 20 bytes — the form the EVM wants."""
    return bytes.fromhex(to_account_id(address)[2:])


def same_account(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """True iff both address forms name the same account."""
    try:
        return to_account_id(a) == to_account_id(b)
    except ValueError:
        return False
