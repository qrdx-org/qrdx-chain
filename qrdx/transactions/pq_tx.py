"""
QRDX Post-Quantum Transaction (type 0x51)
=========================================

A Dilithium/ML-DSA-65-signed transaction that executes in the **same** EVM, in the
same block section, against the same ``account_state`` root as a secp256k1
transaction.  This is what lets a post-quantum account do everything a
traditional account can: transfer QRDX, call contracts, deploy contracts, and be
paid by contracts.

Why a typed transaction and not a new op
---------------------------------------
A secp256k1 transaction authenticates by *recovering* the sender from ``(v, r, s)``
— 65 bytes.  Dilithium has no recovery: verification needs the 1952-byte public
key alongside the 3309-byte signature.  That will never fit the legacy 9-field RLP
shape, so it needs its own envelope.

EIP-2718 gives us exactly that for free.  A typed transaction is
``type_byte ‖ payload``, and the type-byte space was entirely unused here — the
mempool rejected every typed transaction outright.  Claiming ``0x51`` ('Q') means:

  * ``eth_sendRawTransaction`` takes it with no signature change — it is just
    bytes, so web3.py's ``send_raw_transaction`` and any other client work as-is.
  * ``tx_hash = keccak(raw)``, the Ethereum rule, so ``eth_getTransactionByHash``
    and ``eth_getTransactionReceipt`` are unchanged.
  * The sender is a canonical 20-byte account id, so the EVM needs **no** changes
    whatsoever to execute it, and a contract sees an ordinary ``address``.

Wire format
-----------
    0x51 ‖ rlp([chain_id, nonce, gas_price, gas_limit, to, value, data,
                on_behalf_of, public_key, signature])

The signature covers the EIP-2718-style signing hash over the *unsigned* fields::

    sig_hash = keccak(0x51 ‖ rlp([chain_id, nonce, gas_price, gas_limit,
                                  to, value, data, on_behalf_of]))

``on_behalf_of`` is the optional **delegated source**: a 20-byte account id to spend FROM
instead of the signer's own account, or empty for an ordinary transaction. It exists for
system wallets, which are spent by their *controller* and have no key of their own — a
signer cannot otherwise spend from an address it does not hold the key for, by design.
It sits inside the signing hash, so it cannot be altered in flight, and the node still
has to authorise the relationship (``SystemWalletManager.can_spend_from``) before any
value moves. Gas and the nonce are charged to the SIGNER; only the value leaves the
delegated source.

Sender binding is by derivation, not by assertion: the sender is
``to_account_id(PQPublicKey(public_key).to_address())``.  There is no sender field
on the wire to forge — a transaction can only ever spend from the account its
embedded key derives to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import rlp
from eth_hash.auto import keccak

from ..crypto.account_id import to_account_id

__all__ = [
    "PQ_TX_TYPE",
    "PQTransaction",
    "encode_pq_tx",
    "decode_pq_tx",
    "pq_tx_signing_hash",
    "intrinsic_gas_pq",
    "is_pq_tx",
    "PQ_TX_BASE_GAS",
    "PQ_TX_VERIFY_GAS",
    "PQ_TX_CREATE_GAS",
]


# EIP-2718 transaction type byte. 0x51 == ASCII 'Q' (QRDX / quantum).
# Outside every Ethereum-assigned type (0x01 EIP-2930, 0x02 EIP-1559,
# 0x03 EIP-4844, 0x04 EIP-7702), so it can never collide upstream.
PQ_TX_TYPE = 0x51

# --- Gas -------------------------------------------------------------------
# The envelope carries ~5.3KB of key + signature material. It MUST be priced or
# it is a cheap way to make every node do a lot of work for 21000 gas.
PQ_TX_BASE_GAS = 21_000          # same floor as a legacy tx
PQ_TX_VERIFY_GAS = 40_000        # ML-DSA-65 verification (~10x an ecrecover)
PQ_TX_CREATE_GAS = 32_000        # EIP-2 contract-creation surcharge
_GAS_PER_ENVELOPE_BYTE = 16      # Istanbul non-zero calldata rate
_GAS_TXDATA_ZERO = 4
_GAS_TXDATA_NONZERO = 16


class InvalidPQTransaction(ValueError):
    """Raised when a type-0x51 payload is malformed or unauthenticated."""


def _to_bytes(value: int) -> bytes:
    """Minimal big-endian encoding, RLP's canonical integer form."""
    if value < 0:
        raise InvalidPQTransaction("negative integer field")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _from_bytes(raw: bytes) -> int:
    return int.from_bytes(raw, "big") if raw else 0


def is_pq_tx(raw: bytes) -> bool:
    """True iff ``raw`` is a type-0x51 PQ transaction envelope."""
    return bool(raw) and raw[0] == PQ_TX_TYPE


@dataclass
class PQTransaction:
    """A decoded / to-be-signed post-quantum transaction."""

    chain_id: int
    nonce: int
    gas_price: int
    gas_limit: int
    to: Optional[bytes]        # 20-byte account id, or None for contract creation
    value: int                 # wei
    data: bytes
    on_behalf_of: Optional[bytes] = None   # delegated source (system wallets); 20 bytes
    public_key: bytes = b""    # 1952-byte ML-DSA-65 public key
    signature: bytes = b""     # 3309-byte ML-DSA-65 signature

    # -- Field encoding -----------------------------------------------------

    def _unsigned_fields(self) -> list:
        return [
            _to_bytes(self.chain_id),
            _to_bytes(self.nonce),
            _to_bytes(self.gas_price),
            _to_bytes(self.gas_limit),
            self.to or b"",
            _to_bytes(self.value),
            self.data or b"",
            self.on_behalf_of or b"",
        ]

    def signing_hash(self) -> bytes:
        """The 32-byte digest the Dilithium key must sign."""
        return keccak(bytes([PQ_TX_TYPE]) + rlp.encode(self._unsigned_fields()))

    def encode(self) -> bytes:
        """Serialise the signed transaction to its wire bytes."""
        if not self.public_key or not self.signature:
            raise InvalidPQTransaction("cannot encode an unsigned PQ transaction")
        return bytes([PQ_TX_TYPE]) + rlp.encode(
            self._unsigned_fields() + [self.public_key, self.signature]
        )

    def hash(self) -> bytes:
        """Transaction hash — keccak over the wire bytes (the Ethereum rule)."""
        return keccak(self.encode())

    # -- Identity -----------------------------------------------------------

    def pq_address(self) -> str:
        """The human-facing ``0xPQ…`` address of the signing key."""
        from ..crypto.pq.dilithium import PQPublicKey
        return PQPublicKey.from_bytes(self.public_key).to_address()

    def sender(self) -> str:
        """
        The canonical 20-byte account id this transaction spends from.

        Derived from the embedded public key, so it cannot be forged: there is no
        sender field on the wire to tamper with.
        """
        return to_account_id(self.pq_address())

    def spend_from(self) -> str:
        """
        The account this transaction moves VALUE out of.

        Normally the signer. For a delegated spend it is ``on_behalf_of`` — but the node
        must still authorise that relationship before executing; this accessor only says
        what the transaction is asking for, never that it is permitted.
        """
        if self.on_behalf_of:
            return to_account_id(self.on_behalf_of)
        return self.sender()

    def is_delegated(self) -> bool:
        """True when this transaction spends from an account other than the signer's."""
        return bool(self.on_behalf_of)

    # -- Authentication -----------------------------------------------------

    def verify(self) -> bool:
        """
        Verify the ML-DSA-65 signature over ``signing_hash()``.

        Sender *binding* needs no separate check here — unlike an exchange
        transaction, which carries a ``sender`` field that must be proven to match
        the key, this format derives the sender FROM the key, so a valid signature
        is automatically a valid authorisation for exactly one account.

        Never raises; callers branch on the bool.
        """
        if not self.signature or not self.public_key:
            return False
        try:
            from ..crypto.pq.dilithium import PQPublicKey, PQSignature, verify as pq_verify

            pub = PQPublicKey.from_bytes(self.public_key)
            return pq_verify(
                pub, self.signing_hash(), PQSignature.from_bytes(self.signature)
            )
        except Exception:
            return False

    # -- Signing ------------------------------------------------------------

    def sign(self, private_key) -> "PQTransaction":
        """Sign in place with a ``PQPrivateKey`` and return self."""
        from ..crypto.pq.dilithium import sign as pq_sign

        self.public_key = private_key.public_key.to_bytes()
        self.signature = pq_sign(private_key, self.signing_hash()).to_bytes()
        return self

    # -- Gas ----------------------------------------------------------------

    def intrinsic_gas(self) -> int:
        return intrinsic_gas_pq(self.data, self.public_key, self.signature,
                               is_create=self.to is None)


def intrinsic_gas_pq(data: bytes, public_key: bytes, signature: bytes,
                     is_create: bool = False) -> int:
    """
    Minimum gas a PQ transaction must supply before execution begins.

    Prices three things: the legacy 21000 floor, the calldata, and — critically —
    the ~5.3KB authentication envelope plus the verification itself.  Without the
    envelope term a PQ transaction would impose ~250x a legacy transaction's
    bandwidth and verification cost at the same price.
    """
    gas = PQ_TX_BASE_GAS + PQ_TX_VERIFY_GAS
    if is_create:
        gas += PQ_TX_CREATE_GAS
    for byte in data or b"":
        gas += _GAS_TXDATA_ZERO if byte == 0 else _GAS_TXDATA_NONZERO
    gas += (len(public_key or b"") + len(signature or b"")) * _GAS_PER_ENVELOPE_BYTE
    return gas


def encode_pq_tx(tx: PQTransaction) -> bytes:
    """Module-level alias for ``tx.encode()``."""
    return tx.encode()


def pq_tx_signing_hash(tx: PQTransaction) -> bytes:
    """Module-level alias for ``tx.signing_hash()``."""
    return tx.signing_hash()


def decode_pq_tx(raw: bytes) -> PQTransaction:
    """
    Decode a type-0x51 envelope.

    Structural validation only — call ``verify()`` for authentication.

    Raises:
        InvalidPQTransaction: on a wrong type byte, malformed RLP, wrong field
            count, or a wrongly-sized key/signature/recipient.
    """
    if not is_pq_tx(raw):
        raise InvalidPQTransaction(
            f"not a PQ transaction (type byte {raw[0] if raw else 'empty'!r})"
        )
    try:
        fields = rlp.decode(raw[1:])
    except Exception as e:
        raise InvalidPQTransaction(f"malformed RLP: {e}") from e

    if len(fields) != 10:
        raise InvalidPQTransaction(f"expected 10 RLP fields, got {len(fields)}")

    (chain_id, nonce, gas_price, gas_limit, to, value, data, on_behalf_of,
     public_key, signature) = fields

    if to and len(to) != 20:
        raise InvalidPQTransaction(
            f"'to' must be a 20-byte account id or empty, got {len(to)} bytes"
        )
    if on_behalf_of and len(on_behalf_of) != 20:
        raise InvalidPQTransaction(
            f"'on_behalf_of' must be a 20-byte account id or empty, got "
            f"{len(on_behalf_of)} bytes"
        )

    # Reject wrong-sized key/signature material up front: it is cheaper than
    # letting the verifier allocate, and it keeps the failure mode explicit.
    from ..crypto.pq.dilithium import PUBLIC_KEY_SIZE, SIGNATURE_SIZE

    if len(public_key) != PUBLIC_KEY_SIZE:
        raise InvalidPQTransaction(
            f"public key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )
    if len(signature) != SIGNATURE_SIZE:
        raise InvalidPQTransaction(
            f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}"
        )

    return PQTransaction(
        chain_id=_from_bytes(chain_id),
        nonce=_from_bytes(nonce),
        gas_price=_from_bytes(gas_price),
        gas_limit=_from_bytes(gas_limit),
        to=bytes(to) if to else None,
        value=_from_bytes(value),
        data=bytes(data),
        on_behalf_of=bytes(on_behalf_of) if on_behalf_of else None,
        public_key=bytes(public_key),
        signature=bytes(signature),
    )
