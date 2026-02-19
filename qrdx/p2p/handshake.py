"""
QRDX Post-Quantum Handshake Protocol (Whitepaper §5.3)

Implements the 4-step PQ handshake between QRDX nodes:

    Node A                                           Node B
      |                                                 |
      | 1. HELLO(pq_algorithm, pubkey_A, nonce_A)       |
      |------------------------------------------------>|
      |                                                 |
      | 2. HELLO_ACK(pubkey_B, nonce_B,                 |
      |    Dilithium.sign(nonce_A, sk_B))               |
      |<------------------------------------------------|
      |                                                 |
      | 3. AUTH(Dilithium.sign(nonce_B, sk_A),           |
      |    Kyber.encapsulate(pubkey_B))                 |
      |------------------------------------------------>|
      |                                                 |
      | 4. AUTH_ACK(Kyber.decapsulate(ciphertext))       |
      |<------------------------------------------------|
      |                                                 |
      | [Encrypted channel via AES-256-GCM]              |

After the handshake, all communication is encrypted using the
Kyber-derived shared secret with AES-256-GCM.
"""

import os
import time
import struct
from enum import IntEnum
from typing import Optional, Tuple, NamedTuple
from dataclasses import dataclass, field

import oqs
import blake3

from ..logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NONCE_SIZE = 32  # 32 bytes of randomness per nonce
HANDSHAKE_TIMEOUT_SEC = 5.0

# Resolve algorithm names at import time (ML-DSA-65 preferred, Dilithium3 legacy)
def _resolve_sig_algorithm() -> str:
    for name in ('ML-DSA-65', 'Dilithium3'):
        try:
            oqs.Signature(name)
            return name
        except Exception:
            continue
    raise RuntimeError('No supported PQ signature algorithm found in liboqs')

def _resolve_kem_algorithm() -> str:
    for name in ('ML-KEM-768', 'Kyber768'):
        try:
            oqs.KeyEncapsulation(name)
            return name
        except Exception:
            continue
    raise RuntimeError('No supported PQ KEM algorithm found in liboqs')

PQ_SIG_ALGORITHM = _resolve_sig_algorithm()
PQ_KEM_ALGORITHM = _resolve_kem_algorithm()


class HandshakeStep(IntEnum):
    """Handshake message type identifiers."""
    HELLO = 1
    HELLO_ACK = 2
    AUTH = 3
    AUTH_ACK = 4


# ---------------------------------------------------------------------------
# Message Types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HelloMessage:
    """Step 1: Initiator says hello."""
    algorithm: str        # PQ signature algorithm (e.g. 'Dilithium3')
    pubkey: bytes         # Initiator's Dilithium public key
    nonce: bytes          # 32-byte random nonce

    def to_dict(self) -> dict:
        return {
            'step': int(HandshakeStep.HELLO),
            'algorithm': self.algorithm,
            'pubkey': self.pubkey.hex(),
            'nonce': self.nonce.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'HelloMessage':
        return cls(
            algorithm=d['algorithm'],
            pubkey=bytes.fromhex(d['pubkey']),
            nonce=bytes.fromhex(d['nonce']),
        )


@dataclass(frozen=True)
class HelloAckMessage:
    """Step 2: Responder acknowledges and proves identity."""
    pubkey: bytes           # Responder's Dilithium public key
    nonce: bytes            # Responder's 32-byte random nonce
    signature: bytes        # Dilithium.sign(initiator_nonce, sk_B)
    kem_pubkey: bytes       # Responder's Kyber public key for key exchange

    def to_dict(self) -> dict:
        return {
            'step': int(HandshakeStep.HELLO_ACK),
            'pubkey': self.pubkey.hex(),
            'nonce': self.nonce.hex(),
            'signature': self.signature.hex(),
            'kem_pubkey': self.kem_pubkey.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'HelloAckMessage':
        return cls(
            pubkey=bytes.fromhex(d['pubkey']),
            nonce=bytes.fromhex(d['nonce']),
            signature=bytes.fromhex(d['signature']),
            kem_pubkey=bytes.fromhex(d['kem_pubkey']),
        )


@dataclass(frozen=True)
class AuthMessage:
    """Step 3: Initiator proves identity and encapsulates shared secret."""
    signature: bytes        # Dilithium.sign(responder_nonce, sk_A)
    ciphertext: bytes       # Kyber.encapsulate(kem_pubkey_B) → ciphertext

    def to_dict(self) -> dict:
        return {
            'step': int(HandshakeStep.AUTH),
            'signature': self.signature.hex(),
            'ciphertext': self.ciphertext.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'AuthMessage':
        return cls(
            signature=bytes.fromhex(d['signature']),
            ciphertext=bytes.fromhex(d['ciphertext']),
        )


@dataclass(frozen=True)
class AuthAckMessage:
    """Step 4: Responder confirms shared secret."""
    success: bool
    session_id: str         # BLAKE3(shared_secret || nonce_A || nonce_B)

    def to_dict(self) -> dict:
        return {
            'step': int(HandshakeStep.AUTH_ACK),
            'success': self.success,
            'session_id': self.session_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'AuthAckMessage':
        return cls(
            success=d['success'],
            session_id=d['session_id'],
        )


# ---------------------------------------------------------------------------
# Session Result
# ---------------------------------------------------------------------------

@dataclass
class HandshakeResult:
    """Outcome of a completed handshake."""
    success: bool
    peer_pubkey: Optional[bytes] = None     # Peer's Dilithium public key
    peer_node_id: Optional[str] = None      # Peer's BLAKE3 node ID (qx…)
    shared_secret: Optional[bytes] = None   # Kyber-derived 32-byte key
    session_id: Optional[str] = None        # Session identifier
    error: Optional[str] = None


def _derive_session_id(shared_secret: bytes, nonce_a: bytes, nonce_b: bytes) -> str:
    """Derive a unique session ID from the key-exchange material."""
    return blake3.blake3(shared_secret + nonce_a + nonce_b).hexdigest()[:32]


def _derive_node_id(pubkey: bytes) -> str:
    """Derive a node ID from a Dilithium public key — same as identity module."""
    return f"qx{blake3.blake3(pubkey).hexdigest()[:40]}"


# ---------------------------------------------------------------------------
# Initiator (Node A) — creates HELLO, processes HELLO_ACK, creates AUTH
# ---------------------------------------------------------------------------

class HandshakeInitiator:
    """
    Drives the initiator side of the PQ handshake.

    Usage:
        init = HandshakeInitiator(my_secret_key, my_public_key)
        hello = init.create_hello()        # → send to peer
        auth  = init.process_hello_ack(ack) # → send to peer
        result = init.process_auth_ack(ack) # → done
    """

    def __init__(self, secret_key: bytes, public_key: bytes):
        self._sk = secret_key
        self._pk = public_key
        self._nonce_a = os.urandom(NONCE_SIZE)
        self._peer_pubkey: Optional[bytes] = None
        self._peer_nonce: Optional[bytes] = None
        self._shared_secret: Optional[bytes] = None
        self._started_at = time.monotonic()

    def create_hello(self) -> HelloMessage:
        """Step 1 — build the HELLO message."""
        return HelloMessage(
            algorithm=PQ_SIG_ALGORITHM,
            pubkey=self._pk,
            nonce=self._nonce_a,
        )

    def process_hello_ack(self, ack: HelloAckMessage) -> AuthMessage:
        """
        Step 2→3 — verify responder's signature, then create AUTH.

        Raises ValueError on verification failure.
        """
        # Verify responder signed our nonce
        verifier = oqs.Signature(PQ_SIG_ALGORITHM)
        if not verifier.verify(self._nonce_a, ack.signature, ack.pubkey):
            raise ValueError("HELLO_ACK signature verification failed — possible MITM")

        self._peer_pubkey = ack.pubkey
        self._peer_nonce = ack.nonce

        # Sign the responder's nonce to prove our identity
        signer = oqs.Signature(PQ_SIG_ALGORITHM, self._sk)
        sig_a = signer.sign(ack.nonce)

        # Kyber encapsulation using responder's KEM public key
        kem = oqs.KeyEncapsulation(PQ_KEM_ALGORITHM)
        ciphertext, shared_secret = kem.encap_secret(ack.kem_pubkey)
        self._shared_secret = shared_secret

        return AuthMessage(signature=sig_a, ciphertext=ciphertext)

    def process_auth_ack(self, ack: AuthAckMessage) -> HandshakeResult:
        """Step 4 — verify AUTH_ACK and return session result."""
        if not ack.success:
            return HandshakeResult(success=False, error="Peer rejected AUTH")

        expected_session = _derive_session_id(
            self._shared_secret, self._nonce_a, self._peer_nonce
        )

        if ack.session_id != expected_session:
            return HandshakeResult(
                success=False,
                error="Session ID mismatch — shared secret disagrees"
            )

        return HandshakeResult(
            success=True,
            peer_pubkey=self._peer_pubkey,
            peer_node_id=_derive_node_id(self._peer_pubkey),
            shared_secret=self._shared_secret,
            session_id=expected_session,
        )


# ---------------------------------------------------------------------------
# Responder (Node B) — processes HELLO, creates HELLO_ACK, processes AUTH
# ---------------------------------------------------------------------------

class HandshakeResponder:
    """
    Drives the responder side of the PQ handshake.

    Usage:
        resp = HandshakeResponder(my_secret_key, my_public_key)
        hello_ack = resp.process_hello(hello)       # → send back
        result    = resp.process_auth(auth_msg)      # → send AUTH_ACK, done
    """

    def __init__(self, secret_key: bytes, public_key: bytes):
        self._sk = secret_key
        self._pk = public_key
        self._nonce_b = os.urandom(NONCE_SIZE)
        self._peer_pubkey: Optional[bytes] = None
        self._peer_nonce: Optional[bytes] = None
        self._shared_secret: Optional[bytes] = None
        self._kem_secret_key: Optional[bytes] = None
        self._started_at = time.monotonic()

    def process_hello(self, hello: HelloMessage) -> HelloAckMessage:
        """
        Step 1→2 — validate HELLO, sign initiator nonce, generate KEM keypair.
        """
        if hello.algorithm != PQ_SIG_ALGORITHM:
            raise ValueError(f"Unsupported algorithm: {hello.algorithm}")

        if len(hello.nonce) != NONCE_SIZE:
            raise ValueError(f"Invalid nonce length: {len(hello.nonce)}")

        self._peer_pubkey = hello.pubkey
        self._peer_nonce = hello.nonce

        # Sign the initiator's nonce
        signer = oqs.Signature(PQ_SIG_ALGORITHM, self._sk)
        sig_b = signer.sign(hello.nonce)

        # Generate ephemeral Kyber keypair for this session
        kem = oqs.KeyEncapsulation(PQ_KEM_ALGORITHM)
        kem_pubkey = kem.generate_keypair()
        self._kem_secret_key = kem.export_secret_key()

        return HelloAckMessage(
            pubkey=self._pk,
            nonce=self._nonce_b,
            signature=sig_b,
            kem_pubkey=kem_pubkey,
        )

    def process_auth(self, auth: AuthMessage) -> Tuple[AuthAckMessage, HandshakeResult]:
        """
        Step 3→4 — verify initiator's signature, decapsulate shared secret.

        Returns (AuthAckMessage to send, HandshakeResult).
        """
        # Verify initiator signed our nonce
        verifier = oqs.Signature(PQ_SIG_ALGORITHM)
        if not verifier.verify(self._nonce_b, auth.signature, self._peer_pubkey):
            ack = AuthAckMessage(success=False, session_id='')
            return ack, HandshakeResult(success=False, error="AUTH signature verification failed")

        # Kyber decapsulation
        kem = oqs.KeyEncapsulation(PQ_KEM_ALGORITHM, self._kem_secret_key)
        shared_secret = kem.decap_secret(auth.ciphertext)
        self._shared_secret = shared_secret

        session_id = _derive_session_id(shared_secret, self._peer_nonce, self._nonce_b)

        ack = AuthAckMessage(success=True, session_id=session_id)
        result = HandshakeResult(
            success=True,
            peer_pubkey=self._peer_pubkey,
            peer_node_id=_derive_node_id(self._peer_pubkey),
            shared_secret=shared_secret,
            session_id=session_id,
        )
        return ack, result


# ---------------------------------------------------------------------------
# AES-256-GCM Channel Encryption (post-handshake)
# ---------------------------------------------------------------------------

def derive_channel_keys(shared_secret: bytes, nonce_a: bytes, nonce_b: bytes) -> Tuple[bytes, bytes]:
    """
    Derive AES-256-GCM encryption keys from the handshake material.

    Returns (send_key, recv_key) — each 32 bytes.
    The initiator uses (send_key, recv_key); the responder swaps them.
    """
    # Use BLAKE3 in keyed mode to derive separate directional keys
    send_key = blake3.blake3(
        b'qrdx-send' + shared_secret + nonce_a + nonce_b
    ).digest()

    recv_key = blake3.blake3(
        b'qrdx-recv' + shared_secret + nonce_a + nonce_b
    ).digest()

    return send_key, recv_key


def encrypt_message(key: bytes, plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
    """
    Encrypt a message using AES-256-GCM.

    Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if nonce is None:
        nonce = os.urandom(12)

    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct  # 12 + len(plaintext) + 16


def decrypt_message(key: bytes, data: bytes) -> bytes:
    """
    Decrypt a message encrypted with encrypt_message().

    Raises InvalidTag on tampered data.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(data) < 28:  # 12 nonce + 16 tag minimum
        raise ValueError("Ciphertext too short")

    nonce = data[:12]
    ct = data[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)
