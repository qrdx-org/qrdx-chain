"""
Post-Quantum Cryptography P2P Authentication for QRDX Chain
Implements hybrid handshake supporting both legacy ECIES and PQC (Dilithium+Kyber)
"""

import asyncio
import os
import struct
from typing import Tuple, Optional
import rlp
from rlp import sedes

from eth_keys import datatypes
from eth_utils import ValidationError

from p2p.abc import NodeAPI
from p2p.constants import REPLY_TIMEOUT
from p2p.exceptions import HandshakeFailure, DecryptionError, BadAckMessage
from p2p._utils import get_logger, sxor

from trinity.crypto.pqc import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    KyberPrivateKey,
    KyberPublicKey,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    DILITHIUM_PUBLIC_KEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE,
    KYBER_PUBLIC_KEY_SIZE,
    KYBER_CIPHERTEXT_SIZE,
    KYBER_SHARED_SECRET_SIZE,
)
from trinity.crypto.hashing import blake3_256, blake3_512, Blake3Hash


# Protocol version constants
PROTOCOL_VERSION_LEGACY = 0x04  # Legacy ECIES (RLPx v4)
PROTOCOL_VERSION_PQC = 0x10     # Post-Quantum Cryptography

# Message sizes for PQC handshake
PQC_AUTH_MSG_SIZE = (
    1 +  # version byte
    DILITHIUM_PUBLIC_KEY_SIZE +  # initiator public key
    KYBER_PUBLIC_KEY_SIZE +      # ephemeral Kyber public key
    32 +  # nonce
    DILITHIUM_SIGNATURE_SIZE     # signature over handshake data
)

PQC_ACK_MSG_SIZE = (
    1 +  # version byte
    DILITHIUM_PUBLIC_KEY_SIZE +  # responder public key
    KYBER_CIPHERTEXT_SIZE +      # encapsulated shared secret
    32 +  # nonce
    DILITHIUM_SIGNATURE_SIZE     # signature over handshake data
)


class PQCHandshakeBase:
    """
    Base class for PQC handshake with Dilithium signatures and Kyber key encapsulation.
    """
    
    _is_initiator = False
    
    def __init__(
        self,
        remote: NodeAPI,
        dilithium_privkey: DilithiumPrivateKey,
        remote_dilithium_pubkey: Optional[DilithiumPublicKey] = None,
    ) -> None:
        """
        Initialize PQC handshake.
        
        Args:
            remote: Remote node information
            dilithium_privkey: Local Dilithium private key
            remote_dilithium_pubkey: Remote node's Dilithium public key (if known)
        """
        if remote is None:
            raise ValidationError("Cannot create handshake with None remote")
        elif remote.address is None:
            raise ValidationError("Cannot create handshake with remote address=None")
        
        self.logger = get_logger("p2p.peer.PQCHandshake")
        self.remote = remote
        self.dilithium_privkey = dilithium_privkey
        self.dilithium_pubkey = dilithium_privkey.public_key()
        self.remote_dilithium_pubkey = remote_dilithium_pubkey
        
        # Generate ephemeral Kyber keypair for this session
        self.ephemeral_kyber_privkey, self.ephemeral_kyber_pubkey = generate_kyber_keypair()
    
    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to remote peer."""
        return await asyncio.wait_for(
            asyncio.open_connection(
                host=self.remote.address.ip,
                port=self.remote.address.tcp_port
            ),
            timeout=REPLY_TIMEOUT
        )
    
    def derive_secrets(
        self,
        initiator_nonce: bytes,
        responder_nonce: bytes,
        shared_secret: bytes,
        auth_init: bytes,
        auth_ack: bytes,
    ) -> Tuple[bytes, bytes, Blake3Hash, Blake3Hash]:
        """
        Derive encryption and MAC secrets from shared secret.
        Uses BLAKE3 instead of Keccak for quantum resistance.
        
        Args:
            initiator_nonce: Initiator's nonce
            responder_nonce: Responder's nonce
            shared_secret: Shared secret from Kyber KEM
            auth_init: Initial auth message
            auth_ack: Auth acknowledgment message
            
        Returns:
            Tuple of (aes_secret, mac_secret, egress_mac, ingress_mac)
        """
        # Combine nonces
        nonce_material = responder_nonce + initiator_nonce
        nonce_hash = blake3_256(nonce_material)
        
        # Derive session key material
        session_material = shared_secret + nonce_hash
        session_hash = blake3_512(session_material)
        
        # Split into AES and MAC secrets
        aes_secret = blake3_256(shared_secret + session_hash[:32])
        mac_secret = blake3_256(shared_secret + aes_secret)
        
        # Setup BLAKE3 instances for the MACs
        mac1_data = sxor(mac_secret, responder_nonce) + auth_init
        mac1 = Blake3Hash(output_length=32)
        mac1.update(mac1_data)
        
        mac2_data = sxor(mac_secret, initiator_nonce) + auth_ack
        mac2 = Blake3Hash(output_length=32)
        mac2.update(mac2_data)
        
        if self._is_initiator:
            egress_mac, ingress_mac = mac1, mac2
        else:
            egress_mac, ingress_mac = mac2, mac1
        
        return aes_secret, mac_secret, egress_mac, ingress_mac


class PQCHandshakeInitiator(PQCHandshakeBase):
    """
    PQC handshake initiator.
    Sends auth message with Dilithium signature and Kyber public key.
    """
    
    _is_initiator = True
    
    def create_auth_message(self, nonce: bytes) -> bytes:
        """
        Create PQC authentication message.
        
        Format:
        - version (1 byte): PROTOCOL_VERSION_PQC
        - dilithium_pubkey (1952 bytes): Initiator's Dilithium public key
        - kyber_pubkey (1184 bytes): Ephemeral Kyber public key
        - nonce (32 bytes): Random nonce
        - signature (3293 bytes): Dilithium signature over the above data
        
        Args:
            nonce: 32-byte random nonce
            
        Returns:
            Authentication message bytes
        """
        if len(nonce) != 32:
            raise ValidationError(f"Nonce must be 32 bytes, got {len(nonce)}")
        
        # Build message to sign
        msg_data = (
            bytes([PROTOCOL_VERSION_PQC]) +
            self.dilithium_pubkey.to_bytes() +
            self.ephemeral_kyber_pubkey.to_bytes() +
            nonce
        )
        
        # Hash and sign with Dilithium
        msg_hash = blake3_256(msg_data)
        signature = self.dilithium_privkey.sign(msg_hash)
        
        # Complete auth message
        auth_msg = msg_data + signature
        
        if len(auth_msg) != PQC_AUTH_MSG_SIZE:
            raise ValidationError(
                f"Auth message size mismatch. Expected {PQC_AUTH_MSG_SIZE}, "
                f"got {len(auth_msg)}"
            )
        
        return auth_msg
    
    def decode_ack_message(
        self,
        ack_msg: bytes
    ) -> Tuple[DilithiumPublicKey, bytes, bytes]:
        """
        Decode and verify PQC acknowledgment message.
        
        Args:
            ack_msg: Acknowledgment message from responder
            
        Returns:
            Tuple of (responder_pubkey, ciphertext, responder_nonce)
        """
        if len(ack_msg) != PQC_ACK_MSG_SIZE:
            raise BadAckMessage(
                f"Invalid ack message size. Expected {PQC_ACK_MSG_SIZE}, "
                f"got {len(ack_msg)}"
            )
        
        # Parse message
        offset = 0
        version = ack_msg[offset]
        offset += 1
        
        if version != PROTOCOL_VERSION_PQC:
            raise BadAckMessage(f"Invalid protocol version in ack: {version}")
        
        responder_pubkey_bytes = ack_msg[offset:offset + DILITHIUM_PUBLIC_KEY_SIZE]
        offset += DILITHIUM_PUBLIC_KEY_SIZE
        
        ciphertext = ack_msg[offset:offset + KYBER_CIPHERTEXT_SIZE]
        offset += KYBER_CIPHERTEXT_SIZE
        
        responder_nonce = ack_msg[offset:offset + 32]
        offset += 32
        
        signature = ack_msg[offset:offset + DILITHIUM_SIGNATURE_SIZE]
        
        # Reconstruct message for verification
        msg_data = ack_msg[:offset]
        msg_hash = blake3_256(msg_data)
        
        # Verify signature
        try:
            responder_pubkey = DilithiumPublicKey(responder_pubkey_bytes)
        except Exception as e:
            raise BadAckMessage(f"Invalid responder public key: {e}")
        
        if not responder_pubkey.verify(msg_hash, signature):
            raise BadAckMessage("Invalid Dilithium signature in ack message")
        
        return responder_pubkey, ciphertext, responder_nonce
    
    def derive_shared_secret(self, ciphertext: bytes) -> bytes:
        """
        Derive shared secret by decapsulating the ciphertext.
        
        Args:
            ciphertext: Kyber ciphertext from responder
            
        Returns:
            32-byte shared secret
        """
        try:
            shared_secret = self.ephemeral_kyber_privkey.decapsulate(ciphertext)
        except Exception as e:
            raise DecryptionError(f"Failed to decapsulate shared secret: {e}")
        
        if len(shared_secret) != KYBER_SHARED_SECRET_SIZE:
            raise DecryptionError(
                f"Invalid shared secret size. Expected {KYBER_SHARED_SECRET_SIZE}, "
                f"got {len(shared_secret)}"
            )
        
        return shared_secret


class PQCHandshakeResponder(PQCHandshakeBase):
    """
    PQC handshake responder.
    Receives auth message, verifies signature, and sends ack with encapsulated secret.
    """
    
    _is_initiator = False
    
    def decode_auth_message(
        self,
        auth_msg: bytes
    ) -> Tuple[DilithiumPublicKey, KyberPublicKey, bytes]:
        """
        Decode and verify PQC authentication message.
        
        Args:
            auth_msg: Authentication message from initiator
            
        Returns:
            Tuple of (initiator_pubkey, ephemeral_kyber_pubkey, initiator_nonce)
        """
        if len(auth_msg) != PQC_AUTH_MSG_SIZE:
            raise HandshakeFailure(
                f"Invalid auth message size. Expected {PQC_AUTH_MSG_SIZE}, "
                f"got {len(auth_msg)}"
            )
        
        # Parse message
        offset = 0
        version = auth_msg[offset]
        offset += 1
        
        if version != PROTOCOL_VERSION_PQC:
            raise HandshakeFailure(f"Invalid protocol version in auth: {version}")
        
        initiator_pubkey_bytes = auth_msg[offset:offset + DILITHIUM_PUBLIC_KEY_SIZE]
        offset += DILITHIUM_PUBLIC_KEY_SIZE
        
        kyber_pubkey_bytes = auth_msg[offset:offset + KYBER_PUBLIC_KEY_SIZE]
        offset += KYBER_PUBLIC_KEY_SIZE
        
        initiator_nonce = auth_msg[offset:offset + 32]
        offset += 32
        
        signature = auth_msg[offset:offset + DILITHIUM_SIGNATURE_SIZE]
        
        # Reconstruct message for verification
        msg_data = auth_msg[:offset]
        msg_hash = blake3_256(msg_data)
        
        # Verify signature
        try:
            initiator_pubkey = DilithiumPublicKey(initiator_pubkey_bytes)
        except Exception as e:
            raise HandshakeFailure(f"Invalid initiator public key: {e}")
        
        if not initiator_pubkey.verify(msg_hash, signature):
            raise HandshakeFailure("Invalid Dilithium signature in auth message")
        
        try:
            ephemeral_kyber_pubkey = KyberPublicKey(kyber_pubkey_bytes)
        except Exception as e:
            raise HandshakeFailure(f"Invalid Kyber public key: {e}")
        
        return initiator_pubkey, ephemeral_kyber_pubkey, initiator_nonce
    
    def create_ack_message(
        self,
        ephemeral_kyber_pubkey: KyberPublicKey,
        nonce: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Create PQC acknowledgment message with encapsulated shared secret.
        
        Format:
        - version (1 byte): PROTOCOL_VERSION_PQC
        - dilithium_pubkey (1952 bytes): Responder's Dilithium public key
        - ciphertext (1088 bytes): Kyber-encapsulated shared secret
        - nonce (32 bytes): Random nonce
        - signature (3293 bytes): Dilithium signature over the above data
        
        Args:
            ephemeral_kyber_pubkey: Initiator's ephemeral Kyber public key
            nonce: 32-byte random nonce
            
        Returns:
            Tuple of (ack_message, shared_secret)
        """
        if len(nonce) != 32:
            raise ValidationError(f"Nonce must be 32 bytes, got {len(nonce)}")
        
        # Encapsulate shared secret with initiator's Kyber public key
        ciphertext, shared_secret = ephemeral_kyber_pubkey.encapsulate()
        
        # Build message to sign
        msg_data = (
            bytes([PROTOCOL_VERSION_PQC]) +
            self.dilithium_pubkey.to_bytes() +
            ciphertext +
            nonce
        )
        
        # Hash and sign with Dilithium
        msg_hash = blake3_256(msg_data)
        signature = self.dilithium_privkey.sign(msg_hash)
        
        # Complete ack message
        ack_msg = msg_data + signature
        
        if len(ack_msg) != PQC_ACK_MSG_SIZE:
            raise ValidationError(
                f"Ack message size mismatch. Expected {PQC_ACK_MSG_SIZE}, "
                f"got {len(ack_msg)}"
            )
        
        return ack_msg, shared_secret


async def pqc_handshake(
    remote: NodeAPI,
    dilithium_privkey: DilithiumPrivateKey,
    remote_dilithium_pubkey: Optional[DilithiumPublicKey] = None,
) -> Tuple[bytes, bytes, Blake3Hash, Blake3Hash, asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Perform PQC handshake with remote peer.
    
    Args:
        remote: Remote node information
        dilithium_privkey: Local Dilithium private key
        remote_dilithium_pubkey: Remote node's Dilithium public key (optional)
        
    Returns:
        Tuple of (aes_secret, mac_secret, egress_mac, ingress_mac, reader, writer)
    """
    initiator = PQCHandshakeInitiator(remote, dilithium_privkey, remote_dilithium_pubkey)
    reader, writer = await initiator.connect()
    
    try:
        # Generate and send auth message
        initiator_nonce = os.urandom(32)
        auth_msg = initiator.create_auth_message(initiator_nonce)
        
        if writer.transport.is_closing():
            raise HandshakeFailure(f"Writer closed before sending auth to {remote!r}")
        
        writer.write(auth_msg)
        await writer.drain()
        
        # Receive and verify ack message
        ack_msg = await asyncio.wait_for(
            reader.read(PQC_ACK_MSG_SIZE),
            timeout=REPLY_TIMEOUT
        )
        
        if reader.at_eof():
            raise HandshakeFailure(f"{remote!r} disconnected before sending ack")
        
        responder_pubkey, ciphertext, responder_nonce = initiator.decode_ack_message(ack_msg)
        
        # Derive shared secret
        shared_secret = initiator.derive_shared_secret(ciphertext)
        
        # Derive session secrets
        aes_secret, mac_secret, egress_mac, ingress_mac = initiator.derive_secrets(
            initiator_nonce,
            responder_nonce,
            shared_secret,
            auth_msg,
            ack_msg,
        )
        
        return aes_secret, mac_secret, egress_mac, ingress_mac, reader, writer
        
    except BaseException:
        if not reader.at_eof():
            reader.feed_eof()
        writer.close()
        raise
