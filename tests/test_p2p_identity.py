"""
QRDX Stage 2 Tests — P2P Identity, Handshake, Node Model

Covers:
- Step 2.1: PQ Node Identity (Dilithium3/ML-DSA-65 + BLAKE3 + @-schema)
- Step 2.2: 4-step PQ Handshake (Dilithium + Kyber → AES-256-GCM)
- Step 2.3: P2P Node Model (Kademlia XOR distance, @-schema URIs)
- Step 2.4: Bootstrap @-schema parsing
"""

import os
import re
import pytest
import oqs
import blake3


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def sig_algorithm():
    """Resolved PQ signature algorithm name."""
    from qrdx.p2p.handshake import PQ_SIG_ALGORITHM
    return PQ_SIG_ALGORITHM


@pytest.fixture
def kem_algorithm():
    """Resolved PQ KEM algorithm name."""
    from qrdx.p2p.handshake import PQ_KEM_ALGORITHM
    return PQ_KEM_ALGORITHM


@pytest.fixture
def keypair_a(sig_algorithm):
    """Dilithium keypair for node A."""
    sig = oqs.Signature(sig_algorithm)
    pk = sig.generate_keypair()
    sk = sig.export_secret_key()
    return sk, pk


@pytest.fixture
def keypair_b(sig_algorithm):
    """Dilithium keypair for node B."""
    sig = oqs.Signature(sig_algorithm)
    pk = sig.generate_keypair()
    sk = sig.export_secret_key()
    return sk, pk


# ============================================================================
# 2.1 — PQ Node Identity
# ============================================================================

class TestNodeIdentity:
    """Tests for qrdx.node.identity module."""

    def test_initialize_identity(self, tmp_path, monkeypatch):
        """initialize_identity() creates or loads keys."""
        from qrdx.node import identity

        monkeypatch.setattr(identity, 'KEY_FILE_PATH', str(tmp_path / 'node.pq'))
        monkeypatch.setattr(identity, 'PUBKEY_FILE_PATH', str(tmp_path / 'node.pq.pub'))
        monkeypatch.setattr(identity, '_secret_key', None)
        monkeypatch.setattr(identity, '_public_key', None)
        monkeypatch.setattr(identity, '_node_id', None)

        identity.initialize_identity()

        assert identity._node_id is not None
        assert identity._node_id.startswith('qx')
        assert len(identity._node_id) == 42  # 'qx' + 40 hex chars
        assert identity._public_key is not None
        assert identity._secret_key is not None

    def test_identity_persistence(self, tmp_path, monkeypatch):
        """Keys persist to disk and reload correctly."""
        from qrdx.node import identity

        key_path = str(tmp_path / 'node.pq')
        pub_path = str(tmp_path / 'node.pq.pub')
        monkeypatch.setattr(identity, 'KEY_FILE_PATH', key_path)
        monkeypatch.setattr(identity, 'PUBKEY_FILE_PATH', pub_path)
        monkeypatch.setattr(identity, '_secret_key', None)
        monkeypatch.setattr(identity, '_public_key', None)
        monkeypatch.setattr(identity, '_node_id', None)

        identity.initialize_identity()
        first_id = identity._node_id
        first_pk = identity._public_key

        # Reset and reload
        monkeypatch.setattr(identity, '_secret_key', None)
        monkeypatch.setattr(identity, '_public_key', None)
        monkeypatch.setattr(identity, '_node_id', None)
        identity.initialize_identity()

        assert identity._node_id == first_id
        assert identity._public_key == first_pk

    def test_node_id_derivation(self, keypair_a):
        """Node ID = 'qx' + first 40 hex of BLAKE3(pubkey)."""
        from qrdx.node.identity import _derive_node_id

        sk, pk = keypair_a
        node_id = _derive_node_id(pk)
        expected = 'qx' + blake3.blake3(pk).hexdigest()[:40]
        assert node_id == expected

    def test_node_id_deterministic(self, keypair_a):
        """Same key always produces same node ID."""
        from qrdx.node.identity import _derive_node_id

        _, pk = keypair_a
        assert _derive_node_id(pk) == _derive_node_id(pk)

    def test_different_keys_different_ids(self, keypair_a, keypair_b):
        """Different keys produce different node IDs."""
        from qrdx.node.identity import _derive_node_id

        _, pk_a = keypair_a
        _, pk_b = keypair_b
        assert _derive_node_id(pk_a) != _derive_node_id(pk_b)

    def test_sign_verify_roundtrip(self, tmp_path, monkeypatch):
        """sign_message() + verify_signature() round-trip."""
        from qrdx.node import identity

        monkeypatch.setattr(identity, 'KEY_FILE_PATH', str(tmp_path / 'node.pq'))
        monkeypatch.setattr(identity, 'PUBKEY_FILE_PATH', str(tmp_path / 'node.pq.pub'))
        monkeypatch.setattr(identity, '_secret_key', None)
        monkeypatch.setattr(identity, '_public_key', None)
        monkeypatch.setattr(identity, '_node_id', None)
        identity.initialize_identity()

        msg = b'test message for signing'
        sig_hex = identity.sign_message(msg)
        pk_hex = identity.get_public_key_hex()

        assert identity.verify_signature(pk_hex, sig_hex, msg)

    def test_verify_wrong_message(self, tmp_path, monkeypatch):
        """verify_signature() fails on wrong message."""
        from qrdx.node import identity

        monkeypatch.setattr(identity, 'KEY_FILE_PATH', str(tmp_path / 'node.pq'))
        monkeypatch.setattr(identity, 'PUBKEY_FILE_PATH', str(tmp_path / 'node.pq.pub'))
        monkeypatch.setattr(identity, '_secret_key', None)
        monkeypatch.setattr(identity, '_public_key', None)
        monkeypatch.setattr(identity, '_node_id', None)
        identity.initialize_identity()

        sig_hex = identity.sign_message(b'correct')
        pk_hex = identity.get_public_key_hex()

        assert not identity.verify_signature(pk_hex, sig_hex, b'wrong')

    def test_canonical_json(self):
        """get_canonical_json_bytes() is deterministic and sorted."""
        from qrdx.node.identity import get_canonical_json_bytes

        data = {'z': 1, 'a': 2, 'm': 3}
        result = get_canonical_json_bytes(data)
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_canonical_json_deterministic(self):
        """Same input always produces same bytes."""
        from qrdx.node.identity import get_canonical_json_bytes

        data = {'hello': 'world', 'num': 42}
        assert get_canonical_json_bytes(data) == get_canonical_json_bytes(data)


# ============================================================================
# 2.1 — @-Schema Addressing
# ============================================================================

class TestAtSchema:
    """Tests for @-schema address format."""

    def test_at_schema_format(self, tmp_path, monkeypatch):
        """@-schema has correct format: algo@qxID@host:port."""
        from qrdx.node import identity

        monkeypatch.setattr(identity, 'KEY_FILE_PATH', str(tmp_path / 'node.pq'))
        monkeypatch.setattr(identity, 'PUBKEY_FILE_PATH', str(tmp_path / 'node.pq.pub'))
        monkeypatch.setattr(identity, '_secret_key', None)
        monkeypatch.setattr(identity, '_public_key', None)
        monkeypatch.setattr(identity, '_node_id', None)
        identity.initialize_identity()

        addr = identity.get_at_schema_address('node.example.com', 30303)
        # Format: <algo>@qx<hex40>@host:port
        parts = addr.split('@')
        assert len(parts) == 3
        assert parts[1].startswith('qx')
        assert ':' in parts[2]

    def test_parse_at_schema(self):
        """parse_at_schema() extracts fields correctly."""
        from qrdx.node.identity import parse_at_schema

        addr = 'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node.qrdx.org:30303'
        parsed = parse_at_schema(addr)
        assert parsed['algo'] == 'dilithium3'
        assert parsed['node_id'] == 'qx1a2b3c4d5e6f7890abcdef1234567890abcdef12'
        assert parsed['host'] == 'node.qrdx.org'
        assert parsed['port'] == 30303

    def test_parse_ml_dsa_65_schema(self):
        """parse_at_schema() handles ML-DSA-65 algorithm name."""
        from qrdx.node.identity import parse_at_schema

        addr = 'ML-DSA-65@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node.qrdx.org:30303'
        parsed = parse_at_schema(addr)
        assert parsed['algo'] == 'ML-DSA-65'

    def test_validate_at_schema_valid(self):
        """validate_at_schema() accepts valid addresses."""
        from qrdx.node.identity import validate_at_schema

        assert validate_at_schema('dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@host:30303')
        assert validate_at_schema('ml-dsa-65@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@host:30303')

    def test_validate_at_schema_invalid(self):
        """validate_at_schema() rejects invalid addresses."""
        from qrdx.node.identity import validate_at_schema

        assert not validate_at_schema('')
        assert not validate_at_schema('not-an-address')
        assert not validate_at_schema('algo@missing_qx_prefix@host:30303')
        assert not validate_at_schema('algo@qx1234@host:port_not_number')

    def test_parse_at_schema_invalid_raises(self):
        """parse_at_schema() raises ValueError on invalid input."""
        from qrdx.node.identity import parse_at_schema

        with pytest.raises(ValueError):
            parse_at_schema('garbage')


# ============================================================================
# 2.2 — PQ Handshake Protocol
# ============================================================================

class TestHandshake:
    """Tests for the 4-step PQ handshake."""

    def test_full_handshake(self, keypair_a, keypair_b):
        """Complete 4-step handshake succeeds and produces matching secrets."""
        from qrdx.p2p.handshake import HandshakeInitiator, HandshakeResponder

        sk_a, pk_a = keypair_a
        sk_b, pk_b = keypair_b

        init = HandshakeInitiator(sk_a, pk_a)
        resp = HandshakeResponder(sk_b, pk_b)

        # Step 1: HELLO
        hello = init.create_hello()
        assert len(hello.nonce) == 32
        assert len(hello.pubkey) > 0

        # Step 2: HELLO_ACK
        hello_ack = resp.process_hello(hello)
        assert len(hello_ack.nonce) == 32
        assert len(hello_ack.signature) > 0
        assert len(hello_ack.kem_pubkey) > 0

        # Step 3: AUTH
        auth = init.process_hello_ack(hello_ack)
        assert len(auth.signature) > 0
        assert len(auth.ciphertext) > 0

        # Step 4: AUTH_ACK
        auth_ack, resp_result = resp.process_auth(auth)
        assert auth_ack.success is True
        assert len(auth_ack.session_id) > 0

        # Initiator finishes
        init_result = init.process_auth_ack(auth_ack)
        assert init_result.success is True
        assert init_result.shared_secret == resp_result.shared_secret
        assert init_result.session_id == resp_result.session_id
        assert len(init_result.shared_secret) == 32

    def test_handshake_peer_node_ids(self, keypair_a, keypair_b):
        """Both sides derive the correct peer node IDs."""
        from qrdx.p2p.handshake import HandshakeInitiator, HandshakeResponder, _derive_node_id

        sk_a, pk_a = keypair_a
        sk_b, pk_b = keypair_b

        init = HandshakeInitiator(sk_a, pk_a)
        resp = HandshakeResponder(sk_b, pk_b)

        hello = init.create_hello()
        hello_ack = resp.process_hello(hello)
        auth = init.process_hello_ack(hello_ack)
        auth_ack, resp_result = resp.process_auth(auth)
        init_result = init.process_auth_ack(auth_ack)

        assert init_result.peer_node_id == _derive_node_id(pk_b)
        assert resp_result.peer_node_id == _derive_node_id(pk_a)

    def test_handshake_wrong_signature_rejected(self, keypair_a, keypair_b, sig_algorithm):
        """Handshake fails when responder's signature is forged."""
        from qrdx.p2p.handshake import (
            HandshakeInitiator, HandshakeResponder, HelloAckMessage,
        )

        sk_a, pk_a = keypair_a
        sk_b, pk_b = keypair_b

        init = HandshakeInitiator(sk_a, pk_a)
        resp = HandshakeResponder(sk_b, pk_b)

        hello = init.create_hello()
        hello_ack = resp.process_hello(hello)

        # Forge the signature
        forged_ack = HelloAckMessage(
            pubkey=hello_ack.pubkey,
            nonce=hello_ack.nonce,
            signature=b'\x00' * len(hello_ack.signature),  # Bad sig
            kem_pubkey=hello_ack.kem_pubkey,
        )

        with pytest.raises(ValueError, match="signature verification failed"):
            init.process_hello_ack(forged_ack)

    def test_handshake_wrong_auth_rejected(self, keypair_a, keypair_b, sig_algorithm):
        """Handshake fails when initiator's AUTH signature is forged."""
        from qrdx.p2p.handshake import (
            HandshakeInitiator, HandshakeResponder, AuthMessage,
        )

        sk_a, pk_a = keypair_a
        sk_b, pk_b = keypair_b

        init = HandshakeInitiator(sk_a, pk_a)
        resp = HandshakeResponder(sk_b, pk_b)

        hello = init.create_hello()
        hello_ack = resp.process_hello(hello)
        auth = init.process_hello_ack(hello_ack)

        forged_auth = AuthMessage(
            signature=b'\x00' * len(auth.signature),
            ciphertext=auth.ciphertext,
        )

        auth_ack, result = resp.process_auth(forged_auth)
        assert auth_ack.success is False
        assert result.success is False

    def test_hello_message_serialization(self, keypair_a):
        """HelloMessage round-trips through dict."""
        from qrdx.p2p.handshake import HandshakeInitiator, HelloMessage

        sk, pk = keypair_a
        init = HandshakeInitiator(sk, pk)
        hello = init.create_hello()

        d = hello.to_dict()
        restored = HelloMessage.from_dict(d)
        assert restored.algorithm == hello.algorithm
        assert restored.pubkey == hello.pubkey
        assert restored.nonce == hello.nonce

    def test_auth_ack_serialization(self):
        """AuthAckMessage round-trips through dict."""
        from qrdx.p2p.handshake import AuthAckMessage

        ack = AuthAckMessage(success=True, session_id='abc123')
        d = ack.to_dict()
        restored = AuthAckMessage.from_dict(d)
        assert restored.success is True
        assert restored.session_id == 'abc123'

    def test_unsupported_algorithm_rejected(self, keypair_b):
        """Responder rejects HELLO with unknown algorithm."""
        from qrdx.p2p.handshake import HandshakeResponder, HelloMessage

        sk_b, pk_b = keypair_b
        resp = HandshakeResponder(sk_b, pk_b)

        hello = HelloMessage(
            algorithm='Unknown-Algo',
            pubkey=pk_b,
            nonce=os.urandom(32),
        )

        with pytest.raises(ValueError, match="Unsupported algorithm"):
            resp.process_hello(hello)


# ============================================================================
# 2.2 — AES-256-GCM Channel Encryption
# ============================================================================

class TestChannelEncryption:
    """Tests for post-handshake AES-256-GCM encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """encrypt_message() + decrypt_message() round-trip."""
        from qrdx.p2p.handshake import encrypt_message, decrypt_message

        key = os.urandom(32)
        msg = b'Hello, quantum-resistant world!'
        ct = encrypt_message(key, msg)
        pt = decrypt_message(key, ct)
        assert pt == msg

    def test_different_keys_fail(self):
        """Decryption with wrong key fails."""
        from qrdx.p2p.handshake import encrypt_message, decrypt_message
        from cryptography.exceptions import InvalidTag

        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = encrypt_message(key1, b'secret')

        with pytest.raises(InvalidTag):
            decrypt_message(key2, ct)

    def test_tampered_ciphertext_fails(self):
        """Decryption of tampered data fails."""
        from qrdx.p2p.handshake import encrypt_message, decrypt_message
        from cryptography.exceptions import InvalidTag

        key = os.urandom(32)
        ct = encrypt_message(key, b'secret')
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF  # Flip last byte
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            decrypt_message(key, tampered)

    def test_empty_message(self):
        """Empty plaintext encrypts and decrypts correctly."""
        from qrdx.p2p.handshake import encrypt_message, decrypt_message

        key = os.urandom(32)
        ct = encrypt_message(key, b'')
        pt = decrypt_message(key, ct)
        assert pt == b''

    def test_large_message(self):
        """Large message (1 MB) encrypts/decrypts correctly."""
        from qrdx.p2p.handshake import encrypt_message, decrypt_message

        key = os.urandom(32)
        msg = os.urandom(1024 * 1024)  # 1 MB
        ct = encrypt_message(key, msg)
        pt = decrypt_message(key, ct)
        assert pt == msg

    def test_derive_channel_keys(self):
        """derive_channel_keys() produces two distinct 32-byte keys."""
        from qrdx.p2p.handshake import derive_channel_keys

        shared = os.urandom(32)
        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)

        send_key, recv_key = derive_channel_keys(shared, nonce_a, nonce_b)
        assert len(send_key) == 32
        assert len(recv_key) == 32
        assert send_key != recv_key

    def test_ciphertext_too_short(self):
        """decrypt_message() rejects ciphertext shorter than minimum."""
        from qrdx.p2p.handshake import decrypt_message

        key = os.urandom(32)
        with pytest.raises(ValueError, match="too short"):
            decrypt_message(key, b'\x00' * 10)


# ============================================================================
# 2.3 — P2P Node Model
# ============================================================================

class TestP2PNode:
    """Tests for qrdx.p2p.node.Node class."""

    def test_node_creation(self, keypair_a):
        """Node creates with correct properties."""
        from qrdx.p2p.node import Node, Address

        sk, pk = keypair_a
        addr = Address(ip='10.0.0.1', tcp_port=30303)
        node = Node(public_key=pk, address=addr, secret_key=sk)

        assert node.public_key == pk
        assert node.secret_key == sk
        assert node.has_secret_key is True
        assert node.is_resolved is True
        assert node.node_id_hex.startswith('qx')
        assert len(node.node_id) == 20
        assert len(node.node_id_hex) == 42

    def test_node_id_matches_blake3(self, keypair_a):
        """Node ID equals BLAKE3(pubkey)[:20]."""
        from qrdx.p2p.node import Node

        _, pk = keypair_a
        node = Node(public_key=pk)
        expected = blake3.blake3(pk).digest()[:20]
        assert node.node_id == expected

    def test_node_generate(self):
        """Node.generate() creates valid keypair."""
        from qrdx.p2p.node import Node

        node = Node.generate()
        assert node.public_key is not None
        assert node.secret_key is not None
        assert node.has_secret_key is True
        assert node.is_resolved is True

    def test_node_sign_verify(self, keypair_a):
        """Node.sign() + Node.verify() round-trip."""
        from qrdx.p2p.node import Node

        sk, pk = keypair_a
        node = Node(public_key=pk, secret_key=sk)
        msg = b'test message'
        sig = node.sign(msg)
        assert node.verify(msg, sig) is True
        assert node.verify(b'wrong', sig) is False

    def test_remote_node_cannot_sign(self, keypair_a):
        """Remote node (no secret key) raises on sign."""
        from qrdx.p2p.node import Node

        _, pk = keypair_a
        node = Node(public_key=pk)  # No secret key
        assert node.has_secret_key is False

        with pytest.raises(RuntimeError, match="no secret key"):
            node.sign(b'test')

    def test_xor_distance(self, keypair_a, keypair_b):
        """XOR distance is symmetric and non-negative."""
        from qrdx.p2p.node import Node

        _, pk_a = keypair_a
        _, pk_b = keypair_b
        a = Node(public_key=pk_a)
        b = Node(public_key=pk_b)

        assert a.distance(b) == b.distance(a)
        assert a.distance(b) > 0
        assert a.distance(a) == 0

    def test_log_distance(self, keypair_a, keypair_b):
        """Log distance in valid range for 160-bit IDs."""
        from qrdx.p2p.node import Node

        _, pk_a = keypair_a
        _, pk_b = keypair_b
        a = Node(public_key=pk_a)
        b = Node(public_key=pk_b)

        log_d = a.log_distance(b)
        assert 0 <= log_d <= 159
        assert a.log_distance(a) == 0

    def test_at_schema_roundtrip(self, keypair_a):
        """to_at_schema() → from_at_schema() preserves identity."""
        from qrdx.p2p.node import Node, Address

        _, pk = keypair_a
        node = Node(public_key=pk, address=Address('10.0.0.1', 30303))
        at_str = node.to_at_schema()

        parsed = Node.from_at_schema(at_str)
        assert parsed.node_id == node.node_id
        assert parsed.node_id_hex == node.node_id_hex
        assert parsed.address.ip == '10.0.0.1'
        assert parsed.address.tcp_port == 30303
        assert parsed.is_resolved is False  # No pubkey from @-schema alone

    def test_from_at_schema_legacy_dilithium3(self, keypair_a):
        """from_at_schema() accepts 'dilithium3' prefix."""
        from qrdx.p2p.node import Node, Address

        _, pk = keypair_a
        node = Node(public_key=pk, address=Address('10.0.0.1', 30303))
        legacy_addr = f'dilithium3@{node.node_id_hex}@10.0.0.1:30303'

        parsed = Node.from_at_schema(legacy_addr)
        assert parsed.node_id == node.node_id

    def test_from_at_schema_invalid(self):
        """from_at_schema() rejects garbage."""
        from qrdx.p2p.node import Node

        with pytest.raises(ValueError, match="Invalid @-schema"):
            Node.from_at_schema('not-valid')

    def test_from_at_schema_bad_algo(self):
        """from_at_schema() rejects unsupported algorithms."""
        from qrdx.p2p.node import Node

        with pytest.raises(ValueError, match="Unsupported algorithm"):
            Node.from_at_schema('rsa4096@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@host:30303')

    def test_from_http_url(self):
        """from_http_url() creates placeholder node."""
        from qrdx.p2p.node import Node

        node = Node.from_http_url('http://10.0.0.1:3007')
        assert node.address.ip == '10.0.0.1'
        assert node.address.tcp_port == 3007
        assert node.is_resolved is False

    def test_to_http_url(self, keypair_a):
        """to_http_url() generates correct URL."""
        from qrdx.p2p.node import Node, Address

        _, pk = keypair_a
        node = Node(public_key=pk, address=Address('192.168.1.1', 8080))
        assert node.to_http_url() == 'http://192.168.1.1:8080'

    def test_node_resolve(self, keypair_a, keypair_b):
        """resolve() updates public key and node ID."""
        from qrdx.p2p.node import Node, Address, derive_node_id

        _, pk_a = keypair_a
        _, pk_b = keypair_b

        # Create unresolved node from @-schema of A
        node = Node(public_key=pk_a, address=Address('10.0.0.1', 30303))
        original_id = node.node_id

        # Resolve with different key
        node.resolve(pk_b)
        assert node.node_id != original_id
        assert node.node_id == derive_node_id(pk_b)
        assert node.is_resolved is True

    def test_node_equality(self, keypair_a):
        """Nodes with same pubkey are equal."""
        from qrdx.p2p.node import Node

        _, pk = keypair_a
        a = Node(public_key=pk)
        b = Node(public_key=pk)
        assert a == b
        assert hash(a) == hash(b)

    def test_node_inequality(self, keypair_a, keypair_b):
        """Nodes with different pubkeys are not equal."""
        from qrdx.p2p.node import Node

        _, pk_a = keypair_a
        _, pk_b = keypair_b
        a = Node(public_key=pk_a)
        b = Node(public_key=pk_b)
        assert a != b

    def test_node_load_or_generate(self, tmp_path):
        """load_or_generate() creates and reloads."""
        from qrdx.p2p.node import Node

        key_path = str(tmp_path / 'test_node.pq')
        node1 = Node.load_or_generate(key_path)
        assert os.path.exists(key_path)
        assert os.path.exists(key_path + '.pub')

        node2 = Node.load_or_generate(key_path)
        assert node1.node_id == node2.node_id
        assert node1.public_key == node2.public_key


# ============================================================================
# 2.3 — Node ID Helpers
# ============================================================================

class TestNodeIDHelpers:
    """Tests for node ID conversion helpers."""

    def test_node_id_to_hex(self, keypair_a):
        """node_id_to_hex() adds 'qx' prefix."""
        from qrdx.p2p.node import derive_node_id, node_id_to_hex

        _, pk = keypair_a
        nid = derive_node_id(pk)
        hex_str = node_id_to_hex(nid)
        assert hex_str.startswith('qx')
        assert len(hex_str) == 42

    def test_hex_to_node_id_with_prefix(self):
        """hex_to_node_id() strips 'qx' prefix."""
        from qrdx.p2p.node import hex_to_node_id

        nid = hex_to_node_id('qx' + 'ab' * 20)
        assert len(nid) == 20
        assert nid == bytes.fromhex('ab' * 20)

    def test_hex_to_node_id_without_prefix(self):
        """hex_to_node_id() works without prefix."""
        from qrdx.p2p.node import hex_to_node_id

        nid = hex_to_node_id('cd' * 20)
        assert nid == bytes.fromhex('cd' * 20)

    def test_roundtrip(self, keypair_a):
        """node_id_to_hex → hex_to_node_id round-trip."""
        from qrdx.p2p.node import derive_node_id, node_id_to_hex, hex_to_node_id

        _, pk = keypair_a
        nid = derive_node_id(pk)
        assert hex_to_node_id(node_id_to_hex(nid)) == nid


# ============================================================================
# 2.4 — Bootstrap @-Schema Parsing
# ============================================================================

class TestBootstrapParsing:
    """Tests for constants.parse_bootstrap_node with @-schema."""

    def test_parse_at_schema_bootstrap(self):
        """parse_bootstrap_node handles @-schema addresses."""
        from qrdx.constants import parse_bootstrap_node

        uri = 'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@boot1.qrdx.org:30303'
        p = parse_bootstrap_node(uri)
        assert p.node_id == 'qx1a2b3c4d5e6f7890abcdef1234567890abcdef12'
        assert p.algo == 'dilithium3'
        assert p.host == 'boot1.qrdx.org'
        assert p.port == 30303
        assert p.url == 'http://boot1.qrdx.org:30303'
        assert p.is_qnode is True

    def test_parse_ml_dsa_65_bootstrap(self):
        """parse_bootstrap_node handles ML-DSA-65 @-schema."""
        from qrdx.constants import parse_bootstrap_node

        uri = 'ML-DSA-65@qxdeadbeef00112233445566778899aabbccddeeff@192.168.1.100:30303'
        p = parse_bootstrap_node(uri)
        assert p.algo == 'ML-DSA-65'
        assert p.node_id == 'qxdeadbeef00112233445566778899aabbccddeeff'

    def test_parse_http_url_bootstrap(self):
        """parse_bootstrap_node still handles plain HTTP URLs."""
        from qrdx.constants import parse_bootstrap_node

        p = parse_bootstrap_node('http://node.example.com:3007')
        assert p.url == 'http://node.example.com:3007'
        assert p.host == 'node.example.com'
        assert p.port == 3007
        assert p.is_qnode is False
        assert p.node_id == ''

    def test_parse_qnode_uri_bootstrap(self):
        """parse_bootstrap_node still handles legacy qnode:// URIs."""
        from qrdx.constants import parse_bootstrap_node

        p = parse_bootstrap_node('qnode://abcdef1234@host.example.com:30303')
        assert p.is_qnode is True
        assert p.public_key == 'abcdef1234'

    def test_bootstrap_node_is_pq(self):
        """BootstrapNode.is_pq property works."""
        from qrdx.node.bootstrap import BootstrapNode

        node = BootstrapNode.from_uri(
            'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@host:30303'
        )
        assert node.is_pq is True
        assert node.node_id == 'qx1a2b3c4d5e6f7890abcdef1234567890abcdef12'

        http_node = BootstrapNode.from_uri('http://host:3007')
        assert http_node.is_pq is False


# ============================================================================
# 2.5 — Integration: Handshake + Node Model
# ============================================================================

class TestIntegration:
    """Integration tests combining handshake and node model."""

    def test_handshake_with_node_objects(self):
        """Full handshake using Node objects for key management."""
        from qrdx.p2p.node import Node, Address
        from qrdx.p2p.handshake import (
            HandshakeInitiator, HandshakeResponder,
            encrypt_message, decrypt_message, derive_channel_keys,
        )

        node_a = Node.generate(Address('10.0.0.1', 30303))
        node_b = Node.generate(Address('10.0.0.2', 30303))

        init = HandshakeInitiator(node_a.secret_key, node_a.public_key)
        resp = HandshakeResponder(node_b.secret_key, node_b.public_key)

        hello = init.create_hello()
        hello_ack = resp.process_hello(hello)
        auth = init.process_hello_ack(hello_ack)
        auth_ack, resp_result = resp.process_auth(auth)
        init_result = init.process_auth_ack(auth_ack)

        assert init_result.success
        assert init_result.shared_secret == resp_result.shared_secret

        # Encrypted communication
        send_key, recv_key = derive_channel_keys(
            init_result.shared_secret, init._nonce_a, resp._nonce_b
        )
        ct = encrypt_message(send_key, b'block proposal data')
        pt = decrypt_message(send_key, ct)
        assert pt == b'block proposal data'

    def test_node_resolve_after_handshake(self):
        """After handshake, unresolved peer node gets resolved."""
        from qrdx.p2p.node import Node, Address
        from qrdx.p2p.handshake import HandshakeInitiator, HandshakeResponder

        node_a = Node.generate(Address('10.0.0.1', 30303))
        node_b = Node.generate(Address('10.0.0.2', 30303))

        # Create unresolved peer reference from @-schema
        peer_ref = Node.from_at_schema(node_b.to_at_schema())
        assert peer_ref.is_resolved is False

        # Perform handshake
        init = HandshakeInitiator(node_a.secret_key, node_a.public_key)
        resp = HandshakeResponder(node_b.secret_key, node_b.public_key)

        hello = init.create_hello()
        hello_ack = resp.process_hello(hello)
        auth = init.process_hello_ack(hello_ack)
        auth_ack, resp_result = resp.process_auth(auth)
        init_result = init.process_auth_ack(auth_ack)

        # Resolve peer with pubkey from handshake
        peer_ref.resolve(init_result.peer_pubkey)
        assert peer_ref.is_resolved is True
        assert peer_ref.node_id == node_b.node_id

    def test_multiple_handshakes_unique_sessions(self):
        """Each handshake produces unique session IDs and shared secrets."""
        from qrdx.p2p.node import Node
        from qrdx.p2p.handshake import HandshakeInitiator, HandshakeResponder

        node_a = Node.generate()
        node_b = Node.generate()

        sessions = set()
        secrets = set()

        for _ in range(5):
            init = HandshakeInitiator(node_a.secret_key, node_a.public_key)
            resp = HandshakeResponder(node_b.secret_key, node_b.public_key)

            hello = init.create_hello()
            hello_ack = resp.process_hello(hello)
            auth = init.process_hello_ack(hello_ack)
            auth_ack, _ = resp.process_auth(auth)
            result = init.process_auth_ack(auth_ack)

            assert result.success
            sessions.add(result.session_id)
            secrets.add(result.shared_secret)

        # All 5 handshakes should produce unique sessions
        assert len(sessions) == 5
        assert len(secrets) == 5
