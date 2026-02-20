"""
Comprehensive tests for Step 6: PQ Multisignatures & Wallet Architecture.

Covers:
  - ThresholdConfig validation
  - MultisigKeySet creation, sorting, address derivation
  - Partial signature creation
  - Aggregation at various thresholds (2-of-3, 3-of-5, 5-of-7)
  - MultisigSignature verification
  - Serialization round-trips (to_dict / from_dict)
  - Domain separation (cross-wallet replay protection)
  - System wallet multisig migration
  - Prefunded wallet architecture (SpendingPolicy, SubWallet, PrefundedWalletManager)
  - Auto-refill rules
"""

import time
import pytest
from decimal import Decimal
from unittest.mock import patch

# ── Threshold Dilithium ────────────────────────────────────────────────
from qrdx.crypto.threshold_dilithium import (
    ThresholdConfig,
    MultisigKeySet,
    PartialSignature,
    MultisigSignature,
    derive_multisig_address,
    create_multisig_keyset,
    generate_multisig_keyset,
    create_partial_signature,
    aggregate_partial_signatures,
    verify_multisig,
    is_multisig_address,
    _domain_tag_message,
    MULTISIG_ADDRESS_PREFIX,
    MAX_SIGNERS,
    MAX_THRESHOLD,
    MIN_THRESHOLD,
)
from qrdx.crypto.pq.dilithium import (
    PQPrivateKey,
    PQPublicKey,
    PQSignature,
    PQCryptoError,
    PQSignatureError,
    generate_keypair as dilithium_generate_keypair,
)

# ── Wallet Architecture ───────────────────────────────────────────────
from qrdx.wallet.multisig import (
    SpendingScope,
    SpendingPolicy,
    AutoRefillRule,
    SubWallet,
    PrefundedWalletManager,
)

# ── System Wallets ────────────────────────────────────────────────────
from qrdx.crypto.system_wallets import (
    SystemWalletType,
    SystemWallet,
    SystemWalletManager,
    is_system_wallet_address,
    create_default_system_wallets,
    initialize_system_wallets,
)


# ══════════════════════════════════════════════════════════════════════
#  FIXTURES
# ══════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def keyset_2of3():
    """Generate a 2-of-3 multisig keyset with private keys."""
    config = ThresholdConfig(m=2, n=3)
    keyset, privkeys = generate_multisig_keyset(config)
    return keyset, privkeys


@pytest.fixture(scope="module")
def keyset_3of5():
    """Generate a 3-of-5 multisig keyset with private keys."""
    config = ThresholdConfig(m=3, n=5)
    keyset, privkeys = generate_multisig_keyset(config)
    return keyset, privkeys


@pytest.fixture(scope="module")
def keyset_5of7():
    """Generate a 5-of-7 multisig keyset with private keys."""
    config = ThresholdConfig(m=5, n=7)
    keyset, privkeys = generate_multisig_keyset(config)
    return keyset, privkeys


@pytest.fixture(scope="module")
def keyset_1of1():
    """Generate a 1-of-1 keyset (degenerate multisig)."""
    config = ThresholdConfig(m=1, n=1)
    keyset, privkeys = generate_multisig_keyset(config)
    return keyset, privkeys


@pytest.fixture
def sample_message():
    """A sample transaction message."""
    return b"QRDX transfer 100 tokens from treasury"


@pytest.fixture
def pq_controller_address():
    """Generate a PQ controller address for system wallet tests."""
    _, pub = dilithium_generate_keypair()
    return pub.to_address()


# ══════════════════════════════════════════════════════════════════════
#  1. THRESHOLD CONFIG VALIDATION
# ══════════════════════════════════════════════════════════════════════

class TestThresholdConfig:
    """Tests for ThresholdConfig creation and validation."""

    def test_valid_2of3(self):
        cfg = ThresholdConfig(m=2, n=3)
        assert cfg.m == 2
        assert cfg.n == 3

    def test_valid_1of1(self):
        cfg = ThresholdConfig(m=1, n=1)
        assert cfg.m == 1

    def test_valid_max_threshold(self):
        cfg = ThresholdConfig(m=MAX_THRESHOLD, n=MAX_SIGNERS)
        assert cfg.m == MAX_THRESHOLD
        assert cfg.n == MAX_SIGNERS

    def test_m_equals_n(self):
        cfg = ThresholdConfig(m=5, n=5)
        assert cfg.m == cfg.n

    def test_reject_m_greater_than_n(self):
        with pytest.raises(ValueError, match="cannot exceed"):
            ThresholdConfig(m=4, n=3)

    def test_reject_m_zero(self):
        with pytest.raises(ValueError, match="must be >="):
            ThresholdConfig(m=0, n=3)

    def test_reject_n_zero(self):
        with pytest.raises(ValueError):
            ThresholdConfig(m=0, n=0)

    def test_reject_n_exceeds_max(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            ThresholdConfig(m=1, n=MAX_SIGNERS + 1)

    def test_reject_m_exceeds_max(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            ThresholdConfig(m=MAX_THRESHOLD + 1, n=MAX_SIGNERS)

    def test_reject_non_integer_m(self):
        with pytest.raises(TypeError):
            ThresholdConfig(m=2.5, n=3)

    def test_reject_non_integer_n(self):
        with pytest.raises(TypeError):
            ThresholdConfig(m=2, n="3")

    def test_repr(self):
        cfg = ThresholdConfig(m=3, n=5)
        assert "3-of-5" in repr(cfg)

    def test_frozen(self):
        cfg = ThresholdConfig(m=2, n=3)
        with pytest.raises(AttributeError):
            cfg.m = 5

    def test_equality(self):
        a = ThresholdConfig(m=2, n=3)
        b = ThresholdConfig(m=2, n=3)
        assert a == b

    def test_inequality(self):
        a = ThresholdConfig(m=2, n=3)
        b = ThresholdConfig(m=3, n=5)
        assert a != b


# ══════════════════════════════════════════════════════════════════════
#  2. MULTISIG KEYSET
# ══════════════════════════════════════════════════════════════════════

class TestMultisigKeySet:
    """Tests for keyset creation, sorting, and address derivation."""

    def test_keyset_creation(self, keyset_2of3):
        keyset, _ = keyset_2of3
        assert keyset.config == ThresholdConfig(m=2, n=3)
        assert len(keyset.public_keys) == 3
        assert keyset.address.startswith(MULTISIG_ADDRESS_PREFIX)

    def test_keys_are_sorted(self, keyset_2of3):
        keyset, _ = keyset_2of3
        key_bytes = [pk.to_bytes() for pk in keyset.public_keys]
        assert key_bytes == sorted(key_bytes)

    def test_deterministic_address(self):
        """Same keys + config always produce the same address."""
        config = ThresholdConfig(m=2, n=3)
        keyset1, _ = generate_multisig_keyset(config)
        # Re-create from same keys in different order
        shuffled = list(reversed(keyset1.public_keys))
        keyset2 = create_multisig_keyset(config, shuffled)
        assert keyset1.address == keyset2.address

    def test_different_config_different_address(self):
        """Different m with same keys must produce different address."""
        priv1, pub1 = dilithium_generate_keypair()
        priv2, pub2 = dilithium_generate_keypair()
        priv3, pub3 = dilithium_generate_keypair()
        pubs = [pub1, pub2, pub3]

        ks_2of3 = create_multisig_keyset(ThresholdConfig(m=2, n=3), pubs)
        ks_3of3 = create_multisig_keyset(ThresholdConfig(m=3, n=3), pubs)
        assert ks_2of3.address != ks_3of3.address

    def test_contains_key(self, keyset_2of3):
        keyset, privkeys = keyset_2of3
        for pk in keyset.public_keys:
            assert keyset.contains_key(pk)

        # Non-member key
        _, non_member = dilithium_generate_keypair()
        assert not keyset.contains_key(non_member)

    def test_key_index(self, keyset_2of3):
        keyset, _ = keyset_2of3
        for i, pk in enumerate(keyset.public_keys):
            assert keyset.key_index(pk) == i

    def test_key_index_non_member(self, keyset_2of3):
        keyset, _ = keyset_2of3
        _, non_member = dilithium_generate_keypair()
        with pytest.raises(ValueError, match="not a member"):
            keyset.key_index(non_member)

    def test_reject_duplicate_keys(self):
        """Duplicate public keys must be rejected."""
        _, pub = dilithium_generate_keypair()
        config = ThresholdConfig(m=1, n=2)
        with pytest.raises(ValueError, match="Duplicate"):
            create_multisig_keyset(config, [pub, pub])

    def test_reject_wrong_key_count(self):
        config = ThresholdConfig(m=2, n=3)
        _, pub1 = dilithium_generate_keypair()
        _, pub2 = dilithium_generate_keypair()
        with pytest.raises(ValueError, match="Expected 3"):
            create_multisig_keyset(config, [pub1, pub2])

    def test_address_prefix(self, keyset_2of3):
        keyset, _ = keyset_2of3
        assert keyset.address.startswith("0xPQMS")
        # 6 char prefix + 38 hex chars = 44
        assert len(keyset.address) == 44

    def test_serialization_roundtrip(self, keyset_2of3):
        keyset, _ = keyset_2of3
        d = keyset.to_dict()
        restored = MultisigKeySet.from_dict(d)
        assert restored.address == keyset.address
        assert restored.config == keyset.config
        assert len(restored.public_keys) == len(keyset.public_keys)
        for a, b in zip(restored.public_keys, keyset.public_keys):
            assert a.to_bytes() == b.to_bytes()


# ══════════════════════════════════════════════════════════════════════
#  3. PARTIAL SIGNATURES
# ══════════════════════════════════════════════════════════════════════

class TestPartialSignature:
    """Tests for individual signer contributions."""

    def test_create_partial(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        partial = create_partial_signature(privkeys[0], keyset, sample_message)
        assert partial.signer_index == 0
        assert partial.public_key == keyset.public_keys[0]
        assert isinstance(partial.signature, PQSignature)

    def test_partial_from_each_signer(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        for i, priv in enumerate(privkeys):
            p = create_partial_signature(priv, keyset, sample_message)
            assert p.signer_index == i

    def test_reject_non_member_signer(self, keyset_2of3, sample_message):
        keyset, _ = keyset_2of3
        outsider, _ = dilithium_generate_keypair()
        with pytest.raises(ValueError, match="not a member"):
            create_partial_signature(outsider, keyset, sample_message)

    def test_partial_serialization(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        partial = create_partial_signature(privkeys[0], keyset, sample_message)
        d = partial.to_dict()
        restored = PartialSignature.from_dict(d)
        assert restored.signer_index == partial.signer_index
        assert restored.public_key.to_bytes() == partial.public_key.to_bytes()
        assert restored.signature.to_bytes() == partial.signature.to_bytes()


# ══════════════════════════════════════════════════════════════════════
#  4. AGGREGATION
# ══════════════════════════════════════════════════════════════════════

class TestAggregation:
    """Tests for aggregating partial signatures into MultisigSignature."""

    def test_2of3_aggregate(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        p0 = create_partial_signature(privkeys[0], keyset, sample_message)
        p1 = create_partial_signature(privkeys[1], keyset, sample_message)
        ms = aggregate_partial_signatures([p0, p1], keyset, sample_message)
        assert ms.signer_count == 2
        assert ms.config == keyset.config

    def test_3of5_aggregate(self, keyset_3of5, sample_message):
        keyset, privkeys = keyset_3of5
        partials = [
            create_partial_signature(privkeys[i], keyset, sample_message)
            for i in [0, 2, 4]
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        assert ms.signer_count == 3
        assert sorted(ms.signer_indices) == [0, 2, 4]

    def test_5of7_aggregate(self, keyset_5of7, sample_message):
        keyset, privkeys = keyset_5of7
        partials = [
            create_partial_signature(privkeys[i], keyset, sample_message)
            for i in range(5)
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        assert ms.signer_count == 5

    def test_more_than_threshold_accepted(self, keyset_2of3, sample_message):
        """All 3 signers in a 2-of-3 keyset should be accepted."""
        keyset, privkeys = keyset_2of3
        partials = [
            create_partial_signature(priv, keyset, sample_message)
            for priv in privkeys
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        assert ms.signer_count == 3  # All 3

    def test_1of1_aggregate(self, keyset_1of1, sample_message):
        keyset, privkeys = keyset_1of1
        p = create_partial_signature(privkeys[0], keyset, sample_message)
        ms = aggregate_partial_signatures([p], keyset, sample_message)
        assert ms.signer_count == 1

    def test_reject_below_threshold(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        p0 = create_partial_signature(privkeys[0], keyset, sample_message)
        with pytest.raises(ValueError, match="at least 2"):
            aggregate_partial_signatures([p0], keyset, sample_message)

    def test_reject_duplicate_signer(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        p0 = create_partial_signature(privkeys[0], keyset, sample_message)
        with pytest.raises(ValueError, match="Duplicate"):
            aggregate_partial_signatures([p0, p0], keyset, sample_message)

    def test_reject_non_member_partial(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        outsider, _ = dilithium_generate_keypair()
        p0 = create_partial_signature(privkeys[0], keyset, sample_message)

        # Create a fake partial from outsider
        fake_partial = PartialSignature(
            signer_index=0,
            public_key=outsider,
            signature=p0.signature,
        )
        with pytest.raises(ValueError, match="not a member"):
            aggregate_partial_signatures([fake_partial, p0], keyset, sample_message)

    def test_reject_invalid_signature(self, keyset_2of3, sample_message):
        """Corrupted Dilithium signature must be rejected."""
        keyset, privkeys = keyset_2of3
        p0 = create_partial_signature(privkeys[0], keyset, sample_message)
        p1 = create_partial_signature(privkeys[1], keyset, sample_message)

        # Corrupt p1's signature bytes
        bad_bytes = bytearray(p1.signature.to_bytes())
        bad_bytes[0] ^= 0xFF
        bad_sig = PQSignature.from_bytes(bytes(bad_bytes))
        corrupted = PartialSignature(
            signer_index=p1.signer_index,
            public_key=p1.public_key,
            signature=bad_sig,
        )
        with pytest.raises(PQSignatureError, match="Invalid partial signature"):
            aggregate_partial_signatures([p0, corrupted], keyset, sample_message)

    def test_signer_mask_bits(self, keyset_3of5, sample_message):
        keyset, privkeys = keyset_3of5
        partials = [
            create_partial_signature(privkeys[i], keyset, sample_message)
            for i in [1, 3, 4]
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        # Bit 1, bit 3, bit 4 → mask = 0b11010 = 26
        assert ms.signer_mask == (1 << 1) | (1 << 3) | (1 << 4)


# ══════════════════════════════════════════════════════════════════════
#  5. VERIFICATION
# ══════════════════════════════════════════════════════════════════════

class TestVerification:
    """Tests for full MultisigSignature verification."""

    def test_valid_2of3(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        partials = [
            create_partial_signature(privkeys[0], keyset, sample_message),
            create_partial_signature(privkeys[1], keyset, sample_message),
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        assert verify_multisig(keyset, sample_message, ms)

    def test_valid_3of5(self, keyset_3of5, sample_message):
        keyset, privkeys = keyset_3of5
        partials = [
            create_partial_signature(privkeys[i], keyset, sample_message)
            for i in [0, 1, 2]
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        assert verify_multisig(keyset, sample_message, ms)

    def test_valid_5of7(self, keyset_5of7, sample_message):
        keyset, privkeys = keyset_5of7
        partials = [
            create_partial_signature(privkeys[i], keyset, sample_message)
            for i in range(5)
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        assert verify_multisig(keyset, sample_message, ms)

    def test_valid_1of1(self, keyset_1of1, sample_message):
        keyset, privkeys = keyset_1of1
        p = create_partial_signature(privkeys[0], keyset, sample_message)
        ms = aggregate_partial_signatures([p], keyset, sample_message)
        assert verify_multisig(keyset, sample_message, ms)

    def test_wrong_message_fails(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        partials = [
            create_partial_signature(privkeys[0], keyset, sample_message),
            create_partial_signature(privkeys[1], keyset, sample_message),
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)
        assert not verify_multisig(keyset, b"wrong message!", ms)

    def test_wrong_keyset_fails(self, keyset_2of3, sample_message):
        """Sig for keyset A must not verify against keyset B."""
        keyset_a, privkeys_a = keyset_2of3
        partials = [
            create_partial_signature(privkeys_a[0], keyset_a, sample_message),
            create_partial_signature(privkeys_a[1], keyset_a, sample_message),
        ]
        ms = aggregate_partial_signatures(partials, keyset_a, sample_message)

        # Create a different keyset
        keyset_b, _ = generate_multisig_keyset(ThresholdConfig(m=2, n=3))
        assert not verify_multisig(keyset_b, sample_message, ms)

    def test_multisig_signature_serialization(self, keyset_2of3, sample_message):
        keyset, privkeys = keyset_2of3
        partials = [
            create_partial_signature(privkeys[0], keyset, sample_message),
            create_partial_signature(privkeys[2], keyset, sample_message),
        ]
        ms = aggregate_partial_signatures(partials, keyset, sample_message)

        d = ms.to_dict()
        restored = MultisigSignature.from_dict(d)
        assert verify_multisig(keyset, sample_message, restored)


# ══════════════════════════════════════════════════════════════════════
#  6. DOMAIN SEPARATION
# ══════════════════════════════════════════════════════════════════════

class TestDomainSeparation:
    """Tests for cross-wallet replay protection."""

    def test_same_msg_different_keysets_different_tags(self):
        """Same message with different keyset addresses → different domain tags."""
        tag1 = _domain_tag_message("0xPQMS_keyset_A", b"hello")
        tag2 = _domain_tag_message("0xPQMS_keyset_B", b"hello")
        assert tag1 != tag2

    def test_different_msg_same_keyset_different_tags(self):
        tag1 = _domain_tag_message("0xPQMS_keyset_A", b"hello")
        tag2 = _domain_tag_message("0xPQMS_keyset_A", b"world")
        assert tag1 != tag2

    def test_cross_wallet_replay_rejected(self, sample_message):
        """
        A MultisigSignature for keyset A must NOT verify against keyset B,
        even if the underlying Dilithium keys are the same.
        """
        # Generate a shared signer
        priv1, pub1 = dilithium_generate_keypair()
        priv2, pub2 = dilithium_generate_keypair()
        priv3, pub3 = dilithium_generate_keypair()

        # Keyset A: {pub1, pub2, pub3} with 2-of-3
        config = ThresholdConfig(m=2, n=3)
        keyset_a = create_multisig_keyset(config, [pub1, pub2, pub3])

        # Find the correct private keys for keyset_a ordering
        pk_to_priv = {pub1.to_bytes(): priv1, pub2.to_bytes(): priv2, pub3.to_bytes(): priv3}
        sorted_privs_a = [pk_to_priv[pk.to_bytes()] for pk in keyset_a.public_keys]

        # Sign with keyset A
        partials_a = [
            create_partial_signature(sorted_privs_a[0], keyset_a, sample_message),
            create_partial_signature(sorted_privs_a[1], keyset_a, sample_message),
        ]
        ms_a = aggregate_partial_signatures(partials_a, keyset_a, sample_message)
        assert verify_multisig(keyset_a, sample_message, ms_a)

        # Create keyset B with different additional key
        priv4, pub4 = dilithium_generate_keypair()
        keyset_b = create_multisig_keyset(config, [pub1, pub2, pub4])

        # Replay: use ms_a against keyset_b
        assert not verify_multisig(keyset_b, sample_message, ms_a)


# ══════════════════════════════════════════════════════════════════════
#  7. ADDRESS UTILITIES
# ══════════════════════════════════════════════════════════════════════

class TestAddressUtilities:
    """Tests for is_multisig_address and address formatting."""

    def test_is_multisig_address_valid(self, keyset_2of3):
        keyset, _ = keyset_2of3
        assert is_multisig_address(keyset.address)

    def test_is_multisig_address_invalid(self):
        assert not is_multisig_address("0xPQ1234567890abcdef")
        assert not is_multisig_address("0x1234")
        assert not is_multisig_address("")
        assert not is_multisig_address(None)
        assert not is_multisig_address(42)

    def test_derive_multisig_address_format(self, keyset_2of3):
        keyset, _ = keyset_2of3
        assert keyset.address[:6] == "0xPQMS"
        # Total length = 6 + 38 = 44
        assert len(keyset.address) == 44


# ══════════════════════════════════════════════════════════════════════
#  8. SPENDING SCOPE
# ══════════════════════════════════════════════════════════════════════

class TestSpendingScope:
    """Tests for SpendingScope bitmask."""

    def test_individual_scopes(self):
        assert SpendingScope.TRANSFER == 1
        assert SpendingScope.SWAP == 2
        assert SpendingScope.STAKE == 4
        assert SpendingScope.BRIDGE == 8

    def test_all_scopes(self):
        assert SpendingScope.ALL == 15
        assert SpendingScope.ALL == (
            SpendingScope.TRANSFER | SpendingScope.SWAP |
            SpendingScope.STAKE | SpendingScope.BRIDGE
        )

    def test_none_scope(self):
        assert SpendingScope.NONE == 0

    def test_bitmask_combination(self):
        combo = SpendingScope.TRANSFER | SpendingScope.STAKE
        assert combo & SpendingScope.TRANSFER
        assert combo & SpendingScope.STAKE
        assert not (combo & SpendingScope.SWAP)
        assert not (combo & SpendingScope.BRIDGE)


# ══════════════════════════════════════════════════════════════════════
#  9. SPENDING POLICY
# ══════════════════════════════════════════════════════════════════════

class TestSpendingPolicy:
    """Tests for SpendingPolicy constraints."""

    def test_basic_policy(self):
        pol = SpendingPolicy(
            total_budget=Decimal("10000"),
            daily_limit=Decimal("500"),
            allowed_scopes=SpendingScope.TRANSFER,
        )
        assert pol.total_budget == Decimal("10000")
        assert pol.daily_limit == Decimal("500")
        assert pol.allowed_scopes == SpendingScope.TRANSFER

    def test_scope_check(self):
        pol = SpendingPolicy(
            total_budget=Decimal("10000"),
            allowed_scopes=SpendingScope.TRANSFER | SpendingScope.STAKE,
        )
        assert pol.is_scope_allowed(SpendingScope.TRANSFER)
        assert pol.is_scope_allowed(SpendingScope.STAKE)
        assert not pol.is_scope_allowed(SpendingScope.SWAP)
        assert not pol.is_scope_allowed(SpendingScope.BRIDGE)

    def test_negative_budget_rejected(self):
        with pytest.raises(ValueError, match="negative"):
            SpendingPolicy(total_budget=Decimal("-1"))

    def test_negative_daily_rejected(self):
        with pytest.raises(ValueError, match="negative"):
            SpendingPolicy(total_budget=Decimal("100"), daily_limit=Decimal("-10"))

    def test_zero_daily_means_unlimited(self):
        pol = SpendingPolicy(total_budget=Decimal("100"), daily_limit=Decimal("0"))
        assert pol.daily_limit == 0

    def test_policy_to_dict(self):
        pol = SpendingPolicy(
            total_budget=Decimal("5000"),
            daily_limit=Decimal("250"),
            allowed_scopes=SpendingScope.ALL,
        )
        d = pol.to_dict()
        assert d["total_budget"] == "5000"
        assert d["daily_limit"] == "250"
        assert d["allowed_scopes"] == 15


# ══════════════════════════════════════════════════════════════════════
#  10. AUTO-REFILL RULE
# ══════════════════════════════════════════════════════════════════════

class TestAutoRefillRule:
    """Tests for automatic refill configuration."""

    def test_needs_refill(self):
        rule = AutoRefillRule(
            trigger_below=Decimal("100"),
            refill_to=Decimal("1000"),
        )
        assert rule.needs_refill(Decimal("50"))
        assert not rule.needs_refill(Decimal("150"))

    def test_refill_amount(self):
        rule = AutoRefillRule(
            trigger_below=Decimal("100"),
            refill_to=Decimal("1000"),
        )
        assert rule.refill_amount(Decimal("50")) == Decimal("950")
        assert rule.refill_amount(Decimal("200")) == Decimal("0")

    def test_disabled_rule(self):
        rule = AutoRefillRule(
            trigger_below=Decimal("100"),
            refill_to=Decimal("1000"),
            enabled=False,
        )
        assert not rule.needs_refill(Decimal("50"))

    def test_reject_bad_config(self):
        with pytest.raises(ValueError):
            AutoRefillRule(trigger_below=Decimal("-1"), refill_to=Decimal("100"))
        with pytest.raises(ValueError, match="refill_to must be"):
            AutoRefillRule(trigger_below=Decimal("500"), refill_to=Decimal("100"))


# ══════════════════════════════════════════════════════════════════════
#  11. SUB-WALLET
# ══════════════════════════════════════════════════════════════════════

class TestSubWallet:
    """Tests for SubWallet spending checks and recording."""

    def _make_sub_wallet(self, **overrides):
        """Helper to create a SubWallet with defaults."""
        _, pub = dilithium_generate_keypair()
        defaults = dict(
            address="0xSUB0001",
            name="Test Sub",
            delegate_key=pub,
            policy=SpendingPolicy(
                total_budget=Decimal("1000"),
                daily_limit=Decimal("100"),
                allowed_scopes=SpendingScope.ALL,
            ),
            balance=Decimal("500"),
        )
        defaults.update(overrides)
        return SubWallet(**defaults)

    def test_spending_allowed(self):
        sw = self._make_sub_wallet()
        ok, reason = sw.check_spending_allowed(
            Decimal("50"), SpendingScope.TRANSFER, current_timestamp=86400
        )
        assert ok
        assert reason == "OK"

    def test_frozen_wallet(self):
        sw = self._make_sub_wallet(frozen=True)
        ok, reason = sw.check_spending_allowed(
            Decimal("10"), SpendingScope.TRANSFER, current_timestamp=86400
        )
        assert not ok
        assert "frozen" in reason.lower()

    def test_scope_rejected(self):
        sw = self._make_sub_wallet(
            policy=SpendingPolicy(
                total_budget=Decimal("1000"),
                allowed_scopes=SpendingScope.TRANSFER,
            )
        )
        ok, reason = sw.check_spending_allowed(
            Decimal("10"), SpendingScope.SWAP, current_timestamp=86400
        )
        assert not ok
        assert "scope" in reason.lower()

    def test_insufficient_balance(self):
        sw = self._make_sub_wallet(balance=Decimal("10"))
        ok, reason = sw.check_spending_allowed(
            Decimal("100"), SpendingScope.TRANSFER, current_timestamp=86400
        )
        assert not ok
        assert "balance" in reason.lower()

    def test_budget_exceeded(self):
        sw = self._make_sub_wallet(
            policy=SpendingPolicy(total_budget=Decimal("50")),
            balance=Decimal("500"),
            spent_total=Decimal("45"),
        )
        ok, reason = sw.check_spending_allowed(
            Decimal("10"), SpendingScope.TRANSFER, current_timestamp=86400
        )
        assert not ok
        assert "budget" in reason.lower()

    def test_daily_limit_exceeded(self):
        sw = self._make_sub_wallet()
        ts = 86400 * 100  # Day 100
        sw._reset_daily_if_needed(100)

        # Record up to the daily limit
        sw.record_spend(Decimal("90"), current_timestamp=ts)

        ok, reason = sw.check_spending_allowed(
            Decimal("20"), SpendingScope.TRANSFER, current_timestamp=ts
        )
        assert not ok
        assert "daily limit" in reason.lower()

    def test_daily_reset_on_new_day(self):
        sw = self._make_sub_wallet()
        day1_ts = 86400 * 10  # Day 10
        sw.record_spend(Decimal("90"), current_timestamp=day1_ts)

        # Next day → daily counter resets
        day2_ts = 86400 * 11
        ok, reason = sw.check_spending_allowed(
            Decimal("50"), SpendingScope.TRANSFER, current_timestamp=day2_ts
        )
        assert ok

    def test_record_spend_updates_totals(self):
        sw = self._make_sub_wallet()
        ts = 86400 * 5
        sw.record_spend(Decimal("25"), current_timestamp=ts)
        assert sw.balance == Decimal("475")
        assert sw.spent_total == Decimal("25")
        assert sw.spent_today == Decimal("25")

    def test_zero_daily_limit_means_unlimited(self):
        sw = self._make_sub_wallet(
            policy=SpendingPolicy(
                total_budget=Decimal("10000"),
                daily_limit=Decimal("0"),
                allowed_scopes=SpendingScope.ALL,
            ),
            balance=Decimal("5000"),
        )
        ts = 86400 * 1
        sw.record_spend(Decimal("4000"), current_timestamp=ts)
        ok, reason = sw.check_spending_allowed(
            Decimal("500"), SpendingScope.TRANSFER, current_timestamp=ts
        )
        assert ok

    def test_negative_amount_rejected(self):
        sw = self._make_sub_wallet()
        ok, reason = sw.check_spending_allowed(
            Decimal("-5"), SpendingScope.TRANSFER, current_timestamp=86400
        )
        assert not ok
        assert "positive" in reason.lower()

    def test_to_dict(self):
        sw = self._make_sub_wallet()
        d = sw.to_dict()
        assert d["address"] == "0xSUB0001"
        assert d["name"] == "Test Sub"
        assert "balance" in d
        assert "policy" in d


# ══════════════════════════════════════════════════════════════════════
#  12. PREFUNDED WALLET MANAGER
# ══════════════════════════════════════════════════════════════════════

class TestPrefundedWalletManager:
    """Tests for PrefundedWalletManager operations."""

    def _make_manager(self):
        priv, pub = dilithium_generate_keypair()
        return PrefundedWalletManager(
            master_address=pub.to_address(),
            master_pubkey=pub,
        )

    def _make_sub(self, manager, name="ops", balance="1000", scope=SpendingScope.ALL):
        _, delegate_pub = dilithium_generate_keypair()
        return manager.create_sub_wallet(
            address=f"0xSUB_{name}",
            name=name,
            delegate_key=delegate_pub,
            policy=SpendingPolicy(
                total_budget=Decimal("10000"),
                daily_limit=Decimal("500"),
                allowed_scopes=scope,
            ),
            initial_balance=Decimal(balance),
        )

    def test_create_sub_wallet(self):
        mgr = self._make_manager()
        sw = self._make_sub(mgr)
        assert mgr.sub_wallet_count == 1
        assert mgr.get_sub_wallet(sw.address) is sw

    def test_reject_duplicate_address(self):
        mgr = self._make_manager()
        self._make_sub(mgr, name="ops")
        with pytest.raises(ValueError, match="already exists"):
            self._make_sub(mgr, name="ops")

    def test_list_sub_wallets(self):
        mgr = self._make_manager()
        self._make_sub(mgr, name="a")
        self._make_sub(mgr, name="b")
        self._make_sub(mgr, name="c")
        assert len(mgr.list_sub_wallets()) == 3

    def test_freeze_and_unfreeze(self):
        mgr = self._make_manager()
        sw = self._make_sub(mgr)
        mgr.freeze_sub_wallet(sw.address)
        assert sw.frozen
        ok, _ = sw.check_spending_allowed(Decimal("1"), SpendingScope.TRANSFER)
        assert not ok

        mgr.unfreeze_sub_wallet(sw.address)
        assert not sw.frozen

    def test_freeze_nonexistent(self):
        mgr = self._make_manager()
        with pytest.raises(ValueError, match="not found"):
            mgr.freeze_sub_wallet("0xNONEXISTENT")

    def test_reclaim_funds(self):
        mgr = self._make_manager()
        sw = self._make_sub(mgr, balance="5000")
        reclaimed = mgr.reclaim_funds(sw.address)
        assert reclaimed == Decimal("5000")
        assert sw.balance == Decimal("0")
        assert sw.frozen

    def test_fund_sub_wallet(self):
        mgr = self._make_manager()
        sw = self._make_sub(mgr, balance="100")
        mgr.fund_sub_wallet(sw.address, Decimal("900"))
        assert sw.balance == Decimal("1000")

    def test_fund_negative_rejected(self):
        mgr = self._make_manager()
        sw = self._make_sub(mgr)
        with pytest.raises(ValueError, match="positive"):
            mgr.fund_sub_wallet(sw.address, Decimal("-50"))

    def test_destroy_sub_wallet(self):
        mgr = self._make_manager()
        sw = self._make_sub(mgr, balance="3000")
        reclaimed = mgr.destroy_sub_wallet(sw.address)
        assert reclaimed == Decimal("3000")
        assert mgr.sub_wallet_count == 0

    def test_total_balance(self):
        mgr = self._make_manager()
        self._make_sub(mgr, name="a", balance="1000")
        self._make_sub(mgr, name="b", balance="2000")
        self._make_sub(mgr, name="c", balance="3000")
        assert mgr.total_sub_wallet_balance() == Decimal("6000")

    def test_auto_refill_check(self):
        mgr = self._make_manager()
        _, pub = dilithium_generate_keypair()
        mgr.create_sub_wallet(
            address="0xSUB_AR",
            name="auto-refill",
            delegate_key=pub,
            policy=SpendingPolicy(total_budget=Decimal("10000")),
            initial_balance=Decimal("50"),
            auto_refill=AutoRefillRule(
                trigger_below=Decimal("100"),
                refill_to=Decimal("500"),
            ),
        )
        refills = mgr.check_auto_refills()
        assert len(refills) == 1
        assert refills[0] == ("0xSUB_AR", Decimal("450"))

    def test_execute_auto_refills(self):
        mgr = self._make_manager()
        _, pub = dilithium_generate_keypair()
        mgr.create_sub_wallet(
            address="0xSUB_AR",
            name="auto-refill",
            delegate_key=pub,
            policy=SpendingPolicy(total_budget=Decimal("10000")),
            initial_balance=Decimal("50"),
            auto_refill=AutoRefillRule(
                trigger_below=Decimal("100"),
                refill_to=Decimal("500"),
            ),
        )
        executed = mgr.execute_auto_refills(master_balance=Decimal("10000"))
        assert len(executed) == 1
        assert mgr.get_sub_wallet("0xSUB_AR").balance == Decimal("500")

    def test_auto_refill_insufficient_master(self):
        mgr = self._make_manager()
        _, pub = dilithium_generate_keypair()
        mgr.create_sub_wallet(
            address="0xSUB_AR",
            name="big-refill",
            delegate_key=pub,
            policy=SpendingPolicy(total_budget=Decimal("10000")),
            initial_balance=Decimal("0"),
            auto_refill=AutoRefillRule(
                trigger_below=Decimal("100"),
                refill_to=Decimal("5000"),
            ),
        )
        executed = mgr.execute_auto_refills(master_balance=Decimal("100"))
        # Master cannot afford the refill
        assert len(executed) == 0

    def test_to_dict(self):
        mgr = self._make_manager()
        self._make_sub(mgr, name="ops")
        d = mgr.to_dict()
        assert "master_address" in d
        assert "sub_wallets" in d
        assert len(d["sub_wallets"]) == 1


# ══════════════════════════════════════════════════════════════════════
#  13. SYSTEM WALLET — MULTISIG MIGRATION
# ══════════════════════════════════════════════════════════════════════

class TestSystemWalletMultisig:
    """Tests for multisig-upgraded SystemWalletManager."""

    def test_single_key_backward_compat(self, pq_controller_address):
        """Original single-key mode still works."""
        mgr = initialize_system_wallets(pq_controller_address)
        treasury = "0x0000000000000000000000000000000000000008"
        assert mgr.can_spend_from(treasury, pq_controller_address)
        assert not mgr.can_spend_from(treasury, "0xPQbadaddress00000000000000000000000000bad")

    def test_single_key_validate_tx(self, pq_controller_address):
        mgr = initialize_system_wallets(pq_controller_address)
        treasury = "0x0000000000000000000000000000000000000008"
        ok, msg = mgr.validate_system_transaction(treasury, pq_controller_address)
        assert ok

        ok, msg = mgr.validate_system_transaction(treasury, "0xPQwrong_addr")
        assert not ok
        assert "controller" in msg.lower() or "multisig" in msg.lower()

    def test_burner_never_spendable(self, pq_controller_address):
        mgr = initialize_system_wallets(pq_controller_address)
        burner = "0x0000000000000000000000000000000000000001"
        ok, msg = mgr.validate_system_transaction(burner, pq_controller_address)
        assert not ok
        assert "burner" in msg.lower()

    def test_global_multisig_upgrade(self, pq_controller_address):
        """Upgrade global controller to multisig keyset."""
        mgr = initialize_system_wallets(pq_controller_address)
        keyset, privkeys = generate_multisig_keyset(ThresholdConfig(m=2, n=3))

        mgr.set_global_multisig(keyset)
        assert mgr.is_multisig_controlled()
        assert mgr.controller_address == keyset.address

        treasury = "0x0000000000000000000000000000000000000008"
        assert mgr.can_spend_from(treasury, keyset.address)
        assert not mgr.can_spend_from(treasury, pq_controller_address)

    def test_per_wallet_multisig(self, pq_controller_address):
        """Assign a per-wallet keyset to Treasury only."""
        mgr = initialize_system_wallets(pq_controller_address)
        treasury = "0x0000000000000000000000000000000000000008"
        dev_fund = "0x0000000000000000000000000000000000000003"

        keyset, _ = generate_multisig_keyset(ThresholdConfig(m=5, n=9))
        mgr.set_wallet_multisig(treasury, keyset)

        # Treasury now requires multisig address
        assert mgr.can_spend_from(treasury, keyset.address)
        assert not mgr.can_spend_from(treasury, pq_controller_address)

        # Dev fund still uses single-key controller
        assert mgr.can_spend_from(dev_fund, pq_controller_address)
        assert not mgr.can_spend_from(dev_fund, keyset.address)

    def test_verify_multisig_spend(self, pq_controller_address):
        """Full multisig spend verification through SystemWalletManager."""
        mgr = initialize_system_wallets(pq_controller_address)
        treasury = "0x0000000000000000000000000000000000000008"

        keyset, privkeys = generate_multisig_keyset(ThresholdConfig(m=2, n=3))
        mgr.set_wallet_multisig(treasury, keyset)

        message = b"transfer 1000 QRDX from treasury"
        partials = [
            create_partial_signature(privkeys[0], keyset, message),
            create_partial_signature(privkeys[1], keyset, message),
        ]
        ms_sig = aggregate_partial_signatures(partials, keyset, message)

        ok, reason = mgr.verify_multisig_spend(treasury, message, ms_sig)
        assert ok
        assert reason == "OK"

    def test_verify_multisig_spend_wrong_sig(self, pq_controller_address):
        mgr = initialize_system_wallets(pq_controller_address)
        treasury = "0x0000000000000000000000000000000000000008"

        keyset, privkeys = generate_multisig_keyset(ThresholdConfig(m=2, n=3))
        mgr.set_wallet_multisig(treasury, keyset)

        # Sign with correct message, try to verify with wrong message
        message = b"transfer 1000 QRDX from treasury"
        partials = [
            create_partial_signature(privkeys[0], keyset, message),
            create_partial_signature(privkeys[1], keyset, message),
        ]
        ms_sig = aggregate_partial_signatures(partials, keyset, message)

        ok, reason = mgr.verify_multisig_spend(treasury, b"different message", ms_sig)
        assert not ok
        assert "failed" in reason.lower()

    def test_verify_multisig_spend_no_keyset(self, pq_controller_address):
        """Attempting multisig spend on a non-multisig wallet fails gracefully."""
        mgr = initialize_system_wallets(pq_controller_address)
        treasury = "0x0000000000000000000000000000000000000008"

        keyset, privkeys = generate_multisig_keyset(ThresholdConfig(m=2, n=3))
        message = b"test"
        partials = [
            create_partial_signature(privkeys[0], keyset, message),
            create_partial_signature(privkeys[1], keyset, message),
        ]
        ms_sig = aggregate_partial_signatures(partials, keyset, message)

        ok, reason = mgr.verify_multisig_spend(treasury, message, ms_sig)
        assert not ok
        assert "no multisig" in reason.lower()

    def test_per_wallet_multisig_nonexistent(self, pq_controller_address):
        mgr = initialize_system_wallets(pq_controller_address)
        keyset, _ = generate_multisig_keyset(ThresholdConfig(m=2, n=3))
        with pytest.raises(ValueError, match="Not a registered"):
            mgr.set_wallet_multisig("0xNOTAWALLET", keyset)

    def test_multisig_address_accepted_as_controller(self):
        """A multisig address can be used as the initial controller."""
        keyset, _ = generate_multisig_keyset(ThresholdConfig(m=2, n=3))
        # This should not raise — multisig address is accepted
        mgr = SystemWalletManager(keyset.address)
        assert mgr.controller_address == keyset.address

    def test_get_wallet_multisig_fallback(self, pq_controller_address):
        """get_wallet_multisig falls back to global keyset."""
        mgr = initialize_system_wallets(pq_controller_address)
        global_ks, _ = generate_multisig_keyset(ThresholdConfig(m=3, n=5))
        mgr.set_global_multisig(global_ks)

        treasury = "0x0000000000000000000000000000000000000008"
        ks = mgr.get_wallet_multisig(treasury)
        assert ks is global_ks

    def test_get_wallet_multisig_override(self, pq_controller_address):
        """Per-wallet keyset takes priority over global."""
        mgr = initialize_system_wallets(pq_controller_address)
        global_ks, _ = generate_multisig_keyset(ThresholdConfig(m=3, n=5))
        wallet_ks, _ = generate_multisig_keyset(ThresholdConfig(m=5, n=9))

        mgr.set_global_multisig(global_ks)
        treasury = "0x0000000000000000000000000000000000000008"
        mgr.set_wallet_multisig(treasury, wallet_ks)

        ks = mgr.get_wallet_multisig(treasury)
        assert ks is wallet_ks

        dev_fund = "0x0000000000000000000000000000000000000003"
        ks2 = mgr.get_wallet_multisig(dev_fund)
        assert ks2 is global_ks


# ══════════════════════════════════════════════════════════════════════
#  14. CONSTANTS
# ══════════════════════════════════════════════════════════════════════

class TestConstants:
    """Verify multisig constants are present and sane."""

    def test_multisig_constants(self):
        from qrdx.constants import (
            MULTISIG_MAX_SIGNERS,
            MULTISIG_MAX_THRESHOLD,
            MULTISIG_MIN_THRESHOLD,
            MULTISIG_ADDRESS_PREFIX,
            MULTISIG_DOMAIN_SEPARATOR,
        )
        assert MULTISIG_MAX_SIGNERS == 150
        assert MULTISIG_MAX_THRESHOLD == 100
        assert MULTISIG_MIN_THRESHOLD == 1
        assert MULTISIG_ADDRESS_PREFIX == "0xPQMS"
        assert b"QRDX-THRESHOLD-DILITHIUM" in MULTISIG_DOMAIN_SEPARATOR

    def test_spending_scope_constants(self):
        from qrdx.constants import (
            SPENDING_SCOPE_NONE,
            SPENDING_SCOPE_TRANSFER,
            SPENDING_SCOPE_SWAP,
            SPENDING_SCOPE_STAKE,
            SPENDING_SCOPE_BRIDGE,
            SPENDING_SCOPE_ALL,
        )
        assert SPENDING_SCOPE_NONE == 0
        assert SPENDING_SCOPE_TRANSFER == 1
        assert SPENDING_SCOPE_SWAP == 2
        assert SPENDING_SCOPE_STAKE == 4
        assert SPENDING_SCOPE_BRIDGE == 8
        assert SPENDING_SCOPE_ALL == 15

    def test_institutional_custody_defaults(self):
        from qrdx.constants import (
            TREASURY_MULTISIG_THRESHOLD,
            TREASURY_MULTISIG_TOTAL,
            EMERGENCY_RECOVERY_THRESHOLD,
            EMERGENCY_RECOVERY_TOTAL,
        )
        assert TREASURY_MULTISIG_THRESHOLD == 5
        assert TREASURY_MULTISIG_TOTAL == 9
        assert EMERGENCY_RECOVERY_THRESHOLD == 3
        assert EMERGENCY_RECOVERY_TOTAL == 5


# ══════════════════════════════════════════════════════════════════════
#  15. CRYPTO __init__.py EXPORTS
# ══════════════════════════════════════════════════════════════════════

class TestCryptoExports:
    """Verify threshold symbols are accessible through qrdx.crypto."""

    def test_threshold_config_export(self):
        from qrdx.crypto import ThresholdConfig
        cfg = ThresholdConfig(m=2, n=3)
        assert cfg.m == 2

    def test_multisig_keyset_export(self):
        from qrdx.crypto import MultisigKeySet, generate_multisig_keyset, ThresholdConfig
        ks, _ = generate_multisig_keyset(ThresholdConfig(m=1, n=2))
        assert isinstance(ks, MultisigKeySet)

    def test_verify_multisig_export(self):
        from qrdx.crypto import verify_multisig
        assert callable(verify_multisig)

    def test_is_multisig_address_export(self):
        from qrdx.crypto import is_multisig_address
        assert not is_multisig_address("0x1234")


# ══════════════════════════════════════════════════════════════════════
#  16. WALLET PACKAGE IMPORTS
# ══════════════════════════════════════════════════════════════════════

class TestWalletPackage:
    """Verify wallet package exports."""

    def test_import_spending_scope(self):
        from qrdx.wallet import SpendingScope
        assert SpendingScope.ALL == 15

    def test_import_spending_policy(self):
        from qrdx.wallet import SpendingPolicy
        pol = SpendingPolicy(total_budget=Decimal("100"))
        assert pol.total_budget == Decimal("100")

    def test_import_sub_wallet(self):
        from qrdx.wallet import SubWallet
        assert SubWallet is not None

    def test_import_prefunded_manager(self):
        from qrdx.wallet import PrefundedWalletManager
        assert callable(PrefundedWalletManager)

    def test_import_auto_refill(self):
        from qrdx.wallet import AutoRefillRule
        rule = AutoRefillRule(trigger_below=Decimal("10"), refill_to=Decimal("100"))
        assert rule.enabled
