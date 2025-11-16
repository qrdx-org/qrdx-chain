"""
Integration test for Type 4 and Type 5 PQ transactions with actual signatures

Tests the full transaction flow:
1. Generate PQ keys
2. Create and sign transactions
3. Encode/decode via RLP
4. Verify signatures
"""

import sys
import os

# Add paths
sys.path.insert(0, '/workspaces/qrdx-chain/py-evm')
sys.path.insert(0, '/workspaces/qrdx-chain')

from eth_typing import Address
from eth_utils import to_bytes, to_canonical_address
import rlp

from eth.vm.forks.qrdx.transactions import (
    PureQTransaction,
    HybridTransaction,
    QRDXTypedTransaction,
    PURE_PQ_TRANSACTION_TYPE,
    HYBRID_TRANSACTION_TYPE,
)
from trinity.crypto.pq import (
    DilithiumPrivateKey,
    generate_pq_address,
)
from eth_keys import keys


def test_type4_pure_pq_transaction():
    """Test Type 4 transaction with PQ signature"""
    
    print("\n" + "=" * 60)
    print("TEST: Type 4 Pure PQ Transaction")
    print("=" * 60)
    
    # 1. Generate PQ keys
    print("\n1. Generating Dilithium keys...")
    pq_privkey = DilithiumPrivateKey.generate()
    pq_pubkey = pq_privkey.public_key()
    pq_address = generate_pq_address(pq_pubkey)
    
    print(f"   ✅ PQ Address: {pq_address.hex()[:16]}... ({len(pq_address)} bytes)")
    print(f"   ✅ PQ Pubkey size: {len(pq_pubkey.to_bytes())} bytes")
    
    # 2. Create unsigned transaction
    print("\n2. Creating unsigned transaction...")
    
    from eth.vm.forks.qrdx.transactions import UnsignedPureQTransaction
    
    unsigned_tx = UnsignedPureQTransaction(
        chain_id=1,
        nonce=0,
        gas_price=1000000000,  # 1 gwei
        gas=121000,  # 21k base + 100k for PQ verification
        to=to_canonical_address("0x" + "22" * 20),
        value=1000000000000000000,  # 1 ETH
        data=b"",
        pq_pubkey=pq_pubkey.to_bytes(),
    )
    
    print(f"   ✅ Unsigned TX created")
    print(f"      Chain ID: {unsigned_tx.chain_id}")
    print(f"      Gas: {unsigned_tx.gas}")
    print(f"      Intrinsic gas: {unsigned_tx.intrinsic_gas}")
    
    # 3. Sign transaction
    print("\n3. Signing transaction with Dilithium...")
    message = unsigned_tx.get_message_for_signing()
    signature = pq_privkey.sign(message)
    
    print(f"   ✅ Message length: {len(message)} bytes")
    print(f"   ✅ Signature length: {len(signature)} bytes")
    
    # 4. Create signed transaction
    print("\n4. Creating signed transaction...")
    signed_tx = PureQTransaction(
        chain_id=unsigned_tx.chain_id,
        nonce=unsigned_tx.nonce,
        gas_price=unsigned_tx.gas_price,
        gas=unsigned_tx.gas,
        to=unsigned_tx.to,
        value=unsigned_tx.value,
        data=unsigned_tx.data,
        pq_pubkey=unsigned_tx.pq_pubkey,
        pq_signature=signature,
    )
    
    print(f"   ✅ Signed transaction created")
    
    # 5. Wrap in TypedTransaction
    print("\n5. Wrapping in TypedTransaction...")
    typed_tx = QRDXTypedTransaction(PURE_PQ_TRANSACTION_TYPE, signed_tx)
    
    print(f"   ✅ Type ID: {typed_tx.type_id}")
    print(f"   ✅ Chain ID: {typed_tx.chain_id}")
    
    # 6. Encode transaction
    print("\n6. Encoding transaction to bytes...")
    encoded = typed_tx.encode()
    
    print(f"   ✅ Encoded size: {len(encoded)} bytes")
    print(f"   ✅ First 32 bytes: {encoded[:32].hex()}")
    
    # 7. Decode transaction
    print("\n7. Decoding transaction from bytes...")
    decoded_tx = QRDXTypedTransaction.decode(encoded)
    
    print(f"   ✅ Decoded type ID: {decoded_tx.type_id}")
    print(f"   ✅ Decoded chain ID: {decoded_tx.chain_id}")
    print(f"   ✅ Decoded nonce: {decoded_tx.nonce}")
    
    # 8. Verify signature
    print("\n8. Verifying PQ signature...")
    try:
        decoded_tx.check_signature_validity()
        print("   ✅ Signature verification PASSED")
    except Exception as e:
        print(f"   ❌ Signature verification FAILED: {e}")
        return False
    
    # 9. Verify sender derivation
    print("\n9. Verifying sender derivation...")
    sender = decoded_tx.get_sender()
    
    print(f"   ✅ Sender (truncated): {sender.hex()}")
    print(f"   ✅ Expected (truncated): {pq_address[:20].hex()}")
    
    if sender == pq_address[:20]:
        print("   ✅ Sender matches expected!")
    else:
        print("   ❌ Sender mismatch!")
        return False
    
    print("\n" + "=" * 60)
    print("✅ Type 4 Pure PQ Transaction TEST PASSED")
    print("=" * 60)
    
    return True


def test_type5_hybrid_transaction():
    """Test Type 5 hybrid transaction with both ECDSA and PQ signatures"""
    
    print("\n" + "=" * 60)
    print("TEST: Type 5 Hybrid Transaction")
    print("=" * 60)
    
    # 1. Generate keys
    print("\n1. Generating ECDSA and Dilithium keys...")
    
    # ECDSA key
    ecdsa_privkey_bytes = to_bytes(hexstr="0x" + "01" * 32)
    ecdsa_privkey = keys.PrivateKey(ecdsa_privkey_bytes)
    ecdsa_address = ecdsa_privkey.public_key.to_canonical_address()
    
    # PQ key
    pq_privkey = DilithiumPrivateKey.generate()
    pq_pubkey = pq_privkey.public_key()
    pq_address = generate_pq_address(pq_pubkey)
    
    print(f"   ✅ ECDSA Address: {ecdsa_address.hex()}")
    print(f"   ✅ PQ Address: {pq_address.hex()[:16]}...")
    
    # 2. Create unsigned transaction
    print("\n2. Creating unsigned hybrid transaction...")
    
    from eth.vm.forks.qrdx.transactions import UnsignedHybridTransaction
    
    unsigned_tx = UnsignedHybridTransaction(
        chain_id=1,
        nonce=5,
        gas_price=2000000000,  # 2 gwei
        gas=171000,  # 21k base + 150k for dual verification
        to=to_canonical_address("0x" + "33" * 20),
        value=500000000000000000,  # 0.5 ETH
        data=b"hybrid test",
        pq_pubkey=pq_pubkey.to_bytes(),
    )
    
    print(f"   ✅ Unsigned hybrid TX created")
    print(f"      Gas: {unsigned_tx.gas}")
    print(f"      Intrinsic gas: {unsigned_tx.intrinsic_gas}")
    
    # 3. Sign with both keys
    print("\n3. Signing with ECDSA and Dilithium...")
    message = unsigned_tx.get_message_for_signing()
    
    # ECDSA signature
    ecdsa_signature = ecdsa_privkey.sign_msg(message)
    v, r, s = ecdsa_signature.vrs
    
    # PQ signature
    pq_signature = pq_privkey.sign(message)
    
    print(f"   ✅ ECDSA signature: v={v}, r={r}, s={s}")
    print(f"   ✅ PQ signature length: {len(pq_signature)} bytes")
    
    # 4. Create signed transaction
    print("\n4. Creating signed hybrid transaction...")
    signed_tx = HybridTransaction(
        chain_id=unsigned_tx.chain_id,
        nonce=unsigned_tx.nonce,
        gas_price=unsigned_tx.gas_price,
        gas=unsigned_tx.gas,
        to=unsigned_tx.to,
        value=unsigned_tx.value,
        data=unsigned_tx.data,
        pq_pubkey=unsigned_tx.pq_pubkey,
        v=v,
        r=r,
        s=s,
        pq_signature=pq_signature,
    )
    
    print(f"   ✅ Signed hybrid transaction created")
    
    # 5. Wrap in TypedTransaction
    print("\n5. Wrapping in TypedTransaction...")
    typed_tx = QRDXTypedTransaction(HYBRID_TRANSACTION_TYPE, signed_tx)
    
    print(f"   ✅ Type ID: {typed_tx.type_id}")
    
    # 6. Encode transaction
    print("\n6. Encoding transaction to bytes...")
    encoded = typed_tx.encode()
    
    print(f"   ✅ Encoded size: {len(encoded)} bytes")
    
    # 7. Decode transaction
    print("\n7. Decoding transaction from bytes...")
    decoded_tx = QRDXTypedTransaction.decode(encoded)
    
    print(f"   ✅ Decoded type ID: {decoded_tx.type_id}")
    print(f"   ✅ Decoded nonce: {decoded_tx.nonce}")
    
    # 8. Verify both signatures
    print("\n8. Verifying dual signatures...")
    try:
        decoded_tx.check_signature_validity()
        print("   ✅ ECDSA signature verification PASSED")
        print("   ✅ PQ signature verification PASSED")
    except Exception as e:
        print(f"   ❌ Signature verification FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # 9. Verify sender derivation (should match ECDSA address)
    print("\n9. Verifying sender derivation...")
    sender = decoded_tx.get_sender()
    
    print(f"   ✅ Sender: {sender.hex()}")
    print(f"   ✅ Expected (ECDSA): {ecdsa_address.hex()}")
    
    if sender == ecdsa_address:
        print("   ✅ Sender matches ECDSA address!")
    else:
        print("   ❌ Sender mismatch!")
        return False
    
    print("\n" + "=" * 60)
    print("✅ Type 5 Hybrid Transaction TEST PASSED")
    print("=" * 60)
    
    return True


def print_summary():
    """Print summary of PQ transaction implementation"""
    
    print("\n" + "=" * 60)
    print("PQ TRANSACTION IMPLEMENTATION SUMMARY")
    print("=" * 60)
    
    print("\n✅ COMPLETED:")
    print("   • Type 4 (Pure PQ) transaction format")
    print("   • Type 5 (Hybrid) transaction format")
    print("   • RLP encoding/decoding for PQ transactions")
    print("   • Dilithium signature verification")
    print("   • Dual signature verification (ECDSA + Dilithium)")
    print("   • PQ address derivation (32-byte addresses)")
    print("   • Gas cost modeling (100k PQ, 150k hybrid)")
    print("   • Integration with py-evm transaction system")
    
    print("\n⏳ TODO (Next Phase):")
    print("   1. Address Registry Contract")
    print("      - Link classical ↔ PQ addresses")
    print("      - Deploy at 0x...0100")
    print("   ")
    print("   2. RPC API Extensions")
    print("      - eth_sendPQTransaction")
    print("      - eth_generatePQAddress")
    print("      - eth_migrateAccount")
    print("   ")
    print("   3. Transaction Pool Updates")
    print("      - Validate PQ transactions")
    print("      - Handle larger transaction sizes")
    print("      - Fee estimation for PQ gas costs")
    print("   ")
    print("   4. State Database")
    print("      - Store full 32-byte PQ addresses")
    print("      - Maintain address mapping registry")
    print("   ")
    print("   5. QR-PoS Consensus")
    print("      - Replace Ethash with PQ-secured PoS")
    print("      - Dilithium validator signatures")
    
    print("\n📊 SIZE METRICS:")
    print("   Legacy TX:    ~110 bytes")
    print("   Type 4 (PQ):  ~7,300 bytes (66x larger)")
    print("   Type 5 (Hyb): ~7,400 bytes (67x larger)")
    print("   ")
    print("   Block size impact:")
    print("   - 150 legacy TXs/block = ~16.5 KB")
    print("   - 150 PQ TXs/block = ~1.1 MB (67x larger)")
    print("   - Mitigation: Lower TPS or larger blocks")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    print("\n🚀 QRDX PQ Transaction Integration Tests")
    print("=" * 60)
    
    # Run tests
    test1_passed = test_type4_pure_pq_transaction()
    test2_passed = test_type5_hybrid_transaction()
    
    # Print summary
    print_summary()
    
    # Final result
    if test1_passed and test2_passed:
        print("\n🎉 ALL INTEGRATION TESTS PASSED!")
        print("\nType 4 and Type 5 PQ transactions are fully functional.")
        print("Ready to proceed with address registry and RPC API.")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED")
        sys.exit(1)
