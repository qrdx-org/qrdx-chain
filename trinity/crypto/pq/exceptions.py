"""
Post-Quantum Cryptography Exceptions

Custom exceptions for PQ crypto operations.
"""


class PQCryptoError(Exception):
    """Base exception for all PQ crypto errors"""
    pass


class DilithiumError(PQCryptoError):
    """Dilithium signature operation errors"""
    pass


class KyberError(PQCryptoError):
    """Kyber key encapsulation errors"""
    pass


class InvalidPublicKey(PQCryptoError):
    """Invalid public key format or size"""
    pass


class InvalidPrivateKey(PQCryptoError):
    """Invalid private key format or size"""
    pass


class InvalidSignature(PQCryptoError):
    """Invalid signature or signature verification failed"""
    pass


class SignatureVerificationFailed(InvalidSignature):
    """Signature verification failed (signature is valid format but doesn't match)"""
    pass


class InvalidCiphertext(KyberError):
    """Invalid Kyber ciphertext"""
    pass


class KeyGenerationError(PQCryptoError):
    """Error during key generation"""
    pass


class InvalidAddress(PQCryptoError):
    """Invalid PQ address format"""
    pass


class AddressEncodingError(InvalidAddress):
    """Error encoding/decoding PQ address"""
    pass


class HybridKeyError(PQCryptoError):
    """Error with hybrid key operations"""
    pass


class LibraryNotAvailable(PQCryptoError):
    """Required PQ cryptography library not available"""
    pass
