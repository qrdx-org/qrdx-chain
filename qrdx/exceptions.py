"""
QRDX Exceptions

Custom exception classes for the QRDX blockchain.
"""


class QRDXException(Exception):
    """Base exception for QRDX."""
    pass


class DoubleSpendException(QRDXException):
    """Transaction attempts to spend already-spent outputs."""
    pass


class InvalidTransactionException(QRDXException):
    """Transaction is invalid."""
    pass


class InvalidBlockException(QRDXException):
    """Block is invalid."""
    pass


class InvalidKeyError(QRDXException):
    """Invalid cryptographic key."""
    pass


class InvalidAddressError(QRDXException):
    """Invalid address format."""
    pass


class InvalidSignatureError(QRDXException):
    """Invalid cryptographic signature."""
    pass


class NetworkError(QRDXException):
    """Network communication error."""
    pass


class PeerError(QRDXException):
    """Peer-related error."""
    pass


class HandshakeError(PeerError):
    """Handshake failed."""
    pass


class ProtocolError(PeerError):
    """Protocol violation."""
    pass


class SyncError(QRDXException):
    """Chain synchronization error."""
    pass


class ConfigurationError(QRDXException):
    """Configuration error."""
    pass
