"""
Keccak-256 implementation using eth_hash as a drop-in replacement for pysha3.

This module provides a sha3-compatible API using eth_hash which is already
part of the Trinity dependency chain.
"""
from eth_hash.auto import keccak as _keccak


class keccak_256:
    """
    Keccak-256 hasher compatible with pysha3's sha3.keccak_256 API.
    
    This class wraps eth_hash.auto.keccak to provide the same interface
    as pysha3's sha3.keccak_256 class, including update(), digest(), copy(), etc.
    
    Example:
        >>> h = keccak_256()
        >>> h.update(b"hello")
        >>> h.update(b"world")
        >>> h.digest().hex()
        
        >>> # Or initialize with data
        >>> h2 = keccak_256(b"helloworld")
        >>> h2.digest().hex()
    """
    
    def __init__(self, data: bytes = b''):
        """
        Initialize Keccak-256 hasher.
        
        Args:
            data: Optional initial data to hash
        """
        self._data = bytearray(data)
    
    def update(self, data: bytes) -> None:
        """
        Update the hash with additional data.
        
        Args:
            data: Data to add to the hash
        """
        self._data.extend(data)
    
    def digest(self) -> bytes:
        """
        Get the digest of the accumulated data.
        
        Returns:
            32-byte Keccak-256 hash
        """
        return _keccak(bytes(self._data))
    
    def hexdigest(self) -> str:
        """
        Get the hex digest of the accumulated data.
        
        Returns:
            64-character hex string of the hash
        """
        return self.digest().hex()
    
    def copy(self) -> 'keccak_256':
        """
        Create a copy of this hasher.
        
        Returns:
            New keccak_256 instance with the same accumulated data
        """
        new = keccak_256()
        new._data = bytearray(self._data)
        return new
    
    @property
    def digest_size(self) -> int:
        """Size of the hash in bytes (always 32 for Keccak-256)."""
        return 32
    
    @property
    def block_size(self) -> int:
        """Block size in bytes."""
        return 136  # Keccak-256 block size
    
    @property
    def name(self) -> str:
        """Algorithm name."""
        return 'keccak-256'


# Make keccak_256 callable like sha3.keccak_256(data)
def _keccak_256_factory(data: bytes = b'') -> keccak_256:
    """Factory function to create keccak_256 instances."""
    return keccak_256(data)


# For backwards compatibility, also allow sha3.keccak_256() style usage
keccak_256 = type('keccak_256', (), {
    '__call__': lambda self, data=b'': keccak_256.__new__(keccak_256, data),
    '__new__': lambda cls, data=b'': object.__new__(keccak_256).__init__(data) or object.__new__(keccak_256),
})()

# Actually, simpler approach - make the class callable
class Keccak256Meta(type):
    """Metaclass to make keccak_256 class callable as both class and instance."""
    def __call__(cls, data: bytes = b''):
        """Allow keccak_256(data) to create instances."""
        instance = cls.__new__(cls)
        instance.__init__(data)
        return instance


class keccak_256(metaclass=Keccak256Meta):
    """
    Keccak-256 hasher compatible with pysha3's sha3.keccak_256 API.
    
    Usage:
        # Create instance and update
        h = keccak_256()
        h.update(b"data")
        digest = h.digest()
        
        # Or initialize with data
        h = keccak_256(b"data")
        digest = h.digest()
    """
    
    def __init__(self, data: bytes = b''):
        self._data = bytearray(data)
    
    def update(self, data: bytes) -> None:
        """Update the hash with additional data."""
        self._data.extend(data)
    
    def digest(self) -> bytes:
        """Get the 32-byte Keccak-256 digest."""
        return _keccak(bytes(self._data))
    
    def hexdigest(self) -> str:
        """Get the hex digest."""
        return self.digest().hex()
    
    def copy(self) -> 'keccak_256':
        """Create a copy of this hasher."""
        new = keccak_256.__new__(keccak_256)
        new._data = bytearray(self._data)
        return new
    
    @property
    def digest_size(self) -> int:
        return 32
    
    @property
    def block_size(self) -> int:
        return 136
    
    @property
    def name(self) -> str:
        return 'keccak-256'
