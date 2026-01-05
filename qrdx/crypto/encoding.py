"""
QRDX RLP Encoding Module

Recursive Length Prefix (RLP) encoding for Ethereum-compatible
data serialization.
"""

from typing import Any, List, Union, Tuple

# Type alias for RLP-encodable data
RLPData = Union[bytes, List[Any]]


def rlp_encode(data: RLPData) -> bytes:
    """
    Encode data using RLP (Recursive Length Prefix).
    
    Args:
        data: Bytes or list of RLP-encodable items
        
    Returns:
        RLP-encoded bytes
    """
    if isinstance(data, bytes):
        return _encode_bytes(data)
    elif isinstance(data, (list, tuple)):
        return _encode_list(data)
    elif isinstance(data, str):
        return _encode_bytes(data.encode('utf-8'))
    elif isinstance(data, int):
        if data == 0:
            return _encode_bytes(b'')
        return _encode_bytes(_int_to_bytes(data))
    elif data is None:
        return _encode_bytes(b'')
    else:
        raise TypeError(f"Cannot RLP encode type: {type(data)}")


def _encode_bytes(data: bytes) -> bytes:
    """Encode bytes with RLP."""
    length = len(data)
    
    if length == 1 and data[0] < 0x80:
        # Single byte in range [0x00, 0x7f]
        return data
    elif length <= 55:
        # Short string (0-55 bytes)
        return bytes([0x80 + length]) + data
    else:
        # Long string (>55 bytes)
        length_bytes = _int_to_bytes(length)
        return bytes([0xb7 + len(length_bytes)]) + length_bytes + data


def _encode_list(data: List[Any]) -> bytes:
    """Encode list with RLP."""
    # Recursively encode all items
    encoded_items = b''.join(rlp_encode(item) for item in data)
    length = len(encoded_items)
    
    if length <= 55:
        # Short list
        return bytes([0xc0 + length]) + encoded_items
    else:
        # Long list
        length_bytes = _int_to_bytes(length)
        return bytes([0xf7 + len(length_bytes)]) + length_bytes + encoded_items


def rlp_decode(data: bytes) -> RLPData:
    """
    Decode RLP-encoded data.
    
    Args:
        data: RLP-encoded bytes
        
    Returns:
        Decoded data (bytes or list)
    """
    result, remainder = _decode_item(data)
    if remainder:
        raise ValueError(f"Trailing bytes after RLP data: {len(remainder)} bytes")
    return result


def _decode_item(data: bytes) -> Tuple[RLPData, bytes]:
    """Decode a single RLP item and return (item, remaining_bytes)."""
    if not data:
        raise ValueError("Empty RLP data")
    
    prefix = data[0]
    
    if prefix < 0x80:
        # Single byte
        return bytes([prefix]), data[1:]
    
    elif prefix <= 0xb7:
        # Short string (0-55 bytes)
        length = prefix - 0x80
        if len(data) < 1 + length:
            raise ValueError("Insufficient data for short string")
        return data[1:1+length], data[1+length:]
    
    elif prefix <= 0xbf:
        # Long string
        length_of_length = prefix - 0xb7
        if len(data) < 1 + length_of_length:
            raise ValueError("Insufficient data for length")
        length = _bytes_to_int(data[1:1+length_of_length])
        start = 1 + length_of_length
        if len(data) < start + length:
            raise ValueError("Insufficient data for long string")
        return data[start:start+length], data[start+length:]
    
    elif prefix <= 0xf7:
        # Short list
        length = prefix - 0xc0
        if len(data) < 1 + length:
            raise ValueError("Insufficient data for short list")
        return _decode_list_items(data[1:1+length]), data[1+length:]
    
    else:
        # Long list
        length_of_length = prefix - 0xf7
        if len(data) < 1 + length_of_length:
            raise ValueError("Insufficient data for list length")
        length = _bytes_to_int(data[1:1+length_of_length])
        start = 1 + length_of_length
        if len(data) < start + length:
            raise ValueError("Insufficient data for long list")
        return _decode_list_items(data[start:start+length]), data[start+length:]


def _decode_list_items(data: bytes) -> List[RLPData]:
    """Decode all items from list payload."""
    items = []
    while data:
        item, data = _decode_item(data)
        items.append(item)
    return items


def _int_to_bytes(value: int) -> bytes:
    """Convert integer to big-endian bytes (no leading zeros)."""
    if value == 0:
        return b''
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, 'big')


def _bytes_to_int(data: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(data, 'big')


# Convenience functions for common types

def encode_uint(value: int) -> bytes:
    """Encode unsigned integer."""
    if value < 0:
        raise ValueError("Cannot encode negative integer")
    if value == 0:
        return rlp_encode(b'')
    return rlp_encode(_int_to_bytes(value))


def decode_uint(data: bytes) -> int:
    """Decode unsigned integer from RLP."""
    decoded = rlp_decode(data)
    if isinstance(decoded, bytes):
        if len(decoded) == 0:
            return 0
        return _bytes_to_int(decoded)
    raise ValueError("Expected bytes, got list")


def encode_address(address: str) -> bytes:
    """Encode address (20 bytes) for RLP."""
    if address.startswith('0x'):
        address = address[2:]
    return rlp_encode(bytes.fromhex(address))


def encode_transaction(
    nonce: int,
    gas_price: int,
    gas_limit: int,
    to: str,
    value: int,
    data: bytes,
    chain_id: int = None
) -> bytes:
    """
    Encode a transaction for signing.
    
    If chain_id is provided, encodes for EIP-155 signing.
    """
    # Handle 'to' address
    if to:
        if to.startswith('0x'):
            to = to[2:]
        to_bytes = bytes.fromhex(to)
    else:
        to_bytes = b''
    
    tx_list = [
        _int_to_bytes(nonce) if nonce else b'',
        _int_to_bytes(gas_price) if gas_price else b'',
        _int_to_bytes(gas_limit) if gas_limit else b'',
        to_bytes,
        _int_to_bytes(value) if value else b'',
        data or b'',
    ]
    
    # EIP-155 adds chain_id, 0, 0 for signing
    if chain_id is not None:
        tx_list.extend([
            _int_to_bytes(chain_id),
            b'',
            b'',
        ])
    
    return rlp_encode(tx_list)
