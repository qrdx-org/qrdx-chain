"""
QRDX web3_* RPC Methods

Utility JSON-RPC methods.
"""

from ..server import RPCModule, rpc_method
from ...crypto.hashing import keccak256


class Web3Module(RPCModule):
    """
    Web3 utility methods (web3_* namespace).
    """
    
    namespace = "web3"
    
    @rpc_method
    async def clientVersion(self) -> str:
        """
        Returns the client version string.
        
        Returns:
            Client version
        """
        from ...constants import NODE_VERSION
        return f"QRDX/{NODE_VERSION}/python"
    
    @rpc_method
    async def sha3(self, data: str) -> str:
        """
        Returns Keccak-256 hash of input.
        
        Args:
            data: Input data (hex string with 0x prefix)
            
        Returns:
            Hash (hex with 0x prefix)
        """
        if data.startswith("0x"):
            data = data[2:]
        
        input_bytes = bytes.fromhex(data)
        hash_bytes = keccak256(input_bytes)
        return "0x" + hash_bytes.hex()
