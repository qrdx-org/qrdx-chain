"""
QRDX net_* RPC Methods

Network-related JSON-RPC methods.
"""

from typing import List
from ..server import RPCModule, rpc_method


class NetModule(RPCModule):
    """
    Network RPC methods (net_* namespace).
    """
    
    namespace = "net"
    
    @rpc_method
    async def version(self) -> str:
        """
        Returns the network ID.
        
        Returns:
            Network ID string
        """
        chain_id = self.context.config.chain_id if self.context else 1
        return str(chain_id)
    
    @rpc_method
    async def listening(self) -> bool:
        """
        Returns whether the node is listening for connections.
        
        Returns:
            True if listening
        """
        # TODO: Check P2P status
        return True
    
    @rpc_method
    async def peerCount(self) -> str:
        """
        Returns the number of connected peers.
        
        Returns:
            Peer count (hex)
        """
        if self.context and hasattr(self.context, 'p2p'):
            count = len(self.context.p2p.peers)
        else:
            count = 0
        return hex(count)
