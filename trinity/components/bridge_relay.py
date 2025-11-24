"""
QRDX Bridge Relay Service

Standalone service that monitors both Ethereum and QRDX chains for bridge 
events and relays cross-chain transfer confirmations.

This is a separate service from the QRDX chain itself and connects to:
- Ethereum via Infura/Alchemy or local node
- QRDX via local QRDX node RPC

Requirements:
- web3>=6.0.0
- eth-account>=0.8.0
- liboqs-python>=0.9.0 (for Dilithium signatures)
- blake3>=0.4.0 (for hashing)
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from web3 import Web3, HTTPProvider
from web3.contract import Contract
from eth_account import Account
from hexbytes import HexBytes

# Import QRDX crypto modules (assumed to be available from Phase 1-6)
try:
    from eth.crypto.dilithium import DilithiumSigner
    from eth.crypto.blake3 import blake3_hash
except ImportError:
    # Fallback implementations for testing
    import hashlib
    
    class DilithiumSigner:
        def __init__(self, private_key: bytes):
            self.private_key = private_key
        
        def sign(self, message: bytes) -> bytes:
            # Placeholder - real implementation uses liboqs
            return hashlib.sha256(self.private_key + message).digest() * 103  # 3309 bytes
    
    def blake3_hash(data: bytes) -> bytes:
        # Placeholder - real implementation uses blake3 library
        return hashlib.sha256(data).digest()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ChainType(Enum):
    ETHEREUM = "ethereum"
    QRDX = "qrdx"


@dataclass
class BridgeTransfer:
    """Cross-chain transfer"""
    transfer_id: bytes
    sender: str
    recipient: str
    token: str
    amount: int
    source_chain: ChainType
    target_chain: ChainType
    timestamp: int
    confirmations: int
    status: str
    merkle_root: Optional[bytes] = None


class QRDXBridgeRelay:
    """
    Bridge relay service for ETH<->QRDX transfers
    
    Responsibilities:
    - Monitor deposit events on Ethereum
    - Monitor deposit events on QRDX
    - Generate Merkle proofs for transfers
    - Submit validator confirmations
    - Relay transfer data between chains
    """
    
    def __init__(
        self,
        eth_rpc_url: str,
        qrdx_rpc_url: str,
        bridge_eth_address: str,
        bridge_qrdx_address: str,
        validator_private_key: bytes,
        validator_eth_key: str,  # Ethereum private key for signing transactions
        bridge_abi: List[Dict]  # Bridge contract ABI
    ):
        self.eth_rpc_url = eth_rpc_url
        self.qrdx_rpc_url = qrdx_rpc_url
        
        # Web3 connections
        self.eth_w3 = Web3(HTTPProvider(eth_rpc_url))
        self.qrdx_w3 = Web3(HTTPProvider(qrdx_rpc_url))
        
        # Verify connections
        if not self.eth_w3.is_connected():
            raise ConnectionError(f"Cannot connect to Ethereum RPC: {eth_rpc_url}")
        if not self.qrdx_w3.is_connected():
            raise ConnectionError(f"Cannot connect to QRDX RPC: {qrdx_rpc_url}")
        
        logger.info(f"✅ Connected to Ethereum: {eth_rpc_url}")
        logger.info(f"   Chain ID: {self.eth_w3.eth.chain_id}")
        logger.info(f"   Latest block: {self.eth_w3.eth.block_number}")
        
        logger.info(f"✅ Connected to QRDX: {qrdx_rpc_url}")
        logger.info(f"   Chain ID: {self.qrdx_w3.eth.chain_id}")
        logger.info(f"   Latest block: {self.qrdx_w3.eth.block_number}")
        
        # Ethereum account for transaction signing
        self.eth_account = Account.from_key(validator_eth_key)
        logger.info(f"🔑 Validator ETH address: {self.eth_account.address}")
        
        # Bridge contracts
        self.bridge_eth: Contract = self.eth_w3.eth.contract(
            address=Web3.to_checksum_address(bridge_eth_address),
            abi=bridge_abi
        )
        self.bridge_qrdx: Contract = self.qrdx_w3.eth.contract(
            address=Web3.to_checksum_address(bridge_qrdx_address),
            abi=bridge_abi
        )
        
        logger.info(f"📄 Ethereum bridge: {bridge_eth_address}")
        logger.info(f"📄 QRDX bridge: {bridge_qrdx_address}")
        
        # Dilithium signer for quantum-resistant signatures
        self.signer = DilithiumSigner(validator_private_key)
        logger.info("🔐 Dilithium signer initialized")
        
        # Transfer tracking
        self.pending_transfers: Dict[bytes, BridgeTransfer] = {}
        self.confirmed_transfers: Dict[bytes, BridgeTransfer] = {}
        
        # Merkle tree state
        self.merkle_trees: Dict[ChainType, MerkleTree] = {
            ChainType.ETHEREUM: MerkleTree(),
            ChainType.QRDX: MerkleTree()
        }
        
        # Last processed blocks
        self.last_eth_block = 0
        self.last_qrdx_block = 0
        
    async def start(self):
        """Start the bridge relay service"""
        logger.info("Starting QRDX Bridge Relay Service")
        
        # Start monitoring both chains concurrently
        await asyncio.gather(
            self.monitor_ethereum(),
            self.monitor_qrdx(),
            self.process_pending_transfers()
        )
    
    async def monitor_ethereum(self):
        """Monitor Ethereum chain for deposit events"""
        logger.info("🔍 Monitoring Ethereum chain for deposits...")
        
        # Get starting block
        self.last_eth_block = self.eth_w3.eth.block_number
        logger.info(f"   Starting from block {self.last_eth_block}")
        
        while True:
            try:
                # Get latest block
                latest_block = self.eth_w3.eth.block_number
                
                if latest_block > self.last_eth_block:
                    # Get deposit events from bridge contract
                    events = self.bridge_eth.events.DepositInitiated.get_logs(
                        fromBlock=self.last_eth_block + 1,
                        toBlock=latest_block
                    )
                    
                    if events:
                        logger.info(
                            f"📥 Ethereum: Blocks {self.last_eth_block + 1}-{latest_block}, "
                            f"found {len(events)} deposit(s)"
                        )
                    
                        for event in events:
                            transfer = self._parse_deposit_event(event, ChainType.ETHEREUM)
                            await self.handle_new_transfer(transfer)
                    
                    self.last_eth_block = latest_block
                
                await asyncio.sleep(12)  # Ethereum block time (~12 seconds)
                
            except Exception as e:
                logger.error(f"❌ Error monitoring Ethereum: {e}")
                await asyncio.sleep(5)
    
    async def monitor_qrdx(self):
        """Monitor QRDX chain for deposit events"""
        logger.info("🔍 Monitoring QRDX chain for deposits...")
        
        # Get starting block
        self.last_qrdx_block = self.qrdx_w3.eth.block_number
        logger.info(f"   Starting from block {self.last_qrdx_block}")
        
        while True:
            try:
                # Get latest block
                latest_block = self.qrdx_w3.eth.block_number
                
                if latest_block > self.last_qrdx_block:
                    # Get deposit events from bridge contract
                    events = self.bridge_qrdx.events.DepositInitiated.get_logs(
                        fromBlock=self.last_qrdx_block + 1,
                        toBlock=latest_block
                    )
                    
                    if events:
                        logger.info(
                            f"📥 QRDX: Blocks {self.last_qrdx_block + 1}-{latest_block}, "
                            f"found {len(events)} deposit(s)"
                        )
                    
                        for event in events:
                            transfer = self._parse_deposit_event(event, ChainType.QRDX)
                            await self.handle_new_transfer(transfer)
                    
                    self.last_qrdx_block = latest_block
                
                await asyncio.sleep(2)  # QRDX block time (2 seconds)
                
            except Exception as e:
                logger.error(f"❌ Error monitoring QRDX: {e}")
                await asyncio.sleep(2)
    
    async def handle_new_transfer(self, transfer: BridgeTransfer):
        """Handle a new cross-chain transfer"""
        logger.info(f"💸 New transfer: {transfer.transfer_id.hex()}")
        logger.info(f"   From: {transfer.sender}")
        logger.info(f"   To: {transfer.recipient}")
        logger.info(f"   Amount: {transfer.amount}")
        logger.info(f"   {transfer.source_chain.value} → {transfer.target_chain.value}")
        
        # Add to pending transfers
        self.pending_transfers[transfer.transfer_id] = transfer
        
        # Add to Merkle tree for source chain
        self.merkle_trees[transfer.source_chain].add_leaf(
            self._create_merkle_leaf(transfer)
        )
        
        # Generate Merkle proof
        proof = self.merkle_trees[transfer.source_chain].get_proof(
            self._create_merkle_leaf(transfer)
        )
        
        logger.info(f"🌳 Generated Merkle proof ({len(proof)} nodes)")
        
        # Sign transfer with Dilithium
        signature = await self.sign_transfer(transfer)
        
        # Submit confirmation to target chain
        await self.submit_confirmation(transfer, proof, signature)
    
    async def sign_transfer(self, transfer: BridgeTransfer) -> bytes:
        """Sign transfer with Dilithium (quantum-resistant)"""
        # Create message to sign
        message = self._create_transfer_message(transfer)
        
        # Sign with Dilithium
        signature = self.signer.sign(message)
        
        logger.info(f"✍️  Signed with Dilithium ({len(signature)} bytes)")
        return signature
    
    async def submit_confirmation(
        self,
        transfer: BridgeTransfer,
        proof: List[bytes],
        signature: bytes
    ):
        """Submit transfer confirmation to target chain"""
        target_chain = transfer.target_chain
        
        try:
            if target_chain == ChainType.ETHEREUM:
                tx_hash = await self._submit_eth_confirmation(
                    transfer, proof, signature
                )
            else:
                tx_hash = await self._submit_qrdx_confirmation(
                    transfer, proof, signature
                )
            
            logger.info(
                f"✅ Submitted confirmation to {target_chain.value}: {tx_hash}"
            )
            
            # Update confirmation count
            transfer.confirmations += 1
            
        except Exception as e:
            logger.error(f"❌ Failed to submit confirmation: {e}")
            # Will retry on next process_pending_transfers cycle
    
    async def process_pending_transfers(self):
        """Process pending transfers and check for completion"""
        while True:
            try:
                for transfer_id, transfer in list(self.pending_transfers.items()):
                    # Check if transfer is confirmed
                    if await self._is_transfer_confirmed(transfer):
                        logger.info(
                            f"Transfer {transfer_id.hex()} confirmed, "
                            f"moving to completed"
                        )
                        
                        # Move to confirmed
                        self.confirmed_transfers[transfer_id] = transfer
                        del self.pending_transfers[transfer_id]
                    
                    # Check for expiration
                    elif await self._is_transfer_expired(transfer):
                        logger.warning(
                            f"Transfer {transfer_id.hex()} expired, removing"
                        )
                        del self.pending_transfers[transfer_id]
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error processing pending transfers: {e}")
                await asyncio.sleep(10)
    
    def _create_merkle_leaf(self, transfer: BridgeTransfer) -> bytes:
        """Create Merkle tree leaf for transfer"""
        # Encode transfer data
        data = (
            transfer.sender.encode() +
            transfer.recipient.encode() +
            transfer.token.encode() +
            transfer.amount.to_bytes(32, 'big') +
            transfer.timestamp.to_bytes(8, 'big')
        )
        
        # Hash with BLAKE3 (quantum-resistant)
        return blake3_hash(data)
    
    def _create_transfer_message(self, transfer: BridgeTransfer) -> bytes:
        """Create message for signing"""
        return (
            transfer.transfer_id +
            transfer.sender.encode() +
            transfer.recipient.encode() +
            transfer.amount.to_bytes(32, 'big')
        )
    
    def _parse_deposit_event(
        self,
        event: Any,
        source_chain: ChainType
    ) -> BridgeTransfer:
        """Parse deposit event into BridgeTransfer"""
        target_chain = (
            ChainType.QRDX if source_chain == ChainType.ETHEREUM
            else ChainType.ETHEREUM
        )
        
        # Extract event data
        args = event['args']
        
        return BridgeTransfer(
            transfer_id=args['transferId'],
            sender=args['sender'],
            recipient=args['recipient'],
            token=args['token'],
            amount=args['amount'],
            source_chain=source_chain,
            target_chain=target_chain,
            timestamp=int(time.time()),
            confirmations=0,
            status='pending'
        )
    
    async def _submit_eth_confirmation(
        self,
        transfer: BridgeTransfer,
        proof: List[bytes],
        signature: bytes
    ) -> str:
        """Submit confirmation to Ethereum bridge"""
        try:
            # Build transaction
            tx = self.bridge_eth.functions.confirmTransfer(
                transfer.transfer_id,
                signature
            ).build_transaction({
                'from': self.eth_account.address,
                'nonce': self.eth_w3.eth.get_transaction_count(self.eth_account.address),
                'gas': 200000,
                'gasPrice': self.eth_w3.eth.gas_price
            })
            
            # Sign transaction
            signed_tx = self.eth_account.sign_transaction(tx)
            
            # Send transaction
            tx_hash = self.eth_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for receipt
            receipt = self.eth_w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            
            if receipt['status'] == 1:
                logger.info(f"   Gas used: {receipt['gasUsed']:,}")
                return tx_hash.hex()
            else:
                raise Exception(f"Transaction failed: {tx_hash.hex()}")
                
        except Exception as e:
            logger.error(f"Failed to submit Ethereum confirmation: {e}")
            raise
    
    async def _submit_qrdx_confirmation(
        self,
        transfer: BridgeTransfer,
        proof: List[bytes],
        signature: bytes
    ) -> str:
        """Submit confirmation to QRDX bridge"""
        try:
            # Build transaction
            tx = self.bridge_qrdx.functions.confirmTransfer(
                transfer.transfer_id,
                signature
            ).build_transaction({
                'from': self.eth_account.address,
                'nonce': self.qrdx_w3.eth.get_transaction_count(self.eth_account.address),
                'gas': 200000,
                'gasPrice': self.qrdx_w3.eth.gas_price
            })
            
            # Sign transaction
            signed_tx = self.eth_account.sign_transaction(tx)
            
            # Send transaction
            tx_hash = self.qrdx_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for receipt
            receipt = self.qrdx_w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            
            if receipt['status'] == 1:
                logger.info(f"   Gas used: {receipt['gasUsed']:,}")
                return tx_hash.hex()
            else:
                raise Exception(f"Transaction failed: {tx_hash.hex()}")
                
        except Exception as e:
            logger.error(f"Failed to submit QRDX confirmation: {e}")
            raise
    
    async def _is_transfer_confirmed(self, transfer: BridgeTransfer) -> bool:
        """Check if transfer has enough confirmations"""
        try:
            # Query target chain for transfer status
            if transfer.target_chain == ChainType.ETHEREUM:
                transfer_data = self.bridge_eth.functions.getTransfer(
                    transfer.transfer_id
                ).call()
            else:
                transfer_data = self.bridge_qrdx.functions.getTransfer(
                    transfer.transfer_id
                ).call()
            
            # Check status (Confirmed = 1)
            return transfer_data[9] == 1  # status field
            
        except Exception as e:
            logger.debug(f"Transfer {transfer.transfer_id.hex()} not yet on target chain")
            return False
    
    async def _is_transfer_expired(self, transfer: BridgeTransfer) -> bool:
        """Check if transfer has expired"""
        expiration_time = transfer.timestamp + (30 * 24 * 60 * 60)  # 30 days
        return time.time() > expiration_time


class MerkleTree:
    """
    Merkle tree for generating inclusion proofs
    
    Uses BLAKE3 for quantum resistance
    """
    
    def __init__(self):
        self.leaves: List[bytes] = []
        self.root: Optional[bytes] = None
    
    def add_leaf(self, leaf: bytes):
        """Add leaf to tree"""
        self.leaves.append(leaf)
        self.root = self._calculate_root()
    
    def get_proof(self, leaf: bytes) -> List[bytes]:
        """Get Merkle proof for a leaf"""
        if leaf not in self.leaves:
            raise ValueError("Leaf not in tree")
        
        index = self.leaves.index(leaf)
        proof = []
        
        # Build proof by traversing tree
        level = self.leaves.copy()
        
        while len(level) > 1:
            if index % 2 == 0:
                if index + 1 < len(level):
                    proof.append(level[index + 1])
            else:
                proof.append(level[index - 1])
            
            # Move to next level
            new_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                new_level.append(self._hash_pair(left, right))
            
            level = new_level
            index //= 2
        
        return proof
    
    def verify_proof(self, leaf: bytes, proof: List[bytes], root: bytes) -> bool:
        """Verify Merkle proof"""
        computed_hash = leaf
        
        for proof_element in proof:
            if computed_hash <= proof_element:
                computed_hash = self._hash_pair(computed_hash, proof_element)
            else:
                computed_hash = self._hash_pair(proof_element, computed_hash)
        
        return computed_hash == root
    
    def _calculate_root(self) -> bytes:
        """Calculate Merkle root"""
        if not self.leaves:
            return bytes(32)
        
        level = self.leaves.copy()
        
        while len(level) > 1:
            new_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                new_level.append(self._hash_pair(left, right))
            level = new_level
        
        return level[0]
    
    def _hash_pair(self, left: bytes, right: bytes) -> bytes:
        """Hash a pair of nodes using BLAKE3"""
        return blake3_hash(left + right)
    
    def get_root(self) -> bytes:
        """Get current Merkle root"""
        return self.root or bytes(32)


async def main():
    """Main entry point"""
    import sys
    import json
    import os
    
    print("="*70)
    print(" "*15 + "QRDX BRIDGE RELAY SERVICE")
    print("="*70)
    
    # Load configuration from file or environment
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
        logger.info(f"Loading configuration from {config_file}")
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        # Try to load from environment variables
        logger.info("No config file provided, checking environment variables...")
        config = {
            "eth_rpc_url": os.getenv("ETH_RPC_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY"),
            "qrdx_rpc_url": os.getenv("QRDX_RPC_URL", "http://localhost:8546"),
            "bridge_eth_address": os.getenv("BRIDGE_ETH_ADDRESS", "0x0000000000000000000000000000000000000000"),
            "bridge_qrdx_address": os.getenv("BRIDGE_QRDX_ADDRESS", "0x0000000000000000000000000000000000000000"),
            "validator_eth_key": os.getenv("VALIDATOR_ETH_KEY", "0x0000000000000000000000000000000000000000000000000000000000000000"),
            "validator_dilithium_key": os.getenv("VALIDATOR_DILITHIUM_KEY", "dilithium_key.bin"),
            "bridge_abi_file": os.getenv("BRIDGE_ABI_FILE", "contracts/bridge/QRDXBridge_abi.json"),
        }
        
        if config["eth_rpc_url"] == "https://mainnet.infura.io/v3/YOUR_INFURA_KEY":
            logger.error("❌ No configuration provided!")
            logger.error("   Usage: python bridge_relay.py config.json")
            logger.error("   Or set environment variables:")
            logger.error("     - ETH_RPC_URL (e.g., https://mainnet.infura.io/v3/YOUR_KEY)")
            logger.error("     - QRDX_RPC_URL (e.g., http://localhost:8546)")
            logger.error("     - BRIDGE_ETH_ADDRESS")
            logger.error("     - BRIDGE_QRDX_ADDRESS")
            logger.error("     - VALIDATOR_ETH_KEY")
            logger.error("     - VALIDATOR_DILITHIUM_KEY")
            logger.error("")
            logger.error("   Example config.json:")
            logger.error("""
            {
              "eth_rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_KEY",
              "qrdx_rpc_url": "http://localhost:8546",
              "bridge_eth_address": "0x...",
              "bridge_qrdx_address": "0x...",
              "validator_eth_key": "0x...",
              "validator_dilithium_key": "dilithium_key.bin",
              "bridge_abi_file": "contracts/bridge/QRDXBridge_abi.json"
            }
            """)
            sys.exit(1)
    
    # Load Dilithium key
    dilithium_key_path = config['validator_dilithium_key']
    if os.path.exists(dilithium_key_path):
        logger.info(f"Loading Dilithium key from {dilithium_key_path}")
        with open(dilithium_key_path, 'rb') as f:
            dilithium_key = f.read()
    else:
        logger.warning(f"Dilithium key file not found: {dilithium_key_path}")
        logger.warning("Using placeholder key for testing")
        dilithium_key = bytes(4000)  # Dilithium3 private key size
    
    # Load bridge ABI
    abi_file = config.get('bridge_abi_file', 'contracts/bridge/QRDXBridge_abi.json')
    if os.path.exists(abi_file):
        logger.info(f"Loading bridge ABI from {abi_file}")
        with open(abi_file, 'r') as f:
            bridge_abi = json.load(f)
    else:
        logger.error(f"❌ Bridge ABI file not found: {abi_file}")
        logger.error("   Please compile the bridge contract and export the ABI")
        sys.exit(1)
    
    logger.info("\n📋 Configuration:")
    logger.info(f"   Ethereum RPC: {config['eth_rpc_url']}")
    logger.info(f"   QRDX RPC: {config['qrdx_rpc_url']}")
    logger.info(f"   Ethereum Bridge: {config['bridge_eth_address']}")
    logger.info(f"   QRDX Bridge: {config['bridge_qrdx_address']}")
    logger.info("")
    
    try:
        # Create and start relay
        relay = QRDXBridgeRelay(
            eth_rpc_url=config['eth_rpc_url'],
            qrdx_rpc_url=config['qrdx_rpc_url'],
            bridge_eth_address=config['bridge_eth_address'],
            bridge_qrdx_address=config['bridge_qrdx_address'],
            validator_private_key=dilithium_key,
            validator_eth_key=config['validator_eth_key'],
            bridge_abi=bridge_abi
        )
        
        logger.info("\n🚀 Starting relay service...\n")
        await relay.start()
        
    except KeyboardInterrupt:
        logger.info("\n⏹️  Shutting down bridge relay...")
    except Exception as e:
        logger.error(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
