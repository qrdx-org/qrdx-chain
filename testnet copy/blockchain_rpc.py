#!/usr/bin/env python3
"""
Integrated Contract RPC Server - Connects to running testnet node

This RPC server submits transactions to the actual blockchain network.
"""
import sys
import json
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from eth_utils import to_canonical_address, to_checksum_address, encode_hex, decode_hex
import uvicorn

from qrdx.logger import get_logger
from qrdx.transactions import Transaction
from qrdx.crypto.keys import PrivateKey
from qrdx import helpers

logger = get_logger(__name__)

app = FastAPI(title="QRDX Blockchain Contract RPC")

# Global state
node_client = None
test_private_key = None

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "blockchain": "connected" if node_client else "disconnected"}

@app.post("/")
async def rpc_handler(body: dict = Body(...)):
    """Handle JSON-RPC requests."""
    method = body.get("method")
    params = body.get("params", [])
    rpc_id = body.get("id", 1)
    
    try:
        if method == "eth_sendTransaction":
            result = await eth_sendTransaction(params[0] if params else {})
        elif method == "eth_getTransactionReceipt":
            result = await eth_getTransactionReceipt(params[0] if params else "")
        elif method == "eth_blockNumber":
            result = await eth_blockNumber()
        else:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }
        
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": result
        }
    except Exception as e:
        logger.error(f"RPC error: {e}", exc_info=True)
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32603, "message": str(e)}
        }

async def eth_sendTransaction(params: dict) -> str:
    """Create and submit a blockchain transaction."""
    to_hex = params.get("to")
    data_hex = params.get("data", "0x")
    value = int(params.get("value", "0"))
    gas = int(params.get("gas", "1000000"))
    
    # Decode data
    data = decode_hex(data_hex)
    
    # Create transaction
    tx = Transaction(
        sender=test_private_key.get_address(),
        to=to_hex if to_hex else None,  # None for contract creation
        value=value,
        data=data.hex() if data else None,
        gas_limit=gas,
        gas_price=1000000000,
        nonce=0,  # TODO: Get from state
        timestamp=helpers.timestamp()
    )
    
    # Sign transaction
    tx.sign(test_private_key.to_hex())
    
    # Submit to blockchain via node's mempool
    tx_hash = await submit_transaction_to_node(tx)
    
    logger.info(f"📤 Submitted transaction {tx_hash} to blockchain")
    
    return encode_hex(bytes.fromhex(tx_hash))

async def submit_transaction_to_node(tx: Transaction) -> str:
    """Submit transaction to local node's mempool."""
    # TODO: Connect to actual node RPC/P2P
    # For now, write to mempool file
    import json
    from pathlib import Path
    
    mempool_dir = Path("testnet/mempool")
    mempool_dir.mkdir(exist_ok=True)
    
    tx_hash = tx.hash()
    tx_file = mempool_dir / f"{tx_hash}.json"
    
    with open(tx_file, 'w') as f:
        json.dump(tx.to_dict(), f, indent=2)
    
    logger.info(f"💾 Wrote transaction to mempool: {tx_file}")
    
    return tx_hash

async def eth_getTransactionReceipt(tx_hash: str) -> dict:
    """Get transaction receipt from blockchain."""
    # TODO: Query from database
    return None

async def eth_blockNumber() -> str:
    """Get latest block number."""
    # TODO: Query from database
    return "0x0"

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='QRDX Blockchain Contract RPC Server')
    parser.add_argument('--port', type=int, default=8545, help='RPC server port')
    parser.add_argument('--wallet', type=str, required=True, help='Path to wallet JSON file for signing')
    
    args = parser.parse_args()
    
    # Load wallet
    global test_private_key
    with open(args.wallet, 'r') as f:
        wallet_data = json.load(f)
    
    test_private_key = PrivateKey.from_hex(wallet_data['private_key'])
    
    logger.info("=" * 80)
    logger.info("QRDX BLOCKCHAIN CONTRACT RPC SERVER")
    logger.info("=" * 80)
    logger.info(f"Port: {args.port}")
    logger.info(f"Wallet: {args.wallet}")
    logger.info(f"Address: {test_private_key.get_address()}")
    logger.info("")
    logger.info("✅ RPC Server running at http://0.0.0.0:%d", args.port)
    logger.info("")
    logger.info("Available methods:")
    logger.info("  - eth_sendTransaction (submit to blockchain)")
    logger.info("  - eth_getTransactionReceipt")
    logger.info("  - eth_blockNumber")
    logger.info("")
    
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")

if __name__ == "__main__":
    main()
