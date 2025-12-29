#!/usr/bin/env python3
"""Test transaction submission to QRDX testnet."""

from web3 import Web3
from eth_account import Account
import time

# Connect to local node
w3 = Web3(Web3.HTTPProvider('http://localhost:9522'))

print(f"Connected: {w3.is_connected()}")
print(f"Chain ID: {w3.eth.chain_id}")
print(f"Block number: {w3.eth.block_number}")

# Create test accounts
sender = Account.create()
receiver = Account.create()

print(f"\nSender address: {sender.address}")
print(f"Receiver address: {receiver.address}")

# Build transaction
tx = {
    'from': sender.address,
    'to': receiver.address,
    'value': w3.to_wei(0.1, 'ether'),
    'gas': 21000,
    'gasPrice': w3.to_wei(1, 'gwei'),
    'nonce': 0,
    'chainId': w3.eth.chain_id
}

# Sign transaction
signed_tx = sender.sign_transaction(tx)

print(f"\nTransaction hash: {signed_tx.hash.hex()}")
print(f"Raw transaction: {signed_tx.raw_transaction.hex()}")

# Send transaction
try:
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"\n✓ Transaction sent: {tx_hash.hex()}")
    
    # Wait for transaction to be mined
    print("Waiting for transaction to be mined...")
    for i in range(10):
        time.sleep(2)
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            print(f"\n✓ Transaction mined in block {receipt['blockNumber']}")
            print(f"  Status: {'Success' if receipt['status'] == 1 else 'Failed'}")
            print(f"  Gas used: {receipt['gasUsed']}")
            break
        except Exception:
            print(f"  Attempt {i+1}/10: Not mined yet (current block: {w3.eth.block_number})")
    else:
        print("\n✗ Transaction not mined after 20 seconds")
        
except Exception as e:
    print(f"\n✗ Error sending transaction: {e}")
