#!/usr/bin/env python3
"""
Quick script to send a transaction from a system wallet using the master controller.
"""
import sys
import json
import hashlib
from pathlib import Path
from decimal import Decimal

sys.path.insert(0, str(Path(__file__).parent))

from qrdx.crypto.pq.dilithium import PQPrivateKey

def main():
    if len(sys.argv) < 5:
        print("Usage: python send_system_wallet_tx.py <controller_wallet.json> <from_system_addr> <to_addr> <amount>")
        print("\nExample:")
        print("  python send_system_wallet_tx.py testnet/wallets/master_controller.json \\")
        print("    0x000000000000000000000000000000000000000a \\")
        print("    0x0000000000000000000000000000000000000001 \\")
        print("    100")
        sys.exit(1)
    
    controller_file = sys.argv[1]
    from_address = sys.argv[2]
    to_address = sys.argv[3]
    amount = float(sys.argv[4])
    
    node_url = "http://localhost:3007"
    
    # Load controller wallet
    print(f"Loading controller wallet from {controller_file}...")
    with open(controller_file) as f:
        wallet_data = json.load(f)
    
    controller_address = wallet_data['address']
    private_key_hex = wallet_data['private_key']
    
    print(f"✓ Controller: {controller_address}")
    print(f"✓ From (System Wallet): {from_address}")
    print(f"✓ To: {to_address}")
    print(f"✓ Amount: {amount} QRDX")
    print()
    
    # Create PQ private key
    private_key = PQPrivateKey.from_hex(private_key_hex)
    
    # Fetch UTXOs from database (node RPC doesn't have getUTXOs yet)
    import sqlite3
    db_path = "testnet/databases/node0.db"
    
    print(f"Fetching UTXOs from database...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT tx_hash, tx_index, amount
        FROM utxos
        WHERE address = ?
        ORDER BY amount DESC
    """, (from_address,))
    
    utxo_rows = cursor.fetchall()
    conn.close()
    
    if not utxo_rows:
        print(f"✗ No UTXOs found for {from_address}")
        sys.exit(1)
    
    # Convert to format expected by transaction
    utxos = []
    for tx_hash_bytes, idx, amount in utxo_rows:
        utxos.append({
            "tx_hash": tx_hash_bytes.hex(),
            "index": 0,  # Genesis outputs are always index 0
            "amount": amount
        })
    
    print(f"✓ Found {len(utxos)} UTXOs")
    
    # Build transaction
    amount_smallest = int(Decimal(str(amount)) * Decimal("1000000"))  # microQRDX
    fee_smallest = int(Decimal("0.01") * Decimal("1000000"))  # 0.01 QRDX fee
    total_needed = amount_smallest + fee_smallest
    
    # Select UTXOs (amounts are already in microQRDX from database)
    selected_utxos = []
    total_input = 0
    for utxo in utxos:
        selected_utxos.append(utxo)
        total_input += utxo['amount']  # Already in microQRDX
        if total_input >= total_needed:
            break
    
    if total_input < total_needed:
        available = total_input / 1000000
        needed = total_needed / 1000000
        print(f"✗ Insufficient balance. Have: {available} QRDX, Need: {needed} QRDX")
        sys.exit(1)
    
    # Calculate change
    change = total_input - total_needed
    
    print(f"✓ Selected {len(selected_utxos)} UTXOs, total: {total_input/1000000} QRDX")
    print(f"✓ Change: {change/1000000} QRDX")
    
    # Build transaction data
    tx_data = {
        "inputs": [{"tx_hash": utxo["tx_hash"], "index": utxo["index"]} for utxo in selected_utxos],
        "outputs": [
            {"address": to_address, "amount": amount_smallest}
        ],
        "fee": fee_smallest,
        "system_wallet_source": from_address,
        "controller_address": controller_address,
    }
    
    if change > 0:
        tx_data["outputs"].append({"address": from_address, "amount": change})
    
    # Sign transaction with controller
    print("Signing transaction with controller...")
    tx_bytes = json.dumps(tx_data, sort_keys=True).encode()
    tx_hash = hashlib.sha256(tx_bytes).digest()
    
    signature = private_key.sign(tx_hash)
    tx_data["controller_signature"] = signature.hex()
    
    print("✓ Transaction signed")
    
    # Send transaction
    print("Broadcasting transaction...")
    
    import httpx
    send_response = httpx.post(
        f"{node_url}/rpc",
        json={
            "jsonrpc": "2.0",
            "method": "qrdx_sendTransaction",
            "params": [tx_data],
            "id": 2
        },
        timeout=30.0
    )
    
    if send_response.status_code != 200:
        print(f"✗ Failed to send transaction (HTTP {send_response.status_code})")
        print(send_response.text)
        sys.exit(1)
    
    send_result = send_response.json()
    if "error" in send_result:
        print(f"✗ Transaction failed: {send_result['error'].get('message', 'Unknown error')}")
        sys.exit(1)
    
    tx_hash_result = send_result.get("result", {}).get("tx_hash", "unknown")
    
    print()
    print("=" * 80)
    print("✓ Transaction sent successfully!")
    print(f"TX Hash: {tx_hash_result}")
    print("=" * 80)

if __name__ == "__main__":
    main()
