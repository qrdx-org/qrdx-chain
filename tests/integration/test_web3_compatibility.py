#!/usr/bin/env python3
"""
Web3.py Integration Test for QRDX Chain JSON-RPC

Tests web3.py library compatibility with Trinity JSON-RPC endpoint.
Tests both basic queries and more complex operations.

Usage:
    python3 test_web3_compatibility.py <rpc_url>
    
Example:
    python3 test_web3_compatibility.py http://localhost:9658
"""

import sys
from web3 import Web3, HTTPProvider
# from web3.exceptions import Web3ValidationError
import traceback

def test_connection(w3: Web3) -> bool:
    """Test basic connection"""
    try:
        connected = w3.is_connected()
        print(f"✓ Connection test: {'Connected' if connected else 'Failed'}")
        return connected
    except Exception as e:
        print(f"✗ Connection test failed: {e}")
        return False

def test_client_version(w3: Web3) -> bool:
    """Test client version RPC method"""
    try:
        version = w3.client_version
        print(f"✓ Client version: {version}")
        return True
    except Exception as e:
        print(f"✗ Client version failed: {e}")
        return False

def test_chain_id(w3: Web3) -> bool:
    """Test chain ID retrieval"""
    try:
        chain_id = w3.eth.chain_id
        print(f"✓ Chain ID: {chain_id}")
        return True
    except Exception as e:
        print(f"✗ Chain ID failed: {e}")
        return False

def test_block_number(w3: Web3) -> bool:
    """Test block number retrieval"""
    try:
        block_num = w3.eth.block_number
        print(f"✓ Block number: {block_num}")
        return True
    except Exception as e:
        print(f"✗ Block number failed: {e}")
        return False

def test_net_version(w3: Web3) -> bool:
    """Test net version RPC method"""
    try:
        net_ver = w3.net.version
        print(f"✓ Net version: {net_ver}")
        return True
    except Exception as e:
        print(f"✗ Net version failed: {e}")
        traceback.print_exc()
        return False

def test_peer_count(w3: Web3) -> bool:
    """Test peer count retrieval"""
    try:
        peers = w3.net.peer_count
        print(f"✓ Peer count: {peers}")
        return True
    except Exception as e:
        print(f"✗ Peer count failed: {e}")
        traceback.print_exc()
        return False

def test_syncing_status(w3: Web3) -> bool:
    """Test syncing status"""
    try:
        syncing = w3.eth.syncing
        if syncing is False:
            print(f"✓ Syncing: Node is synced")
        else:
            print(f"✓ Syncing: {syncing}")
        return True
    except Exception as e:
        print(f"✗ Syncing status failed: {e}")
        traceback.print_exc()
        return False

def test_genesis_block(w3: Web3) -> bool:
    """Test genesis block retrieval"""
    try:
        genesis = w3.eth.get_block(0)
        print(f"✓ Genesis block:")
        print(f"  - Hash: {genesis['hash'].hex()}")
        print(f"  - Timestamp: {genesis['timestamp']}")
        print(f"  - Difficulty: {genesis['difficulty']}")
        print(f"  - Gas Limit: {genesis['gasLimit']}")
        return True
    except Exception as e:
        print(f"✗ Genesis block failed: {e}")
        traceback.print_exc()
        return False

def test_latest_block(w3: Web3) -> bool:
    """Test latest block retrieval"""
    try:
        latest = w3.eth.get_block('latest')
        print(f"✓ Latest block:")
        print(f"  - Number: {latest['number']}")
        print(f"  - Hash: {latest['hash'].hex()}")
        print(f"  - Transactions: {len(latest['transactions'])}")
        return True
    except Exception as e:
        print(f"✗ Latest block failed: {e}")
        return False

def test_account_balance(w3: Web3) -> bool:
    """Test account balance query"""
    try:
        # Test with a random address
        addr = "0x" + "00" * 20
        balance = w3.eth.get_balance(addr)
        print(f"✓ Account balance: {balance} wei for {addr}")
        return True
    except Exception as e:
        print(f"✗ Account balance failed: {e}")
        traceback.print_exc()
        return False

def test_transaction_count(w3: Web3) -> bool:
    """Test transaction count (nonce) query"""
    try:
        addr = "0x" + "00" * 20
        nonce = w3.eth.get_transaction_count(addr)
        print(f"✓ Transaction count: {nonce} for {addr}")
        return True
    except Exception as e:
        print(f"✗ Transaction count failed: {e}")
        traceback.print_exc()
        return False

def test_gas_price(w3: Web3) -> bool:
    """Test gas price retrieval"""
    try:
        gas_price = w3.eth.gas_price
        print(f"✓ Gas price: {gas_price} wei")
        return True
    except Exception as e:
        print(f"✗ Gas price failed: {e}")
        return False

def test_eth_call(w3: Web3) -> bool:
    """Test eth_call for contract interaction simulation"""
    try:
        # Simple call to a non-existent contract (should return empty)
        result = w3.eth.call({
            'to': '0x' + '00' * 20,
            'data': '0x'
        })
        print(f"✓ eth_call: {result.hex()}")
        return True
    except Exception as e:
        print(f"✗ eth_call failed: {e}")
        traceback.print_exc()
        return False

def test_estimate_gas(w3: Web3) -> bool:
    """Test gas estimation"""
    try:
        estimate = w3.eth.estimate_gas({
            'to': '0x' + '00' * 20,
            'value': 0,
            'data': '0x'
        })
        print(f"✓ Gas estimate: {estimate}")
        return True
    except Exception as e:
        print(f"✗ Gas estimate failed: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test_web3_compatibility.py <rpc_url>")
        print("Example: python3 test_web3_compatibility.py http://localhost:9658")
        sys.exit(1)
    
    rpc_url = sys.argv[1]
    print(f"Testing Web3.py compatibility with {rpc_url}\n")
    print("=" * 70)
    
    # Connect to node
    w3 = Web3(HTTPProvider(rpc_url, request_kwargs={'timeout': 10}))
    
    # Run all tests
    tests = [
        test_connection,
        test_client_version,
        test_chain_id,
        test_block_number,
        test_net_version,
        test_peer_count,
        test_syncing_status,
        test_genesis_block,
        test_latest_block,
        test_account_balance,
        test_transaction_count,
        test_gas_price,
        test_eth_call,
        test_estimate_gas,
    ]
    
    results = []
    for test in tests:
        print()
        result = test(w3)
        results.append(result)
    
    # Summary
    print("\n" + "=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"\nTest Results: {passed}/{total} passed")
    
    if passed == total:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print(f"✗ {total - passed} tests failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
