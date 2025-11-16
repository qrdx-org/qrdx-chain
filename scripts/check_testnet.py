#!/usr/bin/env python3
"""
Testnet Status Checker

Monitor the status of a running QR-PoS testnet.

Usage:
    python3 scripts/check_testnet.py --rpc http://localhost:8545
    python3 scripts/check_testnet.py --rpc http://localhost:8545 --watch
"""

import argparse
import json
import sys
import time
from typing import Dict, Any
from urllib.request import Request, urlopen
from urllib.error import URLError


def rpc_call(url: str, method: str, params: list = None) -> Dict[str, Any]:
    """Make JSON-RPC call"""
    if params is None:
        params = []
    
    request_data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }
    
    req = Request(
        url,
        data=json.dumps(request_data).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode('utf-8'))
            if 'error' in result:
                return {'error': result['error']}
            return result.get('result')
    except URLError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': str(e)}


def check_connection(rpc_url: str) -> bool:
    """Check if RPC is reachable"""
    result = rpc_call(rpc_url, 'net_version')
    return 'error' not in result


def get_chain_info(rpc_url: str) -> Dict[str, Any]:
    """Get basic chain information"""
    info = {}
    
    # Chain ID
    chain_id = rpc_call(rpc_url, 'eth_chainId')
    if 'error' not in chain_id:
        info['chain_id'] = int(chain_id, 16) if isinstance(chain_id, str) else chain_id
    
    # Network version
    net_version = rpc_call(rpc_url, 'net_version')
    if 'error' not in net_version:
        info['network_id'] = net_version
    
    # Block number
    block_number = rpc_call(rpc_url, 'eth_blockNumber')
    if 'error' not in block_number:
        info['block_number'] = int(block_number, 16) if isinstance(block_number, str) else block_number
    
    # Gas price
    gas_price = rpc_call(rpc_url, 'eth_gasPrice')
    if 'error' not in gas_price:
        info['gas_price'] = int(gas_price, 16) if isinstance(gas_price, str) else gas_price
    
    # Peer count
    peer_count = rpc_call(rpc_url, 'net_peerCount')
    if 'error' not in peer_count:
        info['peer_count'] = int(peer_count, 16) if isinstance(peer_count, str) else peer_count
    
    return info


def get_latest_block(rpc_url: str) -> Dict[str, Any]:
    """Get latest block details"""
    return rpc_call(rpc_url, 'eth_getBlockByNumber', ['latest', False])


def format_wei(wei: int) -> str:
    """Format wei to ETH"""
    return f"{wei / 10**18:.6f} ETH"


def format_time(timestamp: int) -> str:
    """Format Unix timestamp"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))


def print_status(rpc_url: str):
    """Print current testnet status"""
    print("="*80)
    print("QR-PoS TESTNET STATUS")
    print("="*80)
    print()
    
    # Check connection
    print("🔌 Connection")
    print(f"  RPC: {rpc_url}")
    
    if not check_connection(rpc_url):
        print("  ❌ Cannot connect to RPC endpoint")
        print()
        return False
    
    print("  ✓ Connected")
    print()
    
    # Chain info
    print("⛓️  Chain Information")
    chain_info = get_chain_info(rpc_url)
    
    if 'chain_id' in chain_info:
        print(f"  Chain ID: {chain_info['chain_id']}")
    if 'network_id' in chain_info:
        print(f"  Network ID: {chain_info['network_id']}")
    if 'block_number' in chain_info:
        print(f"  Block Number: {chain_info['block_number']:,}")
    if 'peer_count' in chain_info:
        print(f"  Peers: {chain_info['peer_count']}")
    if 'gas_price' in chain_info:
        print(f"  Gas Price: {chain_info['gas_price']:,} wei")
    print()
    
    # Latest block
    print("📦 Latest Block")
    latest_block = get_latest_block(rpc_url)
    
    if 'error' not in latest_block and latest_block:
        block_num = latest_block.get('number')
        if block_num:
            print(f"  Number: {int(block_num, 16):,}")
        
        block_hash = latest_block.get('hash')
        if block_hash:
            print(f"  Hash: {block_hash[:18]}...{block_hash[-8:]}")
        
        timestamp = latest_block.get('timestamp')
        if timestamp:
            ts = int(timestamp, 16)
            print(f"  Timestamp: {format_time(ts)}")
            age = int(time.time()) - ts
            print(f"  Age: {age} seconds ago")
        
        tx_count = len(latest_block.get('transactions', []))
        print(f"  Transactions: {tx_count}")
        
        gas_used = latest_block.get('gasUsed')
        gas_limit = latest_block.get('gasLimit')
        if gas_used and gas_limit:
            used = int(gas_used, 16)
            limit = int(gas_limit, 16)
            pct = (used / limit * 100) if limit > 0 else 0
            print(f"  Gas Used: {used:,} / {limit:,} ({pct:.1f}%)")
    else:
        print("  ❌ Could not fetch latest block")
    
    print()
    print("="*80)
    return True


def watch_mode(rpc_url: str, interval: int = 5):
    """Watch mode - continuously update status"""
    try:
        while True:
            # Clear screen
            print("\033[2J\033[H", end="")
            
            # Print status
            if not print_status(rpc_url):
                print("Retrying in 5 seconds...")
                time.sleep(5)
                continue
            
            print(f"Refreshing every {interval} seconds... (Ctrl+C to exit)")
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='Check QR-PoS testnet status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        '--rpc',
        type=str,
        default='http://localhost:8545',
        help='RPC endpoint URL (default: http://localhost:8545)'
    )
    
    parser.add_argument(
        '--watch',
        action='store_true',
        help='Watch mode - continuously update status'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='Update interval in seconds for watch mode (default: 5)'
    )
    
    args = parser.parse_args()
    
    if args.watch:
        watch_mode(args.rpc, args.interval)
    else:
        success = print_status(args.rpc)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
