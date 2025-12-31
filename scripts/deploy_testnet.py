#!/usr/bin/env python3
"""
QRDX Testnet Deployment Script

Deploys a production-ready local testnet with balance-based staking:
- Generates validator keypairs
- Creates genesis file with funded validator addresses
- Starts multi-node testnet with on-chain balance verification

Staking Model: Validators must hold >= 100k QRDX in their address.
No smart contract registration needed.
"""

import argparse
import json
import os
import sys
import subprocess
import time
import shutil
from pathlib import Path
from typing import List, Dict

# Add py-evm to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'py-evm'))

from eth.crypto import generate_keypair, derive_address
from eth_utils import to_checksum_address, to_wei

# Constants
MIN_STAKE = 100_000  # 100k QRDX
CHAIN_ID = 999  # QRDX Chain ID
GENESIS_TIME = int(time.time())
GENESIS_GAS_LIMIT = 30_000_000

# Premine addresses (for testing)
PREMINE_ADDRESSES = [
    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",  # Test account 1 (fixed - added trailing 0)
    "0x123456789abcdef123456789abcdef1234567890",  # Test account 2
]
PREMINE_BALANCE = 1_000_000  # 1M QRDX each


def print_banner(text: str):
    """Print a formatted banner"""
    print("\n" + "="*70)
    print(text)
    print("="*70 + "\n")


def generate_validators(count: int, keystore_dir: Path) -> List[Dict]:
    """
    Generate validator keypairs and save to keystore.
    
    Args:
        count: Number of validators to generate
        keystore_dir: Directory to save keystores
        
    Returns:
        List of validator info dicts
    """
    print_banner(f"Generating {count} Validator Keypairs")
    
    keystore_dir.mkdir(parents=True, exist_ok=True)
    validators = []
    
    for i in range(count):
        print(f"Generating validator {i}...")
        
        # Generate Dilithium keypair
        sk, pk = generate_keypair()
        address = derive_address(pk)
        checksum_addr = to_checksum_address(address)
        
        # Convert keys to bytes then hex
        pk_bytes = pk.to_bytes()
        sk_bytes = sk.to_bytes()
        
        # Create keystore file
        keystore_path = keystore_dir / f"m_3600_{i}_0_0_0-{address.hex()[:8]}"
        keystore_data = {
            "version": 4,
            "crypto": {
                "cipher": "dilithium",
                "pubkey": pk_bytes.hex(),
                "privkey": sk_bytes.hex(),
            },
            "address": address.hex(),
            "path": f"m/3600/{i}/0/0/0",
        }
        
        with open(keystore_path, 'w') as f:
            json.dump(keystore_data, f, indent=2)
        
        print(f"  ✅ Validator {i}: {checksum_addr}")
        print(f"     Keystore: {keystore_path}")
        
        validators.append({
            "index": i,
            "address": checksum_addr,
            "public_key": "0x" + pk_bytes.hex(),
            "keystore_file": str(keystore_path),
        })
    
    print(f"\n✅ Generated {len(validators)} validator keypairs")
    return validators


def create_genesis(
    validators: List[Dict],
    output_file: Path,
) -> Dict:
    """
    Create genesis file with funded validator addresses.
    
    Args:
        validators: List of validator info dicts
        output_file: Path to save genesis.json
        
    Returns:
        Genesis configuration dict
    """
    print_banner("Creating Genesis Configuration")
    
    # Build alloc (account balances)
    alloc = {}
    
    # Fund validators with MIN_STAKE
    for validator in validators:
        address = validator['address'].lower()
        balance_wei = to_wei(MIN_STAKE, 'ether')
        alloc[address] = {
            "balance": hex(balance_wei)
        }
        print(f"  Funding validator {validator['index']} ({validator['address']}): {MIN_STAKE:,} QRDX")
    
    # Add premine accounts for testing
    for addr in PREMINE_ADDRESSES:
        balance_wei = to_wei(PREMINE_BALANCE, 'ether')
        alloc[addr.lower()] = {
            "balance": hex(balance_wei)
        }
        print(f"  Premine account ({addr}): {PREMINE_BALANCE:,} QRDX")
    
    # Build genesis config (EIP1085 compliant - matches working testnet script)
    genesis = {
        "version": "1",
        "params": {
            "chainId": "0x539",  # 1337 decimal
            "miningMethod": "NoProof",
            "frontierForkBlock": "0x0",
            "homesteadForkBlock": "0x0",
            "EIP150ForkBlock": "0x0",
            "EIP158ForkBlock": "0x0",
            "byzantiumForkBlock": "0x0",
            "constantinopleForkBlock": "0x0",
            "petersburgForkBlock": "0x0",
            "istanbulForkBlock": "0x0"
        },
        "genesis": {
            "nonce": "0x0000000000000000",
            "timestamp": hex(GENESIS_TIME),
            "gasLimit": hex(GENESIS_GAS_LIMIT),
            "difficulty": "0x0",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "author": "0x0000000000000000000000000000000000000000",
            "extraData": "0x",
        },
        "accounts": alloc,
        "validators": validators,  # Custom field for QRDX validators
    }
    
    # Save genesis file
    with open(output_file, 'w') as f:
        json.dump(genesis, f, indent=2)
    
    print(f"\n✅ Genesis file created: {output_file}")
    print(f"   Total validators: {len(validators)}")
    print(f"   Total funded addresses: {len(alloc)}")
    print(f"   Genesis time: {GENESIS_TIME}")
    
    return genesis


def start_testnet_node(
    validator_index: int,
    data_dir: Path,
    genesis_file: Path,
    keystore_dir: Path,
    rpc_port: int,
    p2p_port: int,
    enable_validator: bool = True,
    log_file: Path = None,
) -> subprocess.Popen:
    """
    Start a single testnet node.
    
    Args:
        validator_index: Index of this validator
        data_dir: Data directory for node
        genesis_file: Path to genesis.json
        keystore_dir: Path to keystore directory
        rpc_port: RPC port
        p2p_port: P2P port
        enable_validator: Whether to enable block production
        log_file: Optional log file path
        
    Returns:
        Subprocess handle
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Create required subdirectories for Trinity
    (data_dir / "logs-eth1").mkdir(exist_ok=True)
    (data_dir / "mainnet-eth1").mkdir(exist_ok=True)
    (data_dir / "ipcs-eth1").mkdir(exist_ok=True)
    
    # Generate nodekey file (needed for p2p)
    nodekey_file = data_dir / "nodekey"
    if not nodekey_file.exists():
        import secrets
        nodekey_file.write_bytes(secrets.token_bytes(32))
    
    # Build command (matching working start_multi_node_testnet.sh)
    cmd = [
        "trinity",
        "--data-dir", str(data_dir),
        "--network-id", "3600",
        "--port", str(p2p_port),
        "--nodekey", str(nodekey_file),
        "--genesis", str(genesis_file),
        "--sync-mode", "full",
        "--disable-networkdb-component",
        "--enable-http-apis", "eth,net,web3",
        "--http-listen-address", "127.0.0.1",
        "--http-port", str(rpc_port),
    ]
    
    # Set environment variables
    env = os.environ.copy()
    env["QRDX_KEYSTORE_DIR"] = str(keystore_dir)
    env["QRDX_NUM_VALIDATORS"] = str(len([f for f in keystore_dir.glob("*.json")]))
    env["USE_ONCHAIN_VALIDATORS"] = "true"  # Enable balance verification from state
    env["PYTHONPATH"] = "/workspaces/qrdx-chain/lahja:/workspaces/qrdx-chain/async-service:/workspaces/qrdx-chain/asyncio-run-in-process:/workspaces/qrdx-chain:$PYTHONPATH"
    
    # Start process
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        stdout = open(log_file, 'w')
        stderr = subprocess.STDOUT
    else:
        stdout = subprocess.PIPE
        stderr = subprocess.PIPE
    
    print(f"Starting node {validator_index}...")
    print(f"  Data dir: {data_dir}")
    print(f"  RPC port: {rpc_port}")
    print(f"  P2P port: {p2p_port}")
    print(f"  Validator: {'enabled' if enable_validator else 'disabled'}")
    if log_file:
        print(f"  Log file: {log_file}")
    
    process = subprocess.Popen(
        cmd,
        stdout=stdout,
        stderr=stderr,
        env=env,
    )
    
    return process


def deploy_testnet(
    num_validators: int,
    output_dir: Path,
    start_nodes: bool = True,
):
    """
    Deploy a complete testnet.
    
    Args:
        num_validators: Number of validators
        output_dir: Directory for testnet files
        start_nodes: Whether to start nodes after setup
    """
    print_banner(f"QRDX Testnet Deployment - {num_validators} Validators")
    
    # Setup directories
    output_dir.mkdir(parents=True, exist_ok=True)
    keystore_dir = output_dir / "keystores"
    data_dir = output_dir / "nodes"
    logs_dir = output_dir / "logs"
    
    # Generate validators
    validators = generate_validators(num_validators, keystore_dir)
    
    # Create genesis
    genesis_file = output_dir / "genesis.json"
    genesis = create_genesis(validators, genesis_file)
    
    # Write deployment info
    deployment_info = {
        "num_validators": num_validators,
        "genesis_file": str(genesis_file),
        "keystore_dir": str(keystore_dir),
        "data_dir": str(data_dir),
        "chain_id": CHAIN_ID,
        "genesis_time": GENESIS_TIME,
        "validators": validators,
        "rpc_ports": list(range(8545, 8545 + num_validators)),
        "p2p_ports": list(range(30303, 30303 + num_validators)),
    }
    
    info_file = output_dir / "deployment_info.json"
    with open(info_file, 'w') as f:
        json.dump(deployment_info, f, indent=2)
    
    print_banner("Deployment Summary")
    print(f"📁 Output directory: {output_dir}")
    print(f"📝 Genesis file: {genesis_file}")
    print(f"🔑 Keystores: {keystore_dir}")
    print(f"💾 Node data: {data_dir}")
    print(f"📊 Deployment info: {info_file}")
    print(f"\n✅ Testnet configuration complete!")
    
    # Start nodes if requested
    if start_nodes:
        print_banner("Starting Testnet Nodes")
        
        processes = []
        for i in range(num_validators):
            rpc_port = 8545 + i
            p2p_port = 30303 + i
            node_data_dir = data_dir / f"node-{i}"
            log_file = logs_dir / f"node-{i}.log"
            
            process = start_testnet_node(
                validator_index=i,
                data_dir=node_data_dir,
                genesis_file=genesis_file,
                keystore_dir=keystore_dir,
                rpc_port=rpc_port,
                p2p_port=p2p_port,
                enable_validator=True,
                log_file=log_file,
            )
            
            processes.append(process)
            time.sleep(2)  # Stagger starts
        
        print_banner("Testnet Running")
        print(f"✅ Started {len(processes)} nodes")
        print(f"\n💡 RPC Endpoints:")
        for i in range(num_validators):
            print(f"   Node {i}: http://localhost:{8545 + i}")
        
        print(f"\n📋 Logs:")
        for i in range(num_validators):
            print(f"   Node {i}: {logs_dir}/node-{i}.log")
        
        print(f"\n🛑 To stop:")
        print(f"   pkill -f trinity")
        
        print(f"\n🔍 Monitor:")
        print(f"   tail -f {logs_dir}/node-0.log")
        
        # Wait for processes
        try:
            print(f"\n⏳ Nodes running. Press Ctrl+C to stop...")
            for process in processes:
                process.wait()
        except KeyboardInterrupt:
            print(f"\n🛑 Stopping nodes...")
            for process in processes:
                process.terminate()
            for process in processes:
                process.wait()
            print(f"✅ All nodes stopped")


def main():
    parser = argparse.ArgumentParser(
        description="Deploy QRDX testnet with balance-based staking"
    )
    parser.add_argument(
        "--validators",
        type=int,
        default=4,
        help="Number of validators (default: 4)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/qrdx-testnet"),
        help="Output directory (default: /tmp/qrdx-testnet)"
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Don't start nodes after setup"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean output directory before deployment"
    )
    
    args = parser.parse_args()
    
    # Clean if requested
    if args.clean and args.output_dir.exists():
        print(f"🗑️  Cleaning {args.output_dir}...")
        shutil.rmtree(args.output_dir)
    
    # Deploy testnet
    deploy_testnet(
        num_validators=args.validators,
        output_dir=args.output_dir,
        start_nodes=not args.no_start,
    )


if __name__ == "__main__":
    main()
