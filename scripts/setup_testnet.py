#!/usr/bin/env python3
"""
QR-PoS Testnet Setup Script

Creates a complete testnet environment with:
- Genesis configuration with QR-PoS consensus
- Initial validator set with Dilithium keys
- Pre-funded accounts for testing
- Network configuration files
- Validator keystores
- Docker compose for multi-node setup

Usage:
    python3 scripts/setup_testnet.py --validators 4 --output ./testnet
    python3 scripts/setup_testnet.py --validators 8 --chain-id 31337 --output ./devnet
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
import time

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from trinity.crypto.pq.dilithium import DilithiumPrivateKey
from trinity.crypto.pq.addresses import generate_pq_address, encode_pq_address
from trinity.consensus.qrpos.constants import (
    MIN_VALIDATOR_STAKE,
    MAX_EFFECTIVE_BALANCE,
    GENESIS_SLOT,
    GENESIS_EPOCH,
    FAR_FUTURE_EPOCH,
)


class TestnetSetup:
    """Manages testnet setup and configuration"""
    
    def __init__(
        self,
        num_validators: int,
        chain_id: int,
        output_dir: Path,
        initial_balance: int = 1000000,  # ETH
        prefunded_accounts: int = 10,
    ):
        self.num_validators = num_validators
        self.chain_id = chain_id
        self.output_dir = output_dir
        self.initial_balance = initial_balance * 10**18  # Convert to wei
        self.prefunded_accounts = prefunded_accounts
        
        # Create output directory structure
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.genesis_dir = self.output_dir / "genesis"
        self.validators_dir = self.output_dir / "validators"
        self.config_dir = self.output_dir / "config"
        self.keys_dir = self.output_dir / "keys"
        
        for dir_path in [self.genesis_dir, self.validators_dir, self.config_dir, self.keys_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # Storage for generated data
        self.validator_keys: List[Dict[str, Any]] = []
        self.genesis_validators: List[Dict[str, Any]] = []
        self.prefunded_addresses: List[Dict[str, Any]] = []
    
    def generate_validator_keys(self) -> None:
        """Generate Dilithium key pairs for all validators"""
        print(f"\n[1/{7}] Generating {self.num_validators} validator key pairs...")
        
        for i in range(self.num_validators):
            print(f"  Generating validator {i}...", end=" ")
            
            # Generate Dilithium key pair
            privkey = DilithiumPrivateKey.generate()
            pubkey = privkey.public_key()
            pq_address = generate_pq_address(pubkey)
            
            # Store validator info
            validator_data = {
                "index": i,
                "private_key": privkey._key_bytes.hex(),
                "public_key": privkey.public_key_bytes.hex(),
                "pq_address": pq_address.hex(),
                "pq_address_encoded": encode_pq_address(pq_address),
                "stake": MIN_VALIDATOR_STAKE,
                "effective_balance": min(MIN_VALIDATOR_STAKE, MAX_EFFECTIVE_BALANCE),
            }
            
            self.validator_keys.append(validator_data)
            
            # Save individual keystore file
            keystore_file = self.validators_dir / f"validator_{i}.json"
            with open(keystore_file, 'w') as f:
                json.dump({
                    "version": 1,
                    "validator_index": i,
                    "pq_address": validator_data["pq_address_encoded"],
                    "public_key": validator_data["public_key"],
                    "crypto": {
                        "cipher": "plain",  # In production, encrypt with password
                        "ciphertext": validator_data["private_key"],
                    }
                }, f, indent=2)
            
            print(f"✓ {validator_data['pq_address_encoded'][:20]}...")
        
        # Save all validator keys
        all_keys_file = self.keys_dir / "validator_keys.json"
        with open(all_keys_file, 'w') as f:
            json.dump(self.validator_keys, f, indent=2)
        
        print(f"  ✓ Saved {len(self.validator_keys)} validator keystores")
    
    def generate_prefunded_accounts(self) -> None:
        """Generate prefunded PQ accounts for testing"""
        print(f"\n[2/{7}] Generating {self.prefunded_accounts} prefunded test accounts...")
        
        for i in range(self.prefunded_accounts):
            privkey = DilithiumPrivateKey.generate()
            pubkey = privkey.public_key()
            pq_address = generate_pq_address(pubkey)
            
            account_data = {
                "index": i,
                "private_key": privkey._key_bytes.hex(),
                "public_key": privkey.public_key_bytes.hex(),
                "pq_address": pq_address.hex(),
                "pq_address_encoded": encode_pq_address(pq_address),
                "balance": self.initial_balance,
            }
            
            self.prefunded_addresses.append(account_data)
            
            # Save keystore
            keystore_file = self.keys_dir / f"test_account_{i}.json"
            with open(keystore_file, 'w') as f:
                json.dump({
                    "version": 1,
                    "account_index": i,
                    "pq_address": account_data["pq_address_encoded"],
                    "public_key": account_data["public_key"],
                    "crypto": {
                        "cipher": "plain",
                        "ciphertext": account_data["private_key"],
                    }
                }, f, indent=2)
            
            print(f"  Account {i}: {account_data['pq_address_encoded'][:30]}...")
        
        # Save all accounts
        accounts_file = self.keys_dir / "test_accounts.json"
        with open(accounts_file, 'w') as f:
            json.dump(self.prefunded_addresses, f, indent=2)
        
        print(f"  ✓ Saved {len(self.prefunded_addresses)} test accounts")
    
    def create_genesis_validators(self) -> None:
        """Create genesis validator entries"""
        print(f"\n[3/{7}] Creating genesis validator set...")
        
        for validator_data in self.validator_keys:
            genesis_validator = {
                "pq_pubkey": validator_data["public_key"],
                "pq_address": validator_data["pq_address"],
                "stake": str(validator_data["stake"]),
                "effective_balance": str(validator_data["effective_balance"]),
                "activation_eligibility_epoch": GENESIS_EPOCH,
                "activation_epoch": GENESIS_EPOCH,
                "exit_epoch": FAR_FUTURE_EPOCH,
                "withdrawable_epoch": FAR_FUTURE_EPOCH,
                "slashed": False,
                "slashing_epoch": 0,
            }
            
            self.genesis_validators.append(genesis_validator)
        
        print(f"  ✓ Created {len(self.genesis_validators)} genesis validators")
    
    def create_genesis_config(self) -> None:
        """Create genesis.json configuration file"""
        print(f"\n[4/{7}] Creating genesis configuration...")
        
        # Build alloc (initial account balances)
        alloc = {}
        
        # Add validator balances (stake + some extra for gas)
        for validator_data in self.validator_keys:
            pq_addr = validator_data["pq_address"]
            alloc[pq_addr] = {
                "balance": str(validator_data["stake"] + 100 * 10**18),  # stake + 100 ETH
            }
        
        # Add prefunded test accounts
        for account_data in self.prefunded_addresses:
            pq_addr = account_data["pq_address"]
            alloc[pq_addr] = {
                "balance": str(account_data["balance"]),
            }
        
        # Create genesis config
        genesis_config = {
            "config": {
                "chainId": self.chain_id,
                "homesteadBlock": 0,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0,
                "consensus": "qrpos",
                "miningMethod": "QRPoS",
                "qrpos": {
                    "period": 2,  # 2 second slots
                    "epoch": 32,  # 32 slots per epoch
                    "validators": self.genesis_validators,
                }
            },
            "nonce": "0x0",
            "timestamp": hex(int(time.time())),
            "extraData": "0x5152504f5320546573746e6574",  # "QRPoS Testnet" in hex
            "gasLimit": "0x1c9c380",  # 30M gas
            "difficulty": "0x0",  # No PoW difficulty
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "alloc": alloc,
            "number": "0x0",
            "gasUsed": "0x0",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        }
        
        # Save genesis config
        genesis_file = self.genesis_dir / "genesis.json"
        with open(genesis_file, 'w') as f:
            json.dump(genesis_config, f, indent=2)
        
        print(f"  ✓ Genesis config: {genesis_file}")
        print(f"  ✓ Chain ID: {self.chain_id}")
        print(f"  ✓ Initial validators: {len(self.genesis_validators)}")
        print(f"  ✓ Prefunded accounts: {len(alloc)}")
    
    def create_network_config(self) -> None:
        """Create network configuration files"""
        print(f"\n[5/{7}] Creating network configuration...")
        
        # Trinity config
        trinity_config = {
            "network_id": self.chain_id,
            "chain_name": f"QRPoS-Testnet-{self.chain_id}",
            "data_dir": "./data",
            "genesis_config": f"../genesis/genesis.json",
            "port": 30303,
            "rpc_port": 8545,
            "ws_port": 8546,
            "consensus": {
                "type": "qrpos",
                "slot_duration": 2,
                "slots_per_epoch": 32,
                "validator_registry": "../validators",
            },
            "network": {
                "max_peers": 50,
                "listen_address": "0.0.0.0",
                "nat": "any",
            },
            "logging": {
                "level": "INFO",
                "file": "logs/trinity.log",
            }
        }
        
        config_file = self.config_dir / "trinity.json"
        with open(config_file, 'w') as f:
            json.dump(trinity_config, f, indent=2)
        
        print(f"  ✓ Trinity config: {config_file}")
    
    def create_docker_compose(self) -> None:
        """Create docker-compose.yml for multi-node setup"""
        print(f"\n[6/{7}] Creating Docker Compose configuration...")
        
        # Base service configuration
        services = {}
        
        for i in range(self.num_validators):
            validator_data = self.validator_keys[i]
            
            services[f"validator-{i}"] = {
                "image": "qrdx-chain:latest",
                "container_name": f"qrdx-validator-{i}",
                "ports": [
                    f"{30303 + i}:30303",  # P2P
                    f"{8545 + i}:8545",    # RPC
                    f"{8546 + i}:8546",    # WebSocket
                ],
                "volumes": [
                    f"./genesis:/genesis:ro",
                    f"./validators/validator_{i}.json:/validator.json:ro",
                    f"./data/validator-{i}:/data",
                    f"./config:/config:ro",
                ],
                "environment": {
                    "VALIDATOR_INDEX": str(i),
                    "VALIDATOR_KEYSTORE": "/validator.json",
                    "GENESIS_FILE": "/genesis/genesis.json",
                    "DATA_DIR": "/data",
                    "NETWORK_ID": str(self.chain_id),
                    "RPC_ADDR": "0.0.0.0",
                    "RPC_PORT": "8545",
                    "P2P_PORT": "30303",
                },
                "command": [
                    "trinity",
                    "--data-dir=/data",
                    "--genesis=/genesis/genesis.json",
                    f"--network-id={self.chain_id}",
                    "--rpc",
                    "--rpc-addr=0.0.0.0",
                    "--rpc-port=8545",
                    "--ws",
                    "--ws-addr=0.0.0.0",
                    "--ws-port=8546",
                    "--validator=/validator.json",
                ],
                "networks": ["qrdx-testnet"],
            }
            
            # First node is bootnode
            if i == 0:
                services[f"validator-{i}"]["hostname"] = "bootnode"
            else:
                services[f"validator-{i}"]["depends_on"] = ["validator-0"]
                services[f"validator-{i}"]["command"].extend([
                    "--bootnodes=validator-0:30303",
                ])
        
        docker_compose = {
            "version": "3.8",
            "services": services,
            "networks": {
                "qrdx-testnet": {
                    "driver": "bridge",
                }
            },
            "volumes": {
                f"validator-{i}-data": {} for i in range(self.num_validators)
            }
        }
        
        compose_file = self.output_dir / "docker-compose.yml"
        with open(compose_file, 'w') as f:
            # Manual YAML formatting (simpler than adding PyYAML dependency)
            f.write("version: '3.8'\n\n")
            f.write("services:\n")
            for service_name, service_config in services.items():
                f.write(f"  {service_name}:\n")
                for key, value in service_config.items():
                    if isinstance(value, list):
                        f.write(f"    {key}:\n")
                        for item in value:
                            f.write(f"      - {item}\n")
                    elif isinstance(value, dict):
                        f.write(f"    {key}:\n")
                        for k, v in value.items():
                            f.write(f"      {k}: {v}\n")
                    else:
                        f.write(f"    {key}: {value}\n")
            
            f.write("\nnetworks:\n")
            f.write("  qrdx-testnet:\n")
            f.write("    driver: bridge\n")
        
        print(f"  ✓ Docker Compose: {compose_file}")
    
    def create_startup_scripts(self) -> None:
        """Create helper scripts for starting/stopping the testnet"""
        print(f"\n[7/{7}] Creating startup scripts...")
        
        # Start script
        start_script = self.output_dir / "start-testnet.sh"
        with open(start_script, 'w') as f:
            f.write("""#!/bin/bash
set -e

echo "Starting QR-PoS Testnet..."
echo "=========================="
echo ""

# Build Docker image if needed
if [[ "$(docker images -q qrdx-chain:latest 2> /dev/null)" == "" ]]; then
    echo "Building Docker image..."
    docker build -t qrdx-chain:latest ..
fi

# Start all validators
echo "Starting validators..."
docker-compose up -d

echo ""
echo "✓ Testnet started!"
echo ""
echo "Validators:"
""")
            for i in range(self.num_validators):
                f.write(f'echo "  Validator {i}: http://localhost:{8545 + i} (RPC), ws://localhost:{8546 + i} (WS)"\n')
            
            f.write("""
echo ""
echo "View logs: docker-compose logs -f"
echo "Stop testnet: ./stop-testnet.sh"
""")
        
        start_script.chmod(0o755)
        
        # Stop script
        stop_script = self.output_dir / "stop-testnet.sh"
        with open(stop_script, 'w') as f:
            f.write("""#!/bin/bash
set -e

echo "Stopping QR-PoS Testnet..."
docker-compose down

echo "✓ Testnet stopped"
""")
        
        stop_script.chmod(0o755)
        
        # Reset script
        reset_script = self.output_dir / "reset-testnet.sh"
        with open(reset_script, 'w') as f:
            f.write("""#!/bin/bash
set -e

echo "Resetting QR-PoS Testnet..."
echo "WARNING: This will delete all blockchain data!"
read -p "Continue? (y/N) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose down -v
    rm -rf data/
    echo "✓ Testnet reset complete"
    echo "Run ./start-testnet.sh to restart"
fi
""")
        
        reset_script.chmod(0o755)
        
        print(f"  ✓ start-testnet.sh")
        print(f"  ✓ stop-testnet.sh")
        print(f"  ✓ reset-testnet.sh")
    
    def create_readme(self) -> None:
        """Create README with usage instructions"""
        readme_content = f"""# QR-PoS Testnet

Quantum-Resistant Proof-of-Stake testnet with {self.num_validators} validators.

## Network Information

- **Chain ID**: {self.chain_id}
- **Consensus**: QR-PoS (Quantum-Resistant Proof-of-Stake)
- **Validators**: {self.num_validators}
- **Slot Duration**: 2 seconds
- **Slots Per Epoch**: 32
- **Epoch Duration**: 64 seconds

## Validators

"""
        for i, validator in enumerate(self.validator_keys):
            readme_content += f"### Validator {i}\n"
            readme_content += f"- **PQ Address**: `{validator['pq_address_encoded']}`\n"
            readme_content += f"- **Stake**: {validator['stake'] // 10**18} QRDX\n"
            readme_content += f"- **RPC**: http://localhost:{8545 + i}\n"
            readme_content += f"- **WS**: ws://localhost:{8546 + i}\n"
            readme_content += f"- **Keystore**: `validators/validator_{i}.json`\n\n"
        
        readme_content += f"""
## Test Accounts

{self.prefunded_accounts} prefunded accounts with {self.initial_balance // 10**18} ETH each:

"""
        for i, account in enumerate(self.prefunded_addresses[:5]):  # Show first 5
            readme_content += f"- Account {i}: `{account['pq_address_encoded']}`\n"
        
        if len(self.prefunded_addresses) > 5:
            readme_content += f"\n_See `keys/test_accounts.json` for all {len(self.prefunded_addresses)} accounts_\n"
        
        readme_content += """
## Quick Start

### Start the testnet

```bash
./start-testnet.sh
```

### View logs

```bash
docker-compose logs -f
docker-compose logs -f validator-0  # Single validator
```

### Stop the testnet

```bash
./stop-testnet.sh
```

### Reset and start fresh

```bash
./reset-testnet.sh
./start-testnet.sh
```

## Connecting to the Testnet

### Using Web3.py

```python
from web3 import Web3

# Connect to validator 0
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# Check connection
print(f"Connected: {w3.is_connected()}")
print(f"Chain ID: {w3.eth.chain_id}")
print(f"Block number: {w3.eth.block_number}")
```

### Using curl

```bash
# Get latest block
curl -X POST http://localhost:8545 \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Get validator info
curl -X POST http://localhost:8545 \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"eth_getValidatorInfo","params":["0x..."],"id":1}'
```

## Sending Transactions

### Load test account keys

```python
import json
from trinity.crypto.pq.dilithium import DilithiumPrivateKey

# Load a test account
with open('keys/test_account_0.json') as f:
    keystore = json.load(f)

private_key_bytes = bytes.fromhex(keystore['crypto']['ciphertext'])
public_key_bytes = bytes.fromhex(keystore['public_key'])

privkey = DilithiumPrivateKey.from_bytes(private_key_bytes, public_key_bytes)
```

### Send PQ transaction

```python
# Build transaction
tx = {
    'from': keystore['pq_address'],
    'to': recipient_address,
    'value': w3.to_wei(10, 'ether'),
    'gas': 21000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(keystore['pq_address']),
}

# Sign with Dilithium
signed_tx = privkey.sign(encode_transaction(tx))

# Send transaction
tx_hash = w3.eth.send_raw_transaction(signed_tx)
print(f"Transaction hash: {tx_hash.hex()}")
```

## Directory Structure

```
{self.output_dir.name}/
├── genesis/
│   └── genesis.json          # Genesis configuration
├── validators/
│   ├── validator_0.json      # Validator keystores
│   ├── validator_1.json
│   └── ...
├── keys/
│   ├── validator_keys.json   # All validator keys
│   └── test_accounts.json    # All test account keys
├── config/
│   └── trinity.json          # Trinity configuration
├── docker-compose.yml        # Multi-node setup
├── start-testnet.sh          # Start script
├── stop-testnet.sh           # Stop script
├── reset-testnet.sh          # Reset script
└── README.md                 # This file
```

## Security Notice

⚠️ **WARNING**: This testnet uses unencrypted keystores for convenience.
**NEVER** use these keys or this setup for mainnet or with real value!

All private keys are stored in plaintext in the `validators/` and `keys/` directories.

## Monitoring

### Check validator status

```bash
# Check if validator is proposing blocks
docker-compose logs validator-0 | grep "Proposed block"

# Check attestations
docker-compose logs validator-0 | grep "Attestation"

# Check finality
docker-compose logs validator-0 | grep "Finalized"
```

### Network statistics

```bash
# Get validator count
curl -X POST http://localhost:8545 \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"eth_getValidatorCount","params":[],"id":1}'

# Get finalized epoch
curl -X POST http://localhost:8545 \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"eth_getFinalizedEpoch","params":[],"id":1}'
```

## Troubleshooting

### Validators not proposing blocks

- Check validator keystores are mounted correctly
- Verify genesis validators match keystore public keys
- Check logs for slashing or network issues

### Cannot connect to RPC

- Ensure ports are not already in use
- Check firewall settings
- Verify Docker containers are running: `docker-compose ps`

### Finality not progressing

- Ensure at least 2/3 of validators are online
- Check for network partitions
- Verify validator attestations in logs

## Support

For issues or questions:
- GitHub: https://github.com/qrdx-org/qrdx-chain
- Documentation: https://docs.qrdx.org

---

Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
Chain ID: {self.chain_id}
Validators: {self.num_validators}
"""
        
        readme_file = self.output_dir / "README.md"
        with open(readme_file, 'w') as f:
            f.write(readme_content)
        
        print(f"\n  ✓ README.md created")
    
    def run(self) -> None:
        """Execute the full testnet setup"""
        print("="*80)
        print(f"QR-PoS Testnet Setup")
        print("="*80)
        print(f"Output directory: {self.output_dir}")
        print(f"Validators: {self.num_validators}")
        print(f"Chain ID: {self.chain_id}")
        print(f"Prefunded accounts: {self.prefunded_accounts}")
        
        # Execute setup steps
        self.generate_validator_keys()
        self.generate_prefunded_accounts()
        self.create_genesis_validators()
        self.create_genesis_config()
        self.create_network_config()
        self.create_docker_compose()
        self.create_startup_scripts()
        self.create_readme()
        
        # Print summary
        print("\n" + "="*80)
        print("✅ TESTNET SETUP COMPLETE!")
        print("="*80)
        print(f"\nTestnet directory: {self.output_dir}")
        print(f"\nTo start the testnet:")
        print(f"  cd {self.output_dir}")
        print(f"  ./start-testnet.sh")
        print(f"\nValidator endpoints:")
        for i in range(min(3, self.num_validators)):
            print(f"  Validator {i}: http://localhost:{8545 + i}")
        if self.num_validators > 3:
            print(f"  ... and {self.num_validators - 3} more")
        print(f"\nSee {self.output_dir}/README.md for complete documentation")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Setup a QR-PoS testnet with validators at genesis state',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create testnet with 4 validators
  python3 scripts/setup_testnet.py --validators 4 --output ./testnet

  # Create devnet with 8 validators and custom chain ID
  python3 scripts/setup_testnet.py --validators 8 --chain-id 31337 --output ./devnet

  # Create testnet with many prefunded accounts
  python3 scripts/setup_testnet.py --validators 4 --prefunded 100 --output ./testnet
        """
    )
    
    parser.add_argument(
        '--validators',
        type=int,
        default=4,
        help='Number of validators (default: 4)'
    )
    
    parser.add_argument(
        '--chain-id',
        type=int,
        default=1337,
        help='Chain ID for the network (default: 1337)'
    )
    
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('./testnet'),
        help='Output directory for testnet files (default: ./testnet)'
    )
    
    parser.add_argument(
        '--initial-balance',
        type=int,
        default=1000000,
        help='Initial balance for prefunded accounts in ETH (default: 1000000)'
    )
    
    parser.add_argument(
        '--prefunded',
        type=int,
        default=10,
        help='Number of prefunded test accounts (default: 10)'
    )
    
    args = parser.parse_args()
    
    # Validation
    if args.validators < 1:
        print("Error: Need at least 1 validator")
        sys.exit(1)
    
    if args.validators < 4:
        print(f"Warning: {args.validators} validators may not provide sufficient security")
        print("Recommended: at least 4 validators for BFT consensus")
    
    # Create and run setup
    setup = TestnetSetup(
        num_validators=args.validators,
        chain_id=args.chain_id,
        output_dir=args.output,
        initial_balance=args.initial_balance,
        prefunded_accounts=args.prefunded,
    )
    
    setup.run()


if __name__ == '__main__':
    main()
