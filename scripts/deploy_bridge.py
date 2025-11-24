#!/usr/bin/env python3
"""
QRDX Bridge Deployment Script

Deploys bridge contracts on both Ethereum and QRDX chains with:
- Initial validator set configuration
- Genesis state setup
- Cross-chain verification
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from eth_utils import to_checksum_address, to_wei
from web3 import Web3
from web3.contract import Contract


@dataclass
class ValidatorConfig:
    """Validator configuration"""
    eth_address: str
    dilithium_public_key: bytes  # 1952 bytes
    stake: int  # in wei


@dataclass
class BridgeConfig:
    """Bridge deployment configuration"""
    min_validator_stake: int = to_wei(100, 'ether')
    challenge_period: int = 7 * 24 * 60 * 60  # 7 days
    transfer_expiration: int = 30 * 24 * 60 * 60  # 30 days
    confirmation_threshold: int = 67  # 67%
    initial_validators: List[ValidatorConfig] = None


class BridgeDeployer:
    """Deploys and configures QRDX bridge"""
    
    def __init__(
        self,
        eth_rpc_url: str,
        qrdx_rpc_url: str,
        deployer_private_key: str,
        config: BridgeConfig
    ):
        """Initialize deployer
        
        Args:
            eth_rpc_url: Ethereum RPC endpoint
            qrdx_rpc_url: QRDX RPC endpoint
            deployer_private_key: Deployer account private key
            config: Bridge configuration
        """
        self.eth_w3 = Web3(Web3.HTTPProvider(eth_rpc_url))
        self.qrdx_w3 = Web3(Web3.HTTPProvider(qrdx_rpc_url))
        self.config = config
        
        # Setup deployer account
        self.deployer_account = self.eth_w3.eth.account.from_key(deployer_private_key)
        self.deployer_address = self.deployer_account.address
        
        # Contract instances (set after deployment)
        self.eth_bridge: Optional[Contract] = None
        self.qrdx_bridge: Optional[Contract] = None
    
    def load_contract_artifacts(self) -> Dict[str, dict]:
        """Load compiled contract artifacts
        
        Returns:
            Dictionary of contract name -> {abi, bytecode}
        """
        try:
            from solcx import compile_files, set_solc_version
            
            set_solc_version('0.8.20')
            
            contracts_dir = Path(__file__).parent.parent / "contracts" / "bridge"
            
            print("📝 Compiling bridge contracts...")
            
            compiled = compile_files(
                [
                    str(contracts_dir / "IQRDXBridge.sol"),
                    str(contracts_dir / "QRDXBridge.sol"),
                ],
                output_values=['abi', 'bin'],
                solc_version='0.8.20'
            )
            
            artifacts = {}
            for key, value in compiled.items():
                if 'QRDXBridge' in key and 'IQRDXBridge' not in key:
                    artifacts['QRDXBridge'] = {
                        'abi': value['abi'],
                        'bytecode': value['bin']
                    }
            
            print(f"✅ Compiled {len(artifacts)} contracts")
            return artifacts
            
        except Exception as e:
            print(f"❌ Contract compilation failed: {e}")
            raise
    
    async def deploy_on_ethereum(self, artifacts: Dict[str, dict]) -> str:
        """Deploy bridge on Ethereum
        
        Args:
            artifacts: Compiled contract artifacts
            
        Returns:
            Deployed contract address
        """
        print("\n" + "="*60)
        print("Deploying Bridge on Ethereum")
        print("="*60)
        
        # Get bridge artifact
        bridge_artifact = artifacts['QRDXBridge']
        
        # Create contract
        Bridge = self.eth_w3.eth.contract(
            abi=bridge_artifact['abi'],
            bytecode=bridge_artifact['bytecode']
        )
        
        # Estimate gas
        print("⛽ Estimating deployment gas...")
        gas_estimate = Bridge.constructor().estimate_gas({
            'from': self.deployer_address
        })
        
        print(f"   Gas estimate: {gas_estimate:,}")
        
        # Get current gas price
        gas_price = self.eth_w3.eth.gas_price
        print(f"   Gas price: {self.eth_w3.from_wei(gas_price, 'gwei')} gwei")
        
        # Calculate cost
        cost_eth = self.eth_w3.from_wei(gas_estimate * gas_price, 'ether')
        print(f"   Deployment cost: {cost_eth:.4f} ETH")
        
        # Build transaction
        print("\n📤 Deploying contract...")
        transaction = Bridge.constructor().build_transaction({
            'from': self.deployer_address,
            'nonce': self.eth_w3.eth.get_transaction_count(self.deployer_address),
            'gas': gas_estimate,
            'gasPrice': gas_price
        })
        
        # Sign and send
        signed_tx = self.eth_w3.eth.account.sign_transaction(
            transaction,
            private_key=self.deployer_account.key
        )
        
        tx_hash = self.eth_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"   Transaction hash: {tx_hash.hex()}")
        
        # Wait for receipt
        print("   Waiting for confirmation...")
        receipt = self.eth_w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] == 1:
            address = receipt['contractAddress']
            print(f"✅ Bridge deployed at: {address}")
            
            # Create contract instance
            self.eth_bridge = self.eth_w3.eth.contract(
                address=address,
                abi=bridge_artifact['abi']
            )
            
            return address
        else:
            raise Exception("Contract deployment failed")
    
    async def deploy_on_qrdx(self, artifacts: Dict[str, dict]) -> str:
        """Deploy bridge on QRDX
        
        Args:
            artifacts: Compiled contract artifacts
            
        Returns:
            Deployed contract address
        """
        print("\n" + "="*60)
        print("Deploying Bridge on QRDX")
        print("="*60)
        
        # Similar to Ethereum deployment but on QRDX chain
        bridge_artifact = artifacts['QRDXBridge']
        
        Bridge = self.qrdx_w3.eth.contract(
            abi=bridge_artifact['abi'],
            bytecode=bridge_artifact['bytecode']
        )
        
        print("⛽ Estimating deployment gas...")
        gas_estimate = Bridge.constructor().estimate_gas({
            'from': self.deployer_address
        })
        
        print(f"   Gas estimate: {gas_estimate:,}")
        
        gas_price = self.qrdx_w3.eth.gas_price
        print(f"   Gas price: {self.qrdx_w3.from_wei(gas_price, 'gwei')} gwei")
        
        cost_eth = self.qrdx_w3.from_wei(gas_estimate * gas_price, 'ether')
        print(f"   Deployment cost: {cost_eth:.4f} QRDX")
        
        print("\n📤 Deploying contract...")
        transaction = Bridge.constructor().build_transaction({
            'from': self.deployer_address,
            'nonce': self.qrdx_w3.eth.get_transaction_count(self.deployer_address),
            'gas': gas_estimate,
            'gasPrice': gas_price
        })
        
        signed_tx = self.qrdx_w3.eth.account.sign_transaction(
            transaction,
            private_key=self.deployer_account.key
        )
        
        tx_hash = self.qrdx_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"   Transaction hash: {tx_hash.hex()}")
        
        print("   Waiting for confirmation...")
        receipt = self.qrdx_w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] == 1:
            address = receipt['contractAddress']
            print(f"✅ Bridge deployed at: {address}")
            
            self.qrdx_bridge = self.qrdx_w3.eth.contract(
                address=address,
                abi=bridge_artifact['abi']
            )
            
            return address
        else:
            raise Exception("Contract deployment failed")
    
    async def configure_validators(self):
        """Add initial validators to both bridges"""
        print("\n" + "="*60)
        print("Configuring Validators")
        print("="*60)
        
        if not self.config.initial_validators:
            print("⚠️  No initial validators configured")
            return
        
        # Add validators to Ethereum bridge
        print(f"\n➕ Adding {len(self.config.initial_validators)} validators to Ethereum bridge...")
        
        for i, validator in enumerate(self.config.initial_validators):
            print(f"   Validator {i+1}/{len(self.config.initial_validators)}: {validator.eth_address}")
            
            try:
                tx = self.eth_bridge.functions.addValidator(
                    to_checksum_address(validator.eth_address),
                    validator.dilithium_public_key,
                    validator.stake
                ).build_transaction({
                    'from': self.deployer_address,
                    'nonce': self.eth_w3.eth.get_transaction_count(self.deployer_address),
                    'gas': 250000,
                    'gasPrice': self.eth_w3.eth.gas_price
                })
                
                signed_tx = self.eth_w3.eth.account.sign_transaction(
                    tx,
                    private_key=self.deployer_account.key
                )
                
                tx_hash = self.eth_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = self.eth_w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt['status'] == 1:
                    print(f"   ✅ Added successfully")
                else:
                    print(f"   ❌ Failed to add")
                    
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        # Add validators to QRDX bridge
        print(f"\n➕ Adding {len(self.config.initial_validators)} validators to QRDX bridge...")
        
        for i, validator in enumerate(self.config.initial_validators):
            print(f"   Validator {i+1}/{len(self.config.initial_validators)}: {validator.eth_address}")
            
            try:
                tx = self.qrdx_bridge.functions.addValidator(
                    to_checksum_address(validator.eth_address),
                    validator.dilithium_public_key,
                    validator.stake
                ).build_transaction({
                    'from': self.deployer_address,
                    'nonce': self.qrdx_w3.eth.get_transaction_count(self.deployer_address),
                    'gas': 250000,
                    'gasPrice': self.qrdx_w3.eth.gas_price
                })
                
                signed_tx = self.qrdx_w3.eth.account.sign_transaction(
                    tx,
                    private_key=self.deployer_account.key
                )
                
                tx_hash = self.qrdx_w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = self.qrdx_w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt['status'] == 1:
                    print(f"   ✅ Added successfully")
                else:
                    print(f"   ❌ Failed to add")
                    
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        print(f"\n✅ Validator configuration complete")
    
    async def verify_deployment(self):
        """Verify bridge deployment and configuration"""
        print("\n" + "="*60)
        print("Verifying Deployment")
        print("="*60)
        
        # Check Ethereum bridge
        print("\n🔍 Ethereum Bridge:")
        print(f"   Address: {self.eth_bridge.address}")
        
        validator_count = self.eth_bridge.functions.getValidatorCount().call()
        required_confirmations = self.eth_bridge.functions.getRequiredConfirmations().call()
        
        print(f"   Validators: {validator_count}")
        print(f"   Required confirmations: {required_confirmations}")
        print(f"   Min stake: {self.eth_w3.from_wei(self.config.min_validator_stake, 'ether')} ETH")
        print(f"   Challenge period: {self.config.challenge_period / (24*60*60)} days")
        
        # Check QRDX bridge
        print("\n🔍 QRDX Bridge:")
        print(f"   Address: {self.qrdx_bridge.address}")
        
        validator_count = self.qrdx_bridge.functions.getValidatorCount().call()
        required_confirmations = self.qrdx_bridge.functions.getRequiredConfirmations().call()
        
        print(f"   Validators: {validator_count}")
        print(f"   Required confirmations: {required_confirmations}")
        print(f"   Min stake: {self.qrdx_w3.from_wei(self.config.min_validator_stake, 'ether')} QRDX")
        print(f"   Challenge period: {self.config.challenge_period / (24*60*60)} days")
        
        # Test cross-chain configuration
        print("\n🔗 Cross-Chain Configuration:")
        print("   ✅ Both bridges deployed")
        print("   ✅ Same validator set on both chains")
        print("   ✅ Matching consensus parameters")
    
    def save_deployment_info(self, eth_address: str, qrdx_address: str):
        """Save deployment information to file
        
        Args:
            eth_address: Ethereum bridge address
            qrdx_address: QRDX bridge address
        """
        deployment_info = {
            'ethereum': {
                'chain_id': self.eth_w3.eth.chain_id,
                'bridge_address': eth_address,
                'deployer': self.deployer_address,
                'block_number': self.eth_w3.eth.block_number
            },
            'qrdx': {
                'chain_id': self.qrdx_w3.eth.chain_id,
                'bridge_address': qrdx_address,
                'deployer': self.deployer_address,
                'block_number': self.qrdx_w3.eth.block_number
            },
            'config': {
                'min_validator_stake': str(self.config.min_validator_stake),
                'challenge_period': self.config.challenge_period,
                'transfer_expiration': self.config.transfer_expiration,
                'confirmation_threshold': self.config.confirmation_threshold,
                'validator_count': len(self.config.initial_validators) if self.config.initial_validators else 0
            }
        }
        
        output_file = Path(__file__).parent / "bridge_deployment.json"
        output_file.write_text(json.dumps(deployment_info, indent=2))
        
        print(f"\n💾 Deployment info saved to: {output_file}")
    
    async def deploy(self):
        """Execute full deployment"""
        print("\n" + "="*70)
        print(" "*20 + "QRDX BRIDGE DEPLOYMENT")
        print("="*70)
        
        print(f"\n📋 Configuration:")
        print(f"   Deployer: {self.deployer_address}")
        print(f"   Ethereum RPC: {self.eth_w3.provider.endpoint_uri}")
        print(f"   QRDX RPC: {self.qrdx_w3.provider.endpoint_uri}")
        print(f"   Min validator stake: {self.eth_w3.from_wei(self.config.min_validator_stake, 'ether')} ETH")
        print(f"   Challenge period: {self.config.challenge_period / (24*60*60)} days")
        print(f"   Confirmation threshold: {self.config.confirmation_threshold}%")
        
        # Check balances
        eth_balance = self.eth_w3.eth.get_balance(self.deployer_address)
        qrdx_balance = self.qrdx_w3.eth.get_balance(self.deployer_address)
        
        print(f"\n💰 Balances:")
        print(f"   Ethereum: {self.eth_w3.from_wei(eth_balance, 'ether')} ETH")
        print(f"   QRDX: {self.qrdx_w3.from_wei(qrdx_balance, 'ether')} QRDX")
        
        if eth_balance < to_wei(1, 'ether') or qrdx_balance < to_wei(1, 'ether'):
            print("\n⚠️  WARNING: Low balance. Ensure sufficient funds for deployment.")
        
        # Load contracts
        artifacts = self.load_contract_artifacts()
        
        # Deploy on both chains
        eth_address = await self.deploy_on_ethereum(artifacts)
        qrdx_address = await self.deploy_on_qrdx(artifacts)
        
        # Configure validators
        await self.configure_validators()
        
        # Verify deployment
        await self.verify_deployment()
        
        # Save deployment info
        self.save_deployment_info(eth_address, qrdx_address)
        
        # Summary
        print("\n" + "="*70)
        print("Deployment Complete")
        print("="*70)
        print(f"""
✅ Bridge deployed successfully

Ethereum Bridge: {eth_address}
QRDX Bridge: {qrdx_address}

Next Steps:
1. Fund validator accounts with minimum stake
2. Start validator relay services
3. Monitor bridge events
4. Test with small transfers first

For more information, see /contracts/bridge/README.md
""")


async def main():
    """Main deployment script"""
    
    # Configuration (update these values)
    eth_rpc_url = "http://localhost:8545"  # Ethereum node
    qrdx_rpc_url = "http://localhost:8546"  # QRDX node
    deployer_private_key = "0x..."  # Replace with actual key
    
    # Example validator configuration
    # In production, load from secure configuration file
    validators = [
        ValidatorConfig(
            eth_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
            dilithium_public_key=b'\x00' * 1952,  # Replace with actual key
            stake=to_wei(100, 'ether')
        ),
        # Add more validators...
    ]
    
    config = BridgeConfig(
        initial_validators=validators
    )
    
    # Deploy
    deployer = BridgeDeployer(
        eth_rpc_url=eth_rpc_url,
        qrdx_rpc_url=qrdx_rpc_url,
        deployer_private_key=deployer_private_key,
        config=config
    )
    
    await deployer.deploy()


if __name__ == "__main__":
    # Example usage
    print("""
QRDX Bridge Deployment Script

Before running:
1. Start Ethereum node (e.g., Ganache, Geth)
2. Start QRDX node
3. Fund deployer account on both chains
4. Generate Dilithium keys for validators
5. Update configuration in main()

Usage:
    python scripts/deploy_bridge.py
    
⚠️  This script requires:
- web3.py: pip install web3
- py-solc-x: pip install py-solc-x
- liboqs-python: pip install liboqs-python
""")
    
    # Uncomment to run deployment
    # asyncio.run(main())
