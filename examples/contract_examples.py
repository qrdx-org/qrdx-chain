"""
Smart Contract Integration Example

Demonstrates how to deploy and interact with smart contracts on QRDX.
"""

import asyncio
from qrdx.contracts import ContractStateManager, EVMExecutor, QRDXVMExecutor
from qrdx.transactions.contract_transaction import ContractDeployment, ContractCall
from qrdx.crypto.contract import encode_function_call


async def example_contract_deployment():
    """Example: Deploy a simple storage contract."""
    
    # Simplified ERC20 token bytecode (example)
    # In production, compile with solc
    bytecode = bytes.fromhex(
        "608060405234801561001057600080fd5b50..."  # Truncated for example
    )
    
    # Create deployment transaction
    deployment = ContractDeployment(
        nonce=0,
        sender='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',  # Example address
        value=0,  # No ETH sent
        gas_limit=1000000,  # 1M gas
        gas_price=1,  # 1 Gwei (in QRDX)
        data=bytecode,
    )
    
    print(f"Deployment transaction hash: {deployment.tx_hash}")
    print(f"Contract will be deployed to: {deployment.compute_contract_address()}")
    
    return deployment


async def example_contract_call():
    """Example: Call a contract function."""
    
    contract_address = '0x5FbDB2315678afecb367f032d93F642f64180aa3'
    
    # Encode function call: balanceOf(address)
    function_data = encode_function_call(
        'balanceOf(address)',
        '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'
    )
    
    # Create call transaction
    call = ContractCall(
        nonce=1,
        sender='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        to=contract_address,
        value=0,
        gas_limit=100000,
        gas_price=1,
        data=function_data,
    )
    
    print(f"Call transaction hash: {call.tx_hash}")
    print(f"Function selector: {call.get_function_signature()}")
    
    return call


async def example_evm_execution(database):
    """Example: Execute contract using EVM."""
    
    # Initialize state manager
    state_manager = ContractStateManager(database)
    
    # Initialize EVM executor
    evm = EVMExecutor(state_manager, block_number=100)
    
    # Deploy contract
    result = await evm.execute_transaction(
        sender='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        to=None,  # None for deployment
        value=0,
        data=bytes.fromhex('608060405234801561001057600080fd5b50...'),
        gas_limit=1000000,
        gas_price=1,
        nonce=0,
    )
    
    if result.success:
        print(f"✅ Contract deployed at: {result.contract_address}")
        print(f"Gas used: {result.gas_used}")
        print(f"Logs emitted: {len(result.logs)}")
    else:
        print(f"❌ Deployment failed: {result.error}")
    
    return result


async def example_qrdx_vm_execution(database):
    """Example: Execute contract using QRDX VM."""
    
    from qrdx.contracts.vm_executor import VMContext
    
    # Initialize state manager
    state_manager = ContractStateManager(database)
    
    # Initialize QRDX VM
    vm = QRDXVMExecutor(state_manager)
    
    # Simple bytecode: PUSH1 42, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    # Returns the number 42
    simple_code = bytes.fromhex('602a60005260206000f3')
    
    # Create execution context
    context = VMContext(
        sender='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        origin='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        address='0x5FbDB2315678afecb367f032d93F642f64180aa3',
        value=0,
        gas_price=1,
        block_number=100,
        timestamp=1234567890,
        coinbase='0x0000000000000000000000000000000000000000',
        gas_limit=100000,
    )
    
    # Execute
    success, output, gas_used, logs = await vm.execute(
        code=simple_code,
        context=context,
    )
    
    if success:
        print(f"✅ Execution successful")
        print(f"Output: 0x{output.hex()}")
        print(f"Gas used: {gas_used}")
        return_value = int.from_bytes(output, 'big')
        print(f"Return value (decimal): {return_value}")
    else:
        print(f"❌ Execution failed")
    
    return success


async def example_rpc_usage():
    """Example: Using Ethereum RPC methods."""
    
    from qrdx.rpc.modules.contracts import EthereumRPCModule
    
    # Initialize RPC module
    rpc = EthereumRPCModule()
    
    # Wait for initialization
    await asyncio.sleep(1)
    
    # Example 1: Deploy contract
    deployment_result = await rpc.eth_sendTransaction({
        'from': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        'data': '0x608060405234801561001057600080fd5b50...',
        'gas': '0xF4240',  # 1M gas
        'gasPrice': '0x3B9ACA00',  # 1 Gwei
    })
    
    print(f"Deployment TX: {deployment_result}")
    
    # Example 2: Get transaction receipt
    receipt = await rpc.eth_getTransactionReceipt(deployment_result)
    print(f"Contract deployed at: {receipt['contractAddress']}")
    
    # Example 3: Call contract (read-only)
    balance = await rpc.eth_call({
        'to': receipt['contractAddress'],
        'data': '0x70a08231000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f0beb',  # balanceOf
    })
    print(f"Balance: {balance}")
    
    # Example 4: Get contract code
    code = await rpc.eth_getCode(receipt['contractAddress'])
    print(f"Code length: {len(code)} bytes")
    
    # Example 5: Get logs
    logs = await rpc.eth_getLogs({
        'fromBlock': '0x0',
        'toBlock': 'latest',
        'address': receipt['contractAddress'],
    })
    print(f"Total logs: {len(logs)}")
    
    return receipt


async def main():
    """Run all examples."""
    
    print("=" * 70)
    print("QRDX Smart Contract Examples")
    print("=" * 70)
    print()
    
    # Example 1: Transaction creation
    print("1. Creating deployment transaction...")
    deployment = await example_contract_deployment()
    print()
    
    # Example 2: Contract call
    print("2. Creating contract call...")
    call = await example_contract_call()
    print()
    
    # Example 3: EVM execution (requires database)
    # print("3. Executing with EVM...")
    # await example_evm_execution(database)
    # print()
    
    # Example 4: QRDX VM execution (requires database)
    # print("4. Executing with QRDX VM...")
    # await example_qrdx_vm_execution(database)
    # print()
    
    # Example 5: RPC usage (requires full node)
    # print("5. Using RPC methods...")
    # await example_rpc_usage()
    # print()
    
    print("=" * 70)
    print("Examples complete!")
    print("=" * 70)


if __name__ == '__main__':
    asyncio.run(main())
