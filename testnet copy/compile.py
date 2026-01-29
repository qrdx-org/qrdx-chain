#!/usr/bin/env python3
"""Compile Solidity contract."""
from solcx import compile_source, install_solc
import json

# Install specific solc version
print("Installing solc 0.8.24...")
install_solc('0.8.24')

# Read contract
with open('testnet/SimpleStorage.sol', 'r') as f:
    source = f.read()

# Compile
print("Compiling SimpleStorage.sol...")
compiled = compile_source(
    source,
    output_values=['abi', 'bin', 'bin-runtime'],
    solc_version='0.8.24'
)

# Get contract interface
contract_id = list(compiled.keys())[0]
contract_interface = compiled[contract_id]

# Save bytecode
bytecode = contract_interface['bin']
runtime_bytecode = contract_interface['bin-runtime']
abi = contract_interface['abi']

print(f"✅ Compiled successfully!")
print(f"   Bytecode: {len(bytecode) // 2} bytes")
print(f"   Runtime: {len(runtime_bytecode) // 2} bytes")
print()
print(f"Deployment bytecode: {bytecode}")
print()
print("ABI:")
print(json.dumps(abi, indent=2))

# Save to files
with open('testnet/SimpleStorage.bin', 'w') as f:
    f.write(bytecode)
    
with open('testnet/SimpleStorage.abi', 'w') as f:
    json.dump(abi, f, indent=2)

print()
print("✅ Saved to testnet/SimpleStorage.bin and testnet/SimpleStorage.abi")
