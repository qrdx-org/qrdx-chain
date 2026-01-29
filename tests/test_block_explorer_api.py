#!/usr/bin/env python3
"""
Test script for block explorer API endpoints
Tests both with and without contract data in the database
"""

import aiohttp
import asyncio
import json

BASE_URL = "http://localhost:3006"

async def test_endpoint(session, endpoint, params=None):
    """Test a single endpoint"""
    url = f"{BASE_URL}{endpoint}"
    try:
        async with session.get(url, params=params) as response:
            data = await response.json()
            status = "✅ OK" if data.get('ok') else "❌ FAIL"
            print(f"{status} {endpoint}")
            if not data.get('ok'):
                print(f"   Error: {data.get('error')}")
            else:
                result = data.get('result', {})
                if isinstance(result, dict):
                    # Print summary of result
                    for key, value in result.items():
                        if isinstance(value, list):
                            print(f"   {key}: {len(value)} items")
                        elif key not in ['tokens', 'transactions', 'blocks', 'attestations', 'addresses']:
                            print(f"   {key}: {value}")
            return data
    except Exception as e:
        print(f"❌ ERROR {endpoint}: {e}")
        return None

async def main():
    """Run all endpoint tests"""
    print("=" * 60)
    print("Block Explorer API Tests")
    print("=" * 60)
    print()
    
    async with aiohttp.ClientSession() as session:
        # Test 1: Get address tokens (with a sample address)
        print("1. Testing /get_address_tokens")
        await test_endpoint(session, "/get_address_tokens", {
            "address": "0x" + "0" * 40  # Zero address as test
        })
        print()
        
        # Test 2: Get token info (with a sample contract address)
        print("2. Testing /get_token_info")
        await test_endpoint(session, "/get_token_info", {
            "token_address": "0x" + "0" * 40
        })
        print()
        
        # Test 3: Get top addresses by balance
        print("3. Testing /get_top_addresses (by balance)")
        await test_endpoint(session, "/get_top_addresses", {
            "sort_by": "balance",
            "limit": 10
        })
        print()
        
        # Test 4: Get top addresses by transactions
        print("4. Testing /get_top_addresses (by transactions)")
        await test_endpoint(session, "/get_top_addresses", {
            "sort_by": "transactions",
            "limit": 10
        })
        print()
        
        # Test 5: Get top addresses by tokens
        print("5. Testing /get_top_addresses (by tokens)")
        await test_endpoint(session, "/get_top_addresses", {
            "sort_by": "tokens",
            "limit": 10
        })
        print()
        
        # Test 6: Get recent transactions
        print("6. Testing /get_recent_transactions")
        await test_endpoint(session, "/get_recent_transactions", {
            "limit": 20,
            "include_contract_txs": True
        })
        print()
        
        # Test 7: Get recent blocks
        print("7. Testing /get_recent_blocks")
        await test_endpoint(session, "/get_recent_blocks", {
            "limit": 20,
            "include_validator_info": True
        })
        print()
        
        # Test 8: Get attestations
        print("8. Testing /get_attestations")
        await test_endpoint(session, "/get_attestations", {
            "limit": 50
        })
        print()
        
        # Test 9: Get attestations by epoch
        print("9. Testing /get_attestations (filtered by epoch)")
        await test_endpoint(session, "/get_attestations", {
            "epoch": 1,
            "limit": 50
        })
        print()
    
    print("=" * 60)
    print("Tests Complete")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
