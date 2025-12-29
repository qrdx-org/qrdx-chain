#!/usr/bin/env python3
"""Test that the broadcast code is correctly updated."""

import re

# Read the component file
with open('/workspaces/qrdx-chain/trinity/components/builtin/qrpos_validator/component.py', 'r') as f:
    content = f.read()

# Check for the new broadcast code
if 'via event bus' in content:
    print("✅ New broadcast code found in source file")
    
    # Find the _broadcast_block function
    if 'QRPoSNewBlockEvent' in content:
        print("✅ QRPoSNewBlockEvent import found")
    else:
        print("❌ QRPoSNewBlockEvent import NOT found")
        
    if 'await self.event_bus.broadcast' in content:
        print("✅ event_bus.broadcast() call found")
    else:
        print("❌ event_bus.broadcast() call NOT found")
else:
    print("❌ New broadcast code NOT found in source file")
    print("\nSearching for broadcast function...")
    match = re.search(r'async def _broadcast_block.*?(?=\n    async def|\n    def|\Z)', content, re.DOTALL)
    if match:
        print("Found function:")
        print(match.group(0)[:500])
