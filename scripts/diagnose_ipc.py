#!/usr/bin/env python3
"""
Diagnostic script to check IPC event bus connectivity in Trinity.
"""

import asyncio
import sys
from pathlib import Path

# Add trinity to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lahja import AsyncioEndpoint, ConnectionConfig, BaseEvent
from dataclasses import dataclass


@dataclass
class TestEvent(BaseEvent):
    message: str


async def main():
    ipc_path = Path("/tmp/qrdx-node-0/ipcs-eth1")
    
    print(f"Checking IPC directory: {ipc_path}")
    print(f"Exists: {ipc_path.exists()}")
    
    if ipc_path.exists():
        print("\nIPC socket files:")
        for sock in ipc_path.glob("*.ipc"):
            print(f"  - {sock.name}")
    
    print("\nAttempting to connect to main endpoint...")
    
    try:
        # Create a test endpoint
        test_endpoint = AsyncioEndpoint("test-diagnostic")
        
        # Connect to main
        main_config = ConnectionConfig.from_name("main", base_path=ipc_path.parent)
        
        async with test_endpoint.run() as endpoint:
            await endpoint.connect_to_endpoints(main_config)
            print("✓ Successfully connected to main endpoint!")
            
            # Try to get connected endpoints
            connections = endpoint.get_connected_endpoints_and_subscriptions()
            print(f"\nConnected to {len(connections)} endpoints:")
            for name, subscriptions in connections:
                print(f"  - {name}: {len(subscriptions)} subscriptions")
            
            # Try broadcasting a test event
            print("\nBroadcasting test event...")
            await endpoint.broadcast(TestEvent("Hello from diagnostic script!"))
            print("✓ Broadcast successful!")
            
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
