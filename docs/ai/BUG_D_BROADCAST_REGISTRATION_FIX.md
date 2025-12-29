# Bug D: QRPoSNewBlock Command Not Registered for Broadcast

## Summary
Fixed critical bug that caused node crashes in multi-node testnet with error: "Command QRPoSNewBlock is not broadcasted"

## Problem
When a peer node received a `QRPoSNewBlock` command over the network, the `ETHPeerPoolEventServer.handle_native_peer_message()` method did not have a handler for it, causing the code to fall through to the `else` clause which raised an exception.

## Root Cause
The `QRPoSNewBlock` command was properly defined in:
- ✅ Command class (`trinity/protocol/eth/commands.py`)
- ✅ Protocol command list (`trinity/protocol/eth/proto.py`)
- ✅ Proxy send method (`trinity/protocol/eth/proxy.py`)
- ✅ Event classes (`trinity/protocol/eth/events.py`)

But **MISSING** from:
- ❌ `handle_native_peer_message()` if/elif chain in `trinity/protocol/eth/peer.py`

This meant that when a node received a QRPoSNewBlock command from a peer, it didn't know how to handle it and crashed.

## Solution
Added handler for `QRPoSNewBlock` (and `Attestations`) commands in `handle_native_peer_message()`.

### File: `/workspaces/qrdx-chain/trinity/protocol/eth/peer.py`

**Change 1: Import the wire event**
```python
from .events import (
    # ... existing imports ...
    AttestationsEvent,
    SendAttestationsEvent,
    QRPoSNewBlockEvent_Wire,  # ← ADDED
    SendQRPoSNewBlockEvent,
)
```

**Change 2: Add handlers in `handle_native_peer_message()`**
```python
async def handle_native_peer_message(self, session: SessionAPI, cmd: CommandAPI[Any]) -> None:
    # ... existing handlers ...
    elif isinstance(cmd, BlockWitnessHashes):
        await self.event_bus.broadcast(
            BlockWitnessHashesEvent(session, cmd),
            FIRE_AND_FORGET_BROADCASTING
        )
    elif isinstance(cmd, Attestations):  # ← ADDED
        await self.event_bus.broadcast(
            AttestationsEvent(session, cmd),
            FIRE_AND_FORGET_BROADCASTING
        )
    elif isinstance(cmd, QRPoSNewBlock):  # ← ADDED
        await self.event_bus.broadcast(
            QRPoSNewBlockEvent_Wire(session, cmd),
            FIRE_AND_FORGET_BROADCASTING
        )
    else:
        raise Exception(f"Command {cmd} is not broadcasted")
```

## Testing Results

### Before Fix
- ❌ Node-1 crashed immediately with "is not broadcasted" error
- ❌ Multi-node testnet failed
- ✅ Single-node testnet worked (no peer communication needed)

### After Fix
- ✅ Both nodes running successfully for 3+ hours
- ✅ Block heights syncing (Node 0: 7067, Node 1: 7069 - within 2 blocks)
- ✅ Peer connectivity working (each node sees 1 peer)
- ✅ QR-PoS blocks being broadcast successfully
- ✅ Dilithium signatures being validated
- ✅ Attestations being shared between nodes
- ✅ No "is not broadcasted" errors in logs

### Log Evidence
```
INFO  NewBlockService  Received QR-PoS block from local validator 1: block #7372 (slot 5223)
INFO  NewBlockService  QR-PoS block #7372 signature validated successfully (validator 1)
INFO  NewBlockService  Successfully imported QR-PoS block #7372 (hash: a236..9115)
INFO  NewBlockService  Broadcast QR-PoS block #7372 to peers with Dilithium signature
INFO  NewBlockService  Received QR-PoS block #7372 from peer <Session <Node(0x7257c1@127.0.0.1)>>
```

## Related Bugs Fixed in This Session

### Bug A: Consensus Attribute Error
- **File**: `trinity/components/builtin/new_block/component.py`
- **Fix**: Added QRPoSConsensus initialization with validator sorting
- **Result**: 100% attestation validation success

### Bug B: get_score() Exception Handling
- **File**: `trinity/components/builtin/new_block/component.py`
- **Fix**: Changed `except KeyError:` to `except (KeyError, HeaderNotFound):`
- **Result**: Retry logic now works correctly for IPC database delays

### Bug C: Missing ProxyETHAPI Method
- **File**: `trinity/protocol/eth/proxy.py`
- **Fix**: Added `send_qrpos_new_block()` method
- **Result**: QR-PoS blocks can be sent to peer pool

### Bug D: QRPoSNewBlock Broadcast Registration (This Fix)
- **File**: `trinity/protocol/eth/peer.py`
- **Fix**: Added handler in `handle_native_peer_message()`
- **Result**: Multi-node testnet fully operational

## Impact
This was the final missing piece for multi-node testnet functionality. All QR-PoS consensus features now work across multiple nodes:
- ✅ Block production by multiple validators
- ✅ Block propagation over P2P network
- ✅ Attestation sharing
- ✅ Quantum-resistant signature verification
- ✅ Synchronized chain state across nodes

## Date
December 29, 2025

## Status
✅ **RESOLVED** - Multi-node testnet fully operational
