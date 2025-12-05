# IPC Event Delivery Investigation

**Date**: December 4, 2024  
**Status**: Root cause identified, fix in progress

## Problem Statement

QR-PoS consensus blocks and attestations are being created by validators but not propagating through the system. Events are broadcast via the Lahja event bus but never received by subscribing components.

## Investigation Results

### Component Architecture

Trinity uses a multi-process architecture with IPC (Inter-Process Communication) via Unix domain sockets:
- **Main Process**: Coordinates component lifecycle
- **Isolated Components**: Run in separate processes, communicate via Lahja event bus over IPC
- **Event Flow**: Component A → IPC Socket → Event Bus → IPC Socket → Component B

### Expected Flow

1. `QRPoSValidatorComponent` creates block with Dilithium signature
2. Broadcasts `QRPoSNewBlockEvent` via event bus
3. `NewBlockComponent` receives event via `stream(QRPoSNewBlockEvent)`
4. Validates and imports block to chain DB
5. Propagates block to P2P network

### Actual Behavior

**QRPoSValidatorComponent** (✓ Working):
- Successfully creates blocks every 2 seconds
- Successfully creates attestations every 2 seconds
- Broadcasts `QRPoSNewBlockEvent` with `FIRE_AND_FORGET_BROADCASTING`
- IPC socket exists: `/tmp/qrdx-node-0/ipcs-eth1/bqrpos-validator.ipc`

**NewBlockComponent** (✗ Broken):
- Component registered in `ETH1_NODE_COMPONENTS`
- Logs show "Starting components: ...NewBlockComponent..."
- **IPC socket never created**: `/tmp/qrdx-node-0/ipcs-eth1/bnewblockcomponent.ipc` missing
- `do_run()` method never reached (no "QR-PoS block handler started" log)
- Trio event loop initialization fails silently

### IPC Connection Failures

```
WARNING EventBusService  Failed to connect bqrpos-validator to one of bnewblockcomponent: 
  IPC socket file /tmp/qrdx-node-0/ipcs-eth1/bnewblockcomponent.ipc has not appeared in 2 seconds

WARNING EventBusService  Failed to connect bjson-rpc-api to one of bnewblockcomponent: 
  IPC socket file /tmp/qrdx-node-0/ipcs-eth1/bnewblockcomponent.ipc has not appeared in 2 seconds
```

### IPC Sockets Present vs Missing

**Present** (✓):
- `main.ipc`
- `db.ipc`
- `logging.ipc`
- `network-db.ipc`
- `bjson-rpc-api.ipc`
- `bqrpos-validator.ipc`
- `brequest-server.ipc`
- `upnp.ipc`
- `jsonrpc.ipc`

**Missing** (✗):
- `bnewblockcomponent.ipc` ← **Primary issue**
- `networking.ipc` ← Secondary issue

## Root Cause

**NewBlockComponent initialization failure** in Python 3.12 environment.

### Component Type
`NewBlockComponent` is a `TrioIsolatedComponent` which:
1. Runs in a separate process
2. Uses Trio event loop (not asyncio)
3. Requires proper async context manager initialization
4. Creates IPC endpoint during startup

### Hypothesis
Python 3.12 compatibility issue with:
- **Trio library**: May have issues with Python 3.12's event loop changes
- **async_service**: Background service wrapper may fail silently
- **Lahja Trio endpoint**: IPC socket creation timing issue

Similar to the `async_lru` issues we encountered and fixed earlier.

## Impact

### Current State
1. ✗ Blocks created but not imported to DB
2. ✗ Blocks not propagated to peers
3. ✗ Chain stuck at genesis block #0
4. ✗ Attestations created but never broadcast (TODO in code)
5. ✗ P2P consensus not functioning

### Chain State
- Latest block: #0 (genesis)
- Slot number: 960+ (should have ~480 blocks if 2-second slots)
- Validators creating attestations but no blocks finalized

## Fix Strategy

### Option 1: Fix Trio Initialization (Preferred)
- Debug why TrioIsolatedComponent fails to start
- Check Trio version compatibility with Python 3.12
- Add explicit error handling/logging during component startup
- Ensure IPC socket creation happens before timeout

### Option 2: Convert to AsyncioIsolatedComponent
- Change NewBlockComponent from Trio to asyncio
- Update all async code to use asyncio primitives
- Keep consistency with other components

### Option 3: Workaround - Direct Event Bus Connection
- Have QRPoSValidatorComponent directly import blocks
- Bypass IPC event delivery for local validator blocks
- Keep IPC for P2P-received blocks only

## Implementation Plan

1. **Add diagnostic logging** to component startup
2. **Catch and log exceptions** in TrioIsolatedComponent initialization
3. **Verify Trio version** compatibility
4. **Test IPC socket creation** separately
5. **Fix identified issue** (likely exception swallowed during startup)
6. **Verify event delivery** end-to-end
7. **Implement attestation broadcasting** once IPC works

## Related TODOs in Code

### Attestation Broadcasting
File: `trinity/components/builtin/qrpos_validator/component.py:381`
```python
# TODO: Broadcast attestation to network
# For now, just log it
logger.debug(f"Attestation: {attestation}")
```

**Action**: Create `QRPoSAttestationEvent` and broadcast via IPC once event bus is fixed.

## References

- Component registry: `trinity/components/registry.py`
- NewBlock component: `trinity/components/builtin/new_block/component.py`
- QRPoS Validator: `trinity/components/builtin/qrpos_validator/component.py`
- Event definitions: `trinity/protocol/eth/events.py`
- Lahja IPC: `lahja/lahja/trio/endpoint.py`
