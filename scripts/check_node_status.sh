#!/bin/bash
# Simple script to monitor QRDX node status

echo "=== QRDX Node Status ==="
echo ""

# Check Trinity processes
TRINITY_COUNT=$(ps aux | grep "trinity --network-id 1337" | grep -v grep | wc -l)
echo "Trinity processes running: $TRINITY_COUNT"
echo ""

# Check each node
for i in 0 1; do
    NODE_DIR="/tmp/qrdx-node-${i}"
    if [ -d "$NODE_DIR" ]; then
        echo "Node ${i}:"
        echo "  Data dir: $NODE_DIR"
        
        # Check if log file exists
        if [ -f "$NODE_DIR/trinity.log" ]; then
            # Get PID from ps
            PID=$(ps aux | grep "trinity.*--port $((30303 + i))" | grep -v grep | awk '{print $2}' | head -1)
            if [ -n "$PID" ]; then
                echo "  Status: RUNNING (PID: $PID)"
            else
                echo "  Status: STOPPED"
            fi
            
            # Check for peer connections in log
            PEER_LINES=$(grep "Connected peers" "$NODE_DIR/trinity.log" | tail -1)
            if [ -n "$PEER_LINES" ]; then
                echo "  $PEER_LINES"
            else
                echo "  Peer info: Not yet available"
            fi
            
            # Check for components
            COMPONENTS=$(grep "Starting components:" "$NODE_DIR/trinity.log" | tail -1 | cut -d: -f4-)
            if [ -n "$COMPONENTS" ]; then
                echo "  Components:$COMPONENTS"
            fi
        else
            echo "  Status: No log file found"
        fi
        echo ""
    fi
done

echo "=== Block Number Check ==="
curl -s -X POST http://localhost:8545 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | python3 -m json.tool 2>/dev/null || echo "RPC not responding"
