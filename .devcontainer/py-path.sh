cat >> ~/.bashrc << 'EOF'

# QRDX Chain Python Path
export PYTHONPATH="/workspaces/qrdx-chain/lahja:/workspaces/qrdx-chain/async-service:/workspaces/qrdx-chain/asyncio-run-in-process:/workspaces/qrdx-chain:$PYTHONPATH"
EOF
echo "PYTHONPATH added to .bashrc"
export PYTHONPATH="/workspaces/qrdx-chain/lahja:/workspaces/qrdx-chain/async-service:/workspaces/qrdx-chain/asyncio-run-in-process:/workspaces/qrdx-chain:$PYTHONPATH" && echo "PYTHONPATH set to: $PYTHONPATH"