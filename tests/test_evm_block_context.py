"""
Contracts see the real block: ``block.number`` and ``block.timestamp`` (web3 compatibility).

The executor built its block context from constants — ``TIMESTAMP`` and ``NUMBER`` were
always 1 — so any contract with a timelock, vesting schedule, auction window or router
deadline behaved as if the chain never advanced. Every consensus path now passes the block
being executed, and ``eth_call`` the latest block, as geth does.

Also pinned here: the RPC layer has exactly one write path. A direct-execution
``eth_sendTransaction`` handler in main.py ran signed calls straight against the EVM state
manager (no block, no mempool, no nonce check); its dirty cache entries were committed by the
next block's EVM flush, so any RPC client could push off-chain effects into a node's
account_state and replay them at will.
"""
import inspect
from unittest.mock import MagicMock

import pytest

from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
from qrdx.contracts.state import ContractStateManager

TIMESTAMP, NUMBER = 0x42, 0x43
CONTRACT = "0x" + "c0" * 20
CALLER = bytes.fromhex("11" * 20)


def _probe(opcode):
    """<opcode> PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN — returns the opcode's value."""
    return bytes([opcode, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3])


def _read(opcode, **context):
    sm = ContractStateManager(MagicMock())
    sm.set_code_sync(CONTRACT, _probe(opcode))
    result = QRDXEVMExecutor(sm).call(sender=CALLER, to=bytes.fromhex(CONTRACT[2:]),
                                      data=b"", **context)
    assert result.success, result.error
    return int.from_bytes(result.output, "big")


@pytest.mark.parametrize("opcode, context, expected", [
    (TIMESTAMP, {"block_number": 77, "timestamp": 1_790_000_000}, 1_790_000_000),
    (NUMBER, {"block_number": 77, "timestamp": 1_790_000_000}, 77),
    (TIMESTAMP, {}, 1),           # no block: the old constant, for standalone callers
    (NUMBER, {}, 1),
], ids=["timestamp", "number", "default-timestamp", "default-number"])
def test_contracts_read_the_block_context(opcode, context, expected):
    assert _read(opcode, **context) == expected


def test_every_consensus_execution_passes_its_block():
    from qrdx.node import main as node_main
    src = inspect.getsource(node_main._execute_evm_raw_tx)
    assert "block_number=int(block_height or 1)" in src
    assert "timestamp=_evm_block_timestamp(block_timestamp)" in src


@pytest.mark.parametrize("value, expected", [
    (1_790_000_000, 1_790_000_000), ("1790000000", 1_790_000_000),
    ("2026-09-30 01:44:32+00:00", 1),   # genesis stores a datetime
    (None, 1), (0, 1),
])
def test_block_timestamps_map_to_evm_seconds(value, expected):
    from qrdx.node.main import _evm_block_timestamp
    assert _evm_block_timestamp(value) == expected


def test_eth_call_uses_the_latest_block():
    from qrdx.node import main as node_main
    src = inspect.getsource(node_main.startup)
    call = src[src.index("evm_executor.call("):]
    call = call[:call.index("), preload=")]
    assert "block_number=max(tip, 1)" in call and "timestamp=_evm_block_timestamp(" in call


def test_there_is_one_write_path():
    """main.py must not register eth_sendTransaction: EthModule's refusal must stand."""
    from qrdx.node import main as node_main
    src = inspect.getsource(node_main.startup)
    assert "register_method('eth_sendTransaction'" not in src
    assert "async def eth_sendTransaction_handler" not in src
    from qrdx.rpc.modules.eth import EthModule
    refusal = inspect.getsource(EthModule.sendTransaction)
    assert "eth_sendRawTransaction" in refusal and "not supported" in refusal
