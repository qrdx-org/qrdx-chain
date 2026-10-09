"""
QRDX EVM Executor (Production)

Direct integration with py-evm QRDX fork for full Ethereum + PQ compatibility.
Uses QRDXVM (extends ShanghaiVM) with quantum-resistant precompiles at
0x09-0x0c.  Stripped down to essentials — no unnecessary abstractions.
"""

import logging
import sys
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass

from importlib import util as importlib_util

# Prefer an installed `eth` package (the container installs the py-evm QRDX fork
# as a wheel). Fall back to the in-repo checkout for local development, resolved
# relative to this file rather than a hardcoded absolute path.
import os

if importlib_util.find_spec("eth") is None:
    _vendored_py_evm = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "py-evm",
    )
    if os.path.isdir(_vendored_py_evm) and _vendored_py_evm not in sys.path:
        sys.path.insert(0, _vendored_py_evm)

from eth.vm.forks.qrdx import QRDXVM
from eth.db.atomic import AtomicDB
from eth.db.account import AccountDB
from eth.vm.forks.qrdx.state import QRDXState
from eth.vm.forks.qrdx.computation import QRDXComputation
from eth.vm.message import Message
from eth.vm.transaction_context import BaseTransactionContext
from eth.vm.execution_context import ExecutionContext
from eth.constants import CREATE_CONTRACT_ADDRESS, ZERO_ADDRESS, GENESIS_DIFFICULTY
from eth_typing import Address
from eth_utils import (
    to_canonical_address,
    to_checksum_address,
    to_bytes,
    to_int,
    keccak,
    encode_hex,
    decode_hex,
)
import rlp

from ..constants import CHAIN_ID

logger = logging.getLogger(__name__)


@dataclass
class EVMResult:
    """Minimal EVM execution result."""
    success: bool
    gas_used: int
    output: bytes
    logs: List[Tuple[bytes, List[bytes], bytes]]  # (address, topics, data)
    error: Optional[str] = None
    created_address: Optional[bytes] = None
    # Native token moves and approvals the execution made (contracts/native_token_evm.py),
    # for the caller to fold into its block's EvmSection when the transaction succeeded.
    token_journal: List[tuple] = None


class QRDXEVMExecutor:
    """
    100% EVM-Compatible Executor.

    Uses py-evm QRDX fork (extends Shanghai) with PQ precompiles. Every execution runs on a
    fresh state built from an ``EvmWorld`` (contracts/evm_world.py): accounts and storage loaded
    from the state manager on demand, and every account and slot the execution touched written
    back to it afterwards. There is no state held here between executions.
    """

    def __init__(self, state_manager):
        """
        Args:
            state_manager: QRDX contract state manager (the canonical account store)
        """
        self.state_manager = state_manager

    def _create_message(
        self,
        sender: bytes,
        to: bytes,
        value: int,
        data: bytes,
        gas: int,
        code: bytes = b'',
        is_create: bool = False,
    ) -> Message:
        """Create EVM message."""
        if is_create:
            return Message(
                gas=gas,
                to=CREATE_CONTRACT_ADDRESS,
                sender=sender,
                value=value,
                data=b'',
                code=code,
                create_address=to,
            )
        return Message(
            gas=gas,
            to=to,
            sender=sender,
            value=value,
            data=data,
            code=code,
        )

    @staticmethod
    def _execution_context(block_number: int, timestamp: int) -> ExecutionContext:
        # block.number / block.timestamp are the block being executed — every consensus
        # path passes them (proposer, importers, rebuild), so contracts with timelocks or
        # vesting see the chain advance, identically on every node.
        return ExecutionContext(
            coinbase=ZERO_ADDRESS,
            timestamp=max(1, int(timestamp)),
            block_number=max(1, int(block_number)),
            difficulty=GENESIS_DIFFICULTY,
            mix_hash=b'\x00' * 32,
            gas_limit=10_000_000,
            prev_hashes=[b'\x00' * 32] * 256,
            chain_id=CHAIN_ID,  # the network's chain id (chain spec) — the CHAINID opcode
            base_fee_per_gas=1000000000,  # 1 gwei
        )

    def execute(
        self,
        sender: bytes,
        to: Optional[bytes],
        value: int,
        data: bytes,
        gas: int,
        gas_price: int,
        origin: Optional[bytes] = None,
        intrinsic_gas: int = 0,
        block_number: int = 1,
        timestamp: int = 1,
        world=None,
        write_back: bool = True,
        payer: Optional[bytes] = None,
    ) -> EVMResult:
        """
        Execute an EVM transaction.

        ``payer`` (default ``sender``) pays the gas and has its nonce consumed: for a delegated
        spend the EVM ``sender`` is the source the value leaves, while the signer pays.

        With ``world`` (an ``EvmWorld``), a read of state the world has not loaded raises
        ``StateMiss``: the async caller loads it and calls again (``evm_world.run``). Without
        one — legacy synchronous callers — the state comes from the state manager's cache.

        ``intrinsic_gas``: the transaction-level gas floor (21000 + calldata for a legacy tx;
        substantially more for a type-0x51 PQ tx, which must pay for its ~5.3KB
        authentication envelope). ``apply_message`` charges NO transaction-level gas, so
        without this a plain transfer costs nothing at all. Callers that are not executing a
        real transaction (``eth_call``, gas estimation) leave it at 0.

        ``write_back`` False (``eth_call``, estimation): nothing is written anywhere.

        Returns an EVMResult; ``gas_used`` is the amount actually charged, i.e. the floor when
        execution consumed less than it.
        """
        from .evm_world import EvmWorld, run_sync
        if world is None:
            legacy = EvmWorld(self.state_manager)
            return run_sync(legacy, lambda: self._execute(
                legacy, sender, to, value, data, gas, gas_price, origin, intrinsic_gas,
                block_number, timestamp, write_back, payer))
        return self._execute(world, sender, to, value, data, gas, gas_price, origin,
                             intrinsic_gas, block_number, timestamp, write_back, payer)

    def _execute(self, world, sender, to, value, data, gas, gas_price, origin, intrinsic_gas,
                 block_number, timestamp, write_back, payer=None) -> EVMResult:
        from .evm_world import StateMiss, WorldComputation
        if origin is None:
            origin = sender
        is_create = (to is None)

        try:
            state = world.build_state(self._execution_context(block_number, timestamp))
            if is_create:
                code = data
                to = self._compute_create_address(sender, state.get_nonce(sender))
            else:
                code = state.get_code(to)

            message = self._create_message(
                sender=sender,
                to=to if to else ZERO_ADDRESS,
                value=value,
                data=data if not is_create else b'',
                gas=gas,
                code=code,
                is_create=is_create,
            )
            tx_context = BaseTransactionContext(gas_price=gas_price, origin=origin)
            if is_create:
                computation = WorldComputation.apply_create_message(state, message, tx_context)
            else:
                computation = WorldComputation.apply_message(state, message, tx_context)

            success = not computation.is_error
            if success:
                # What a transaction's finalization does and apply_message does not: accounts
                # that SELFDESTRUCTed are removed (with their storage).
                for account in computation.get_accounts_for_deletion():
                    state.delete_account(account)
            gas_used = gas - computation.get_gas_remaining()
            output = bytes(computation.output)
            logs = []
            try:
                for log_entry in computation.get_log_entries():
                    if isinstance(log_entry, tuple):
                        logs.append(log_entry)
                    else:
                        logs.append((log_entry.address, log_entry.topics, log_entry.data))
            except Exception as e:
                logger.warning(f"Could not extract logs: {e}")
            error = None
            if computation.is_error:
                error = str(computation.error) if computation.error else "Execution failed"
            journal = list(state.token_journal) if success else []
        except StateMiss:
            raise
        except Exception as e:
            logger.error(f"EVM execution error: {e}", exc_info=True)
            return EVMResult(success=False, gas_used=gas, output=b'', logs=[],
                             error=f"Execution error: {str(e)}", token_journal=[])

        created_address = to if (is_create and success) else None
        if not write_back:
            return EVMResult(success=success, gas_used=gas_used, output=output, logs=logs,
                             error=error, created_address=created_address,
                             token_journal=journal)

        # Every account and slot the execution changed — the sender, the recipient, any
        # account a contract paid or created, every storage slot it wrote — into the
        # state manager. (A failed top-level call was already rolled back by the EVM.)
        payer = payer or sender
        world.write_back(state, always=[sender, payer])

        # Increment the payer's nonce on ANY successful transaction, not just a contract
        # creation: ``apply_message`` / ``apply_create_message`` do not touch the sender
        # nonce (that is ``apply_transaction``'s job, which this executor does not use).
        sender_addr = to_checksum_address(payer)
        if success:
            self.state_manager.set_nonce_sync(
                sender_addr, self.state_manager.get_nonce_sync(sender_addr) + 1)

        # Charge tx-level gas: py-evm's apply_message does no transaction-level gas
        # accounting. At least the intrinsic floor, never more than the gas limit.
        gas_used = min(gas, max(gas_used, intrinsic_gas))
        gas_cost = gas_used * gas_price
        sender_balance = self.state_manager.get_balance_sync(sender_addr)
        self.state_manager.set_balance_sync(sender_addr, sender_balance - gas_cost)

        return EVMResult(
            success=success,
            gas_used=gas_used,
            output=output,
            logs=logs,
            error=error,
            created_address=created_address,
            token_journal=journal,
        )

    def call(
        self,
        sender: bytes,
        to: bytes,
        data: bytes,
        value: int = 0,
        gas: int = 10_000_000,
        block_number: int = 1,
        timestamp: int = 1,
        world=None,
    ) -> EVMResult:
        """Execute a read-only call (eth_call), in the context of ``block_number`` /
        ``timestamp`` (the caller passes the latest block's). Writes nothing."""
        return self.execute(sender=sender, to=to, value=value, data=data, gas=gas,
                            gas_price=0, block_number=block_number, timestamp=timestamp,
                            world=world, write_back=False)

    def estimate_gas(
        self,
        sender: bytes,
        to: Optional[bytes],
        data: bytes,
        value: int = 0,
        world=None,
    ) -> int:
        """Estimate gas by binary search for the least gas the call succeeds with (+10 %).
        Writes nothing."""
        low, high = 21000, 10_000_000
        while low < high:
            mid = (low + high) // 2
            result = self.execute(sender=sender, to=to, value=value, data=data, gas=mid,
                                  gas_price=0, world=world, write_back=False)
            if result.success:
                high = mid
            else:
                low = mid + 1
        return int(low * 1.1)

    def _compute_create_address(self, sender: bytes, nonce: int) -> bytes:
        """Compute CREATE address."""
        rlp_encoded = rlp.encode([sender, nonce])
        return keccak(rlp_encoded)[12:]  # Take last 20 bytes
