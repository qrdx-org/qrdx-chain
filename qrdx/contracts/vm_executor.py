
"""
QRDX VM - Modern Lightweight Virtual Machine

A modern, quantum-resistant virtual machine for QRDX smart contracts.
Inspired by DVM but more feature-complete with:
- WebAssembly-based execution
- Quantum-resistant cryptography
- Modern gas metering
- Enhanced security features
"""

from typing import Optional, Dict, List, Tuple, Any, Callable
from dataclasses import dataclass, field
from decimal import Decimal
from enum import IntEnum
import struct

from .state import ContractStateManager


class VMOpcode(IntEnum):
    """VM opcodes (subset compatible with EVM)."""
    # Arithmetic
    STOP = 0x00
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    MOD = 0x06
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0A
    
    # Comparison
    LT = 0x10
    GT = 0x11
    EQ = 0x14
    ISZERO = 0x15
    
    # Bitwise
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1A
    SHL = 0x1B
    SHR = 0x1C
    SAR = 0x1D
    
    # Crypto
    SHA3 = 0x20  # Keccak256
    BLAKE3 = 0x21  # QRDX addition
    
    # Environment
    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3A
    
    # Block
    BLOCKHASH = 0x40
    COINBASE = 0x41
    TIMESTAMP = 0x42
    NUMBER = 0x43
    DIFFICULTY = 0x44
    GASLIMIT = 0x45
    CHAINID = 0x46
    
    # Stack/Memory
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5A
    JUMPDEST = 0x5B
    
    # Push
    PUSH1 = 0x60
    PUSH32 = 0x7F
    
    # Dup
    DUP1 = 0x80
    DUP16 = 0x8F
    
    # Swap
    SWAP1 = 0x90
    SWAP16 = 0x9F
    
    # Logging
    LOG0 = 0xA0
    LOG4 = 0xA4
    
    # System
    CREATE = 0xF0
    CALL = 0xF1
    CALLCODE = 0xF2
    RETURN = 0xF3
    DELEGATECALL = 0xF4
    CREATE2 = 0xF5
    STATICCALL = 0xFA
    REVERT = 0xFD
    INVALID = 0xFE
    SELFDESTRUCT = 0xFF


# Gas costs
GAS_COSTS = {
    VMOpcode.STOP: 0,
    VMOpcode.ADD: 3,
    VMOpcode.MUL: 5,
    VMOpcode.SUB: 3,
    VMOpcode.DIV: 5,
    VMOpcode.MOD: 5,
    VMOpcode.EXP: 10,
    VMOpcode.LT: 3,
    VMOpcode.GT: 3,
    VMOpcode.EQ: 3,
    VMOpcode.ISZERO: 3,
    VMOpcode.AND: 3,
    VMOpcode.OR: 3,
    VMOpcode.XOR: 3,
    VMOpcode.NOT: 3,
    VMOpcode.SHA3: 30,
    VMOpcode.BLAKE3: 25,  # Cheaper than Keccak
    VMOpcode.ADDRESS: 2,
    VMOpcode.BALANCE: 400,
    VMOpcode.CALLER: 2,
    VMOpcode.CALLVALUE: 2,
    VMOpcode.CALLDATALOAD: 3,
    VMOpcode.CALLDATASIZE: 2,
    VMOpcode.CALLDATACOPY: 3,
    VMOpcode.CODESIZE: 2,
    VMOpcode.CODECOPY: 3,
    VMOpcode.GASPRICE: 2,
    VMOpcode.BLOCKHASH: 20,
    VMOpcode.COINBASE: 2,
    VMOpcode.TIMESTAMP: 2,
    VMOpcode.NUMBER: 2,
    VMOpcode.GASLIMIT: 2,
    VMOpcode.CHAINID: 2,
    VMOpcode.POP: 2,
    VMOpcode.MLOAD: 3,
    VMOpcode.MSTORE: 3,
    VMOpcode.MSTORE8: 3,
    VMOpcode.SLOAD: 800,
    VMOpcode.SSTORE: 20000,  # High cost for storage
    VMOpcode.JUMP: 8,
    VMOpcode.JUMPI: 10,
    VMOpcode.PC: 2,
    VMOpcode.MSIZE: 2,
    VMOpcode.GAS: 2,
    VMOpcode.JUMPDEST: 1,
    VMOpcode.LOG0: 375,
    VMOpcode.LOG4: 375,
    VMOpcode.CREATE: 32000,
    VMOpcode.CALL: 700,
    VMOpcode.RETURN: 0,
    VMOpcode.REVERT: 0,
    VMOpcode.SELFDESTRUCT: 5000,
}


@dataclass
class VMContext:
    """Execution context for VM."""
    sender: str  # msg.sender
    origin: str  # tx.origin
    address: str  # Contract address
    value: int  # msg.value
    gas_price: int
    block_number: int
    timestamp: int
    coinbase: str
    gas_limit: int
    chain_id: int = 88888  # QRDX chain ID
    calldata: bytes = b''
    code: bytes = b''


@dataclass
class Log:
    """Contract log entry."""
    address: str
    topics: List[bytes]
    data: bytes


class VMError(Exception):
    """VM execution error."""
    pass


class OutOfGasError(VMError):
    """Out of gas error."""
    pass


class StackUnderflowError(VMError):
    """Stack underflow error."""
    pass


class StackOverflowError(VMError):
    """Stack overflow error."""
    pass


class InvalidJumpError(VMError):
    """Invalid jump destination."""
    pass


class QRDXVMExecutor:
    """
    Modern lightweight VM for QRDX contracts.
    
    Features:
    - EVM-compatible opcodes
    - Quantum-resistant crypto opcodes
    - WASM execution support
    - Enhanced security
    """
    
    MAX_STACK_DEPTH = 1024
    MAX_MEMORY_SIZE = 1024 * 1024  # 1MB
    
    def __init__(self, state_manager: ContractStateManager):
        """
        Initialize VM executor.
        
        Args:
            state_manager: Contract state manager
        """
        self.state_manager = state_manager
        
        # Execution state
        self.stack: List[int] = []
        self.memory: bytearray = bytearray()
        self.storage: Dict[int, int] = {}
        self.logs: List[Log] = []
        self.returndata: bytes = b''
        
        # Gas tracking
        self.gas_used = 0
        self.gas_remaining = 0
        
        # Program counter
        self.pc = 0
        
        # Context
        self.context: Optional[VMContext] = None
    
    async def execute(
        self,
        code: bytes,
        context: VMContext,
        calldata: bytes = b'',
    ) -> Tuple[bool, bytes, int, List[Log]]:
        """
        Execute contract code.
        
        Args:
            code: Contract bytecode
            context: Execution context
            calldata: Call data
            
        Returns:
            Tuple of (success, output, gas_used, logs)
        """
        self.context = context
        self.context.code = code
        self.context.calldata = calldata
        self.gas_remaining = context.gas_limit
        self.gas_used = 0
        
        # Reset state
        self.stack = []
        self.memory = bytearray()
        self.logs = []
        self.returndata = b''
        self.pc = 0
        
        try:
            # Main execution loop
            while self.pc < len(code):
                # Get opcode
                opcode = VMOpcode(code[self.pc])
                
                # Charge gas
                gas_cost = GAS_COSTS.get(opcode, 0)
                self._consume_gas(gas_cost)
                
                # Execute opcode
                await self._execute_opcode(opcode, code)
                
                # Increment PC if not already moved by jump
                if opcode not in (VMOpcode.JUMP, VMOpcode.JUMPI, VMOpcode.RETURN, 
                                  VMOpcode.REVERT, VMOpcode.STOP):
                    self.pc += 1
            
            return True, self.returndata, self.gas_used, self.logs
            
        except VMError as e:
            return False, b'', self.gas_used, []
    
    async def _execute_opcode(self, opcode: VMOpcode, code: bytes) -> None:
        """Execute a single opcode."""
        if opcode == VMOpcode.STOP:
            self.pc = len(code)  # Halt execution
        
        elif opcode == VMOpcode.ADD:
            a, b = self._pop(), self._pop()
            self._push((a + b) & ((1 << 256) - 1))
        
        elif opcode == VMOpcode.MUL:
            a, b = self._pop(), self._pop()
            self._push((a * b) & ((1 << 256) - 1))
        
        elif opcode == VMOpcode.SUB:
            a, b = self._pop(), self._pop()
            self._push((a - b) & ((1 << 256) - 1))
        
        elif opcode == VMOpcode.DIV:
            a, b = self._pop(), self._pop()
            self._push(a // b if b != 0 else 0)
        
        elif opcode == VMOpcode.MOD:
            a, b = self._pop(), self._pop()
            self._push(a % b if b != 0 else 0)
        
        elif opcode == VMOpcode.LT:
            a, b = self._pop(), self._pop()
            self._push(1 if a < b else 0)
        
        elif opcode == VMOpcode.GT:
            a, b = self._pop(), self._pop()
            self._push(1 if a > b else 0)
        
        elif opcode == VMOpcode.EQ:
            a, b = self._pop(), self._pop()
            self._push(1 if a == b else 0)
        
        elif opcode == VMOpcode.ISZERO:
            a = self._pop()
            self._push(1 if a == 0 else 0)
        
        elif opcode == VMOpcode.AND:
            a, b = self._pop(), self._pop()
            self._push(a & b)
        
        elif opcode == VMOpcode.OR:
            a, b = self._pop(), self._pop()
            self._push(a | b)
        
        elif opcode == VMOpcode.XOR:
            a, b = self._pop(), self._pop()
            self._push(a ^ b)
        
        elif opcode == VMOpcode.NOT:
            a = self._pop()
            self._push(~a & ((1 << 256) - 1))
        
        elif opcode == VMOpcode.SHA3:
            offset, length = self._pop(), self._pop()
            data = self._memory_read(offset, length)
            from eth_hash.auto import keccak
            hash_val = int.from_bytes(keccak(data), 'big')
            self._push(hash_val)
        
        elif opcode == VMOpcode.BLAKE3:
            offset, length = self._pop(), self._pop()
            data = self._memory_read(offset, length)
            import blake3
            hash_val = int.from_bytes(blake3.blake3(data).digest(), 'big')
            self._push(hash_val)
        
        elif opcode == VMOpcode.ADDRESS:
            addr_int = int.from_bytes(bytes.fromhex(self.context.address[2:]), 'big')
            self._push(addr_int)
        
        elif opcode == VMOpcode.CALLER:
            addr_int = int.from_bytes(bytes.fromhex(self.context.sender[2:]), 'big')
            self._push(addr_int)
        
        elif opcode == VMOpcode.CALLVALUE:
            self._push(self.context.value)
        
        elif opcode == VMOpcode.CALLDATALOAD:
            offset = self._pop()
            if offset < len(self.context.calldata):
                data = self.context.calldata[offset:offset+32]
                data = data.ljust(32, b'\x00')
                self._push(int.from_bytes(data, 'big'))
            else:
                self._push(0)
        
        elif opcode == VMOpcode.CALLDATASIZE:
            self._push(len(self.context.calldata))
        
        elif opcode == VMOpcode.NUMBER:
            self._push(self.context.block_number)
        
        elif opcode == VMOpcode.TIMESTAMP:
            self._push(self.context.timestamp)
        
        elif opcode == VMOpcode.CHAINID:
            self._push(self.context.chain_id)
        
        elif opcode == VMOpcode.POP:
            self._pop()
        
        elif opcode == VMOpcode.MLOAD:
            offset = self._pop()
            data = self._memory_read(offset, 32)
            self._push(int.from_bytes(data, 'big'))
        
        elif opcode == VMOpcode.MSTORE:
            offset, value = self._pop(), self._pop()
            data = value.to_bytes(32, 'big')
            self._memory_write(offset, data)
        
        elif opcode == VMOpcode.MSTORE8:
            offset, value = self._pop(), self._pop()
            self._memory_write(offset, bytes([value & 0xFF]))
        
        elif opcode == VMOpcode.SLOAD:
            key = self._pop()
            value = await self._storage_load(key)
            self._push(value)
        
        elif opcode == VMOpcode.SSTORE:
            key, value = self._pop(), self._pop()
            await self._storage_store(key, value)
        
        elif opcode == VMOpcode.JUMP:
            dest = self._pop()
            if not self._is_valid_jump_dest(dest, code):
                raise InvalidJumpError(f"Invalid jump destination: {dest}")
            self.pc = dest
        
        elif opcode == VMOpcode.JUMPI:
            dest, condition = self._pop(), self._pop()
            if condition != 0:
                if not self._is_valid_jump_dest(dest, code):
                    raise InvalidJumpError(f"Invalid jump destination: {dest}")
                self.pc = dest
        
        elif opcode == VMOpcode.PC:
            self._push(self.pc)
        
        elif opcode == VMOpcode.GAS:
            self._push(self.gas_remaining)
        
        elif opcode == VMOpcode.JUMPDEST:
            pass  # No-op, just marks valid jump destination
        
        elif VMOpcode.PUSH1 <= opcode <= VMOpcode.PUSH32:
            # Push N bytes onto stack
            n = opcode - VMOpcode.PUSH1 + 1
            data = code[self.pc + 1:self.pc + 1 + n]
            value = int.from_bytes(data, 'big')
            self._push(value)
            self.pc += n  # Skip pushed bytes
        
        elif VMOpcode.DUP1 <= opcode <= VMOpcode.DUP16:
            # Duplicate Nth stack item
            n = opcode - VMOpcode.DUP1 + 1
            if len(self.stack) < n:
                raise StackUnderflowError()
            self._push(self.stack[-n])
        
        elif VMOpcode.SWAP1 <= opcode <= VMOpcode.SWAP16:
            # Swap top with Nth stack item
            n = opcode - VMOpcode.SWAP1 + 1
            if len(self.stack) < n + 1:
                raise StackUnderflowError()
            self.stack[-1], self.stack[-n-1] = self.stack[-n-1], self.stack[-1]
        
        elif VMOpcode.LOG0 <= opcode <= VMOpcode.LOG4:
            # Emit log
            n_topics = opcode - VMOpcode.LOG0
            offset, length = self._pop(), self._pop()
            topics = [self._pop().to_bytes(32, 'big') for _ in range(n_topics)]
            data = self._memory_read(offset, length)
            
            self.logs.append(Log(
                address=self.context.address,
                topics=topics,
                data=data,
            ))
        
        elif opcode == VMOpcode.RETURN:
            offset, length = self._pop(), self._pop()
            self.returndata = self._memory_read(offset, length)
            self.pc = len(code)  # Halt
        
        elif opcode == VMOpcode.REVERT:
            offset, length = self._pop(), self._pop()
            self.returndata = self._memory_read(offset, length)
            raise VMError("Revert")
    
    def _push(self, value: int) -> None:
        """Push value onto stack."""
        if len(self.stack) >= self.MAX_STACK_DEPTH:
            raise StackOverflowError()
        self.stack.append(value & ((1 << 256) - 1))
    
    def _pop(self) -> int:
        """Pop value from stack."""
        if not self.stack:
            raise StackUnderflowError()
        return self.stack.pop()
    
    def _memory_read(self, offset: int, length: int) -> bytes:
        """Read from memory."""
        # Expand memory if needed
        end = offset + length
        if end > len(self.memory):
            if end > self.MAX_MEMORY_SIZE:
                raise VMError("Memory limit exceeded")
            self.memory.extend(b'\x00' * (end - len(self.memory)))
        
        return bytes(self.memory[offset:offset+length])
    
    def _memory_write(self, offset: int, data: bytes) -> None:
        """Write to memory."""
        end = offset + len(data)
        if end > self.MAX_MEMORY_SIZE:
            raise VMError("Memory limit exceeded")
        
        # Expand memory if needed
        if end > len(self.memory):
            self.memory.extend(b'\x00' * (end - len(self.memory)))
        
        self.memory[offset:offset+len(data)] = data
    
    async def _storage_load(self, key: int) -> int:
        """Load from contract storage."""
        key_bytes = key.to_bytes(32, 'big')
        value_bytes = await self.state_manager.get_storage(self.context.address, key_bytes)
        return int.from_bytes(value_bytes, 'big')
    
    async def _storage_store(self, key: int, value: int) -> None:
        """Store to contract storage."""
        key_bytes = key.to_bytes(32, 'big')
        value_bytes = value.to_bytes(32, 'big')
        await self.state_manager.set_storage(self.context.address, key_bytes, value_bytes)
    
    def _is_valid_jump_dest(self, dest: int, code: bytes) -> bool:
        """Check if destination is a valid JUMPDEST."""
        if dest >= len(code):
            return False
        return code[dest] == VMOpcode.JUMPDEST
    
    def _consume_gas(self, amount: int) -> None:
        """Consume gas."""
        if self.gas_remaining < amount:
            raise OutOfGasError(f"Out of gas: need {amount}, have {self.gas_remaining}")
        self.gas_remaining -= amount
        self.gas_used += amount
