"""
EVM execution state, loaded on demand from the canonical account store.

Every EVM execution — a block's transactions, ``eth_call``, gas estimation — runs on a fresh
py-evm state over the ContractStateManager (this block's pending changes over the database).
The state is flat (``WorldAccountDB``: accounts and slots in dictionaries, journaled for the
EVM's call frames), and what the execution reads that is not loaded yet goes through
``EvmWorld.need``:

* under ``run`` (async callers) the execution runs in a greenlet: a read of something not
  loaded switches back to ``run``, which loads it and resumes the execution where it stopped.
  Each account and slot costs one load, however many the execution touches.
* under ``run_sync`` (legacy synchronous callers) it raises ``StateMiss``: the state manager's
  cache supplies it and the execution runs again.

When the execution finishes, every account and storage slot it touched is written back to the
state manager, and from there to the database.

The execution used to start over on every miss, on a state rebuilt and re-hashed from
everything loaded so far: a transaction touching n new accounts did O(n²) work — 800,000 gas
of BALANCE calls took 2.8 s, and the 10,000,000 gas a transaction could carry took minutes, on
every node (docs/KNOWN_ISSUES.md, "A transaction could stall every node"). Before that, a
persistent per-node trie received only a transaction's sender and recipient and returned only
their balances and nonces (docs/KNOWN_ISSUES.md, "EVM state lived in a per-node trie").

Native tokens (qrdx/exchange/tokens.py) are part of the same world: ``tokens`` is a
``native_token_evm.TokenWorld``, and the state journals token moves so a reverted call undoes
them (``WorldState``).
"""

from __future__ import annotations

import contextvars
from collections.abc import Mapping
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, cast

from eth.abc import AccountDatabaseAPI, MetaWitnessAPI
from eth.constants import BLANK_ROOT_HASH, EMPTY_SHA3
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.db.witness import MetaWitness
from eth.validation import (
    validate_canonical_address,
    validate_is_bytes,
    validate_uint64,
    validate_uint256,
)
from eth.vm.forks.qrdx.computation import QRDXComputation
from eth.vm.forks.qrdx.state import QRDXState
from eth_hash.auto import keccak
from eth_typing import Address, Hash32
from eth_utils import ValidationError
from greenlet import greenlet

from ..crypto.account_id import to_account_id

# ``run_sync`` re-runs an execution once per miss (``run`` loads in place and never re-runs);
# each re-run loads at least one more item, and gas bounds what one execution can touch.
MAX_LOAD_ROUNDS = 100_000
EMPTY_CODE = b""
# What a native token's or NFT collection's address reports as its code: its precompile runs
# instead of any code, but a non-zero EXTCODESIZE lets Solidity call functions that return
# nothing (ERC-721 transfers, ERC-777 send). Never written back (INVALID if it ever ran).
NATIVE_STUB_CODE = b"\xfe"


class StateMiss(Exception):
    """The execution read state that is not loaded; load it and run again."""

    def __init__(
        self,
        accounts: Iterable[bytes] = (),
        slots: Iterable[Tuple[bytes, int]] = (),
        tokens: Iterable[Tuple[str, str]] = (),
        roots: Iterable[int] = (),
    ):
        self.accounts = set(accounts)
        self.slots = set(slots)
        self.tokens = set(tokens)
        self.roots = set(roots)  # heights whose signed state root is needed (state proofs)
        super().__init__(
            f"state not loaded: {len(self.accounts)} account(s), "
            f"{len(self.slots)} slot(s), {len(self.tokens)} token balance(s)"
        )


def _hex(address: bytes) -> str:
    return "0x" + bytes(address).hex()


Record = Tuple[int, int, bytes]  # (balance, nonce, code)


class WorldAccountDB(AccountDatabaseAPI):
    """py-evm's account database as dictionaries over the world, journaled for the EVM's call
    frames. It has the semantics of ``eth.db.account.AccountDB`` on a state seeded with what
    the world holds, including those gas depends on:

    * an account exists once anything is written to it, even nothing (``touch_account``, which
      every message does, and ``delete_storage``, which every CREATE does);
    * an account that holds nothing (no balance, nonce or code) when the execution begins has
      no storage;
    * a slot's *original* value (EIP-2200) is its value when the execution began — or 0 once
      the account's storage was deleted and until that is reverted;
    * warm accounts and slots (EIP-2929) are journaled with everything else.

    State roots are not computed here (the account store computes its own): ``state_root`` is
    the empty root throughout."""

    world: Optional["EvmWorld"] = None  # set by EvmWorld.build_state

    def __init__(self, db: Any = None, state_root: Hash32 = BLANK_ROOT_HASH) -> None:
        self._records: Dict[bytes, Optional[Record]] = {}  # written this execution; None = gone
        self._storage: Dict[bytes, Dict[int, int]] = {}  # slots written since the last wipe
        self._wiped: Set[bytes] = set()  # storage deleted this execution
        self._warm: Set[Any] = set()
        self._log: List[Tuple[Any, ...]] = []  # undo entries, while a checkpoint is open
        self._checkpoints: List[Tuple[int, int]] = []  # (checkpoint, log length)
        self._next_checkpoint = 0
        self._locked: Optional[Tuple[Dict[bytes, Dict[int, int]], Set[bytes]]] = None

    # -- the world underneath ------------------------------------------------

    def _base(self, address: bytes) -> Record:
        world = self.world
        if world is None:
            return (0, 0, EMPTY_CODE)
        record = world.accounts.get(address)
        if record is None:
            world.need(accounts=[address])
            record = world.accounts[address]
        return record

    def _base_slot(self, address: bytes, slot: int) -> int:
        base = self._base(address)
        if not (base[0] or base[1] or base[2]):
            return 0  # an account that held nothing has no storage (never seeded)
        world = cast("EvmWorld", self.world)
        key = (address, slot)
        if key not in world.storage:
            world.need(slots=[key])
        return world.storage[key]

    def _record(self, address: bytes) -> Optional[Record]:
        if address in self._records:
            return self._records[address]
        base = self._base(address)
        return base if (base[0] or base[1] or base[2]) else None

    # -- the journal -----------------------------------------------------------

    def _note(self, entry: Tuple[Any, ...]) -> None:
        if self._checkpoints:
            self._log.append(entry)

    def _set_record(self, address: bytes, record: Optional[Record]) -> None:
        self._note(("record", address, address in self._records, self._records.get(address)))
        self._records[address] = record

    def _wipe(self, address: bytes) -> None:
        self._note(("wipe", address, self._storage.get(address), address in self._wiped))
        self._storage[address] = {}
        self._wiped.add(address)

    def _undo(self, entry: Tuple[Any, ...]) -> None:
        kind = entry[0]
        if kind == "record":
            _, address, had, old = entry
            if had:
                self._records[address] = old
            else:
                self._records.pop(address, None)
        elif kind == "slot":
            _, address, slot, had, old = entry
            slots = self._storage.setdefault(address, {})
            if had:
                slots[slot] = old
            else:
                slots.pop(slot, None)
        elif kind == "wipe":
            _, address, old, was_wiped = entry
            if old is None:
                self._storage.pop(address, None)
            else:
                self._storage[address] = old
            if not was_wiped:
                self._wiped.discard(address)
        elif kind == "warm":
            self._warm.discard(entry[1])

    def record(self) -> Any:
        checkpoint = self._next_checkpoint
        self._next_checkpoint += 1
        self._checkpoints.append((checkpoint, len(self._log)))
        return checkpoint

    def _find(self, checkpoint: Any) -> int:
        for i in range(len(self._checkpoints) - 1, -1, -1):
            if self._checkpoints[i][0] == checkpoint:
                return i
        raise ValidationError(f"checkpoint {checkpoint} is not open")

    def discard(self, checkpoint: Any) -> None:
        i = self._find(checkpoint)
        length = self._checkpoints[i][1]
        while len(self._log) > length:
            self._undo(self._log.pop())
        del self._checkpoints[i:]

    def commit(self, checkpoint: Any) -> None:
        del self._checkpoints[self._find(checkpoint) :]
        if not self._checkpoints:
            self._log.clear()

    def lock_changes(self) -> None:
        """End of a transaction: its changes become the next one's original values and can no
        longer be reverted, and nothing is warm."""
        self._locked = (
            {address: dict(slots) for address, slots in self._storage.items()},
            set(self._wiped),
        )
        self._warm.clear()
        self._log.clear()
        self._checkpoints.clear()

    # -- roots (computed by the account store, not here) -----------------------

    @property
    def state_root(self) -> Hash32:
        return BLANK_ROOT_HASH

    @state_root.setter
    def state_root(self, value: Hash32) -> None:
        pass

    def has_root(self, state_root: bytes) -> bool:
        return state_root == BLANK_ROOT_HASH

    def make_state_root(self) -> Hash32:
        return BLANK_ROOT_HASH

    def persist(self) -> MetaWitnessAPI:
        return MetaWitness(set(), {})

    # -- storage ----------------------------------------------------------------

    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(slot, title="Storage Slot")
        world = self.world
        if world is not None:
            world.touched_slots.add((address, slot))
        if from_journal:
            slots = self._storage.get(address)
            if slots is not None and slot in slots:
                return slots[slot]
            if address in self._wiped:
                return 0
            return self._base_slot(address, slot)
        if self._locked is not None:
            locked, locked_wiped = self._locked
            if address in locked and slot in locked[address]:
                return locked[address][slot]
            if address in locked_wiped:
                return 0
        if address in self._wiped:
            return 0  # deleted storage: py-evm reads originals from the emptied trie
        return self._base_slot(address, slot)

    def set_storage(self, address: Address, slot: int, value: int) -> None:
        validate_uint256(value, title="Storage Value")
        validate_uint256(slot, title="Storage Slot")
        validate_canonical_address(address, title="Storage Address")
        world = self.world
        if world is not None:
            world.touched_slots.add((address, slot))
            if address not in self._wiped:
                self._base_slot(address, slot)  # loaded, so writing it back compares exactly
        slots = self._storage.setdefault(address, {})
        self._note(("slot", address, slot, slot in slots, slots.get(slot)))
        slots[slot] = value

    def delete_storage(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        self._set_record(address, self._record(address) or (0, 0, EMPTY_CODE))
        self._wipe(address)

    def is_storage_warm(self, address: Address, slot: int) -> bool:
        return (address, slot) in self._warm

    def mark_storage_warm(self, address: Address, slot: int) -> None:
        key = (address, slot)
        if key not in self._warm:
            self._warm.add(key)
            self._note(("warm", key))

    # -- balance, nonce, code ----------------------------------------------------

    def get_balance(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")
        record = self._record(address)
        return record[0] if record else 0

    def set_balance(self, address: Address, balance: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(balance, title="Account Balance")
        _, nonce, code = self._record(address) or (0, 0, EMPTY_CODE)
        self._set_record(address, (balance, nonce, code))

    def get_nonce(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")
        record = self._record(address)
        return record[1] if record else 0

    def set_nonce(self, address: Address, nonce: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint64(nonce, title="Nonce")
        balance, _, code = self._record(address) or (0, 0, EMPTY_CODE)
        self._set_record(address, (balance, nonce, code))

    def increment_nonce(self, address: Address) -> None:
        self.set_nonce(address, self.get_nonce(address) + 1)

    def get_code(self, address: Address) -> bytes:
        validate_canonical_address(address, title="Storage Address")
        record = self._record(address)
        code = record[2] if record else EMPTY_CODE
        world = self.world
        if not code and world is not None and world.is_native(address):
            return NATIVE_STUB_CODE
        return code

    def set_code(self, address: Address, code: bytes) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_is_bytes(code, title="Code")
        balance, nonce, _ = self._record(address) or (0, 0, EMPTY_CODE)
        self._set_record(address, (balance, nonce, bytes(code)))

    def get_code_hash(self, address: Address) -> Hash32:
        validate_canonical_address(address, title="Storage Address")
        record = self._record(address)
        return Hash32(keccak(record[2])) if record and record[2] else EMPTY_SHA3

    def delete_code(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        balance, nonce, _ = self._record(address) or (0, 0, EMPTY_CODE)
        self._set_record(address, (balance, nonce, EMPTY_CODE))

    # -- accounts -----------------------------------------------------------------

    def account_has_code_or_nonce(self, address: Address) -> bool:
        return self.get_nonce(address) != 0 or self.get_code_hash(address) != EMPTY_SHA3

    def delete_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        self._record(address)  # loaded, so writing it back removes it
        self._wipe(address)
        self._set_record(address, None)

    def account_exists(self, address: Address) -> bool:
        validate_canonical_address(address, title="Storage Address")
        return self._record(address) is not None

    def touch_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        self._set_record(address, self._record(address) or (0, 0, EMPTY_CODE))

    def account_is_empty(self, address: Address) -> bool:
        return not self.account_has_code_or_nonce(address) and self.get_balance(address) == 0

    def is_address_warm(self, address: Address) -> bool:
        return address in self._warm

    def mark_address_warm(self, address: Address) -> None:
        if address not in self._warm:
            self._warm.add(address)
            self._note(("warm", address))


# Precompiles py-evm runs in pure Python far slower than their Ethereum gas prices assume
# (Ethereum clients run them natively): each is charged extra here so that, like everything
# else, a block's worth of them executes at least as fast as the cheapest instructions do
# (~1.9 Mgas/s: docs/BLOCK_LIMITS.md, measured with scripts/bench/evm_gas.py). Without it, a block
# of bn128 pairings would take ~6 s on every node. Extra gas = per-call + per-input-unit.
# Verifies a proof of one account, storage slot or token balance against an ancestor block's
# signed state root (qrdx/contracts/state_proof_evm.py, docs/STATE_PROOFS.md).
STATE_PROOF_ADDRESS = (0x0300).to_bytes(20, "big")
# getChainState: a source chain's finalized head as validators attested it (consensus state,
# qrdx/exchange/bridge.py) — in place of the fork's module-level table, which a node could
# fill from its own observations (docs/KNOWN_ISSUES.md).
CHAIN_STATE_ADDRESS = (0x0200).to_bytes(20, "big")
# verifyExternalProof: an account (and slot) on a bridged chain, proven against an attested head
# (qrdx/contracts/external_proof_evm.py) — in place of the fork's, which fails closed.
EXTERNAL_PROOF_ADDRESS = (0x0201).to_bytes(20, "big")  # (0x0100-0x0104: retired; 0x0200: oracle)
# The exchange from a contract (qrdx/contracts/exchange_evm.py): read its state, and send actions
# as the contract's account (run at the start of the next block).
EXCHANGE_READ_ADDRESS = (0x0400).to_bytes(20, "big")
EXCHANGE_WRITE_ADDRESS = (0x0401).to_bytes(20, "big")
BN128_MUL_ADDRESS = (7).to_bytes(20, "big")
BN128_PAIRING_ADDRESS = (8).to_bytes(20, "big")
BN128_MUL_SURCHARGE = 12_000  # 6,000 → 18,000 (py_ecc: ~8.5 ms a multiplication)
BN128_PAIRING_SURCHARGE_PER_PAIR = 316_000  # 34,000 → 350,000 a pair (~180 ms a pair)
_PAIR_SIZE = 192


def chain_state_precompile(computation):
    """0x0200 ``getChainState(chain_id)``: the source chain's attested finalized head — height (8)
    · hash (32) · state root (32) · timestamp (8) — or 80 zero bytes if none is attested. Read
    from the exchange's consensus state as of this point of the block, so it is the same on every
    node."""
    from eth.vm.forks.qrdx.precompiles import GAS_ORACLE_GET_CHAIN_STATE

    from ..exchange.state_manager import ExchangeStateManager

    computation.consume_gas(GAS_ORACLE_GET_CHAIN_STATE, reason="getChainState")
    data = bytes(computation.msg.data_as_bytes)
    head = None
    if len(data) >= 4:
        head = ExchangeStateManager.get_instance().bridge.head(int.from_bytes(data[:4], "big"))
    if head is None:
        computation.output = bytes(80)
    else:
        computation.output = (
            head.height.to_bytes(8, "big")
            + bytes.fromhex(head.hash[2:])
            + bytes.fromhex(head.state_root[2:])
            + head.timestamp.to_bytes(8, "big")
        )
    return computation


def _surcharged(precompile, extra):
    def run(computation):
        computation.consume_gas(extra(computation.msg.data), reason="QRDX precompile surcharge")
        return precompile(computation)

    return run


_SURCHARGES = {
    BN128_MUL_ADDRESS: lambda data: BN128_MUL_SURCHARGE,
    BN128_PAIRING_ADDRESS: lambda data: BN128_PAIRING_SURCHARGE_PER_PAIR
    * (len(data) // _PAIR_SIZE),
}


class _WorldPrecompiles(Mapping):
    """The fork's precompiles — the slow ones surcharged — plus every native token's and NFT
    collection's address (when tokens are in play)."""

    def __init__(self, base, tokens):
        self.base, self.tokens = base, tokens
        self._wrapped = {
            address: _surcharged(base[address], extra)
            for address, extra in _SURCHARGES.items()
            if address in base
        }

    def get(self, address, default=None):
        if address == CHAIN_STATE_ADDRESS:  # (before the fork's own: see the constant)
            return chain_state_precompile
        if address == EXTERNAL_PROOF_ADDRESS:
            from .external_proof_evm import external_proof_precompile

            return external_proof_precompile
        fn = self._wrapped.get(address) or self.base.get(address)
        if fn is not None:
            return fn
        if address == STATE_PROOF_ADDRESS:
            from .state_proof_evm import state_proof_precompile

            return state_proof_precompile
        if address == EXCHANGE_READ_ADDRESS:
            from .exchange_evm import exchange_read_precompile

            return exchange_read_precompile
        if address == EXCHANGE_WRITE_ADDRESS:
            from .exchange_evm import exchange_write_precompile

            return exchange_write_precompile
        tokens = self.tokens
        if tokens is None:
            return default
        if tokens.is_token(address):
            from .native_token_evm import native_token_precompile

            return native_token_precompile
        if tokens.is_collection(address):
            from .nft_evm import nft_precompile

            return nft_precompile
        return default

    def __getitem__(self, address):
        fn = self.get(address)
        if fn is None:
            raise KeyError(address)
        return fn

    def __contains__(self, address):
        return self.get(address) is not None

    def __iter__(self):
        return iter(self.base)

    def __len__(self):
        return len(self.base)


class WorldComputation(QRDXComputation):
    @property
    def precompiles(self):
        return _WorldPrecompiles(super().precompiles, getattr(self.state, "native_tokens", None))


class WorldState(QRDXState):
    """QRDX state over the world: account reads go through ``WorldAccountDB``, and native token
    moves are journaled so that a reverted call frame undoes them like any other state."""

    account_db_class = WorldAccountDB
    computation_class = WorldComputation

    def __init__(self, *args, **kwargs):
        self.token_journal: list = []
        self.native_tokens = None
        super().__init__(*args, **kwargs)

    def snapshot(self):
        return super().snapshot(), len(self.token_journal)

    def revert(self, snapshot) -> None:
        inner, journal_length = snapshot
        del self.token_journal[journal_length:]
        super().revert(inner)

    def commit(self, snapshot) -> None:
        inner, _ = snapshot
        super().commit(inner)


class EvmWorld:
    """What one execution may see: accounts and storage slots loaded from the state manager.
    A read of anything not loaded raises StateMiss; ``run`` loads it from the manager (pending
    changes over the database) and starts again. ``run_sync`` — for legacy synchronous callers —
    loads from the manager's cache only, as the old executor read it."""

    def __init__(self, state_manager, tokens=None):
        self.sm = state_manager
        self.tokens = tokens
        self.accounts: Dict[bytes, Tuple[int, int, bytes]] = {}  # address → (balance, nonce, code)
        self.storage: Dict[Tuple[bytes, int], int] = {}  # loaded slots
        self.touched_slots: Set[Tuple[bytes, int]] = set()
        # height → the block's signed state root (None: no such block, or none signed)
        self.header_roots: Dict[int, Optional[str]] = {}
        self._loader: Optional[greenlet] = None  # where ``need`` switches to, under ``run``

    # -- loading ------------------------------------------------------------

    def has_slot(self, address: bytes, slot: int) -> bool:
        return (address, slot) in self.storage

    def need(self, accounts=(), slots=(), tokens=(), roots=()) -> None:
        """Make sure these are loaded before the execution reads them: in place under ``run``
        (switching to it while it loads them), by raising StateMiss under ``run_sync``."""
        miss = StateMiss(accounts, slots, tokens, roots)
        if self._loader is None:
            raise miss
        self._loader.switch(miss)

    def load_sync(self, miss: StateMiss) -> None:
        """Load from the manager's cache only (legacy synchronous callers)."""
        for address in miss.accounts | {a for a, _ in miss.slots}:
            if address not in self.accounts:
                h = _hex(address)
                code = self.sm.get_code_sync(h) or EMPTY_CODE
                self.accounts[address] = (
                    self.sm.get_balance_sync(h),
                    self.sm.get_nonce_sync(h),
                    bytes(code),
                )
        for address, slot in miss.slots:
            raw = self.sm.get_storage_sync(_hex(address), int(slot).to_bytes(32, "big"))
            self.storage[(address, slot)] = int.from_bytes(raw, "big")
        if miss.tokens:
            raise RuntimeError("native token balances need an async loader (use run)")
        for height in miss.roots:  # (no database here: a proof against it does not verify)
            self.header_roots.setdefault(height, None)

    async def load_account(self, address: bytes) -> None:
        if address in self.accounts:
            return
        h = _hex(address)
        account = await self.sm.get_account(h)
        code = await self.sm.get_code(h) if account.code_hash else EMPTY_CODE
        self.accounts[address] = (int(account.balance), int(account.nonce), bytes(code or b""))

    async def load_slot(self, address: bytes, slot: int) -> None:
        if (address, slot) in self.storage:
            return
        raw = await self.sm.get_storage(_hex(address), int(slot).to_bytes(32, "big"))
        self.storage[(address, slot)] = int.from_bytes(raw, "big")

    async def load(self, miss: StateMiss) -> None:
        for address in sorted(miss.accounts):
            await self.load_account(address)
        for address, slot in sorted(miss.slots):
            await self.load_account(address)
            await self.load_slot(address, slot)
        if miss.tokens and self.tokens is not None:
            await self.tokens.load(miss.tokens)
        for height in sorted(miss.roots):
            if height not in self.header_roots:
                self.header_roots[height] = await self._signed_root(height)

    async def _signed_root(self, height: int) -> Optional[str]:
        """The state root block ``height`` of this chain signed (its header's ``state_root``)."""
        db = getattr(self.sm, "db", None)
        if db is None:
            return None
        try:
            block = await db.get_block_by_id(int(height))
            if not block:
                return None
            from ..validator.block_verification import _parse_block_content

            root = _parse_block_content(block.get("content")).get("state_root")
            return str(root) if root else None
        except Exception:
            return None

    def is_native(self, address) -> bool:
        """Is ``address`` a native token or NFT collection (its precompile, not code)?"""
        tokens = self.tokens
        return tokens is not None and (tokens.is_token(address) or tokens.is_collection(address))

    # -- a state for one execution ------------------------------------------

    def build_state(self, execution_context) -> WorldState:
        """A fresh state over the world: it reads what is loaded, and what is not through
        ``need``."""
        state = WorldState(AtomicDB(MemoryDB()), execution_context, BLANK_ROOT_HASH)
        cast(WorldAccountDB, state._account_db).world = self  # WorldState.account_db_class
        state.native_tokens = self.tokens
        return state

    # -- writing back -------------------------------------------------------

    def write_back(self, state: WorldState, always: Iterable[bytes] = ()) -> None:
        """Every change the execution made, into the state manager. ``always`` are written even
        when unchanged (the sender, whose gas the executor then charges from the manager)."""
        sm = self.sm
        forced = set(always)
        for address, (balance, nonce, code) in sorted(self.accounts.items()):
            h = _hex(address)
            existed = bool(balance or nonce or code)
            address = Address(address)
            if not state.account_exists(address):
                if existed:
                    sm.destroy_sync(h)
                elif address in forced:
                    sm.set_balance_sync(h, 0)
                    sm.set_nonce_sync(h, 0)
                continue
            final_balance = state.get_balance(address)
            final_nonce = state.get_nonce(address)
            final_code = state.get_code(address)
            if final_balance != balance or address in forced:
                sm.set_balance_sync(h, final_balance)
            if final_nonce != nonce or address in forced:
                sm.set_nonce_sync(h, final_nonce)
            if final_code != code and not (
                final_code == NATIVE_STUB_CODE and self.is_native(address)
            ):
                sm.set_code_sync(h, final_code)
        for address, slot in sorted(self.touched_slots | set(self.storage)):
            if address not in self.accounts or not state.account_exists(Address(address)):
                continue
            before = self.storage.get((address, slot), 0)
            after = state.get_storage(Address(address), slot)
            if after != before:
                sm.set_storage_sync(
                    _hex(address), int(slot).to_bytes(32, "big"), int(after).to_bytes(32, "big")
                )


async def run(world: EvmWorld, execute, preload: Iterable[bytes] = ()):
    """Run ``execute()`` (a synchronous EVM execution over ``world``) in a greenlet: whenever it
    needs something not loaded, it switches back here, the world loads it, and the execution
    resumes where it stopped. (A StateMiss raised outright — by code that does not go through
    ``need`` — is loaded and the execution started again.)"""
    for address in preload:
        if address:
            await world.load_account(bytes(address))
    for _ in range(MAX_LOAD_ROUNDS):
        child = greenlet(execute)
        child.gr_context = contextvars.copy_context()  # a new greenlet's context is empty
        world._loader = greenlet.getcurrent()
        try:
            result = child.switch()
            while not child.dead:
                await world.load(result)  # what the execution needs
                result = child.switch()
            return result
        except StateMiss as miss:
            await world.load(miss)
        finally:
            world._loader = None
    raise RuntimeError("EVM execution kept needing more state")


def run_sync(world: EvmWorld, execute):
    """``run`` for synchronous callers: loads from the state manager's cache."""
    for _ in range(MAX_LOAD_ROUNDS):
        try:
            return execute()
        except StateMiss as miss:
            world.load_sync(miss)
    raise RuntimeError("EVM execution kept needing more state")


def account_id(address: bytes) -> str:
    return to_account_id(bytes(address))
