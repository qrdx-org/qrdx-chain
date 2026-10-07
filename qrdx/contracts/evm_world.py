"""
EVM execution state, loaded on demand from the canonical account store.

Every EVM execution — a block's transactions, ``eth_call``, gas estimation — runs on a fresh
py-evm state populated from the ContractStateManager (this block's pending changes over the
database). Anything the execution reads that is not loaded yet raises ``StateMiss``; the async
caller loads it and runs the execution again from the start (``run``), so the result is exactly
what it would be had everything been loaded up front. When it finishes, every account and
storage slot it touched is written back to the state manager, and from there to the database.

It replaced a persistent per-node in-memory trie into which only a transaction's sender and
recipient were copied, and from which only their balances and nonces were copied back.
Contract storage never reached the database or the state root, a contract's payment to any
other account was lost the next time that account transacted, code a contract created was not
saved, and a reorg or restart left the trie disagreeing with the chain (docs/KNOWN_ISSUES.md,
"EVM state lived in a per-node trie").

Native tokens (qrdx/exchange/tokens.py) are part of the same world: ``tokens`` is a
``native_token_evm.TokenWorld``, and the state journals token moves so a reverted call undoes
them (``WorldState``).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from eth.constants import BLANK_ROOT_HASH
from eth.db.account import AccountDB
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.vm.forks.qrdx.computation import QRDXComputation
from eth.vm.forks.qrdx.state import QRDXState

from ..crypto.account_id import to_account_id

# A touched account's whole storage is loaded at once when it has at most this many slots
# (otherwise slot by slot): fewer re-runs, the same result either way.
FULL_STORAGE_LIMIT = 4096
# Each re-run loads at least one more item; gas bounds what one execution can touch.
MAX_LOAD_ROUNDS = 100_000
EMPTY_CODE = b""
# What a native token's or NFT collection's address reports as its code: its precompile runs
# instead of any code, but a non-zero EXTCODESIZE lets Solidity call functions that return
# nothing (ERC-721 transfers, ERC-777 send). Never written back (INVALID if it ever ran).
NATIVE_STUB_CODE = b"\xfe"


class StateMiss(Exception):
    """The execution read state that is not loaded; load it and run again."""

    def __init__(self, accounts: Iterable[bytes] = (), slots: Iterable[Tuple[bytes, int]] = (),
                 tokens: Iterable[Tuple[str, str]] = ()):
        self.accounts = set(accounts)
        self.slots = set(slots)
        self.tokens = set(tokens)
        super().__init__(f"state not loaded: {len(self.accounts)} account(s), "
                         f"{len(self.slots)} slot(s), {len(self.tokens)} token balance(s)")


def _hex(address: bytes) -> str:
    return "0x" + bytes(address).hex()


class WorldAccountDB(AccountDB):
    """py-evm's account database, refusing to read what the world has not loaded."""

    world: Optional["EvmWorld"] = None

    def _get_encoded_account(self, address, from_journal: bool = True) -> bytes:
        world = self.world
        if world is not None and address not in world.accounts:
            raise StateMiss(accounts=[address])
        return super()._get_encoded_account(address, from_journal)

    def get_code(self, address) -> bytes:
        code = super().get_code(address)
        world = self.world
        if not code and world is not None and world.is_native(address):
            return NATIVE_STUB_CODE
        return code

    def get_storage(self, address, slot: int, from_journal: bool = True) -> int:
        world = self.world
        if world is not None:
            if not world.has_slot(address, slot):
                raise StateMiss(slots=[(address, slot)])
            world.touched_slots.add((address, slot))
        return super().get_storage(address, slot, from_journal)


class _PrecompilesWithTokens(Mapping):
    """The fork's precompiles, plus every native token's and NFT collection's address (when
    tokens are in play)."""

    def __init__(self, base, tokens):
        self.base, self.tokens = base, tokens

    def get(self, address, default=None):
        fn = self.base.get(address)
        if fn is not None:
            return fn
        if self.tokens.is_token(address):
            from .native_token_evm import native_token_precompile
            return native_token_precompile
        if self.tokens.is_collection(address):
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
        tokens = getattr(self.state, "native_tokens", None)
        base = super().precompiles
        return base if tokens is None else _PrecompilesWithTokens(base, tokens)


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
        self.accounts: Dict[bytes, Tuple[int, int, bytes]] = {}   # address → (balance, nonce, code)
        self.storage: Dict[Tuple[bytes, int], int] = {}           # loaded non-zero/known slots
        self.full_storage: Set[bytes] = set()                     # every slot of these is loaded
        self.touched_slots: Set[Tuple[bytes, int]] = set()

    # -- loading ------------------------------------------------------------

    def has_slot(self, address: bytes, slot: int) -> bool:
        return (address, slot) in self.storage or address in self.full_storage

    def load_sync(self, miss: StateMiss) -> None:
        """Load from the manager's cache only (legacy synchronous callers)."""
        for address in miss.accounts | {a for a, _ in miss.slots}:
            if address not in self.accounts:
                h = _hex(address)
                code = self.sm.get_code_sync(h) or EMPTY_CODE
                self.accounts[address] = (self.sm.get_balance_sync(h), self.sm.get_nonce_sync(h),
                                          bytes(code))
        for address, slot in miss.slots:
            raw = self.sm.get_storage_sync(_hex(address), int(slot).to_bytes(32, "big"))
            self.storage[(address, slot)] = int.from_bytes(raw, "big")
        if miss.tokens:
            raise RuntimeError("native token balances need an async loader (use run)")

    async def load_account(self, address: bytes) -> None:
        if address in self.accounts:
            return
        h = _hex(address)
        account = await self.sm.get_account(h)
        code = await self.sm.get_code(h) if account.code_hash else EMPTY_CODE
        self.accounts[address] = (int(account.balance), int(account.nonce), bytes(code or b""))
        slots = await self.sm.get_all_storage(h, limit=FULL_STORAGE_LIMIT)
        if slots is not None:
            for key, value in slots.items():
                self.storage[(address, int.from_bytes(key, "big"))] = int.from_bytes(value, "big")
            self.full_storage.add(address)

    async def load_slot(self, address: bytes, slot: int) -> None:
        if (address, slot) in self.storage or address in self.full_storage:
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

    def is_native(self, address) -> bool:
        """Is ``address`` a native token or NFT collection (its precompile, not code)?"""
        tokens = self.tokens
        return tokens is not None and (tokens.is_token(address) or tokens.is_collection(address))

    # -- a state for one execution ------------------------------------------

    def build_state(self, execution_context) -> WorldState:
        """A fresh state holding exactly what is loaded, read through the world."""
        db = AtomicDB(MemoryDB())
        seed = WorldState(db, execution_context, BLANK_ROOT_HASH)
        for address, (balance, nonce, code) in self.accounts.items():
            if not (balance or nonce or code):
                continue                       # an empty account stays absent (EIP-161)
            seed.set_balance(address, balance)
            seed.set_nonce(address, nonce)
            if code:
                seed.set_code(address, code)
        for (address, slot), value in self.storage.items():
            if value and address in self.accounts and any(self.accounts[address]):
                seed.set_storage(address, slot, value)
        seed.persist()
        state = WorldState(db, execution_context, seed.state_root)
        state._account_db.world = self
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
            if final_code != code and not (final_code == NATIVE_STUB_CODE
                                           and self.is_native(address)):
                sm.set_code_sync(h, final_code)
        for address, slot in sorted(self.touched_slots | set(self.storage)):
            if address not in self.accounts or not state.account_exists(address):
                continue
            before = self.storage.get((address, slot), 0)
            after = state.get_storage(address, slot)
            if after != before:
                sm.set_storage_sync(_hex(address), int(slot).to_bytes(32, "big"),
                                    int(after).to_bytes(32, "big"))


async def run(world: EvmWorld, execute, preload: Iterable[bytes] = ()):
    """Run ``execute()`` (a synchronous EVM execution over ``world``) until nothing it needs is
    missing: each StateMiss is loaded and the execution starts again from the beginning."""
    for address in preload:
        if address:
            await world.load_account(bytes(address))
    for _ in range(MAX_LOAD_ROUNDS):
        try:
            return execute()
        except StateMiss as miss:
            await world.load(miss)
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
