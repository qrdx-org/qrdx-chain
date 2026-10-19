"""
The flat, load-in-place EVM world executes exactly as the trie-backed one it replaced
(qrdx/contracts/evm_world.py).

The old world ran on py-evm's own ``AccountDB``, seeded with everything loaded so far, and
started the execution over whenever it read something not loaded — O(n²) for n accounts. The
new one is a journaled dictionary state that loads what it misses in place. Both are run here
side by side on random contracts that exercise what the account database decides: storage
written and restored to its original value (EIP-2200 refunds), warm and cold accounts and slots
(EIP-2929), nested, reverting and static calls, CREATE and CREATE2 (collisions included),
SELFDESTRUCT, value transfers to new accounts, logs. Every transaction's result, gas and logs,
and the account store's root after each one, must be identical.
"""
import os
import random
import tempfile

import pytest
from eth.constants import BLANK_ROOT_HASH
from eth.db.account import AccountDB
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth_typing import Address

from qrdx.contracts import evm_world as W
from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
from qrdx.contracts.native_token_evm import EvmSection, TokenWorld
from qrdx.contracts.state import ContractStateManager
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeStateManager


# ── the world as it was (trie-backed, restart on every miss) ─────────────────

class TrieAccountDB(AccountDB):
    """py-evm's account database, refusing to read what the world has not loaded."""

    world = None

    def _get_encoded_account(self, address, from_journal=True):
        world = self.world
        if world is not None and address not in world.accounts:
            raise W.StateMiss(accounts=[address])
        return super()._get_encoded_account(address, from_journal)

    def get_code(self, address):
        code = super().get_code(address)
        world = self.world
        if not code and world is not None and world.is_native(address):
            return W.NATIVE_STUB_CODE
        return code

    def get_storage(self, address, slot, from_journal=True):
        world = self.world
        if world is not None:
            if (address, slot) not in world.storage:
                raise W.StateMiss(slots=[(address, slot)])
            world.touched_slots.add((address, slot))
        return super().get_storage(address, slot, from_journal)


class TrieState(W.WorldState):
    account_db_class = TrieAccountDB


class TrieWorld(W.EvmWorld):
    def need(self, accounts=(), slots=(), tokens=()):
        raise W.StateMiss(accounts, slots, tokens)

    def build_state(self, execution_context):
        db = AtomicDB(MemoryDB())
        seed = TrieState(db, execution_context, BLANK_ROOT_HASH)
        for address, (balance, nonce, code) in self.accounts.items():
            if not (balance or nonce or code):
                continue
            seed.set_balance(Address(address), balance)
            seed.set_nonce(Address(address), nonce)
            if code:
                seed.set_code(Address(address), code)
        for (address, slot), value in self.storage.items():
            if value and address in self.accounts and any(self.accounts[address]):
                seed.set_storage(Address(address), slot, value)
        seed.persist()
        state = TrieState(db, execution_context, seed.state_root)
        state._account_db.world = self
        state.native_tokens = self.tokens
        return state


async def trie_run(world, execute, preload=()):
    for address in preload:
        if address:
            await world.load_account(bytes(address))
    for _ in range(W.MAX_LOAD_ROUNDS):
        try:
            return execute()
        except W.StateMiss as miss:
            await world.load(miss)
    raise RuntimeError("EVM execution kept needing more state")


# ── random contracts ─────────────────────────────────────────────────────────

def a(i):
    return bytes([0xC0 + i]) + bytes(19)


EOAS = [bytes([0xE0 + i]) * 20 for i in range(3)]
CONTRACTS = [a(i) for i in range(6)]
FRESH = [bytes([0xF0 + i]) * 20 for i in range(6)]
PRECOMPILES = [bytes(19) + bytes([i]) for i in (1, 2, 4)]
EVERYONE = EOAS + CONTRACTS + FRESH + PRECOMPILES


def push(n, width=None):
    width = width or max(1, (n.bit_length() + 7) // 8)
    return bytes([0x5F + width]) + n.to_bytes(width, "big")


INIT = bytes.fromhex("602a600055" "6000600053" "60016000f3")   # slot 0 := 42; runtime "00"


def snippet(rng):
    kind = rng.choice(["sload", "sstore", "sstore", "balance", "extcode", "call", "call",
                       "static", "delegate", "create", "create2", "log", "selfbalance"])
    slot = rng.randrange(4)
    target = rng.choice(EVERYONE)
    gas = push(rng.choice([0, 3_000, 30_000, 120_000]), 3)
    if kind == "sload":
        return push(slot) + b"\x54\x50"
    if kind == "sstore":
        return push(rng.choice([0, 1, 7, 42])) + push(slot) + b"\x55"
    if kind == "balance":
        return b"\x73" + target + b"\x31\x50"
    if kind == "extcode":
        return b"\x73" + target + rng.choice([b"\x3b", b"\x3f"]) + b"\x50"
    if kind == "call":
        value = push(rng.choice([0, 0, 1, 5]))
        return (push(0) * 4) + value + b"\x73" + target + gas + b"\xf1\x50"
    if kind == "static":
        return (push(0) * 4) + b"\x73" + target + gas + b"\xfa\x50"
    if kind == "delegate":
        return (push(0) * 4) + b"\x73" + target + gas + b"\xf4\x50"
    if kind == "create":
        return b"\x6e" + INIT + push(0) + b"\x52" + push(15) + push(17) + push(rng.randrange(2)) \
            + b"\xf0\x50"
    if kind == "create2":
        return push(rng.randrange(2)) + b"\x6e" + INIT + push(0) + b"\x52" + push(15) + push(17) \
            + push(0) + b"\xf5\x50"
    if kind == "log":
        return push(slot) + push(0) + push(0) + b"\xa1"
    return b"\x47\x50"                                                     # SELFBALANCE


def contract(rng):
    code = b"".join(snippet(rng) for _ in range(rng.randrange(2, 9)))
    end = rng.random()
    if end < 0.2:
        return code + push(0) + push(0) + b"\xfd"                              # REVERT
    if end < 0.3:
        return code + b"\x73" + rng.choice(EVERYONE) + b"\xff"                 # SELFDESTRUCT
    return code + b"\x00"


def create_targets():
    """Where the contracts' CREATEs (first nonces) and CREATE2s (both salts) land — given a
    balance and storage beforehand, so a CREATE there wipes storage that exists (its original
    values then read 0: SSTORE's gas depends on it)."""
    import rlp
    from eth_hash.auto import keccak

    out = []
    for creator in CONTRACTS:
        out += [keccak(rlp.encode([creator, n]))[12:] for n in range(3)]
        out += [keccak(b"\xff" + creator + salt.to_bytes(32, "big") + keccak(INIT))[12:]
                for salt in range(2)]
    return out


# ── the two worlds, side by side ─────────────────────────────────────────────

class Node:
    def __init__(self, db, legacy):
        self.db, self.legacy = db, legacy
        self.sm = ContractStateManager(db)
        self.ex = QRDXEVMExecutor(self.sm)
        db.account_write_listeners = [self.sm.invalidate]
        self.height = 1

    async def setup(self, codes, storage):
        for who in EOAS:
            self.sm.set_balance_sync("0x" + who.hex(), 10 ** 21)
        for target in create_targets():
            self.sm.set_balance_sync("0x" + target.hex(), 1)
            for slot in range(2):
                self.sm.set_storage_sync("0x" + target.hex(), slot.to_bytes(32, "big"),
                                         (5).to_bytes(32, "big"))
        for addr, code in zip(CONTRACTS, codes):
            self.sm.set_balance_sync("0x" + addr.hex(), 10)
            self.sm.set_code_sync("0x" + addr.hex(), code)
            for slot, value in storage.get(addr, {}).items():
                self.sm.set_storage_sync("0x" + addr.hex(), slot.to_bytes(32, "big"),
                                         value.to_bytes(32, "big"))
        await self.sm.commit(self.height)
        await self.db.connection.commit()

    async def tx(self, sender, to, value, gas):
        self.height += 1
        self.sm.reset_cache()
        section = EvmSection()
        snap = await self.sm.snapshot()
        world = (TrieWorld if self.legacy else W.EvmWorld)(
            self.sm, tokens=TokenWorld(self.db, section))
        runner = trie_run if self.legacy else W.run
        r = await runner(world, lambda: self.ex.execute(
            sender, to, value, b"", gas, 0, world=world, block_number=self.height),
            preload=[sender, to])
        if not r.success:
            await self.sm.revert(snap)
        await self.sm.commit(self.height)
        await self.db.connection.commit()
        root = await self.db.get_account_state_root()
        return (r.success, r.gas_used, r.output, [tuple(x) for x in r.logs], r.error,
                r.created_address, root)


@pytest.fixture
async def nodes():
    paths, made = [], []
    ExchangeStateManager.reset_instance()
    for legacy in (True, False):
        path = tempfile.mktemp(suffix=".db")
        paths.append(path)
        made.append(Node(await DatabaseSQLite.create(db_path=path), legacy))
    yield made
    ExchangeStateManager.reset_instance()
    for node in made:
        await node.db.close()
    for path in paths:
        for p in (path, path + "-wal", path + "-shm"):
            if os.path.exists(p):
                os.remove(p)


SEEN = {"outcomes": set(), "transactions": 0}


@pytest.mark.parametrize("seed", range(12))
async def test_the_flat_world_executes_exactly_as_the_trie_world(nodes, seed):
    rng = random.Random(seed)
    codes = [contract(rng) for _ in CONTRACTS]
    storage = {addr: {s: rng.choice([1, 7, 42]) for s in range(4) if rng.random() < 0.5}
               for addr in CONTRACTS}
    trie, flat = nodes
    for node in nodes:
        await node.setup(codes, storage)
    for i in range(25):
        sender = rng.choice(EOAS)
        to = rng.choice(CONTRACTS + FRESH[:2])
        value, gas = rng.choice([0, 0, 3]), rng.choice([60_000, 200_000, 1_000_000])
        want = await trie.tx(sender, to, value, gas)
        got = await flat.tx(sender, to, value, gas)
        assert got == want, (seed, i, to.hex())
        SEEN["outcomes"].add(want[0])
        SEEN["transactions"] += 1


def test_the_random_transactions_both_succeeded_and_failed():
    """(Runs after the comparisons above: they must have covered both outcomes.)"""
    if not SEEN["transactions"]:
        pytest.skip("run with the comparisons")
    assert SEEN["outcomes"] == {True, False}
