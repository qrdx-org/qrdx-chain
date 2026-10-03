"""
EVM state is the account store (docs/KNOWN_ISSUES.md, "EVM state lived in a per-node trie").

The executor used to keep its own in-memory trie, copying in only a transaction's sender and
recipient and copying back only their balances and nonces: contract storage never reached the
database or the state root, a contract's payment to a third account was lost the next time
that account transacted, and a restart or reorg left the trie disagreeing with the chain.
Every execution now runs on a world loaded on demand from the state manager, and writes back
everything it touched. Native tokens are ERC-20s inside it (a precompile at each token's
address over the native ledger), journaled so a reverted call undoes them.

The contracts are hand-assembled (no compiler in the environment); each is described where
it is built.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
from qrdx.contracts.evm_world import EvmWorld, run
from qrdx.contracts.native_token_evm import (
    APPROVAL_TOPIC, TRANSFER_TOPIC, EvmSection, TokenWorld)
from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP

D = Decimal
ALICE = bytes.fromhex("a1" * 20)
BOB = bytes.fromhex("b0" * 20)
CAROL = bytes.fromhex("c0" * 20)


def _hex(b):
    return "0x" + b.hex()


def deploy_code(runtime: bytes) -> bytes:
    """Init code that returns ``runtime``."""
    n = len(runtime)
    return bytes.fromhex("60%02x600c60003960%02x6000f3" % (n, n)) + runtime


# no calldata → return slot 0; otherwise slot 0 := calldata[0:32]
STORE = bytes.fromhex("36600f5760005460005260206000f35b60003560005500")
# write calldata[0:32] into slot calldata[32:64] (for many-slot contracts)
STORE_AT = bytes.fromhex("6000356020355500")
# return slot calldata[0:32]
LOAD_AT = bytes.fromhex("60003554" "60005260206000f3")


def forwarder(target: bytes, revert_after: bool = False) -> bytes:
    """Forward the calldata (and no value) to ``target``; optionally REVERT afterwards. The
    call's return data is returned when it does not revert."""
    body = bytes.fromhex("366000600037") + bytes.fromhex("60206000366000600073") + target + \
        bytes.fromhex("5af150")
    tail = bytes.fromhex("60006000fd") if revert_after else bytes.fromhex("60206000f3")
    return body + tail


def payer(to: bytes) -> bytes:
    """Send the call's value on to ``to``."""
    return bytes.fromhex("600060006000600034" "73") + to + bytes.fromhex("5af15000")


def suicider(beneficiary: bytes) -> bytes:
    """Slot 0 := 7 on calldata; SELFDESTRUCT to ``beneficiary`` without."""
    return bytes.fromhex("36601a57" "73") + beneficiary + bytes.fromhex("ff5b600760005500")


class Chain:
    """A database, the state manager over it, and an executor — a node's EVM."""

    def __init__(self, db):
        self.db = db
        self.sm = ContractStateManager(db)
        self.ex = QRDXEVMExecutor(self.sm)
        self.height = 1
        db.account_write_listeners = [self.sm.invalidate]

    async def fund(self, who: bytes, wei: int):
        await self.sm.set_balance(_hex(who), wei)
        await self.sm.commit(self.height)

    async def tx(self, sender, to, data=b"", value=0, gas=1_000_000, commit_section=True):
        """One transaction in its own EVM section, as a block applies it."""
        self.height += 1
        self.sm.reset_cache()
        section = EvmSection()
        snap = await self.sm.snapshot()
        world = EvmWorld(self.sm, tokens=TokenWorld(self.db, section))
        r = await run(world, lambda: self.ex.execute(
            sender, to, value, data, gas, 0, world=world, block_number=self.height),
            preload=[sender, to])
        if r.success:
            section.absorb(r.token_journal)
        else:
            await self.sm.revert(snap)
        await self.sm.commit(self.height)
        if commit_section:
            await section.commit(self.db)
            await self.db.connection.commit()
        return r

    async def call(self, to, data=b"", sender=ALICE):
        world = EvmWorld(self.sm, tokens=TokenWorld(self.db))
        return await run(world, lambda: self.ex.call(sender, to, data, world=world),
                         preload=[sender, to])

    async def deploy(self, runtime, sender=ALICE):
        r = await self.tx(sender, None, deploy_code(runtime))
        assert r.success, r.error
        return r.created_address


@pytest.fixture
async def chain():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    ExchangeStateManager.reset_instance()
    c = Chain(db)
    await c.fund(ALICE, 10 ** 22)
    yield c
    ExchangeStateManager.reset_instance()
    await db.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


def word(n: int) -> bytes:
    return int(n).to_bytes(32, "big")


def addr_word(a: bytes) -> bytes:
    return bytes(12) + a


# ── accounts and storage ───────────────────────────────────────────────────

async def test_contract_storage_reaches_the_database_and_survives_a_restart(chain):
    c = await chain.deploy(STORE)
    root_before = await chain.db.get_account_state_root()
    assert (await chain.tx(ALICE, c, word(42))).success
    assert await chain.db.get_account_state_root() != root_before     # storage is in the root
    restarted = Chain(chain.db)                                       # fresh manager + executor
    assert int.from_bytes((await restarted.call(c)).output, "big") == 42


async def test_a_contract_writing_another_contracts_storage_persists(chain):
    store = await chain.deploy(STORE)
    proxy = await chain.deploy(forwarder(store))
    assert (await chain.tx(ALICE, proxy, word(7))).success
    assert int.from_bytes((await Chain(chain.db).call(store)).output, "big") == 7


async def test_a_payment_to_a_third_account_is_kept(chain):
    pay = await chain.deploy(payer(CAROL))
    assert (await chain.tx(ALICE, pay, value=5 * 10 ** 18)).success
    restarted = Chain(chain.db)
    assert await restarted.sm.get_balance(_hex(CAROL)) == 5 * 10 ** 18
    # … and stays when Carol herself transacts (the old executor overwrote it from a stale copy)
    assert (await restarted.tx(CAROL, BOB, value=10 ** 18)).success
    assert await restarted.sm.get_balance(_hex(CAROL)) == 4 * 10 ** 18
    assert await restarted.sm.get_balance(_hex(BOB)) == 10 ** 18


async def test_storage_too_big_to_load_whole_is_loaded_slot_by_slot(chain, monkeypatch):
    from qrdx.contracts import evm_world
    many = await chain.deploy(STORE_AT)
    for slot in range(5):
        assert (await chain.tx(ALICE, many, word(100 + slot) + word(slot))).success
    monkeypatch.setattr(evm_world, "FULL_STORAGE_LIMIT", 2)
    reader = await chain.deploy(LOAD_AT)
    # LOAD_AT reads its OWN storage; check through a restarted node instead
    rows = await (await chain.db.connection.execute(
        "SELECT COUNT(*) FROM contract_storage WHERE contract_address = ?",
        (to_account_id(many),))).fetchone()
    assert rows[0] == 5
    world = EvmWorld(Chain(chain.db).sm)
    await world.load_account(many)
    assert many not in world.full_storage                     # too many: per slot
    await world.load_slot(many, 3)
    assert world.storage[(many, 3)] == 103
    assert reader


async def test_selfdestruct_removes_the_account_and_all_its_storage(chain):
    c = await chain.deploy(suicider(BOB))
    assert (await chain.tx(ALICE, c, word(1))).success           # slot 0 := 7
    assert await chain.db.get_account_state_root()
    assert (await chain.tx(ALICE, c)).success                    # SELFDESTRUCT
    rows = await (await chain.db.connection.execute(
        "SELECT COUNT(*) FROM contract_storage WHERE contract_address = ?",
        (to_account_id(c),))).fetchone()
    assert rows[0] == 0
    assert (await Chain(chain.db).sm.get_code(_hex(c))) == b""


async def test_a_reverted_transaction_writes_nothing_back(chain):
    store = await chain.deploy(STORE)
    bad = await chain.deploy(forwarder(store, revert_after=True))
    root = await chain.db.get_account_state_root()
    r = await chain.tx(ALICE, bad, word(9))
    assert not r.success
    assert await chain.db.get_account_state_root() == root
    assert int.from_bytes((await chain.call(store)).output, "big") == 0


async def test_a_direct_database_write_is_not_shadowed_by_a_cached_copy(chain):
    await chain.sm.get_account(_hex(BOB))                      # cached at 0
    await chain.db.apply_account_balance_delta(_hex(BOB), D(3))  # e.g. the exchange's flush
    assert await chain.sm.get_balance(_hex(BOB)) == 3 * 10 ** 18


# ── native tokens inside the EVM ───────────────────────────────────────────

async def _token(chain, holder: bytes, supply="1000", freeze=True):
    """A native token (6 decimals) deployed through the exchange, its supply credited to
    ``holder`` in the ledger."""
    mgr = ExchangeStateManager.get_instance()
    issuer = "0xPQ" + "e" * 64
    mgr.begin_block(1, 1_700_000_000.0)
    r = mgr.process_transaction(ExchangeTransaction(
        op_type=ExchangeOpType.TOKEN_DEPLOY, sender=issuer, nonce=0,
        params={"name": "Quantum USD", "symbol": "qUSD", "decimals": 6, "total_supply": supply,
                "freeze_authority": issuer if freeze else ""}, gas_limit=1_000_000))
    assert r.success, r.error
    mgr.commit_block()
    await BP.flush_token_balance_deltas(chain.db, mgr)
    token = r.data["token_address"]
    await chain.db.apply_token_balance_delta(token, issuer, -D(supply))
    await chain.db.apply_token_balance_delta(token, _hex(holder), D(supply))
    await chain.db.connection.commit()
    return bytes.fromhex(token[2:]), issuer


def _transfer(to: bytes, units: int) -> bytes:
    return bytes.fromhex("a9059cbb") + addr_word(to) + word(units)


async def _balance(chain, token: bytes, who: bytes) -> Decimal:
    return await chain.db.get_token_balance(_hex(token), _hex(who))


async def test_a_wallet_reads_and_sends_a_native_token(chain):
    token, _ = await _token(chain, ALICE)
    out = (await chain.call(token, bytes.fromhex("313ce567"))).output
    assert int.from_bytes(out, "big") == 6
    bal = (await chain.call(token, bytes.fromhex("70a08231") + addr_word(ALICE))).output
    assert int.from_bytes(bal, "big") == 1000 * 10 ** 6
    r = await chain.tx(ALICE, token, _transfer(BOB, 250 * 10 ** 6))   # MetaMask's "send"
    assert r.success, r.error
    assert await _balance(chain, token, ALICE) == 750 and await _balance(chain, token, BOB) == 250
    [log] = r.logs
    assert log[0] == token and log[1][0] == TRANSFER_TOPIC
    assert log[1][2] == int.from_bytes(BOB, "big") and int.from_bytes(log[2], "big") == 250 * 10 ** 6


async def test_a_contract_holds_and_moves_native_tokens(chain):
    token, _ = await _token(chain, ALICE)
    vault = await chain.deploy(forwarder(token))
    assert (await chain.tx(ALICE, token, _transfer(vault, 100 * 10 ** 6))).success
    assert await _balance(chain, token, vault) == 100
    assert (await chain.tx(ALICE, vault, _transfer(CAROL, 40 * 10 ** 6))).success  # vault pays
    assert await _balance(chain, token, vault) == 60 and await _balance(chain, token, CAROL) == 40


async def test_a_reverted_frame_undoes_its_token_moves(chain):
    token, _ = await _token(chain, ALICE)
    regretful = await chain.deploy(forwarder(token, revert_after=True))
    assert (await chain.tx(ALICE, token, _transfer(regretful, 10 * 10 ** 6))).success
    r = await chain.tx(ALICE, regretful, _transfer(BOB, 10 * 10 ** 6))
    assert not r.success
    assert await _balance(chain, token, regretful) == 10 and await _balance(chain, token, BOB) == 0


async def test_refusals_revert_with_a_reason(chain):
    token, issuer = await _token(chain, ALICE)
    r = await chain.tx(BOB, token, _transfer(CAROL, 1))              # Bob holds nothing
    assert not r.success
    r = await chain.tx(ALICE, token, _transfer(bytes(20), 1))         # to the zero address
    assert not r.success
    mgr = ExchangeStateManager.get_instance()
    mgr.tokens.freeze(_hex(token), issuer, _hex(ALICE), True)
    r = await chain.tx(ALICE, token, _transfer(BOB, 1))
    assert not r.success
    assert await _balance(chain, token, ALICE) == 1000


async def test_approve_and_transfer_from_through_a_contract(chain):
    token, _ = await _token(chain, ALICE)
    spender = await chain.deploy(forwarder(token))
    approve = bytes.fromhex("095ea7b3") + addr_word(spender) + word(300 * 10 ** 6)
    r = await chain.tx(ALICE, token, approve)
    assert r.success and r.logs[0][1][0] == APPROVAL_TOPIC
    mgr = ExchangeStateManager.get_instance()
    assert mgr.tokens.allowance(_hex(token), _hex(ALICE), _hex(spender)) == 300   # one registry
    pull = bytes.fromhex("23b872dd") + addr_word(ALICE) + addr_word(CAROL) + word(120 * 10 ** 6)
    assert (await chain.tx(ALICE, spender, pull)).success
    assert await _balance(chain, token, CAROL) == 120
    assert mgr.tokens.allowance(_hex(token), _hex(ALICE), _hex(spender)) == 180
    over = bytes.fromhex("23b872dd") + addr_word(ALICE) + addr_word(CAROL) + word(181 * 10 ** 6)
    r = await chain.tx(ALICE, spender, over)      # the forwarder swallows the token's revert …
    assert r.output[:4].hex() == "08c379a0"       # … and returns its Error(string)
    assert await _balance(chain, token, CAROL) == 120
    assert mgr.tokens.allowance(_hex(token), _hex(ALICE), _hex(spender)) == 180


async def test_a_section_that_is_not_accepted_moves_nothing(chain):
    token, _ = await _token(chain, ALICE)
    r = await chain.tx(ALICE, token, _transfer(BOB, 5 * 10 ** 6), commit_section=False)
    assert r.success
    assert await _balance(chain, token, BOB) == 0 and await _balance(chain, token, ALICE) == 1000


async def test_later_transactions_in_a_section_see_earlier_moves(chain):
    """Within one block, the second transfer spends what the first delivered — before
    anything reaches the ledger."""
    token, _ = await _token(chain, ALICE)
    section = EvmSection()
    for sender, to in ((ALICE, BOB), (BOB, CAROL)):
        world = EvmWorld(chain.sm, tokens=TokenWorld(chain.db, section))
        r = await run(world, lambda: chain.ex.execute(
            sender, token, 0, _transfer(to, 5 * 10 ** 6), 1_000_000, 0, world=world),
            preload=[sender, token])
        assert r.success, r.error
        section.absorb(r.token_journal)
    assert await _balance(chain, token, CAROL) == 0                  # not yet committed
    await section.commit(chain.db)
    assert await _balance(chain, token, CAROL) == 5 and await _balance(chain, token, BOB) == 0
