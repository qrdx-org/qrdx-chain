"""
Genesis commits to the chain spec and to every allocation, and a node builds exactly the
genesis its network's file describes — or refuses to start.

Before chain specs, the genesis state root covered validator stakes and system wallets but not
the prefunded accounts, the RANDAO seed was random per node, a genesis file that failed to load
silently fell back to a built-in genesis, and the initializer counted every prefunded account
twice in the state it hashed. Each is pinned here.
"""
import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx import chain_spec as cs
from qrdx.chain_spec import ChainSpecError
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.genesis import GenesisConfig, GenesisCreator, create_mainnet_genesis
from qrdx.validator.genesis_init import initialize_genesis_if_needed

SPEC = cs.build_spec("qrdx-genesis-test", 4242, {"SLOTS_PER_EPOCH": 8})
GENESIS_TIME = 1_790_000_000
ALICE = "0x" + "a1" * 20
BOB = "0x" + "b2" * 20


def _key():
    k = PQPrivateKey.generate()
    return k.public_key.to_address(), k.public_key.to_hex()


CONTROLLER, _ = _key()
VALIDATOR, VALIDATOR_PK = _key()


def _creator(spec=SPEC, accounts=None, validators=((VALIDATOR, VALIDATOR_PK),)):
    config = GenesisConfig(chain_spec=spec, genesis_time=GENESIS_TIME, min_genesis_validators=1,
                           system_wallet_controller=CONTROLLER, enable_system_wallets=True)
    for addr, amount in (accounts or {ALICE: Decimal("1000"), BOB: Decimal("250.5")}).items():
        config.pre_allocations[addr] = amount
    creator = GenesisCreator(config)
    for addr, pk in validators:
        assert creator.add_validator(addr, pk, Decimal("100000"))
    return creator


def _genesis(**kw):
    return _creator(**kw).create_genesis()


def _write_file(tmp_path, spec=SPEC, **kw):
    creator = _creator(spec=spec, **kw)
    state, block = creator.create_genesis()
    path = str(tmp_path / "genesis_config.json")
    creator.export_genesis(state, block, path)
    return path, block


@pytest.fixture
async def db():
    path = tempfile.mktemp(suffix=".db")
    database = await DatabaseSQLite.create(db_path=path)
    yield database
    await database.close()          # an open aiosqlite connection keeps the process alive
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)


# ── what genesis commits to ─────────────────────────────────────────────────────────────

def test_genesis_commits_to_the_prefunded_accounts():
    """The V1 root left these out: two networks funding different accounts shared a genesis."""
    _, base = _genesis()
    _, more = _genesis(accounts={ALICE: Decimal("1000"), BOB: Decimal("250.6")})
    _, other = _genesis(accounts={ALICE: Decimal("1000"), "0x" + "c3" * 20: Decimal("250.5")})
    assert len({base.block_hash, more.block_hash, other.block_hash}) == 3


def test_genesis_commits_to_the_chain_spec():
    _, base = _genesis()
    _, other_params = _genesis(spec=cs.build_spec("qrdx-genesis-test", 4242, {"SLOTS_PER_EPOCH": 16}))
    _, other_chain = _genesis(spec=cs.build_spec("qrdx-genesis-test", 4243, {"SLOTS_PER_EPOCH": 8}))
    assert len({base.block_hash, other_params.block_hash, other_chain.block_hash}) == 3


def test_genesis_does_not_depend_on_the_upgrade_schedule():
    """Upgrades are appended to a live network's spec; its genesis must not move."""
    upgraded = cs.build_spec("qrdx-genesis-test", 4242, {"SLOTS_PER_EPOCH": 8}, forks=[
        {"name": "randao", "height": 1000, "features": ["randao_selection"]}])
    assert _genesis()[1].block_hash == _genesis(spec=upgraded)[1].block_hash


def test_genesis_is_deterministic_including_the_randao_seed():
    s1, b1 = _genesis()
    s2, b2 = _genesis()
    assert b1.block_hash == b2.block_hash
    assert s1.randao_seed == s2.randao_seed and s1.randao_seed
    assert s1.chain_spec_hash == SPEC.genesis_hash()


def test_amount_representation_does_not_change_the_commitment():
    _, a = _genesis(accounts={ALICE: Decimal("1000"), BOB: Decimal("250.5")})
    _, b = _genesis(accounts={ALICE: Decimal("1000.000"), BOB: Decimal("2.505E+2")})
    assert a.block_hash == b.block_hash


def test_mainnet_genesis_needs_a_real_spec():
    import time
    with pytest.raises(ChainSpecError):
        create_mainnet_genesis([], {}, int(time.time()) + 3600, cs.dev_spec(env={}))


def test_an_explicit_spec_must_agree_with_explicit_ids():
    with pytest.raises(ChainSpecError, match="chain_id"):
        GenesisCreator(GenesisConfig(chain_spec=SPEC, chain_id=1))


# ── a node builds its network's genesis, or refuses ─────────────────────────────────────

async def test_a_node_reproduces_the_genesis_its_file_describes(tmp_path, db):
    path, block = _write_file(tmp_path)
    assert await initialize_genesis_if_needed(db, genesis_file=path, chain_spec=SPEC) is True
    g = await db.get_block_by_id(0)
    assert (g.get("hash") or g.get("block_hash")) == block.block_hash
    content = json.loads(g.get("content") or g.get("block_content"))
    assert content["chain_spec_hash"] == SPEC.genesis_hash()
    assert content["chain_id"] == 4242
    # Funded exactly once, at the declared amount.
    assert await db.get_address_balance(BOB) == Decimal("250.5")
    assert await db.get_address_balance(ALICE) == Decimal("1000")
    # Recorded in the node's own database, not beside the package.
    cur = await db.connection.execute("SELECT value FROM chain_metadata WHERE key = 'genesis'")
    meta = json.loads((await cur.fetchone())[0])
    assert meta["genesis_block_hash"] == block.block_hash
    # Already initialised: a second call changes nothing.
    assert await initialize_genesis_if_needed(db, genesis_file=path, chain_spec=SPEC) is False


async def test_an_edited_genesis_file_is_refused(tmp_path, db):
    path, _ = _write_file(tmp_path)
    data = json.load(open(path))
    data["state"]["accounts"][BOB]["balance"] = "250000"      # someone tops up an account
    json.dump(data, open(path, "w"))
    with pytest.raises(ChainSpecError, match="records block hash"):
        await initialize_genesis_if_needed(db, genesis_file=path, chain_spec=SPEC)
    assert await db.get_next_block_id() == 0                  # nothing was written


async def test_a_genesis_file_for_another_spec_is_refused(tmp_path, db):
    path, _ = _write_file(tmp_path)
    other = cs.build_spec("qrdx-genesis-test", 4242, {"SLOTS_PER_EPOCH": 16})
    with pytest.raises(ChainSpecError, match="different chain spec"):
        await initialize_genesis_if_needed(db, genesis_file=path, chain_spec=other)


async def test_a_broken_genesis_file_never_falls_back_to_another_genesis(tmp_path, db):
    path = tmp_path / "genesis_config.json"
    path.write_text("{ truncated")
    with pytest.raises(ChainSpecError):
        await initialize_genesis_if_needed(db, genesis_file=str(path), chain_spec=SPEC)
    assert await db.get_next_block_id() == 0


async def test_a_real_network_needs_its_genesis_file(db):
    with pytest.raises(ChainSpecError, match="genesis file"):
        await initialize_genesis_if_needed(db, genesis_file=None, chain_spec=SPEC)


async def test_a_dev_network_gets_the_builtin_genesis_bound_to_its_spec(db):
    dev = cs.dev_spec(env={"QRDX_SLOTS_PER_EPOCH": "4"})
    assert await initialize_genesis_if_needed(db, genesis_file=None, chain_spec=dev) is True
    g = await db.get_block_by_id(0)
    content = json.loads(g.get("content") or g.get("block_content"))
    assert content["chain_spec_hash"] == dev.genesis_hash()


def test_mainnet_genesis_is_on_chain_762():
    import time
    with pytest.raises(ChainSpecError, match="762"):
        create_mainnet_genesis([], {}, int(time.time()) + 3600,
                               cs.build_spec("qrdx-testnet", 7620, {}))
