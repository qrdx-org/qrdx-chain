"""
Contracts present from genesis (chain-spec parameter EVM_PREDEPLOYS, qrdx/predeploys.py): the PQ
smart account's implementation at 0x…0600 and its factory at 0x…0601, too big to deploy in a
block. Genesis writes them as block-0 records, every rebuild seeds them from there, and a block
can then create an account through the factory and use it.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest
from eth_abi import decode, encode
from eth_utils import keccak
from test_evm_world import ALICE, Chain, chain  # noqa: F401  (fixture)
from test_pq_smart_account import CALLS, BOB, Key, _call, _sel, _tx

from qrdx import chain_spec as cs
from qrdx import predeploy_code, predeploys
from qrdx.database_sqlite import DatabaseSQLite

ART = json.loads(
    (Path(__file__).resolve().parents[1] / "contracts/accounts/PQSmartAccount.artifact.json").read_text()
)
IMPL = bytes.fromhex(predeploys.IMPLEMENTATION_ADDRESS[2:])
FACTORY = bytes.fromhex(predeploys.FACTORY_ADDRESS[2:])


def _runtime(name):
    return ART["contracts"][name]["runtime"].removeprefix("0x")


def test_the_embedded_code_is_the_artifact():
    assert predeploy_code.SOURCE_SHA256 == ART["source_sha256"]
    assert predeploy_code.PQ_SMART_ACCOUNT_RUNTIME == _runtime("PQSmartAccount")
    assert predeploy_code.PQ_ACCOUNT_FACTORY_RUNTIME == _runtime("PQAccountFactory")


async def test_the_factory_code_is_what_its_constructor_deploys(chain):
    creation = bytes.fromhex(ART["contracts"]["PQAccountFactory"]["bytecode"].removeprefix("0x"))
    r = await chain.tx(ALICE, None, creation + encode(["address"], [predeploys.IMPLEMENTATION_ADDRESS]))
    assert r.success, r.error
    deployed = await chain.sm.get_code("0x" + bytes(r.created_address).hex())
    assert deployed == predeploys.factory_code()
    assert deployed != bytes.fromhex(predeploy_code.PQ_ACCOUNT_FACTORY_RUNTIME)  # (filled in)


@pytest.mark.parametrize("entry,why", [
    ("0x" + "00" * 18 + "0500:0x00", "reserved for precompiles"),
    ("0x" + "11" * 20 + ":0xzz", "not hex"),
    ("0x" + "11" * 20 + ":0x", "code of 0 bytes"),
    ("0x" + "11" * 20 + ":0x" + "00" * 24_577, "code of 24577"),
    ("0x" + "11" * 20 + ":0x00:0x1", "not SLOT=VALUE"),
    ("0x" + "11" * 19 + ":0x00", "not a 20-byte address"),
])
def test_a_bad_entry_is_refused(entry, why):
    with pytest.raises(ValueError, match=why):
        predeploys.parse(entry)


def test_the_spec_refuses_one_address_twice():
    entry = "0x" + "11" * 20 + ":0x00"
    with pytest.raises(cs.ChainSpecError, match="listed twice|twice"):
        cs.build_spec("qrdx-test-predeploy", 991243, {"EVM_PREDEPLOYS": [entry, entry + ":0x1=0x2"]},
                      dev=True)


async def _seed(db):
    for p in predeploys.check(predeploys.default_entries()):
        await db.seed_genesis_contract(predeploys.genesis_record(p))
    await db.connection.commit()


async def test_an_account_is_created_and_used_through_the_predeployed_factory(chain):
    await _seed(chain.db)
    chain.sm.reset_cache()
    (impl,) = decode(["address"], await _call(chain, FACTORY, _sel("implementation()")))
    assert impl == predeploys.IMPLEMENTATION_ADDRESS
    locked = await _tx(chain, ALICE, IMPL, _sel("initialize(bytes32)") + encode(["bytes32"], [b"\x01" * 32]))
    assert not locked.success                                  # the implementation is locked

    owner, salt = Key(), b"\x00" * 32
    (predicted,) = decode(["address"], await _call(
        chain, FACTORY, _sel("predict(bytes32,bytes32)") + encode(["bytes32", "bytes32"], [owner.hash, salt])))
    r = await _tx(chain, ALICE, FACTORY, _sel("create(bytes32,bytes32)") + encode(["bytes32", "bytes32"], [owner.hash, salt]),
                  gas=900_000)
    assert r.success, r.error
    assert r.gas_used < 1_000_000                               # fits a block
    account = bytes.fromhex(predicted[2:])
    await chain.fund(account, 10 ** 21)
    calls = [("0x" + BOB.hex(), 10 ** 18, b"")]
    (digest,) = decode(["bytes32"], await _call(
        chain, account, _sel(f"executeHash({CALLS},uint256,uint256)") + encode([CALLS, "uint256", "uint256"], [calls, 0, 0])))
    data = _sel(f"execute({CALLS},uint256,uint256,bytes,bytes)") + encode(
        [CALLS, "uint256", "uint256", "bytes", "bytes"], [calls, 0, 0, owner.pub, owner.sign(digest)])
    r = await _tx(chain, ALICE, account, data)
    assert r.success, r.error
    assert await chain.sm.get_balance("0x" + BOB.hex()) == 10 ** 18


@pytest.fixture
async def genesis_db():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    yield db
    await db.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


async def test_genesis_writes_them_and_every_rebuild_seeds_them_again(genesis_db):
    from qrdx.validator.genesis_init import GenesisInitializer

    db = genesis_db
    await GenesisInitializer(db).initialize_genesis(validators=[], genesis_time=1_700_000_000)
    await db.connection.commit()

    async def state():
        cur = await db.connection.execute(
            "SELECT address, code_hash, nonce, is_contract FROM account_state "
            "WHERE address IN (?, ?) ORDER BY address",
            (predeploys.IMPLEMENTATION_ADDRESS, predeploys.FACTORY_ADDRESS))
        accounts = [tuple(r) for r in await cur.fetchall()]
        cur = await db.connection.execute(
            "SELECT contract_address, storage_key, storage_value FROM contract_storage "
            "ORDER BY contract_address, storage_key")
        return accounts, [tuple(r) for r in await cur.fetchall()]

    accounts, storage = await state()
    assert [a[0] for a in accounts] == [predeploys.IMPLEMENTATION_ADDRESS, predeploys.FACTORY_ADDRESS]
    assert accounts[1][1] == keccak(predeploys.factory_code()).hex() and accounts[1][2:] == (1, 1)
    assert storage == [(predeploys.IMPLEMENTATION_ADDRESS, "00" * 32, predeploys.IMPLEMENTATION_LOCK)]
    cur = await db.connection.execute(
        "SELECT tx_hex FROM transactions WHERE tx_hex LIKE '%genesis_contract%'")
    assert len(await cur.fetchall()) == 2                      # block-0 records

    root = await db.get_account_state_root()
    await db.connection.execute("DELETE FROM account_state")    # as a rebuild clears it
    await db.connection.execute("DELETE FROM contract_storage")
    await db.seed_genesis_account_state()
    assert await state() == (accounts, storage)
    assert await db.get_account_state_root() == root


def test_the_genesis_block_commits_to_the_code():
    plain = cs.build_spec("qrdx-test-predeploy", 991244, {}, dev=True)
    other = cs.build_spec("qrdx-test-predeploy", 991244, {"EVM_PREDEPLOYS": predeploys.default_entries()[:1]},
                          dev=True)
    assert plain.genesis_hash() != other.genesis_hash()
