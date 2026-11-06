"""
Quantum migration (docs/QUANTUM_MIGRATION.md): an ECDSA account names its post-quantum successor
while ECDSA still holds — on QRDX through account control (the EVM write precompile), or on
another chain through QRDXMigrationRegistry, proven on QRDX with MIGRATION_CLAIM — and once its
ECDSA key is off, only the successor signs for it.
"""

import json
from pathlib import Path

import pytest
import rlp
from eth_abi import encode
from eth_account import Account as EthAccount
from eth_utils import keccak, to_checksum_address
from test_bridge import ASSET, CHAIN, T0, Key, _genesis
from test_evm_exchange import _action, _next_block
from test_evm_world import ALICE, chain, forwarder  # noqa: F401  (fixture)
from trie import HexaryTrie

from qrdx import constants
from qrdx.constants import CHAIN_ID
from qrdx.contracts.evm_mempool import _ecdsa_signer_allowed
from qrdx.contracts.evm_world import EXCHANGE_WRITE_ADDRESS
from qrdx.contracts.external_proof_evm import EMPTY_CODE, EMPTY_TRIE
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.migration import REGISTERED_AT_SLOT, SUCCESSOR_SLOT, mapping_slot

REGISTRY = "0x" + "77" * 20
HEIGHT = 9_000
ART = json.loads((Path(__file__).resolve().parents[1]
                  / "contracts/migration/QRDXMigrationRegistry.artifact.json").read_text())
ETH_KEY = "0x" + "e1" * 32
ETH_ACCOUNT = EthAccount.from_key(ETH_KEY).address.lower()


def _sel(sig):
    return keccak(text=sig)[:4]


def _signed_legacy(nonce=0):
    signed = EthAccount.sign_transaction(
        {"nonce": nonce, "gasPrice": 10**9, "gas": 21_000, "to": to_checksum_address("0x" + "0b" * 20),
         "value": 1, "data": b"", "chainId": CHAIN_ID}, ETH_KEY)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return "0x" + bytes(raw).hex()


# ── the registry contract ─────────────────────────────────────────────────────────────


async def test_the_registry_takes_one_commitment_from_an_account_never_a_contract(chain):
    r = await chain.tx(ALICE, None, bytes.fromhex(ART["bytecode"][2:]))
    assert r.success, r.error
    registry = r.created_address
    successor = bytes.fromhex("5c" * 32)
    register = _sel("register(bytes32)") + encode(["bytes32"], [successor])
    assert (await chain.tx(ALICE, registry, register)).success
    again = _sel("register(bytes32)") + encode(["bytes32"], [bytes.fromhex("6d" * 32)])
    assert not (await chain.tx(ALICE, registry, again)).success          # immutable
    alice = "0x" + ALICE.hex()
    assert bytes(await chain.sm.get_storage("0x" + registry.hex(), mapping_slot(alice, SUCCESSOR_SLOT))
                 ).rjust(32, b"\x00") == successor                         # the slot QRDX proves
    via_contract = await chain.deploy(forwarder(registry))
    r = await chain.tx(ALICE, via_contract, register)                     # (the forwarder ignores
    assert bytes(r.output)[:4] == bytes.fromhex("08c379a0")               # the revert it relays)
    slot = mapping_slot("0x" + via_contract.hex(), SUCCESSOR_SLOT)
    assert not any(bytes(await chain.sm.get_storage("0x" + registry.hex(), slot)))  # a contract cannot


# ── claiming on QRDX ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mgr(monkeypatch):
    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    monkeypatch.setattr(constants, "MIGRATION_REGISTRIES", (f"{CHAIN}:{REGISTRY}",))
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    v1, v2, v3 = Key(), Key(), Key()
    m.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    m.begin_block(1, float(T0))
    m._test_validators = (v1, v2, v3)
    yield m
    ExchangeStateManager.reset_instance()


def _source_state(account, successor_hex, time):
    storage = HexaryTrie(db={})
    storage[keccak(mapping_slot(account, SUCCESSOR_SLOT))] = rlp.encode(bytes.fromhex(successor_hex[4:]))
    storage[keccak(mapping_slot(account, REGISTERED_AT_SLOT))] = rlp.encode(time)
    accounts = HexaryTrie(db={})
    for i in range(1, 20):
        accounts[keccak(bytes([i]) * 20)] = rlp.encode([i, i, EMPTY_TRIE, EMPTY_CODE])
    accounts[keccak(bytes.fromhex(REGISTRY[2:]))] = rlp.encode([1, 0, storage.root_hash, b"\xc0" * 32])
    return accounts, storage


def _attest(m, root, height=HEIGHT):
    v1, _v2, v3 = m._test_validators
    head = {"chain": CHAIN, "height": height, "hash": "0x" + "ab" * 32,
            "state_root": "0x" + root.hex(), "timestamp": T0}
    for who in (v1, v3):
        assert m.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"heads": [head]})).success


def _proof(trie, key):
    return ["0x" + rlp.encode(n).hex() for n in trie.get_proof(keccak(key))]


def _claim(m, sender, account, successor, time, accounts, storage, height=HEIGHT, block=3):
    params = {"chain": CHAIN, "account": account, "successor": successor, "time": time,
              "height": height, "account_proof": _proof(accounts, bytes.fromhex(REGISTRY[2:])),
              "successor_proof": _proof(storage, mapping_slot(account, SUCCESSOR_SLOT)),
              "time_proof": _proof(storage, mapping_slot(account, REGISTERED_AT_SLOT))}
    m.begin_block(block, float(T0 + block))
    return m.process_transaction(sender.tx(ExchangeOpType.MIGRATION_CLAIM, params))


def test_a_proven_commitment_binds_the_successor_as_controller(mgr):
    successor, relayer = Key(), Key()
    accounts, storage = _source_state(ETH_ACCOUNT, successor.addr, T0 - 100)
    _attest(mgr, accounts.root_hash)
    r = _claim(mgr, relayer, ETH_ACCOUNT, successor.addr, T0 - 100, accounts, storage)
    assert r.success, r.error
    policy = mgr.authority.policy(ETH_ACCOUNT)
    assert [c.lower() for c in policy.controllers] == [successor.addr.lower()] and policy.own_key
    from qrdx.exchange.views import authority
    assert authority(mgr, ETH_ACCOUNT)["migration"] == {"successor": successor.addr, "chain": CHAIN,
                                                     "registered_at": T0 - 100}
    again = _claim(mgr, relayer, ETH_ACCOUNT, successor.addr, T0 - 100, accounts, storage, block=4)
    assert again.success and again.data["already"]                     # idempotent
    other = Key()
    acc2, st2 = _source_state(ETH_ACCOUNT, other.addr, T0 - 50)
    _attest(mgr, acc2.root_hash, height=HEIGHT + 1)
    r = _claim(mgr, relayer, ETH_ACCOUNT, other.addr, T0 - 50, acc2, st2, height=HEIGHT + 1, block=5)
    assert not r.success and "already bound" in r.error                 # one successor


def test_a_forged_or_unanchored_claim_binds_nothing(mgr, monkeypatch):
    successor, relayer = Key(), Key()
    accounts, storage = _source_state(ETH_ACCOUNT, successor.addr, T0 - 100)
    _attest(mgr, accounts.root_hash)
    for kwargs, why in (
        ({"successor": Key().addr}, "does not hold this commitment"),
        ({"time": T0 - 99}, "does not hold this commitment"),
        ({"account": "0x" + "12" * 20}, "does not"),
        ({"height": HEIGHT + 5}, "no attested head"),
    ):
        args = {"account": ETH_ACCOUNT, "successor": successor.addr, "time": T0 - 100, **kwargs}
        r = _claim(mgr, relayer, args["account"], args["successor"], args["time"], accounts, storage,
                   height=kwargs.get("height", HEIGHT))
        assert not r.success and why in r.error, (kwargs, r.error)
    monkeypatch.setattr(constants, "MIGRATION_REGISTRIES", ())
    r = _claim(mgr, relayer, ETH_ACCOUNT, successor.addr, T0 - 100, accounts, storage)
    assert not r.success and "no registry" in r.error
    assert not mgr.authority.policy(ETH_ACCOUNT).controllers


def test_once_its_ecdsa_key_is_off_only_the_successor_signs_for_the_account(mgr):
    successor, relayer = Key(), Key()
    accounts, storage = _source_state(ETH_ACCOUNT, successor.addr, T0 - 100)
    _attest(mgr, accounts.root_hash)
    assert _claim(mgr, relayer, ETH_ACCOUNT, successor.addr, T0 - 100, accounts, storage).success
    assert _ecdsa_signer_allowed(_signed_legacy()) == (True, "")
    # The successor, as the account's controller, turns the ECDSA key off at once.
    t = ExchangeTransaction(op_type=ExchangeOpType.ACCOUNT_POLICY, sender=ETH_ACCOUNT,
                            signer=successor.addr, params={"action": "own_key", "enabled": False},
                            nonce=mgr.get_nonce(f"{ETH_ACCOUNT}|{successor.addr}"), gas_limit=10**6)
    t.public_key = successor.key.public_key.to_bytes()
    t.signature = successor.key.sign(t.signing_bytes()).to_bytes()
    assert t.verify()
    mgr.begin_block(6, float(T0 + 6))
    r = mgr.process_transaction(t)
    assert r.success, r.error
    allowed, why = _ecdsa_signer_allowed(_signed_legacy())
    assert not allowed and "ECDSA key is turned off" in why


# ── on QRDX: account control from an Ethereum wallet ─────────────────────────────────


async def test_an_ethereum_account_binds_a_successor_and_locks_its_key_through_the_evm(chain):
    mgr = ExchangeStateManager.get_instance()
    successor = Key()
    account = "0x" + ALICE.hex()
    bind = _action("ACCOUNT_POLICY", action="add_controller", controller=successor.addr)
    assert (await chain.tx(ALICE, EXCHANGE_WRITE_ADDRESS, bind)).success
    (event,) = _next_block(mgr)
    assert event["success"], event
    assert [c.lower() for c in mgr.authority.policy(account).controllers] == [successor.addr.lower()]
    lock = _action("ACCOUNT_POLICY", action="own_key", enabled=False)
    assert (await chain.tx(ALICE, EXCHANGE_WRITE_ADDRESS, lock)).success
    assert _next_block(mgr, 3)[0]["success"]
    assert not mgr.authority.own_key_enabled(account)
