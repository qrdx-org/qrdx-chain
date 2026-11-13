"""
The trust-minimized inbound bridge (docs/BRIDGE.md "Proving a deposit"): BRIDGE_PROVE_DEPOSIT
mints a deposit on a storage proof that the source chain's lockbox (BRIDGE_LOCKBOXES) records
exactly it, against a finalized head of that chain the validators attested. The validators vouch
for one state root, not for each deposit; anyone may send the proof. Real Merkle-Patricia proofs
(as eth_getProof returns them), the record and slot the lockbox computes
(tests/test_lockbox_contract.py checks them against the compiled contract).
"""

from decimal import Decimal as D

import pytest
import rlp
from eth_utils import keccak
from test_bridge import ASSET, CHAIN, T0, USDC, Key, _deposit, _genesis
from trie import HexaryTrie

from qrdx import constants
from qrdx.contracts.external_proof_evm import EMPTY_CODE, EMPTY_TRIE
from qrdx.exchange import ExchangeOpType, ExchangeStateManager
from qrdx.exchange.bridge import configured_assets, deposit_slot, parse_deposit, token_address

LOCKBOX = "0x" + "4c" * 20
HEIGHT = 5_000


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    monkeypatch.setattr(constants, "BRIDGE_LOCKBOXES", (f"{CHAIN}:{LOCKBOX}",))
    monkeypatch.setattr(constants, "BRIDGE_MINT_LIMITS", ())
    v1, v2, v3, user, relayer = Key(), Key(), Key(), Key(), Key()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    mgr.begin_block(1, float(T0))
    yield mgr, (v1, v2, v3), user, relayer
    ExchangeStateManager.reset_instance()


def _source_chain(deposits, lockbox=LOCKBOX):
    """A source chain's state: some accounts and the lockbox, whose storage holds the records."""
    asset = configured_assets()[(CHAIN, USDC)]
    storage = HexaryTrie(db={})
    for d in deposits:
        storage[keccak(deposit_slot(d.number))] = rlp.encode(d.record(asset))
    accounts = HexaryTrie(db={})
    for i in range(1, 30):
        accounts[keccak(bytes([i]) * 20)] = rlp.encode([i, 10**15 * i, EMPTY_TRIE, EMPTY_CODE])
    accounts[keccak(bytes.fromhex(lockbox[2:]))] = rlp.encode([1, 0, storage.root_hash, b"\xc0" * 32])
    return accounts, storage


def _proof(trie, key: bytes):
    return ["0x" + rlp.encode(n).hex() for n in trie.get_proof(keccak(key))]


def _attest_head(mgr, validators, state_root, height=HEIGHT):
    v1, _v2, v3 = validators
    head = {"chain": CHAIN, "height": height, "hash": "0x" + "ab" * 32,
            "state_root": "0x" + state_root.hex(), "timestamp": T0}
    for who in (v1, v3):
        r = mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"heads": [head]}))
        assert r.success, r.error
    assert mgr.bridge.head(CHAIN).height == height


def _prove(mgr, sender, raw, accounts, storage, height=HEIGHT, lockbox=LOCKBOX, at=T0 + 60, block=3):
    d = parse_deposit(raw, configured_assets())
    params = {"deposit": raw, "height": height,
              "account_proof": _proof(accounts, bytes.fromhex(lockbox[2:])),
              "storage_proof": _proof(storage, deposit_slot(d.number))}
    mgr.begin_block(block, float(at))
    return mgr.process_transaction(sender.tx(ExchangeOpType.BRIDGE_PROVE_DEPOSIT, params))


def _supply(mgr):
    t = mgr.tokens.get(token_address(CHAIN, USDC))
    return t.supply if t is not None else D(0)


def test_anyone_mints_a_deposit_by_proving_the_lockboxs_record(setup):
    mgr, validators, user, relayer = setup
    raw = _deposit(user.addr, "250.5")
    d = parse_deposit(raw, configured_assets())
    accounts, storage = _source_chain([d])
    _attest_head(mgr, validators, accounts.root_hash)
    r = _prove(mgr, relayer, raw, accounts, storage)                 # a relayer, not the user
    assert r.success, r.error
    assert r.data["deposit"] == d.id and _supply(mgr) == D("250.5")
    assert mgr.token_balance_deltas() == {(user.addr, token_address(CHAIN, USDC)): D("250.5")}
    again = _prove(mgr, relayer, raw, accounts, storage, block=4)
    assert not again.success and "already minted" in again.error and _supply(mgr) == D("250.5")


def test_a_deposit_mints_once_whichever_way_it_arrives(setup):
    mgr, validators, user, relayer = setup
    raw = _deposit(user.addr, "10")
    accounts, storage = _source_chain([parse_deposit(raw, configured_assets())])
    v1, _v2, v3 = validators
    for who in (v3, v1):                                              # attested and minted …
        mgr.begin_block(2, float(T0))
        mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"deposits": [raw]}))
    assert _supply(mgr) == D(10)
    _attest_head(mgr, validators, accounts.root_hash)
    r = _prove(mgr, relayer, raw, accounts, storage)                  # … so the proof is refused
    assert not r.success and "already minted" in r.error and _supply(mgr) == D(10)


def test_a_forged_or_unanchored_proof_mints_nothing(setup):
    mgr, validators, user, relayer = setup
    raw = _deposit(user.addr, "250.5")
    d = parse_deposit(raw, configured_assets())
    accounts, storage = _source_chain([d])
    _attest_head(mgr, validators, accounts.root_hash)
    cases = [
        (dict(raw, amount="2505"), {}, "not this deposit"),           # a bigger amount than recorded
        (dict(raw, to=relayer.addr), {}, "not this deposit"),         # another recipient
        (raw, {"height": HEIGHT + 1}, "no attested head"),            # an unattested height
    ]
    for bad, extra, why in cases:
        r = _prove(mgr, relayer, bad, accounts, storage, **extra)
        assert not r.success and why in r.error, (why, r.error)
    # A lockbox the network does not name: its records prove nothing.
    rogue = "0x" + "66" * 20
    acc2, st2 = _source_chain([d], lockbox=rogue)
    _attest_head(mgr, validators, acc2.root_hash, height=HEIGHT + 2)
    r = _prove(mgr, relayer, raw, acc2, st2, height=HEIGHT + 2, lockbox=rogue)
    assert not r.success and "does not hold" in r.error
    # A proof against another state root than the attested one.
    other, other_storage = _source_chain([d, parse_deposit(_deposit(user.addr, tx="cd"), configured_assets())])
    r = _prove(mgr, relayer, raw, other, other_storage)
    assert not r.success and "does not hold" in r.error
    assert _supply(mgr) == 0


def test_the_window_and_the_guardrails_apply_to_proofs_too(setup, monkeypatch):
    mgr, validators, user, relayer = setup
    old = _deposit(user.addr, "5", time=T0 - 8 * 86_400)
    big = _deposit(user.addr, "500", tx="cd")
    accounts, storage = _source_chain([parse_deposit(x, configured_assets()) for x in (old, big)])
    _attest_head(mgr, validators, accounts.root_hash)
    r = _prove(mgr, relayer, old, accounts, storage)
    assert not r.success and "deposit window" in r.error                # refundable instead
    monkeypatch.setattr(constants, "BRIDGE_MINT_LIMITS", ("USDC:300:0",))
    r = _prove(mgr, relayer, big, accounts, storage, block=4)
    assert not r.success and "proven, not minted" in r.error and "daily mint limit" in r.error
    monkeypatch.setattr(constants, "BRIDGE_LOCKBOXES", ())
    r = _prove(mgr, relayer, big, accounts, storage, block=5)
    assert not r.success and "no lockbox" in r.error
    assert _supply(mgr) == 0
