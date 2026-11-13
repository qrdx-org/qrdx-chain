"""
The Doomsday Protocol (qrdx/exchange/doomsday.py, docs/QUANTUM_MIGRATION.md): proof that a canary
— an address no one holds the key of — has signed, against a finalized head of its chain the
validators attested, or governance's ``declare_quantum_emergency``, turns ECDSA off on QRDX. From
that block: ECDSA-signed transactions are refused and ECRECOVER recovers nothing; agents a ``0x``
account approved are revoked; the bridge neither mints nor withdraws; migration commitments
registered from the trigger's time on prove nothing. Accounts act through the post-quantum
controllers they bound beforehand.
"""

import hashlib
from decimal import Decimal as D

import pytest
import rlp
from eth_account import Account as EthAccount
from eth_keys import keys
from eth_utils import keccak
from test_bridge import ASSET, CHAIN, T0, Key, _genesis
from test_evm_world import ALICE, chain  # noqa: F401  (fixture)
from test_governance import HOLDER, Chain, _passed
from test_quantum_migration import ETH_ACCOUNT, ETH_KEY, REGISTRY, _signed_legacy
from trie import HexaryTrie

from qrdx import constants
from qrdx.contracts.evm_mempool import _ecdsa_signer_allowed
from qrdx.contracts.evm_world import ECRECOVER_ADDRESS
from qrdx.contracts.external_proof_evm import EMPTY_CODE, EMPTY_TRIE
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.bridge import configured_assets
from qrdx.exchange.doomsday import (
    DoomsdayError,
    canary_address,
    canary_key,
    is_ecdsa_account,
    parse_canaries,
)
from qrdx.exchange.governance import EXECUTED, Governance, GovernanceError
from qrdx.exchange.migration import REGISTERED_AT_SLOT, SUCCESSOR_SLOT, mapping_slot
from qrdx.exchange.trading import AgentGrant

CANARY = canary_address()


# ── the canary ────────────────────────────────────────────────────────────────────────


def test_the_canary_is_a_curve_point_derived_from_a_hash():
    pub = canary_key()
    assert len(pub) == 64 and pub == canary_key()                         # anyone recomputes it
    x, y = int.from_bytes(pub[:32], "big"), int.from_bytes(pub[32:], "big")
    assert x >= int.from_bytes(hashlib.sha256(b"QRDX doomsday canary").digest(), "big") and y % 2 == 0
    assert keys.PublicKey(pub).to_canonical_address().hex() == CANARY[2:]  # a valid secp256k1 key
    assert CANARY == "0x2fe433468ddfd1ac11eb17355b831645c6b4f26e"
    assert canary_address("another label") != CANARY


def test_canaries_parse_strictly():
    assert parse_canaries([f"1:{CANARY.upper().replace('0X', '0x')}"]) == {1: CANARY}
    for bad in ("1", f"x:{CANARY}", f"0:{CANARY}", "1:0x12"):
        with pytest.raises(DoomsdayError):
            parse_canaries([bad])
    with pytest.raises(DoomsdayError, match="repeated"):
        parse_canaries([f"1:{CANARY}", f"1:{CANARY}"])
    assert is_ecdsa_account(ETH_ACCOUNT) and not is_ecdsa_account("0xPQ" + "ab" * 32)
    assert not is_ecdsa_account("0xSUBA" + "ab" * 18)


# ── proving a spend ───────────────────────────────────────────────────────────────────


@pytest.fixture
def mgr(monkeypatch):
    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    monkeypatch.setattr(constants, "MIGRATION_REGISTRIES", (f"{CHAIN}:{REGISTRY}",))
    monkeypatch.setattr(constants, "DOOMSDAY_CANARIES", (f"{CHAIN}:{CANARY}",))
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    v1, v2, v3 = Key(), Key(), Key()
    m.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    m.begin_block(1, float(T0))
    m._test_validators = (v1, v2, v3)
    m._test_block = 1
    yield m
    ExchangeStateManager.reset_instance()


def _source(canary_nonce, commitments=()):
    """A source chain's state: the canary at ``canary_nonce``, the registry holding
    ``commitments`` ((account, successor, time), ...), and some other accounts."""
    storage = HexaryTrie(db={})
    for account, successor, time in commitments:
        storage[keccak(mapping_slot(account, SUCCESSOR_SLOT))] = rlp.encode(bytes.fromhex(successor[4:]))
        storage[keccak(mapping_slot(account, REGISTERED_AT_SLOT))] = rlp.encode(time)
    accounts = HexaryTrie(db={})
    for i in range(1, 20):
        accounts[keccak(bytes([i]) * 20)] = rlp.encode([i, i, EMPTY_TRIE, EMPTY_CODE])
    accounts[keccak(bytes.fromhex(REGISTRY[2:]))] = rlp.encode([1, 0, storage.root_hash, b"\xc0" * 32])
    accounts[keccak(bytes.fromhex(CANARY[2:]))] = rlp.encode([canary_nonce, 10**18, EMPTY_TRIE, EMPTY_CODE])
    return accounts, storage


def _proof(trie, key):
    return ["0x" + rlp.encode(n).hex() for n in trie.get_proof(keccak(key))]


def _attest(m, root, height, timestamp):
    v1, _v2, v3 = m._test_validators
    head = {"chain": CHAIN, "height": height, "hash": "0x" + "ab" * 32,
            "state_root": "0x" + root.hex(), "timestamp": timestamp}
    for who in (v1, v3):
        assert m.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"heads": [head]})).success


def _next(m):
    m._test_block += 1
    m.begin_block(m._test_block, float(T0 + m._test_block))


def _prove(m, sender, accounts, height, chain=CHAIN):
    _next(m)
    return m.process_transaction(sender.tx(ExchangeOpType.DOOMSDAY_PROVE, {
        "chain": chain, "height": height,
        "account_proof": _proof(accounts, bytes.fromhex(CANARY[2:]))}))


def _trigger(m, height=9_000, timestamp=T0 - 30):
    accounts, _ = _source(1)
    _attest(m, accounts.root_hash, height, timestamp)
    r = _prove(m, Key(), accounts, height)
    assert r.success, r.error
    return r


def test_a_canary_that_never_signed_proves_nothing(mgr):
    accounts, _ = _source(0)
    _attest(mgr, accounts.root_hash, 9_000, T0)
    r = _prove(mgr, Key(), accounts, 9_000)
    assert not r.success and "never signed" in r.error and mgr.bridge.doomsday is None
    assert mgr.doomsday_cutoff() is None


def test_a_proven_spend_triggers_the_protocol_once_and_its_time_only_moves_earlier(mgr, monkeypatch):
    spent, _ = _source(1)
    r = _prove(mgr, Key(), spent, 9_001)
    assert not r.success and "no attested head" in r.error
    _attest(mgr, spent.root_hash, 8_990, T0 - 90)                          # (heads attested in
    other, _ = _source(0)                                                  # order, as finalized)
    _attest(mgr, other.root_hash, 9_000, T0 - 40)
    r = _prove(mgr, Key(), spent, 9_000)                                   # a proof of another root
    assert not r.success and "does not hold" in r.error
    _attest(mgr, spent.root_hash, 9_002, T0 - 30)
    r = _prove(mgr, Key(), spent, 9_002, chain=CHAIN + 1)
    assert not r.success and "no canary" in r.error
    assert mgr.bridge.doomsday is None

    before = mgr.bridge.commitment()
    r = _prove(mgr, Key(), spent, 9_002)
    assert r.success, r.error
    state = mgr.bridge.doomsday
    assert state["time"] == T0 - 30 and state["height"] == mgr._test_block    # the head's time
    assert CANARY in state["cause"] and mgr.doomsday_cutoff() == T0 - 30
    assert mgr.bridge.commitment() != before                               # in the exchange root
    assert mgr.bridge.guardrails()["doomsday"] == state

    _attest(mgr, spent.root_hash, 9_003, T0 - 10)                          # a later head: no change
    assert _prove(mgr, Key(), spent, 9_003).success and mgr.doomsday_cutoff() == T0 - 30
    assert _prove(mgr, Key(), spent, 8_990).success                        # an earlier one
    assert mgr.doomsday_cutoff() == T0 - 90 and mgr.bridge.doomsday["height"] == state["height"]

    monkeypatch.setattr(constants, "DOOMSDAY_CANARIES", ())
    assert not _prove(mgr, Key(), spent, 9_002).success                    # no canary configured


# ── what it changes ───────────────────────────────────────────────────────────────────


def test_after_the_trigger_ecdsa_keys_sign_nothing(mgr):
    assert _ecdsa_signer_allowed(_signed_legacy()) == (True, "")
    _trigger(mgr)
    allowed, why = _ecdsa_signer_allowed(_signed_legacy())
    assert not allowed and "Doomsday" in why


def test_after_the_trigger_the_bridge_neither_mints_nor_withdraws(mgr):
    (asset,) = configured_assets().values()
    assert mgr.bridge.mint_refusal(asset, D(1), D(0), D(T0), True) is None
    _trigger(mgr)
    assert "Doomsday" in mgr.bridge.mint_refusal(asset, D(1), D(0), D(T0), True)
    _next(mgr)
    r = mgr.process_transaction(Key().tx(ExchangeOpType.BRIDGE_WITHDRAW, {
        "token_address": asset.address, "amount": "1", "to": "0x" + "12" * 20}))
    assert not r.success and "Doomsday" in r.error


def _claim(m, account, successor, time, accounts, storage, height):
    params = {"chain": CHAIN, "account": account, "successor": successor, "time": time,
              "height": height, "account_proof": _proof(accounts, bytes.fromhex(REGISTRY[2:])),
              "successor_proof": _proof(storage, mapping_slot(account, SUCCESSOR_SLOT)),
              "time_proof": _proof(storage, mapping_slot(account, REGISTERED_AT_SLOT))}
    _next(m)
    return m.process_transaction(Key().tx(ExchangeOpType.MIGRATION_CLAIM, params))


def test_commitments_registered_from_the_trigger_on_prove_nothing(mgr):
    early, late = Key(), Key()
    late_account = "0x" + "a5" * 20
    accounts, storage = _source(1, [(ETH_ACCOUNT, early.addr, T0 - 31),
                                    (late_account, late.addr, T0 - 30)])
    _attest(mgr, accounts.root_hash, 9_000, T0 - 30)
    assert _prove(mgr, Key(), accounts, 9_000).success                     # cutoff: T0 - 30
    r = _claim(mgr, late_account, late.addr, T0 - 30, accounts, storage, 9_000)
    assert not r.success and "after the Doomsday Protocol" in r.error
    r = _claim(mgr, ETH_ACCOUNT, early.addr, T0 - 31, accounts, storage, 9_000)
    assert r.success, r.error                                              # made before: binds


def test_the_trigger_revokes_every_agent_a_0x_account_approved(mgr):
    agent, pq_owner = Key(), Key()
    _next(mgr)
    r = mgr.process_transaction(pq_owner.tx(ExchangeOpType.AGENT_APPROVE,
                                            {"agent": agent.addr, "name": "bot"}))
    assert r.success, r.error
    mgr.trading.agents[ETH_ACCOUNT] = (AgentGrant(agent.addr, D(0), "bot"),)
    order = ExchangeTransaction(op_type=ExchangeOpType.CANCEL_ALL, sender=ETH_ACCOUNT,
                                signer=agent.addr, params={}, nonce=0, gas_limit=10**6)
    assert mgr.signer_error(order) == ""
    _trigger(mgr)
    assert mgr.trading.grant(ETH_ACCOUNT, agent.addr) is None
    assert "may not act" in mgr.signer_error(order)
    assert mgr.trading.grant(pq_owner.addr, agent.addr) is not None        # post-quantum: kept


def test_a_bound_successor_moves_the_accounts_qrdx_after_the_trigger(mgr):
    successor, to = Key(), "0xPQ" + "77" * 32
    accounts, storage = _source(1, [(ETH_ACCOUNT, successor.addr, T0 - 500)])
    _attest(mgr, accounts.root_hash, 9_000, T0 - 30)
    assert _claim(mgr, ETH_ACCOUNT, successor.addr, T0 - 500, accounts, storage, 9_000).success
    assert _prove(mgr, Key(), accounts, 9_000).success
    assert not _ecdsa_signer_allowed(_signed_legacy())[0]                  # the old key: refused

    t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=ETH_ACCOUNT,
                            signer=successor.addr,
                            params={"token_address": "QRDX", "to": to, "amount": "40"},
                            nonce=mgr.get_nonce(f"{ETH_ACCOUNT}|{successor.addr}"), gas_limit=10**6)
    t.public_key = successor.key.public_key.to_bytes()
    t.signature = successor.key.sign(t.signing_bytes()).to_bytes()
    _next(mgr)
    mgr.set_available_balance(ETH_ACCOUNT, D(100))
    r = mgr.process_transaction(t)
    assert r.success, r.error
    deltas = mgr.balance_deltas()
    assert deltas[ETH_ACCOUNT] <= D(-40) and deltas[to] == D(40)          # (less the gas fee)

    over = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=ETH_ACCOUNT,
                               signer=successor.addr,
                               params={"token_address": "qrdx", "to": to, "amount": "1000"},
                               nonce=t.nonce + 1, gas_limit=10**6)
    over.public_key = t.public_key
    over.signature = successor.key.sign(over.signing_bytes()).to_bytes()
    r = mgr.process_transaction(over)
    assert not r.success and "insufficient QRDX" in r.error


# ── governance ────────────────────────────────────────────────────────────────────────


def test_governance_declares_the_emergency_with_a_stated_reason():
    gov = Governance()
    assert gov._check_action("declare_quantum_emergency", {"reason": " a break "}, 1) == {"reason": "a break"}
    for bad in ({}, {"reason": ""}, {"reason": "x" * 201}, {"reason": 5}):
        with pytest.raises(GovernanceError, match="reason"):
            gov._check_action("declare_quantum_emergency", bad, 1)

    c = Chain()
    pid = _passed(c, action="declare_quantum_emergency", reason="ECDSA keys recovered in the wild")
    assert c.m.bridge.doomsday is None                                     # not before execution
    run = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=c.gov.proposals[pid].timelock_ends)
    assert run.success, run.error
    assert run.result["status"] == EXECUTED
    state = c.m.bridge.doomsday
    assert state and "ECDSA keys recovered in the wild" in state["cause"]
    assert state["time"] == 1_700_000_000 + c.gov.proposals[pid].timelock_ends
    assert run.result["doomsday"] == state
    ExchangeStateManager.reset_instance()


# ── in the EVM ────────────────────────────────────────────────────────────────────────


async def test_ecrecover_recovers_nothing_after_the_trigger(chain):
    digest = keccak(b"a permit")
    sig = EthAccount._sign_hash(digest, ETH_KEY)
    data = digest + sig.v.to_bytes(32, "big") + sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
    r = await chain.tx(ALICE, ECRECOVER_ADDRESS, data)
    assert r.success and bytes(r.output)[12:].hex() == ETH_ACCOUNT[2:]
    mgr = ExchangeStateManager.get_instance()
    mgr.bridge.set_doomsday(T0, 1, "test")
    try:
        r = await chain.tx(ALICE, ECRECOVER_ADDRESS, data)
        assert r.success and bytes(r.output) == b""                         # address(0) to a contract
    finally:
        ExchangeStateManager.reset_instance()


def test_a_rejected_block_takes_the_trigger_back(mgr):
    agent = Key()
    mgr.trading.agents[ETH_ACCOUNT] = (AgentGrant(agent.addr, D(0), "bot"),)
    accounts, _ = _source(1)
    _attest(mgr, accounts.root_hash, 9_000, T0 - 30)
    _next(mgr)
    mgr.take_snapshot()
    before = mgr.compute_state_root()
    assert mgr.process_transaction(Key().tx(ExchangeOpType.DOOMSDAY_PROVE, {
        "chain": CHAIN, "height": 9_000,
        "account_proof": _proof(accounts, bytes.fromhex(CANARY[2:]))})).success
    assert mgr.bridge.doomsday and mgr.trading.grant(ETH_ACCOUNT, agent.addr) is None
    mgr.revert_block()
    assert mgr.bridge.doomsday is None and mgr.doomsday_cutoff() is None
    assert mgr.trading.grant(ETH_ACCOUNT, agent.addr) is not None
    assert mgr.compute_state_root() == before
