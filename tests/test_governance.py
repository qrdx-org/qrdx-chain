"""
On-chain governance (qrdx/exchange/governance.py, docs/GOVERNANCE.md).

Validators propose and decide by stake; QRDX holders can veto a passed proposal during its
timelock by locking QRDX; nothing takes effect before the timelock ends. Governance moves
system-wallet funds, freezes the genesis master controller (whose authority also ends on its
own at SYSTEM_WALLET_MASTER_SUNSET_HEIGHT), and approves scheduled forks — an unapproved fork
stays dormant.

What must hold: exact value movement (every QRDX accounted for, escrow included), the vote and
veto thresholds exactly, deadlines by block height, determinism (two nodes, one root), revert
safety, and that an approval never depends on a node's own chain spec.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx import chain_spec as cs
from qrdx import constants as C
from qrdx.exchange import block_processor as BP
from qrdx.exchange.governance import (
    EXECUTED, EXPIRED, PASSED, REJECTED, VETOED, VOTING, master_authority, veto_escrow_address,
)
from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.transactions import ExchangeOpType, ExchangeTransaction

D = Decimal
V1, V2, V3 = ("0xPQ" + c * 64 for c in "123")
HOLDER, HOLDER2 = "0xPQ" + "4" * 64, "0xPQ" + "5" * 64
RECIPIENT = "0x" + "77" * 20
TREASURY = C.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"].lower()
ESCROW = veto_escrow_address()
RICH = D(100_000_000)


class Chain:
    """One node's exchange state, fed block by block."""

    def __init__(self):
        ExchangeStateManager.reset_instance()
        self.m = ExchangeStateManager.get_instance()
        BP.apply_enforcement(self.m)
        self.m.oracle_committee = {V1.lower(): D(400_000), V2.lower(): D(300_000),
                                   V3.lower(): D(300_000)}
        self.m.governance.system_wallets_enabled = True
        self.m.governance.genesis_loaded = True
        self.nonces = {}
        self.height = 0
        self.results = []

    def tx(self, sender, op, **params):
        n = self.nonces.get(sender, 0)
        self.nonces[sender] = n + 1
        return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                                   gas_limit=1_000_000)

    def block(self, *txs, height=None, balances=None):
        self.height = height if height is not None else self.height + 1
        for addr in {t.sender for t in txs}:
            self.m.set_available_balance(addr, (balances or {}).get(addr, RICH))
        for addr, bal in (balances or {}).items():
            self.m.set_available_balance(addr, bal)
        ok, err, root = BP.process_exchange_transactions(self.height, 1_700_000_000 + self.height,
                                                         list(txs), self.m)
        assert ok, err
        self.m.commit_block()
        self.results = [t for t in txs]
        return root

    def deltas(self):
        """This block's balance moves, fees excluded."""
        out = dict(self.m.balance_deltas())
        for t in self.results:
            out[t.sender] = out.get(t.sender, D(0)) + t.fee()
        return {a: d for a, d in out.items() if d != 0}

    def propose(self, sender=V1, **params):
        self.block(self.tx(sender, ExchangeOpType.GOV_PROPOSE, **params))
        return self.last()

    def vote(self, sender, pid, support=True):
        self.block(self.tx(sender, ExchangeOpType.GOV_VOTE, proposal_id=pid, support=support))
        return self.last()

    def last(self):
        t = self.results[-1]
        return t.success, t.result if t.success else t.error

    @property
    def gov(self):
        return self.m.governance


def _spend(amount="2500"):
    return dict(action="system_spend", wallet=TREASURY, to=RECIPIENT, amount=amount)


def _passed(chain, **params):
    ok, res = chain.propose(**(params or _spend()))
    assert ok, res
    pid = res["proposal_id"]
    assert chain.vote(V1, pid)[0] and chain.vote(V2, pid)[0]      # 700k of 1M ≥ 2/3
    assert chain.gov.proposals[pid].status == PASSED
    return pid


# ── proposing and voting ────────────────────────────────────────────────────────────────

def test_only_validators_propose():
    c = Chain()
    ok, err = c.propose(sender=HOLDER, **_spend())
    assert not ok and "validator" in err
    ok, res = c.propose(**_spend())
    assert ok and res["proposal_id"] == 1 and res["voting_ends"] == c.height + C.GOV_VOTING_PERIOD_BLOCKS


@pytest.mark.parametrize("params, why", [
    (dict(action="mint_everything"), "action"),
    (_spend() | {"wallet": C.SYSTEM_WALLET_ADDRESSES["GARBAGE_COLLECTOR"]}, "spendable"),
    (_spend() | {"wallet": "0x" + "99" * 20}, "spendable"),
    (_spend() | {"to": "not-an-address"}, "recipient"),
    (_spend() | {"to": ESCROW}, "ordinary"),
    (_spend("0"), "positive"),
    (_spend("1.0000000000000000001"), "18 decimal"),
    (dict(action="approve_fork", fork="F!", height=10**6, definition_hash="ab" * 32), "fork name"),
    (dict(action="approve_fork", fork="f1", height=1, definition_hash="ab" * 32), "passed"),
    (dict(action="approve_fork", fork="f1", height=10**6, definition_hash="zz"), "definition_hash"),
])
def test_malformed_proposals_are_refused(params, why):
    c = Chain()
    ok, err = c.propose(**params)
    assert not ok and why in err


def test_a_chain_without_system_wallets_has_nothing_to_spend():
    c = Chain()
    c.gov.system_wallets_enabled = False
    ok, err = c.propose(**_spend())
    assert not ok and "no system wallets" in err


def test_two_thirds_of_the_snapshot_stake_passes_and_votes_are_final():
    c = Chain()
    pid = c.propose(**_spend())[1]["proposal_id"]
    ok, res = c.vote(V1, pid)                                  # 400k: not yet
    assert ok and res["status"] == VOTING
    assert not c.vote(V1, pid)[0]                              # no second vote
    assert not c.vote(HOLDER, pid)[0]                          # not in the snapshot
    ok, res = c.vote(V2, pid)                                  # 700k ≥ 666.7k
    assert ok and res["status"] == PASSED
    assert res["timelock_ends"] == c.height + C.GOV_TIMELOCK_BLOCKS


def test_a_proposal_is_rejected_once_approval_is_out_of_reach():
    c = Chain()
    pid = c.propose(**_spend())[1]["proposal_id"]
    assert c.vote(V2, pid, support=False)[1]["status"] == VOTING     # 300k no: 700k still possible
    assert c.vote(V3, pid, support=False)[1]["status"] == REJECTED   # 600k no: at most 400k yes


def test_the_voting_window_closes_by_height():
    c = Chain()
    pid = c.propose(**_spend())[1]["proposal_id"]
    p = c.gov.proposals[pid]
    c.height = p.voting_ends - 1                                # next block: the window's last
    assert c.vote(V1, pid)[0]
    ok, err = c.vote(V2, pid)                                   # one past it
    assert not ok and "not open for voting (rejected)" in err


def test_the_stake_snapshot_is_taken_at_proposal_time():
    c = Chain()
    pid = c.propose(**_spend())[1]["proposal_id"]
    c.m.oracle_committee[HOLDER.lower()] = D(5_000_000)        # joins after the proposal
    assert not c.vote(HOLDER, pid)[0]
    assert c.gov.proposals[pid].total_weight == D(1_000_000)


def test_open_proposals_are_bounded():
    c = Chain()
    for _ in range(4):
        assert c.propose(**_spend())[0]
    ok, err = c.propose(**_spend())
    assert not ok and "at most 4 open" in err


# ── timelock, execution and value ───────────────────────────────────────────────────────

def test_a_system_spend_executes_after_its_timelock_and_moves_exactly_the_amount():
    c = Chain()
    pid = _passed(c)
    p = c.gov.proposals[pid]
    early = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(early, height=p.timelock_ends - 1, balances={TREASURY: D(20_000_000)})
    assert not early.success and "timelocked" in early.error
    run = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=p.timelock_ends, balances={TREASURY: D(20_000_000)})
    assert run.success and run.result["status"] == EXECUTED
    assert c.deltas() == {TREASURY: D(-2500), RECIPIENT: D(2500)}
    again = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(again, height=p.timelock_ends + 1, balances={TREASURY: D(20_000_000)})
    assert not again.success and "executed" in again.error


def test_a_spend_beyond_the_wallet_balance_waits_and_can_be_retried():
    c = Chain()
    pid = _passed(c)
    p = c.gov.proposals[pid]
    short = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(short, height=p.timelock_ends, balances={TREASURY: D(100)})
    assert not short.success and c.gov.proposals[pid].status == PASSED
    retry = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(retry, height=p.timelock_ends + 1, balances={TREASURY: D(5000)})
    assert retry.success


def test_two_spends_in_one_block_cannot_overdraw_the_wallet():
    c = Chain()
    a, b = _passed(c), _passed(c)
    h = max(c.gov.proposals[a].timelock_ends, c.gov.proposals[b].timelock_ends)
    ta = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=a)
    tb = c.tx(HOLDER2, ExchangeOpType.GOV_EXECUTE, proposal_id=b)
    c.block(ta, tb, height=h, balances={TREASURY: D(4000)})
    assert ta.success and not tb.success                        # 2500 + 2500 > 4000


def test_an_unexecuted_proposal_expires():
    c = Chain()
    pid = _passed(c)
    p = c.gov.proposals[pid]
    close = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(close, height=p.execute_by + 1, balances={TREASURY: D(20_000_000)})
    assert close.success and close.result["status"] == EXPIRED and not close.result["executed"]
    assert c.deltas() == {}


# ── holders' veto ───────────────────────────────────────────────────────────────────────

def test_vetoes_lock_real_qrdx_and_the_threshold_stops_the_proposal():
    c = Chain()
    pid = _passed(c)
    half = D(C.GOV_VETO_THRESHOLD_QRDX) / 2
    v1 = c.tx(HOLDER, ExchangeOpType.GOV_VETO, proposal_id=pid, amount=str(half))
    c.block(v1)
    assert v1.success and c.gov.proposals[pid].status == PASSED
    assert c.deltas() == {HOLDER: -half, ESCROW: half}
    v2 = c.tx(HOLDER2, ExchangeOpType.GOV_VETO, proposal_id=pid, amount=str(half))
    c.block(v2)
    assert v2.success and v2.result["status"] == VETOED
    # HOLDER2's lock and both refunds net out: everyone has their QRDX back, the escrow is empty.
    assert c.deltas() == {HOLDER: half, ESCROW: -half}
    run = c.tx(V1, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=c.gov.proposals[pid].timelock_ends)
    assert not run.success and "vetoed" in run.error


def test_a_veto_cannot_lock_more_than_the_holder_has():
    c = Chain()
    pid = _passed(c)
    v = c.tx(HOLDER, ExchangeOpType.GOV_VETO, proposal_id=pid, amount="1000")
    c.block(v, balances={HOLDER: D(999)})
    assert not v.success and "insufficient" in v.error


def test_vetoes_are_open_only_during_the_timelock():
    c = Chain()
    pid = c.propose(**_spend())[1]["proposal_id"]
    v = c.tx(HOLDER, ExchangeOpType.GOV_VETO, proposal_id=pid, amount="1")
    c.block(v)
    assert not v.success                                        # still voting
    c.vote(V1, pid), c.vote(V2, pid)
    late = c.tx(HOLDER, ExchangeOpType.GOV_VETO, proposal_id=pid, amount="1")
    c.block(late, height=c.gov.proposals[pid].timelock_ends)
    assert not late.success                                     # the timelock has ended


def test_a_failed_veto_is_returned_when_the_proposal_executes():
    c = Chain()
    pid = _passed(c)
    c.block(c.tx(HOLDER, ExchangeOpType.GOV_VETO, proposal_id=pid, amount="1234.5"))
    run = c.tx(V3, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=c.gov.proposals[pid].timelock_ends, balances={TREASURY: D(10_000)})
    assert run.success
    assert c.deltas() == {TREASURY: D(-2500), RECIPIENT: D(2500), ESCROW: D("-1234.5"),
                          HOLDER: D("1234.5")}


# ── the master controller ───────────────────────────────────────────────────────────────

def test_the_master_controller_retires_at_the_sunset_height():
    Chain()
    sunset = C.SYSTEM_WALLET_MASTER_SUNSET_HEIGHT
    assert master_authority(sunset - 1)[0]
    ok, why = master_authority(sunset)
    assert not ok and str(sunset) in why


def test_validators_can_freeze_the_master_controller_earlier():
    c = Chain()
    pid = _passed(c, action="freeze_master")
    at = c.gov.proposals[pid].timelock_ends
    assert master_authority(at)[0]
    run = c.tx(V1, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=at)
    assert run.success and run.result["master_frozen_at"] == at
    assert master_authority(at - 1)[0]                          # earlier blocks were fine
    ok, why = master_authority(at)
    assert not ok and "froze" in why
    ok, err = c.propose(action="freeze_master")
    assert not ok and "already frozen" in err


async def test_a_frozen_master_cannot_spend_from_a_system_wallet():
    """At the shared check used by admission, block import and the proposer."""
    from qrdx.contracts.evm_mempool import verify_delegated_spend
    from qrdx.crypto.pq.dilithium import generate_keypair
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.transactions.pq_tx import PQTransaction

    priv, pub = generate_keypair()
    wallet = bytes.fromhex(C.SYSTEM_WALLET_ADDRESSES["DEVELOPER_FUND"][2:])
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        await db.connection.execute(
            "INSERT INTO system_wallets (address, name, description, wallet_type, "
            "controller_address, is_burner, category) VALUES (?, 'Dev', 't', 't', ?, 0, 'c')",
            (C.SYSTEM_WALLET_ADDRESSES["DEVELOPER_FUND"], pub.to_address()))
        await db.connection.commit()
        raw = "0x" + PQTransaction(chain_id=C.CHAIN_ID, nonce=0, gas_price=10 ** 9,
                                   gas_limit=500_000, to=bytes.fromhex("cd" * 20), value=1,
                                   data=b"", on_behalf_of=wallet).sign(priv).encode().hex()
        c = Chain()
        assert (await verify_delegated_spend(db, raw, 50))[0]
        assert not (await verify_delegated_spend(db, raw, C.SYSTEM_WALLET_MASTER_SUNSET_HEIGHT))[0]
        c.gov.master_frozen_at = 40
        ok, why = await verify_delegated_spend(db, raw, 50)
        assert not ok and "froze" in why
    finally:
        await db.close()
        for s in ("", "-wal", "-shm"):
            if os.path.exists(path + s):
                os.remove(path + s)


# ── fork approval ───────────────────────────────────────────────────────────────────────

# A proposal made in block 1 passes in block 3 (two votes), so its timelock ends — and the
# approval executes — at block 3 + GOV_TIMELOCK_BLOCKS.
APPROVED_AT = 3 + C.GOV_TIMELOCK_BLOCKS
LEAD = 50


def _upgrade_spec(height=APPROVED_AT + 10_000):
    return cs.build_spec("qrdx-gov-test", 4242, {"GOV_FORK_APPROVAL_LEAD_BLOCKS": LEAD}, forks=[
        {"name": "randao", "height": height, "features": ["randao_selection"]}])


def _approve(c, spec, name="randao"):
    fork = next(f for f in spec.forks if f["name"] == name)
    pid = _passed(c, action="approve_fork", fork=name, height=fork["height"],
                  definition_hash=cs.ChainSpec.fork_definition_hash(fork))
    run = c.tx(V1, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=c.gov.proposals[pid].timelock_ends)
    assert run.success, run.error
    assert c.height == APPROVED_AT
    return pid


def test_a_fork_stays_dormant_until_validators_approve_it():
    spec = _upgrade_spec()
    H = spec.forks[0]["height"]
    c = Chain()
    with cs.use_spec(spec):
        assert spec.is_scheduled("randao_selection", H)
        assert not cs.is_active("randao_selection", 10 ** 7)        # scheduled, not approved
        _approve(c, spec)                                           # well before H - LEAD
        assert not cs.is_active("randao_selection", H - 1)
        assert cs.is_active("randao_selection", H)
        assert cs.active_features(H) == ["randao_selection"]


def test_a_late_approval_does_not_activate_the_fork():
    """Approval must execute at least GOV_FORK_APPROVAL_LEAD_BLOCKS before the fork — deeper
    than any reorg — so no reorg can change whether it activates."""
    spec = _upgrade_spec(height=APPROVED_AT + LEAD - 1)            # approve_by is one block too early
    c = Chain()
    with cs.use_spec(spec):
        _approve(c, spec)
        assert not cs.is_active("randao_selection", 10 ** 7)
        report = cs.report(spec, "ab" * 32, 10 ** 7, "test")
        assert report["forks"][0]["status"].startswith("dormant")
    on_time = _upgrade_spec(height=APPROVED_AT + LEAD)              # exactly in time
    c = Chain()
    with cs.use_spec(on_time):
        _approve(c, on_time)
        assert cs.is_active("randao_selection", APPROVED_AT + LEAD)


def test_an_approval_names_the_exact_fork_definition():
    approved_spec = _upgrade_spec()
    edited_spec = _upgrade_spec(height=approved_spec.forks[0]["height"] + 20)
    c = Chain()
    with cs.use_spec(approved_spec):
        _approve(c, approved_spec)
    with cs.use_spec(edited_spec):                    # the release moved the fork: re-approve
        assert not cs.is_active("randao_selection", 10 ** 7)


def test_an_approval_is_recorded_whatever_the_nodes_own_spec_says():
    """Nodes that have not installed an upgrade must keep identical state: approve_fork never
    consults the local spec."""
    c = Chain()
    with cs.use_spec(cs.build_spec("qrdx-gov-test", 4242, {})):          # no forks at all
        _passed(c, action="approve_fork", fork="future", height=10 ** 7, definition_hash="cd" * 32)


def test_a_dev_fork_may_skip_approval_but_a_real_one_may_not():
    dev = cs.build_spec("qrdx-dev", 88888, {}, dev=True, forks=[
        {"name": "f", "height": 10, "features": ["randao_selection"], "approval": "none"}])
    with cs.use_spec(dev):
        assert cs.is_active("randao_selection", 10)
    with pytest.raises(cs.ChainSpecError, match="only a dev network"):
        cs.build_spec("qrdx-gov-test", 4242, {}, forks=[
            {"name": "f", "height": 10, "features": ["randao_selection"], "approval": "none"}])


# ── determinism ─────────────────────────────────────────────────────────────────────────

def _script(c):
    pid = _passed(c)
    c.block(c.tx(HOLDER, ExchangeOpType.GOV_VETO, proposal_id=pid, amount="7"))
    run = c.tx(V2, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    return c.block(run, height=c.gov.proposals[pid].timelock_ends, balances={TREASURY: D(9000)})


def test_two_nodes_reach_the_same_root_and_governance_is_in_it():
    first = _script(Chain())
    second = _script(Chain())
    assert first == second
    c = Chain()
    before = c.block()
    c.propose(**_spend())
    assert c.m.compute_state_root() != before


def test_a_rejected_block_leaves_governance_untouched():
    c = Chain()
    pid = c.propose(**_spend())[1]["proposal_id"]
    root = c.m.compute_state_root()
    c.m.take_snapshot()
    c.m.begin_block(c.height + 1, 1)
    c.m.process_transaction(c.tx(V1, ExchangeOpType.GOV_VOTE, proposal_id=pid, support=True))
    assert c.gov.proposals[pid].yes > 0
    c.m.revert_block()
    assert c.gov.proposals[pid].yes == 0 and c.m.compute_state_root() == root


# ── through the database: the regression the live chain caught ─────────────────────────

async def test_a_system_spend_debits_the_wallet_in_the_ledger_and_conserves_value():
    """The integration testnet caught this: system wallets were funded at genesis as UTXO
    outputs, which balance READS fall back to, while account_state had no row for them. A
    governance spend's debit therefore found nothing to debit and was dropped — the recipient
    was credited, the treasury never debited: QRDX created from nothing. Genesis now funds them
    in account_state, and the flush logs any debit that finds no row as [VALUE-LOST]."""
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.validator.genesis_init import GenesisInitializer

    controller = PQPrivateKey.generate().public_key.to_address()
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        await GenesisInitializer(db).initialize_genesis(
            prefunded_accounts={HOLDER: (D(1000), "holder")},
            system_wallet_controller=controller, enable_system_wallets=True)
        fund = C.SYSTEM_WALLET_ADDRESSES["DEVELOPER_FUND"]
        start = await db.get_address_balance(fund)
        assert start == D(10_000_000)
        cur = await db.connection.execute(
            "SELECT balance FROM account_state WHERE LOWER(address) = LOWER(?)", (fund,))
        assert await cur.fetchone(), "a system wallet's genesis balance lives in account_state"
        assert await db.seed_genesis_account_state() >= 2       # restored after a reorg too

        c = Chain()
        pid = _passed(c, action="system_spend", wallet=fund, to=RECIPIENT, amount="1234.5")
        run = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
        h = c.gov.proposals[pid].timelock_ends
        await BP.preload_sender_balances(db, [run], c.m)        # the wallet's real balance
        ok, err, _root = BP.process_exchange_transactions(h, 1_700_000_000 + h, [run], c.m)
        assert ok and run.success, run.error
        c.m.commit_block()
        await BP.flush_exchange_balance_deltas(db, c.m, enforce=True)
        assert await db.get_address_balance(fund) == start - D("1234.5")
        assert await db.get_address_balance(RECIPIENT) == D("1234.5")
        holder_left = await db.get_address_balance(HOLDER)
        assert holder_left == D(1000) - run.fee()               # the executor paid only gas
    finally:
        await db.close()
        for s in ("", "-wal", "-shm"):
            if os.path.exists(path + s):
                os.remove(path + s)
