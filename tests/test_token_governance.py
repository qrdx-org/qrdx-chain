"""
Phase 7 — Token Standard & Governance Test Suite

Coverage:
  Step 9.1 : qRC20 Base Standard — deploy, transfer, approve, transferFrom,
             batchTransfer, bridgeMint, bridgeBurn, freeze, registry
  Step 9.2 : shouldTradeAfterDoomsday() — advisory hook, DoomsdayHook,
             three client modes (Strict / Warning / Permissionless)
  Step 10.1: On-Chain Governance — proposal lifecycle, stake-weighted voting,
             quorum/approval thresholds, delegation, timelock, guardian veto,
             parameter execution
"""

import hashlib
import time
import sys
import os
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

# ── Path setup ────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── qRC20 Token Standard (Step 9) ────────────────────────────────────
from qrdx.tokens.qrc20 import (
    QRC20Token,
    QRC20Registry,
    QRC20TransferEvent,
    QRC20ApprovalEvent,
    QRC20BridgeMintEvent,
    QRC20BridgeBurnEvent,
    QRC20Error,
    InsufficientBalanceError,
    InsufficientAllowanceError,
    InvalidSignatureError,
    TokenFrozenError,
)
from qrdx.tokens.doomsday_hook import (
    DoomsdayHook,
    DoomsdayTradingMode,
    DoomsdayTradingPreference,
)

# ── Governance (Step 10) ─────────────────────────────────────────────
from qrdx.governance.proposals import (
    GovernanceError,
    InvalidProposalError,
    Proposal,
    ProposalLifecycleError,
    ProposalStatus,
    ProposalType,
)
from qrdx.governance.voting import (
    AlreadyVotedError,
    InsufficientVotingPowerError,
    QuorumNotReachedError,
    Vote,
    VoteRecord,
    VotingClosedError,
    VotingEngine,
    VotingResult,
    Delegation,
)
from qrdx.governance.execution import (
    GovernanceExecutor,
    GuardianVetoError,
    TimelockEntry,
    TimelockError,
    TimelockNotReadyError,
    TimelockQueue,
    TimelockStatus,
)

# ── Constants ─────────────────────────────────────────────────────────
from qrdx.constants import (
    GOVERNANCE_APPROVAL_THRESHOLD,
    GOVERNANCE_DEFAULT_PARAMETERS,
    GOVERNANCE_GUARDIAN_THRESHOLD,
    GOVERNANCE_GUARDIAN_TOTAL,
    GOVERNANCE_PROPOSAL_DEPOSIT,
    GOVERNANCE_QUORUM_THRESHOLD,
    GOVERNANCE_SUPERMAJORITY_THRESHOLD,
    GOVERNANCE_TIMELOCK_DEFAULT_DELAY_SECONDS,
    GOVERNANCE_TIMELOCK_MAX_DELAY_SECONDS,
    GOVERNANCE_TIMELOCK_MIN_DELAY_SECONDS,
    GOVERNANCE_VOTE_ABSTAIN,
    GOVERNANCE_VOTE_AGAINST,
    GOVERNANCE_VOTE_FOR,
    GOVERNANCE_VOTING_PERIOD_DAYS,
    QRC20_DEFAULT_DECIMALS,
    QRC20_DOMAIN_APPROVE,
    QRC20_DOMAIN_TRANSFER,
    QRC20_MAX_BATCH_SIZE,
    QRC20_MAX_SUPPLY,
    QRC20_SHIELDED_TOKENS,
)


# ══════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════

ALICE = "0xPQ" + "A1" * 32
BOB = "0xPQ" + "B2" * 32
CAROL = "0xPQ" + "C3" * 32
DAVE = "0xPQ" + "D4" * 32
EVE = "0xPQ" + "E5" * 32
BRIDGE_OP = "0xPQ" + "FF" * 32


def make_token(
    name="TestToken",
    symbol="TST",
    supply=Decimal("1000000"),
    deployer=ALICE,
    **kwargs,
) -> QRC20Token:
    """Helper to create a qRC20 token for testing."""
    return QRC20Token(
        name=name,
        symbol=symbol,
        total_supply=supply,
        deployer=deployer,
        **kwargs,
    )


def make_proposal(
    pid=1,
    title="Test Proposal",
    description="Test description",
    ptype=ProposalType.PARAMETER_CHANGE,
    proposer=ALICE,
    deposit=None,
    **kwargs,
) -> Proposal:
    """Helper to create a governance proposal for testing."""
    dep = deposit if deposit is not None else GOVERNANCE_PROPOSAL_DEPOSIT
    return Proposal(
        id=pid,
        title=title,
        description=description,
        proposal_type=ptype,
        proposer=proposer,
        deposit=dep,
        **kwargs,
    )


# ══════════════════════════════════════════════════════════════════════
#  STEP 9.1 — qRC20 BASE STANDARD
# ══════════════════════════════════════════════════════════════════════


class TestQRC20Deploy:
    """Token deployment and basic properties."""

    def test_deploy_basic(self):
        token = make_token()
        assert token.name == "TestToken"
        assert token.symbol == "TST"
        assert token.decimals == QRC20_DEFAULT_DECIMALS
        assert token.total_supply == Decimal("1000000")
        assert token.balance_of(ALICE) == Decimal("1000000")
        assert token.deployer == ALICE

    def test_deploy_custom_decimals(self):
        token = make_token(decimals=8)
        assert token.decimals == 8

    def test_deploy_zero_supply(self):
        token = QRC20Token(name="Zero", symbol="ZRO", total_supply=Decimal("0"))
        assert token.total_supply == Decimal("0")

    def test_deploy_empty_name_raises(self):
        with pytest.raises(QRC20Error, match="name cannot be empty"):
            QRC20Token(name="", symbol="X")

    def test_deploy_empty_symbol_raises(self):
        with pytest.raises(QRC20Error, match="symbol cannot be empty"):
            QRC20Token(name="X", symbol="")

    def test_deploy_negative_supply_raises(self):
        with pytest.raises(QRC20Error, match="negative"):
            make_token(supply=Decimal("-1"))

    def test_deploy_invalid_decimals_raises(self):
        with pytest.raises(QRC20Error, match="Decimals"):
            make_token(decimals=19)

    def test_deploy_exceeds_max_supply_raises(self):
        with pytest.raises(QRC20Error, match="exceeds max"):
            make_token(supply=QRC20_MAX_SUPPLY + 1)

    def test_to_dict(self):
        token = make_token()
        d = token.to_dict()
        assert d["symbol"] == "TST"
        assert d["totalSupply"] == "1000000"
        assert d["frozen"] is False
        assert d["holders"] == 1

    def test_repr(self):
        token = make_token()
        assert "TST" in repr(token)


class TestQRC20BalanceOf:
    """balanceOf queries."""

    def test_balance_of_deployer(self):
        token = make_token()
        assert token.balance_of(ALICE) == Decimal("1000000")

    def test_balance_of_unknown(self):
        token = make_token()
        assert token.balance_of(BOB) == Decimal("0")

    def test_nonce_starts_at_zero(self):
        token = make_token()
        assert token.nonce_of(ALICE) == 0


class TestQRC20Transfer:
    """transfer() with PQ proof."""

    @pytest.mark.asyncio
    async def test_basic_transfer(self):
        token = make_token()
        event = await token.transfer(ALICE, BOB, Decimal("100"))
        assert isinstance(event, QRC20TransferEvent)
        assert token.balance_of(ALICE) == Decimal("999900")
        assert token.balance_of(BOB) == Decimal("100")
        assert event.amount == Decimal("100")
        assert event.proof_hash  # non-empty

    @pytest.mark.asyncio
    async def test_transfer_increments_nonce(self):
        token = make_token()
        await token.transfer(ALICE, BOB, Decimal("1"))
        assert token.nonce_of(ALICE) == 1
        await token.transfer(ALICE, BOB, Decimal("1"))
        assert token.nonce_of(ALICE) == 2

    @pytest.mark.asyncio
    async def test_transfer_insufficient_balance(self):
        token = make_token()
        with pytest.raises(InsufficientBalanceError):
            await token.transfer(ALICE, BOB, Decimal("1000001"))

    @pytest.mark.asyncio
    async def test_transfer_zero_amount_raises(self):
        token = make_token()
        with pytest.raises(QRC20Error, match="positive"):
            await token.transfer(ALICE, BOB, Decimal("0"))

    @pytest.mark.asyncio
    async def test_transfer_to_self_raises(self):
        token = make_token()
        with pytest.raises(QRC20Error, match="self"):
            await token.transfer(ALICE, ALICE, Decimal("10"))

    @pytest.mark.asyncio
    async def test_transfer_emits_event(self):
        token = make_token()
        await token.transfer(ALICE, BOB, Decimal("50"))
        assert len(token.events) == 1
        assert token.events[0].token_symbol == "TST"

    @pytest.mark.asyncio
    async def test_transfer_with_signature_verification(self):
        """When verify_signature_fn rejects, transfer fails."""
        async def reject_all(addr, msg, sig):
            return False

        token = make_token(verify_signature_fn=reject_all)
        with pytest.raises(InvalidSignatureError):
            await token.transfer(ALICE, BOB, Decimal("10"), signature=b"bad")

    @pytest.mark.asyncio
    async def test_transfer_with_valid_signature(self):
        """When verify_signature_fn accepts, transfer succeeds."""
        async def accept_all(addr, msg, sig):
            return True

        token = make_token(verify_signature_fn=accept_all)
        ev = await token.transfer(ALICE, BOB, Decimal("10"), signature=b"good")
        assert ev.amount == Decimal("10")


class TestQRC20Approve:
    """approve() and allowance()."""

    @pytest.mark.asyncio
    async def test_approve(self):
        token = make_token()
        event = await token.approve(ALICE, BOB, Decimal("500"))
        assert isinstance(event, QRC20ApprovalEvent)
        assert token.allowance(ALICE, BOB) == Decimal("500")

    @pytest.mark.asyncio
    async def test_approve_overwrite(self):
        token = make_token()
        await token.approve(ALICE, BOB, Decimal("500"))
        await token.approve(ALICE, BOB, Decimal("200"))
        assert token.allowance(ALICE, BOB) == Decimal("200")

    @pytest.mark.asyncio
    async def test_approve_negative_raises(self):
        token = make_token()
        with pytest.raises(QRC20Error, match="negative"):
            await token.approve(ALICE, BOB, Decimal("-1"))

    @pytest.mark.asyncio
    async def test_approve_zero_allowed(self):
        token = make_token()
        await token.approve(ALICE, BOB, Decimal("0"))
        assert token.allowance(ALICE, BOB) == Decimal("0")


class TestQRC20TransferFrom:
    """transferFrom() with allowance and PQ proof."""

    @pytest.mark.asyncio
    async def test_transfer_from_basic(self):
        token = make_token()
        await token.approve(ALICE, BOB, Decimal("300"))
        event = await token.transfer_from(BOB, ALICE, CAROL, Decimal("200"))
        assert isinstance(event, QRC20TransferEvent)
        assert token.balance_of(ALICE) == Decimal("999800")
        assert token.balance_of(CAROL) == Decimal("200")
        assert token.allowance(ALICE, BOB) == Decimal("100")

    @pytest.mark.asyncio
    async def test_transfer_from_exceeds_allowance(self):
        token = make_token()
        await token.approve(ALICE, BOB, Decimal("100"))
        with pytest.raises(InsufficientAllowanceError):
            await token.transfer_from(BOB, ALICE, CAROL, Decimal("200"))

    @pytest.mark.asyncio
    async def test_transfer_from_exceeds_balance(self):
        token = make_token()
        await token.approve(ALICE, BOB, Decimal("2000000"))
        with pytest.raises(InsufficientBalanceError):
            await token.transfer_from(BOB, ALICE, CAROL, Decimal("1000001"))

    @pytest.mark.asyncio
    async def test_transfer_from_zero_amount_raises(self):
        token = make_token()
        await token.approve(ALICE, BOB, Decimal("100"))
        with pytest.raises(QRC20Error, match="positive"):
            await token.transfer_from(BOB, ALICE, CAROL, Decimal("0"))


class TestQRC20BatchTransfer:
    """Batch transfers."""

    @pytest.mark.asyncio
    async def test_batch_transfer(self):
        token = make_token()
        events = await token.batch_transfer(
            ALICE,
            [(BOB, Decimal("100")), (CAROL, Decimal("200"))],
        )
        assert len(events) == 2
        assert token.balance_of(BOB) == Decimal("100")
        assert token.balance_of(CAROL) == Decimal("200")
        assert token.balance_of(ALICE) == Decimal("999700")

    @pytest.mark.asyncio
    async def test_batch_exceeds_max_size(self):
        token = make_token()
        too_many = [(BOB, Decimal("1"))] * (QRC20_MAX_BATCH_SIZE + 1)
        with pytest.raises(QRC20Error, match="Batch size"):
            await token.batch_transfer(ALICE, too_many)


class TestQRC20Bridge:
    """Bridge mint/burn hooks."""

    @pytest.mark.asyncio
    async def test_bridge_mint(self):
        token = make_token(supply=Decimal("0"))
        token.add_bridge_operator(BRIDGE_OP)
        event = await token.bridge_mint(
            BRIDGE_OP, BOB, Decimal("500"), source_chain_id=1, source_tx_hash="0xabc123"
        )
        assert isinstance(event, QRC20BridgeMintEvent)
        assert token.balance_of(BOB) == Decimal("500")
        assert token.total_supply == Decimal("500")

    @pytest.mark.asyncio
    async def test_bridge_mint_unauthorized_raises(self):
        token = make_token(supply=Decimal("0"))
        with pytest.raises(QRC20Error, match="not an authorized"):
            await token.bridge_mint(
                BOB, CAROL, Decimal("100"), source_chain_id=1, source_tx_hash="0x"
            )

    @pytest.mark.asyncio
    async def test_bridge_burn(self):
        token = make_token()
        token.add_bridge_operator(BRIDGE_OP)
        event = await token.bridge_burn(
            BRIDGE_OP, ALICE, Decimal("100"), destination_address="0xETH_ADDR"
        )
        assert isinstance(event, QRC20BridgeBurnEvent)
        assert token.balance_of(ALICE) == Decimal("999900")
        assert token.total_supply == Decimal("999900")

    @pytest.mark.asyncio
    async def test_bridge_burn_insufficient_balance(self):
        token = make_token()
        token.add_bridge_operator(BRIDGE_OP)
        with pytest.raises(InsufficientBalanceError):
            await token.bridge_burn(
                BRIDGE_OP, BOB, Decimal("1"), destination_address="0x"
            )

    @pytest.mark.asyncio
    async def test_bridge_mint_exceeds_max_supply(self):
        token = make_token(supply=QRC20_MAX_SUPPLY)
        token.add_bridge_operator(BRIDGE_OP)
        with pytest.raises(QRC20Error, match="exceed max supply"):
            await token.bridge_mint(
                BRIDGE_OP, BOB, Decimal("1"), source_chain_id=1, source_tx_hash="0x"
            )

    def test_bridge_info(self):
        token = make_token(source_chain_id=1, source_token_address="0xETH")
        info = token.bridge_info()
        assert info["sourceChainId"] == 1
        assert info["sourceToken"] == "0xETH"

    def test_add_remove_bridge_operator(self):
        token = make_token()
        token.add_bridge_operator(BRIDGE_OP)
        token.remove_bridge_operator(BRIDGE_OP)
        with pytest.raises(QRC20Error, match="not an authorized"):
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                token.bridge_mint(BRIDGE_OP, BOB, Decimal("1"), 1, "0x")
            )


class TestQRC20Freeze:
    """Governance-controlled freeze."""

    @pytest.mark.asyncio
    async def test_frozen_transfer_raises(self):
        token = make_token()
        token.freeze()
        assert token.is_frozen
        with pytest.raises(TokenFrozenError):
            await token.transfer(ALICE, BOB, Decimal("10"))

    @pytest.mark.asyncio
    async def test_unfreeze_allows_transfer(self):
        token = make_token()
        token.freeze()
        token.unfreeze()
        assert not token.is_frozen
        await token.transfer(ALICE, BOB, Decimal("10"))

    @pytest.mark.asyncio
    async def test_frozen_approve_raises(self):
        token = make_token()
        token.freeze()
        with pytest.raises(TokenFrozenError):
            await token.approve(ALICE, BOB, Decimal("100"))

    @pytest.mark.asyncio
    async def test_frozen_bridge_mint_raises(self):
        token = make_token(supply=Decimal("0"))
        token.add_bridge_operator(BRIDGE_OP)
        token.freeze()
        with pytest.raises(TokenFrozenError):
            await token.bridge_mint(BRIDGE_OP, BOB, Decimal("10"), 1, "0x")


class TestQRC20Registry:
    """Token registry operations."""

    def test_deploy_and_get(self):
        registry = QRC20Registry()
        token = make_token(symbol="AAA")
        registry.deploy(token)
        assert registry.get("AAA") is token
        assert registry.exists("AAA")
        assert registry.count == 1

    def test_deploy_duplicate_raises(self):
        registry = QRC20Registry()
        registry.deploy(make_token(symbol="DUP"))
        with pytest.raises(QRC20Error, match="already registered"):
            registry.deploy(make_token(symbol="DUP"))

    def test_registry_full_raises(self):
        registry = QRC20Registry(max_tokens=2)
        registry.deploy(make_token(symbol="A1"))
        registry.deploy(make_token(symbol="A2"))
        with pytest.raises(QRC20Error, match="full"):
            registry.deploy(make_token(symbol="A3"))

    def test_get_or_raise(self):
        registry = QRC20Registry()
        with pytest.raises(QRC20Error, match="not found"):
            registry.get_or_raise("NOPE")

    def test_list_and_all_tokens(self):
        registry = QRC20Registry()
        registry.deploy(make_token(symbol="X1"))
        registry.deploy(make_token(symbol="X2"))
        assert set(registry.list_tokens()) == {"X1", "X2"}
        assert len(registry.all_tokens()) == 2

    def test_remove(self):
        registry = QRC20Registry()
        registry.deploy(make_token(symbol="REM"))
        assert registry.remove("REM")
        assert not registry.exists("REM")
        assert not registry.remove("REM")  # idempotent

    def test_to_dict(self):
        registry = QRC20Registry()
        registry.deploy(make_token(symbol="D1"))
        d = registry.to_dict()
        assert d["tokenCount"] == 1
        assert "D1" in d["tokens"]


# ══════════════════════════════════════════════════════════════════════
#  STEP 9.2 — shouldTradeAfterDoomsday() HOOK
# ══════════════════════════════════════════════════════════════════════


class TestDoomsdayHookInactive:
    """When Doomsday is NOT active, all tokens can trade."""

    def test_should_trade_when_inactive(self):
        protocol = MagicMock()
        protocol.is_active = False
        hook = DoomsdayHook(doomsday_protocol=protocol)

        token = make_token(post_doomsday_trade=True)
        pref = hook.should_trade_after_doomsday(token)
        assert pref.should_trade is True
        assert pref.doomsday_active is False

    def test_all_tokens_trade_when_inactive(self):
        protocol = MagicMock()
        protocol.is_active = False
        hook = DoomsdayHook(doomsday_protocol=protocol)

        token_backed = make_token(symbol="qETH", post_doomsday_trade=True)
        token_unbacked = make_token(symbol="SHADY", post_doomsday_trade=False)

        assert hook.should_trade_after_doomsday(token_backed).should_trade is True
        assert hook.should_trade_after_doomsday(token_unbacked).should_trade is True


class TestDoomsdayHookActive:
    """When Doomsday IS active, advisory flags matter."""

    def test_backed_token_can_trade(self):
        protocol = MagicMock()
        protocol.is_active = True
        hook = DoomsdayHook(doomsday_protocol=protocol)

        token = make_token(symbol="qETH", post_doomsday_trade=True)
        pref = hook.should_trade_after_doomsday(token)
        assert pref.should_trade is True
        assert pref.doomsday_active is True
        assert "backed" in pref.reason

    def test_unbacked_token_should_not_trade(self):
        protocol = MagicMock()
        protocol.is_active = True
        hook = DoomsdayHook(doomsday_protocol=protocol)

        token = make_token(symbol="SHADY", post_doomsday_trade=False)
        pref = hook.should_trade_after_doomsday(token)
        assert pref.should_trade is False
        assert "NOT advisable" in pref.reason

    def test_evaluate_all(self):
        protocol = MagicMock()
        protocol.is_active = True
        hook = DoomsdayHook(doomsday_protocol=protocol)

        tokens = [
            make_token(symbol="qETH", post_doomsday_trade=True),
            make_token(symbol="SHADY", post_doomsday_trade=False),
        ]
        results = hook.evaluate_all(tokens)
        assert len(results) == 2
        assert results[0].should_trade is True
        assert results[1].should_trade is False


class TestDoomsdayClientModes:
    """Three client enforcement modes (§9.3)."""

    def _active_hook(self):
        protocol = MagicMock()
        protocol.is_active = True
        return DoomsdayHook(doomsday_protocol=protocol)

    def test_strict_blocks_unbacked(self):
        hook = self._active_hook()
        token = make_token(symbol="SHADY", post_doomsday_trade=False)
        result = hook.check_client_mode(token, DoomsdayTradingMode.STRICT)
        assert result["allowed"] is False
        assert result["warning"] != ""

    def test_strict_allows_backed(self):
        hook = self._active_hook()
        token = make_token(symbol="qETH", post_doomsday_trade=True)
        result = hook.check_client_mode(token, DoomsdayTradingMode.STRICT)
        assert result["allowed"] is True

    def test_warning_allows_with_warning(self):
        hook = self._active_hook()
        token = make_token(symbol="SHADY", post_doomsday_trade=False)
        result = hook.check_client_mode(token, DoomsdayTradingMode.WARNING)
        assert result["allowed"] is True
        assert result["warning"] != ""

    def test_permissionless_ignores_flag(self):
        hook = self._active_hook()
        token = make_token(symbol="SHADY", post_doomsday_trade=False)
        result = hook.check_client_mode(token, DoomsdayTradingMode.PERMISSIONLESS)
        assert result["allowed"] is True
        assert result["warning"] == ""


class TestDoomsdayHookEdgeCases:
    """Edge cases for DoomsdayHook."""

    def test_no_protocol_means_inactive(self):
        hook = DoomsdayHook(doomsday_protocol=None)
        assert hook.is_doomsday_active is False
        token = make_token(post_doomsday_trade=False)
        pref = hook.should_trade_after_doomsday(token)
        assert pref.should_trade is True

    def test_cache_populated(self):
        hook = DoomsdayHook(doomsday_protocol=None)
        token = make_token(symbol="CACHED")
        hook.should_trade_after_doomsday(token)
        cached = hook.get_cached_preference("CACHED")
        assert cached is not None
        assert cached.token_symbol == "CACHED"

    def test_clear_cache(self):
        hook = DoomsdayHook(doomsday_protocol=None)
        hook.should_trade_after_doomsday(make_token(symbol="C1"))
        hook.clear_cache()
        assert hook.get_cached_preference("C1") is None

    def test_to_dict(self):
        hook = DoomsdayHook(doomsday_protocol=None)
        d = hook.to_dict()
        assert "doomsdayActive" in d
        assert "cachedPreferences" in d

    def test_preference_to_dict(self):
        pref = DoomsdayTradingPreference(
            token_symbol="TST",
            should_trade=True,
            reason="test",
            doomsday_active=False,
        )
        d = pref.to_dict()
        assert d["tokenSymbol"] == "TST"
        assert d["shouldTrade"] is True


# ══════════════════════════════════════════════════════════════════════
#  STEP 10.1 — ON-CHAIN GOVERNANCE: PROPOSALS
# ══════════════════════════════════════════════════════════════════════


class TestProposalCreation:
    """Proposal construction and validation."""

    def test_create_basic(self):
        p = make_proposal()
        assert p.id == 1
        assert p.status == ProposalStatus.DRAFT
        assert not p.is_terminal
        assert not p.is_votable

    def test_create_missing_title_raises(self):
        with pytest.raises(InvalidProposalError, match="title"):
            make_proposal(title="")

    def test_create_missing_description_raises(self):
        with pytest.raises(InvalidProposalError, match="description"):
            make_proposal(description="")

    def test_create_missing_proposer_raises(self):
        with pytest.raises(InvalidProposalError, match="Proposer"):
            make_proposal(proposer="")

    def test_proposal_hash_deterministic(self):
        p = make_proposal()
        h1 = p.proposal_hash
        h2 = p.proposal_hash
        assert h1 == h2
        assert len(h1) == 64  # 32-byte blake2b → hex

    def test_proposal_types(self):
        for pt in ProposalType:
            p = make_proposal(ptype=pt)
            assert p.proposal_type == pt

    def test_parameter_change_threshold(self):
        p = make_proposal(ptype=ProposalType.PARAMETER_CHANGE)
        assert p.approval_threshold == GOVERNANCE_APPROVAL_THRESHOLD
        assert not p.requires_supermajority

    def test_protocol_upgrade_supermajority(self):
        p = make_proposal(ptype=ProposalType.PROTOCOL_UPGRADE)
        assert p.requires_supermajority
        assert p.approval_threshold == GOVERNANCE_SUPERMAJORITY_THRESHOLD

    def test_to_dict_from_dict(self):
        p = make_proposal(parameters={"bridge_fee_bps": 15})
        d = p.to_dict()
        assert d["proposalType"] == "PARAMETER_CHANGE"
        p2 = Proposal.from_dict(d)
        assert p2.title == p.title
        assert p2.proposal_type == p.proposal_type


class TestProposalLifecycle:
    """State transitions through the full lifecycle."""

    def test_draft_to_discussion(self):
        p = make_proposal()
        p.submit_for_discussion()
        assert p.status == ProposalStatus.DISCUSSION

    def test_discussion_to_temperature(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        assert p.status == ProposalStatus.TEMPERATURE

    def test_temperature_to_active(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        assert p.status == ProposalStatus.ACTIVE
        assert p.is_votable
        assert p.voting_start is not None
        assert p.voting_end > p.voting_start

    def test_active_to_passed(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        assert p.status == ProposalStatus.PASSED

    def test_active_to_defeated(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_defeated()
        assert p.status == ProposalStatus.DEFEATED
        assert p.is_terminal

    def test_active_to_expired(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_expired()
        assert p.status == ProposalStatus.EXPIRED

    def test_passed_to_queued(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        p.queue_for_execution(time.time() + 86400)
        assert p.status == ProposalStatus.QUEUED
        assert p.execution_eta is not None

    def test_queued_to_executed(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        p.queue_for_execution(time.time() + 86400)
        p.mark_executed()
        assert p.status == ProposalStatus.EXECUTED
        assert p.is_terminal

    def test_cancel_from_any_nonterminal(self):
        for status_target in [
            ProposalStatus.DISCUSSION,
            ProposalStatus.TEMPERATURE,
        ]:
            p = make_proposal()
            p.submit_for_discussion()
            if status_target == ProposalStatus.TEMPERATURE:
                p.start_temperature_check()
            p.cancel("User requested")
            assert p.status == ProposalStatus.CANCELLED
            assert p.is_terminal

    def test_cancel_terminal_raises(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_defeated()
        with pytest.raises(ProposalLifecycleError, match="Cannot cancel"):
            p.cancel()

    def test_invalid_transition_raises(self):
        p = make_proposal()
        with pytest.raises(ProposalLifecycleError, match="Cannot transition"):
            p.transition_to(ProposalStatus.ACTIVE, "skip")

    def test_history_tracking(self):
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        # INIT→DRAFT (implicit), DRAFT→DISCUSSION, DISCUSSION→TEMPERATURE
        assert len(p.history) >= 3

    def test_insufficient_deposit_raises(self):
        p = make_proposal(deposit=Decimal("0"))
        p.submit_for_discussion()
        p.start_temperature_check()
        with pytest.raises(GovernanceError, match="Deposit"):
            p.activate_voting()


# ══════════════════════════════════════════════════════════════════════
#  STEP 10.1 — ON-CHAIN GOVERNANCE: VOTING
# ══════════════════════════════════════════════════════════════════════


class TestVoteTypes:
    """Vote type helpers."""

    def test_vote_for(self):
        assert Vote.FOR == GOVERNANCE_VOTE_FOR
        assert Vote.name(Vote.FOR) == "FOR"

    def test_vote_against(self):
        assert Vote.name(Vote.AGAINST) == "AGAINST"

    def test_vote_abstain(self):
        assert Vote.name(Vote.ABSTAIN) == "ABSTAIN"

    def test_is_valid(self):
        assert Vote.is_valid(Vote.FOR)
        assert Vote.is_valid(Vote.AGAINST)
        assert Vote.is_valid(Vote.ABSTAIN)
        assert not Vote.is_valid(99)


class TestVotingEngine:
    """Stake-weighted voting mechanics."""

    def _make_engine(self, stakes=None, total_supply=Decimal("100000000")):
        """Create engine with stake lookup functions."""
        stakes = stakes or {}
        return VotingEngine(
            get_stake_fn=lambda addr: stakes.get(addr, Decimal("0")),
            get_total_supply_fn=lambda: total_supply,
        )

    def _activate_proposal(self, p=None):
        """Helper to create and activate a proposal."""
        p = p or make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=86400)
        return p

    def test_cast_vote_for(self):
        engine = self._make_engine({ALICE: Decimal("5000000")})
        p = self._activate_proposal()
        record = engine.cast_vote(p, ALICE, Vote.FOR)
        assert record.vote_type == Vote.FOR
        assert record.voting_power == Decimal("5000000")

    def test_cast_vote_against(self):
        engine = self._make_engine({BOB: Decimal("3000000")})
        p = self._activate_proposal()
        record = engine.cast_vote(p, BOB, Vote.AGAINST)
        assert record.vote_type == Vote.AGAINST

    def test_cast_vote_abstain(self):
        engine = self._make_engine({CAROL: Decimal("2000000")})
        p = self._activate_proposal()
        record = engine.cast_vote(p, CAROL, Vote.ABSTAIN)
        assert record.vote_type == Vote.ABSTAIN

    def test_vote_record_to_dict(self):
        engine = self._make_engine({ALICE: Decimal("1000000")})
        p = self._activate_proposal()
        record = engine.cast_vote(p, ALICE, Vote.FOR)
        d = record.to_dict()
        assert d["voteType"] == "FOR"
        assert d["votingPower"] == "1000000"

    def test_double_vote_raises(self):
        engine = self._make_engine({ALICE: Decimal("1000000")})
        p = self._activate_proposal()
        engine.cast_vote(p, ALICE, Vote.FOR)
        with pytest.raises(AlreadyVotedError):
            engine.cast_vote(p, ALICE, Vote.AGAINST)

    def test_zero_stake_raises(self):
        engine = self._make_engine()  # no stakes
        p = self._activate_proposal()
        with pytest.raises(InsufficientVotingPowerError):
            engine.cast_vote(p, ALICE, Vote.FOR)

    def test_invalid_vote_type_raises(self):
        engine = self._make_engine({ALICE: Decimal("1000000")})
        p = self._activate_proposal()
        with pytest.raises(Exception, match="Invalid vote type"):
            engine.cast_vote(p, ALICE, 99)

    def test_vote_on_non_active_raises(self):
        engine = self._make_engine({ALICE: Decimal("1000000")})
        p = make_proposal()  # Still in DRAFT
        with pytest.raises(VotingClosedError):
            engine.cast_vote(p, ALICE, Vote.FOR)

    def test_has_voted(self):
        engine = self._make_engine({ALICE: Decimal("1000000")})
        p = self._activate_proposal()
        assert not engine.has_voted(p.id, ALICE)
        engine.cast_vote(p, ALICE, Vote.FOR)
        assert engine.has_voted(p.id, ALICE)

    def test_voter_count(self):
        stakes = {
            ALICE: Decimal("5000000"),
            BOB: Decimal("3000000"),
            CAROL: Decimal("2000000"),
        }
        engine = self._make_engine(stakes)
        p = self._activate_proposal()
        engine.cast_vote(p, ALICE, Vote.FOR)
        engine.cast_vote(p, BOB, Vote.AGAINST)
        assert engine.voter_count(p.id) == 2

    def test_get_votes(self):
        engine = self._make_engine({ALICE: Decimal("1000000")})
        p = self._activate_proposal()
        engine.cast_vote(p, ALICE, Vote.FOR)
        votes = engine.get_votes(p.id)
        assert len(votes) == 1

    def test_override_voting_power(self):
        engine = self._make_engine()
        p = self._activate_proposal()
        record = engine.cast_vote(p, ALICE, Vote.FOR, voting_power=Decimal("9999"))
        assert record.voting_power == Decimal("9999")


class TestVotingResult:
    """VotingResult calculations."""

    def test_quorum_reached(self):
        r = VotingResult(
            proposal_id=1,
            votes_for=Decimal("8000000"),
            votes_against=Decimal("2000000"),
            votes_abstain=Decimal("1000000"),
            total_eligible_supply=Decimal("100000000"),
        )
        # 11M / 100M = 11% > 10% quorum
        assert r.quorum_reached

    def test_quorum_not_reached(self):
        r = VotingResult(
            proposal_id=1,
            votes_for=Decimal("5000000"),
            votes_against=Decimal("1000000"),
            total_eligible_supply=Decimal("100000000"),
        )
        # 6M / 100M = 6% < 10%
        assert not r.quorum_reached

    def test_approval_rate(self):
        r = VotingResult(
            proposal_id=1,
            votes_for=Decimal("7000000"),
            votes_against=Decimal("3000000"),
            total_eligible_supply=Decimal("100000000"),
        )
        assert r.approval_rate == Decimal("0.7")  # 70%

    def test_is_approved(self):
        r = VotingResult(
            proposal_id=1,
            votes_for=Decimal("8000000"),
            votes_against=Decimal("2000000"),
            votes_abstain=Decimal("1000000"),
            total_eligible_supply=Decimal("100000000"),
        )
        assert r.is_approved  # 11% quorum, 80% approval > 60%

    def test_not_approved_low_rate(self):
        r = VotingResult(
            proposal_id=1,
            votes_for=Decimal("4000000"),
            votes_against=Decimal("7000000"),
            votes_abstain=Decimal("1000000"),
            total_eligible_supply=Decimal("100000000"),
        )
        # 12% quorum met, but ~36% approval < 60%
        assert r.quorum_reached
        assert not r.is_approved

    def test_abstain_counts_toward_quorum(self):
        r = VotingResult(
            proposal_id=1,
            votes_for=Decimal("1000000"),
            votes_against=Decimal("0"),
            votes_abstain=Decimal("10000000"),
            total_eligible_supply=Decimal("100000000"),
        )
        # 11M total (1M for + 10M abstain) = 11% > 10%
        assert r.quorum_reached
        # Approval: 1M / 1M = 100% (abstain not counted in decisive)
        assert r.approval_rate == Decimal("1")
        assert r.is_approved

    def test_zero_supply_quorum(self):
        r = VotingResult(
            proposal_id=1,
            votes_for=Decimal("100"),
            total_eligible_supply=Decimal("0"),
        )
        assert not r.quorum_reached

    def test_to_dict(self):
        r = VotingResult(proposal_id=1, total_eligible_supply=Decimal("100"))
        d = r.to_dict()
        assert "quorumReached" in d
        assert "approvalRate" in d


class TestDelegation:
    """Delegation support."""

    def test_delegate_power(self):
        engine = VotingEngine(
            get_stake_fn=lambda addr: Decimal("1000000") if addr == ALICE else Decimal("0"),
            get_total_supply_fn=lambda: Decimal("100000000"),
        )
        engine.delegate(BOB, ALICE, Decimal("500000"))
        power = engine.get_voting_power(ALICE, own_stake=Decimal("1000000"))
        assert power == Decimal("1500000")

    def test_delegate_to_self_raises(self):
        engine = VotingEngine()
        with pytest.raises(Exception, match="self"):
            engine.delegate(ALICE, ALICE, Decimal("100"))

    def test_delegate_negative_raises(self):
        engine = VotingEngine()
        with pytest.raises(Exception, match="positive"):
            engine.delegate(ALICE, BOB, Decimal("-1"))

    def test_undelegate(self):
        engine = VotingEngine(
            get_stake_fn=lambda addr: Decimal("0"),
            get_total_supply_fn=lambda: Decimal("100000000"),
        )
        engine.delegate(BOB, ALICE, Decimal("500000"))
        engine.undelegate(BOB)
        assert engine.get_delegated_power(ALICE) == Decimal("0")

    def test_delegation_to_dict(self):
        d = Delegation(delegator=BOB, delegate=ALICE, amount=Decimal("1000"))
        data = d.to_dict()
        assert data["delegator"] == BOB
        assert data["amount"] == "1000"


class TestVotingFinalization:
    """End-to-end finalization."""

    def _setup(self, stakes, total_supply=Decimal("100000000")):
        engine = VotingEngine(
            get_stake_fn=lambda addr: stakes.get(addr, Decimal("0")),
            get_total_supply_fn=lambda: total_supply,
        )
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=86400)
        return engine, p

    def test_finalize_passed(self):
        stakes = {
            ALICE: Decimal("8000000"),
            BOB: Decimal("3000000"),
        }
        engine, p = self._setup(stakes)
        engine.cast_vote(p, ALICE, Vote.FOR)
        engine.cast_vote(p, BOB, Vote.FOR)
        result = engine.finalize(p)
        assert result.is_approved
        assert p.status == ProposalStatus.PASSED

    def test_finalize_defeated(self):
        stakes = {
            ALICE: Decimal("4000000"),
            BOB: Decimal("7000000"),
            CAROL: Decimal("1000000"),
        }
        engine, p = self._setup(stakes)
        engine.cast_vote(p, ALICE, Vote.FOR)
        engine.cast_vote(p, BOB, Vote.AGAINST)
        engine.cast_vote(p, CAROL, Vote.ABSTAIN)
        result = engine.finalize(p)
        assert not result.is_approved
        assert p.status == ProposalStatus.DEFEATED

    def test_finalize_expired_no_quorum(self):
        stakes = {ALICE: Decimal("1000000")}  # 1% < 10%
        engine, p = self._setup(stakes)
        engine.cast_vote(p, ALICE, Vote.FOR)
        result = engine.finalize(p)
        assert not result.quorum_reached
        assert p.status == ProposalStatus.EXPIRED

    def test_finalize_already_finalized_raises(self):
        stakes = {ALICE: Decimal("11000000")}
        engine, p = self._setup(stakes)
        engine.cast_vote(p, ALICE, Vote.FOR)
        engine.finalize(p)
        with pytest.raises(Exception, match="already finalized"):
            engine.finalize(p)

    def test_supermajority_threshold(self):
        """Protocol upgrades need 75%."""
        stakes = {
            ALICE: Decimal("7000000"),
            BOB: Decimal("4000000"),
        }
        engine = VotingEngine(
            get_stake_fn=lambda addr: stakes.get(addr, Decimal("0")),
            get_total_supply_fn=lambda: Decimal("100000000"),
        )
        p = make_proposal(ptype=ProposalType.PROTOCOL_UPGRADE)
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=86400)
        engine.cast_vote(p, ALICE, Vote.FOR)
        engine.cast_vote(p, BOB, Vote.AGAINST)
        result = engine.finalize(p)
        # 7M / 11M ≈ 63.6% < 75% supermajority
        assert not result.is_approved
        assert p.status == ProposalStatus.DEFEATED


# ══════════════════════════════════════════════════════════════════════
#  STEP 10.1 — ON-CHAIN GOVERNANCE: TIMELOCK & EXECUTION
# ══════════════════════════════════════════════════════════════════════


class TestTimelockEntry:
    """TimelockEntry basics."""

    def test_entry_creation(self):
        now = time.time()
        entry = TimelockEntry(
            proposal_id=1,
            queued_at=now,
            delay_seconds=172800,  # 2 days
        )
        assert entry.eta == now + 172800
        assert entry.status == TimelockStatus.PENDING
        assert entry.time_remaining > 0

    def test_entry_not_ready_before_eta(self):
        entry = TimelockEntry(
            proposal_id=1,
            queued_at=time.time(),
            delay_seconds=86400,
        )
        assert not entry.is_ready

    def test_entry_ready_after_eta(self):
        past = time.time() - 200
        entry = TimelockEntry(
            proposal_id=1,
            queued_at=past,
            delay_seconds=100,
            eta=past + 100,
        )
        assert entry.is_ready

    def test_entry_expired_after_grace(self):
        long_ago = time.time() - (15 * 86400)  # 15 days ago
        entry = TimelockEntry(
            proposal_id=1,
            queued_at=long_ago,
            delay_seconds=100,
            eta=long_ago + 100,
            grace_period=14 * 86400,
        )
        assert entry.is_expired

    def test_entry_to_dict(self):
        entry = TimelockEntry(proposal_id=1)
        d = entry.to_dict()
        assert d["proposalId"] == 1
        assert "status" in d


class TestTimelockQueue:
    """TimelockQueue operations."""

    def test_queue_proposal(self):
        q = TimelockQueue()
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        entry = q.queue(p)
        assert entry.proposal_id == p.id
        assert p.status == ProposalStatus.QUEUED

    def test_queue_non_passed_raises(self):
        q = TimelockQueue()
        p = make_proposal()  # DRAFT
        with pytest.raises(TimelockError, match="PASSED"):
            q.queue(p)

    def test_queue_duplicate_raises(self):
        q = TimelockQueue()
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        q.queue(p)
        # Proposal is now QUEUED, so re-queuing hits status check
        with pytest.raises(TimelockError, match="PASSED"):
            q.queue(p)

    def test_queue_delay_below_min_raises(self):
        q = TimelockQueue(min_delay=86400)
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        with pytest.raises(TimelockError, match="minimum"):
            q.queue(p, delay_seconds=100)

    def test_queue_delay_above_max_raises(self):
        q = TimelockQueue(min_delay=1, max_delay=86400)
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        with pytest.raises(TimelockError, match="maximum"):
            q.queue(p, delay_seconds=86401)

    def test_pending_and_ready_entries(self):
        q = TimelockQueue(default_delay=1, min_delay=1)
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        q.queue(p, delay_seconds=1)
        assert len(q.pending_entries()) == 1

    def test_to_dict(self):
        q = TimelockQueue()
        d = q.to_dict()
        assert "defaultDelay" in d
        assert "queuedCount" in d


class TestGuardianVeto:
    """Guardian council veto (§13.4)."""

    def _queued_entry(self):
        q = TimelockQueue(default_delay=86400, min_delay=1)
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        entry = q.queue(p, delay_seconds=86400)
        return q, p, entry

    def test_guardian_veto_success(self):
        q, p, entry = self._queued_entry()
        signers = [f"guardian_{i}" for i in range(GOVERNANCE_GUARDIAN_THRESHOLD)]
        result = q.guardian_veto(p.id, signers)
        assert result.status == TimelockStatus.VETOED
        assert len(result.veto_signers) == GOVERNANCE_GUARDIAN_THRESHOLD

    def test_guardian_veto_insufficient_signers(self):
        q, p, entry = self._queued_entry()
        with pytest.raises(GuardianVetoError, match="Need"):
            q.guardian_veto(p.id, ["only_one"])

    def test_guardian_veto_nonexistent_raises(self):
        q = TimelockQueue()
        with pytest.raises(TimelockError, match="No queued"):
            q.guardian_veto(999, ["a", "b", "c"])


class TestGovernanceExecutor:
    """GovernanceExecutor with parameter mutation."""

    def _ready_proposal(self, ptype=ProposalType.PARAMETER_CHANGE, params=None):
        """Create a proposal that's QUEUED and ready for execution."""
        q = TimelockQueue(default_delay=1, min_delay=1, max_delay=999999)
        executor = GovernanceExecutor(timelock_queue=q)
        p = make_proposal(ptype=ptype, parameters=params or {})
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()

        # Queue with very short delay and manually set ETA to the past
        entry = q.queue(p, delay_seconds=1)
        entry.eta = time.time() - 10  # make it ready now
        entry.queued_at = entry.eta - 1

        return executor, p

    def test_execute_parameter_change(self):
        executor, p = self._ready_proposal(
            params={"bridge_fee_bps": 20, "min_validator_stake": Decimal("200000")}
        )
        changes = executor.execute(p)
        assert p.status == ProposalStatus.EXECUTED
        assert executor.get_parameter("bridge_fee_bps") == 20
        assert executor.get_parameter("min_validator_stake") == Decimal("200000")
        assert "bridge_fee_bps" in changes

    def test_execute_treasury_spend(self):
        executor, p = self._ready_proposal(
            ptype=ProposalType.TREASURY_SPEND,
            params={"recipient": BOB, "amount": "500000", "purpose": "Grant"},
        )
        changes = executor.execute(p)
        assert "treasury_spend" in changes
        assert changes["treasury_spend"]["recipient"] == BOB

    def test_execute_protocol_upgrade(self):
        executor, p = self._ready_proposal(
            ptype=ProposalType.PROTOCOL_UPGRADE,
            params={"version": "3.0.0", "description": "Major upgrade"},
        )
        changes = executor.execute(p)
        assert "protocol_upgrade" in changes

    def test_execute_not_queued_raises(self):
        executor = GovernanceExecutor()
        p = make_proposal()
        with pytest.raises(GovernanceError, match="not QUEUED"):
            executor.execute(p)

    def test_execute_no_timelock_entry_raises(self):
        executor = GovernanceExecutor()
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        p.queue_for_execution(time.time())
        with pytest.raises(TimelockError, match="No timelock"):
            executor.execute(p)

    def test_execute_vetoed_cancels(self):
        q = TimelockQueue(default_delay=86400, min_delay=1, max_delay=999999)
        executor = GovernanceExecutor(timelock_queue=q)
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        entry = q.queue(p, delay_seconds=86400)
        # Veto it
        signers = [f"g{i}" for i in range(GOVERNANCE_GUARDIAN_THRESHOLD)]
        q.guardian_veto(p.id, signers)
        with pytest.raises(GuardianVetoError):
            executor.execute(p)

    def test_execute_timelock_not_ready_raises(self):
        q = TimelockQueue(default_delay=86400, min_delay=1, max_delay=999999)
        executor = GovernanceExecutor(timelock_queue=q)
        p = make_proposal()
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=3600)
        p.mark_passed()
        q.queue(p, delay_seconds=86400)  # not ready yet
        with pytest.raises(TimelockNotReadyError):
            executor.execute(p)

    def test_execution_log(self):
        executor, p = self._ready_proposal(params={"voting_period_days": 14})
        executor.execute(p)
        assert executor.execution_count() == 1
        log = executor.execution_log
        assert log[0]["proposalId"] == p.id

    def test_get_all_parameters(self):
        executor = GovernanceExecutor()
        params = executor.get_all_parameters()
        assert "bridge_fee_bps" in params

    def test_set_parameter_directly(self):
        executor = GovernanceExecutor()
        executor.set_parameter("test_key", 42)
        assert executor.get_parameter("test_key") == 42

    def test_custom_executor(self):
        executor, p = self._ready_proposal(
            ptype=ProposalType.ECOSYSTEM_GRANT,
            params={"grant_to": "ProjectX"},
        )
        custom_result = {"custom": True}
        executor.register_executor(
            ProposalType.ECOSYSTEM_GRANT,
            lambda prop: custom_result,
        )
        changes = executor.execute(p)
        assert changes == custom_result

    def test_to_dict(self):
        executor = GovernanceExecutor()
        d = executor.to_dict()
        assert "parameters" in d
        assert "timelockQueue" in d

    def test_repr(self):
        executor = GovernanceExecutor()
        assert "GovernanceExecutor" in repr(executor)


# ══════════════════════════════════════════════════════════════════════
#  END-TO-END: FULL GOVERNANCE CYCLE
# ══════════════════════════════════════════════════════════════════════


class TestEndToEndGovernance:
    """Full proposal → vote → timelock → execute cycle."""

    def test_full_parameter_change_cycle(self):
        # Setup stakes
        stakes = {
            ALICE: Decimal("5000000"),
            BOB: Decimal("4000000"),
            CAROL: Decimal("2000000"),
        }

        engine = VotingEngine(
            get_stake_fn=lambda addr: stakes.get(addr, Decimal("0")),
            get_total_supply_fn=lambda: Decimal("100000000"),
        )
        q = TimelockQueue(default_delay=1, min_delay=1, max_delay=999999)
        executor = GovernanceExecutor(timelock_queue=q)

        # 1. Create proposal
        p = make_proposal(
            title="Reduce bridge fee to 5bps",
            parameters={"bridge_fee_bps": 5},
        )

        # 2. Lifecycle: DRAFT → DISCUSSION → TEMPERATURE → ACTIVE
        p.submit_for_discussion()
        p.start_temperature_check()
        p.activate_voting(voting_period_seconds=86400)

        # 3. Vote (11M total = 11% quorum)
        engine.cast_vote(p, ALICE, Vote.FOR)       # 5M FOR
        engine.cast_vote(p, BOB, Vote.FOR)          # 4M FOR
        engine.cast_vote(p, CAROL, Vote.AGAINST)    # 2M AGAINST

        # 4. Finalize
        result = engine.finalize(p)
        assert result.quorum_reached  # 11% > 10%
        assert result.is_approved     # 9M/11M ≈ 81.8% > 60%
        assert p.status == ProposalStatus.PASSED

        # 5. Queue in timelock
        entry = q.queue(p, delay_seconds=1)
        assert p.status == ProposalStatus.QUEUED

        # 6. Make timelock ready
        entry.eta = time.time() - 10
        entry.queued_at = entry.eta - 1

        # 7. Execute
        changes = executor.execute(p)
        assert p.status == ProposalStatus.EXECUTED
        assert executor.get_parameter("bridge_fee_bps") == 5
        assert "bridge_fee_bps" in changes


class TestEndToEndTokenAndGovernance:
    """Token + governance integration."""

    @pytest.mark.asyncio
    async def test_governance_freezes_token(self):
        """Governance can freeze a qRC20 token."""
        registry = QRC20Registry()
        token = make_token(symbol="qETH")
        registry.deploy(token)

        # Simulate governance execution
        token.freeze()
        assert token.is_frozen
        with pytest.raises(TokenFrozenError):
            await token.transfer(ALICE, BOB, Decimal("10"))

        # Governance unfreezes
        token.unfreeze()
        await token.transfer(ALICE, BOB, Decimal("10"))
        assert token.balance_of(BOB) == Decimal("10")


# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS VERIFICATION
# ══════════════════════════════════════════════════════════════════════


class TestConstants:
    """Verify governance and qRC20 constants are properly defined."""

    def test_qrc20_constants(self):
        assert QRC20_DEFAULT_DECIMALS == 18
        assert QRC20_MAX_BATCH_SIZE == 256
        assert QRC20_MAX_SUPPLY > 0
        assert len(QRC20_DOMAIN_TRANSFER) > 0
        assert len(QRC20_DOMAIN_APPROVE) > 0

    def test_qrc20_shielded_tokens(self):
        assert "qETH" in QRC20_SHIELDED_TOKENS
        assert "QRDX" in QRC20_SHIELDED_TOKENS
        for sym, info in QRC20_SHIELDED_TOKENS.items():
            assert "source_chain" in info
            assert "post_doomsday_trade" in info

    def test_governance_voting_constants(self):
        assert GOVERNANCE_PROPOSAL_DEPOSIT == Decimal("10000000")
        assert GOVERNANCE_QUORUM_THRESHOLD == Decimal("0.10")
        assert GOVERNANCE_APPROVAL_THRESHOLD == Decimal("0.60")
        assert GOVERNANCE_SUPERMAJORITY_THRESHOLD == Decimal("0.75")
        assert GOVERNANCE_VOTING_PERIOD_DAYS == 7

    def test_governance_vote_types(self):
        assert GOVERNANCE_VOTE_FOR == 1
        assert GOVERNANCE_VOTE_AGAINST == 2
        assert GOVERNANCE_VOTE_ABSTAIN == 3

    def test_governance_timelock_constants(self):
        assert GOVERNANCE_TIMELOCK_MIN_DELAY_SECONDS == 2 * 86400
        assert GOVERNANCE_TIMELOCK_MAX_DELAY_SECONDS == 14 * 86400
        assert GOVERNANCE_TIMELOCK_DEFAULT_DELAY_SECONDS == 2 * 86400

    def test_governance_guardian_constants(self):
        assert GOVERNANCE_GUARDIAN_THRESHOLD == 3
        assert GOVERNANCE_GUARDIAN_TOTAL == 5

    def test_governance_default_parameters(self):
        params = GOVERNANCE_DEFAULT_PARAMETERS
        assert "bridge_fee_bps" in params
        assert "min_validator_stake" in params
        assert "voting_period_days" in params
        assert params["validator_set_size"] == 150
