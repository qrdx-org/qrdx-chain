"""
The validators' price oracle, attested chain heads and the bridge, quantum migration and the
Doomsday Protocol.

These are ExchangeStateManager's methods, written as functions of the manager (``self``) and
bound to it under the same names in qrdx/exchange/state_manager.py. They are here only to keep
that file to a size one can read: read them as the class's.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from .. import undo
from ..bridge import (
    BRIDGE_AUTHORITY,
    MAX_VOTE_DEPOSITS,
    MAX_VOTE_HEADS,
    BridgeError,
    Deposit,
    asset_by_token,
    configured_assets,
    parse_deposit,
    parse_head,
)
from ..clearinghouse import Clearinghouse
from ..tokens import (
    TokenError,
    amount as token_amount,
)
from ..transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)
from .common import (
    ZERO,
    ExchangeExecResult,
    _apply_policy,
    logger,
)

if TYPE_CHECKING:
    from ..state_manager import ExchangeStateManager


#  Validator price oracle (docs/PERPS_CLEARINGHOUSE.md §8)
def load_oracle_committee(self: ExchangeStateManager, genesis_content: Any) -> None:
    """Seed the committee from a genesis block's ``validator_set`` (address, stake) — for a
    manager with no chain behind it (tests, tools). On a node the committee is set before
    every block from the chain-derived validator set (block_processor.ensure_oracle_committee).
    A genesis without a validator set leaves votes disabled (None)."""
    if self.oracle_committee is not None:
        return
    try:
        content = (
            json.loads(genesis_content) if isinstance(genesis_content, str) else genesis_content
        )
        members = content.get("validator_set") if isinstance(content, dict) else None
    except Exception:
        members = None
    if not members:
        return
    committee: Dict[str, Decimal] = {}
    for v in members:
        stake = Decimal(str(v["stake"]))
        if stake > 0:
            key = str(v["address"]).lower()
            committee[key] = committee.get(key, ZERO) + stake
    self.oracle_committee = committee


def _op_oracle_vote(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A committee member's USD prices, keyed by market base ("BTC" → BTC-USD-PERP), and
    other venues' perp prices ("BTC:perp", the mark's third input). Votes only for existing
    markets; each replaces the voter's previous one for that market. A vote may also attest
    bridge deposits (``deposits``, docs/BRIDGE.md): the one that brings a deposit to a
    quorum mints it."""
    from ... import constants

    committee = self._oracle_members()
    if not committee or tx.sender.lower() not in committee:
        return ExchangeExecResult(success=False, error="sender is not in the oracle committee")
    prices = tx.params.get("prices", {})
    deposits_raw = tx.params.get("deposits", [])
    heads_raw = tx.params.get("heads", [])
    if not isinstance(deposits_raw, list) or len(deposits_raw) > MAX_VOTE_DEPOSITS:
        return ExchangeExecResult(
            success=False, error=f"a vote attests at most {MAX_VOTE_DEPOSITS} deposits"
        )
    if not isinstance(heads_raw, list) or len(heads_raw) > MAX_VOTE_HEADS:
        return ExchangeExecResult(
            success=False, error=f"a vote attests at most {MAX_VOTE_HEADS} chain heads"
        )
    if (
        not isinstance(prices, dict)
        or len(prices) > self.MAX_VOTE_PRICES
        or not (prices or deposits_raw or heads_raw)
    ):
        return ExchangeExecResult(
            success=False,
            error=f"a vote carries 1 to {self.MAX_VOTE_PRICES} prices, or only attestations",
        )
    try:
        heads = [parse_head(raw) for raw in heads_raw]
    except BridgeError as e:
        return ExchangeExecResult(success=False, error=f"chain head: {e}")
    if len({h.chain for h in heads}) != len(heads):
        return ExchangeExecResult(success=False, error="one head per chain")
    deposits: List[Deposit] = []
    if deposits_raw:
        assets = configured_assets()
        for raw in deposits_raw:
            try:
                deposits.append(parse_deposit(raw, assets))
            except BridgeError as e:
                return ExchangeExecResult(success=False, error=f"deposit: {e}")
    parsed: Dict[str, Decimal] = {}
    perp: Dict[str, Decimal] = {}
    ignored: List[str] = []
    for key in sorted(prices):
        base = str(key)
        is_perp = base.endswith(":perp")
        if is_perp:
            base = base[: -len(":perp")]
        market_id = Clearinghouse.market_id(base, constants.PERP_QUOTE)
        if market_id not in self.clearinghouse.markets:
            return ExchangeExecResult(success=False, error=f"no market {market_id}")
        try:
            price = Decimal(str(prices[key]))
        except Exception:
            return ExchangeExecResult(success=False, error=f"invalid price for {base}")
        if not price.is_finite() or price <= 0:
            return ExchangeExecResult(success=False, error=f"invalid price for {base}")
        m = self.clearinghouse.markets[market_id]
        if Clearinghouse.contained(m):
            # A token perp: its spot market prices it, never votes. Skipped, not refused —
            # the rest of the vote stands.
            ignored.append(str(key))
            continue
        (perp if is_perp else parsed)[market_id] = price
    now = Decimal(str(self._block_clock()))
    voter = tx.sender.lower()
    # (Plain registries, applied at the tick: each entry kept for a rollback.)
    for market_id, price in parsed.items():
        undo.keep_entry(self.oracle_votes, market_id)
        self.oracle_votes.setdefault(market_id, {})[voter] = (price, now)
    for market_id, price in perp.items():
        undo.keep_entry(self.perp_votes, market_id)
        self.perp_votes.setdefault(market_id, {})[voter] = (price, now)
    data: Dict[str, Any] = {"markets": sorted(parsed)}
    if perp:
        data["perp_prices"] = sorted(perp)
    if ignored:
        data["ignored"] = ignored
    if heads:
        # Only the chains the network bridges: a head of any other chain is skipped (the rest
        # of the vote stands) — each one voted would sit in the state for an hour.
        bridged = {a.chain for a in configured_assets().values()}
        skipped = [h.chain for h in heads if h.chain not in bridged]
        heads = [h for h in heads if h.chain in bridged]
        data["heads"] = [h.chain for h in heads]
        if skipped:
            data["ignored_heads"] = skipped
        attested = [h.chain for h in heads if self.bridge.attest_head(h, voter, now, committee)]
        if attested:
            data["attested_heads"] = attested
    if deposits:
        from ... import chain_spec as _chain_spec

        data["deposits"] = [d.id for d in deposits]
        minted: List[str] = []
        refused: Dict[str, str] = {}
        queued: Dict[str, str] = {}
        dev = _chain_spec.active().dev
        for d in deposits:
            # Past its window a deposit never counts again: what makes refunding it safe.
            why = self.bridge.refusal(d, now)
            if why:
                refused[d.id] = why
                continue
            if not self.bridge.attest(d, voter, now, committee):
                continue
            why = self._bridge_mint(d, now, dev)
            if why:  # stays attested: a later vote mints it when the guardrail allows
                queued[d.id] = why
                continue
            minted.append(d.id)
        if minted:
            data["minted"] = minted
        if refused:
            data["refused_deposits"] = refused
        if queued:
            data["queued_deposits"] = queued
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ORACLE_VOTE], data=data
    )


def _mint_deposit(self: ExchangeStateManager, d: Deposit) -> None:
    """Mint a deposit that reached a quorum to its recipient, creating the bridged token at
    its first deposit (zero supply, the bridge's mint authority)."""
    asset = configured_assets()[(d.chain, d.token)]
    if self.tokens.get(asset.address) is None:
        self.tokens.deploy(
            asset.address,
            BRIDGE_AUTHORITY,
            self._current_block_height,
            name=f"{asset.symbol} (bridged)",
            symbol=asset.symbol,
            decimals=asset.decimals,
            initial_supply=0,
            mint_authority=BRIDGE_AUTHORITY,
        )
        # Its symbol is a reserved ticker: the bridge's token holds it (no one buys it).
        ticker = asset.symbol.upper()
        if self.trading.tickers.peek(ticker) is None and re.fullmatch(r"[A-Z0-9]{1,12}", ticker):
            self.trading.tickers[ticker] = str(asset.address).lower()
    minted = self.tokens.mint(asset.address, BRIDGE_AUTHORITY, d.amount)
    self._record_token_delta(d.to, asset.address, minted)


def _bridge_mint(self: ExchangeStateManager, d: Deposit, now: Decimal, dev: bool) -> Optional[str]:
    """Mint a deposit whose attestation or proof is in hand, within the guardrails; None once
    minted, else why not (it is left as it was). The one place either path mints."""
    asset = configured_assets()[(d.chain, d.token)]
    token = self.tokens.get(asset.address)
    supply = token.supply if token is not None else Decimal(0)
    why = self.bridge.mint_refusal(asset, d.amount, supply, now, dev)
    if why:
        return why
    try:
        self._mint_deposit(d)
    except TokenError as e:
        logger.warning("bridge deposit %s cannot mint: %s", d.id, e)
        return f"cannot mint: {e}"
    self.bridge.record_mint(asset, d.amount, now)
    self.bridge.complete(d)
    return None


def _op_bridge_prove_deposit(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """Mint a deposit on a storage proof (docs/BRIDGE.md "Proving a deposit"): the source
    chain's lockbox (``BRIDGE_LOCKBOXES``) records exactly this deposit in
    ``deposits[id]`` at a finalized head of that chain the validators attested (one of the
    last 64). Anyone may send it. The validators vouch for one state root, not for each
    deposit; the deposit window, the guardrails and the minted set apply as to an attested
    deposit, which has the same id, so a deposit mints once whichever way it arrives."""
    from ... import chain_spec as _chain_spec
    from ..bridge import configured_lockboxes, verify_deposit_proof

    p = tx.params
    try:
        d = parse_deposit(p["deposit"], configured_assets())
        height = int(p["height"])
        if d.id in self.bridge.done:
            raise BridgeError(f"deposit {d.id} is already minted")
        now = Decimal(str(self._block_clock()))
        why = self.bridge.refusal(d, now)
        if why:
            raise BridgeError(why)
        asset = configured_assets()[(d.chain, d.token)]
        why = verify_deposit_proof(
            d,
            asset,
            self.bridge.head_at(d.chain, height),
            configured_lockboxes().get(d.chain),
            p["account_proof"],
            p["storage_proof"],
        )
        if why:
            raise BridgeError(why)
    except (BridgeError, KeyError, TypeError, ValueError) as e:
        return ExchangeExecResult(success=False, error=f"BRIDGE_PROVE_DEPOSIT: {e}")
    why = self._bridge_mint(d, now, _chain_spec.active().dev)
    if why:
        return ExchangeExecResult(
            success=False, error=f"BRIDGE_PROVE_DEPOSIT: proven, not minted: {why}"
        )
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.BRIDGE_PROVE_DEPOSIT],
        data={"deposit": d.id, "minted": str(d.amount), "to": d.to, "head": height},
    )


def _op_migration_claim(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Bind a 0x account's post-quantum successor, committed on another chain
    (docs/QUANTUM_MIGRATION.md): the chain's QRDXMigrationRegistry (``MIGRATION_REGISTRIES``)
    holds the commitment at a finalized head the validators attested. Anyone may send it.
    The successor becomes a controller of the account (account control). An account binds
    once; a commitment made after the Doomsday Protocol triggered proves nothing."""
    from ..authority import account_id
    from ..migration import MigrationError, configured_registries, parse_claim, verify_claim

    p = tx.params
    try:
        claim = parse_claim(p)
        key = account_id(claim.account)
        bound = self.authority.migrations.get(key) if len(self.authority.migrations) else None
        if bound is not None:
            if str(bound[0]).lower() == claim.successor.lower():
                return ExchangeExecResult(
                    success=True,
                    gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.MIGRATION_CLAIM],
                    data={"account": claim.account, "successor": bound[0], "already": True},
                )
            raise MigrationError("the account is already bound to another successor")
        cutoff = self.doomsday_cutoff()
        if cutoff is not None and claim.time >= cutoff:
            raise MigrationError(
                "registered after the Doomsday Protocol triggered: it proves nothing"
            )
        why = verify_claim(
            claim,
            self.bridge.head_at(claim.chain, int(p["height"])),
            configured_registries().get(claim.chain),
            p["account_proof"],
            p["successor_proof"],
            p["time_proof"],
        )
        if why:
            raise MigrationError(why)
        policy = self.authority.policy(claim.account)
        if account_id(claim.successor) not in policy.controller_ids():
            policy = _apply_policy(policy, "add_controller", claim.successor, claim.account)
    except (MigrationError, KeyError, TypeError, ValueError) as e:
        return ExchangeExecResult(success=False, error=f"MIGRATION_CLAIM: {e}")
    self.authority.set_policy(claim.account, policy)
    self.authority.migrations[key] = [claim.successor, claim.chain, claim.time]
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.MIGRATION_CLAIM],
        data={"account": claim.account, "successor": claim.successor, "chain": claim.chain},
    )


def doomsday_cutoff(self: ExchangeStateManager) -> Optional[int]:
    """The time from which ECDSA is not trusted (the Doomsday Protocol triggered), or None."""
    state = self.bridge.doomsday
    return int(state["time"]) if state else None


def _trigger_doomsday(
    self: ExchangeStateManager, cause: str, since: Optional[int] = None
) -> Dict[str, Any]:
    """Trigger the Doomsday Protocol at this block (qrdx/exchange/doomsday.py), once: record
    it, and revoke every agent a ``0x`` account approved — an approval its ECDSA key may
    have signed for someone who broke it. (A ``0x`` account approves again only through a
    post-quantum root: its controller, or a contract a post-quantum transaction drives.)

    Its time — from which no migration commitment counts — is this block's, or ``since``
    when earlier: a canary proven spent at a source chain's head was spent by then. A later
    proof against an earlier head moves it earlier; nothing moves it later."""
    from ..doomsday import is_ecdsa_account

    now = int(Decimal(str(self._block_clock())))
    at = now if since is None else min(now, int(since))
    state = self.bridge.doomsday
    if state is not None and at < int(state["time"]):
        self.bridge.set_doomsday(at, int(state["height"]), str(state["cause"]))
    if state is None:
        self.bridge.set_doomsday(at, self._current_block_height, cause)
        if len(self.trading.agents):
            for account, grants in sorted(self.trading.agents.peek_items()):
                if is_ecdsa_account(account):
                    del self.trading.agents[account]
                    for g in grants:
                        self.trading.forget_spend(account, g.agent)
        logger.critical(
            "Doomsday Protocol triggered at block %s: %s", self._current_block_height, cause
        )
    return dict(self.bridge.doomsday or {})


def _op_doomsday_prove(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Trigger the Doomsday Protocol on proof that a canary signed: its account's nonce,
    against a finalized head of its chain the validators attested, is above 0. Anyone may
    send it. Triggered already, it can only move the trigger's time earlier (an earlier
    head)."""
    from ..doomsday import DoomsdayError, configured_canaries, verify_canary_spent

    p = tx.params
    try:
        chain = int(p["chain"])
        canary = configured_canaries().get(chain)
        head = self.bridge.head_at(chain, int(p["height"]))
        why = verify_canary_spent(chain, head, canary, p["account_proof"])
        if why:
            raise DoomsdayError(why)
    except (DoomsdayError, KeyError, TypeError, ValueError) as e:
        return ExchangeExecResult(success=False, error=f"DOOMSDAY_PROVE: {e}")
    assert head is not None
    state = self._trigger_doomsday(
        f"the canary {canary} on chain {chain} signed (by its block {head.height})",
        since=head.timestamp,
    )
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.DOOMSDAY_PROVE],
        data={"doomsday": state},
    )


def _op_bridge_withdraw(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Burn ``amount`` of a bridged token and record the withdrawal to ``to`` on its source
    chain, for the lockbox's custodian to release (docs/BRIDGE.md)."""
    p = tx.params
    if self.bridge.doomsday:
        return ExchangeExecResult(
            success=False,
            error="BRIDGE_WITHDRAW: the Doomsday Protocol stopped withdrawals to classical chains",
        )
    asset = asset_by_token(str(p["token_address"]))
    if asset is None:
        return ExchangeExecResult(success=False, error="BRIDGE_WITHDRAW: not a bridged token")
    to = str(p["to"]).strip().lower()
    if not (len(to) == 42 and to.startswith("0x") and all(c in "0123456789abcdef" for c in to[2:])):
        return ExchangeExecResult(
            success=False,
            error="BRIDGE_WITHDRAW: the recipient is a 0x address on the source chain",
        )
    try:
        v = token_amount(p["amount"])
        if v != v.quantize(Decimal(1).scaleb(-asset.decimals)):
            raise TokenError(f"{asset.symbol} has {asset.decimals} decimals")
        self.tokens.require(asset.address)
        avail = self.available_token_balance(tx.sender, asset.address)
        if self.enforce_spot_settlement and (avail is None or avail < v):
            raise TokenError(f"insufficient token balance: need {v}, available {avail}")
        self.tokens.burn(asset.address, v)
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"BRIDGE_WITHDRAW: {e}")
    self._record_token_delta(tx.sender, asset.address, -v)
    wid = self.bridge.record_withdrawal(
        {
            "chain": asset.chain,
            "token": asset.source_token,
            "to": to,
            "amount": str(v),
            "from": tx.sender,
            "height": self._current_block_height,
            "tx_hash": tx.tx_hash(),
        }
    )
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.BRIDGE_WITHDRAW],
        data={"withdrawal_id": wid, "amount": str(v), "chain": asset.chain, "to": to},
    )


def _oracle_members(self: ExchangeStateManager) -> Dict[str, Decimal]:
    """The committee less the members slashing evidence has convicted."""
    committee = self.oracle_committee or {}
    excluded: Set[str] = getattr(self, "oracle_excluded", set())
    return {v: w for v, w in committee.items() if v not in excluded}


def apply_oracle_votes(self: ExchangeStateManager, now) -> None:
    """Each block (before the clearinghouse tick): set every voted market's oracle to the
    stake-weighted median of fresh committee votes — when they carry a majority of the
    committee's stake. Without that the oracle is not refreshed, and goes stale. Votes
    older than the window are dropped, so the state stays small. Votes for other venues'
    perp price (``"<base>:perp"`` keys) set each market's external price the same way."""
    now = Decimal(str(now))
    self.bridge.expire(now)  # deposits that never reached a quorum
    committee = self._oracle_members()
    if not committee:
        return
    self.oracle_votes = self._aggregate_votes(
        self.oracle_votes,
        committee,
        now,
        self.clearinghouse.set_oracle_price,
        lambda m: (m.oracle_price, m.oracle_time),
    )
    self.perp_votes = self._aggregate_votes(
        self.perp_votes,
        committee,
        now,
        self.clearinghouse.set_external_perp_price,
        lambda m: (m.external_price, m.external_time),
    )


def _aggregate_votes(
    self: ExchangeStateManager, all_votes, committee, now: Decimal, apply, current
) -> Dict[str, Any]:
    """Per market: drop votes older than the window or from non-members; when the fresh
    ones carry a majority of the committee's stake and number at least ORACLE_MIN_VOTERS
    (or the whole committee), ``apply`` their stake-weighted (lower) median — moved at most
    ORACLE_MAX_STEP_BPS a second of block time from the current price (``current``), so a
    captured or mistaken majority can only walk the price, while the circuit breaker
    watches. Votes outside ORACLE_OUTLIER_BAND_BPS of the median are recorded against
    their validators. Returns the votes kept."""
    from ... import constants

    max_age = Decimal(constants.PERP_ORACLE_VOTE_MAX_AGE)
    min_voters = min(int(constants.ORACLE_MIN_VOTERS), len(committee))
    step = Decimal(int(constants.ORACLE_MAX_STEP_BPS)) / 10_000
    band = Decimal(int(constants.ORACLE_OUTLIER_BAND_BPS)) / 10_000
    total = sum(committee.values(), ZERO)
    kept: Dict[str, Any] = {}
    for market_id in sorted(all_votes):
        votes = {
            v: pt
            for v, pt in all_votes[market_id].items()
            if v in committee and now - pt[1] <= max_age
        }
        if votes:
            kept[market_id] = votes
        if market_id not in self.clearinghouse.markets or len(votes) < max(1, min_voters):
            continue
        m = self.clearinghouse.markets[market_id]
        if Clearinghouse.contained(m):
            continue  # a token perp: its spot market prices it
        weighted = sorted((price, committee[v]) for v, (price, _t) in votes.items())
        weight = sum((w for _p, w in weighted), ZERO)
        if weight * 2 <= total:
            continue
        acc = ZERO
        median = ZERO
        for price, w in weighted:  # lower weighted median
            acc += w
            if acc * 2 >= weight:
                median = price
                break
        if band > 0:
            for v in sorted(votes):
                if abs(votes[v][0] - median) > median * band:
                    self.oracle_outliers[v] = self.oracle_outliers.get(v, 0) + 1
        prev, prev_time = current(self.clearinghouse.markets[market_id])
        if step > 0 and prev > 0 and prev_time > 0 and now > prev_time:
            bound = step * (now - prev_time)
            lo, hi = prev * (1 - min(bound, Decimal("0.99"))), prev * (1 + bound)
            median = min(max(median, lo), hi).quantize(Decimal(1).scaleb(-18))
        apply(market_id, median, now)
    return kept


def oracle_state_hash(self: ExchangeStateManager) -> bytes:
    """The live votes. (Not the committee: see block_processor.ensure_oracle_committee —
    it is a function of genesis and the staking ops, which the chain already commits to.)"""
    blob = json.dumps(self.oracle_state(), sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(blob.encode(), digest_size=32).digest()


def oracle_state(self: ExchangeStateManager) -> Any:
    """What ``oracle_state_hash`` commits to (and a state proof's ``oracle`` part holds)."""
    votes = {
        m: {v: [str(p), str(t)] for v, (p, t) in sorted(vs.items())}
        for m, vs in sorted(self.oracle_votes.items())
    }
    state: Any = votes
    if self.oracle_vote_seqs:  # absent while no vote has run (a root unchanged till then)
        state = {"votes": votes, "seqs": dict(sorted(self.oracle_vote_seqs.items()))}
        if self.oracle_outliers:
            state["outliers"] = dict(sorted(self.oracle_outliers.items()))
        if self.perp_votes:
            state["perp"] = {
                m: {v: [str(p), str(t)] for v, (p, t) in sorted(vs.items())}
                for m, vs in sorted(self.perp_votes.items())
            }
    return state


def exchange_proof_root(self: ExchangeStateManager, height: Optional[int] = None) -> bytes:
    """The exchange tree root (qrdx/exchange/proofs.py): every in-memory entry under one root,
    bound into the signed state root beside the database tree's. With the block's
    ``height``, the trees are kept for proofs of it."""
    from ..proofs import fold

    return fold(self, height)
