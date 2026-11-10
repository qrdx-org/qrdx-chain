"""
The node's EVM runtime: executing account-model transactions, their nonces and failed-tx
charges, eth_call, and the EVM section of a block (produced and imported).

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import os

from qrdx.logger import get_logger
from qrdx.node import main as _node
from qrdx.node.nodes_manager import NodeInterface, NodesManager

logger = get_logger(__name__)

# Transaction-nonce validity gate.
#
# Closes a replay / double-spend hole: nothing used to compare a transaction's nonce to
# the sender's ACCOUNT nonce during execution. Mempool admission checked a nonce window,
# but against EVM_PENDING_NONCE — an in-memory dict lost on restart — and the dedup cache
# was in-memory too. So after a node restart an already-executed signed transaction could
# be re-submitted, re-admitted (expected nonce back to 0) and RE-EXECUTED, moving value a
# second time.
#
# This check is the authoritative one; the mempool's window is advisory spam control.
#
# A mismatched transaction is rejected as a NO-OP rather than invalidating the whole
# block. Ethereum treats an invalid-nonce transaction as making its block invalid, which
# is stricter, but here rejecting the block would turn any nonce disagreement into an
# import halt, and a poisoned mempool entry into a griefing vector (the proposer drops its
# entire EVM section on a tx that cannot execute). Rejecting just the transaction leaves
# state untouched, is identical on every node (so roots still agree), and still makes the
# replay impossible — which is the security property. The trade-off is recorded in
# docs/KNOWN_ISSUES.md.
_ENFORCE_TX_NONCE = True

# Charge gas and consume the nonce for a FAILED transaction, as Ethereum does.
#
# On failure ``ExecutionContext.finalize_execution`` reverts the EVM snapshot, which undid
# the gas charge AND the nonce increment that ``execute()`` had applied — so a transaction
# that reverted or ran out of gas cost its sender NOTHING and could be retried forever with
# the same nonce. Free failed execution is a spam vector: an attacker makes every node run
# expensive work and pays nothing.
#
# It also contradicted the importer's own assumption —
# ``apply_block_evm_section``'s comment states that a reverted transaction "is still validly
# included and still mutates state (nonce/gas)", which was not true.
#
# With this on, only the *state changes* roll back: the gas is charged and the nonce
# advances, re-applied explicitly after the revert.
# ENABLED. Env-overridable (QRDX_ENFORCE_FAILED_TX_COSTS=0) for A/B testing, the way
# ENFORCE_RANDAO_SELECTION is gated.
#
# This was briefly gated OFF on a suspicion that it amplified reorg churn: the first two
# soaks with it on came in at 20-21 reorgs and failed CLOB convergence scenarios, against
# 9-16 reorgs on earlier passing runs. A controlled A/B refuted that:
#
#   flag ON : 20, 21 reorgs   (10 differing block hashes between nodes, 2-way token split)
#   flag OFF:  9, 10, 14, 20 reorgs
#   flag OFF at 20 reorgs: 19 differing hashes, THREE-way token split — WORSE than with it on
#
# So the failures track churn, not this flag, and the underlying cause is the pre-existing
# block-history fork ("Block history did not converge" in docs/KNOWN_ISSUES.md; since fixed) which reproduced with this off. While that fork
# broke any 20+-reorg soak regardless, "wait for a clean high-churn soak" was an unmeetable
# bar for every change — so the gate was decided on the change's own
# merits: deterministic, unit-tested including cross-node account-root agreement, and not
# implicated in any observed failure.
_ENFORCE_FAILED_TX_COSTS = os.getenv("QRDX_ENFORCE_FAILED_TX_COSTS", "1").lower() not in (
    "0",
    "false",
    "no",
)


async def _reset_evm_pending_nonces() -> int:
    """
    REPLACE the mempool's per-sender nonce expectations with the durable account nonces.

    Unlike ``_rehydrate_evm_pending_nonces`` (which only raises expectations), this also
    LOWERS them — needed after derived state is rebuilt from the chain. A transaction that
    executed in a block which was then orphaned (reorg) or rejected (E-D4) bumped
    EVM_PENDING_NONCE past the sender's real account nonce. Left alone, the mempool refuses
    that transaction as "nonce too low" when it is re-queued — so every reorg silently lost
    its orphaned EVM transactions — and refuses the sender's correct next transaction too.
    """
    _node.EVM_PENDING_NONCE.clear()
    return await _rehydrate_evm_pending_nonces()


async def _rehydrate_evm_pending_nonces() -> int:
    """
    Rebuild EVM_PENDING_NONCE from the durable account nonces at startup.

    Without this the mempool's expected nonce resets to 0 on every restart, so a replayed
    transaction is *admitted* (and only stopped later, at execution). Rehydrating means a
    replay is refused at the door, which also keeps it out of a proposer's selection.

    Best-effort: the execution-path check in ``_execute_evm_raw_tx`` is what actually
    guarantees safety, so a failure here degrades spam filtering, not correctness.
    """
    try:
        rows = [
            (r.address.lower(), r.nonce)
            for r in _node.db.store["account_state"].scan()
            if r.nonce and int(r.nonce) > 0
        ]
    except Exception as e:
        logger.warning("EVM pending-nonce rehydrate skipped: %s", e)
        return 0
    for address, nonce in rows:
        try:
            _node.EVM_PENDING_NONCE[address] = max(
                _node.EVM_PENDING_NONCE.get(address, 0), int(nonce)
            )
        except (TypeError, ValueError):
            continue
    if rows:
        logger.info("Rehydrated %d account nonce(s) into the EVM mempool's expectations", len(rows))
    return len(rows)


async def _charge_failed_tx(
    state_manager,
    sender_hex,
    tx_nonce,
    gas_used,
    gas_limit,
    gas_price,
    intrinsic,
    defer_commit=False,
):
    """
    Apply the cost of a FAILED transaction: charge gas and consume the nonce.

    Called after ``finalize_execution`` has reverted the execution snapshot. That revert
    is what makes a failure safe — no state changes survive — but it also rolled back the
    gas charge and the nonce increment, which SHOULD survive: otherwise a reverting
    transaction is free to submit and free to retry with the same nonce, and every node
    does its work for nothing.

    Gas charged is ``min(gas_limit, max(consumed, intrinsic))`` — the same rule the success
    path uses, so a failure is never cheaper than the floor and never exceeds what the
    sender authorised. A sender who cannot cover it is charged down to zero rather than
    going negative (the balance check belongs at admission, and clamping keeps this
    deterministic rather than raising mid-block).

    Nonce advances to ``tx_nonce + 1``, which is what stops a failed transaction from being
    resubmitted unchanged — and keeps the nonce sequence gap-free for the sender's next
    transaction.

    Does not commit; under ``defer_commit`` the change rides the block's flush like any
    other, so it is included in the declared account_state root.
    """
    charged = min(gas_limit, max(int(gas_used or 0), int(intrinsic or 0)))
    cost = charged * int(gas_price or 0)
    try:
        if cost > 0:
            balance = state_manager.get_balance_sync(sender_hex)
            state_manager.set_balance_sync(sender_hex, max(0, balance - cost))
        # Consume the nonce regardless of gas price: a zero-gas-price failure must still
        # not be replayable.
        state_manager.set_nonce_sync(sender_hex, int(tx_nonce) + 1)
    except Exception as e:
        logger.error("could not charge failed tx for %s: %s", sender_hex[:20], e)
        return 0
    _node.EVM_PENDING_NONCE[sender_hex.lower()] = max(
        _node.EVM_PENDING_NONCE.get(sender_hex.lower(), 0), int(tx_nonce) + 1
    )
    return charged


def _evm_block_timestamp(value) -> int:
    """A block's timestamp as the EVM's ``block.timestamp``. Blocks store unix seconds;
    genesis stores a datetime string, which (like a missing value) maps to 1."""
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1


async def _execute_evm_raw_tx(
    raw_tx_hex, block_height, block_hash, block_timestamp, defer_commit=False
):
    """
    Execute a signed raw EVM transaction against EVM/account state (E-D3 core).

    Shared by the RPC handler, the block proposer, and import replay so all three
    apply the identical deterministic state transition. Commits or reverts
    atomically via ExecutionContext.

    ``defer_commit`` (E-D3b): when True, a successful tx's account changes are
    kept in the EVM cache instead of being flushed to the DB per-tx, so a block
    validator can execute the whole EVM section and then flush-read-decide the
    block's ``account_state_root`` atomically (see
    ``qrdx.contracts.evm_block_apply.apply_block_evm_section``).

    Returns a dict: {success, tx_hash, sender, nonce, created_address, error}.
    """
    from eth_utils import decode_hex, encode_hex

    evm_executor = _node.EVM_EXECUTOR
    state_manager = _node.EVM_STATE_MANAGER
    if evm_executor is None or state_manager is None:
        return {"success": False, "error": "EVM system not initialized", "tx_hash": None}

    # Decode + authenticate through the SHARED parser, which is also what mempool
    # admission and block-section import use — so the RPC, the proposer and every
    # importer agree byte-for-byte on who the sender is and what the tx does.
    # It handles both envelopes: legacy/EIP-155 (sender recovered from v,r,s) and
    # type 0x51 post-quantum (sender derived from the embedded ML-DSA-65 key).
    # Either way ``sender`` is 20 bytes, which is why the EVM below needs no
    # knowledge of PQ accounts at all.
    from ..contracts.evm_mempool import effective_gas_price, parse_eth_raw_tx
    from ..fee_market import current_evm_base_fee

    try:
        parsed = parse_eth_raw_tx(raw_tx_hex)
        nonce = parsed["nonce"]
        # What it pays per gas in this block: its price, or for an EIP-1559 transaction its
        # fee cap or base fee + tip, whichever is lower (all burned).
        gas_price_wei = effective_gas_price(parsed, current_evm_base_fee())
        gas = parsed["gas"] or 21000
        value_wei = parsed["value"]
        data = parsed["data"]
        sender_hex = parsed["sender"]
        sender = decode_hex(sender_hex)
        # Delegated spend: VALUE leaves this account instead of the signer's, while the
        # nonce and gas stay with the signer (they submitted and they pay). Authorisation
        # already happened in parse/verify_delegated_spend at both choke points.
        spend_hex = parsed.get("spend_from") or sender_hex
        spend_from = decode_hex(spend_hex)
        to_hex = parsed["to"]
        to_bytes = decode_hex(to_hex) if to_hex else b""
        tx_hash_hex = parsed["tx_hash"]
    except Exception as e:
        return {"success": False, "error": f"decode/authenticate failed: {e}", "tx_hash": None}

    # Nonce validity — the authoritative anti-replay check. Compared against the
    # sender's durable ACCOUNT nonce, so it holds across restarts (unlike the
    # mempool's in-memory expectation) and is identical on every node replaying the
    # same chain. Reading the account caches it but does not mark it dirty, so this
    # cannot move the state root.
    if _ENFORCE_TX_NONCE:
        try:
            expected_nonce = await state_manager.get_nonce(sender_hex)
        except Exception as e:
            return {
                "success": False,
                "error": f"cannot read account nonce: {e}",
                "tx_hash": tx_hash_hex,
                "sender": sender_hex,
                "nonce": nonce,
            }
        if nonce != expected_nonce:
            # No state is touched, so this is a deterministic no-op on every node.
            return {
                "success": False,
                "error": (
                    f"invalid nonce: tx has {nonce}, account expects "
                    f"{expected_nonce}"
                    + (
                        " (replay of an already-executed transaction)"
                        if nonce < expected_nonce
                        else ""
                    )
                ),
                "tx_hash": tx_hash_hex,
                "sender": sender_hex,
                "nonce": nonce,
            }

    # The payer must be able to pay for all the gas it offers, at its highest price (Ethereum's
    # up-front check). Otherwise nothing runs and nothing is charged: like a stale nonce, the
    # same no-op on every node. Without it a successful transaction's gas charge drove the
    # payer's balance negative. (A payer who covers the gas but not the value still runs and
    # pays for the failure, below.)
    try:
        upfront = int(gas) * int(parsed["gas_price"])
        payer_balance = int(await state_manager.get_balance(sender_hex))
    except Exception as e:
        return {
            "success": False,
            "error": f"cannot read the payer's balance: {e}",
            "tx_hash": tx_hash_hex,
            "sender": sender_hex,
            "nonce": nonce,
        }
    if payer_balance < upfront:
        return {
            "success": False,
            "error": (
                f"insufficient funds for gas * price: {gas} x {parsed['gas_price']} wei "
                f"exceeds the balance {payer_balance}"
            ),
            "tx_hash": tx_hash_hex,
            "sender": sender_hex,
            "nonce": nonce,
        }

    # The EVM reads state on demand from the state manager (this block's pending changes over
    # the database) and writes back everything it touched (contracts/evm_world.py). Native
    # token moves join the block's EvmSection, written to the token ledger only when the
    # section is accepted (contracts/native_token_evm.py).
    from ..contracts.evm_world import EvmWorld, run as run_evm
    from ..contracts.native_token_evm import CURRENT_SECTION, EvmSection, TokenWorld

    section = CURRENT_SECTION.get()
    standalone = section is None
    if standalone:
        section = EvmSection()
    await state_manager.get_account(sender_hex)  # the payer is in the cache
    snap = await state_manager.snapshot()
    world = EvmWorld(state_manager, tokens=TokenWorld(_node.db, section, height=block_height))

    def _receipt(result, success, error):
        section.record(
            tx_hash=tx_hash_hex,
            block_number=int(block_height or 0),
            **{"from": sender_hex},
            to=to_hex,
            value=value_wei,
            gas_limit=gas,
            gas_used=min(
                gas,
                max(
                    int(getattr(result, "gas_used", gas) or 0),
                    int(parsed.get("intrinsic_gas") or 0),
                ),
            ),
            gas_price=gas_price_wei,
            nonce=nonce,
            data=data,
            contract_address=(
                encode_hex(result.created_address)
                if result is not None and result.created_address
                else None
            ),
            success=success,
            error=error,
            logs=(result.logs if result is not None else []),
            timestamp=_evm_block_timestamp(block_timestamp),
        )

    try:
        # The EVM moves value from the account named as `sender`, so a delegated spend
        # runs with the SOURCE as the EVM sender and `origin` kept as the real signer (so a
        # contract still sees who authorised it via tx.origin); the signer — `payer` — pays
        # the gas and consumes its nonce.
        result = await run_evm(
            world,
            lambda: evm_executor.execute(
                spend_from,
                to_bytes if to_bytes else None,
                value_wei,
                data,
                gas,
                gas_price_wei,
                origin=sender,
                intrinsic_gas=int(parsed.get("intrinsic_gas") or 0),
                block_number=int(block_height or 1),
                timestamp=_evm_block_timestamp(block_timestamp),
                world=world,
                payer=sender,
                access_list=parsed.get("access_list") or (),
            ),
            preload=[sender, spend_from, to_bytes],
        )
        _receipt(result, result.success, result.error)
        if not result.success:
            # Undo the state changes but not what a failure must still cost: the gas
            # charge and the nonce. Deterministic: every node takes this branch for the same
            # transaction with the same gas figure, so the account root still agrees.
            await state_manager.revert(snap)
            if _ENFORCE_FAILED_TX_COSTS:
                await _charge_failed_tx(
                    state_manager,
                    sender_hex,
                    nonce,
                    gas_used=result.gas_used,
                    gas_limit=gas,
                    gas_price=gas_price_wei,
                    intrinsic=int(parsed.get("intrinsic_gas") or 0),
                    defer_commit=defer_commit,
                )
            if not defer_commit:
                await state_manager.commit(block_height)
            return {
                "success": False,
                "error": result.error,
                "tx_hash": tx_hash_hex,
                "sender": sender_hex,
                "nonce": nonce,
                "gas_charged": min(
                    gas, max(result.gas_used, int(parsed.get("intrinsic_gas") or 0))
                ),
            }
        section.absorb(result.token_journal or [])
        if not defer_commit:
            await state_manager.commit(block_height)
        if standalone:
            await section.commit(_node.db)
        created = encode_hex(result.created_address) if result.created_address else None
        _node.EVM_PENDING_NONCE[sender_hex.lower()] = max(
            _node.EVM_PENDING_NONCE.get(sender_hex.lower(), 0), nonce + 1
        )
        return {
            "success": True,
            "tx_hash": tx_hash_hex,
            "sender": sender_hex,
            "nonce": nonce,
            "created_address": created,
        }
    except Exception as e:
        logger.error(f"EVM execution of {tx_hash_hex} raised: {e}")
        await state_manager.revert(snap)
        _receipt(None, False, str(e))
        # A transaction that raised (out of gas, insufficient funds mid-execution, a VM
        # error) must cost the same as one that reverted — otherwise the cheapest way to
        # spam the network is to make execution throw. The full gas limit is charged, as
        # Ethereum does for an out-of-gas failure, since the work was done and the cause
        # is not attributable to a partial execution.
        if _ENFORCE_FAILED_TX_COSTS:
            await _charge_failed_tx(
                state_manager,
                sender_hex,
                nonce,
                gas_used=gas,
                gas_limit=gas,
                gas_price=gas_price_wei,
                intrinsic=int(parsed.get("intrinsic_gas") or 0),
                defer_commit=defer_commit,
            )
        if not defer_commit:
            await state_manager.commit(block_height)
        return {
            "success": False,
            "error": str(e),
            "tx_hash": tx_hash_hex,
            "sender": sender_hex,
            "nonce": nonce,
        }


async def _eth_call(evm_executor, call_params: dict) -> str:
    """eth_call against the latest state, in the latest block's context (its number and
    timestamp, as geth does), with the call's ``value`` — a payable call is simulated as sent,
    so the caller must hold it, as with geth — and its ``gas`` (at most the block gas limit).
    Nothing is written. The value used to be dropped: every payable call ran as if it sent
    nothing."""
    from eth_utils import decode_hex, encode_hex, to_canonical_address

    from ..contracts.evm_world import EvmWorld, run as run_evm
    from ..contracts.native_token_evm import TokenWorld

    def _quantity(raw, default):
        if raw is None or raw == "":
            return default
        if isinstance(raw, int):
            return raw
        text = str(raw)
        return int(text, 16) if text.lower().startswith("0x") else int(text)

    sender_hex = call_params.get("from") or "0x" + "0" * 40
    to_hex = call_params["to"]
    data_hex = call_params.get("data", call_params.get("input", "0x")) or "0x"
    sender = to_canonical_address(sender_hex)
    to = to_canonical_address(to_hex)
    data = decode_hex(data_hex)
    value = _quantity(call_params.get("value"), 0)
    gas = _quantity(call_params.get("gas"), None)
    if value < 0 or (gas is not None and gas <= 0):
        raise Exception("Call failed: value and gas must be positive quantities")

    # The state is loaded on demand, native tokens included (their precompile answers ERC-20
    # calls at the token's address).
    tip = (await _node.db.get_next_block_id()) - 1
    tip_block = await _node.db.get_block_by_id(tip) if tip >= 0 else None
    world = EvmWorld(evm_executor.state_manager, tokens=TokenWorld(_node.db))
    result = await run_evm(
        world,
        lambda: evm_executor.call(
            sender=sender,
            to=to,
            data=data,
            value=value,
            gas=gas,
            block_number=max(tip, 1),
            timestamp=_evm_block_timestamp((tip_block or {}).get("timestamp")),
            world=world,
        ),
        preload=[sender, to],
    )
    if not result.success:
        raise Exception(f"Call failed: {result.error}")
    return encode_hex(result.output)


def _evm_defer_execute():
    """An execute_tx callable bound to the live executor, deferring per-tx commit."""

    async def _execute(raw, h, bh, bt):
        return await _execute_evm_raw_tx(raw, h, bh, bt, defer_commit=True)

    return _execute


async def _produce_evm_section(block_height, block_hash, block_timestamp, raw_txs):
    """
    Proposer hook (E-D3b execute-on-mine): execute the selected EVM section
    against live EVM state and return ``(account_state_root, included_raw_txs)``.

    ``(None, [])`` when EVM is disabled, there are no txs, or the section could
    not be produced (the proposer then ships the block without an EVM section).
    """
    if _node.EVM_STATE_MANAGER is None or not raw_txs:
        return None, []
    from ..contracts.evm_block_apply import produce_block_evm_section

    return await produce_block_evm_section(
        block_height,
        block_hash,
        block_timestamp,
        raw_txs,
        _node.db,
        _node.EVM_STATE_MANAGER,
        _evm_defer_execute(),
    )


async def _apply_evm_section_on_import(
    block_height, block_hash, block_timestamp, evm_section, declared_root
):
    """
    Importer hook (E-D3b): validate + replay a block's EVM section, rejecting on
    any mismatch (local state left untouched). Returns ``(ok, error)``.

    Two modes:
      - **Strict (live broadcast):** a declared ``account_state_root`` is present,
        so replay and REJECT on mismatch — real-time defense against a malicious
        proposer.
      - **Trust-replay (sync):** no root is bound to the block (the sync-serving
        endpoints attach the section but not a root, and pre-D4 the root is not
        bound into the block hash). The block is canonical history already
        accepted by the network, so replay and ADOPT the computed root, exactly
        like ``rebuild_account_state_from_chain``. Best-effort: a replay failure
        is logged but does not halt sync of a canonical block.

    Backward-compatible: an empty/absent section is accepted. If this node does
    not run the EVM system it accepts without applying (stored for later rebuild).
    """
    if not evm_section:
        return True, ""
    from ..contracts.evm_block_apply import section_gas_error

    # A validity rule on every path (BLOCK_LIMITS.md), at the block's height (big blocks).
    gas_error = section_gas_error(evm_section, block_height)
    if gas_error:
        return False, f"block {block_height}: {gas_error}"
    if _node.EVM_STATE_MANAGER is None:
        logger.warning(
            "EVM section present but EVM disabled on this node — storing without applying"
        )
        return True, ""
    from .. import post_state

    if post_state.active(block_height):
        # Deferred execution: the block was signed before it ran, so it runs whole — a
        # transaction that cannot run is skipped — and the next block's root binds the result.
        from ..contracts.evm_block_apply import apply_block_evm_section_total

        ok, err, _ran = await apply_block_evm_section_total(
            block_height,
            block_hash,
            block_timestamp,
            evm_section,
            _node.db,
            _node.EVM_STATE_MANAGER,
            _evm_defer_execute(),
        )
        return ok, err
    if declared_root:
        from ..contracts.evm_block_apply import apply_block_evm_section

        return await apply_block_evm_section(
            block_height,
            block_hash,
            block_timestamp,
            evm_section,
            declared_root,
            _node.db,
            _node.EVM_STATE_MANAGER,
            _evm_defer_execute(),
        )
    # Trust-replay (sync): adopt the canonical section's computed root.
    from ..contracts.evm_block_apply import produce_block_evm_section

    try:
        root, included = await produce_block_evm_section(
            block_height,
            block_hash,
            block_timestamp,
            evm_section,
            _node.db,
            _node.EVM_STATE_MANAGER,
            _evm_defer_execute(),
        )
        if root is None:
            logger.warning(f"EVM section trust-replay produced no root at block {block_height}")
        return True, ""
    except Exception as e:
        logger.warning(f"EVM section trust-replay failed at block {block_height}: {e}")
        return True, ""


async def _gossip_evm_raw_tx(raw_tx_hex: str):
    """
    Best-effort propagate a signed EVM raw transaction to peers' mempools.

    Under execute-on-mine (E-D3b) ``eth_sendRawTransaction`` is admit-only, so
    this gossip is **mempool propagation**: each peer admits the tx to its own
    EVM mempool so whichever node proposes the next block can include it. The
    peer's EVM_TX_CACHE stops the gossip from looping. (Previously this drove
    Phase-1 live execution convergence; that role is retired.)
    """
    try:
        peers = NodesManager.get_propagate_peers()
    except Exception as e:
        logger.debug("EVM gossip: could not list peers: %s", e)
        return
    for peer in peers:
        url = peer.get("url")
        if not url:
            continue
        try:
            ni = NodeInterface(url, client=_node.http_client, db=_node.db)
            # _propagated=True so the receiving peer does not re-broadcast on our behalf.
            await ni._rpc_call("eth_sendRawTransaction", [raw_tx_hex, True])
        except Exception as e:
            logger.debug("EVM tx gossip to %s failed: %s", url, e)
