"""
Importing a block: the checks every block passes (chain rules, parent continuity,
proposer, unified state root) and applying its sections (exchange, withdrawals, tick).
process_and_create_block is the one path every block takes into the chain.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import os
import time
from typing import Dict, Optional, Tuple

from qrdx.logger import get_logger
from qrdx.node import derived_state as _derived, evm_runtime as _evm, main as _node
from qrdx.transactions import Transaction
from qrdx.validator.block_verification import verify_block_proposer, verify_proposer_eligibility

logger = get_logger(__name__)

# Slot-proposer eligibility gate. Enabled after the validator-set convergence fix:
# with a consistent validator set + correct identities, every node reconstructs the
# same slot proposer — observed 0 mismatches across a 3-run soak (all import paths,
# incl. sync) — so out-of-turn proposals are now rejected.
_ENFORCE_PROPOSER_ELIGIBILITY = True

# Parent-hash continuity on import (observe-first). The import path validates
# height-sequentiality but NOT that a block's declared parent_hash matches the
# local chain tip — so a fork block can be appended on a mismatched parent,
# leaving a broken parent linkage (get_block_by_id(h) returns a non-canonical
# block whose hash != the next block's parent_hash). This was found via the RANDAO
# observe mix diverging on a node that had a stale block at height 2 whose child's
# parent it never stored. OBSERVE = log the mismatch; ENFORCE = reject the fork
# block (never append it on a mismatched parent).
#
# Mechanism-1 enforce is now PROVEN SAFE (post-logger-fix re-soak: 6/6 pass, incl. a
# run with 15 parent-rejections that still fully converged — so the first soak's run6
# fall-behind was the reorg-abort bug, NOT the reject). BUT it is INSUFFICIENT alone:
# a genesis-era equal-height fork still persists (a node ended with block1 from one
# fork + block2 from another → 1 broken link, 2 RANDAO mixes, with NO reorg in its
# log — the fork block reached it via a path the import check doesn't cover, i.e.
# genesis bootstrap / proposer self-build). Full convergence needs mechanism-2
# (equal-height tie-break) + covering that path. Kept OBSERVE (minimal footprint,
# known-good) until both land and can be enforced together. See FORK_CHOICE_CONVERGENCE.md.
# Env-overridable (QRDX_ENFORCE_PARENT_CONTINUITY=1) for A/B testing.
#
# NOTE (2026-09-29): the "6/6 pass" enforce soak above only ever covered the sync and REST
# paths. The p2p path — live broadcast, where most blocks arrive — called the checker
# without `enforce`, so it defaulted to False and p2p NEVER enforced whatever this flag
# said. `_check_parent_continuity` now defaults to this flag, so enabling it covers p2p too.
#
# ENABLED (2026-09-29) together with _ENFORCE_FORK_CHOICE_RECONCILE, the combination prior
# work concluded was required. Interleaved A/B, three fault-injecting soaks per arm:
#   observe : worst block divergence 4, 4, 5   broken parent links 3, 3, 4
#   ENFORCED: worst block divergence 0, 0, 0   broken parent links 0, 0, 0
# all six soaks PASS 19/19 with derived state converged; liveness unchanged (tips 182-225
# vs 184-237, tip spread 6-7 vs 6-15). Env-overridable (=0) for A/B testing only — it must
# match on every node.
_ENFORCE_PARENT_CONTINUITY = os.getenv("QRDX_ENFORCE_PARENT_CONTINUITY", "1").lower() not in (
    "0",
    "false",
    "no",
)


async def _apply_block_withdrawals_on_import(block_height, block_epoch):
    """
    Apply a block's stake withdrawals during import — the importer's half of the in-block
    withdrawal mechanism (qrdx/validator/withdrawals.py).

    Placed after the EVM section and before the unified-root check on every import path,
    mirroring the proposer, so both compute the same credits against the same state. An
    unknown epoch skips processing rather than guessing: a guessed epoch could pay a
    different set than the proposer did.
    """
    if block_epoch is None:
        return
    try:
        from ..validator.withdrawals import process_block_withdrawals

        await process_block_withdrawals(_node.db, int(block_height), int(block_epoch))
    except Exception as e:
        logger.error(f"withdrawal processing failed on import of block {block_height}: {e}")


async def _exchange_tick_on_import(block_height, block_timestamp) -> None:
    """
    The exchange's per-block tick for an imported block that carries no exchange section
    (``block_processor.run_exchange_tick``). Clearinghouse duties — mark prices now,
    liquidations and funding next — must advance on every block, so every path ticks every
    block from height 1: the proposer, these importers and both rebuilds.
    """
    if not block_height or int(block_height) < 1:
        return
    try:
        from ..exchange.block_processor import ensure_oracle_committee, tick_and_flush
        from ..exchange.state_manager import ExchangeStateManager

        await ensure_oracle_committee(
            _node.db, ExchangeStateManager.get_instance(), int(block_height)
        )
        await tick_and_flush(_node.db, int(block_height), float(block_timestamp or 0))
    except Exception as e:
        logger.error(f"exchange tick failed at block {block_height}: {e}")


async def _apply_exchange_section_on_import(
    block_height, block_timestamp, ex_section, declared_root, block_epoch=None
):
    """
    Importer hook for the exchange section, with the same strict/trust split as
    the EVM one (E-D3b). Strict (declared root present, live broadcast): validate
    + reject-on-mismatch. Trust-replay (no root, sync of canonical history):
    replay + adopt, like ``rebuild_exchange_state_from_chain``. Returns
    ``(ok, error)``; trust-replay never halts sync of a canonical block.
    """
    if not ex_section:
        return True, ""
    from ..exchange.block_processor import (
        ENFORCE_EXCHANGE_COLLATERAL,
        apply_enforcement,
        decode_exchange_txs,
        flush_exchange_balance_deltas,
        flush_token_balance_deltas,
        flush_validator_lifecycle_deltas,
        preload_sender_balances,
        preload_token_balances,
        section_form_error,
        verify_exchange_txs,
    )
    from ..exchange.state_manager import ExchangeStateManager

    # Authenticate every transaction first, on both paths, before anything changes. The
    # trust-replay branch (no declared root) used to execute the section unverified: a proposer
    # that left the root out could act as any account with an unsigned transaction in its name
    # (docs/EXCHANGE_AUDIT.md).
    # Decoded once, here; the steps below share these transactions (a compact block's are the
    # mempool's own, checked when admitted: docs/PERFORMANCE.md).
    # The section in the form its height carries (chain-spec ``binary_exchange_txs``): a
    # compact block is rebuilt by height, so a proposer may not choose another.
    _form = section_form_error(ex_section, int(block_height))
    if _form:
        return False, f"exchange section of block {block_height}: {_form}"
    try:
        _decoded = decode_exchange_txs(ex_section)
    except Exception as e:
        return False, f"undecodable exchange section: {e}"
    for _i, (_ok, _why) in enumerate(await verify_exchange_txs(_decoded)):
        if not _ok:
            return False, f"exchange tx {_i} in block {block_height} failed verification: {_why}"

    mgr = ExchangeStateManager.get_instance()
    apply_enforcement(mgr)
    # Phase E: pre-load senders' real QRDX + token balances so the collateral and
    # spot-sufficiency checks can read them during the sync section processing.
    try:
        known = await preload_sender_balances(_node.db, _decoded, mgr, int(block_height))
        await preload_token_balances(_node.db, _decoded, mgr, known=known)
    except Exception as e:
        logger.debug(f"exchange balance pre-load skipped at block {block_height}: {e}")

    if declared_root:
        from ..exchange.block_processor import apply_block_exchange_section

        ok, err = apply_block_exchange_section(
            block_height,
            float(block_timestamp or 0),
            _decoded,
            declared_root,
            verified=True,  # (above, on these very items)
        )
        if ok:
            # Phase E: flush margin debits to account_state + token moves to the
            # token ledger (before the E-D4 root check, so both domains reflect).
            await flush_exchange_balance_deltas(_node.db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
            await flush_token_balance_deltas(_node.db, mgr)
            await flush_validator_lifecycle_deltas(
                _node.db, mgr, block_epoch=block_epoch, block_height=block_height
            )
        else:
            # The section is left half-applied (no per-block revert point): back to the tip.
            await _derived._restore_after_rejected_block(block_height, f"exchange section: {err}")
        return ok, err
    # Trust-replay (sync): adopt the canonical section's computed root. Under deferred execution
    # (qrdx/post_state.py) no block declares its own exchange root, and a section that does not
    # run (one its transactions may not be in: ``exchange_inclusion``) refuses the block on every
    # path: its root is bound by the next block, so adopting it would bind a state the proposer
    # never had.
    from .. import post_state

    deferred = post_state.active(block_height)
    try:
        from ..exchange.block_processor import process_exchange_transactions

        ok, err, _root = process_exchange_transactions(
            block_height,
            float(block_timestamp or 0),
            _decoded,
            mgr,
        )
        if ok:
            mgr.commit_block()
            await flush_exchange_balance_deltas(_node.db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
            await flush_token_balance_deltas(_node.db, mgr)
            await flush_validator_lifecycle_deltas(
                _node.db, mgr, block_epoch=block_epoch, block_height=block_height
            )
        else:
            # Adopted without its section, as a replay does (it reverts): back to the tip.
            if not deferred:
                logger.warning(
                    f"Exchange section trust-replay failed at block {block_height}: {err}"
                )
            await _derived._restore_after_rejected_block(block_height, f"exchange section: {err}")
            if deferred:
                return False, err
        return True, ""
    except Exception as e:
        logger.warning(f"Exchange section trust-replay error at block {block_height}: {e}")
        await _derived._restore_after_rejected_block(block_height, f"exchange section: {e}")
        if deferred:
            return False, f"exchange section raised: {e}"
        return True, ""


# E-D4 rollout flag. Enabled after validator-set convergence: the live-broadcast
# paths (p2p/REST) recompute the unified state root and observed 0 mismatches
# across a 3-run soak (reorgs now ~0, so no transient divergence). With True, a
# live-broadcast block whose recomputed unified root != the signed root is
# REJECTED. The bulk-sync path has its own gates below.
_ED4_ENFORCE_UNIFIED_ROOT = True

# E-D4 sync-path enforcement at the FINALIZED boundary (doc item 1). The bulk-sync path
# stays trust-replay for the churning tip (a catching-up node transiently differs mid-
# reorg), but a block at/under the node's deterministic finalized height is SETTLED — the
# reorg guard refuses to roll back below it — so its unified root can no longer change and
# a mismatch there means the synced block's state genuinely diverges from what this node
# computed (a corrupt/malicious peer). Now that finality is real + bounds reorgs, enforce
# E-D4 for finalized synced blocks. Observe-first: False logs would-reject at finalized
# heights (to confirm 0 before flipping); True rejects them. Measured 0 would-rejects (the
# path near-never fires — a node syncs blocks ABOVE its tip and its local finalized_height
# trails its tip), and honest deterministic replay can't mismatch a settled block, so
# enforcing is safe + correct defense-in-depth.
_ED4_ENFORCE_SYNC_FINALIZED = True

# E-D4 on the bulk-sync TIP, not only at finalized heights. While the tip only observed, E-D4
# was not binding at all: a block the live paths REJECTED for a bad root re-entered through
# sync — its proposer builds on it, the next live block triggers a sync from that proposer,
# and the sync path accepted the bad block with an "[E-D4 observe]" warning. That is exactly
# how the proposer-mid-rebuild bug's wrong roots got into every node's chain.
#
# The tip was left observe because "a catching-up node legitimately holds different state
# mid-reorg". That stopped being true: every rollback now rebuilds derived state from the
# canonical prefix in forward order, the proposer can no longer build over a half-finished
# rebuild, and the exchange no longer reads the wall clock — so a node's state is a function
# of its chain, and an honest block's root must match. Two fault-injecting soaks with those
# fixes logged zero observe mismatches. A node whose own state is wrong is not stuck either:
# the rejection rebuilds derived state from the chain, and the next sync attempt re-applies
# the block on clean state. Env-overridable (QRDX_ED4_ENFORCE_SYNC=0) for A/B testing only.
_ED4_ENFORCE_SYNC_TIP = os.getenv("QRDX_ED4_ENFORCE_SYNC", "1").lower() not in ("0", "false", "no")


def _sync_ed4_enforced(at_finalized: bool) -> bool:
    """Whether the bulk-sync path rejects a block whose unified root does not match."""
    return _ED4_ENFORCE_SYNC_TIP or (at_finalized and _ED4_ENFORCE_SYNC_FINALIZED)


async def _check_parent_continuity(
    block_height, block_content, enforce: Optional[bool] = None
) -> Tuple[bool, str]:
    """
    Verify a block's declared ``parent_hash`` equals the local tip (the stored
    block at ``block_height - 1``). The import path otherwise only checks that
    heights are sequential, so a fork block can be appended on a mismatched parent
    — leaving a broken linkage where ``get_block_by_id(h).hash`` != the next
    block's ``parent_hash`` (a non-canonical block stranded at height h).

    Genesis (height 0) has no parent → always ok. On mismatch: ``enforce`` rejects
    (so the caller can reorg to the correct parent); otherwise it logs and accepts
    (observe). Returns ``(ok, error)``.
    """
    if enforce is None:
        # Default to the global gate so EVERY caller honours it — the p2p hook calls
        # this without `enforce`, and used to get a silent False.
        enforce = _ENFORCE_PARENT_CONTINUITY
    if not block_height or block_height <= 0:
        return True, ""
    from ..validator.block_verification import _parse_block_content

    try:
        bc = _parse_block_content(block_content)
        declared_parent = bc.get("parent_hash")
    except Exception:
        return True, ""  # unparseable content is the proposer-sig check's job
    if not declared_parent:
        return True, ""
    try:
        read = (
            getattr(_node.db, "get_block_header", None) or _node.db.get_block_by_id
        )  # no body needed
        parent_block = await read(block_height - 1)
    except Exception:
        parent_block = None
    local_tip = (
        (parent_block.get("hash") or parent_block.get("block_hash")) if parent_block else None
    )
    if local_tip and declared_parent != local_tip:
        msg = (
            f"parent_hash mismatch at height {block_height}: declared "
            f"{str(declared_parent)[:16]}..., local tip {str(local_tip)[:16]}... "
            f"(block is on a fork)"
        )
        if enforce:
            return False, msg
        logger.warning(f"[parent-continuity observe] {msg}")
        return True, ""
    return True, ""


_GENESIS_TIME: Dict[str, float] = {}


async def _current_slot() -> Optional[int]:
    """This node's wall-clock slot, from the genesis block's time (None before genesis)."""
    if "t" not in _GENESIS_TIME:
        from ..validator.node_integration import parse_block_timestamp

        genesis = await _node.db.get_block_by_id(0)
        parsed = parse_block_timestamp(genesis.get("timestamp") if genesis else None)
        if parsed is None:
            return None
        _GENESIS_TIME["t"] = parsed.timestamp()
    from ..constants import SLOT_DURATION

    return max(0, int((time.time() - _GENESIS_TIME["t"]) // SLOT_DURATION))


async def _verify_chain_rules(
    block_content, block_height, exchange_section=None, evm_section=None, block_hash=None
) -> Tuple[bool, str]:
    """The rules a block must satisfy against the chain it extends, run by every import path
    after the parent check and before anything is applied:

    * it is the block its proposer signed: its body matches the ``body_root`` in its signed
      header, and ``block_hash`` (as received) is its header's hash
      (block_verification.block_integrity_error; the sections, where they travel beside the
      content, are passed in);
    * at a trusted checkpoint's height, it is that checkpoint (qrdx/checkpoints.py);
    * it carries no more than a block may — gas, votes, slashing proofs (qrdx/block_limits.py);
    * it declares the base fees its parent sets, and pays them (qrdx/fee_market.py);
    * its slot is later than its parent's and not ahead of the clock
      (block_verification.verify_slot_progression), and its timestamp is that slot's start
      time (block_verification.verify_block_timestamp, under ``slot_timestamps``);
    * every attestation it carries is a valid Casper FFG vote for this chain — known key,
      valid signature, target this chain's checkpoint (ffg.verify_block_votes)."""
    from ..validator import ffg
    from ..validator.block_verification import (
        _parse_block_content,
        epoch_from_block,
        verify_block_timestamp,
        verify_slot_progression,
    )

    try:
        bc = _parse_block_content(block_content)
    except Exception as e:
        return False, f"unparseable block: {e}"
    if not isinstance(bc, dict):
        return False, "unparseable block"
    from .. import checkpoints
    from ..block_limits import block_resource_error
    from ..fee_market import base_fees_at, block_fee_error
    from ..validator.block_verification import block_integrity_error, reconstruct_signing_root

    if exchange_section is None:
        exchange_section = bc.get("exchange_transactions")
    if evm_section is None:
        evm_section = bc.get("evm_transactions")
    try:
        wrong = block_integrity_error(bc, exchange_section, evm_section, block_hash)
        trusted = checkpoints.trusted()
        if not wrong and int(block_height) in trusted:  # weak subjectivity (checkpoints.py)
            own_hash = block_hash or reconstruct_signing_root(bc).hex()
            wrong = checkpoints.checkpoint_error(int(block_height), own_hash, trusted)
        if not wrong:
            wrong = block_resource_error(bc, exchange_section, evm_section, block_height)
        if not wrong:
            expected = await base_fees_at(_node.db, int(block_height))
            wrong = block_fee_error(bc, exchange_section, evm_section, expected)
    except Exception as e:
        wrong = f"unreadable block contents: {e}"
    if wrong:
        return False, wrong
    try:
        ok, err = await verify_slot_progression(
            _node.db, bc, int(block_height), await _current_slot()
        )
        if not ok:
            return False, err
        ok, err = await verify_block_timestamp(_node.db, bc, int(block_height))
        if not ok:
            return False, err
        return await ffg.verify_block_votes(_node.db, bc, int(block_height), epoch_from_block(bc))
    except Exception as e:
        return False, f"chain-rule verification error: {e}"


async def _check_deferred_root(block_content, height: int) -> Tuple[bool, str]:
    """Before a block runs, under deferred execution (qrdx/post_state.py): its signed root must
    be the root of the state its parent left — the state this node holds. (True, "") when the
    feature is not in force at ``height``: the root is then checked after the block runs."""
    from .. import post_state

    if not post_state.active(height):
        return True, ""
    return await post_state.check(_node.db, block_content, int(height))


async def _verify_unified_state_root(
    block_content,
    enforce: Optional[bool] = None,
    height: Optional[int] = None,
    block_hash: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    E-D4: recompute the post-block unified state root (UTXO + account + exchange)
    and compare it to the block's signed ``state_root`` (in block_content).

    Must be called AFTER the block's protocol sections have been replayed but
    BEFORE the native block is applied — the same point the proposer computed it
    (UTXO pre-native-apply, account/exchange post-section). Returns ``(ok, err)``.

    ``enforce`` overrides the global gate: the live-broadcast paths use the global
    ``_ED4_ENFORCE_UNIFIED_ROOT``; the bulk-sync path passes ``_sync_ed4_enforced(...)``.
    """
    if enforce is None:
        enforce = _ED4_ENFORCE_UNIFIED_ROOT
    from .. import post_state
    from ..crypto.hashing import unified_state_root
    from ..validator.block_verification import _parse_block_content

    # Under deferred execution the block's root was checked before it ran (_check_deferred_root);
    # what it leaves is the next block's to sign. Its root is computed now and kept for that.
    if height is not None and post_state.active(int(height)):
        try:
            slot = _parse_block_content(block_content).get("slot")
        except Exception:
            slot = None
        slot = None if slot is None else int(slot)
        if block_hash:
            await post_state.settle(_node.db, int(height), block_hash, slot)
        else:
            await post_state.unified_root(_node.db, int(height), slot)
        return True, ""

    try:
        bc = _parse_block_content(block_content)
        declared = bc.get("state_root")
    except Exception:
        return True, ""  # malformed content is the proposer-sig check's job
    if not declared:
        return True, ""
    # Each domain's root is judged under the rule of this block's HEIGHT — given by the applying
    # path, else its parent's + 1. Never its signed ``number``: that is its slot, ahead of the
    # height after any skipped slot, so a height-gated fork would switch here before the
    # proposer did (and the state-proof roots were filed under the wrong height).
    if height is None:
        from ..validator.block_verification import block_height_of

        height = await block_height_of(_node.db, bc)

    try:
        utxo_root = await _node.db.get_unspent_outputs_hash(height)
    except Exception:
        utxo_root = "0" * 64
    try:
        account_root = await _node.db.get_account_state_root(height)
    except Exception:
        account_root = "0" * 128
    try:
        from ..exchange.state_manager import ExchangeStateManager

        exchange_root = ExchangeStateManager.get_instance().compute_state_root()
    except Exception:
        exchange_root = "0" * 128
    try:
        token_root = await _node.db.get_token_balances_root(height)
    except Exception:
        token_root = "0" * 128

    # The validators' state (qrdx/validator/validator_root.py), once its feature is in force:
    # S of the block's epoch on its parent chain and the staking logs through this block.
    from .. import state_proofs
    from ..validator import validator_root as vroot

    validators = None
    if height is not None and vroot.active(height):
        try:
            validators = await vroot.compute(_node.db, int(height), int(bc["slot"]))
        except Exception as e:
            logger.error(f"validator root failed at block {height}: {e}")
            return False, f"validator root: {e}"
    # The state-proof tree's root (qrdx/state_proofs.py), once its feature is in force.
    proof_root = None
    if height is not None and state_proofs.scheduled():
        # The exchange tree beside the database tree (qrdx/exchange/proofs.py), at the same
        # point as the exchange root.
        try:
            from ..exchange.state_manager import ExchangeStateManager

            xroot = ExchangeStateManager.get_instance().exchange_proof_root(height)
        except Exception as e:
            logger.error(f"exchange proof tree failed at block {height}: {e}")
            return False, f"exchange proof tree: {e}"
        proof_root = await state_proofs.proof_root(_node.db, height, xroot)
        await state_proofs.record_parts(
            _node.db,
            height,
            {
                "utxo": utxo_root or "0" * 64,
                "account": account_root,
                "exchange": exchange_root,
                "token": token_root,
                "proof": proof_root,
                "xtree": xroot.hex(),
                "validators": validators,
            },
        )
    # Token domain bound at the live token-ledger root — token state is now a
    # consensus object that converges across nodes (Phase E spot inc4/inc4b).
    computed = unified_state_root(
        utxo_root or "0" * 64, account_root, exchange_root, token_root, proof_root, validators
    )
    if computed != declared:
        msg = (
            f"unified state root mismatch: declared {str(declared)[:16]}..., "
            f"computed {computed[:16]}..."
        )
        if enforce:
            return False, msg
        logger.warning(f"[E-D4 observe] {msg}")
        return True, ""
    return True, ""


async def process_and_create_block(block_info: dict, is_bulk_sync: bool = False) -> bool:
    """Processes a single block dictionary with validation.

    Supports both PoW blocks (hex content → manager.create_block) and
    PoS blocks (already-committed dict data → direct DB insert).
    """
    block = block_info["block"]
    txs_hex = block_info.get("transactions", [])
    block_content = block.get("content", "")

    block_height = block.get("id") or block.get("block_height", 0)
    block_hash = block.get("hash") or block.get("block_hash", "")
    validator_address = block.get("address") or block.get("validator_address", "")

    # ---- PoS fast-path ----
    # If we already have a block_hash (produced by a validator) we store it
    # directly rather than running the PoW validation pipeline.
    if block_hash and validator_address:
        # Security: basic sanity checks even during sync
        if not isinstance(block_hash, str) or len(block_hash) < 16:
            logger.warning(f"[SYNC] Rejecting block with malformed hash at height {block_height}")
            return False

        # Security: block height must be exactly the next expected
        expected_height = await _node.db.get_next_block_id()
        if block_height != expected_height:
            logger.warning(
                f"[SYNC] Rejecting PoS block: height {block_height} != expected {expected_height}"
            )
            return False

        # Security: authenticate the proposer — verify the carried public key
        # derives to the claimed validator address (identity binding) and the
        # Dilithium signature over the signed header is valid. Without this an
        # imported block is only "from a registered address", not proven to be
        # produced by that validator.
        ok_prop, prop_err = await verify_block_proposer(
            _node.db, block_content, validator_address, block_height
        )
        if not ok_prop:
            logger.warning(
                f"[SYNC] Rejecting PoS block {block_height}: proposer auth failed: {prop_err}"
            )
            return False

        # Security: verify the proposer is the validator selected for this slot (catches
        # signature-valid but out-of-turn proposals) — on EVERY path, sync and fork-choice
        # adoption included. The set is the block's own parent chain's (validator/epoch_state.py),
        # so a block judged long after its slot is judged against the set it was proposed under.
        # Sync used to trust-replay this: the set was this node's live table, which moved with
        # finality, and judging history against it would have refused canonical blocks.
        ok_elig, elig_err = await verify_proposer_eligibility(
            _node.db,
            block_content,
            enforce=_ENFORCE_PROPOSER_ELIGIBILITY,
            height=int(block_height),
        )
        if not ok_elig:
            logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {elig_err}")
            return False

        # Parent-hash continuity (observe-first): the block's declared parent_hash
        # must equal the local tip's hash, else this block is on a fork and
        # appending it would break the height→block linkage. OBSERVE: warn only.
        ok_par, par_err = await _check_parent_continuity(
            block_height,
            block_content,
            enforce=_ENFORCE_PARENT_CONTINUITY,
        )
        if not ok_par:
            logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {par_err}")
            return False

        # Block limits, slot progression and FFG votes — _verify_chain_rules.
        ok_votes, votes_err = await _verify_chain_rules(
            block_content,
            block_height,
            block.get("exchange_transactions") or block_info.get("exchange_transactions"),
            block.get("evm_transactions") or block_info.get("evm_transactions"),
            block_hash,
        )
        if not ok_votes:
            logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {votes_err}")
            return False

        # Deferred execution (qrdx/post_state.py): the block's signed root is the state its
        # parent left, checked before it runs — under the same rule as E-D4 below.
        ok_root, root_err = await _check_deferred_root(block_content, int(block_height))
        if not ok_root:
            try:
                from ..validator.finality import finalized_block_height

                final_h = await finalized_block_height(_node.db)
                settled = final_h is not None and final_h >= 0 and block_height <= final_h
            except Exception:
                settled = False
            if _sync_ed4_enforced(settled):
                logger.warning(f"[SYNC] Refusing block {block_height} before it runs: {root_err}")
                return False
            logger.warning(f"[SYNC] [E-D4 observe] block {block_height} before it runs: {root_err}")

        # Everything the block changes from here is recorded in the undo journal under its
        # height (a checkpoint first if it opens an epoch) — what makes a later reorg cheap.
        from ..derived_state_rebuild import before_block
        from ..validator.block_verification import epoch_from_block as _block_epoch

        _epoch = _block_epoch(block)
        async with await before_block(
            _node.db, block_height, _epoch if _epoch is not None else _block_epoch(block_info)
        ):
            # D3/E-D3b: replay the exchange section (if any) before storing. Strict
            # (reject-on-mismatch) when a root is declared (live broadcast); trust-
            # replay (adopt) when syncing canonical history with no bound root.
            ex_section = block.get("exchange_transactions") or block_info.get(
                "exchange_transactions"
            )
            if ex_section:
                declared = block.get("exchange_state_root") or block_info.get("exchange_state_root")
                from ..validator.block_verification import epoch_from_block

                ok, verr = await _apply_exchange_section_on_import(
                    block_height,
                    block.get("timestamp", 0) or 0,
                    ex_section,
                    declared,
                    block_epoch=epoch_from_block(block) or epoch_from_block(block_info),
                )
                if not ok:
                    logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {verr}")
                    return False
            else:
                # No exchange transactions — the exchange still ticks (mark prices, ...).
                await _exchange_tick_on_import(block_height, block.get("timestamp", 0) or 0)

            # E-D3b: validate + replay the EVM section (execute-on-mine) before
            # storing — reject any block whose account_state_root doesn't match.
            evm_section = block.get("evm_transactions") or block_info.get("evm_transactions")
            if evm_section:
                ts_evm = block.get("timestamp", 0) or 0
                if hasattr(ts_evm, "timestamp"):
                    ts_evm = int(ts_evm.timestamp())
                declared_acc = block.get("account_state_root") or block_info.get(
                    "account_state_root"
                )
                ok_evm, verr_evm = await _evm._apply_evm_section_on_import(
                    block_height,
                    block_hash,
                    int(ts_evm),
                    evm_section,
                    declared_acc,
                )
                if not ok_evm:
                    logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {verr_evm}")
                    await _derived._restore_after_rejected_block(
                        block_height, f"EVM section: {verr_evm}"
                    )
                    return False

            # Stake withdrawals — same point as the proposer: after EVM, before E-D4.
            from ..validator.block_verification import epoch_from_block as _efb

            _wd_epoch = _efb(block)
            if _wd_epoch is None:
                _wd_epoch = _efb(block_info)
            await _apply_block_withdrawals_on_import(block_height, _wd_epoch)

            # E-D4 on the bulk-sync path — binding at the tip too (see _ED4_ENFORCE_SYNC_TIP):
            # without it, a block the live paths rejected for a bad root re-entered here.
            try:
                from ..validator.finality import finalized_block_height

                final_h = await finalized_block_height(_node.db)
                at_finalized = final_h is not None and final_h >= 0 and block_height <= final_h
                ok_ed4, verr_ed4 = await _verify_unified_state_root(
                    block_content,
                    enforce=_sync_ed4_enforced(at_finalized),
                    height=block_height,
                    block_hash=block_hash,
                )
                if not ok_ed4:
                    logger.warning(f"[SYNC] Rejecting block {block_height}: E-D4 {verr_ed4}")
                    await _derived._restore_after_rejected_block(block_height, f"E-D4: {verr_ed4}")
                    return False
            except Exception as e:
                logger.debug(f"[SYNC] E-D4 check skipped for block {block_height}: {e}")

            try:
                timestamp_val = block.get("timestamp", 0)
                await _node.db.add_block(
                    block_hash=block_hash,
                    block_height=block_height,
                    block_content=block_content or "",
                    validator_address=validator_address,
                    timestamp=timestamp_val,
                )
                # Store accompanying transactions
                for tx_hex in txs_hex or []:
                    try:
                        tx = await Transaction.from_hex(tx_hex)
                        await _node.db.add_transaction(tx, block_hash)
                    except Exception:
                        pass  # Non-critical during sync
                # D2.2b: persist the (now-validated) exchange section so a node rebuilt
                # from peers carries the same protocol-level state.
                if ex_section:
                    try:
                        await _node.db.add_block_exchange_txs(block_hash, ex_section)
                    except Exception as e:
                        logger.warning(
                            f"[SYNC] Failed to store exchange section for block {block_height}: {e}"
                        )
                # E-D3b: persist the (now-validated) EVM section for durability/rebuild.
                if evm_section:
                    try:
                        await _node.db.add_block_evm_txs(block_hash, evm_section)
                    except Exception as e:
                        logger.warning(
                            f"[SYNC] Failed to store EVM section for block {block_height}: {e}"
                        )
                # Finality (observe): record this block's attestation votes + recompute
                # justified/finalized. Best-effort; never blocks block storage.
                try:
                    from ..validator.finality import record_finality_from_block

                    await record_finality_from_block(_node.db, block_content)
                except Exception as e:
                    logger.debug(f"[SYNC] finality record skipped for block {block_height}: {e}")
                logger.debug(
                    f"[SYNC] Stored PoS block {block_height} ({block_hash[:16]}...) validator={validator_address[:20]}"
                )
                return True
            except Exception as e:
                logger.error(f"[SYNC] Failed to store PoS block {block_height}: {e}")
                return False

    # ---- A block without a proposer: the inherited proof-of-work format, refused ----
    # (manager.create_block refuses it too; docs/KNOWN_ISSUES.md)
    logger.warning(
        f"Sync failed: block {block_height} has no proposer (a proof-of-work block): refused"
    )
    return False
