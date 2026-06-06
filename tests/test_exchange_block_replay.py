"""
Phase D3 — secure import replay + exchange state-root validation.

An importing node must re-execute a block's exchange section, verify every
transaction's signature, and accept the block only if the recomputed
exchange_state_root matches the proposer's declared root — reverting local state
on any failure so a bad block cannot corrupt it.

Covers (see docs/EXCHANGE_PRODUCTION_READINESS.md §4 Phase D3):
  - a valid section is accepted and advances state to the declared root;
  - proposer and a fresh importer converge on identical state (determinism);
  - a forged/tampered tx in the section is rejected with state untouched;
  - a wrong declared root is rejected and state is reverted (not corrupted);
  - a section without a declared root is rejected;
  - empty/absent section is a no-op.
"""

from decimal import Decimal

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import (
    ExchangeStateManager,
    ExchangeTransaction,
    ExchangeOpType,
    encode_exchange_txs,
    apply_block_exchange_section,
)
from qrdx.exchange.amm import FeeTier, PoolType
from qrdx.exchange.block_processor import process_exchange_transactions

HEIGHT = 1
TS = 1_700_000_000.0


def _signer():
    k = PQPrivateKey.generate()
    return k, k.public_key.to_address()


def _sign(tx, key):
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def _block_section():
    """A deterministic section: create a pool + a resting limit order."""
    lpk, lp = _signer()
    mk_k, mk = _signer()
    create = _sign(ExchangeTransaction(
        op_type=ExchangeOpType.CREATE_POOL, sender=lp, nonce=0,
        params={"token0": "qBTC", "token1": "qUSD", "fee_tier": int(FeeTier.MEDIUM),
                "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": "173.205080756",
                "stake_amount": "10000"},
        gas_limit=1_000_000, gas_price=Decimal("1")), lpk)
    order = _sign(ExchangeTransaction(
        op_type=ExchangeOpType.PLACE_ORDER, sender=mk, nonce=0,
        params={"pair": "qBTC:qUSD", "side": "sell", "order_type": "limit",
                "price": "30000", "amount": "1"},
        gas_limit=1_000_000, gas_price=Decimal("1")), mk_k)
    return [create, order]


def _propose(txs):
    """Proposer: execute on a fresh manager, return the declared root."""
    mgr = ExchangeStateManager()
    ok, err, root = process_exchange_transactions(HEIGHT, TS, txs, mgr)
    assert ok, err
    mgr.commit_block()
    return root


def test_valid_section_accepted_and_advances_state():
    txs = _block_section()
    declared = _propose(txs)

    importer = ExchangeStateManager()
    ok, err = apply_block_exchange_section(HEIGHT, TS, encode_exchange_txs(txs), declared, importer)
    assert ok, err
    # State advanced to exactly the declared root.
    assert importer.compute_state_root() == declared


def test_proposer_and_importer_converge():
    txs = _block_section()
    declared = _propose(txs)
    importer = ExchangeStateManager()
    ok, _ = apply_block_exchange_section(HEIGHT, TS, encode_exchange_txs(txs), declared, importer)
    assert ok
    # Re-proposing on yet another fresh manager yields the same root → determinism.
    assert _propose(txs) == declared == importer.compute_state_root()


def test_forged_tx_rejected_state_untouched():
    txs = _block_section()
    declared = _propose(txs)
    section = encode_exchange_txs(txs)
    # Corrupt the signature of the second tx in the wire section.
    section[1]["signature"] = "00" * 10

    importer = ExchangeStateManager()
    before = importer.compute_state_root()
    ok, err = apply_block_exchange_section(HEIGHT, TS, section, declared, importer)
    assert not ok and "verification" in err
    assert importer.compute_state_root() == before, "rejected block must not touch state"


def test_tampered_params_rejected():
    txs = _block_section()
    declared = _propose(txs)
    section = encode_exchange_txs(txs)
    # Mutate a param so the signature no longer matches (authentication fails).
    section[1]["params"]["amount"] = "999"

    importer = ExchangeStateManager()
    before = importer.compute_state_root()
    ok, err = apply_block_exchange_section(HEIGHT, TS, section, declared, importer)
    assert not ok
    assert importer.compute_state_root() == before


def test_wrong_declared_root_rejected_and_reverted():
    txs = _block_section()
    _propose(txs)  # ignore real root
    wrong_root = "ab" * 64  # 128-hex but wrong

    importer = ExchangeStateManager()
    before = importer.compute_state_root()
    ok, err = apply_block_exchange_section(HEIGHT, TS, encode_exchange_txs(txs), wrong_root, importer)
    assert not ok and "mismatch" in err
    # CRITICAL: state reverted, not left in the wrongly-applied state.
    assert importer.compute_state_root() == before


def test_section_without_declared_root_rejected():
    txs = _block_section()
    importer = ExchangeStateManager()
    before = importer.compute_state_root()
    ok, err = apply_block_exchange_section(HEIGHT, TS, encode_exchange_txs(txs), None, importer)
    assert not ok and "declares no exchange_state_root" in err
    assert importer.compute_state_root() == before


def test_empty_section_is_noop():
    importer = ExchangeStateManager()
    before = importer.compute_state_root()
    assert apply_block_exchange_section(HEIGHT, TS, None, None, importer) == (True, "")
    assert apply_block_exchange_section(HEIGHT, TS, [], "anything", importer) == (True, "")
    assert importer.compute_state_root() == before


def test_commit_block_blocks_later_revert():
    """After commit, a stray revert_block must not undo committed state."""
    txs = _block_section()
    mgr = ExchangeStateManager()
    ok, err, root = process_exchange_transactions(HEIGHT, TS, txs, mgr)
    assert ok
    mgr.commit_block()
    committed = mgr.compute_state_root()
    mgr.revert_block()  # snapshot was cleared by commit → no-op
    assert mgr.compute_state_root() == committed
