"""
Submitting transactions: legacy and exchange transactions, and exchange receipts and
nonces.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import sqlite3

from fastapi import Body, Depends, HTTPException, status
from starlette.background import BackgroundTasks
from starlette.requests import Request

from qrdx.constants import MAX_MEMPOOL_SIZE
from qrdx.logger import get_logger
from qrdx.node import main as _node, peers as _peers
from qrdx.node.api import verified_sender
from qrdx.node.main import app, limiter
from qrdx.transactions import Transaction

logger = get_logger(__name__)


@app.post("/push_tx")
@limiter.limit("100/minute")
async def push_tx(
    request: Request,
    background_tasks: BackgroundTasks,
    body: dict = Body(...),
    verified_sender: str = Depends(verified_sender),
):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    tx_hex = body.get("tx_hex")
    if not tx_hex:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "'tx_hex' not found in body.")

    is_valid, error_msg = _node.security.input_validator.validate_transaction_data(tx_hex)
    if not is_valid:
        await _node.security.reputation_manager.record_violation(
            verified_sender, "invalid_transaction", severity=2, details=error_msg
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, error_msg)

    tx = await Transaction.from_hex(tx_hex)

    # Verify the transaction before accepting it into the mempool.
    try:
        if not await tx.verify():
            await _node.security.reputation_manager.record_violation(
                verified_sender,
                "invalid_transaction_content",
                severity=5,
                details="Transaction failed full verification",
            )
            return {"ok": False, "error": "Transaction verification failed"}
    except Exception as e:
        await _node.security.reputation_manager.record_violation(
            verified_sender,
            "invalid_transaction_content",
            severity=5,
            details=f"Verification error: {e}",
        )
        return {"ok": False, "error": f"Transaction verification failed: {e}"}

    if await _node.security.transaction_cache.contains(tx.hash()):
        return {"ok": False, "error": "Transaction just added"}

    pending_count = await _node.db.get_pending_transaction_count()
    if pending_count >= MAX_MEMPOOL_SIZE:
        await _node.security.security_monitor.log_event(
            "mempool_full", {"peer_id": verified_sender, "pending_count": pending_count}
        )
        return {"ok": False, "error": "Mempool is full"}

    try:
        if await _node.security.transaction_pool.add_transaction(tx.hash(), tx, _node.db):
            background_tasks.add_task(
                _peers.propagate, "push_tx", {"tx_hex": tx_hex}, ignore_node_id=verified_sender
            )
            await _node.security.transaction_cache.put(tx.hash(), True)
            return {"ok": True, "result": "Transaction has been accepted"}
        else:
            return {"ok": False, "error": "Transaction has not been added"}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": "Transaction already present"}
    except Exception as e:
        await _node.security.security_monitor.log_event(
            "transaction_error", {"peer_id": verified_sender, "error": str(e)}
        )
        return {"ok": False, "error": "Transaction rejected"}


@app.post("/submit_tx")
@limiter.limit("30/minute")
async def submit_tx(request: Request, background_tasks: BackgroundTasks, body: dict = Body(...)):
    tx_hex = body.get("tx_hex")
    if not tx_hex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="'tx_hex' not found in body."
        )

    is_valid, error_msg = _node.security.input_validator.validate_transaction_data(tx_hex)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    try:
        tx = await Transaction.from_hex(tx_hex)

        # Verify the transaction before accepting it.
        if not await tx.verify():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Transaction verification failed."
            )

    except HTTPException:
        raise
    except Exception as e:
        # Catch verification errors or deserialization errors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid transaction: {e}"
        ) from e

    if await _node.security.transaction_cache.contains(tx.hash()):
        return {"ok": False, "error": "Transaction recently seen"}

    pending_count = await _node.db.get_pending_transaction_count()
    if pending_count >= MAX_MEMPOOL_SIZE:
        return {"ok": False, "error": "Mempool is full"}

    try:
        if await _node.security.transaction_pool.add_transaction(tx.hash(), tx, _node.db):
            logger.info(
                f"Accepted transaction {tx.hash()} from external client. Propagating to network..."
            )
            background_tasks.add_task(
                _peers.propagate, "push_tx", {"tx_hex": tx_hex}, ignore_node_id=None
            )
            await _node.security.transaction_cache.put(tx.hash(), True)
            return {"ok": True, "result": "Transaction has been accepted"}
        else:
            return {"ok": False, "error": "Transaction failed validation"}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": "Transaction already present in pending pool"}
    except Exception:
        return {"ok": False, "error": "Transaction rejected"}


@app.post("/submit_exchange_tx")
@limiter.limit("30/minute")
async def submit_exchange_tx(request: Request, body: dict = Body(...)):
    """
    Submit a signed exchange transaction (spot, perps, staking, oracle votes — every exchange op).

    Body: ``{"tx": {...}}`` (the transaction as a JSON object) or ``{"tx_hex": "..."}`` (the
    string ``ExchangeTransaction.to_hex()`` makes). Admission — PQ signature + sender binding,
    nonce window, dedup, capacity — happens here; then the transaction is gossiped to peers and
    executes when a validator includes it in a block. Poll ``/get_exchange_receipt`` for the
    result. ``POST /exchange_signing_payload`` returns the exact bytes to sign.
    """
    tx = body.get("tx") if body.get("tx") is not None else body.get("tx_hex")
    if tx is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="send the transaction as 'tx' (object) or 'tx_hex' (string)",
        )
    try:
        ok, error, tx_hash = await _node._get_exchange_submitter().submit(tx)
    except Exception as e:
        logger.error(f"submit_exchange_tx error: {e}")
        return {"ok": False, "error": "Exchange transaction rejected"}
    if not ok:
        return {"ok": False, "error": error}
    return {
        "ok": True,
        "result": {"tx_hash": tx_hash, "mempool_size": _node._get_exchange_mempool().size()},
    }


@app.post("/exchange_signing_payload")
async def exchange_signing_payload(body: dict = Body(...)):
    """The exact bytes an exchange transaction's sender signs, for these fields (``op_type`` as
    a number or name, ``sender``, ``nonce``, ``params``, optional ``gas_limit`` / ``gas_price``),
    and the hash the transaction will have. Sign ``signing_bytes`` with the sender's Dilithium
    key, add ``signature`` and ``public_key`` (hex) to ``tx``, and submit it."""
    from qrdx.exchange.submission import signing_payload

    try:
        return {"ok": True, "result": signing_payload(body.get("tx", body))}
    except Exception as e:
        return {"ok": False, "error": f"invalid transaction fields: {e}"}


@app.get("/get_exchange_receipt")
async def get_exchange_receipt(tx_hash: str):
    """The executed result of an exchange transaction — success or failure, its error, and the
    operation's data (an order's id and fills, a deposit's collateral, …). ``null`` while it is
    pending (or after it ages out of this node's journal)."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.receipt(ExchangeStateManager.get_instance(), tx_hash)}


@app.get("/get_exchange_nonce")
async def get_exchange_nonce(address: str):
    """The next exchange nonce for ``address`` (exchange transactions have their own sequence)."""
    from qrdx.exchange import ExchangeStateManager, views

    mgr = ExchangeStateManager.get_instance()
    return {
        "ok": True,
        "result": {
            "address": address,
            "nonce": mgr.get_nonce(views.account_key(mgr.clearinghouse, address) or address),
        },
    }
