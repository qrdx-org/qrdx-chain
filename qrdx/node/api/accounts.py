"""
Read-only REST views of accounts: balances, history, tokens and transactions.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import json
from typing import Optional

from fastapi import HTTPException, Query, status
from fastapi.responses import Response
from starlette.requests import Request

from qrdx.logger import get_logger
from qrdx.node import main as _node
from qrdx.node.api import CustomJSONEncoder
from qrdx.node.main import app, limiter

logger = get_logger(__name__)


@app.get("/get_address_info")
@limiter.limit("8/second")
async def get_address_info(
    request: Request,
    address: str,
    transactions_count_limit: int = Query(default=5, le=50),
    page: int = Query(default=1, ge=1),
    show_pending: bool = False,
    verify: bool = False,
    pretty: bool = False,
):
    # Validate address format. Protocol holders (pool reserves, order-book escrow, the perps
    # clearinghouse) are readable here even though no transaction can name them.
    from qrdx.crypto.account_id import is_synthetic_holder

    if not (
        _node.security.input_validator.validate_address(address) or is_synthetic_holder(address)
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid address format")

    # Check query cost
    offset = (page - 1) * transactions_count_limit
    await _node.security.query_calculator.check_and_update_cost(
        address, offset, transactions_count_limit
    )

    outputs = await _node.db.get_spendable_outputs(address)
    # Headline balance comes from the canonical reader (account_state first, UTXO
    # fallback) — in the unified ledger genesis + exchange-settled funds live in
    # account_state, so summing only the UTXO outputs would under-report (return 0
    # for an account_state-funded address). ``spendable_outputs`` below still
    # lists the UTXO entries available for legacy-style spends.
    balance = await _node.db.get_address_balance(address)

    transactions = (
        await _node.db.get_address_transactions(
            address, limit=transactions_count_limit, offset=offset, check_signatures=True
        )
        if transactions_count_limit > 0
        else []
    )

    result = {
        "ok": True,
        "result": {
            "balance": "{:f}".format(balance),
            "spendable_outputs": [
                {
                    "amount": "{:f}".format(output.amount),
                    "tx_hash": output.tx_hash,
                    "index": output.index,
                }
                for output in outputs
            ],
            "transactions": [
                await _node.db.get_nice_transaction(tx.hash(), address if verify else None)
                for tx in transactions
            ],
            "pending_transactions": (
                [
                    await _node.db.get_nice_transaction(tx.hash(), address if verify else None)
                    for tx in await _node.db.get_address_pending_transactions(address, True)
                ]
                if show_pending
                else None
            ),
            "pending_spent_outputs": (
                await _node.db.get_address_pending_spent_outputs(address) if show_pending else None
            ),
        },
    }

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


# ── transaction history (qrdx/tx_index.py) ───────────────────────────────


def _history_kinds(kinds: Optional[str]):
    return [k.strip() for k in kinds.split(",") if k.strip()] if kinds else None


@app.get("/get_address_history")
@limiter.limit("8/second")
async def get_address_history(
    request: Request,
    address: str,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: Optional[str] = None,
    kinds: Optional[str] = None,
):
    """Everything an address did or received — legacy transfers, exchange operations (token
    moves, swaps, orders and the fills of its resting orders, pools, perps, staking), EVM
    transactions and the token transfers they emitted — newest first, with each transaction's
    status, fee and the address's roles. ``0x`` and ``0xPQ`` forms of an account share one
    history. Page with ``cursor`` (the previous page's ``next_cursor``); ``kinds`` filters
    (comma-separated: genesis, transfer, coinbase, exchange, evm)."""
    from qrdx import tx_index

    try:
        return {
            "ok": True,
            "result": await tx_index.history(
                _node.db, address, limit=limit, cursor=cursor, kinds=_history_kinds(kinds)
            ),
        }
    except ValueError as e:
        return {"ok": False, "error": str(e)}


@app.get("/get_latest_transactions")
@limiter.limit("8/second")
async def get_latest_transactions(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: Optional[str] = None,
    kinds: Optional[str] = None,
):
    """The chain's latest transactions of every kind, newest first (paged like
    ``/get_address_history``)."""
    from qrdx import tx_index

    try:
        return {
            "ok": True,
            "result": await tx_index.recent(
                _node.db, limit=limit, cursor=cursor, kinds=_history_kinds(kinds)
            ),
        }
    except ValueError as e:
        return {"ok": False, "error": str(e)}


@app.get("/get_indexed_transaction")
async def get_indexed_transaction(tx_hash: str):
    """One indexed transaction of any kind — its block, status, fee, summary and every
    account it touched with their roles."""
    from qrdx import tx_index

    found = await tx_index.lookup(_node.db, tx_hash)
    if found is None:
        return {"ok": False, "error": f"transaction {tx_hash} not indexed"}
    return {"ok": True, "result": found}


@app.get("/get_address_tokens")
@limiter.limit("8/second")
async def get_address_tokens(
    request: Request, address: str, token_type: str = Query(default=None), pretty: bool = False
):
    """
    Get all QRC-20, QRC-721, and QRC-1155 tokens owned by an address
    """
    # Validate address format
    if not _node.security.input_validator.validate_address(address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid address format")

    # Normalize address to checksummed format
    try:
        from eth_utils import to_checksum_address

        normalized_address = (
            to_checksum_address(address)
            if address.startswith("0x") and len(address) == 42
            else address
        )
    except (ImportError, ValueError):
        normalized_address = address

    # ERC20 Transfer event signature: Transfer(address,address,uint256)
    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    try:
        if hasattr(_node.db, "pool"):
            # PostgreSQL implementation
            async with _node.db.pool.acquire() as conn:
                # Format address as 32-byte hex for topic matching
                address_topic = "0x" + normalized_address.lower().replace("0x", "").zfill(64)

                # Get all tokens received by this address
                tokens = await conn.fetch(
                    """
                    SELECT DISTINCT
                        cl.contract_address,
                        cm.name,
                        cm.symbol,
                        COALESCE(cm.verified, false) as verified
                    FROM contract_logs cl
                    LEFT JOIN contract_metadata cm ON cl.contract_address = cm.contract_address
                    WHERE cl.topic0 = $1
                      AND cl.topic2 = $2
                      AND cl.removed = false
                """,
                    transfer_topic,
                    address_topic,
                )

                result_tokens = []
                for token in tokens:
                    # Get transfer count for this token
                    balance_info = await conn.fetchrow(
                        """
                        SELECT COUNT(*) as received
                        FROM contract_logs
                        WHERE contract_address = $1
                          AND topic0 = $2
                          AND topic2 = $3
                          AND removed = false
                    """,
                        token["contract_address"],
                        transfer_topic,
                        address_topic,
                    )

                    if balance_info and balance_info["received"] > 0:
                        result_tokens.append(
                            {
                                "contract_address": token["contract_address"],
                                "name": token["name"],
                                "symbol": token["symbol"],
                                "verified": token["verified"],
                                "type": "QRC-20",
                                "transfer_count": int(balance_info["received"]),
                            }
                        )
        else:
            # SQLite implementation
            tokens = await _node.db.get_address_tokens(normalized_address, transfer_topic)
            result_tokens = [
                {
                    "contract_address": token["contract_address"],
                    "name": token["name"],
                    "symbol": token["symbol"],
                    "verified": bool(token["verified"]),
                    "type": "QRC-20",
                    "transfer_count": token["transfer_count"],
                }
                for token in tokens
            ]

        result = {
            "ok": True,
            "result": {
                "address": normalized_address,
                "tokens": result_tokens,
                "total_tokens": len(result_tokens),
            },
        }

    except Exception as e:
        logger.error(f"Error fetching address tokens: {e}")
        result = {"ok": False, "error": "Error fetching token information"}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.get("/get_token_info")
@limiter.limit("8/second")
async def get_token_info(request: Request, token_address: str, pretty: bool = False):
    """
    Get detailed information about a specific token contract
    """
    # Validate address format
    if not _node.security.input_validator.validate_address(token_address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid token address format")

    try:
        from eth_utils import to_checksum_address

        normalized_address = (
            to_checksum_address(token_address)
            if token_address.startswith("0x") and len(token_address) == 42
            else token_address
        )
    except (ImportError, ValueError):
        normalized_address = token_address

    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    try:
        if hasattr(_node.db, "pool"):
            # PostgreSQL implementation
            async with _node.db.pool.acquire() as conn:
                # Get contract metadata
                metadata = await conn.fetchrow(
                    """
                    SELECT
                        cm.*,
                        ac.balance,
                        ac.created_at,
                        cc.bytecode,
                        cc.deployed_at,
                        cc.deployer
                    FROM contract_metadata cm
                    LEFT JOIN account_state ac ON cm.contract_address = ac.address
                    LEFT JOIN contract_code cc ON ac.code_hash = cc.code_hash
                    WHERE cm.contract_address = $1
                """,
                    normalized_address,
                )

                if not metadata:
                    result = {"ok": False, "error": "Token contract not found"}
                else:
                    # Get transfer count
                    transfer_count = await conn.fetchval(
                        """
                        SELECT COUNT(*) FROM contract_logs
                        WHERE contract_address = $1 AND topic0 = $2 AND removed = false
                    """,
                        normalized_address,
                        transfer_topic,
                    )

                    # Get holder count
                    holder_count = await conn.fetchval(
                        """
                        SELECT COUNT(DISTINCT topic2) FROM contract_logs
                        WHERE contract_address = $1 AND topic0 = $2 AND removed = false
                    """,
                        normalized_address,
                        transfer_topic,
                    )

                    result = {
                        "ok": True,
                        "result": {
                            "contract_address": normalized_address,
                            "name": metadata["name"],
                            "symbol": metadata["symbol"],
                            "verified": metadata["verified"],
                            "compiler_version": metadata["compiler_version"],
                            "deployer": metadata.get("deployer"),
                            "deployed_at": metadata.get("deployed_at"),
                            "total_transfers": transfer_count,
                            "total_holders": holder_count,
                            "abi": metadata["abi"] if metadata["verified"] else None,
                        },
                    }
        else:
            # SQLite implementation
            token_info = await _node.db.get_token_info(normalized_address, transfer_topic)

            if not token_info:
                result = {"ok": False, "error": "Token contract not found"}
            else:
                result = {
                    "ok": True,
                    "result": {
                        "contract_address": normalized_address,
                        "name": token_info.get("name"),
                        "symbol": token_info.get("symbol"),
                        "verified": bool(token_info.get("verified", False)),
                        "total_transfers": token_info.get("total_transfers", 0),
                        "total_holders": token_info.get("total_holders", 0),
                        "abi": token_info.get("abi") if token_info.get("verified") else None,
                    },
                }

    except Exception as e:
        logger.error(f"Error fetching token info: {e}")
        result = {"ok": False, "error": "Error fetching token information"}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.get("/get_top_addresses")
@limiter.limit("5/minute")
async def get_top_addresses(
    request: Request,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    order_by: str = Query(default="balance"),  # balance, transactions, tokens
    pretty: bool = False,
):
    """
    Get top addresses by balance or activity
    """
    # Validate order_by parameter
    valid_orders = ["balance", "transactions", "tokens"]
    if order_by not in valid_orders:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Invalid order_by. Must be one of: {valid_orders}"
        )

    try:
        if hasattr(_node.db, "pool"):
            # PostgreSQL implementation
            async with _node.db.pool.acquire() as conn:
                if order_by == "balance":
                    # Get top addresses by balance (sum of unspent outputs)
                    query = """
                        SELECT
                            address,
                            SUM(amount) as balance,
                            COUNT(*) as output_count
                        FROM (
                            SELECT
                                uo.address,
                                CAST(COALESCE(t.outputs_amounts[uo.index + 1], 0) AS NUMERIC) / 1000000.0 as amount
                            FROM unspent_outputs uo
                            JOIN transactions t ON uo.tx_hash = t.tx_hash
                            WHERE uo.address IS NOT NULL
                        ) as balances
                        GROUP BY address
                        ORDER BY balance DESC
                        LIMIT $1 OFFSET $2
                    """
                    addresses = await conn.fetch(query, limit, offset)

                    result_addresses = [
                        {
                            "address": addr["address"],
                            "balance": "{:f}".format(addr["balance"]),
                            "output_count": addr["output_count"],
                        }
                        for addr in addresses
                    ]

                elif order_by == "transactions":
                    # Get most active addresses by transaction count
                    query = """
                        SELECT
                            address,
                            COUNT(*) as tx_count
                        FROM (
                            SELECT UNNEST(inputs_addresses) as address FROM transactions
                            UNION ALL
                            SELECT UNNEST(outputs_addresses) as address FROM transactions
                        ) as all_addresses
                        WHERE address IS NOT NULL
                        GROUP BY address
                        ORDER BY tx_count DESC
                        LIMIT $1 OFFSET $2
                    """
                    addresses = await conn.fetch(query, limit, offset)

                    result_addresses = [
                        {"address": addr["address"], "transaction_count": addr["tx_count"]}
                        for addr in addresses
                    ]

                else:  # tokens
                    # Get addresses with most token holdings
                    transfer_topic = (
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                    )
                    query = """
                        SELECT
                            topic2 as address_topic,
                            COUNT(DISTINCT contract_address) as token_count,
                            COUNT(*) as transfer_count
                        FROM contract_logs
                        WHERE topic0 = $1 AND removed = false
                        GROUP BY topic2
                        ORDER BY token_count DESC
                        LIMIT $2 OFFSET $3
                    """
                    addresses = await conn.fetch(query, transfer_topic, limit, offset)

                    result_addresses = [
                        {
                            "address": addr["address_topic"],
                            "token_count": addr["token_count"],
                            "transfer_count": addr["transfer_count"],
                        }
                        for addr in addresses
                    ]
        else:
            # SQLite implementation
            if order_by == "balance":
                addresses = await _node.db.get_top_addresses_by_balance(limit, offset)
                result_addresses = [
                    {
                        "address": addr["address"],
                        "balance": str(addr["balance"]),
                        "output_count": addr.get("output_count", 0),
                    }
                    for addr in addresses
                ]
            elif order_by == "transactions":
                addresses = await _node.db.get_top_addresses_by_transactions(limit, offset)
                result_addresses = [
                    {"address": addr["address"], "transaction_count": addr["tx_count"]}
                    for addr in addresses
                ]
            else:  # tokens
                transfer_topic = (
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                )
                addresses = await _node.db.get_top_addresses_by_tokens(
                    limit, offset, transfer_topic
                )
                result_addresses = [
                    {
                        "address": addr["address"],
                        "token_count": addr["token_count"],
                        "transfer_count": addr.get("transfer_count", 0),
                    }
                    for addr in addresses
                ]

        result = {
            "ok": True,
            "result": {
                "addresses": result_addresses,
                "count": len(result_addresses),
                "order_by": order_by,
            },
        }

    except Exception as e:
        logger.error(f"Error fetching top addresses: {e}")
        result = {"ok": False, "error": "Error fetching address rankings"}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.get("/get_recent_transactions")
@limiter.limit("10/minute")
async def get_recent_transactions(
    request: Request,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    include_contract_txs: bool = Query(default=True),
    pretty: bool = False,
):
    """
    Get most recent transactions across the chain
    """
    try:
        if hasattr(_node.db, "pool"):
            # PostgreSQL implementation
            async with _node.db.pool.acquire() as conn:
                # Get recent regular transactions
                txs_query = """
                SELECT
                    t.tx_hash,
                    t.block_hash,
                    b.id as block_number,
                    b.timestamp,
                    t.fees,
                    COALESCE(array_length(t.outputs_addresses, 1), 0) as output_count
                FROM transactions t
                JOIN blocks b ON t.block_hash = b.hash
                ORDER BY b.id DESC
                LIMIT $1 OFFSET $2
            """

            recent_txs = await conn.fetch(txs_query, limit, offset)

            result_txs = []
            for tx in recent_txs:
                result_txs.append(
                    {
                        "tx_hash": tx["tx_hash"],
                        "block_number": tx["block_number"],
                        "timestamp": tx["timestamp"].isoformat() if tx["timestamp"] else None,
                        "fees": "{:f}".format(tx["fees"]) if tx["fees"] else "0",
                        "output_count": tx["output_count"],
                        "type": "regular",
                    }
                )

            # Get recent contract transactions if requested
            if include_contract_txs:
                contract_txs_query = """
                    SELECT
                        ct.tx_hash,
                        ct.block_number,
                        ct.from_address,
                        ct.to_address,
                        ct.value,
                        ct.gas_used,
                        ct.status,
                        b.timestamp
                    FROM contract_transactions ct
                    JOIN blocks b ON ct.block_number = b.id
                    ORDER BY ct.block_number DESC
                    LIMIT $1 OFFSET $2
                """

                contract_txs = await conn.fetch(contract_txs_query, min(limit, 100), 0)

                for tx in contract_txs:
                    result_txs.append(
                        {
                            "tx_hash": tx["tx_hash"],
                            "block_number": tx["block_number"],
                            "timestamp": tx["timestamp"].isoformat() if tx["timestamp"] else None,
                            "from": tx["from_address"],
                            "to": tx["to_address"],
                            "value": tx["value"],
                            "gas_used": tx["gas_used"],
                            "status": "success" if tx["status"] == 1 else "failed",
                            "type": "contract",
                        }
                    )

                # Sort all transactions by block number
                result_txs.sort(key=lambda x: x["block_number"], reverse=True)
                result_txs = result_txs[:limit]
        else:
            # SQLite implementation
            transactions = await _node.db.get_recent_transactions_with_blocks(limit, offset)
            result_txs = [
                {
                    "tx_hash": tx["tx_hash"],
                    "block_number": tx.get("height", 0),
                    "block_hash": tx.get("block_hash", ""),
                    "timestamp": tx.get("timestamp", ""),
                    "fees": str(tx.get("fee", 0)),
                    "output_count": tx.get("output_count", 0),
                    "type": "regular",
                }
                for tx in transactions
            ]

            if include_contract_txs:
                contract_txs = await _node.db.get_recent_contract_transactions(
                    min(limit, 100), offset
                )
                for ctx in contract_txs:
                    result_txs.append(
                        {
                            "tx_hash": ctx["tx_hash"],
                            "block_number": ctx.get("height", 0),
                            "timestamp": ctx.get("timestamp", ""),
                            "from": ctx["sender"],
                            "to": ctx["contract_address"],
                            "value": str(ctx["value"]),
                            "gas_used": ctx["gas_used"],
                            "status": ctx["status"],
                            "type": "contract",
                        }
                    )

                # Sort all by timestamp and limit
                result_txs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                result_txs = result_txs[:limit]

            result = {"ok": True, "result": {"transactions": result_txs, "count": len(result_txs)}}

    except Exception as e:
        logger.error(f"Error fetching recent transactions: {e}")
        result = {"ok": False, "error": "Error fetching recent transactions"}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.get("/get_transaction")
@limiter.limit("8/second")
async def get_transaction(
    request: Request, tx_hash: str, verify: bool = False, pretty: bool = False
):
    # Validate transaction hash format
    if not _node.security.input_validator.validate_hex(tx_hash, min_length=64, max_length=64):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid transaction hash format")

    tx = await _node.db.get_nice_transaction(tx_hash)
    if tx is None:
        result = {"ok": False, "error": "Not found"}
    else:
        result = {"ok": True, "result": tx}
    return (
        Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
        if pretty
        else result
    )
