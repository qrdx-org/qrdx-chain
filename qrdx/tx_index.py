"""
The transaction index — what a wallet did and what the chain did recently, in one place.

Every canonical block's transactions are indexed, whatever kind they are:

* ``genesis`` / ``transfer`` / ``coinbase`` — the block's legacy transactions;
* ``exchange`` — its exchange operations (token transfers and mints, swaps, orders, pools,
  perps, staking, …), with the outcome, the fee and what the operation did (from the
  exchange journal's receipt);
* ``evm`` — its EVM transactions (QRDX transfers, contract calls and deployments), with the
  receipt's status and fee and every ERC-20 ``Transfer`` the transaction emitted (native
  tokens included).

Each transaction is filed under every account it touched, with that account's roles: the
sender; recipients, spenders, the account a freeze names; the makers whose orders it filled;
the parties of each token ``Transfer``. Accounts are canonical account ids
(qrdx/crypto/account_id.py), so a wallet finds the same history by its ``0x`` or its ``0xPQ``
address.

Derived, node-local, never hashed. The indexer follows the tip from a background task while
holding the block-processing lock (so it never reads a block mid-application), a few hundred
blocks per pass; ``remove_blocks`` cuts the index back with the chain, and each pass re-checks
the indexed block hashes near the tip so a reorg that bypassed it re-indexes too.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

INDEX_BATCH = 200            # blocks per pass under the lock
REORG_CHECK_DEPTH = 64       # indexed block hashes re-checked against the chain each pass
DETAIL_LIMIT = 4000          # bytes of JSON detail kept per transaction
WEI = Decimal(10) ** 18

# Exchange-operation parameters that name an account the operation touches.
ACCOUNT_PARAMS = ("to", "from", "spender", "account", "new_authority", "recipient", "owner",
                  "operator", "delegate", "new_owner", "beneficiary")


def account_key(address: Any) -> Optional[str]:
    """The key an address's history is filed under: its canonical account id."""
    if not isinstance(address, str) or not address.strip():
        return None
    from .crypto.account_id import to_account_id
    try:
        return to_account_id(address.strip())
    except (ValueError, TypeError):
        return address.strip().lower()


def _timestamp(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return int(value.timestamp())
    try:
        return int(float(value))
    except (TypeError, ValueError):
        pass
    try:
        return int(datetime.fromisoformat(str(value)).timestamp())
    except ValueError:
        return None


def _detail(value: Dict[str, Any]) -> Optional[str]:
    if not value:
        return None
    text = json.dumps(value, sort_keys=True, default=str)
    if len(text) > DETAIL_LIMIT:
        text = json.dumps({"truncated": True, **{k: value[k] for k in list(value)[:4]}},
                          sort_keys=True, default=str)[:DETAIL_LIMIT]
    return text


class _BlockIndex:
    def __init__(self, height: int, block_hash: str, timestamp: Optional[int]):
        self.height, self.block_hash, self.timestamp = height, block_hash, timestamp
        self.rows: List[Dict[str, Any]] = []
        self.parts: Dict[Tuple[str, int], Set[str]] = {}

    def add(self, kind: str, tx_hash: str, **fields) -> int:
        pos = len(self.rows)
        self.rows.append({"position": pos, "tx_hash": str(tx_hash).lower(), "kind": kind,
                          "timestamp": self.timestamp, **fields})
        return pos

    def touch(self, address: Any, pos: int, role: str) -> None:
        key = account_key(address)
        if key:
            self.parts.setdefault((key, pos), set()).add(role)

    def participants(self) -> List[Tuple[str, int, str]]:
        return [(a, pos, ",".join(sorted(roles))) for (a, pos), roles in sorted(self.parts.items())]


# ── what each kind of transaction contributes ─────────────────────────────

async def _legacy(db, blk: _BlockIndex) -> None:
    cursor = await db.connection.execute(
        "SELECT tx_hash, tx_hex FROM transactions WHERE block_hash = ? ORDER BY rowid",
        (blk.block_hash,))
    for tx_hash, tx_hex in await cursor.fetchall():
        try:
            doc = json.loads(tx_hex)
        except (TypeError, ValueError):
            doc = None
        if isinstance(doc, dict):
            if doc.get("type") == "genesis_allocation":
                pos = blk.add("genesis", tx_hash, op="GENESIS_ALLOCATION",
                              target=doc.get("recipient"), asset="QRDX",
                              amount=str(doc.get("amount", "0")), status=1)
                blk.touch(doc.get("recipient"), pos, "recipient")
            continue
        try:
            from .transactions import CoinbaseTransaction, Transaction
            tx = await Transaction.from_hex(tx_hex, check_signatures=False)
        except Exception:
            blk.add("transfer", tx_hash, status=1)
            continue
        outputs = [(o.address, Decimal(str(o.amount))) for o in getattr(tx, "outputs", [])]
        kind = "coinbase" if isinstance(tx, CoinbaseTransaction) else "transfer"
        senders = []
        for inp in getattr(tx, "inputs", []) or []:
            try:
                senders.append(await inp.get_address())
            except Exception:
                pass
        pos = blk.add(kind, tx_hash, op=kind.upper(), sender=senders[0] if senders else None,
                      target=outputs[0][0] if outputs else None, asset="QRDX",
                      amount=str(sum((a for _, a in outputs), Decimal(0))), status=1,
                      detail=_detail({"outputs": [[a, str(v)] for a, v in outputs]}))
        for s in senders:
            blk.touch(s, pos, "sender")
        for address, _ in outputs:
            if address not in senders:
                blk.touch(address, pos, "recipient")


def _exchange_summary(op: str, p: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """What the row shows at a glance: the operation's object and amount."""
    if op.startswith("TOKEN_"):
        return {"target": p.get("to") or p.get("spender") or p.get("account"),
                "asset": p.get("token_address") or data.get("token_address"),
                "amount": p.get("amount") or p.get("total_supply") or p.get("initial_supply")}
    if op == "SWAP":
        return {"target": p.get("token_out"), "asset": p.get("token_in"),
                "amount": p.get("amount_in")}
    if op in ("PLACE_ORDER", "CANCEL_ORDER"):
        return {"target": p.get("pair"), "amount": p.get("amount")}
    if op in ("CREATE_POOL", "ADD_LIQUIDITY", "REMOVE_LIQUIDITY", "REMOVE_POOL"):
        return {"target": p.get("pool_id") or data.get("pool_id")
                or (f"{p.get('token0')}:{p.get('token1')}" if p.get("token0") else None),
                "amount": p.get("amount") or p.get("stake_amount")}
    if op.startswith("PERP_") or op.startswith("VAULT_"):
        return {"target": p.get("market_id"), "amount": p.get("size") or p.get("amount")
                or p.get("shares")}
    if op.startswith("STAKE_"):
        return {"amount": p.get("stake_amount") or p.get("amount"), "asset": "QRDX"}
    if op.startswith("NFT_"):
        return {"target": p.get("to") or p.get("spender") or p.get("operator"),
                "asset": p.get("collection") or data.get("collection"),
                "amount": data.get("token_id") or p.get("token_id")}
    return {}


async def _exchange(db, blk: _BlockIndex, journal) -> None:
    section = await db.get_block_exchange_txs(blk.block_hash)
    if not section:
        return
    from .exchange.block_processor import decode_exchange_txs
    for tx in decode_exchange_txs(section):
        tx_hash = tx.tx_hash()
        op = tx.op_type.name
        p = dict(tx.params or {})
        receipt = journal.receipt(tx_hash) if journal is not None else None
        data = (receipt or {}).get("data") or {}
        summary = _exchange_summary(op, p, data)
        detail = {"nonce": tx.nonce, "params": p}
        for k in ("order_id", "token_address", "pool_id", "amount_out", "filled", "position_id",
                  "collection", "token_id", "fee", "memo"):
            if k in data:
                detail[k] = data[k]
        fills = data.get("fills") or []
        if fills:
            detail["fills"] = len(fills)
        pos = blk.add(
            "exchange", tx_hash, op=op, sender=tx.sender,
            target=None if summary.get("target") is None else str(summary["target"]),
            asset=None if summary.get("asset") is None else str(summary["asset"]),
            amount=None if summary.get("amount") is None else str(summary["amount"]),
            status=None if receipt is None else int(bool(receipt.get("success"))),
            fee=None if receipt is None else receipt.get("fee"),
            error=(receipt or {}).get("error") or None, detail=_detail(detail))
        blk.touch(tx.sender, pos, "sender")
        for key in ACCOUNT_PARAMS:
            if isinstance(p.get(key), str) and p[key].startswith(("0x", "0X")):
                blk.touch(p[key], pos, key)
        for fill in fills:
            maker = fill.get("maker")
            if maker and account_key(maker) != account_key(tx.sender):
                blk.touch(maker, pos, "maker")


async def _evm(db, blk: _BlockIndex, final: bool) -> bool:
    """False if a transaction's receipt is not written yet (the block is still applying) —
    only possible at the tip; the next pass picks it up."""
    raws = await db.get_block_evm_txs(blk.block_hash)
    if not raws:
        return True
    from eth_hash.auto import keccak
    from .contracts.native_token_evm import TRANSFER_TOPIC
    topic = "0x%064x" % TRANSFER_TOPIC
    for raw in raws:
        raw_hex = raw if isinstance(raw, str) else str(raw)
        tx_hash = "0x" + keccak(bytes.fromhex(raw_hex.removeprefix("0x"))).hex()
        cursor = await db.connection.execute(
            "SELECT from_address, to_address, value, gas_used, gas_price, contract_address, "
            "status, error_message, nonce FROM contract_transactions WHERE tx_hash = ?",
            (tx_hash,))
        rec = await cursor.fetchone()
        if rec is None:
            if not final:
                return False
            try:
                from .contracts.evm_mempool import parse_eth_raw_tx
                parsed = parse_eth_raw_tx(raw_hex)
            except Exception:
                blk.add("evm", tx_hash)
                continue
            frm, to, value, nonce = parsed["sender"], parsed["to"], parsed["value"], parsed["nonce"]
            rec = (frm, to, str(value), None, None, None, None, None, nonce)
        frm, to, value, gas_used, gas_price, created, status, error, nonce = tuple(rec)
        logs = await (await db.connection.execute(
            "SELECT contract_address, topic1, topic2, topic3, data FROM contract_logs "
            "WHERE tx_hash = ? AND topic0 = ? ORDER BY log_index", (tx_hash, topic))).fetchall()
        transfers = []
        for token, t1, t2, t3, data in logs:
            if t1 is None or t2 is None:
                continue
            raw_value = bytes(data or b"") if not isinstance(data, str) else bytes.fromhex(
                data.removeprefix("0x"))
            move = {"token": token, "from": "0x" + str(t1)[-40:], "to": "0x" + str(t2)[-40:]}
            if t3 is not None:                       # ERC-721: the token id is indexed
                move["token_id"] = str(int(str(t3), 16))
            else:
                move["value"] = str(int.from_bytes(raw_value[:32], "big")) if raw_value else "0"
            transfers.append(move)
        try:
            amount = Decimal(int(value or 0)) / WEI
        except (TypeError, ValueError):
            amount = Decimal(0)
        fee = (str(Decimal(int(gas_used) * int(gas_price)) / WEI)
               if gas_used is not None and gas_price not in (None, "") else None)
        op = "CREATE" if not to else ("TOKEN_TRANSFER" if transfers and amount == 0 else
                                      "TRANSFER" if amount > 0 else "CALL")
        asset, target = "QRDX", to or created
        if op == "TOKEN_TRANSFER" and len(transfers) == 1:
            asset, target, amount = transfers[0]["token"], transfers[0]["to"], None
            if "token_id" in transfers[0]:
                op, amount = "NFT_TRANSFER", transfers[0]["token_id"]
        pos = blk.add("evm", tx_hash, op=op, sender=frm, target=target, asset=asset,
                      amount=None if amount is None else str(amount),
                      status=None if status is None else int(status), fee=fee,
                      error=error or None,
                      detail=_detail({"nonce": nonce, "gas_used": gas_used,
                                      "gas_price": None if gas_price is None else str(gas_price),
                                      "contract_address": created,
                                      "token_transfers": transfers}))
        blk.touch(frm, pos, "sender")
        if to:
            blk.touch(to, pos, "to")
        if created:
            blk.touch(created, pos, "created")
        for t in transfers:
            blk.touch(t["from"], pos, "token_from")
            blk.touch(t["to"], pos, "token_to")
    return True


async def index_block(db, height: int, journal=None, *, final: bool = True) -> bool:
    """Index (or re-index) the canonical block at ``height``. False if the block is not there
    or not fully applied yet."""
    block = await db.get_block_by_id(int(height))
    if block is None:
        return False
    blk = _BlockIndex(int(height), block["block_hash"], _timestamp(block.get("timestamp")))
    await _legacy(db, blk)
    await _exchange(db, blk, journal)
    if not await _evm(db, blk, final):
        return False
    await db.tx_index_write_block(blk.height, blk.block_hash, blk.rows, blk.participants())
    return True


async def sync_index(db, journal=None, *, max_blocks: int = INDEX_BATCH) -> int:
    """Bring the index up to the chain's tip (at most ``max_blocks`` blocks); returns how many
    blocks were indexed. A changed block hash at an indexed height cuts the index back there."""
    head = await db.tx_index_head()
    if head >= 0:
        for h, indexed_hash in await db.tx_index_blocks_from(max(0, head - REORG_CHECK_DEPTH)):
            canon = await db.get_block_by_id(h)
            if canon is None or canon["block_hash"] != indexed_hash:
                await db.tx_index_cut(h)
                head = h - 1
                break
    tip = int(await db.get_next_block_id()) - 1
    done = 0
    for h in range(head + 1, min(tip, head + max_blocks) + 1):
        if not await index_block(db, h, journal, final=h < tip):
            break
        done += 1
    return done


async def tx_index_poller(db_getter, lock: Optional[asyncio.Lock] = None, *,
                          get_journal=None, interval: float = 1.0,
                          _max_iterations: Optional[int] = None) -> None:
    """Follow the tip: each pass indexes what is new, under ``lock`` so a block is never read
    mid-application. Never raises (the index is a convenience; consensus does not wait on it)."""
    iterations = 0
    while True:
        try:
            db = db_getter()
            if db is not None and hasattr(db, "tx_index_head"):
                journal = get_journal() if get_journal is not None else None
                if lock is not None:
                    async with lock:
                        done = await sync_index(db, journal)
                else:
                    done = await sync_index(db, journal)
                if done >= INDEX_BATCH:
                    iterations += 1
                    if _max_iterations is not None and iterations >= _max_iterations:
                        break
                    await asyncio.sleep(0)          # catching up: yield, then go again
                    continue
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug("tx index pass failed: %s", e)
        iterations += 1
        if _max_iterations is not None and iterations >= _max_iterations:
            break
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break


# ── reading it ─────────────────────────────────────────────────────────────

def present(row: Dict[str, Any]) -> Dict[str, Any]:
    """An index row as the API returns it (detail decoded, a status word, a page cursor)."""
    out = dict(row)
    if out.get("detail"):
        try:
            out["detail"] = json.loads(out["detail"])
        except ValueError:
            pass
    status = out.get("status")
    out["status"] = {1: "success", 0: "failed"}.get(status, "unknown") if status is not None \
        else "unknown"
    if "roles" in out:
        out["roles"] = out["roles"].split(",") if out["roles"] else []
    out["cursor"] = f"{out['block_height']}:{out['position']}"
    return out


def parse_cursor(cursor: Optional[str]) -> Optional[Tuple[int, int]]:
    if not cursor:
        return None
    h, _, pos = str(cursor).partition(":")
    return int(h), int(pos or 0)


async def history(db, address: str, *, limit: int = 50, cursor: Optional[str] = None,
                  kinds: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """An address's transactions, newest first, a page at a time: pass the returned
    ``next_cursor`` to continue."""
    limit = max(1, min(int(limit), 500))
    account = account_key(address)
    rows = await db.get_account_history(account, limit, parse_cursor(cursor),
                                        list(kinds) if kinds else None)
    items = [present(r) for r in rows]
    return {"address": address, "account": account, "transactions": items,
            "next_cursor": items[-1]["cursor"] if len(items) == limit else None,
            "indexed_height": await db.tx_index_head()}


async def recent(db, *, limit: int = 50, cursor: Optional[str] = None,
                 kinds: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """The chain's most recent transactions, every kind, newest first."""
    limit = max(1, min(int(limit), 500))
    rows = await db.get_indexed_transactions(limit, parse_cursor(cursor),
                                             list(kinds) if kinds else None)
    items = [present(r) for r in rows]
    return {"transactions": items,
            "next_cursor": items[-1]["cursor"] if len(items) == limit else None,
            "indexed_height": await db.tx_index_head()}


async def lookup(db, tx_hash: str) -> Optional[Dict[str, Any]]:
    found = await db.get_indexed_transaction(tx_hash)
    if not found:
        return None
    row = found[-1]
    out = present(row)
    out["accounts"] = {a: roles.split(",") for a, roles in row["accounts"].items()}
    return out
