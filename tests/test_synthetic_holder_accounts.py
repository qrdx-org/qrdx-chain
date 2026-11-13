"""
The protocol's own internal holders must be keyable by the unified ledger.

An AMM pool's reserves and a CLOB book's resting-order escrow are held under
deterministic synthetic addresses — ``0xPOOL…`` and ``0xCLOB…`` (see
``ExchangeStateManager.pool_holder_address`` / ``orderbook_escrow_address``). They are
``0x``-prefixed but NOT hex, and no key can sign for them: the protocol owns them.

Regression test for a real break introduced when the token ledger began keying holders
by canonical account id: ``to_account_id`` rejected these forms, so
``apply_token_balance_delta`` raised, and ``flush_token_balance_deltas`` — which catches
per-delta exceptions and logs a warning — silently DROPPED the credit while applying the
paired debit. Every liquidity add and every resting CLOB order would have burned the
tokens it moved into the pool or escrow, with only a log line to show for it.

Token conservation is the assertion that catches this. "The debit happened" does not.
"""
from decimal import Decimal

import pytest

from qrdx.crypto.account_id import (
    SYNTHETIC_HOLDER_PREFIXES,
    is_account_id,
    to_account_id,
)
from qrdx.exchange.state_manager import ExchangeStateManager

from pq_addrs import pq

TOKEN = "0x" + "77" * 20


def _pool(pool_id="pool-1"):
    return ExchangeStateManager.pool_holder_address(pool_id)


def _escrow(pair="A:B"):
    return ExchangeStateManager.orderbook_escrow_address(pair)


# ── The forms the exchange actually produces must resolve ──────────────────

def test_pool_and_escrow_holders_resolve_to_account_ids():
    for addr in (_pool(), _escrow()):
        aid = to_account_id(addr)
        assert is_account_id(aid), f"{addr} did not resolve to an account id"


def test_every_declared_prefix_is_one_the_exchange_produces():
    """Keeps the declared list honest against the real derivations."""
    produced = {_pool()[:6].upper(), _escrow()[:6].upper()}
    declared = {p.upper() for p in SYNTHETIC_HOLDER_PREFIXES}
    assert produced <= declared, f"exchange produces un-declared prefixes: {produced - declared}"


def test_distinct_holders_get_distinct_account_ids():
    ids = {
        to_account_id(_pool("pool-1")),
        to_account_id(_pool("pool-2")),
        to_account_id(_escrow("A:B")),
        to_account_id(_escrow("C:D")),
    }
    assert len(ids) == 4, "synthetic holders collided"


def test_a_pool_and_a_book_cannot_collide_on_the_same_body():
    """
    Domain separation puts the prefix inside the hash tag, so two different kinds of
    internal holder that happen to share a body are still different accounts.
    """
    body = "ab" * 18
    assert to_account_id("0xPOOL" + body) != to_account_id("0xCLOB" + body)


def test_resolution_is_idempotent_and_case_stable():
    addr = _pool()
    aid = to_account_id(addr)
    assert to_account_id(aid) == aid
    assert to_account_id(addr.upper().replace("0X", "0x", 1)) == aid


# ── Strictness must survive: this is not a permissive fallback ─────────────

@pytest.mark.parametrize("bad", [
    "0xPOOL",                    # no body
    "0xPOOLzz!!",                # wrong length
    "0xPOOL" + "ab" * 10,        # too short
    "0xPOOL" + "ab" * 24,        # too long
    "0xPOOL" + "zz" * 18,        # right length, not hex
    "0xCLOB" + "gg" * 18,        # right length, not hex
    "0xNOPE" + "ab" * 18,        # not a declared prefix
])
def test_malformed_synthetic_holders_are_still_rejected(bad):
    """
    The synthetic prefixes are an explicit allow-list, NOT a "anything non-hex gets
    hashed" fallback. A fallback would make every malformed user-supplied
    TOKEN_TRANSFER recipient silently keyable, defeating the check that stops an
    unspendable recipient from burning tokens.
    """
    with pytest.raises(ValueError):
        to_account_id(bad)


# ── Conservation through the real flush ───────────────────────────────────

async def test_liquidity_and_escrow_moves_conserve_tokens():
    import os
    import tempfile

    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.exchange.block_processor import flush_token_balance_deltas

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        provider = pq("liquidity-provider")
        pool, escrow = _pool(), _escrow()

        await db.apply_token_balance_delta(TOKEN, provider, Decimal("5000"))
        await db.connection.commit()

        mgr = ExchangeStateManager()
        mgr.begin_block(1, 0.0)
        # An AMM liquidity add and a resting CLOB order, as the settlement paths record them.
        mgr._record_token_delta(provider, TOKEN, Decimal("-1000"))
        mgr._record_token_delta(pool, TOKEN, Decimal("1000"))
        mgr._record_token_delta(provider, TOKEN, Decimal("-500"))
        mgr._record_token_delta(escrow, TOKEN, Decimal("500"))
        mgr.commit_block()

        await flush_token_balance_deltas(db, mgr)
        await db.connection.commit()

        held = await db.get_token_balance(TOKEN, provider)
        reserves = await db.get_token_balance(TOKEN, pool)
        escrowed = await db.get_token_balance(TOKEN, escrow)

        assert reserves == Decimal("1000"), "pool reserves were dropped"
        assert escrowed == Decimal("500"), "order escrow was dropped"
        assert held + reserves + escrowed == Decimal("5000"), "tokens were destroyed"
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


async def test_pool_reserves_are_readable_through_the_account_id():
    """Reserves are an ordinary account, so an ERC-20 style view of them works."""
    import os
    import tempfile

    from qrdx.database_sqlite import DatabaseSQLite

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        pool = _pool()
        await db.apply_token_balance_delta(TOKEN, pool, Decimal("1234"))
        await db.connection.commit()
        assert await db.get_token_balance(TOKEN, pool) == Decimal("1234")
        assert await db.get_token_balance(TOKEN, to_account_id(pool)) == Decimal("1234")
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


def test_holder_addresses_are_recognised_for_read_only_queries():
    """/get_address_info accepts these (a holder's balance is public state) even though the
    transaction address pattern rightly refuses them."""
    from qrdx.constants import VALID_ADDRESS_PATTERN
    from qrdx.crypto.account_id import is_synthetic_holder
    perps = ExchangeStateManager.perps_holder_address()
    for addr in (_pool(), _escrow(), perps):
        assert is_synthetic_holder(addr) and not VALID_ADDRESS_PATTERN.match(addr)
    for bad in (perps[:-1], perps + "0", "0xPERP" + "zz" * 18, "0x" + "11" * 20, pq(1), None):
        assert not is_synthetic_holder(bad)
