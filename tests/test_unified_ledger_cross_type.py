"""
Ledger unification, end to end: can value move between a traditional ``0x``
account and a post-quantum ``0xPQ`` account, in both directions?

This is the question the whole account-id design exists to answer "yes" to. Before
it, ``account_state`` held balances for both address families but only 20-byte
accounts could be *named* by the EVM, so a PQ account could not send a native
transfer, could not be an RLP ``to``, and could not be paid by a contract.

The tests are grouped as:
  1. **One row** — a PQ address and its account id are the same ledger entry, not
     two entries kept in sync.
  2. **Real EVM** — the actual QRDXEVMExecutor moves value in both directions with
     no PQ-specific code path, which is the point of a 20-byte account id.
  3. **Whole pipeline** — a PQ-signed transaction authenticates, admits, and
     resolves to the same account the ledger funded.
"""
import os
import json
import tempfile
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from qrdx.contracts.evm_mempool import EVMMempool, parse_eth_raw_tx
from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import generate_keypair
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.transactions.pq_tx import PQTransaction

from pq_addrs import pq
from qrdx.constants import CHAIN_ID  # the network's chain id (chain spec)

WEI = 10 ** 18
TRADITIONAL = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"


async def _db():
    return await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))


async def _row_count(db, address):
    cur = await db.connection.execute(
        "SELECT COUNT(*) FROM account_state WHERE LOWER(address) = LOWER(?)",
        (to_account_id(address),))
    return (await cur.fetchone())[0]


async def _all_rows(db):
    cur = await db.connection.execute("SELECT address, balance FROM account_state")
    return {r[0]: int(r[1]) for r in await cur.fetchall()}


# ══════════════════════════════════════════════════════════════════════════
#  1. ONE ROW — not two representations kept in sync
# ══════════════════════════════════════════════════════════════════════════

async def test_pq_address_and_its_account_id_are_one_balance():
    """
    Credit through the ``0xPQ`` display address, read back through the 20-byte
    account id (and vice versa): one balance, one row. This is the property that
    makes a registry and a reconciliation path unnecessary.
    """
    db = await _db()
    try:
        holder = pq("holder")
        account_id = to_account_id(holder)

        await db.apply_account_balance_delta(holder, Decimal("100"))
        await db.connection.commit()

        assert await db.get_address_balance(holder) == Decimal("100")
        assert await db.get_address_balance(account_id) == Decimal("100")
        assert await _row_count(db, holder) == 1, "PQ credit created more than one row"

        # Debit through the OTHER form — it must hit the same balance.
        await db.apply_account_balance_delta(account_id, Decimal("-40"))
        await db.connection.commit()
        assert await db.get_address_balance(holder) == Decimal("60")
        assert len(await _all_rows(db)) == 1
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


async def test_genesis_pq_allocation_is_keyed_by_account_id():
    """
    Genesis funding of a PQ address must land on the account id, or the EVM could
    never see those funds — the original reason a PQ account was second-class.
    """
    db = await _db()
    try:
        holder = pq("genesis-holder")
        await db.add_block(block_hash="00" * 32, block_height=0, block_content="",
                           validator_address=pq("validator"), timestamp=1_700_000_000)
        await db.add_transaction(
            tx_hash="genesis-pq-1", block_hash="00" * 32,
            tx_hex=json.dumps({"type": "genesis_allocation",
                               "recipient": holder, "amount": "500000"}))
        await db.connection.commit()

        seeded = await db.seed_genesis_account_state()
        await db.connection.commit()
        assert seeded == 1

        rows = await _all_rows(db)
        assert list(rows) == [to_account_id(holder)], (
            f"genesis row not keyed by account id: {list(rows)}")
        assert await db.get_address_balance(holder) == Decimal("500000")
        assert await db.get_address_balance(to_account_id(holder)) == Decimal("500000")
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


async def test_token_ledger_shares_the_same_holder_key():
    """A PQ trader's QRC-20 balance and an ERC-20 view of it cannot drift apart."""
    db = await _db()
    try:
        holder = pq("trader")
        token = "0x" + "77" * 20
        await db.apply_token_balance_delta(token, holder, Decimal("1000"))
        await db.connection.commit()

        assert await db.get_token_balance(token, holder) == Decimal("1000")
        assert await db.get_token_balance(token, to_account_id(holder)) == Decimal("1000")

        cur = await db.connection.execute(
            "SELECT COUNT(*) FROM token_balances WHERE token_address = ?", (token,))
        assert (await cur.fetchone())[0] == 1
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


async def test_mixed_spellings_cannot_split_an_account_into_two_rows():
    """
    ``account_state.address`` is a PRIMARY KEY with exact matching, so before
    canonicalization a checksummed write and a lowercase write were two rows —
    two balances for one account, and a state root that depended on spelling.
    """
    db = await _db()
    try:
        for spelling in (TRADITIONAL, TRADITIONAL.lower(), TRADITIONAL.upper().replace("0X", "0x", 1)):
            await db.apply_account_balance_delta(spelling, Decimal("10"))
        await db.connection.commit()
        rows = await _all_rows(db)
        assert len(rows) == 1, f"spelling variants split the account: {rows}"
        assert await db.get_address_balance(TRADITIONAL) == Decimal("30")
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


# ══════════════════════════════════════════════════════════════════════════
#  2. REAL EVM — both directions, no PQ-specific code path
# ══════════════════════════════════════════════════════════════════════════

def _evm():
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
    sm = ContractStateManager(MagicMock())
    return sm, QRDXEVMExecutor(sm)


def test_pq_account_sends_native_value_to_a_traditional_account():
    """
    PQ → 0x through the real EVM. The executor is handed the PQ account's 20-byte
    id and never learns that a Dilithium key is behind it — which is exactly why
    this works with zero EVM changes.
    """
    sm, evm = _evm()
    _priv, pub = generate_keypair()
    sender_id = pub.to_account_id()
    sender = bytes.fromhex(sender_id[2:])
    recipient = bytes.fromhex(to_account_id(TRADITIONAL)[2:])

    sm.set_balance_sync(sender_id, 100 * WEI)
    result = evm.execute(sender=sender, to=recipient, value=5 * WEI,
                         data=b"", gas=100_000, gas_price=1)

    assert result.success, result.error
    assert sm.get_balance_sync(to_account_id(TRADITIONAL)) == 5 * WEI
    # Sender paid the value plus gas.
    assert sm.get_balance_sync(sender_id) <= 95 * WEI
    # Readable through the human-facing PQ address too — one account.
    assert sm.get_balance_sync(pub.to_address()) == sm.get_balance_sync(sender_id)


def test_traditional_account_sends_native_value_to_a_pq_account():
    """
    0x → PQ through the real EVM: the direction that was previously
    *unrepresentable*, because an RLP ``to`` field is 20 bytes and a 0xPQ address
    is 32. Naming the PQ account by its account id is what makes it expressible.
    """
    sm, evm = _evm()
    _priv, pub = generate_keypair()
    recipient_id = pub.to_account_id()

    sender = bytes.fromhex(to_account_id(TRADITIONAL)[2:])
    sm.set_balance_sync(TRADITIONAL, 100 * WEI)

    result = evm.execute(sender=sender, to=bytes.fromhex(recipient_id[2:]),
                         value=7 * WEI, data=b"", gas=100_000, gas_price=1)

    assert result.success, result.error
    # The PQ holder sees the funds under their OWN address — the user-visible claim.
    assert sm.get_balance_sync(pub.to_address()) == 7 * WEI
    assert sm.get_balance_sync(recipient_id) == 7 * WEI


def test_value_round_trips_between_the_two_account_families():
    """0x → PQ → 0x: conservation across a full round trip."""
    sm, evm = _evm()
    _priv, pub = generate_keypair()
    pq_id = pub.to_account_id()
    trad_id = to_account_id(TRADITIONAL)

    sm.set_balance_sync(trad_id, 50 * WEI)
    out = evm.execute(sender=bytes.fromhex(trad_id[2:]), to=bytes.fromhex(pq_id[2:]),
                      value=20 * WEI, data=b"", gas=100_000, gas_price=0)
    assert out.success, out.error
    assert sm.get_balance_sync(pub.to_address()) == 20 * WEI

    back = evm.execute(sender=bytes.fromhex(pq_id[2:]), to=bytes.fromhex(trad_id[2:]),
                       value=8 * WEI, data=b"", gas=100_000, gas_price=0)
    assert back.success, back.error
    assert sm.get_balance_sync(pub.to_address()) == 12 * WEI
    assert sm.get_balance_sync(TRADITIONAL) == 38 * WEI
    # Zero gas price ⇒ nothing burned ⇒ supply conserved exactly.
    assert sm.get_balance_sync(trad_id) + sm.get_balance_sync(pq_id) == 50 * WEI


# ══════════════════════════════════════════════════════════════════════════
#  3. WHOLE PIPELINE — funded ledger ↔ authenticated transaction
# ══════════════════════════════════════════════════════════════════════════

async def test_pq_transaction_sender_matches_the_funded_ledger_row():
    """
    The join that makes a PQ transfer actually spendable: the account the ledger
    funded (from a ``0xPQ`` genesis allocation) and the sender the parser derives
    from the signed transaction must be the SAME key.
    """
    db = await _db()
    try:
        priv, pub = generate_keypair()
        await db.apply_account_balance_delta(pub.to_address(), Decimal("1000"))
        await db.connection.commit()

        tx = PQTransaction(chain_id=CHAIN_ID, nonce=0, gas_price=10 ** 9, gas_limit=500_000,
                           to=bytes.fromhex(to_account_id(TRADITIONAL)[2:]),
                           value=3 * WEI, data=b"").sign(priv)
        parsed = parse_eth_raw_tx("0x" + tx.encode().hex())

        assert parsed["sender"] == pub.to_account_id()
        assert await db.get_address_balance(parsed["sender"]) == Decimal("1000")
        # ...and the funds are the same ones visible under the PQ display address.
        assert await db.get_address_balance(pub.to_address()) == Decimal("1000")
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


def test_both_transaction_families_share_one_mempool_and_nonce_space():
    """
    A PQ transaction is not a separate settlement domain: it queues in the same
    mempool, under the same nonce rules, and is selected for blocks alongside
    secp256k1 transactions.
    """
    from eth_account import Account as EthAccount

    mp = EVMMempool()
    priv, _pub = generate_keypair()
    pq_raw = "0x" + PQTransaction(
        chain_id=CHAIN_ID, nonce=0, gas_price=10 ** 9, gas_limit=500_000,
        to=bytes.fromhex("cd" * 20), value=1, data=b"").sign(priv).encode().hex()

    key = "0x" + "22" * 32
    acct = EthAccount.from_key(key)
    signed = EthAccount.sign_transaction(
        {"nonce": 0, "gasPrice": 10 ** 9, "gas": 21000, "to": acct.address,
         "value": 1, "data": b"", "chainId": CHAIN_ID}, key)
    legacy_raw = "0x" + bytes(
        getattr(signed, "raw_transaction", None) or signed.rawTransaction).hex()

    assert mp.admit(pq_raw)[0]
    assert mp.admit(legacy_raw)[0]
    assert mp.size() == 2
    assert len(mp.select_for_block()) == 2


def test_a_pq_account_can_be_a_contract_creation_sender():
    """
    Deployment closes the last gap in first-class status: contract addresses derive
    from ``rlp([sender, nonce])``, which needs a 20-byte sender — previously
    impossible for a PQ account (``bytes.fromhex('PQ…')`` simply threw).
    """
    from qrdx.crypto.contract import generate_contract_address

    _priv, pub = generate_keypair()
    addr = generate_contract_address(pub.to_account_id(), 0)
    assert addr.startswith("0x") and len(addr) == 42
    # Deterministic, and distinct per nonce.
    assert addr == generate_contract_address(pub.to_account_id(), 0)
    assert addr != generate_contract_address(pub.to_account_id(), 1)
