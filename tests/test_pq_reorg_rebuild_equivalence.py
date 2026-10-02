"""
Reorg safety for post-quantum accounts: the account-state REBUILD must reproduce
exactly what incremental forward application produced, for chains containing PQ
genesis allocations and PQ-signed transactions.

This is the gate on the account-id change. A node that never reorgs builds
``account_state`` forward, block by block; a node that reorgs CLEARS it and runs
``rebuild_account_state_from_chain`` (clear → reseed genesis → replay every
canonical block). If those two disagree by even one key, a reorged node diverges
from the network at equal tip — the exact failure class that has bitten this chain
repeatedly, and the reason account ids are *derived* rather than looked up in a
registry that a rebuild could leave stale.

The PQ-specific hazards this covers:
  * a genesis allocation written to a ``0xPQ`` display address must be reseeded
    under the SAME account id the forward path used;
  * a PQ-signed transaction must resolve to the same sender on replay as on first
    execution (derivation from the embedded key, so no registry to go stale);
  * both transaction families in one section must replay in the same order.

Companion to test_evm_reorg_rebuild_equivalence.py (traditional accounts only).
"""
import json
import os
import tempfile

from eth_account import Account as EthAccount

from qrdx.contracts.evm_block_apply import (
    produce_block_evm_section,
    rebuild_account_state_from_chain,
)
from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import generate_keypair
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.transactions.pq_tx import PQTransaction

WEI = 10 ** 18
RECIPIENT = bytes.fromhex("cd" * 20)


def _legacy_raw(i, nonce=0, value=1):
    """A validly-signed legacy tx from key i."""
    key = "0x" + f"{i:064x}"
    acct = EthAccount.from_key(key)
    signed = EthAccount.sign_transaction(
        {"nonce": nonce, "gasPrice": 10 ** 9, "gas": 21000, "to": acct.address,
         "value": value, "data": b"", "chainId": 1}, key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return "0x" + bytes(raw).hex(), to_account_id(acct.address)


def _pq_raw(priv, nonce=0, value=1):
    """A validly-signed type-0x51 PQ tx."""
    tx = PQTransaction(chain_id=1, nonce=nonce, gas_price=10 ** 9, gas_limit=500_000,
                       to=RECIPIENT, value=value, data=b"").sign(priv)
    return "0x" + tx.encode().hex()


def _executor(sm, credit):
    """
    Deterministic stand-in for real execution: sets the sender's balance to
    ``credit``. Identical on the forward and rebuild paths, so any root divergence
    is the rebuild ORCHESTRATION (genesis reseed, replay order, sender resolution),
    not execution itself.
    """
    async def execute_tx(raw_tx_hex, block_height, block_hash, block_timestamp):
        from qrdx.contracts.evm_mempool import parse_eth_raw_tx
        p = parse_eth_raw_tx(raw_tx_hex)
        acc = await sm.get_account(p["sender"])
        acc.balance = credit
        acc.nonce = int(p["nonce"]) + 1
        await sm.set_account(acc)
        return {"success": True, "tx_hash": p["tx_hash"], "sender": p["sender"],
                "nonce": p["nonce"], "created_address": None}
    return execute_tx


async def _add_block(db, height, evm_section=None, genesis_alloc=None):
    bh = f"{height:064x}"
    await db.add_block(block_hash=bh, block_height=height, block_content="",
                       validator_address="0xPQ" + "00" * 32,
                       timestamp=1_700_000_000 + height)
    for i, (recipient, amount) in enumerate(genesis_alloc or []):
        await db.add_transaction(
            tx_hash=f"alloc-{height}-{i}",
            tx_hex=json.dumps({"type": "genesis_allocation",
                               "recipient": recipient, "amount": str(amount)}),
            block_hash=bh)
    if evm_section:
        await db.add_block_evm_txs(bh, evm_section)
    return bh


async def test_rebuild_equals_forward_apply_with_pq_accounts():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        # Actors:
        #   trad_a  — traditional, sends legacy txs
        #   pq_send — post-quantum, sends PQ txs
        #   pq_only — post-quantum, GENESIS-ONLY (never sends; must survive the clear)
        priv_send, pub_send = generate_keypair()
        _priv_only, pub_only = generate_keypair()
        legacy_1, trad_a = _legacy_raw(201, nonce=0)
        legacy_2, _ = _legacy_raw(201, nonce=1)
        pq_1 = _pq_raw(priv_send, nonce=0)
        pq_2 = _pq_raw(priv_send, nonce=1)

        await _add_block(db, 0, genesis_alloc=[
            (trad_a, "500000"),
            (pub_send.to_address(), "250000"),   # funded by DISPLAY address
            (pub_only.to_address(), "777"),      # genesis-only PQ account
        ])
        # Mixed sections: both families interleaved, plus an empty section.
        await _add_block(db, 1, evm_section=[legacy_1, pq_1])
        await _add_block(db, 2, evm_section=[pq_2, legacy_2])
        await _add_block(db, 3, evm_section=[])

        CREDIT = 4242

        # ── Forward: seed genesis once, build each block incrementally, no clear.
        await db.seed_genesis_account_state()
        await db.connection.commit()
        sm_f = ContractStateManager(db)
        for h in range(4):
            section = await db.get_block_evm_txs(f"{h:064x}")
            if not section:
                continue
            await produce_block_evm_section(h, f"{h:064x}", 0, section, db, sm_f,
                                            _executor(sm_f, CREDIT))
        await db.connection.commit()
        forward_root = await db.get_account_state_root()
        forward_rows = dict(await _rows(db))

        # ── Rebuild: clear + reseed + replay every canonical block.
        sm_r = ContractStateManager(db)
        rebuild_root = await rebuild_account_state_from_chain(db, sm_r,
                                                             _executor(sm_r, CREDIT))

        assert rebuild_root == forward_root, (
            f"PQ account rebuild diverges from forward apply: "
            f"forward={forward_root[:16]} rebuild={rebuild_root[:16]}")
        assert dict(await _rows(db)) == forward_rows, "row-for-row state differs"

        # The genesis-only PQ account survived, keyed by its account id, readable
        # through its own 0xPQ address.
        assert await db.get_address_balance(pub_only.to_address()) == 777
        assert to_account_id(pub_only.to_address()) in forward_rows
    finally:
        await db.close()
        os.remove(path)


async def test_pq_sender_resolves_identically_on_replay():
    """
    A PQ transaction's sender is derived from its embedded key, so first execution
    and rebuild replay must agree with no registry consulted — this is what makes
    the rebuild stateless with respect to identity.
    """
    from qrdx.contracts.evm_mempool import parse_eth_raw_tx

    priv, pub = generate_keypair()
    raw = _pq_raw(priv, nonce=5)
    senders = {parse_eth_raw_tx(raw)["sender"] for _ in range(10)}
    assert senders == {pub.to_account_id()}


async def test_genesis_reseed_is_idempotent_for_pq_allocations():
    """
    The rebuild reseeds genesis before replaying. Running it twice must not double
    a PQ allocation — seeding sets absolute balances, not deltas.
    """
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        _priv, pub = generate_keypair()
        await _add_block(db, 0, genesis_alloc=[(pub.to_address(), "1000")])
        await db.connection.commit()

        await db.seed_genesis_account_state()
        await db.connection.commit()
        first = await db.get_account_state_root()

        await db.seed_genesis_account_state()
        await db.connection.commit()
        assert await db.get_account_state_root() == first
        assert await db.get_address_balance(pub.to_address()) == 1000
    finally:
        await db.close()
        os.remove(path)


async def _rows(db):
    cur = await db.connection.execute(
        "SELECT address, balance, nonce FROM account_state ORDER BY address")
    return {r[0]: (r[1], r[2]) for r in await cur.fetchall()}
