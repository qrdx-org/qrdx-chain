"""
The proposer selects from the same validator set importers check eligibility against
(qrdx/validator/node_integration.py ValidatorNode._refresh_validator_set).

The proposer's set used to be built once, at startup. The validators table changes — rewards and
penalties at each finalized epoch, validators joining and leaving — so after the integration
testnet added a validator, proposers and importers disagreed on whose slot it was: blocks were
refused and the chain forked. The set is now rebuilt from the table every slot, the way
block_verification.verify_proposer_eligibility builds it.
"""
import os
import tempfile
from decimal import Decimal
from types import SimpleNamespace

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import block_verification as BV
from qrdx.validator.node_integration import ValidatorNode
from qrdx.validator.selection import ValidatorSelector

ADDRS = [f"0xPQ{i:064x}" for i in range(1, 5)]


async def _expected(db, slot):
    rows = await db.get_validators()
    validators = [
        (r["address"], Decimal(str(r.get("effective_stake") or r.get("stake") or 0)))
        for r in rows
        if str(r.get("status", "active")).upper() in ("ACTIVE", "PENDING", "EXITING")
    ]
    return BV.expected_proposer_for_slot(slot, validators)


async def test_the_proposer_follows_the_table_the_importers_check_against():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    try:
        for a in ADDRS[:3]:
            await db.connection.execute(
                "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
                "activation_epoch) VALUES (?, 'pk', '100000', '100000', 'active', 0)", (a,))
        await db.connection.commit()
        node = ValidatorNode(db, "unused")
        node.wallet = SimpleNamespace(address=ADDRS[0], public_key=b"pk")
        node.manager = SimpleNamespace(_validator_set=None)
        selector = ValidatorSelector()

        async def agree():
            await node._refresh_validator_set()
            mine = node.manager._validator_set.validators
            for slot in range(200):
                chosen = selector.select_proposer(slot, mine, BV.PROPOSER_RANDAO_MIX)
                assert chosen.address == await _expected(db, slot), slot

        await agree()
        # A finalized epoch's rewards move the stakes; a validator joins; one starts exiting;
        # one is slashed out.
        await db.connection.execute("UPDATE validators SET effective_stake = '100045.25' "
                                    "WHERE address = ?", (ADDRS[1],))
        await db.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
            "activation_epoch) VALUES (?, 'pk', '100000', '100000', 'pending', 11)", (ADDRS[3],))
        await db.connection.execute("UPDATE validators SET status = 'exiting' WHERE address = ?",
                                    (ADDRS[2],))
        await db.connection.commit()
        await agree()
        await db.connection.execute("UPDATE validators SET status = 'slashed' WHERE address = ?",
                                    (ADDRS[1],))
        await db.connection.commit()
        await agree()
    finally:
        await db.connection.close()
        os.remove(path)
