"""
Regenerate tests/fixtures/lockbox_deposit_logs.json: the logs QRDXLockbox (contracts/bridge/)
emits, from the committed build run in an EVM (the lockbox's CustodyAccepted at deployment, then a
250.5-unit deposit of a 6-decimal test token to a 0xPQ recipient), in eth_getLogs' shape. The
watcher's decoder is tested against it (tests/test_bridge.py).

    python tests/fixtures/make_lockbox_deposit_logs.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1]))


async def main() -> None:
    from test_evm_world import ALICE, Chain
    from test_lockbox_contract import CHAIN, _tx, deployed, deposit, logs_as_rpc

    from qrdx.bridge import lockbox as L
    from qrdx.database_sqlite import DatabaseSQLite

    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        chain = Chain(db)
        await chain.fund(ALICE, 10**22)
        token, lockbox = await deployed(chain)
        # The deployment's own log (CustodyAccepted), from a second lockbox the same way.
        art = L.load_artifact()
        custody = await _tx(chain, ALICE, None, L.deploy_data(art["bytecode"], "0x" + "c0" * 20, 8 * 86_400))
        r = await deposit(chain, token, lockbox, 250_500_000)
        logs = logs_as_rpc(custody, tx_hash="0x" + "22" * 32, block=2)
        logs += [x for x in logs_as_rpc(r, block=3) if x["topics"][0] == L.TOPIC_DEPOSIT]
        out = {"chain": CHAIN, "token": "0x" + token.hex(), "decimals": 6, "logs": logs}
        (HERE / "lockbox_deposit_logs.json").write_text(json.dumps(out, indent=1) + "\n")
        print(f"wrote {len(logs)} logs")
    finally:
        await db.close()
        for p in (path, path + "-wal", path + "-shm"):
            if os.path.exists(p):
                os.remove(p)


if __name__ == "__main__":
    asyncio.run(main())
