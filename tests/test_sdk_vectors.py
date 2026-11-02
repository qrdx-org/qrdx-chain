"""
The TypeScript SDK (sdk/typescript) against the node.

* Its vectors and op table (scripts/sdk/make_vectors.py) are what the node's code computes now: a
  change to a signed format, an op number or the predeploys fails here until they are made again.
* The smart-account values it computes (executeHash, the account's CREATE2 address) are the
  contract's own, run in the QRDX EVM from the predeployed factory.
* Where Node.js and the SDK's dependencies are installed: its own tests pass, and an exchange
  transaction and a type-0x51 transaction it signs verify here, with liboqs.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from eth_abi import decode, encode
from eth_utils import keccak
from test_evm_world import ALICE, chain  # noqa: F401  (fixture)
from test_pq_smart_account import CALLS, _call, _sel, _tx

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "sdk" / "typescript"
sys.path.insert(0, str(ROOT / "scripts" / "sdk"))
import make_vectors  # noqa: E402

STORED = json.loads((SDK / "test" / "vectors.json").read_text())


def _without_signatures(v):
    v = json.loads(json.dumps(v))
    for case in v["exchange"]:
        case.pop("signature")
    for case in v["pq_tx"]:
        for k in ("signature", "raw", "hash"):
            case.pop(k)
    return v


def test_the_vectors_and_the_op_table_are_current():
    fresh = make_vectors.build()
    assert _without_signatures(fresh) == _without_signatures(STORED), (
        "the node's formats changed: run python scripts/sdk/make_vectors.py")
    assert (SDK / "src" / "ops.ts").read_text() == make_vectors.ops_table()


def test_the_stored_signatures_are_the_nodes():
    from qrdx.crypto.pq.dilithium import PQPublicKey, PQSignature, verify
    from qrdx.transactions.pq_tx import decode_pq_tx

    pub = PQPublicKey.from_bytes(bytes.fromhex(STORED["key"]["public_key"]))
    for case in STORED["exchange"]:
        assert verify(pub, bytes.fromhex(case["canonical"]), PQSignature.from_bytes(bytes.fromhex(case["signature"])))
    for case in STORED["pq_tx"]:
        tx = decode_pq_tx(bytes.fromhex(case["raw"]))
        assert tx.verify() and tx.hash().hex() == case["hash"]


async def test_the_smart_account_values_are_the_contracts(chain):
    from qrdx import chain_spec, predeploys

    for p in predeploys.check(predeploys.default_entries()):
        await chain.db.seed_genesis_contract(predeploys.genesis_record(p))
    await chain.db.connection.commit()
    chain.sm.reset_cache()
    s = STORED["smart_account"]
    factory = bytes.fromhex(s["factory"][2:])
    owner, salt = bytes.fromhex(s["owner_key"][2:]), bytes.fromhex(s["salt"][2:])
    (predicted,) = decode(["address"], await _call(
        chain, factory, _sel("predict(bytes32,bytes32)") + encode(["bytes32", "bytes32"], [owner, salt])))
    assert predicted == s["account"]
    assert (await _tx(chain, ALICE, factory, bytes.fromhex(s["create_calldata"][2:]))).success
    account = bytes.fromhex(s["account"][2:])
    calls = [(c["target"], int(c["value"]), bytes.fromhex(c["data"][2:])) for c in s["calls"]]
    (got,) = decode(["bytes32"], await _call(
        chain, account, _sel(f"executeHash({CALLS},uint256,uint256)")
        + encode([CALLS, "uint256", "uint256"], [calls, int(s["nonce"]), int(s["valid_until"])])))
    chain_id = chain_spec.active().chain_id                    # (block.chainid in this EVM)
    expected = keccak(encode(
        ["bytes32", "uint256", "address", "uint256", "uint256", CALLS],
        [bytes.fromhex(s["domain"][2:]), chain_id, s["account"], int(s["nonce"]), int(s["valid_until"]), calls]))
    assert got == expected                                     # the vectors' formula is the contract's


def _node():
    if shutil.which("node") is None or not (SDK / "node_modules" / "@noble" / "post-quantum").exists():
        pytest.skip("Node.js or the SDK's dependencies (npm ci in sdk/typescript) are not installed")


def test_the_sdks_own_tests_pass():
    _node()
    out = subprocess.run(["npm", "test", "--silent"], cwd=SDK, capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-2000:]


SIGN = """
import { PQKey, signExchangeTx, signPQTx } from './src/index.ts';
const v = JSON.parse(process.argv[1]);
const key = PQKey.fromSecretKey(v.secret_key);
const ex = signExchangeTx({ op: 'PERP_ORDER', sender: key.address, nonce: 4, chainId: v.chain_id,
  params: { market_id: 'BTC-QRDX-PERP', side: 'sell', size: '0.5', price: '31000', note: 'é' },
  gasLimit: 300000, gasPrice: '1000000000' }, key);
const pq = signPQTx({ chainId: v.chain_id, nonce: 9, gasPrice: 7, gasLimit: 90000,
  to: '0x' + 'b0'.repeat(20), value: 5n, data: '0x1234' }, key);
console.log(JSON.stringify({ ex: { ...ex, nonce: Number(ex.nonce), gas_limit: Number(ex.gas_limit),
  chain_id: Number(ex.chain_id) }, pq }));
"""


def test_what_the_sdk_signs_verifies_here():
    _node()
    from qrdx import chain_spec
    from qrdx.exchange.submission import parse_exchange_tx
    from qrdx.transactions.pq_tx import decode_pq_tx

    chain_id = chain_spec.active().chain_id
    arg = json.dumps({"secret_key": STORED["key"]["secret_key"], "chain_id": chain_id})
    out = subprocess.run(["node", "--input-type=module", "-e", SIGN, arg], cwd=SDK,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    got = json.loads(out.stdout)
    tx = parse_exchange_tx(got["ex"])
    assert tx.verify() and tx.tx_hash() == got["ex"]["tx_hash"]
    assert tx.sender == STORED["key"]["address"] and tx.params["note"] == "é"
    pq = decode_pq_tx(bytes.fromhex(got["pq"]["raw"][2:]))
    assert pq.verify() and "0x" + pq.hash().hex() == got["pq"]["hash"]
    assert pq.sender() == STORED["key"]["account_id"] and pq.value == 5 and pq.data == b"\x124"
