"""
Fuzzing what peers and users can hand a node (docs/MAINNET_READINESS.md §4, "Fuzzing and
conformance"): every decoder they reach, and the EVM's precompiles. Each property is the contract
a decoder keeps with its callers: what it raises on bad input (a ValueError, which each caller
turns into a refusal), and what it must never do: raise anything else, return wrong data, or take
time out of proportion to its input.

By default each property runs a fixed, reproducible set of examples. QRDX_FUZZ_EXAMPLES=N draws
N fresh examples per property instead (a deep run):

    QRDX_FUZZ_EXAMPLES=20000 pytest tests/test_fuzz_decoders.py -p no:cacheprovider
"""

import asyncio
import json
import os
import time
from decimal import Decimal

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from qrdx.exchange import (
    ExchangeOpType,
    ExchangeStateManager,
    ExchangeTransaction,
    block_processor as BP,
)

_DEEP = int(os.environ.get("QRDX_FUZZ_EXAMPLES", "0"))
pytestmark = pytest.mark.timeout(0 if _DEEP else 600)


def fuzz(examples: int = 150):
    return settings(max_examples=_DEEP or examples, derandomize=not _DEEP, deadline=None,
                    database=None, suppress_health_check=list(HealthCheck))


A, B = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64

# Values a JSON body can carry, weighted toward the ones decoders get wrong.
LEAVES = st.one_of(
    st.none(), st.booleans(), st.integers(min_value=-2**70, max_value=2**70),
    st.floats(allow_nan=True, allow_infinity=True), st.text(max_size=12),
    st.sampled_from(["1", "0", "-1", "0.5", "1e9999", "NaN", "Infinity", "sNaN", "0x00", "", "1" * 400,
                     "BTC-USD-PERP", "QRDX", "buy", "sell", "limit", "alo", "cross", A, B,
                     "0x" + "11" * 20, "7b7d", "ab" * 32]),
)
JSON = st.recursive(LEAVES, lambda inner: st.one_of(
    st.lists(inner, max_size=4),
    st.dictionaries(st.text(max_size=8) | st.sampled_from(["op", "params", "key", "value"]), inner,
                    max_size=4)), max_leaves=12)


@st.composite
def mutated(draw, seeds):
    """A seed with a few bytes flipped, inserted, deleted, cut or repeated."""
    data = bytearray(draw(st.sampled_from(seeds)))
    for _ in range(draw(st.integers(1, 4))):
        kind = draw(st.sampled_from(["flip", "insert", "delete", "cut", "repeat"]))
        at = draw(st.integers(0, max(0, len(data) - 1)))
        if kind == "flip" and data:
            data[at] ^= 1 << draw(st.integers(0, 7))
        elif kind == "insert":
            data[at:at] = draw(st.binary(min_size=1, max_size=4))
        elif kind == "delete" and data:
            del data[at:at + draw(st.integers(1, 8))]
        elif kind == "cut":
            data = data[:at]
        elif kind == "repeat":
            data[at:at] = data[at:at + draw(st.integers(1, 64))]
    return bytes(data)


# ── exchange transactions (a block's section, gossip, exchange_sendTransaction) ──────────────

TX_FIELDS = {
    "op_type": st.one_of(st.sampled_from([o.value for o in ExchangeOpType]), JSON),
    "sender": st.one_of(st.just(A), JSON),
    "nonce": st.one_of(st.integers(-5, 2**65), JSON),
    "params": st.one_of(st.dictionaries(st.sampled_from(["market_id", "side", "size", "price",
                                                         "expires_at", "actions", "pool_id"]),
                                        JSON, max_size=4), JSON),
    "gas_limit": st.one_of(st.integers(-5, 2**65), JSON),
    "gas_price": st.one_of(st.integers(-5, 2**80), JSON),
    "timestamp": JSON,
    "signature": st.one_of(st.just("7b7d"), st.text(max_size=8), JSON),
    "public_key": st.one_of(st.just("7b226d223a317d"), JSON),
    "chain_id": JSON,
    "signer": JSON,
}


@st.composite
def tx_dicts(draw):
    keys = draw(st.sets(st.sampled_from(sorted(TX_FIELDS))))
    keys |= {"op_type", "sender", "nonce", "params"} if draw(st.booleans()) else set()
    return {k: draw(TX_FIELDS[k]) for k in keys}


@fuzz(400)
@given(tx_dicts())
def test_an_exchange_transaction_decodes_or_is_refused_with_a_value_error(d):
    from qrdx.exchange.submission import parse_exchange_tx

    try:
        tx = ExchangeTransaction.from_dict(d)
    except ValueError:
        tx = None
    for text in (json.dumps(d), d):  # (exchange_sendTransaction takes either)
        try:
            parse_exchange_tx(text)
        except ValueError:
            pass
    if tx is None:
        return
    # A decoded transaction hashes, round-trips to the same hash, and every check answers.
    h = tx.tx_hash()
    assert ExchangeTransaction.from_dict(tx.to_dict()).tx_hash() == h
    assert tx.verify() in (True, False)
    ok, why = BP.verify_exchange_tx(tx)
    assert ok is False and why
    tx.expires_at()
    tx.signature_gas()
    try:
        tx.validate_basic()
    except ValueError:
        pass


KEYS = ["market_id", "side", "size", "price", "leverage", "amount", "pair", "order_type", "token0",
        "token1", "pool_id", "position_id", "expires_at", "tif", "reduce_only", "orders",
        "actions", "path", "amount_in", "token_in", "token_out", "agent", "to", "token_address",
        "heads", "prices", "deposits", "order_id", "cloid", "trigger_price", "kind", "tick_lower",
        "tick_upper", "fee_tier", "pool_type", "stake_amount", "initial_price", "margin_mode",
        "vault", "chain", "proof", "name", "symbol", "total_supply", "decimals",
        "validator_public_key", "account", "successor", "time", "duration", "builder",
        "referrer", "guardians", "proposal_id", "vote", "params", "op", "recipient", "asset"]


@st.composite
def signed_envelopes(draw):
    """A well-formed envelope around any operation and any parameters: what reaches execution
    once a signature verifies."""
    return ExchangeTransaction(
        op_type=draw(st.sampled_from(list(ExchangeOpType))), sender=draw(st.sampled_from([A, B])),
        nonce=0, params=draw(st.dictionaries(st.sampled_from(KEYS), JSON, max_size=6)),
        gas_limit=draw(st.sampled_from([10_000_000, 2_000_000, 100_000])),
        gas_price=draw(st.sampled_from([10**9, 0])), timestamp=1.0)


@fuzz(300)
@given(signed_envelopes())
def test_any_parameters_execute_or_fail_and_never_escape_the_exchange(tx):
    ExchangeStateManager.reset_instance()
    try:
        m = ExchangeStateManager.get_instance()
        BP.apply_enforcement(m)
        for who in (A, B):
            m.set_available_balance(who, Decimal(10**8))
        m.begin_block(1, 1_700_000_000.0)
        try:
            tx.validate_basic()
        except ValueError:
            pass
        assert isinstance(m.section_errors([tx], 1, 1_700_000_000.0,
                                           balance_of=lambda a: Decimal(10**8)), dict)
        r = m.process_transaction(tx)
        assert r.success in (True, False)
    finally:
        ExchangeStateManager.reset_instance()


# ── EVM transactions (eth_sendRawTransaction, a block's EVM section) ─────────────────────────

def _raw_seeds():
    from eth_account import Account
    from eth_utils import to_checksum_address

    from qrdx.constants import CHAIN_ID
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.transactions.pq_tx import PQTransaction

    key = Account.from_key("0x" + "42" * 32)
    to = to_checksum_address("0x" + "c7" * 20)
    base = {"nonce": 3, "gas": 50_000, "to": to, "value": 5, "data": b"\x01\x02",
            "chainId": CHAIN_ID}
    raws = []
    for extra in ({"gasPrice": 10**9},
                  {"type": 1, "gasPrice": 10**9,
                   "accessList": [{"address": to, "storageKeys": ["0x" + "00" * 32]}]},
                  {"type": 2, "maxFeePerGas": 3 * 10**9, "maxPriorityFeePerGas": 10**9}):
        signed = Account.sign_transaction({**base, **extra}, key.key)
        raws.append(bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction))
    pq = PQTransaction(chain_id=CHAIN_ID, nonce=0, gas_price=10**9, gas_limit=500_000,
                       to=bytes.fromhex("c7" * 20), value=1, data=b"\x00\x01")
    raws.append(pq.sign(PQPrivateKey.generate()).encode())
    return raws


RAW_SEEDS = _raw_seeds()


def test_the_seeds_are_valid_transactions():
    from qrdx.contracts.evm_mempool import parse_eth_raw_tx

    assert [parse_eth_raw_tx("0x" + r.hex())["tx_type"] for r in RAW_SEEDS] == [0, 1, 2, 0x51]


@fuzz(400)
@given(st.one_of(mutated(RAW_SEEDS), st.binary(max_size=300),
                 st.binary(max_size=200).map(lambda b: b"\x51" + b)))
def test_a_raw_evm_transaction_parses_or_is_refused_with_a_value_error(raw):
    from qrdx.contracts.evm_block_apply import section_gas_error
    from qrdx.contracts.evm_mempool import parse_eth_raw_tx
    from qrdx.transactions.pq_tx import InvalidPQTransaction, decode_pq_tx, is_pq_tx

    for form in ("0x" + raw.hex(), raw.hex()):
        try:
            parsed = parse_eth_raw_tx(form)
            assert parsed["sender"].startswith("0x") and isinstance(parsed["gas"], int)
        except ValueError:
            pass
    if is_pq_tx(raw):
        try:
            decode_pq_tx(raw)
        except InvalidPQTransaction:
            pass
    assert isinstance(section_gas_error(["0x" + raw.hex()]), str)


@fuzz()
@given(JSON)
def test_a_raw_transaction_that_is_not_text_is_refused(value):
    from qrdx.contracts.evm_block import decode_evm_txs
    from qrdx.contracts.evm_block_apply import section_gas_error
    from qrdx.contracts.evm_mempool import parse_eth_raw_tx

    with pytest.raises(ValueError):
        parse_eth_raw_tx(value)
    assert isinstance(section_gas_error(value if isinstance(value, list) else [value]), str)
    decode_evm_txs(value if isinstance(value, list) else None)


# ── block content (submit_block, p2p_submitBlock, sync) ──────────────────────────────────────

def _full_block() -> dict:
    """The most a block may carry: every vote and slashing proof it is allowed."""
    from qrdx.block_limits import MAX_SLASHING_EVIDENCE_PER_BLOCK
    from qrdx.constants import MAX_ATTESTATIONS_PER_BLOCK

    sig = "ab" * 3309
    header = {"number": 7, "parent_hash": "aa" * 32, "state_root": "bb" * 32,
              "transactions_root": "cc" * 32, "timestamp": 1_800_000_000,
              "proposer_address": "0xPQ" + "ee" * 32, "proposer_signature": sig, "slot": 99,
              "epoch": 12, "randao_reveal": sig, "body_root": "dd" * 32, "base_fee": 10**9,
              "exchange_base_fee": 10**9, "hash": "ff" * 32}
    vote = {"slot": 123456, "epoch": 15432, "block_hash": "cd" * 32,
            "validator_address": "0xPQ" + "ef" * 32, "validator_index": 7, "signature": sig,
            "source_epoch": 15430, "target_epoch": 15431, "source_root": "12" * 32,
            "target_root": "34" * 32, "included_in_block": None,
            "created_at": "2026-11-04T02:46:42.123456"}
    signed = dict(header, proposer_public_key="aa" * 1952)
    proof = {"condition": "double_sign", "proposer": header["proposer_address"], "slot": 99,
             "epoch": 12, "header_a": signed, "header_b": signed}
    return dict(header, attestations=[dict(vote)] * MAX_ATTESTATIONS_PER_BLOCK,
                slashing_evidence=[proof] * MAX_SLASHING_EVIDENCE_PER_BLOCK,
                graffiti="QRDX-QR-PoS" * 5)


def test_the_fullest_block_is_well_within_the_content_structure_budget():
    from qrdx.validator.block_verification import (
        _parse_block_content,
        content_structure,
        max_content_structure,
    )

    text = str(_full_block())
    assert content_structure(text) * 2 < max_content_structure()
    assert _parse_block_content(text) == _full_block()


def test_content_built_to_be_slow_to_parse_is_refused_unparsed():
    """Any peer can submit a block, and every import path parsed its content several times
    before checking who signed it: 4 MB of ``1,1,1,…`` took about four seconds a parse, with the
    block-processing lock held."""
    from qrdx.constants import MAX_BLOCK_CONTENT_SIZE
    from qrdx.validator.block_verification import _parse_block_content

    n = MAX_BLOCK_CONTENT_SIZE
    for text in ("{'a': [" + "1," * (n // 2 - 8) + "]}",
                 "{'a': " + "'a'" * (n // 3 - 8) + "}",
                 "{'a': " + "+".join(["1j"] * (n // 3 - 8)) + "}",
                 "{" + ",".join(f"{i}:{i}" for i in range(n // 16)) + "}"):
        start = time.perf_counter()
        with pytest.raises(ValueError, match="more structure"):
            _parse_block_content(text)
        assert time.perf_counter() - start < 0.5


def test_each_parse_gets_its_own_copy():
    from qrdx.validator.block_verification import _parse_block_content

    text = str({"slot": 1, "attestations": [{"slot": 1}]})
    first = _parse_block_content(text)
    first["attestations"][0]["slot"] = 99
    assert _parse_block_content(text)["attestations"][0]["slot"] == 1


LITERAL = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8), st.floats()),
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.tuples(inner, inner),
                            st.dictionaries(st.text(max_size=6), inner, max_size=4)),
    max_leaves=12)


@fuzz(300)
@given(st.one_of(LITERAL.map(repr), LITERAL.map(repr).flatmap(
    lambda t: mutated([t.encode()]).map(lambda b: b.decode("utf-8", "replace"))),
    st.text(max_size=200)))
def test_block_content_parses_or_is_refused(text):
    from qrdx.validator.block_verification import (
        _parse_block_content,
        block_integrity_error,
        epoch_from_block,
        is_double_sign,
    )

    try:
        block = _parse_block_content(text)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        block = None
    epoch_from_block({"block_content": text})
    assert is_double_sign(text, text) is False
    if isinstance(block, dict):
        assert isinstance(block_integrity_error(block, block_hash="00"), str)


@fuzz(300)
@given(st.dictionaries(st.sampled_from(["attestations", "slashing_evidence", "graffiti",
                                        "exchange_transactions", "evm_transactions", "body_root",
                                        "number", "slot", "epoch", "proposer_address"]), JSON))
def test_a_blocks_integrity_is_judged_for_any_fields(block):
    from qrdx.block_limits import block_resource_error
    from qrdx.validator.block_verification import block_integrity_error

    assert isinstance(block_integrity_error(block, block_hash="00" * 32), str)
    try:
        assert isinstance(block_resource_error(block), str)
    except (TypeError, ValueError):
        pass  # (_verify_chain_rules turns these into a refusal)


# ── multisig keys and signatures (exchange and 0x51 transactions) ────────────────────────────

def _multisig_seeds():
    from qrdx.crypto import multisig_wire
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    keys = [PQPrivateKey.generate() for _ in range(3)]
    keyset = multisig_wire.keyset_of([k.public_key for k in keys], 2)
    return multisig_wire.sign(keyset, keys[:2], b"message")


MULTISIG = _multisig_seeds()


@fuzz(200)
@given(st.one_of(mutated([MULTISIG[0]]), mutated([MULTISIG[1]]), JSON.map(lambda v: json.dumps(v).encode()),
                 st.binary(max_size=64)))
def test_multisig_material_decodes_or_is_refused(material):
    from qrdx.crypto import multisig_wire

    for decode in (multisig_wire.decode_keyset, multisig_wire.decode_signature):
        try:
            decode(material)
        except ValueError:
            pass
    assert multisig_wire.verify(material, MULTISIG[1], b"message") in (None, multisig_wire.verify(*MULTISIG, b"message"))
    assert multisig_wire.verify(MULTISIG[0], material, b"message") in (None, multisig_wire.verify(*MULTISIG, b"message"))
    assert isinstance(multisig_wire.signer_count(material), int)


def test_the_multisig_seed_verifies():
    from qrdx.crypto import multisig_wire

    assert multisig_wire.verify(*MULTISIG, b"message")


# ── peer discovery and the peer handshake (no identity needed to send these) ─────────────────

def _discovery():
    from qrdx.p2p.discovery import KademliaProtocol
    from qrdx.p2p.node import Node
    from qrdx.p2p.routing import RoutingTable

    node = Node.generate()
    return KademliaProtocol(RoutingTable(node.node_id), node)


@fuzz(300)
@given(st.one_of(JSON, st.fixed_dictionaries(
    {"type": st.sampled_from(["ping", "find_node", "store", "find_value", "pong"]) | JSON,
     "sender_id": st.just("qx" + "ab" * 20) | JSON, "sender_host": st.just("10.0.0.1") | JSON,
     "sender_port": st.just(30303) | JSON,
     "payload": st.dictionaries(st.sampled_from(["key", "value", "target"]), JSON) | JSON})))
def test_a_dht_message_is_answered_or_refused(message):
    from qrdx.p2p.discovery import DHTMessage

    protocol = _discovery()
    try:
        answer = protocol.handle_message(DHTMessage.from_dict(message))
    except (KeyError, ValueError):
        return  # (handle_incoming answers these with an error)
    assert isinstance(answer.to_dict(), dict)


def test_the_dht_store_is_bounded():
    from qrdx.p2p.discovery import MAX_STORE_ENTRIES, DHTMessage, DHTMessageType

    protocol = _discovery()
    for i in range(MAX_STORE_ENTRIES + 50):
        msg = DHTMessage(type=DHTMessageType.STORE, sender_id="qx" + "ab" * 20, sender_host="10.0.0.1",
                         sender_port=30303, payload={"key": f"k{i}", "value": "v" * 8192})
        protocol.handle_message(msg)
    assert len(protocol._store) == MAX_STORE_ENTRIES


@fuzz(200)
@given(st.text(max_size=16), st.dictionaries(st.sampled_from(["pubkey", "node_id", "proof", "url"]), JSON))
def test_a_handshake_answer_proves_an_identity_or_says_why_not(nonce, answer):
    from qrdx.rpc.modules.p2p import verify_handshake_proof

    assert isinstance(verify_handshake_proof(nonce, answer), str)


# ── the EVM's precompiles (any contract can call them with any input) ────────────────────────

PRECOMPILES = [n.to_bytes(20, "big") for n in (*range(1, 10), 0x0200, 0x0201, 0x0300, 0x0400,
                                                 0x0401, 0x0500, 0x0501)]


@pytest.fixture
def evm_chain():
    import tempfile

    from test_evm_world import ALICE, Chain

    from qrdx.database_sqlite import DatabaseSQLite

    loop = asyncio.new_event_loop()
    path = tempfile.mktemp(suffix=".db")
    db = loop.run_until_complete(DatabaseSQLite.create(db_path=path))
    ExchangeStateManager.reset_instance()
    chain = Chain(db)
    loop.run_until_complete(chain.fund(ALICE, 10**22))
    yield loop, chain
    ExchangeStateManager.reset_instance()
    loop.run_until_complete(db.close())
    loop.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


def _calldata():
    from eth_abi import encode

    from qrdx.contracts.exchange_evm import SEND_ACTION

    action = JSON.map(lambda v: SEND_ACTION + encode(["string"], [json.dumps(v)]))
    named = st.fixed_dictionaries({"op": st.sampled_from([o.name for o in ExchangeOpType]),
                                   "params": st.dictionaries(st.sampled_from(KEYS), JSON, max_size=4)})
    return st.one_of(st.binary(max_size=400), action,
                     named.map(lambda v: SEND_ACTION + encode(["string"], [json.dumps(v)])),
                     st.binary(max_size=200).map(lambda b: SEND_ACTION + b))


def test_every_precompile_runs_any_input_as_an_evm_call(evm_chain):
    """A Python exception inside a precompile ends the whole transaction, with all of its gas
    charged, where a contract expects that one call to fail and to carry on: every precompile
    must fail as an EVM call does, whatever it is given."""
    from test_evm_world import ALICE

    loop, chain = evm_chain

    @fuzz(60)
    @given(st.sampled_from(PRECOMPILES), _calldata(), st.booleans())
    def run(address, data, as_tx):
        r = loop.run_until_complete(chain.tx(ALICE, address, data) if as_tx
                                    else chain.call(address, data))
        assert not (r.error or "").startswith("Execution error"), (address.hex(), r.error)

    run()
