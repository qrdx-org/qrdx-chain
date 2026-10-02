"""
Wallets must be able to learn a transaction's intrinsic gas floor.

A type-0x51 post-quantum transaction carries a ~5.3KB ML-DSA-65 public key and signature,
and its intrinsic floor prices that — roughly 145,000 gas for a plain transfer against
21,000 for a legacy one. A transaction below its floor is **invalid**, rejected outright
rather than merely reverting, so a wallet that assumed 21,000 would have every PQ
transaction refused.

`QRDXEVMExecutor.estimate_gas` binary-searches execution and knows nothing about the
envelope, so it cannot answer this. Two surfaces now can:

  * ``eth_estimateGas`` honours the standard EIP-2718 ``type`` field;
  * ``qrdx_getIntrinsicGas`` answers directly, for callers that would rather ask.

Both must agree with the executor's own floor — that is the property that keeps a wallet's
estimate and the node's validity rule from drifting apart.
"""
import pytest

from qrdx.contracts.evm_mempool import intrinsic_gas_legacy
from qrdx.crypto.pq.dilithium import PUBLIC_KEY_SIZE, SIGNATURE_SIZE
from qrdx.rpc.modules.qrdx import QRDXModule
from qrdx.transactions.pq_tx import PQ_TX_TYPE, PQTransaction, intrinsic_gas_pq


def _module():
    return QRDXModule()


def _pq_floor(data=b"", is_create=False):
    return intrinsic_gas_pq(data, b"\x00" * PUBLIC_KEY_SIZE, b"\x00" * SIGNATURE_SIZE,
                            is_create=is_create)


# ── qrdx_getIntrinsicGas ───────────────────────────────────────────────────

async def test_legacy_transfer_floor():
    r = await _module().getIntrinsicGas(envelope="legacy")
    assert r["intrinsicGas"] == 21_000 == intrinsic_gas_legacy(b"")
    assert r["envelope"] == "legacy"
    assert r["txType"] == "0x0"


async def test_legacy_creation_adds_the_eip2_surcharge():
    r = await _module().getIntrinsicGas(envelope="legacy", is_create=True)
    assert r["intrinsicGas"] == 53_000 == intrinsic_gas_legacy(b"", is_create=True)


async def test_pq_floor_prices_the_authentication_envelope():
    r = await _module().getIntrinsicGas(envelope="pq")
    assert r["intrinsicGas"] == _pq_floor()
    assert r["txType"] == hex(PQ_TX_TYPE)
    # The envelope dominates: a PQ transfer costs several times a legacy one.
    assert r["intrinsicGas"] > 5 * 21_000


async def test_calldata_is_priced_per_byte():
    empty = (await _module().getIntrinsicGas(envelope="legacy"))["intrinsicGas"]
    with_data = (await _module().getIntrinsicGas(
        envelope="legacy", data="0x" + "ff" * 100))["intrinsicGas"]
    assert with_data == empty + 100 * 16


async def test_zero_bytes_are_cheaper_than_non_zero():
    zeros = (await _module().getIntrinsicGas(envelope="legacy", data="0x" + "00" * 50))["intrinsicGas"]
    ones = (await _module().getIntrinsicGas(envelope="legacy", data="0x" + "ff" * 50))["intrinsicGas"]
    assert zeros < ones


@pytest.mark.parametrize("alias", ["pq", "PQ", "post-quantum", "0x51", "81"])
async def test_pq_envelope_aliases(alias):
    r = await _module().getIntrinsicGas(envelope=alias)
    assert r["envelope"] == "pq"
    assert r["intrinsicGas"] == _pq_floor()


async def test_an_unknown_envelope_is_rejected():
    from qrdx.rpc.server import RPCError
    with pytest.raises(RPCError):
        await _module().getIntrinsicGas(envelope="ed25519")


async def test_malformed_data_is_rejected():
    from qrdx.rpc.server import RPCError
    with pytest.raises(RPCError):
        await _module().getIntrinsicGas(envelope="legacy", data="0xnothex")


async def test_hex_and_int_forms_agree():
    r = await _module().getIntrinsicGas(envelope="pq")
    assert int(r["intrinsicGasHex"], 16) == r["intrinsicGas"]


# ── Agreement with what the node actually enforces ─────────────────────────

def test_the_quoted_pq_floor_matches_what_a_real_transaction_requires():
    """
    The property that matters: a transaction funded with the quoted floor must be
    ACCEPTED by the parser, and one funded a single gas below it must be REFUSED. If the
    quote and the validity rule ever drift apart, every PQ wallet breaks.
    """
    from qrdx.contracts.evm_mempool import parse_eth_raw_tx
    from qrdx.crypto.pq.dilithium import generate_keypair

    priv, _pub = generate_keypair()
    floor = _pq_floor()

    exact = PQTransaction(chain_id=1, nonce=0, gas_price=10 ** 9, gas_limit=floor,
                          to=bytes.fromhex("cd" * 20), value=1, data=b"").sign(priv)
    parsed = parse_eth_raw_tx("0x" + exact.encode().hex())
    assert parsed["intrinsic_gas"] == floor
    assert parsed["gas"] == floor

    short = PQTransaction(chain_id=1, nonce=0, gas_price=10 ** 9, gas_limit=floor - 1,
                          to=bytes.fromhex("cd" * 20), value=1, data=b"").sign(priv)
    with pytest.raises(ValueError, match="intrinsic gas too low"):
        parse_eth_raw_tx("0x" + short.encode().hex())


def test_the_quoted_legacy_floor_matches_the_parser():
    from eth_account import Account as EthAccount
    from eth_utils import to_checksum_address

    from qrdx.contracts.evm_mempool import parse_eth_raw_tx

    key = "0x" + "d4" * 32
    signed = EthAccount.sign_transaction(
        {"nonce": 0, "gasPrice": 10 ** 9, "gas": 21_000,
         "to": to_checksum_address("0x" + "cd" * 20), "value": 1, "data": b"",
         "chainId": 1}, key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    parsed = parse_eth_raw_tx("0x" + bytes(raw).hex())
    assert parsed["intrinsic_gas"] == intrinsic_gas_legacy(b"") == 21_000
