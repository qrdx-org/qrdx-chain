"""
QRDXLockbox v3 (contracts/bridge/QRDXLockbox.sol) run in an EVM: each deposit gets an id and a
record in storage that QRDX can prove (``deposits[id]`` at slot 4, the hash
qrdx/exchange/bridge.py computes); a refund pays back exactly a recorded deposit, to its
depositor, once, after the refund delay, and only from the custodian.
"""

from pathlib import Path

import pytest
from eth_abi import decode, encode
from eth_utils import keccak
from test_evm_world import ALICE, chain  # noqa: F401  (fixture)

from qrdx.bridge import lockbox as L
from qrdx.contracts.evm_world import EvmWorld, run
from qrdx.contracts.native_token_evm import EvmSection, TokenWorld
from qrdx.exchange.bridge import DEPOSITS_SLOT, BridgeAsset, deposit_slot, parse_deposit
from qrdx.validator.bridge_watcher import decode_deposit_log

CUSTODIAN = bytes.fromhex("c0" * 20)
STRANGER = bytes.fromhex("5e" * 20)
RECIPIENT = "0xPQ" + "ab" * 32
DELAY = 8 * 86_400
CHAIN = 31337
TOKEN_SOURCE = Path(__file__).with_name("fixtures") / "TestToken.sol"


def _sel(sig):
    return keccak(text=sig)[:4]


def _token_bytecode() -> bytes:
    solcx = pytest.importorskip("solcx")
    out = solcx.compile_standard(
        {"language": "Solidity", "sources": {"T.sol": {"content": TOKEN_SOURCE.read_text()}},
         "settings": {**L.SOLC_SETTINGS, "outputSelection": {"*": {"*": ["evm.bytecode.object"]}}}},
        solc_version=L.SOLC_VERSION,
    )
    return bytes.fromhex(out["contracts"]["T.sol"]["TestToken"]["evm"]["bytecode"]["object"])


async def _tx(chain, sender, to, data=b"", timestamp=1_000):
    chain.height += 1
    chain.sm.reset_cache()
    section = EvmSection()
    snap = await chain.sm.snapshot()
    world = EvmWorld(chain.sm, tokens=TokenWorld(chain.db, section))
    r = await run(world, lambda: chain.ex.execute(
        sender, to, 0, data, 5_000_000, 0, world=world, block_number=chain.height,
        timestamp=timestamp), preload=[sender, to])
    if not r.success:
        await chain.sm.revert(snap)
    await chain.sm.commit(chain.height)
    await chain.db.connection.commit()
    return r


def logs_as_rpc(result, tx_hash="0x" + "11" * 32, block=7):
    """EVMResult logs in eth_getLogs' shape."""
    out = []
    for i, (address, topics, data) in enumerate(result.logs):
        out.append({
            "address": "0x" + bytes(address).hex(),
            "topics": ["0x" + int(t).to_bytes(32, "big").hex() for t in topics],
            "data": "0x" + bytes(data).hex(),
            "transactionHash": tx_hash,
            "logIndex": hex(i),
            "blockNumber": hex(block),
        })
    return out


async def deployed(chain, delay=DELAY):
    """A test token (ALICE holds it all) and a lockbox with CUSTODIAN; ALICE approved it."""
    await chain.fund(CUSTODIAN, 10**20)
    await chain.fund(STRANGER, 10**20)
    r = await _tx(chain, ALICE, None, _token_bytecode() + encode(["uint256"], [10**12]))
    assert r.success, r.error
    token = r.created_address
    art = L.load_artifact()
    r = await _tx(chain, ALICE, None, L.deploy_data(art["bytecode"], "0x" + CUSTODIAN.hex(), delay))
    assert r.success, r.error
    lockbox = r.created_address
    approve = _sel("approve(address,uint256)") + encode(["address", "uint256"], ["0x" + lockbox.hex(), 10**12])
    assert (await _tx(chain, ALICE, token, approve)).success
    return token, lockbox


async def deposit(chain, token, lockbox, units, recipient=RECIPIENT, timestamp=1_000):
    data = _sel("deposit(address,uint256,string)") + encode(
        ["address", "uint256", "string"], ["0x" + token.hex(), units, recipient])
    r = await _tx(chain, ALICE, lockbox, data, timestamp=timestamp)
    assert r.success, r.error
    return r


async def _storage(chain, lockbox, slot: bytes) -> bytes:
    value = await chain.sm.get_storage("0x" + lockbox.hex(), slot)
    return bytes(value).rjust(32, b"\x00")


async def test_a_deposit_is_recorded_where_and_as_qrdx_proves_it(chain):
    token, lockbox = await deployed(chain)
    r = await deposit(chain, token, lockbox, 250_500_000)
    (log,) = [x for x in logs_as_rpc(r) if x["topics"][0] == L.TOPIC_DEPOSIT]
    asset = BridgeAsset("TUSD", CHAIN, "0x" + token.hex(), 6)
    raw = decode_deposit_log(CHAIN, log, {(CHAIN, "0x" + token.hex()): asset})
    assert raw["id"] == 1 and raw["to"] == RECIPIENT and raw["amount"] == "250.500000"
    assert raw["from"] == "0x" + ALICE.hex() and raw["time"] == 1_000
    d = parse_deposit(raw, {(CHAIN, "0x" + token.hex()): asset})
    # The record QRDX checks a proof against is the one in the lockbox's storage, at slot 4.
    assert await _storage(chain, lockbox, deposit_slot(1)) == d.record(asset)
    (count,) = decode(["uint256"], bytes((await chain.call(lockbox, _sel("depositCount()"))).output))
    assert count == 1 and DEPOSITS_SLOT == 4
    r2 = await deposit(chain, token, lockbox, 1_000_000, timestamp=1_100)
    (log2,) = [x for x in logs_as_rpc(r2) if x["topics"][0] == L.TOPIC_DEPOSIT]
    assert int(log2["topics"][1], 16) == 2                       # ids are sequential


async def test_a_refund_is_exactly_a_recorded_deposit_once_after_the_delay(chain):
    token, lockbox = await deployed(chain)
    await deposit(chain, token, lockbox, 77_000_000, recipient="not a qrdx address")
    d = L.DepositEvent("x", 1, L.to_checksum_address("0x" + token.hex()),
                       L.to_checksum_address("0x" + ALICE.hex()), 77_000_000, "not a qrdx address", 0, 1_000)
    refund = L.refund_calldata(d)
    before = await chain.call(token, _sel("balanceOf(address)") + encode(["address"], ["0x" + ALICE.hex()]))
    assert not (await _tx(chain, CUSTODIAN, lockbox, refund, timestamp=1_000 + DELAY)).success  # too early
    assert not (await _tx(chain, STRANGER, lockbox, refund, timestamp=1_001 + DELAY)).success   # not custodian
    wrong = L.DepositEvent(d.deposit_id, 1, d.token, d.sender, 77_000_001, d.recipient, 0, d.time)
    assert not (await _tx(chain, CUSTODIAN, lockbox, L.refund_calldata(wrong), timestamp=2 * DELAY)).success
    to_other = L.DepositEvent(d.deposit_id, 1, d.token, L.to_checksum_address("0x" + STRANGER.hex()),
                              d.units, d.recipient, 0, d.time)
    assert not (await _tx(chain, CUSTODIAN, lockbox, L.refund_calldata(to_other), timestamp=2 * DELAY)).success
    r = await _tx(chain, CUSTODIAN, lockbox, refund, timestamp=1_001 + DELAY)
    assert r.success, r.error
    after = await chain.call(token, _sel("balanceOf(address)") + encode(["address"], ["0x" + ALICE.hex()]))
    assert int.from_bytes(bytes(after.output), "big") - int.from_bytes(bytes(before.output), "big") == 77_000_000
    assert not (await _tx(chain, CUSTODIAN, lockbox, refund, timestamp=2 * DELAY)).success     # once
    (done,) = decode(["bool"], bytes((await chain.call(lockbox, _sel("refunded(uint256)") + encode(["uint256"], [1]))).output))
    assert done
    ghost = L.DepositEvent("y", 9, d.token, d.sender, 1, "x", 0, 1_000)
    assert not (await _tx(chain, CUSTODIAN, lockbox, L.refund_calldata(ghost), timestamp=2 * DELAY)).success


async def test_a_lockbox_needs_a_refund_delay_of_a_day(chain):
    art = L.load_artifact()
    r = await _tx(chain, ALICE, None, L.deploy_data(art["bytecode"], "0x" + CUSTODIAN.hex(), 3_600))
    assert not r.success


def test_the_layout_puts_deposits_at_slot_4():
    solcx = pytest.importorskip("solcx")
    if L.SOLC_VERSION not in {str(v) for v in solcx.get_installed_solc_versions()}:
        pytest.skip(f"solc {L.SOLC_VERSION} is not installed")
    out = solcx.compile_standard(
        {"language": "Solidity", "sources": {"QRDXLockbox.sol": {"content": L.SOURCE_PATH.read_text()}},
         "settings": {**L.SOLC_SETTINGS, "outputSelection": {"*": {"*": ["storageLayout"]}}}},
        solc_version=L.SOLC_VERSION,
    )
    layout = out["contracts"]["QRDXLockbox.sol"]["QRDXLockbox"]["storageLayout"]["storage"]
    assert {s["label"]: int(s["slot"]) for s in layout}["deposits"] == DEPOSITS_SLOT
