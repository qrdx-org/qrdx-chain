"""eth_getBlockByNumber on a block holding native transactions: the genesis allocations' rows
store their transaction hash as raw bytes, and formatting them failed — so the genesis block
("earliest", or "latest" until the first block after it) answered with an internal error, which
wallets, explorers and the bridge's watcher all call."""
from qrdx.rpc.modules import eth


def test_hashes_stored_as_bytes_format_as_hex():
    raw = bytes(range(32))
    assert eth._ensure_0x(raw) == "0x" + raw.hex()
    assert eth._strip_0x(raw) == raw.hex()
    assert eth._ensure_0x("ab") == "0xab" and eth._strip_0x("0xab") == "ab"


def test_a_native_transaction_with_a_bytes_hash_formats():
    module = eth.EthModule.__new__(eth.EthModule)
    tx = {"tx_hash": bytes(range(32)), "block_hash": "00" * 32,
          "outputs_addresses": "0x" + "11" * 20, "outputs_amounts": "5"}
    out = module._fmt_native_tx(tx, {"id": 0})
    assert out["hash"] == "0x" + bytes(range(32)).hex() and out["value"] == "0x5"


async def test_a_block_reports_its_own_gas_limit_base_fee_root_and_bloom(monkeypatch):
    """Wallets build an EIP-1559 fee cap from the block's base fee, cap gas by its gas limit,
    and indexers skip blocks whose bloom is empty: these were 0, 30M and an empty bloom."""
    import json
    from types import SimpleNamespace

    from qrdx.block_limits import evm_gas_limit_at

    log = {"contract_address": "0x" + "cd" * 20, "topic0": "0x" + "dd" * 32, "topic1": None,
           "topic2": None, "topic3": None, "block_number": 7, "removed": 0}
    db = SimpleNamespace(contract_logs_between=lambda lo, hi, *a: [log] if lo <= 7 <= hi else [])
    module = eth.EthModule.__new__(eth.EthModule)
    monkeypatch.setattr(module, "_db", lambda: db)
    content = json.dumps({"base_fee": 3_000_000_000, "state_root": "ab" * 64})
    block = {"id": 7, "hash": "11" * 32, "content": content}
    header = await module._header_fields(block, 7, [{"gas_used": 21000}])
    out = module._fmt_block(block, [], False, header=header)

    assert out["baseFeePerGas"] == hex(3_000_000_000)
    assert out["gasLimit"] == hex(evm_gas_limit_at(7)) and out["gasUsed"] == hex(21000)
    # The 64-byte unified root, as a 32-byte stateRoot clients accept (and in full beside it).
    from eth_hash.auto import keccak

    assert out["stateRoot"] == "0x" + keccak(bytes.fromhex("ab" * 64)).hex()
    assert out["qrdxStateRoot"] == "0x" + "ab" * 64
    assert out["logsBloom"] != "0x" + "00" * 256
    assert out["logsBloom"] == eth._logs_bloom([("0x" + "cd" * 20, "0x" + "dd" * 32)])


async def test_the_suggested_tip_is_zero_because_tips_buy_nothing():
    module = eth.EthModule.__new__(eth.EthModule)
    assert await module.maxPriorityFeePerGas() == "0x0"
