"""
Big blocks (docs/BLOCK_LIMITS.md, HyperEVM's two block sizes): every BIG_BLOCK_INTERVAL-th
block, by height, may carry BIG_BLOCK_GAS_LIMIT of EVM gas — room for a contract deployment no
ordinary block holds. A transaction above the ordinary limit waits for one. Big blocks are priced
on an EVM fee track of their own, which moves up to 1/2 per big block, so ordinary blocks' price
is never moved by them, and filling every big block with slow work gets expensive in minutes.
"""
import pytest
from test_fee_market import GWEI, _raw

from qrdx import block_limits as BL
from qrdx import constants
from qrdx import fee_market as F
from qrdx.contracts.evm_block_apply import section_gas_error
from qrdx.contracts.evm_mempool import EVMMempool


@pytest.fixture
def big(monkeypatch):
    monkeypatch.setattr(constants, "BLOCK_GAS_LIMIT", 1_000_000)
    monkeypatch.setattr(constants, "BIG_BLOCK_GAS_LIMIT", 3_000_000)
    monkeypatch.setattr(constants, "BIG_BLOCK_INTERVAL", 4)


def test_every_intervals_block_is_big(big, monkeypatch):
    assert [h for h in range(0, 13) if BL.is_big_block(h)] == [4, 8, 12]
    assert BL.evm_gas_limit_at(8) == 3_000_000 and BL.evm_gas_limit_at(9) == 1_000_000
    assert BL.max_evm_tx_gas() == 3_000_000
    monkeypatch.setattr(constants, "BIG_BLOCK_INTERVAL", 0)                 # turned off
    assert not BL.is_big_block(8) and BL.max_evm_tx_gas() == 1_000_000


def test_a_section_over_the_ordinary_limit_fits_only_a_big_block(big):
    deploy = [_raw(1, gas=2_000_000)]
    assert "exceeds the block gas limit" in section_gas_error(deploy, 9)
    assert section_gas_error(deploy, 8) == ""
    assert "exceeds" in section_gas_error([_raw(1, gas=2_000_000), _raw(2, gas=1_500_000)], 8)
    assert BL.block_resource_error({}, [], deploy, height=8) == ""
    assert BL.block_resource_error({}, [], deploy, height=7) != ""


def test_a_large_transaction_is_admitted_and_waits_for_a_big_block(big):
    pool = EVMMempool(nonce_provider=lambda a: 0)
    ok, err, _ = pool.admit(_raw(1, gas=2_000_000))
    assert ok, err
    ok, err, _ = pool.admit(_raw(2, gas=4_000_000))
    assert not ok and "largest block" in err
    small = _raw(3)
    assert pool.admit(small)[0]
    ordinary = pool.select_for_block(gas_limit=BL.evm_gas_limit_at(9))
    assert ordinary == [small]                                            # the deploy waits
    assert len(pool.select_for_block(gas_limit=BL.evm_gas_limit_at(8))) == 2


def test_the_gaslimit_opcode_reads_the_blocks_own_limit(big):
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor

    assert QRDXEVMExecutor._execution_context(8, 1).gas_limit == 3_000_000
    assert QRDXEVMExecutor._execution_context(9, 1).gas_limit == 1_000_000


# ── the fee tracks ──────────────────────────────────────────────────────────

class _Chain:
    """Stored blocks: each a header's base fees and an EVM section of declared gas amounts."""

    def __init__(self, blocks):
        self.blocks = blocks  # height → (evm fee, evm gas)

    async def get_block_by_id(self, h):
        if h not in self.blocks:
            return None
        fee, _gas = self.blocks[h]
        return {"hash": f"h{h}", "content": {"base_fee": fee, "exchange_base_fee": GWEI}}

    async def get_block_exchange_txs(self, _hash):
        return []

    async def get_block_evm_txs(self, block_hash):
        return [str(self.blocks[int(block_hash[1:])][1])]


@pytest.fixture
def chain(big, monkeypatch):
    import qrdx.contracts.evm_mempool as M
    from qrdx.validator import block_verification as V

    monkeypatch.setattr(M, "parse_eth_raw_tx", lambda raw: {"gas": int(raw), "gas_price": 0})
    monkeypatch.setattr(V, "_parse_block_content", lambda c: c)
    return _Chain


async def test_an_ordinary_block_is_priced_by_the_ordinary_block_before_it(chain):
    # Block 4 is big and full; block 5's price comes from block 3, which was at target.
    db = chain({3: (8 * GWEI, 500_000), 4: (2 * GWEI, 3_000_000)})
    evm_fee, _ex = await F.base_fees_at(db, 5)
    assert evm_fee == 8 * GWEI
    db = chain({5: (8 * GWEI, 1_000_000)})                               # an ordinary parent
    assert (await F.base_fees_at(db, 6))[0] == 9 * GWEI                  # full: +1/8


async def test_a_big_block_is_priced_by_the_big_block_before_it_and_moves_by_half(chain):
    db = chain({4: (2 * GWEI, 3_000_000), 7: (GWEI, 0)})
    assert (await F.base_fees_at(db, 8))[0] == 3 * GWEI                  # full big block: +1/2
    db = chain({4: (4 * GWEI, 0), 7: (GWEI, 1_000_000)})
    assert (await F.base_fees_at(db, 8))[0] == 2 * GWEI                  # empty: −1/2
    assert (await F.base_fees_at(chain({7: (GWEI, 0)}), 4))[0] == GWEI   # the first: the floor


async def test_without_big_blocks_the_parent_prices_the_block(chain, monkeypatch):
    monkeypatch.setattr(constants, "BIG_BLOCK_INTERVAL", 0)
    db = chain({3: (8 * GWEI, 500_000), 4: (2 * GWEI, 1_000_000)})
    assert (await F.base_fees_at(db, 5))[0] == 2 * GWEI + 2 * GWEI // 8


def test_a_flood_of_full_big_blocks_is_priced_out_in_minutes():
    fee = GWEI
    for _ in range(20):                                                  # 20 minutes at 1/min
        fee = F.next_base_fee(fee, 3_000_000, 3_000_000, GWEI,
                              denominator=F.BIG_BLOCK_CHANGE_DENOMINATOR)
    assert fee > 3_000 * GWEI
