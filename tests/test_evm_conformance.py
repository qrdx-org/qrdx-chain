"""
The EVM follows Ethereum (chain-spec feature ``evm_conformance``, docs/EVM_CONFORMANCE.md).

Ethereum's state tests, run through QRDX's executor (scripts/conformance/eest_state_tests.py),
found where it did not: the intrinsic gas was a floor on the charge instead of coming out of the
gas limit (a message ran with the whole limit, so a transaction got its calldata and signature
check free whenever it executed more), the payer was charged after the message instead of
buying the gas up front, no refund was given, the sender and recipient started cold, a creation
did not check for an account at its address, and MODEXP of an empty base returned 0. Each test
here shows the rule with the feature, and the old behavior without it (the rule is a fork).

With QRDX_EEST_FIXTURES set to an extracted fixtures release (scripts/conformance/
fetch_eest.sh), the last test runs every Shanghai state test as well.
"""

import os

import pytest
from test_evm_world import ALICE, Chain, chain, deploy_code, word  # noqa: F401  (fixture)

from qrdx import chain_spec
from qrdx.contracts.evm_world import EvmWorld, run
from qrdx.contracts.native_token_evm import EvmSection, TokenWorld

PRICE = 7
STORE_SLOT0 = bytes.fromhex("36600f5760005460005260206000f35b60003560005500")  # (test_evm_world)
ORIGIN_BALANCE = bytes.fromhex("3231" "60005260206000f3")  # BALANCE(ORIGIN)
SELF_BALANCE_GAS = bytes.fromhex("5a303150" "5a900360005260206000f3")  # gas of BALANCE(ADDRESS)
CLEAR_SLOT0 = bytes.fromhex("600060005500")  # SSTORE(0, 0)


@pytest.fixture(params=[True, False], ids=["evm_conformance", "before"])
def conform(request, monkeypatch):
    if not request.param:
        active = chain_spec.is_active
        monkeypatch.setattr(chain_spec, "is_active",
                            lambda f, h=None: f != "evm_conformance" and active(f, h))
    return request.param


async def _send(chain, to, data=b"", gas=100_000, intrinsic=21_000, value=0, price=PRICE):
    """A transaction as the node's path runs it: the gas limit, its price and intrinsic gas."""
    chain.height += 1
    chain.sm.reset_cache()
    world = EvmWorld(chain.sm, tokens=TokenWorld(chain.db, EvmSection()))
    r = await run(world, lambda: chain.ex.execute(
        ALICE, to, value, data, gas, price, intrinsic_gas=intrinsic, block_number=chain.height,
        world=world), preload=[ALICE, to])
    await chain.sm.commit(chain.height)
    await chain.db.connection.commit()
    return r


async def test_the_intrinsic_gas_comes_out_of_the_gas_limit(chain, conform):
    store = await chain.deploy(STORE_SLOT0)
    r = await _send(chain, store, word(5), gas=21_000 + 3_000)  # a new slot needs ~22,200 more
    assert r.success is (not conform)  # (before: the message ran with all 24,000)
    assert int.from_bytes(await chain.sm.get_storage(store.hex(), bytes(32)), "big") == (
        0 if conform else 5)


async def test_the_payer_pays_intrinsic_plus_execution_less_the_refund(chain, conform):
    clear = await chain.deploy(CLEAR_SLOT0)
    await chain.sm.set_storage(clear.hex(), bytes(32), word(1))
    await chain.sm.commit(chain.height)
    before = await chain.sm.get_balance(ALICE.hex())
    r = await _send(chain, clear)
    assert r.success
    # PUSH1 PUSH1 (3 + 3) and clearing a cold slot (2,100 + 2,900); refund 4,800 (EIP-3529).
    assert r.gas_used == (21_000 + 5_006 - 4_800 if conform else 21_000)
    assert before - await chain.sm.get_balance(ALICE.hex()) == r.gas_used * PRICE


async def test_the_gas_limit_is_paid_for_before_the_message_runs(chain, conform):
    probe = await chain.deploy(ORIGIN_BALANCE)
    before = await chain.sm.get_balance(ALICE.hex())
    r = await _send(chain, probe, gas=60_000)
    assert r.success
    seen = int.from_bytes(r.output, "big")
    assert seen == (before - 60_000 * PRICE if conform else before)


async def test_the_sender_and_recipient_start_warm(chain, conform):
    probe = await chain.deploy(SELF_BALANCE_GAS)
    r = await _send(chain, probe)
    assert int.from_bytes(r.output, "big") == (106 if conform else 2_606)  # EIP-2929


async def test_a_transaction_below_its_intrinsic_gas_does_not_run(chain, conform):
    store = await chain.deploy(STORE_SLOT0)
    r = await _send(chain, store, word(5), gas=20_000)
    assert not r.success
    assert not int.from_bytes(await chain.sm.get_storage(store.hex(), bytes(32)), "big")


async def test_a_creation_onto_an_existing_account_fails(chain, conform):
    nonce = await chain.sm.get_nonce(ALICE.hex())
    target = chain.ex._compute_create_address(ALICE, nonce)
    await chain.sm.set_code(target.hex(), b"\x00", chain.height, ALICE.hex())
    await chain.sm.commit(chain.height)
    r = await _send(chain, None, deploy_code(b"\x60\x01"), gas=200_000, intrinsic=53_000)
    assert r.success is (not conform)
    assert (await chain.sm.get_code(target.hex())) == (b"\x00" if conform else b"\x60\x01")


async def test_modexp_of_an_empty_base_is_the_exponent_of_zero(chain, conform):
    # base length 0, exponent length 1, modulus length 1: 0 ** 0 mod 2 = 1
    data = word(0) + word(1) + word(1) + b"\x00" + b"\x02"
    r = await chain.call((5).to_bytes(20, "big"), data)
    assert r.output == (b"\x01" if conform else b"\x00")


async def test_the_cross_chain_submit_precompile_is_retired(chain, conform):
    r = await chain.call((0x0202).to_bytes(20, "big"), (1).to_bytes(4, "big") + b"\xaa")
    assert r.success is (not conform)
    if conform:
        assert b"retired" in r.output


async def test_an_estimate_is_enough_to_send(chain):
    store = await chain.deploy(STORE_SLOT0)
    world = EvmWorld(chain.sm, tokens=TokenWorld(chain.db))
    estimate = await run(world, lambda: chain.ex.estimate_gas(
        ALICE, store, word(5), world=world, block_number=chain.height + 1), preload=[ALICE, store])
    r = await _send(chain, store, word(5), gas=estimate, intrinsic=21_000 + 16 + 31 * 4)
    assert r.success, r.error


@pytest.mark.skipif(not os.environ.get("QRDX_EEST_FIXTURES"),
                    reason="QRDX_EEST_FIXTURES: an extracted fixtures release (fetch_eest.sh)")
@pytest.mark.timeout(1800)
async def test_ethereums_state_tests():
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "conformance"))
    import eest_state_tests as E

    cases = E.load_cases(os.environ["QRDX_EEST_FIXTURES"])
    assert len(cases) > 1000
    differ = []
    async with E.Runner() as runner:
        for case in cases:
            out = await runner.run(case)
            if (out.diffs or out.error) and (out.error or not E.known(case.name)):
                differ.append(f"{case.name}: {out.error or out.diffs[:2]}")
    assert not differ, "\n".join(differ[:20])
