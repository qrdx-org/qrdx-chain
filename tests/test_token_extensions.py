"""
Token-2022-style extensions on the native token standard, and ERC-777 operators
(qrdx/exchange/tokens.py, docs/NATIVE_TOKENS.md §7) — through the exchange's TOKEN_*
operations and through the EVM (each token's precompile):

metadata with an update authority · a transfer fee withheld at the token's address and
withdrawn by its authority (rate changes are delayed) · non-transferable · default-frozen ·
permanent delegate · pausable · memos · operators (authorized and default) — with the supply
equal to the sum of balances throughout, and a plain token committed exactly as before.
"""
from decimal import Decimal

import pytest

from qrdx.contracts.native_token_evm import (
    AUTHORIZED_TOPIC, BURNED_TOPIC, SENT_TOPIC, SIGNATURES, TRANSFER_TOPIC, _selector)
from qrdx.crypto.account_id import to_account_id
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import tokens as TK

D = Decimal
ISSUER, ALICE, BOB, CAROL = ("0xPQ" + c * 64 for c in "abcd")
_nonces = {}


def _tx(sender, op, **params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=10_000_000, gas_price=10**9)


@pytest.fixture
def mgr():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.enforce_spot_settlement = True
    m.begin_block(1, 1_700_000_000.0)
    yield m
    ExchangeStateManager.reset_instance()


def run(m, sender, op, **params):
    return m.process_transaction(_tx(sender, op, **params))


def ok(m, sender, op, **params):
    r = run(m, sender, op, **params)
    assert r.success, r.error
    return r


def deploy(m, supply="1000", **ext):
    r = ok(m, ISSUER, Op.TOKEN_DEPLOY, name="Ext Token", symbol="EXT", decimals=6,
           total_supply=supply, mint_authority=ISSUER, freeze_authority=ISSUER, **ext)
    token = r.data["token_address"]
    for who in (ALICE, BOB, CAROL, token):
        m.set_available_token_balance(who, token, D(0))
    m.set_available_token_balance(ISSUER, token, D(supply))
    return token


def bal(m, who, token):
    return m.available_token_balance(who, token)


def supply_is_the_sum_of_balances(m, token):
    total = sum((v for (h, t), v in m.token_balance_deltas().items() if t == token), D(0))
    assert total == m.tokens.get(token).supply, (total, m.tokens.get(token).supply)


# ── a plain token is committed exactly as before ─────────────────────────────

def test_a_plain_token_has_no_extensions_and_the_old_commitment(mgr):
    token = deploy(mgr)
    t = mgr.tokens.get(token)
    assert t.extensions() == {} and t.summary()["extensions"] == {}
    entry = mgr.tokens.canonical()["tokens"][token]
    assert len(entry) == 9                              # the pre-extension shape
    assert set(mgr.tokens.canonical()) == {"tokens", "allowances", "frozen"}


# ── metadata ────────────────────────────────────────────────────────────────

def test_metadata_with_an_update_authority(mgr):
    token = deploy(mgr, uri="ipfs://meta", metadata={"website": "qrdx.org"})
    t = mgr.tokens.get(token)
    assert t.extensions()["metadata"] == {"uri": "ipfs://meta", "fields": {"website": "qrdx.org"},
                                          "update_authority": ISSUER}
    r = run(mgr, ALICE, Op.TOKEN_UPDATE_METADATA, token_address=token, uri="x")
    assert not r.success and "metadata authority" in r.error
    r = ok(mgr, ISSUER, Op.TOKEN_UPDATE_METADATA, token_address=token, name="Renamed",
           uri="ipfs://v2", fields={"website": None, "twitter": "@qrdx"})
    assert (t.name, t.uri, t.fields) == ("Renamed", "ipfs://v2", {"twitter": "@qrdx"})
    assert r.data["fields"] == {"twitter": "@qrdx"}
    ok(mgr, ISSUER, Op.TOKEN_SET_AUTHORITY, token_address=token, authority="metadata",
       new_authority="")
    r = run(mgr, ISSUER, Op.TOKEN_UPDATE_METADATA, token_address=token, uri="y")
    assert not r.success and "immutable" in r.error


@pytest.mark.parametrize("params, error", [
    ({"uri": "x" * 300}, "uri"),
    ({"metadata": {f"k{i}": "v" for i in range(17)}}, "fields"),
    ({"transfer_fee_bps": 10_001}, "transfer_fee_bps"),
    ({"transfer_fee_bps": 5, "non_transferable": True}, "non-transferable"),
    ({"default_frozen": True, "freeze_authority": ""}, "freeze authority"),
    ({"default_operators": [f"0x{i:040x}" for i in range(1, 10)]}, "default operators"),
])
def test_bad_extension_parameters_are_refused(mgr, params, error):
    base = dict(name="T", symbol="T", total_supply="1", freeze_authority=ISSUER)
    base.update(params)
    r = run(mgr, ISSUER, Op.TOKEN_DEPLOY, **base)
    assert not r.success and error in r.error, r.error


# ── transfer fee ─────────────────────────────────────────────────────────────

def test_a_transfer_fee_is_withheld_and_withdrawn(mgr):
    token = deploy(mgr, transfer_fee_bps=100, max_transfer_fee="5")   # 1%, at most 5
    r = ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="100")
    assert (r.data["fee"], r.data["received"]) == ("1", "99")
    assert bal(mgr, ALICE, token) == 99 and bal(mgr, token, token) == 1
    ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=BOB, amount="800")
    assert bal(mgr, BOB, token) == 795 and bal(mgr, token, token) == 6     # capped at 5
    # transfer_from pays it too
    ok(mgr, ALICE, Op.TOKEN_APPROVE, token_address=token, spender=CAROL, amount="10")
    r = ok(mgr, CAROL, Op.TOKEN_TRANSFER_FROM, token_address=token,
           **{"from": ALICE, "to": CAROL, "amount": "10"})
    assert r.data["fee"] == "0.1" and bal(mgr, CAROL, token) == D("9.9")
    supply_is_the_sum_of_balances(mgr, token)
    # only the withdraw authority collects
    r = run(mgr, ALICE, Op.TOKEN_WITHDRAW_FEES, token_address=token)
    assert not r.success and "withdraw authority" in r.error
    r = ok(mgr, ISSUER, Op.TOKEN_WITHDRAW_FEES, token_address=token, to=CAROL)
    assert D(r.data["amount"]) == D("6.1") and bal(mgr, token, token) == 0
    assert bal(mgr, CAROL, token) == D("16.0")
    supply_is_the_sum_of_balances(mgr, token)


def test_a_new_fee_rate_applies_only_after_the_delay(mgr):
    token = deploy(mgr, transfer_fee_bps=0)
    r = run(mgr, ALICE, Op.TOKEN_SET_TRANSFER_FEE, token_address=token, transfer_fee_bps=50)
    assert not r.success and "fee authority" in r.error
    r = ok(mgr, ISSUER, Op.TOKEN_SET_TRANSFER_FEE, token_address=token, transfer_fee_bps=500)
    assert r.data["from_height"] == 1 + TK.FEE_UPDATE_DELAY_BLOCKS
    r = ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="100")
    assert "fee" not in r.data                                    # still the old rate (0)
    mgr.commit_block()
    mgr.begin_block(1 + TK.FEE_UPDATE_DELAY_BLOCKS, 1_700_001_000.0)
    r = ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="100")
    assert r.data["fee"] == "5"


def test_fee_and_soulbound_tokens_cannot_be_pooled(mgr):
    for ext in ({"transfer_fee_bps": 10}, {"non_transferable": True}):
        token = deploy(mgr, **ext)
        mgr.set_available_balance(ISSUER, D(10 ** 9))
        r = run(mgr, ISSUER, Op.CREATE_POOL, token0=token, token1="QRDX", fee_tier=3000,
                pool_type="STANDARD", initial_price="1", stake_amount="10000")
        assert not r.success and "cannot be pooled" in r.error


# ── non-transferable, default-frozen, permanent delegate, pausable ───────────

def test_a_non_transferable_token_mints_and_burns_but_never_moves(mgr):
    token = deploy(mgr, supply="0", non_transferable=True)
    ok(mgr, ISSUER, Op.TOKEN_MINT, token_address=token, to=ALICE, amount="1")
    r = run(mgr, ALICE, Op.TOKEN_TRANSFER, token_address=token, to=BOB, amount="1")
    assert not r.success and "non-transferable" in r.error
    ok(mgr, ALICE, Op.TOKEN_BURN, token_address=token, amount="1")
    assert mgr.tokens.get(token).supply == 0


def test_a_default_frozen_token_needs_each_account_thawed(mgr):
    token = deploy(mgr, default_frozen=True)
    ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="10")  # issuer thawed
    r = run(mgr, ALICE, Op.TOKEN_TRANSFER, token_address=token, to=BOB, amount="1")
    assert not r.success and "frozen" in r.error
    ok(mgr, ISSUER, Op.TOKEN_THAW, token_address=token, account=ALICE)
    ok(mgr, ALICE, Op.TOKEN_TRANSFER, token_address=token, to=BOB, amount="1")
    ok(mgr, ISSUER, Op.TOKEN_FREEZE, token_address=token, account=ALICE)
    assert not run(mgr, ALICE, Op.TOKEN_TRANSFER, token_address=token, to=BOB, amount="1").success
    assert mgr.tokens.is_frozen(token, BOB) and not mgr.tokens.is_frozen(token, ISSUER)
    assert "thawed" in mgr.tokens.canonical()


def test_the_permanent_delegate_moves_and_burns_anyones_balance(mgr):
    token = deploy(mgr, permanent_delegate=CAROL)
    ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="10")
    r = ok(mgr, CAROL, Op.TOKEN_TRANSFER_FROM, token_address=token,
           **{"from": ALICE, "to": BOB, "amount": "4"})               # no allowance needed
    assert r.data["via"] == "permanent_delegate" and bal(mgr, BOB, token) == 4
    r = ok(mgr, CAROL, Op.TOKEN_BURN, token_address=token, amount="3", **{"from": ALICE})
    assert r.data["via"] == "permanent_delegate" and bal(mgr, ALICE, token) == 3
    r = run(mgr, BOB, Op.TOKEN_BURN, token_address=token, amount="1", **{"from": ALICE})
    assert not r.success and "permanent delegate" in r.error
    ok(mgr, CAROL, Op.TOKEN_SET_AUTHORITY, token_address=token, authority="permanent_delegate",
       new_authority="")
    assert not run(mgr, CAROL, Op.TOKEN_TRANSFER_FROM, token_address=token,
                   **{"from": ALICE, "to": BOB, "amount": "1"}).success
    supply_is_the_sum_of_balances(mgr, token)


def test_a_paused_token_does_not_move_mint_or_burn(mgr):
    token = deploy(mgr, pausable=True)
    assert not run(mgr, ALICE, Op.TOKEN_PAUSE, token_address=token).success
    ok(mgr, ISSUER, Op.TOKEN_PAUSE, token_address=token)
    for op, params in ((Op.TOKEN_TRANSFER, {"to": ALICE, "amount": "1"}),
                       (Op.TOKEN_MINT, {"amount": "1"}), (Op.TOKEN_BURN, {"amount": "1"})):
        r = run(mgr, ISSUER, op, token_address=token, **params)
        assert not r.success and "paused" in r.error, (op, r.error)
    # a spot move of it is refused at settlement
    with pytest.raises(ValueError, match="paused"):
        mgr._settle_token_move(ISSUER, ALICE, token, D(1))
    ok(mgr, ISSUER, Op.TOKEN_RESUME, token_address=token)
    ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="1")


def test_a_memo_rides_a_transfer(mgr):
    token = deploy(mgr)
    r = ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="1",
           memo="invoice 42")
    assert r.data["memo"] == "invoice 42"
    r = run(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="1",
            memo="x" * 300)
    assert not r.success and "memo" in r.error


# ── ERC-777 operators ───────────────────────────────────────────────────────

def test_an_operator_moves_and_burns_without_an_allowance(mgr):
    token = deploy(mgr)
    ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="10")
    assert not run(mgr, BOB, Op.TOKEN_TRANSFER_FROM, token_address=token,
                   **{"from": ALICE, "to": BOB, "amount": "1"}).success
    ok(mgr, ALICE, Op.TOKEN_AUTHORIZE_OPERATOR, token_address=token, operator=BOB)
    r = ok(mgr, BOB, Op.TOKEN_TRANSFER_FROM, token_address=token,
           **{"from": ALICE, "to": CAROL, "amount": "4"})
    assert r.data["via"] == "operator" and "allowance_left" not in r.data
    r = ok(mgr, BOB, Op.TOKEN_BURN, token_address=token, amount="1", **{"from": ALICE})
    assert r.data["via"] == "operator"
    ok(mgr, ALICE, Op.TOKEN_REVOKE_OPERATOR, token_address=token, operator=BOB)
    assert not run(mgr, BOB, Op.TOKEN_TRANSFER_FROM, token_address=token,
                   **{"from": ALICE, "to": CAROL, "amount": "1"}).success
    assert not run(mgr, ALICE, Op.TOKEN_AUTHORIZE_OPERATOR, token_address=token,
                   operator=ALICE).success                          # always its own
    supply_is_the_sum_of_balances(mgr, token)


def test_default_operators_until_a_holder_revokes(mgr):
    token = deploy(mgr, default_operators=[CAROL])
    ok(mgr, ISSUER, Op.TOKEN_TRANSFER, token_address=token, to=ALICE, amount="10")
    assert mgr.tokens.is_operator(token, ALICE, CAROL)
    ok(mgr, CAROL, Op.TOKEN_TRANSFER_FROM, token_address=token,
       **{"from": ALICE, "to": CAROL, "amount": "1"})
    ok(mgr, ALICE, Op.TOKEN_REVOKE_OPERATOR, token_address=token, operator=CAROL)
    assert not mgr.tokens.is_operator(token, ALICE, CAROL)
    assert mgr.tokens.is_operator(token, ISSUER, CAROL)            # others keep it
    ok(mgr, ALICE, Op.TOKEN_AUTHORIZE_OPERATOR, token_address=token, operator=CAROL)
    assert mgr.tokens.is_operator(token, ALICE, CAROL)


def test_operators_per_holder_are_bounded(mgr, monkeypatch):
    monkeypatch.setattr(TK, "MAX_OPERATORS_PER_HOLDER", 2)
    token = deploy(mgr)
    for op in (BOB, CAROL):
        ok(mgr, ALICE, Op.TOKEN_AUTHORIZE_OPERATOR, token_address=token, operator=op)
    r = run(mgr, ALICE, Op.TOKEN_AUTHORIZE_OPERATOR, token_address=token, operator=ISSUER)
    assert not r.success and "at most 2" in r.error


def test_extension_state_is_committed_and_reverts_with_a_block(mgr):
    token = deploy(mgr, pausable=True, default_frozen=True)
    hashes = [mgr.tokens.state_hash()]
    snap = mgr.take_snapshot()
    ok(mgr, ALICE, Op.TOKEN_AUTHORIZE_OPERATOR, token_address=token, operator=BOB)
    hashes.append(mgr.tokens.state_hash())
    ok(mgr, ISSUER, Op.TOKEN_PAUSE, token_address=token)
    hashes.append(mgr.tokens.state_hash())
    ok(mgr, ISSUER, Op.TOKEN_THAW, token_address=token, account=ALICE)
    hashes.append(mgr.tokens.state_hash())
    assert len(set(hashes)) == len(hashes)
    mgr._restore_snapshot(snap)
    assert mgr.tokens.state_hash() == hashes[0]
    assert not mgr.tokens.get(token).paused and not mgr.tokens.operators


# ── the same rules inside the EVM ───────────────────────────────────────────

from test_evm_world import ALICE as E_ALICE, BOB as E_BOB, CAROL as E_CAROL  # noqa: E402
from test_evm_world import _hex, addr_word, chain, word  # noqa: E402,F401
from qrdx.exchange import block_processor as BP  # noqa: E402


def sel(name):
    return bytes.fromhex(_selector(SIGNATURES[name]))


def _dyn(*parts: bytes) -> bytes:
    """ABI tail for trailing dynamic ``bytes`` arguments (offsets after ``static`` words)."""
    return b"".join(parts)


async def _ext_token(chain, holder: bytes, supply="1000", **ext):
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, 1_700_000_000.0)
    r = mgr.process_transaction(ExchangeTransaction(
        op_type=Op.TOKEN_DEPLOY, sender=ISSUER, nonce=len(mgr.tokens.tokens),
        params={"name": "Ext", "symbol": "EXT", "decimals": 6, "total_supply": supply,
                "freeze_authority": ISSUER, **ext}, gas_limit=1_000_000))
    assert r.success, r.error
    mgr.commit_block()
    await BP.flush_token_balance_deltas(chain.db, mgr)
    token = r.data["token_address"]
    await chain.db.apply_token_balance_delta(token, ISSUER, -D(supply))
    await chain.db.apply_token_balance_delta(token, _hex(holder), D(supply))
    await chain.db.connection.commit()
    return bytes.fromhex(token[2:])


async def _bal(chain, token, who):
    return await chain.db.get_token_balance(_hex(token), _hex(who))


def _send(to: bytes, units: int, data: bytes = b"") -> bytes:
    pad = data + b"\0" * ((-len(data)) % 32)
    return sel("send") + addr_word(to) + word(units) + word(96) + word(len(data)) + pad


async def test_evm_transfer_withholds_the_fee_and_logs_it(chain):
    token = await _ext_token(chain, E_ALICE, transfer_fee_bps=100)
    r = await chain.tx(E_ALICE, token, sel("transfer") + addr_word(E_BOB) + word(100 * 10 ** 6))
    assert r.success, r.error
    assert await _bal(chain, token, E_BOB) == 99 and await _bal(chain, token, token) == 1
    net, fee = r.logs
    assert int.from_bytes(net[2], "big") == 99 * 10 ** 6
    assert fee[1][2] == int.from_bytes(token, "big") and int.from_bytes(fee[2], "big") == 10 ** 6


async def test_evm_refuses_paused_and_soulbound_tokens(chain):
    soulbound = await _ext_token(chain, E_ALICE, non_transferable=True)
    r = await chain.tx(E_ALICE, soulbound, sel("transfer") + addr_word(E_BOB) + word(1))
    assert not r.success
    pausable = await _ext_token(chain, E_ALICE, pausable=True, pause_authority=ISSUER)
    ExchangeStateManager.get_instance().tokens.set_paused(_hex(pausable), ISSUER, True)
    out = (await chain.call(pausable, sel("paused"))).output
    assert int.from_bytes(out, "big") == 1
    r = await chain.tx(E_ALICE, pausable, sel("transfer") + addr_word(E_BOB) + word(1))
    assert not r.success and await _bal(chain, pausable, E_BOB) == 0


async def test_erc777_operators_send_and_burn(chain):
    token = await _ext_token(chain, E_ALICE, uri="ipfs://ext", default_operators=[_hex(E_CAROL)])
    reg = ExchangeStateManager.get_instance().tokens
    # metadata (ERC-1046) and the default operators
    from eth_abi import decode
    assert decode(["string"], (await chain.call(token, sel("tokenURI"))).output) == ("ipfs://ext",)
    assert decode(["address[]"], (await chain.call(token, sel("defaultOperators"))).output) == \
        ((_hex(E_CAROL),),)
    # Alice authorizes Bob through the EVM: the registry has it once the section is accepted
    r = await chain.tx(E_ALICE, token, sel("authorizeOperator") + addr_word(E_BOB))
    assert r.success and r.logs[0][1][0] == AUTHORIZED_TOPIC
    assert reg.is_operator(_hex(token), _hex(E_ALICE), _hex(E_BOB))
    is_op = sel("isOperatorFor") + addr_word(E_BOB) + addr_word(E_ALICE)
    assert int.from_bytes((await chain.call(token, is_op)).output, "big") == 1
    # Bob moves Alice's tokens with operatorSend: Sent + Transfer
    payload = (sel("operatorSend") + addr_word(E_ALICE) + addr_word(E_CAROL) + word(5 * 10 ** 6)
               + word(160) + word(224) + word(2) + b"hi".ljust(32, b"\0") + word(0))
    r = await chain.tx(E_BOB, token, payload)
    assert r.success, r.error
    assert [log[1][0] for log in r.logs] == [SENT_TOPIC, TRANSFER_TOPIC]
    assert await _bal(chain, token, E_CAROL) == 5
    # a plain send with data
    r = await chain.tx(E_ALICE, token, _send(E_BOB, 10 ** 6, b"memo"))
    assert r.success and await _bal(chain, token, E_BOB) == 1
    # a stranger cannot operatorSend
    r = await chain.tx(E_BOB, token, payload.replace(addr_word(E_ALICE), addr_word(E_CAROL), 1))
    assert not r.success
    # burn reduces the supply
    before = reg.get(_hex(token)).supply
    burn = sel("burn") + word(2 * 10 ** 6) + word(64) + word(0)
    r = await chain.tx(E_ALICE, token, burn)
    assert r.success and r.logs[0][1][0] == BURNED_TOPIC
    assert reg.get(_hex(token)).supply == before - 2
    assert await _bal(chain, token, E_ALICE) == 1000 - 5 - 1 - 2
    # revoke
    assert (await chain.tx(E_ALICE, token, sel("revokeOperator") + addr_word(E_BOB))).success
    assert not reg.is_operator(_hex(token), _hex(E_ALICE), _hex(E_BOB))


# ── the CLI ─────────────────────────────────────────────────────────────────

def test_the_cli_deploys_extensions_and_manages_them(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from qrdx.cli import perp as P
    from qrdx.cli import token as T
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange.submission import parse_exchange_tx
    from qrdx.wallet_v2 import PQWallet
    wallet = PQWallet(private_key=PQPrivateKey.generate())
    calls = []

    def fake_rpc(node, method, params=None, timeout=20.0):
        calls.append((method, params))
        if method == "exchange_getNonce":
            return 0
        if method == "exchange_gasPrice":
            return 10 ** 9
        if method == "exchange_sendTransaction":
            return parse_exchange_tx(params[0]).tx_hash()
        raise AssertionError(method)

    for module in (P, T):
        monkeypatch.setattr(module, "rpc", fake_rpc)
    monkeypatch.setattr(P, "_signer", lambda wallet_file: wallet)
    wf = tmp_path / "w.json"
    wf.write_text("{}")

    def sent(args):
        r = CliRunner().invoke(T.token, args + ["--yes"])
        assert r.exit_code == 0, r.output
        tx = parse_exchange_tx(calls[-1][1][0])
        assert tx.verify()
        return tx

    tx = sent(["deploy", str(wf), "Ext", "EXT", "--supply", "10", "--uri", "ipfs://x",
               "--field", "site=qrdx.org", "--transfer-fee-bps", "25", "--pausable",
               "--freeze-authority", "self", "--default-frozen", "--default-operator", ALICE])
    assert tx.op_type == Op.TOKEN_DEPLOY
    p = tx.params
    assert (p["uri"], p["metadata"], p["transfer_fee_bps"], p["pausable"], p["default_frozen"],
            p["default_operators"]) == ("ipfs://x", {"site": "qrdx.org"}, 25, True, True, [ALICE])
    assert sent(["metadata", str(wf), "0xabc", "--uri", "ipfs://y", "--field", "site="]).params \
        == {"token_address": "0xabc", "uri": "ipfs://y", "fields": {"site": None}}
    assert sent(["set-fee", str(wf), "0xabc", "50"]).op_type == Op.TOKEN_SET_TRANSFER_FEE
    assert sent(["withdraw-fees", str(wf), "0xabc"]).op_type == Op.TOKEN_WITHDRAW_FEES
    assert sent(["pause", str(wf), "0xabc"]).op_type == Op.TOKEN_PAUSE
    assert sent(["resume", str(wf), "0xabc"]).op_type == Op.TOKEN_RESUME
    tx = sent(["operator", str(wf), "0xabc", BOB])
    assert tx.op_type == Op.TOKEN_AUTHORIZE_OPERATOR and tx.params["operator"] == BOB
    assert sent(["revoke-operator", str(wf), "0xabc", BOB]).op_type == Op.TOKEN_REVOKE_OPERATOR
    assert sent(["transfer", str(wf), "0xabc", BOB, "1", "--memo", "hi"]).params["memo"] == "hi"
    assert sent(["set-authority", str(wf), "0xabc", "pause", "none"]).params["authority"] == "pause"
