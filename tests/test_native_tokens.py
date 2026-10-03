"""
The native token standard (qrdx/exchange/tokens.py): mint and freeze authorities, mint, burn,
approvals and transfer_from, handing over or renouncing an authority, freezing — and the
invariants every one of them keeps: each token's supply equals the sum of its balances, a
refused operation changes nothing, any address form of one account is one holder, and the
registry is committed in the exchange root and restored with a reverted block.
"""
import random
from decimal import Decimal

import pytest

from qrdx.crypto.account_id import to_account_id
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import tokens as TK

D = Decimal
ALICE, BOB, CAROL, MINTER, FREEZER = ("0xPQ" + c * 64 for c in "abcde")
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


def deploy(m, supply="0", mint=MINTER, freeze=FREEZER, **extra):
    r = run(m, MINTER, ExchangeOpType.TOKEN_DEPLOY, name="Quantum USD", symbol="qUSD",
            decimals=6, total_supply=supply, mint_authority=mint, freeze_authority=freeze,
            **extra)
    assert r.success, r.error
    token = r.data["token_address"]
    for who in (ALICE, BOB, CAROL, MINTER, FREEZER):
        if m.available_token_balance(who, token) is None:
            m.set_available_token_balance(who, token, D(0))
    if D(supply) > 0:
        m.set_available_token_balance(MINTER, token, D(supply))
    return token


def balances(m, token):
    return {who: m.available_token_balance(who, token)
            for who in (ALICE, BOB, CAROL, MINTER, FREEZER)}


def supply_is_the_sum_of_balances(m, token):
    t = m.tokens.get(token)
    total = sum((v for (h, tok), v in m.token_balance_deltas().items() if tok == token), D(0))
    assert total == t.supply, (total, t.supply)


# ── deploy ─────────────────────────────────────────────────────────────────

def test_a_bridge_token_starts_at_zero_and_only_its_minter_mints(mgr):
    token = deploy(mgr)
    t = mgr.tokens.get(token)
    assert t.supply == 0 and t.decimals == 6 and t.mint_authority == MINTER
    r = run(mgr, ALICE, ExchangeOpType.TOKEN_MINT, token_address=token, amount="5")
    assert not r.success and "mint authority" in r.error
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_MINT, token_address=token, amount="250", to=ALICE)
    assert r.success and r.data["total_supply"] == "250"
    assert mgr.available_token_balance(ALICE, token) == 250
    supply_is_the_sum_of_balances(mgr, token)


def test_a_fixed_supply_token_can_never_mint(mgr):
    token = deploy(mgr, supply="1000", mint=None)
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_MINT, token_address=token, amount="1")
    assert not r.success and "fixed" in r.error


def test_max_supply_caps_minting(mgr):
    token = deploy(mgr, supply="10", max_supply="100")
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_MINT, token_address=token, amount="90").success
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_MINT, token_address=token, amount="0.000001")
    assert not r.success and "max supply" in r.error
    assert mgr.tokens.get(token).supply == 100


@pytest.mark.parametrize("params,error", [
    ({"name": "", "symbol": "X", "total_supply": "1"}, "name"),
    ({"name": "X", "symbol": "A:B", "total_supply": "1"}, "symbol"),
    ({"name": "X", "symbol": "X", "decimals": 19, "total_supply": "1"}, "decimals"),
    ({"name": "X", "symbol": "X"}, "initial supply or a mint authority"),
    ({"name": "X", "symbol": "X", "total_supply": "1.0000000000000000001"}, "18 decimal"),
    ({"name": "X", "symbol": "X", "total_supply": "10", "max_supply": "5"}, "max_supply"),
    ({"name": "X", "symbol": "X", "total_supply": "1", "mint_authority": "nonsense"}, "invalid address"),
])
def test_deploy_refuses_bad_parameters(mgr, params, error):
    r = run(mgr, ALICE, ExchangeOpType.TOKEN_DEPLOY, **params)
    assert not r.success and error in r.error, r.error
    assert mgr.tokens.tokens == {} and mgr.token_balance_deltas() == {}


# ── burn, approve, transfer_from ───────────────────────────────────────────

def test_burning_reduces_the_balance_and_the_supply(mgr):
    token = deploy(mgr, supply="1000")
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_BURN, token_address=token, amount="400")
    assert r.success and r.data["total_supply"] == "600"
    assert mgr.available_token_balance(MINTER, token) == 600
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_BURN, token_address=token, amount="601")
    assert not r.success and "insufficient" in r.error
    supply_is_the_sum_of_balances(mgr, token)


def test_a_spender_moves_tokens_within_its_allowance(mgr):
    token = deploy(mgr, supply="1000")
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=BOB,
               amount="300").success
    r = run(mgr, BOB, ExchangeOpType.TOKEN_TRANSFER_FROM, token_address=token, **{
        "from": MINTER, "to": CAROL, "amount": "200"})
    assert r.success and r.data["allowance_left"] == "100"
    before = balances(mgr, token)
    r = run(mgr, BOB, ExchangeOpType.TOKEN_TRANSFER_FROM, token_address=token, **{
        "from": MINTER, "to": BOB, "amount": "101"})
    assert not r.success and "allowance" in r.error and balances(mgr, token) == before
    r = run(mgr, CAROL, ExchangeOpType.TOKEN_TRANSFER_FROM, token_address=token, **{
        "from": MINTER, "to": CAROL, "amount": "1"})
    assert not r.success                                # Carol was never approved
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=BOB,
               amount="0").success                      # revoke
    assert mgr.tokens.allowance(token, MINTER, BOB) == 0 and not mgr.tokens.allowances
    assert mgr.available_token_balance(CAROL, token) == 200
    supply_is_the_sum_of_balances(mgr, token)


def test_an_account_is_one_holder_whatever_address_form_names_it(mgr):
    """An allowance granted by a PQ address is spent against its 0x account id, and the
    authority check accepts either form."""
    token = deploy(mgr, supply="50")
    minter_id = to_account_id(MINTER)
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=BOB,
               amount="10").success
    assert mgr.tokens.allowance(token, minter_id, to_account_id(BOB)) == 10
    assert mgr.tokens.get(token).mint_authority == MINTER          # shown as given
    assert TK.same(mgr.tokens.get(token).mint_authority, minter_id)


def test_allowances_per_owner_are_bounded(mgr, monkeypatch):
    monkeypatch.setattr(TK, "MAX_ALLOWANCES_PER_OWNER", 2)
    token = deploy(mgr, supply="50")
    for spender in (ALICE, BOB):
        assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token,
                   spender=spender, amount="1").success
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=CAROL,
            amount="1")
    assert not r.success and "at most 2" in r.error
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=ALICE,
               amount="5").success                      # changing one is fine
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=ALICE,
               amount="0").success
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=CAROL,
               amount="1").success                      # after a revoke there is room


# ── authorities ────────────────────────────────────────────────────────────

def test_an_authority_can_be_handed_over_or_renounced_for_good(mgr):
    token = deploy(mgr)
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_SET_AUTHORITY, token_address=token,
               authority="mint", new_authority=ALICE).success
    assert not run(mgr, MINTER, ExchangeOpType.TOKEN_MINT, token_address=token,
                   amount="1").success
    assert run(mgr, ALICE, ExchangeOpType.TOKEN_MINT, token_address=token, amount="1").success
    assert run(mgr, ALICE, ExchangeOpType.TOKEN_SET_AUTHORITY, token_address=token,
               authority="mint", new_authority="").success
    for who in (ALICE, MINTER):
        assert not run(mgr, who, ExchangeOpType.TOKEN_MINT, token_address=token,
                       amount="1").success
    r = run(mgr, ALICE, ExchangeOpType.TOKEN_SET_AUTHORITY, token_address=token,
            authority="mint", new_authority=ALICE)
    assert not r.success and "renounced" in r.error
    assert mgr.tokens.get(token).supply == 1


# ── freezing ───────────────────────────────────────────────────────────────

def test_a_frozen_account_cannot_move_its_balance_but_can_receive(mgr):
    token = deploy(mgr, supply="1000")
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_TRANSFER, token_address=token, to=ALICE,
               amount="100").success
    r = run(mgr, ALICE, ExchangeOpType.TOKEN_FREEZE, token_address=token, account=ALICE)
    assert not r.success and "freeze authority" in r.error
    assert run(mgr, FREEZER, ExchangeOpType.TOKEN_FREEZE, token_address=token,
               account=ALICE).success
    before = balances(mgr, token)
    for op, params in ((ExchangeOpType.TOKEN_TRANSFER, {"to": BOB, "amount": "1"}),
                       (ExchangeOpType.TOKEN_BURN, {"amount": "1"})):
        r = run(mgr, ALICE, op, token_address=token, **params)
        assert not r.success and "frozen" in r.error, r.error
    assert run(mgr, ALICE, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=BOB,
               amount="10").success                     # approving moves nothing …
    r = run(mgr, BOB, ExchangeOpType.TOKEN_TRANSFER_FROM, token_address=token,
            **{"from": ALICE, "to": BOB, "amount": "5"})
    assert not r.success and "frozen" in r.error        # … and spending it is refused
    assert balances(mgr, token) == before
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_TRANSFER, token_address=token, to=ALICE,
               amount="5").success                      # receiving still works
    assert run(mgr, FREEZER, ExchangeOpType.TOKEN_THAW, token_address=token,
               account=ALICE).success
    assert run(mgr, ALICE, ExchangeOpType.TOKEN_TRANSFER, token_address=token, to=BOB,
               amount="105").success
    supply_is_the_sum_of_balances(mgr, token)


def test_a_token_without_a_freeze_authority_can_never_freeze(mgr):
    token = deploy(mgr, supply="10", freeze=None)
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_FREEZE, token_address=token, account=ALICE)
    assert not r.success and "no freeze authority" in r.error


def test_a_frozen_account_cannot_trade_the_token_either(mgr):
    """The freeze holds on every debit path — here a swap through an AMM pool."""
    token = deploy(mgr, supply="1000000")
    r = run(mgr, MINTER, ExchangeOpType.TOKEN_DEPLOY, name="Other", symbol="OTH",
            total_supply="1000000")
    other = r.data["token_address"]
    mgr.set_available_balance(MINTER, D(1_000_000))
    for who in (ALICE, MINTER):
        mgr.set_available_token_balance(who, other, D(0))
    mgr.set_available_token_balance(MINTER, other, D(1_000_000))
    r = run(mgr, MINTER, ExchangeOpType.CREATE_POOL, token0=token, token1=other,
            fee_tier=3000, pool_type="STANDARD", initial_price="1", stake_amount="10000")
    assert r.success, r.error
    pid = r.data["pool_id"]
    holder = mgr.pool_holder_address(pid)
    for t in (token, other):
        mgr.set_available_token_balance(holder, t, D(0))
        mgr.set_available_token_balance(mgr.orderbook_escrow_address(
            ":".join(sorted((token, other)))), t, D(0))
    assert run(mgr, MINTER, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid, tick_lower=-6000,
               tick_upper=6000, amount="100000").success
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_TRANSFER, token_address=token, to=ALICE,
               amount="100").success
    assert run(mgr, FREEZER, ExchangeOpType.TOKEN_FREEZE, token_address=token,
               account=ALICE).success
    pool = mgr.pool_manager.get_pool(pid)
    digest, deltas = pool.state_digest(), mgr.token_balance_deltas()
    r = run(mgr, ALICE, ExchangeOpType.SWAP, token_in=token, token_out=other, amount_in="10")
    assert not r.success and "frozen" in r.error
    assert (pool.state_digest(), mgr.token_balance_deltas()) == (digest, deltas)


# ── commitment and reverts ─────────────────────────────────────────────────

def test_the_registry_is_in_the_exchange_root_and_reverts_with_a_block(mgr):
    token = deploy(mgr, supply="1000")
    roots = [mgr.compute_state_root()]
    snap = mgr.take_snapshot()
    for op, params in ((ExchangeOpType.TOKEN_APPROVE, {"spender": BOB, "amount": "1"}),
                       (ExchangeOpType.TOKEN_BURN, {"amount": "1"})):
        assert run(mgr, MINTER, op, token_address=token, **params).success
        roots.append(mgr.compute_state_root())
    assert run(mgr, FREEZER, ExchangeOpType.TOKEN_FREEZE, token_address=token,
               account=ALICE).success
    roots.append(mgr.compute_state_root())
    assert len(set(roots)) == len(roots)
    mgr._restore_snapshot(snap)
    assert mgr.tokens.get(token).supply == 1000 and not mgr.tokens.allowances
    assert not mgr.tokens.frozen


@pytest.mark.parametrize("seed", range(4))
def test_random_token_activity_keeps_supply_equal_to_balances(mgr, seed):
    rng = random.Random(seed)
    token = deploy(mgr, supply="10000")
    people = (ALICE, BOB, CAROL, MINTER)
    for _ in range(300):
        who = rng.choice(people)
        roll = rng.random()
        amount = str(D(rng.randint(1, 3000)) / D(rng.choice([1, 100, 1000000])))
        if roll < 0.15:
            op, params = ExchangeOpType.TOKEN_MINT, {"amount": amount, "to": rng.choice(people)}
            who = MINTER if rng.random() < 0.8 else who
        elif roll < 0.3:
            op, params = ExchangeOpType.TOKEN_BURN, {"amount": amount}
        elif roll < 0.45:
            op, params = ExchangeOpType.TOKEN_APPROVE, {"spender": rng.choice(people),
                                                        "amount": amount}
        elif roll < 0.6:
            op, params = ExchangeOpType.TOKEN_TRANSFER_FROM, {
                "from": rng.choice(people), "to": rng.choice(people), "amount": amount}
        elif roll < 0.7:
            op = rng.choice([ExchangeOpType.TOKEN_FREEZE, ExchangeOpType.TOKEN_THAW])
            params = {"account": rng.choice(people)}
            who = FREEZER
        else:
            op, params = ExchangeOpType.TOKEN_TRANSFER, {"to": rng.choice(people),
                                                         "amount": amount}
        before = (mgr.tokens.state_hash(), mgr.token_balance_deltas())
        r = run(mgr, who, op, token_address=token, **params)
        if not r.success:
            assert (mgr.tokens.state_hash(), mgr.token_balance_deltas()) == before, r.error
        supply_is_the_sum_of_balances(mgr, token)
        assert all(v >= 0 for v in balances(mgr, token).values())


# ── wallets: RPC, REST, CLI ────────────────────────────────────────────────

async def test_token_rpc(mgr):
    import json
    from types import SimpleNamespace
    from qrdx.rpc.modules.exchange import ExchangeModule
    from qrdx.rpc.server import RPCServer
    token = deploy(mgr, supply="100")
    assert run(mgr, MINTER, ExchangeOpType.TOKEN_APPROVE, token_address=token, spender=BOB,
               amount="7").success
    assert run(mgr, FREEZER, ExchangeOpType.TOKEN_FREEZE, token_address=token,
               account=ALICE).success

    class FakeDB:
        async def get_token_balance(self, token_address, address):
            return D(42)

    server = RPCServer(rate_limit=False)
    server.register_module(ExchangeModule(SimpleNamespace(db=FakeDB(), submitter=None)))

    async def call(method, *params):
        return json.loads(await server.handle_request(
            json.dumps({"jsonrpc": "2.0", "method": method, "params": list(params), "id": 1})))

    [listed] = (await call("exchange_getTokens"))["result"]
    assert listed["token_address"] == token and listed["mint_authority"] == MINTER
    info = (await call("exchange_getToken", token.upper().replace("0X", "0x")))["result"]
    assert info["total_supply"] == "100" and info["frozen_accounts"] == 1
    assert (await call("exchange_getToken", "0x" + "00" * 20))["error"]["code"] == -32001
    assert (await call("exchange_getAllowance", token, MINTER, BOB))["result"]["allowance"] == "7"
    assert (await call("exchange_getAllowance", token, MINTER, "garbage"))["error"]["code"] == -32602
    acct = (await call("exchange_getTokenAccount", token, ALICE))["result"]
    assert acct == {"token_address": token, "address": ALICE, "balance": "42", "frozen": True}


def test_the_node_serves_the_token_views():
    from qrdx.node import main
    paths = {getattr(r, "path", None) for r in main.app.routes}
    for path in ("/get_tokens", "/get_token", "/get_token_allowance", "/get_token_balance"):
        assert path in paths, path
    methods = main.rpc_server.get_methods()
    for name in ("exchange_getTokens", "exchange_getToken", "exchange_getAllowance",
                 "exchange_getTokenAccount"):
        assert name in methods, name


def test_the_cli_deploys_a_bridge_token_and_renounces_an_authority(monkeypatch, tmp_path):
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
            return 3
        if method == "exchange_sendTransaction":
            return parse_exchange_tx(params[0]).tx_hash()
        if method == "exchange_getTokenAccount":
            return {"balance": "5", "frozen": True}
        raise AssertionError(method)

    for module in (P, T):
        monkeypatch.setattr(module, "rpc", fake_rpc)
    monkeypatch.setattr(P, "_signer", lambda wallet_file: wallet)
    wallet_file = tmp_path / "w.json"
    wallet_file.write_text("{}")

    r = CliRunner().invoke(T.token, ["deploy", str(wallet_file), "Bridged USD", "qUSD",
                                     "--decimals", "6", "--mint-authority", "self", "--yes"])
    assert r.exit_code == 0, r.output
    sent = parse_exchange_tx(calls[-1][1][0])
    assert sent.verify() and sent.op_type == ExchangeOpType.TOKEN_DEPLOY and sent.nonce == 3
    assert sent.params == {"name": "Bridged USD", "symbol": "qUSD", "decimals": 6,
                           "total_supply": "0", "mint_authority": wallet.address,
                           "freeze_authority": ""}

    r = CliRunner().invoke(T.token, ["set-authority", str(wallet_file), "0xabc", "mint", "none",
                                     "--yes"])
    assert r.exit_code == 0 and "cannot be undone" in r.output, r.output
    sent = parse_exchange_tx(calls[-1][1][0])
    assert sent.op_type == ExchangeOpType.TOKEN_SET_AUTHORITY
    assert sent.params == {"token_address": "0xabc", "authority": "mint", "new_authority": ""}

    r = CliRunner().invoke(T.token, ["freeze", str(wallet_file), "0xabc", ALICE, "--yes"])
    assert r.exit_code == 0, r.output
    assert parse_exchange_tx(calls[-1][1][0]).op_type == ExchangeOpType.TOKEN_FREEZE

    r = CliRunner().invoke(T.token, ["balance", "0xabc", ALICE])
    assert r.exit_code == 0 and "5" in r.output and "frozen" in r.output


# ── web3: native tokens are ERC-20s inside the EVM (tests/test_evm_world.py) ──

async def test_eth_call_reads_a_native_token_through_the_evm(mgr, tmp_path):
    """MetaMask's import-token reads go through eth_call: the EVM runs the token's precompile
    over the ledger."""
    from types import SimpleNamespace
    from eth_abi import decode
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
    from qrdx.contracts.state import ContractStateManager
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.rpc.modules.eth import EthModule
    from qrdx.rpc.server import RPCError
    token = deploy(mgr, supply="5")
    db = await DatabaseSQLite.create(db_path=str(tmp_path / "n.db"))
    try:
        await db.apply_token_balance_delta(token, MINTER, D("5.0000019"))
        await db.connection.commit()
        sm = ContractStateManager(db)
        module = EthModule()
        module.context = SimpleNamespace(db=db, state_manager=sm,
                                         evm_executor=QRDXEVMExecutor(sm))
        who = to_account_id(MINTER)[2:]
        out = await module.call({"to": token, "data": "0x70a08231" + "00" * 12 + who})
        assert decode(["uint256"], bytes.fromhex(out[2:])) == (5_000_001,)   # 6 decimals, floor
        out = await module.call({"to": token, "data": "0x95d89b41"})
        assert decode(["string"], bytes.fromhex(out[2:])) == ("qUSD",)
        with pytest.raises(RPCError, match="execution reverted"):
            await module.call({"to": token, "data": "0xdeadbeef"})          # not ERC-20
    finally:
        await db.close()


def test_the_mempool_admits_a_token_transfer(mgr):
    """Native tokens move from the EVM now: a wallet's "send token" is an ordinary EVM
    transaction to the token's address (it used to be refused)."""
    from eth_account import Account
    from eth_utils import to_checksum_address
    from qrdx.contracts.evm_mempool import EVMMempool
    token = deploy(mgr, supply="5")
    signed = Account.sign_transaction({
        "nonce": 0, "gasPrice": 10 ** 9, "gas": 60_000, "to": to_checksum_address(token),
        "value": 0, "data": bytes.fromhex("a9059cbb") + bytes(64), "chainId": 1},
        "0x" + "11" * 32)
    raw = "0x" + bytes(getattr(signed, "raw_transaction", None) or signed.rawTransaction).hex()
    ok, err, _ = EVMMempool(nonce_provider=lambda addr: 0).admit(raw)
    assert ok, err


# ── fail-closed debits: the preload list covers every debit path ──────────

async def test_every_debit_path_is_preloaded():
    """Under enforcement a debit whose balance was not preloaded is refused. Drive each
    operation that debits a trader, a pool's holder or a book's escrow through the real
    preload (a ledger in which everyone is rich) and require that none is refused as "not
    loaded" — a gap in the list would otherwise turn into refused blocks. (ADD_LIQUIDITY named
    only by pool id was such a gap.)"""
    from qrdx.exchange import block_processor as BP

    class RichLedger:
        async def get_token_balance(self, token, holder):
            return D(10 ** 12)

        async def get_address_balance(self, address):
            return D(10 ** 12)

    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.enforce_spot_settlement = BP.ENFORCE_SPOT_SETTLEMENT
    m.enforce_orderbook_settlement = BP.ENFORCE_ORDERBOOK_SETTLEMENT
    m.enforce_pool_stake = BP.ENFORCE_POOL_STAKE
    db, height, results = RichLedger(), [0], []

    async def block(*txs):
        height[0] += 1
        m.begin_block(height[0], 1_700_000_000.0 + height[0])
        await BP.preload_sender_balances(db, txs, m)
        await BP.preload_token_balances(db, txs, m)
        out = [m.process_transaction(tx) for tx in txs]
        results.extend((tx.op_type.name, r) for tx, r in zip(txs, out))
        m.commit_block()
        return out

    try:
        a, b = await block(_tx(ALICE, ExchangeOpType.TOKEN_DEPLOY, name="A", symbol="AAA",
                               total_supply="1000000"),
                           _tx(ALICE, ExchangeOpType.TOKEN_DEPLOY, name="B", symbol="BBB",
                               total_supply="1000000"))
        ta, tb = a.data["token_address"], b.data["token_address"]
        pair = ":".join(sorted((ta, tb)))
        (pool,) = await block(_tx(ALICE, ExchangeOpType.CREATE_POOL, token0=ta, token1=tb,
                                  fee_tier=3000, pool_type="STANDARD", initial_price="1",
                                  stake_amount="10000"))
        pid = pool.data["pool_id"]
        (pos,) = await block(_tx(ALICE, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid,
                                 tick_lower=-6000, tick_upper=6000, amount="100000"))
        (order,) = await block(_tx(BOB, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy",
                                   order_type="limit", price="0.99", amount="5"))
        base, quote = pair.split(":")                        # Bob bids for the base
        await block(
            _tx(CAROL, ExchangeOpType.SWAP, token_in=base, token_out=quote, amount_in="1",
                venue="amm"),
            _tx(CAROL, ExchangeOpType.SWAP, token_in=base, token_out=quote, amount_in="1",
                venue="clob"),
            _tx(ALICE, ExchangeOpType.TOKEN_TRANSFER, token_address=ta.upper().replace("0X", "0x"),
                to=BOB, amount="3"),
            _tx(ALICE, ExchangeOpType.TOKEN_BURN, token_address=ta, amount="1"),
            _tx(ALICE, ExchangeOpType.TOKEN_APPROVE, token_address=ta, spender=CAROL,
                amount="5"))
        await block(
            _tx(CAROL, ExchangeOpType.TOKEN_TRANSFER_FROM, token_address=ta,
                **{"from": ALICE, "to": CAROL, "amount": "2"}),
            _tx(BOB, ExchangeOpType.CANCEL_ORDER, pair=pair, order_id=order.data["order_id"]),
            _tx(ALICE, ExchangeOpType.REMOVE_LIQUIDITY, pool_id=pid,
                position_id=pos.data["position_id"]))
        await block(_tx(ALICE, ExchangeOpType.REMOVE_POOL, pool_id=pid))
        refused = [(name, r.error) for name, r in results if not r.success]
        assert refused == [], refused
        assert [name for name, _ in results if name == "SWAP"] == ["SWAP", "SWAP"]
        sources = [r.data["source"] for name, r in results if name == "SWAP"]
        assert sources == ["amm", "clob"]                    # both venues settled
    finally:
        ExchangeStateManager.reset_instance()


def test_the_nodes_eth_call_accepts_the_standard_block_tag():
    """Every web3 client sends eth_call as [transaction, block]. The node's handler took the
    transaction alone, so every such call failed with an internal error (found by S20's live
    ERC-20 read)."""
    import ast
    import pathlib
    from qrdx.node import main
    tree = ast.parse(pathlib.Path(main.__file__).read_text())
    [handler] = [n for n in ast.walk(tree)
                 if isinstance(n, ast.AsyncFunctionDef) and n.name == "eth_call_handler"]
    assert [a.arg for a in handler.args.args] == ["call_params", "block_number"]
    assert len(handler.args.defaults) == 1
