"""``qrdx-wallet bridge`` (qrdx/cli/bridge.py) and the node's bridge_* reads (docs/BRIDGE.md)."""
from click.testing import CliRunner

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType
from qrdx.exchange.submission import parse_exchange_tx

ASSETS = [{"symbol": "USDC", "chain": 42161, "source_token": "0x" + "af" * 20, "decimals": 6,
           "token_address": "0x" + "01" * 20, "supply": "10", "mint_authority": "0xBRDG"}]


def _wire(monkeypatch):
    from qrdx.cli import bridge as B
    from qrdx.cli import perp as P
    from qrdx.wallet_v2 import PQWallet

    wallet = PQWallet(private_key=PQPrivateKey.generate())
    sent = []

    def fake_rpc(node, method, params=None, timeout=20.0):
        if method == "p2p_getStatus":
            from qrdx.constants import CHAIN_ID

            return {"network": {"chain_id": CHAIN_ID}}
        if method == "bridge_getAssets":
            return ASSETS
        if method == "exchange_getNonce":
            return 0
        if method == "exchange_gasPrice":
            return 10**9
        if method == "exchange_sendTransaction":
            tx = parse_exchange_tx(params[0])
            sent.append(tx)
            return tx.tx_hash()
        raise AssertionError(method)

    monkeypatch.setattr(P, "rpc", fake_rpc)
    monkeypatch.setattr(B, "rpc", fake_rpc)
    monkeypatch.setattr(P, "_signer", lambda wallet_file: wallet)
    return B, sent


def test_withdraw_names_the_asset_by_symbol(monkeypatch, tmp_path):
    B, sent = _wire(monkeypatch)
    w = tmp_path / "w.json"
    w.write_text("{}")
    r = CliRunner().invoke(B.bridge, ["withdraw", str(w), "usdc", "12.5", "0x" + "34" * 20, "--yes"])
    assert r.exit_code == 0, r.output
    (tx,) = sent
    assert tx.verify() and tx.op_type == ExchangeOpType.BRIDGE_WITHDRAW
    assert tx.params == {"token_address": "0x" + "01" * 20, "amount": "12.5",
                         "to": "0x" + "34" * 20}
    r = CliRunner().invoke(B.bridge, ["withdraw", str(w), "DAI", "1", "0x" + "34" * 20, "--yes"])
    assert r.exit_code != 0 and "bridged: USDC" in r.output and len(sent) == 1


def test_the_node_serves_the_bridge_reads_and_the_wallet_has_the_group():
    from qrdx.cli.wallet import cli
    from qrdx.node import main

    methods = main.rpc_server.get_methods()
    for name in ("bridge_getAssets", "bridge_getDeposit", "bridge_getWithdrawals"):
        assert name in methods, name
    assert "bridge" in cli.commands
