"""
``qrdx-wallet stake`` (qrdx/cli/stake.py). Staking had no wallet support: STAKE_DEPOSIT and
STAKE_EXIT were posted by hand to /submit_exchange_tx (docs/KNOWN_ISSUES.md).
"""
from click.testing import CliRunner

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType
from qrdx.exchange.submission import parse_exchange_tx


def _wire(monkeypatch, validators=()):
    from qrdx.cli import perp as P
    from qrdx.cli import stake as S
    from qrdx.wallet_v2 import PQWallet

    wallet = PQWallet(private_key=PQPrivateKey.generate())
    sent = []

    def fake_rpc(node, method, params=None, timeout=20.0):
        if method == "p2p_getStatus":
            from qrdx.constants import CHAIN_ID

            return {"network": {"chain_id": CHAIN_ID}}
        if method == "exchange_getNonce":
            return 3
        if method == "exchange_gasPrice":
            return 10**9
        if method == "exchange_sendTransaction":
            tx = parse_exchange_tx(params[0])
            sent.append(tx)
            return tx.tx_hash()
        raise AssertionError(method)

    monkeypatch.setattr(P, "rpc", fake_rpc)
    monkeypatch.setattr(P, "_signer", lambda wallet_file: wallet)
    monkeypatch.setattr(S, "_validators", lambda node: list(validators))
    return S, wallet, sent


def test_deposit_signs_a_stake_deposit_with_the_wallets_own_key(monkeypatch, tmp_path):
    S, wallet, sent = _wire(monkeypatch)
    w = tmp_path / "v.json"
    w.write_text("{}")
    r = CliRunner().invoke(S.stake, ["deposit", str(w), "150000", "--yes"])
    assert r.exit_code == 0, r.output
    (tx,) = sent
    assert tx.verify() and tx.sender == wallet.address and tx.nonce == 3
    assert tx.op_type == ExchangeOpType.STAKE_DEPOSIT
    assert tx.params == {"stake_amount": "150000",
                         "validator_public_key": wallet.public_key.hex()}


def test_deposit_below_the_minimum_is_refused_before_signing(monkeypatch, tmp_path):
    S, _wallet, sent = _wire(monkeypatch)
    w = tmp_path / "v.json"
    w.write_text("{}")
    r = CliRunner().invoke(S.stake, ["deposit", str(w), "5000", "--yes"])
    assert r.exit_code != 0 and "at least" in r.output and sent == []


def test_exit_signs_a_stake_exit(monkeypatch, tmp_path):
    S, wallet, sent = _wire(monkeypatch)
    w = tmp_path / "v.json"
    w.write_text("{}")
    r = CliRunner().invoke(S.stake, ["exit", str(w), "--yes"])
    assert r.exit_code == 0, r.output
    (tx,) = sent
    assert tx.verify() and tx.op_type == ExchangeOpType.STAKE_EXIT and tx.params == {}


def test_status_shows_when_the_principal_is_paid(monkeypatch):
    from qrdx.constants import WITHDRAWAL_DELAY_EPOCHS

    rows = [{"address": "0xPQaa", "stake": "100000", "effective_stake": "100012.5",
             "status": "exiting", "activation_epoch": 4, "exit_epoch": 90, "slashed": False},
            {"address": "0xPQbb", "stake": "200000", "effective_stake": "200000",
             "status": "active", "activation_epoch": 0, "exit_epoch": None, "slashed": False}]
    S, _wallet, _sent = _wire(monkeypatch, rows)
    r = CliRunner().invoke(S.stake, ["status", "0xpqAA"])
    assert r.exit_code == 0, r.output
    assert "EXITING" in r.output and "0xPQbb" not in r.output
    assert f"principal paid from epoch {90 + WITHDRAWAL_DELAY_EPOCHS}" in r.output
    r = CliRunner().invoke(S.stake, ["status", "0xPQcc"])
    assert r.exit_code != 0 and "not a validator" in r.output


def test_the_wallet_cli_has_the_stake_group():
    from qrdx.cli.wallet import cli

    assert "stake" in cli.commands
