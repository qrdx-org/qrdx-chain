"""
The chain spec (qrdx/chain_spec.py): a network's identity, parameters and upgrade schedule.

What must hold for upgrades to be safe:
  * validation is strict — anything this release cannot follow is refused, never ignored;
  * the genesis hash commits to everything except the upgrade schedule;
  * a rule is active exactly from its fork height (a block is judged by its own height);
  * peers are compatible only if they share our genesis, chain id and passed fork history
    (Ethereum's EIP-2124 rules), so a node that missed an upgrade is cut off at the fork;
  * on a non-dev network the environment cannot change consensus.
"""
import json
import os

import pytest

from qrdx import chain_spec as cs
from qrdx.chain_spec import ChainSpec, ChainSpecError

GENESIS = "ab" * 32


@pytest.fixture
def extra_features(monkeypatch):
    """Two throwaway features, so schedules with several forks can be exercised."""
    feats = dict(cs.FEATURES)
    feats.update({"test_rule_a": "test", "test_rule_b": "test", "test_rule_c": "test"})
    monkeypatch.setattr(cs, "FEATURES", feats)


def _spec(forks=(), features=(), dev=False, chain_id=4242, network="qrdx-testnet", **params):
    return cs.build_spec(network, chain_id, params, dev=dev, features=features, forks=forks)


def _raw(**over):
    raw = _spec().to_dict()
    raw.update(over)
    return raw


# ── validation ──────────────────────────────────────────────────────────────────────────

def test_dev_spec_reproduces_the_historical_defaults():
    spec = cs.dev_spec(env={})
    assert spec.dev and spec.chain_id == 88888 and spec.network == "qrdx-dev"
    assert spec.params == {k: p.default for k, p in cs.PARAMS.items()}
    assert spec.scheduled_features_at(10 ** 9) == frozenset()


def test_dev_spec_takes_parameters_from_the_environment():
    spec = cs.dev_spec(env={"QRDX_SLOTS_PER_EPOCH": "8", "QRDX_ORACLE_REPORTERS": "a, b,",
                            "QRDX_PERP_QUOTE": "  ", "QRDX_CHAIN_ID": "777"})
    assert spec.params["SLOTS_PER_EPOCH"] == 8
    assert spec.params["ORACLE_REPORTERS"] == ["a", "b"]
    assert spec.params["PERP_QUOTE"] == "USD"           # blank means the default, as before
    assert spec.chain_id == 777


def test_dev_spec_rejects_a_malformed_environment_value():
    with pytest.raises(ChainSpecError):
        cs.dev_spec(env={"QRDX_SLOT_DURATION": "two"})


@pytest.mark.parametrize("mutate, message", [
    (lambda r: r.update(surprise=1), "unknown key"),
    (lambda r: r.pop("forks"), "missing key"),
    (lambda r: r.update(format=2), "format"),
    (lambda r: r.update(format=True), "format"),
    (lambda r: r.update(network="bad name!"), "network name"),
    (lambda r: r.update(dev="no"), "dev"),
    (lambda r: r.update(chain_id=0), "chain_id"),
    (lambda r: r.update(chain_id=True), "chain_id"),
    (lambda r: r["params"].pop("SLOT_DURATION"), "missing parameter"),
    (lambda r: r["params"].update(NOT_A_PARAM=1), "unknown parameter"),
    (lambda r: r["params"].update(SLOT_DURATION=0), ">= 1"),
    (lambda r: r["params"].update(SLOT_DURATION=True), "integer"),
    (lambda r: r["params"].update(SLOT_DURATION=2.0), "integer"),
    (lambda r: r["params"].update(PERP_QUOTE=" USD"), "whitespace"),
    (lambda r: r["params"].update(ORACLE_REPORTERS=["a", "a"]), "twice"),
    (lambda r: r["params"].update(ORACLE_REPORTERS=["a,b"]), "list"),
    (lambda r: r.update(features=["no_such_rule"]), "unknown feature"),
])
def test_strict_validation(mutate, message):
    raw = _raw()
    mutate(raw)
    with pytest.raises(ChainSpecError, match=message):
        ChainSpec.from_dict(raw)


@pytest.mark.parametrize("chain_id", [1, 88888, 11155111, 31337])
def test_a_real_network_cannot_reuse_another_chains_id(chain_id):
    with pytest.raises(ChainSpecError, match="belongs to"):
        _spec(chain_id=chain_id)
    assert _spec(chain_id=chain_id, dev=True).chain_id == chain_id     # dev networks may


def test_an_unknown_feature_in_a_future_fork_still_refuses_to_load():
    """This release could not follow the chain past that fork; loading anyway would fork the
    node off at the activation height instead of telling the operator to upgrade now."""
    with pytest.raises(ChainSpecError, match="upgrade the node software"):
        _spec(forks=[{"name": "f1", "height": 10 ** 9, "features": ["from_the_future"]}])


@pytest.mark.parametrize("forks, message", [
    ([{"name": "f1", "height": 0, "features": ["test_rule_a"]}], "height must be"),
    ([{"name": "f1", "height": 10, "features": ["test_rule_a"]},
      {"name": "f2", "height": 10, "features": ["test_rule_b"]}], "height must be"),
    ([{"name": "f1", "height": 10, "features": ["test_rule_a"]},
      {"name": "f2", "height": 5, "features": ["test_rule_b"]}], "height must be"),
    ([{"name": "f1", "height": 10, "features": ["test_rule_a"]},
      {"name": "f1", "height": 20, "features": ["test_rule_b"]}], "used twice"),
    ([{"name": "f1", "height": 10, "features": ["test_rule_a"]},
      {"name": "f2", "height": 20, "features": ["test_rule_a"]}], "already activated"),
    ([{"name": "f1", "height": 10, "features": []}], "must change something"),
    ([{"name": "f1", "height": 10, "features": ["test_rule_a"], "extra": 1}], "unknown key"),
    ([{"name": "F1", "height": 10, "features": ["test_rule_a"]}], "fork name"),
    ([{"name": "f1", "height": 10, "features": ["test_rule_a"],
       "params": {"SLOTS_PER_EPOCH": 8}}], "cannot change at a fork"),
])
def test_fork_schedule_validation(extra_features, forks, message):
    with pytest.raises(ChainSpecError, match=message):
        _spec(forks=forks)


def test_a_genesis_feature_cannot_be_scheduled_again(extra_features):
    with pytest.raises(ChainSpecError, match="already activated"):
        _spec(features=["test_rule_a"],
              forks=[{"name": "f1", "height": 5, "features": ["test_rule_a"]}])


def test_a_spec_can_only_be_built_through_validation():
    with pytest.raises(TypeError):
        ChainSpec({"format": 1})


# ── identity ────────────────────────────────────────────────────────────────────────────

def test_genesis_hash_is_stable_and_covers_everything_but_the_schedule(extra_features):
    base = _spec()
    assert base.genesis_hash() == _spec().genesis_hash()
    assert base.genesis_hash() == ChainSpec.from_dict(json.loads(json.dumps(base.to_dict()))).genesis_hash()
    # Upgrades are appended without changing the network's genesis.
    upgraded = _spec(forks=[{"name": "f1", "height": 100, "features": ["test_rule_a"]}])
    assert upgraded.genesis_hash() == base.genesis_hash()
    # Anything else is a different network.
    for other in (_spec(SLOTS_PER_EPOCH=8), _spec(chain_id=4243), _spec(network="qrdx-other"),
                  _spec(features=["test_rule_a"]), _spec(dev=True),
                  _spec(ORACLE_REPORTERS=["0xabc"])):
        assert other.genesis_hash() != base.genesis_hash()


def test_rules_switch_on_exactly_at_their_fork_height(extra_features):
    spec = _spec(features=["test_rule_c"], forks=[
        {"name": "f1", "height": 100, "features": ["test_rule_a"]},
        {"name": "f2", "height": 250, "features": ["test_rule_b"]}])
    assert spec.scheduled_features_at(0) == {"test_rule_c"}
    assert not spec.is_scheduled("test_rule_a", 99)
    assert spec.is_scheduled("test_rule_a", 100) and spec.is_scheduled("test_rule_a", 10 ** 9)
    assert not spec.is_scheduled("test_rule_b", 249) and spec.is_scheduled("test_rule_b", 250)
    assert spec.is_scheduled("test_rule_c", 0)
    assert spec.activation_height("test_rule_a") == 100
    assert spec.activation_height("test_rule_c") == 0
    assert spec.activation_height("randao_selection") is None
    assert spec.next_fork(99)["name"] == "f1" and spec.next_fork(100)["name"] == "f2"
    assert spec.next_fork(250) is None


def test_a_rule_check_needs_a_real_height_and_a_known_feature():
    spec = _spec()
    with pytest.raises(ValueError, match="block height is required"):
        spec.is_scheduled("randao_selection", None)
    with pytest.raises(ValueError):
        spec.is_scheduled("randao_selection", -1)
    with pytest.raises(KeyError):
        spec.is_scheduled("randao_selction", 5)          # a typo must not read as "off"


def test_the_spec_is_immutable_from_outside():
    spec = _spec()
    spec.params["SLOT_DURATION"] = 99
    spec.to_dict()["params"]["SLOT_DURATION"] = 99
    assert spec.params["SLOT_DURATION"] == 2


# ── peers (EIP-2124) ────────────────────────────────────────────────────────────────────

def _schedule(extra_features_unused=None):
    return _spec(forks=[{"name": "f1", "height": 100, "features": ["test_rule_a"]},
                        {"name": "f2", "height": 200, "features": ["test_rule_b"]}])


def _identity(spec, head, genesis=GENESIS):
    return cs.network_identity(spec, genesis, head, "test")


def test_fork_id_tracks_passed_forks(extra_features):
    spec = _schedule()
    assert spec.fork_id(GENESIS, 0) == spec.fork_id(GENESIS, 99)
    assert spec.fork_id(GENESIS, 99).next == 100
    assert spec.fork_id(GENESIS, 100).hash != spec.fork_id(GENESIS, 99).hash
    assert spec.fork_id(GENESIS, 150).next == 200
    assert spec.fork_id(GENESIS, 300).next == 0
    assert spec.fork_id(GENESIS, 0).hash != spec.fork_id("cd" * 32, 0).hash


@pytest.mark.parametrize("local_head, remote_head", [
    (50, 50), (150, 150), (300, 300),        # in step
    (150, 50), (300, 50), (300, 150),        # the peer is behind but knows what we passed
    (50, 150), (50, 300), (150, 300),        # we are behind and know what the peer passed
])
def test_peers_on_the_same_schedule_are_compatible_whatever_their_heights(extra_features, local_head, remote_head):
    spec = _schedule()
    ok, reason = cs.check_peer_compatibility(spec, GENESIS, local_head, _identity(spec, remote_head))
    assert ok, reason


def test_a_peer_that_missed_an_upgrade_is_cut_off_at_the_fork(extra_features):
    upgraded = _schedule()
    stale = _spec(forks=[{"name": "f1", "height": 100, "features": ["test_rule_a"]}])
    # Before f2 nobody can tell — the stale node still follows the same chain.
    ok, _ = cs.check_peer_compatibility(upgraded, GENESIS, 150, _identity(stale, 150))
    assert ok
    # Once we pass f2 the stale peer (still announcing no next fork) is refused...
    ok, reason = cs.check_peer_compatibility(upgraded, GENESIS, 200, _identity(stale, 199))
    assert not ok and "200" in reason
    ok, reason = cs.check_peer_compatibility(upgraded, GENESIS, 250, _identity(stale, 250))
    assert not ok
    # ...and the stale node, seeing us announce/pass a fork it does not know, refuses us too.
    ok, reason = cs.check_peer_compatibility(stale, GENESIS, 250, _identity(upgraded, 250))
    assert not ok
    ok, reason = cs.check_peer_compatibility(stale, GENESIS, 250, _identity(upgraded, 150))
    assert not ok and "has passed" in reason


def test_different_networks_and_rewritten_history_are_refused(extra_features):
    spec = _schedule()
    rewritten = _spec(forks=[{"name": "f1", "height": 100, "features": ["test_rule_b"]},
                             {"name": "f2", "height": 200, "features": ["test_rule_a"]}])
    other_chain = _spec(chain_id=4243, forks=spec.forks)
    for remote, why in [
        (_identity(spec, 50, genesis="cd" * 32), "different genesis"),
        (_identity(other_chain, 50), "different chain id"),
        (_identity(rewritten, 150), "incompatible fork history"),
        (None, "no network identity"),
        ({"genesis_hash": GENESIS}, "malformed"),
        ({**_identity(spec, 50), "fork_next": -1}, "malformed"),
    ]:
        ok, reason = cs.check_peer_compatibility(spec, GENESIS, 150, remote)
        assert not ok and why in reason, (why, reason)


# ── environment ─────────────────────────────────────────────────────────────────────────

def test_a_real_network_refuses_environment_overrides():
    spec = _spec(SLOTS_PER_EPOCH=8)
    assert cs.environment_conflicts(spec, env={}) == []
    assert cs.environment_conflicts(spec, env={"QRDX_SLOTS_PER_EPOCH": "8",
                                                "QRDX_CHAIN_ID": "4242",
                                                "QRDX_NETWORK_NAME": "qrdx-testnet",
                                                "QRDX_ENFORCE_RANDAO": ""}) == []
    problems = cs.environment_conflicts(spec, env={
        "QRDX_SLOTS_PER_EPOCH": "32", "QRDX_CHAIN_ID": "1", "QRDX_NETWORK_NAME": "other",
        "QRDX_ENFORCE_FAILED_TX_COSTS": "0", "QRDX_WITHDRAWAL_DELAY_EPOCHS": "soon"})
    joined = "\n".join(problems)
    for needle in ("QRDX_SLOTS_PER_EPOCH", "QRDX_CHAIN_ID", "QRDX_NETWORK_NAME",
                   "QRDX_ENFORCE_FAILED_TX_COSTS", "QRDX_WITHDRAWAL_DELAY_EPOCHS"):
        assert needle in joined
    assert len(problems) == 5


def test_a_dev_network_takes_the_environment_by_design():
    assert cs.environment_conflicts(cs.dev_spec(env={}), env={"QRDX_ENFORCE_RANDAO": "1"}) == []


# ── loading ─────────────────────────────────────────────────────────────────────────────

def test_genesis_file_loading_fails_closed(tmp_path):
    missing_section = tmp_path / "old.json"
    missing_section.write_text(json.dumps({"state": {}, "block": {}}))
    with pytest.raises(ChainSpecError, match="no chain_spec"):
        cs.load_genesis_file(str(missing_section))
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json")
    with pytest.raises(ChainSpecError, match="cannot read"):
        cs.load_genesis_file(str(garbage))
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"chain_spec": _spec().to_dict()}))
    assert cs.load_genesis_file(str(good))[1].genesis_hash() == _spec().genesis_hash()


def test_genesis_file_resolution(tmp_path):
    (tmp_path / "databases").mkdir()
    db = tmp_path / "databases" / "node0.db"
    assert cs.resolve_genesis_file(env={}, database_path=str(db)) is None
    (tmp_path / "genesis_config.json").write_text("{}")
    assert cs.resolve_genesis_file(env={}, database_path=str(db)) == str(tmp_path / "genesis_config.json")
    explicit = tmp_path / "explicit.json"
    explicit.write_text("{}")
    assert cs.resolve_genesis_file(env={"QRDX_GENESIS_FILE": str(explicit)},
                                   database_path=str(db)) == str(explicit)
    with pytest.raises(ChainSpecError, match="does not exist"):
        cs.resolve_genesis_file(env={"QRDX_GENESIS_FILE": str(tmp_path / "nope.json")})


def test_a_process_with_a_genesis_file_takes_its_parameters_from_it(tmp_path):
    """End to end through qrdx.constants, in a subprocess (constants load at import)."""
    import subprocess
    import sys
    spec = _spec(SLOTS_PER_EPOCH=8, SLOT_DURATION=6, PERP_QUOTE="QRDX")
    (tmp_path / "databases").mkdir()
    (tmp_path / "genesis_config.json").write_text(json.dumps({"chain_spec": spec.to_dict()}))
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    probe = ("import json, qrdx.constants as k; print(json.dumps([k.SLOTS_PER_EPOCH, "
             "k.SLOT_DURATION, k.PERP_QUOTE, k.CHAIN_ID, k.NETWORK_NAME, "
             "list(k.CHAIN_SPEC_ENV_CONFLICTS)]))")
    env = {k: v for k, v in os.environ.items() if not k.startswith("QRDX_")}
    env.update(PYTHONPATH=repo, QRDX_DATABASE_PATH=str(tmp_path / "databases" / "n.db"),
               QRDX_SLOTS_PER_EPOCH="32")
    out = subprocess.run([sys.executable, "-c", probe], env=env, cwd=repo,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    slots, slot_s, quote, chain_id, network, conflicts = json.loads(out.stdout.strip().splitlines()[-1])
    assert (slots, slot_s, quote, chain_id, network) == (8, 6, "QRDX", 4242, "qrdx-testnet")
    assert len(conflicts) == 1 and "QRDX_SLOTS_PER_EPOCH" in conflicts[0]


# ── QRDX's own networks ─────────────────────────────────────────────────────────────────

def test_mainnet_and_testnet_ids_belong_to_their_networks():
    assert cs.build_spec("qrdx-mainnet", 762, {}).chain_id == 762
    assert cs.build_spec("qrdx-testnet", 7620, {}).chain_id == 7620
    for network, chain_id, dev in [("qrdx-testnet", 762, False), ("my-private-net", 762, False),
                                   ("qrdx-mainnet", 762, True), ("qrdx-mainnet", 7620, False)]:
        with pytest.raises(ChainSpecError, match="only that"):
            cs.build_spec(network, chain_id, {}, dev=dev)


@pytest.mark.parametrize("chain_id", ["762", "7620"])
def test_a_dev_node_cannot_claim_a_public_qrdx_network_id(chain_id):
    """A dev network on 762 would sign transactions valid on mainnet."""
    with pytest.raises(ChainSpecError, match="genesis file"):
        cs.dev_spec(env={"QRDX_CHAIN_ID": chain_id})


def test_a_dev_node_cannot_claim_another_chains_id():
    with pytest.raises(ChainSpecError, match="Ethereum mainnet"):
        cs.dev_spec(env={"QRDX_CHAIN_ID": "1"})
    assert cs.dev_spec(env={"QRDX_CHAIN_ID": "31337"}).chain_id == 31337   # local-dev convention
