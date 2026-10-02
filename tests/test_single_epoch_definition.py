"""
There must be ONE definition of an epoch.

`qrdx/validator/config.py` used to hardcode POS_CONSTANTS['SLOTS_PER_EPOCH'] = 32 (and
SLOT_DURATION = 2, UNBONDING_PERIOD_EPOCHS = 9450), while `qrdx.constants` read them from
the environment. On the testnet (QRDX_SLOTS_PER_EPOCH=8) the node loop, finality, RANDAO,
block verification and slashing used 8-slot epochs, but `ValidatorManager.propose_block`
stamped every block's `epoch` field at 32 — and `epoch_from_block` reads that field. So:

  * the proposer scheduled a validator exit for epoch 11 and every importer for epoch 4;
  * reconstruction walked epochs in finality's 8-slot terms but read op epochs in 32-slot
    terms, compressing a deposit's activation and a later exit into the same epoch, where
    the exit was silently dropped and the validator stayed active forever.

Production defaults (32) agreed by coincidence, which is why it hid. These tests run in a
subprocess because the bug only exists when the environment overrides the defaults.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_PROBE = r"""
import json
import qrdx.constants as k
import qrdx.validator.config as c
print(json.dumps({
    "k_spe": k.SLOTS_PER_EPOCH, "c_spe": c.POS_CONSTANTS["SLOTS_PER_EPOCH"],
    "k_sd": k.SLOT_DURATION, "c_sd": c.POS_CONSTANTS["SLOT_DURATION"],
    "k_ub": k.UNBONDING_PERIOD_EPOCHS, "c_ub": c.POS_CONSTANTS["UNBONDING_PERIOD_EPOCHS"],
}))
"""


def _probe(env_overrides):
    env = {**os.environ, **env_overrides, "PYTHONPATH": REPO}
    out = subprocess.run([sys.executable, "-c", _PROBE], env=env, cwd=REPO,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("overrides", [
    {},
    {"QRDX_SLOTS_PER_EPOCH": "8"},                          # the testnet
    {"QRDX_SLOTS_PER_EPOCH": "4", "QRDX_SLOT_DURATION": "6"},  # the RANDAO larger-slot config
    {"QRDX_UNBONDING_PERIOD_EPOCHS": "2"},                  # the s16 round-trip config
])
def test_validator_constants_follow_the_single_source_of_truth(overrides):
    v = _probe(overrides)
    assert v["c_spe"] == v["k_spe"], (
        f"POS_CONSTANTS SLOTS_PER_EPOCH {v['c_spe']} != qrdx.constants {v['k_spe']} — "
        f"blocks would carry an epoch importers and finality disagree with")
    assert v["c_sd"] == v["k_sd"], "slot duration diverged between the two definitions"
    assert v["c_ub"] == v["k_ub"], "unbonding period diverged between the two definitions"


def test_the_block_epoch_field_matches_the_node_epoch():
    """What the proposer schedules with must equal what importers read back."""
    from qrdx.constants import SLOTS_PER_EPOCH
    from qrdx.validator.block_verification import epoch_from_block
    from qrdx.validator.config import POS_CONSTANTS

    for slot in (0, 7, 8, 75, 1000):
        stamped = slot // POS_CONSTANTS["SLOTS_PER_EPOCH"]        # propose_block
        node = slot // SLOTS_PER_EPOCH                             # node loop / finality
        assert stamped == node
        assert epoch_from_block({"epoch": stamped, "slot": slot}) == node


def test_epoch_is_recovered_from_every_import_path_shape():
    """
    The sync path's block dict carries the header under `content` (the stored column
    name); p2p/REST carry it under `block_content`. Only the latter was read, so every
    sync-imported block — bulk sync and post-reorg re-fetches — had its validator
    lifecycle ops scheduled with no epoch, and exits were never logged for withdrawal.
    """
    from qrdx.constants import SLOTS_PER_EPOCH
    from qrdx.validator.block_verification import epoch_from_block

    header = str({"slot": 3 * SLOTS_PER_EPOCH + 1, "epoch": 3, "number": 81})
    shapes = {
        "p2p/REST envelope": {"block_content": header},
        "sync path (stored row)": {"content": header, "hash": "ab" * 32, "id": 81},
        "parsed block": {"epoch": 3},
        "slot only": {"slot": 3 * SLOTS_PER_EPOCH + 1},
    }
    for name, shape in shapes.items():
        assert epoch_from_block(shape) == 3, f"epoch not recovered from the {name} shape"
