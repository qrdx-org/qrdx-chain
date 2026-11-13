"""
The proposer selects from exactly the set importers judge its block against
(qrdx/validator/node_integration.py ValidatorNode._refresh_validator_set).

It was once built at startup, then from the node's live ``validators`` table, which moved with
that node's view of finality, so proposer and importers could disagree on whose slot it was
(the forks that followed a validator joining the testnet). Both now take ``S_E`` of the tip's
chain (validator/epoch_state.py), recomputed every slot.
"""
from types import SimpleNamespace

from qrdx.constants import ACTIVATION_DELAY_EPOCHS, SLOTS_PER_EPOCH
from qrdx.validator import block_verification as BV
from qrdx.validator import epoch_state as ES
from qrdx.validator.node_integration import ValidatorNode
from qrdx.validator.selection import ValidatorSelector

from test_epoch_state import G, J, Chain, chain  # noqa: F401  (fixture)


async def _agree(node, db, epoch):
    selector = ValidatorSelector()
    for slot in range(epoch * SLOTS_PER_EPOCH, (epoch + 1) * SLOTS_PER_EPOCH):
        await node._refresh_validator_set(slot)
        mine = node.manager._validator_set.validators
        chosen = selector.select_proposer(slot, mine, BV.PROPOSER_RANDAO_MIX)
        expected = BV.expected_proposer_for_slot(slot, await ES.proposers_for_slot(db, slot))
        assert chosen.address == expected, slot


async def test_the_proposer_follows_the_set_the_importers_check_against(chain):
    node = ValidatorNode(chain.db, "unused")
    node.wallet = SimpleNamespace(address=G[0], public_key=b"pk")
    node.manager = SimpleNamespace(_validator_set=None)
    await chain.epoch(1, deposits=[(J, "400000")], exits=[G[2]])
    for e in range(2, 3 + ACTIVATION_DELAY_EPOCHS):
        await chain.epoch(e, voters=G[:2])
    # Rewards and penalties have moved the stakes, a validator has joined, one is exiting.
    tip_epoch = 2 + ACTIVATION_DELAY_EPOCHS
    state = await ES.state_at(chain.db, tip_epoch + 1)
    assert state[J].status == "active" and state[G[2]].status == "exiting"
    await _agree(node, chain.db, tip_epoch + 1)
