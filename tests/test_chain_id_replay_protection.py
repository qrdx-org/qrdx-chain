"""
Every EVM transaction must be signed for THIS network's chain id.

The chain id was parsed but never compared, so a transaction signed for any chain — another
QRDX network, Ethereum, or no chain at all (pre-EIP-155) — executed here once its nonce lined
up: a key used on two networks had every one of its transactions replayable across them. The
check lives in the shared parser (contracts/evm_mempool.parse_eth_raw_tx), so mempool admission,
execution and block import all apply it.
"""
import pytest
from eth_account import Account

from qrdx.constants import CHAIN_ID
from qrdx.contracts.evm_mempool import EVMMempool, parse_eth_raw_tx
from qrdx.crypto.pq.dilithium import generate_keypair
from qrdx.transactions.pq_tx import PQTransaction

KEY = "0x" + "4c" * 32
TO = "0x" + "11" * 20


def _legacy(chain_id):
    tx = {"nonce": 0, "gasPrice": 10 ** 9, "gas": 21000, "to": TO, "value": 1, "data": b""}
    if chain_id is not None:
        tx["chainId"] = chain_id
    signed = Account.sign_transaction(tx, KEY)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return "0x" + bytes(raw).hex()


def _pq(chain_id):
    priv, _pub = generate_keypair()
    tx = PQTransaction(chain_id=chain_id, nonce=0, gas_price=10 ** 9, gas_limit=500_000,
                       to=bytes.fromhex(TO[2:]), value=1, data=b"")
    tx.sign(priv)
    return "0x" + tx.encode().hex()


def test_this_networks_transactions_parse():
    assert parse_eth_raw_tx(_legacy(CHAIN_ID))["chain_id"] == CHAIN_ID
    assert parse_eth_raw_tx(_pq(CHAIN_ID))["chain_id"] == CHAIN_ID


@pytest.mark.parametrize("chain_id", [1, CHAIN_ID + 1, 9999])
def test_a_transaction_signed_for_another_chain_is_refused(chain_id):
    with pytest.raises(ValueError, match="signed for chain id"):
        parse_eth_raw_tx(_legacy(chain_id))
    with pytest.raises(ValueError, match="signed for chain id"):
        parse_eth_raw_tx(_pq(chain_id))


def test_a_transaction_bound_to_no_chain_is_refused():
    with pytest.raises(ValueError, match="pre-EIP-155"):
        parse_eth_raw_tx(_legacy(None))
    with pytest.raises(ValueError, match="not bound to a chain id"):
        parse_eth_raw_tx(_pq(0))


def test_the_mempool_refuses_another_chains_transaction():
    mp = EVMMempool()
    ok, err, _ = mp.admit(_legacy(1))
    assert not ok and "chain id" in err
    assert mp.admit(_legacy(CHAIN_ID))[0]


async def test_eth_chain_id_reports_the_id_the_node_enforces():
    from qrdx.rpc.modules.eth import EthModule
    assert int(await EthModule().chainId(), 16) == CHAIN_ID
