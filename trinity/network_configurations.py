from enum import (
    Enum,
)

from typing import (
    NamedTuple,
    Tuple,
    Type,
)

from eth.abc import VirtualMachineAPI

from eth_typing.evm import BlockNumber

from eth.chains.goerli import (
    GOERLI_GENESIS_HEADER,
    GOERLI_VM_CONFIGURATION,
)
from eth.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
    MAINNET_VM_CONFIGURATION,
)
from eth.chains.ropsten import (
    ROPSTEN_GENESIS_HEADER,
    ROPSTEN_VM_CONFIGURATION,
)
from eth.chains.qrdx import (
    QRDX_GENESIS_HEADER,
    QRDX_VM_CONFIGURATION,
)

from eth.rlp.headers import BlockHeader

from p2p.constants import (
    GOERLI_BOOTNODES,
    MAINNET_BOOTNODES,
    ROPSTEN_BOOTNODES,
)
from trinity.constants import (
    GOERLI_NETWORK_ID,
    MAINNET_NETWORK_ID,
    ROPSTEN_NETWORK_ID,
)

# QRDX Network ID (1337 is our testnet)
QRDX_NETWORK_ID = 1337


class MiningMethod(Enum):

    NoProof = "noproof"
    Ethash = "ethash"
    Clique = "clique"


class Eth1NetworkConfiguration(NamedTuple):

    network_id: int
    chain_name: str
    data_dir_name: str
    eip1085_filename: str
    bootnodes: Tuple[str, ...]
    genesis_header: BlockHeader
    vm_configuration: Tuple[Tuple[BlockNumber, Type[VirtualMachineAPI]], ...]
    mining_method: MiningMethod


PRECONFIGURED_NETWORKS = {
    GOERLI_NETWORK_ID: Eth1NetworkConfiguration(
        GOERLI_NETWORK_ID,
        'GoerliChain',
        'goerli',
        'goerli.json',
        GOERLI_BOOTNODES,
        GOERLI_GENESIS_HEADER,
        GOERLI_VM_CONFIGURATION,
        MiningMethod.Clique,
    ),
    MAINNET_NETWORK_ID: Eth1NetworkConfiguration(
        MAINNET_NETWORK_ID,
        'MainnetChain',
        'mainnet',
        'mainnet.json',
        MAINNET_BOOTNODES,
        MAINNET_GENESIS_HEADER,
        MAINNET_VM_CONFIGURATION,
        MiningMethod.Ethash,
    ),
    ROPSTEN_NETWORK_ID: Eth1NetworkConfiguration(
        ROPSTEN_NETWORK_ID,
        'RopstenChain',
        'ropsten',
        'ropsten.json',
        ROPSTEN_BOOTNODES,
        ROPSTEN_GENESIS_HEADER,
        ROPSTEN_VM_CONFIGURATION,
        MiningMethod.Ethash,
    ),
    QRDX_NETWORK_ID: Eth1NetworkConfiguration(
        QRDX_NETWORK_ID,
        'QRDXChain',
        'qrdx',
        'qrdx.json',
        (),  # No bootnodes for local testnet
        QRDX_GENESIS_HEADER,
        QRDX_VM_CONFIGURATION,
        MiningMethod.NoProof,  # QR-PoS uses NoProof mining method
    ),
}
