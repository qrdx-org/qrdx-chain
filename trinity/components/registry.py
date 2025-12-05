import pkg_resources
from typing import (
    Tuple,
    Type,
)

# MetricsComponent disabled due to Python 3.12 compatibility issues with async_lru
# from trinity.components.builtin.metrics.component import MetricsComponent

# AttachComponent disabled due to Python 3.12 compatibility with parsimonious (getargspec)
# from trinity.components.builtin.attach.component import (
#     DbShellComponent,
#     AttachComponent,
# )

# BeamExec disabled due to Python 3.12 compatibility with async_lru
# from trinity.components.builtin.beam_exec.component import (
#     BeamChainExecutionComponent,
# )
# from trinity.components.builtin.beam_preview.component import (
#     BeamChainPreviewComponent0,
#     BeamChainPreviewComponent1,
#     BeamChainPreviewComponent2,
#     BeamChainPreviewComponent3,
# )

from trinity.extensibility import (
    BaseComponentAPI,
)
# from trinity.components.builtin.ethstats.component import (
#     EthstatsComponent,
# )
from trinity.components.builtin.fix_unclean_shutdown.component import (
    FixUncleanShutdownComponent
)
# from trinity.components.builtin.import_export.component import (
#     ExportBlockComponent,
#     ImportBlockComponent,
# )
from trinity.components.builtin.json_rpc.component import (
    JsonRpcServerComponent,
)
from trinity.components.builtin.network_db.component import (
    NetworkDBComponent,
)
from trinity.components.builtin.new_block.component import (
    NewBlockComponent,
)
from trinity.components.builtin.peer_discovery.component import (
    PeerDiscoveryComponent,
)
from trinity.components.builtin.preferred_node.component import (
    PreferredNodeComponent,
)
from trinity.components.builtin.request_server.component import (
    RequestServerComponent,
)
from trinity.components.builtin.syncer.component import (
    SyncerComponent,
)
from trinity.components.builtin.upnp.component import (
    UpnpComponent,
)
from trinity.components.builtin.tx_pool.component import (
    TxComponent,
)
from trinity.components.builtin.qrpos_validator.component import (
    QRPoSValidatorComponent,
)


BASE_COMPONENTS: Tuple[Type[BaseComponentAPI], ...] = (
    # AttachComponent,  # Disabled - Python 3.12 compatibility
    # DbShellComponent,  # Disabled - Python 3.12 compatibility
    FixUncleanShutdownComponent,
    JsonRpcServerComponent,
    NetworkDBComponent,
    PeerDiscoveryComponent,
    PreferredNodeComponent,
    UpnpComponent,
)

ETH1_NODE_COMPONENTS: Tuple[Type[BaseComponentAPI], ...] = (
    # BeamChainExecutionComponent,  # Disabled - Python 3.12
    # BeamChainPreviewComponent0,  # Disabled - Python 3.12
    # BeamChainPreviewComponent1,  # Disabled - Python 3.12
    # BeamChainPreviewComponent2,  # Disabled - Python 3.12
    # BeamChainPreviewComponent3,  # Disabled - Python 3.12
    # EthstatsComponent,  # Disabled - Python 3.12
    # ExportBlockComponent,  # Disabled - Python 3.12
    # ImportBlockComponent,  # Disabled - Python 3.12
    # MetricsComponent,  # Disabled - Python 3.12 compatibility issue
    NewBlockComponent,
    QRPoSValidatorComponent,
    RequestServerComponent,
    SyncerComponent,
    TxComponent,
)


def discover_components() -> Tuple[Type[BaseComponentAPI], ...]:
    # Components need to define entrypoints at 'trinity.components' to automatically get loaded
    # https://packaging.python.org/guides/creating-and-discovering-components/#using-package-metadata

    return tuple(
        entry_point.load() for entry_point in pkg_resources.iter_entry_points('trinity.components')
    )


def get_all_components(*extra_components: Type[BaseComponentAPI],
                       ) -> Tuple[Type[BaseComponentAPI], ...]:
    return BASE_COMPONENTS + extra_components + discover_components()


def get_components_for_eth1_client() -> Tuple[Type[BaseComponentAPI], ...]:
    return get_all_components(*ETH1_NODE_COMPONENTS)
