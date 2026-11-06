"""The node's source, for the tests that check how it is wired: qrdx/node/main.py and the
modules split out of it (docs/NODE_LAYOUT.md)."""

import inspect

NODE_MODULES = [
    "qrdx.node.main",
    "qrdx.node.security",
    "qrdx.node.evm_runtime",
    "qrdx.node.block_import",
    "qrdx.node.derived_state",
    "qrdx.node.fork_choice",
    "qrdx.node.sync",
    "qrdx.node.peers",
    "qrdx.node.discovery",
    "qrdx.node.chain_identity",
    "qrdx.node.api",
    "qrdx.node.api.observability",
    "qrdx.node.api.transactions",
    "qrdx.node.api.exchange",
    "qrdx.node.api.blocks",
    "qrdx.node.api.chain",
    "qrdx.node.api.accounts",
]


def node_modules():
    import importlib

    return [importlib.import_module(m) for m in NODE_MODULES]


def node_source() -> str:
    return "\n".join(inspect.getsource(m) for m in node_modules())


def normalized_node_source():
    """node_source(), searched formatter-independently (tests/source_text.py)."""
    from source_text import NormalizedSource, normalize

    return NormalizedSource(normalize(node_source()))
