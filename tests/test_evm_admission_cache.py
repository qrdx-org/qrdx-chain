"""
A refused EVM transaction stays refused when it is sent again (docs/KNOWN_ISSUES.md, "A refused
EVM transaction was answered as admitted when sent again").

``eth_sendRawTransaction`` remembers the transactions it admitted, so a peer's echo of one is
not gossiped again. It used to remember a transaction before judging it: sent a second time, a
refused transaction (malformed, unfunded) was answered with its hash, as if admitted, and one
refused because its account could not pay could not be sent again once it could. Found by the
flood of integration_tests/adversarial.py, which saw 643 of its refused transactions "admitted".

The handler is defined inside the node's startup (it closes over the live mempool), so this
reads its order: what it remembers, it remembers only after the mempool admitted it.
"""

import inspect


def _handler() -> str:
    from qrdx.node import main as node_main

    src = inspect.getsource(node_main)
    handler = src[src.index("async def eth_sendRawTransaction_handler"):]
    return handler[: handler.index("rpc_server.register_method")]


def test_only_an_admitted_transaction_is_remembered():
    handler = _handler()
    assert handler.count("EVM_TX_CACHE.put(") == 1
    assert handler.index("mp.admit(") < handler.index("EVM_TX_CACHE.put(")
    assert handler.index("insufficient funds") < handler.index("EVM_TX_CACHE.put(")
    assert handler.index("verify_delegated_spend(") < handler.index("EVM_TX_CACHE.put(")


def test_a_refusal_is_not_an_error_in_the_nodes_log():
    """Anyone can send refused transactions as fast as the node takes them: an ERROR with a
    traceback for each filled the log and cost the event loop."""
    handler = _handler()
    assert "logger.error" not in handler and "exc_info=True" not in handler
