"""
Phase C guard: one block path, no PostgreSQL remnants.

The exchange/PoS consensus scaffolding used to exist twice — once on the live
SQLite path and once in a parallel PostgreSQL implementation
(``create_pos_block`` / ``commit_pos_block`` + ``node/validator_integration.py``)
that was dead and broken on SQLite (``database.pool`` / ``$1`` placeholders).
That duplicate path was removed. These tests pin the result so it cannot
silently come back (see docs/EXCHANGE_PRODUCTION_READINESS.md §4 Phase C).
"""

import inspect

import qrdx.manager as manager


def test_dead_pg_block_functions_are_gone():
    """The PostgreSQL-only duplicate block functions must not exist."""
    assert not hasattr(manager, "create_pos_block"), "create_pos_block (PG path) was reintroduced"
    assert not hasattr(manager, "commit_pos_block"), "commit_pos_block (PG path) was reintroduced"


def test_dead_orchestrator_module_is_gone():
    """The unused PostgreSQL block orchestrator must not be importable."""
    import importlib
    try:
        importlib.import_module("qrdx.node.validator_integration")
    except ModuleNotFoundError:
        return  # expected — module removed
    raise AssertionError("qrdx.node.validator_integration (dead PG orchestrator) was reintroduced")


def test_live_block_functions_present():
    """The live SQLite block functions remain."""
    assert hasattr(manager, "create_block"), "live create_block missing"
    assert hasattr(manager, "validate_pos_block"), "validate_pos_block missing"
    assert hasattr(manager, "get_pos_chain_head"), "get_pos_chain_head missing"


def test_no_postgres_remnants_in_manager_source():
    """manager.py must not use asyncpg-style pool/placeholders."""
    src = inspect.getsource(manager)
    assert "database.pool" not in src, "PostgreSQL connection pool usage present in manager.py"
    assert "$1" not in src and "$2" not in src, "PostgreSQL ($N) placeholders present in manager.py"
