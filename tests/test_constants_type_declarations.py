"""
The configuration constants qrdx.constants creates dynamically (from NODE_DEFAULTS and
LOGGER_DEFAULTS, via globals()) are also declared under TYPE_CHECKING so the type checker can
see them. The two lists must not drift: a name added to the defaults but not declared would
reappear as an "attribute not defined" error in CI; one declared but no longer created would
type-check and then fail at import.
"""
import ast
from pathlib import Path

import qrdx.constants as k


def test_every_dynamic_constant_is_declared_for_type_checkers_and_vice_versa():
    tree = ast.parse(Path(k.__file__).read_text())
    declared = set()
    for node in tree.body:
        if isinstance(node, ast.If) and getattr(node.test, "id", None) == "TYPE_CHECKING":
            declared |= {n.target.id for n in node.body if isinstance(n, ast.AnnAssign)}
    assert declared == set(k.DEFAULTS)
    for name in declared:
        assert hasattr(k, name)
