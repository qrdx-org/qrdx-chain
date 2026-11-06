#!/usr/bin/env python3
"""
The determinism checks (docs/MAINNET_READINESS.md §4, "Determinism checks in CI"). They catch
the bugs that split a network, which a green test suite does not: every node runs the same
code, so a nondeterministic result agrees with itself in any single process.

* ``rollback``: every exchange operation the suite runs is first run inside an undo scope and
  failed on purpose (rollback_audit.py). The state root must not move. Fails on any operation
  that leaves state behind.
* ``hashseed``: the suite runs three times, logging every test's final exchange root
  (rootlog.py): twice under one ``PYTHONHASHSEED``, once under another. Of the roots the repeat
  reproduces, fails on any the other seed changes.

The rebuild-equivalence tests (forward application ≡ rebuild from the chain) are part of the
unit suite itself.

    python scripts/determinism/check.py rollback [pytest args]
    python scripts/determinism/check.py hashseed [pytest args]

Extra pytest arguments narrow the run (default: the unit suite).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Dict, List

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BASE = [
    "-q",
    "-p",
    "no:cacheprovider",
    "-m",
    "not integration",
    "--timeout=600",
    "-W",
    "ignore::SyntaxWarning",
]


def _pytest(args: List[str], env: Dict[str, str]) -> int:
    cmd = [sys.executable, "-m", "pytest", *BASE, *args]
    return subprocess.run(cmd, cwd=ROOT, env={**os.environ, **env}).returncode


def _rows(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def rollback(args: List[str]) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "rollback.jsonl")
        # (The wrapper changes what some tests count, so their verdicts are not this check's.)
        _pytest(
            ["-p", "scripts.determinism.rollback_audit", *(args or ["tests"])],
            {"ROLLBACK_OUT": out},
        )
        rows = _rows(out)
    left = [r for r in rows if r["kind"] == "root"]
    other = [r for r in rows if r["kind"] != "root"]
    for r in other:
        print(f"note: {r['op']} succeeded in trial, not for real ({r['real'][1]}): {r['test']}")
    for r in left:
        print(f"LEFT STATE BEHIND: {r['op']} in {r['test']}")
    print(
        f"rollback audit: {len(left)} operation(s) left state behind on failure"
        f" ({len(other)} note(s))"
    )
    return 1 if left else 0


def hashseed(args: List[str]) -> int:
    """Three runs: two under one hash seed, one under another. A test whose root the repeat
    does not reproduce makes its own randomness (fresh keys), so it says nothing about the hash
    seed. Of the rest, any root the other seed changes is iteration order deciding state."""
    runs = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, seed in enumerate(("0", "0", "4242")):
            out = os.path.join(tmp, f"roots-{i}.jsonl")
            _pytest(
                ["-p", "scripts.determinism.rootlog", *(args or ["tests"])],
                {"ROOTLOG_OUT": out, "PYTHONHASHSEED": seed},
            )
            runs.append({r["test"]: r.get("root", r.get("error")) for r in _rows(out)})
    a, again, b = runs
    logged = [t for t in a if t in again and t in b]  # (in the order the tests ran)
    stable = [t for t in logged if a[t] == again[t]]
    differ = [t for t in stable if a[t] != b[t]]
    # The manager is a singleton that a test may leave as it was: a root that differs once goes
    # on differing in the tests after it. The first one is the place to look.
    for t in differ[:10]:
        print(f"DIFFERS WITH THE HASH SEED: {t}")
    if len(differ) > 10:
        print(f"... and {len(differ) - 10} more after it")
    print(
        f"hash-seed check: {len(stable)} reproducible final exchange roots compared "
        f"({len(logged) - len(stable)} tests make their own randomness), {len(differ)} differ"
    )
    if len(stable) < 0.5 * max(len(logged), 1):
        print("too few reproducible roots to compare")
        return 1
    return 1 if differ else 0


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("rollback", "hashseed"):
        print(__doc__)
        return 2
    return {"rollback": rollback, "hashseed": hashseed}[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
