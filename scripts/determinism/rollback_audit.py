"""
pytest plugin: a rollback-completeness audit of every exchange operation the suite runs
(docs/EXCHANGE_AUDIT.md, finding 7; run by scripts/determinism/check.py).

Before each real ``process_transaction``, the operation runs once inside an undo scope and is
failed on purpose. The exchange state root must then be exactly what it was. Anything else is
state an operation changes that a failure does not put back, and on a real chain one node's
failed operation would then leave state that another node's does not.

Each finding is a JSON line in ``$ROLLBACK_OUT``:

* ``root``: the root changed. This is a defect.
* ``success``: the trial and the real run disagreed about success. Mostly these are refusals
  the real run makes before executing (the nonce, the signer, the fee), which the trial
  skips; ``PRE`` names the known ones.

    pytest tests/ -p scripts.determinism.rollback_audit
"""

import json
import os

OUT = os.environ.get("ROLLBACK_OUT", os.devnull)
PRE = (
    "nonce",
    "may not act",
    "own key",
    "agent may not",
    "not authorized",
    "signed by",
    "expired",
    "free action",
    "for gas",
    "signature",
    "key is turned off",
    "may not sign",
    "below the minimum",
    "whole number of wei",
    "Gas limit too low",
    "insufficient balance",
)


class _Boom(Exception):
    pass


def _install() -> None:
    from qrdx.exchange.state_manager import ExchangeStateManager

    real = ExchangeStateManager.process_transaction
    if getattr(real, "_audited", False):
        return

    def process_transaction(self, tx, *a, **kw):
        if getattr(self, "_in_audit", False):
            return real(self, tx, *a, **kw)
        self._in_audit = True
        row, trial = None, None
        try:
            try:
                before = self.compute_state_root()
            except Exception:  # noqa: BLE001 — a manager the test left half-built
                return real(self, tx, *a, **kw)
            try:
                with self.atomic():
                    if not self._charge_agent(tx):
                        trial = self._execute_op(tx)
                    raise _Boom()
            except _Boom:
                pass
            except Exception as e:  # noqa: BLE001 — the operation raised: rolled back too
                trial = e
            if self.compute_state_root() != before:
                row = {"kind": "root", "op": tx.op_type.name}
        finally:
            self._in_audit = False
        result = real(self, tx, *a, **kw)
        if row is None and trial is not None and not isinstance(trial, Exception):
            if bool(trial.success) != bool(result.success) and not any(
                w in str(result.error or "") for w in PRE
            ):
                row = {
                    "kind": "success",
                    "op": tx.op_type.name,
                    "trial": [trial.success, str(trial.error)[:120]],
                    "real": [result.success, str(result.error)[:120]],
                }
        if row is not None:
            row["test"] = os.environ.get("PYTEST_CURRENT_TEST", "")
            with open(OUT, "a") as f:
                f.write(json.dumps(row) + "\n")
        return result

    process_transaction._audited = True
    ExchangeStateManager.process_transaction = process_transaction


def pytest_configure(config):
    _install()
