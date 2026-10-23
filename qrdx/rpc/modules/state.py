"""
State proofs (docs/STATE_PROOFS.md): ``state_getProof`` proves one entry of QRDX state — an
account, a contract storage slot, a token balance, or any exchange entry — or its absence, at a
block, against that block's signed state root;
``state_verifyProof`` checks one. ``state_proofInput`` encodes a proof as the state proof
precompile's input (qrdx/contracts/state_proof_evm.py), for a contract to verify on chain.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..server import RPCError, RPCErrorCode, RPCModule, rpc_method


class StateModule(RPCModule):
    namespace = "state"

    def _db(self):
        db = getattr(self.context, "db", None)
        if db is None or not hasattr(db, "connection"):
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "state database unavailable")
        return db

    @rpc_method
    async def getProof(
        self, kind: str, a: Any, b: Any = None, height: Optional[int] = None
    ) -> Dict[str, Any]:
        """``kind``:

        * ``"account"`` (a = address), ``"storage"`` (a = contract, b = slot), ``"token"``
          (a = token, b = holder) — database state;
        * ``"exchange"`` (a = a collection's path such as ``"qns.names"`` or
          ``"ch.accounts"``, or a book's ``"spot:<pair>"`` / ``"perp:<market>"``; b = the
          entry's key as JSON, or a level such as ``"b65000"``);
        * ``"exchange_part"`` (a = ``"market:<id>"``, ``"pool:<id>"``, ``"oracle"``, …).

        ``height``: default the newest provable block (an exchange proof: one of the last 256)."""
        from ... import state_proofs

        db = self._db()
        if not state_proofs.scheduled():
            raise RPCError(
                RPCErrorCode.RESOURCE_UNAVAILABLE, "state proofs are off on this network"
            )
        try:
            if kind in ("exchange", "exchange_part"):
                from ...exchange.state_manager import ExchangeStateManager

                proof = await state_proofs.prove_exchange(
                    db,
                    ExchangeStateManager.get_instance(),
                    str(a),
                    b,
                    height=height,
                    part=kind == "exchange_part",
                )
            else:
                ident = (a,) if kind == "account" else (a, b)
                if kind != "account" and b is None:
                    raise ValueError(f"a {kind} proof needs two identifiers")
                proof = await state_proofs.prove(db, kind, *ident, height=height)
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e
        block = await db.get_block_by_id(proof["height"])
        signed = None
        if block:
            from ...validator.block_verification import _parse_block_content

            try:
                signed = _parse_block_content(block.get("content")).get("state_root")
            except Exception:
                signed = None
        proof["block_hash"] = block.get("hash") if block else None
        proof["state_root"] = signed
        # Never serve a proof this node cannot itself verify against the block it holds at that
        # height (a record that does not belong to it, or a block not stored here).
        if not signed or not state_proofs.verify_against(str(signed), proof):
            raise RPCError(
                RPCErrorCode.RESOURCE_UNAVAILABLE,
                f"no proof of height {proof['height']} this node can stand behind",
            )
        if proof.get("entry") and proof.get("domain") == "database":
            proof["fields"] = state_proofs.decode_entry(bytes.fromhex(proof["entry"]))
        return proof

    @rpc_method
    async def verifyProof(self, proof: Dict[str, Any], state_root: Optional[str] = None) -> bool:
        """Does ``proof`` hold against ``state_root`` (default: the root the proof's block
        signed, read from this node)?"""
        from ... import state_proofs

        root = state_root or proof.get("state_root")
        if not root:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, "no state root to verify against")
        try:
            return state_proofs.verify_against(str(root), proof)
        except (KeyError, ValueError, TypeError) as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, f"malformed proof: {e}") from e

    @rpc_method
    async def proofInput(self, proof: Dict[str, Any]) -> str:
        """The proof as the state proof precompile's input (hex), at address 0x…0300."""
        from ...contracts.state_proof_evm import encode

        try:
            return "0x" + encode(proof).hex()
        except (KeyError, ValueError, TypeError) as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, f"malformed proof: {e}") from e
