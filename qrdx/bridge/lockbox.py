"""
Off-chain tooling for the bridge's source-chain side (docs/BRIDGE.md, "Deploying to a new
chain"): deploying ``QRDXLockbox`` and the custodian's work — planning releases, building the
multisig's batch, and reconciling what was released against what QRDX recorded.

Nothing here is consensus. It talks JSON-RPC to the source chain and to QRDX nodes, and it never
holds a multisig's keys: the custodian's signers review and sign the batch in their own wallets.
The scripts in ``scripts/bridge/`` are its command lines.

The rules it enforces, because a release cannot be undone:

* **Only finalized withdrawals.** A withdrawal's number is assigned in the block that burned it.
  A reorg can give that number to a different withdrawal, so a release waits until the block is
  finalized on QRDX.
* **Every QRDX node agrees.** Each node the custodian names must report the same withdrawal. A
  node that lies or lags cannot slip a withdrawal in.
* **Never twice.** A withdrawal the lockbox already released is skipped (the lockbox refuses it
  anyway).
* **The bytecode is the audited one.** The deployed contract is compiled from the pinned source
  with pinned settings, and checked against the committed artifact and, after deployment, against
  the chain.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address

_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = _ROOT / "contracts" / "bridge" / "QRDXLockbox.sol"
ARTIFACT_PATH = _ROOT / "contracts" / "bridge" / "QRDXLockbox.artifact.json"

# Pinned: change any of these and the bytecode (and so the audit) changes. ``paris``: no PUSH0,
# so the same bytecode deploys on every EVM chain, newest or not.
SOLC_VERSION = "0.8.24"
SOLC_SETTINGS: Dict[str, Any] = {"optimizer": {"enabled": True, "runs": 200}, "evmVersion": "paris"}


class LockboxError(Exception):
    """Something the tooling refuses to do, with why."""


# ── the contract ──────────────────────────────────────────────────────────────


def compile_lockbox() -> Dict[str, Any]:
    """Compile ``QRDXLockbox.sol`` with the pinned compiler and settings (py-solc-x; the
    compiler is installed on first use)."""
    import solcx

    if SOLC_VERSION not in {str(v) for v in solcx.get_installed_solc_versions()}:
        solcx.install_solc(SOLC_VERSION)
    source = SOURCE_PATH.read_text()
    out = solcx.compile_standard(
        {
            "language": "Solidity",
            "sources": {"QRDXLockbox.sol": {"content": source}},
            "settings": {
                **SOLC_SETTINGS,
                "outputSelection": {
                    "*": {
                        "*": [
                            "abi",
                            "evm.bytecode.object",
                            "evm.deployedBytecode.object",
                            "evm.deployedBytecode.immutableReferences",
                        ]
                    }
                },
            },
        },
        solc_version=SOLC_VERSION,
    )
    c = out["contracts"]["QRDXLockbox.sol"]["QRDXLockbox"]
    return {
        "contract": "QRDXLockbox",
        "compiler": f"solc {SOLC_VERSION}",
        "settings": SOLC_SETTINGS,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "abi": c["abi"],
        "bytecode": "0x" + c["evm"]["bytecode"]["object"],
        "runtime": "0x" + c["evm"]["deployedBytecode"]["object"],
        # Where the deployed code holds its one immutable, refundDelay (the compiler leaves zeros
        # there; the constructor writes the value): a deployed lockbox is checked against the
        # runtime with it filled in (``deployed_runtime``).
        "immutable_offsets": sorted(
            ref["start"]
            for refs in c["evm"]["deployedBytecode"].get("immutableReferences", {}).values()
            for ref in refs
        ),
    }


def load_artifact() -> Dict[str, Any]:
    """The committed build (``QRDXLockbox.artifact.json``): what was audited is what deploys."""
    art = json.loads(ARTIFACT_PATH.read_text())
    source = SOURCE_PATH.read_text()
    if hashlib.sha256(source.encode()).hexdigest() != art["source_sha256"]:
        raise LockboxError(
            "QRDXLockbox.sol no longer matches its committed artifact: rebuild the artifact "
            "(and have the change audited) before deploying"
        )
    return art


def deployed_runtime(art: Dict[str, Any], refund_delay: int) -> str:
    """The runtime code a lockbox deployed with ``refund_delay`` holds: the artifact's, with the
    immutable written where the compiler reserved it."""
    code = bytearray.fromhex(art["runtime"].removeprefix("0x"))
    value = int(refund_delay).to_bytes(32, "big")
    for start in art.get("immutable_offsets", []):
        code[start : start + 32] = value
    return "0x" + code.hex()


def code_hash(hexcode: str) -> str:
    return "0x" + keccak(bytes.fromhex(hexcode.removeprefix("0x"))).hex()


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


SEL_RELEASE = selector("release(uint256,address,address,uint256)")
SEL_RELEASED = selector("released(uint256)")
SEL_CUSTODIAN = selector("custodian()")
SEL_PENDING_CUSTODIAN = selector("pendingCustodian()")
SEL_DEPOSITS_PAUSED = selector("depositsPaused()")
SEL_BALANCE_OF = selector("balanceOf(address)")
SEL_REFUND = selector("refund(uint256,address,address,uint256,string,uint256)")
SEL_REFUNDED = selector("refunded(uint256)")
SEL_REFUND_DELAY = selector("refundDelay()")
TOPIC_RELEASED = "0x" + keccak(text="Released(uint256,address,address,uint256)").hex()
TOPIC_DEPOSIT = "0x" + keccak(text="Deposit(uint256,address,address,uint256,string,uint256)").hex()
TOPIC_REFUNDED = "0x" + keccak(text="Refunded(uint256,address,address,uint256)").hex()


def deploy_data(bytecode: str, custodian: str, refund_delay: int) -> bytes:
    """The contract creation's data: the bytecode and its constructor arguments."""
    return bytes.fromhex(bytecode.removeprefix("0x")) + encode(
        ["address", "uint256"], [custodian, int(refund_delay)]
    )


def release_calldata(withdrawal_id: int, token: str, to: str, units: int) -> bytes:
    return SEL_RELEASE + encode(
        ["uint256", "address", "address", "uint256"],
        [int(withdrawal_id), to_checksum_address(token), to_checksum_address(to), int(units)],
    )


def refund_calldata(deposit: "DepositEvent") -> bytes:
    """``refund`` of a deposit exactly as the lockbox recorded it (the contract checks it)."""
    return SEL_REFUND + encode(
        ["uint256", "address", "address", "uint256", "string", "uint256"],
        [
            deposit.number,
            deposit.token,
            deposit.sender,
            deposit.units,
            deposit.recipient,
            deposit.time,
        ],
    )


def create_address(deployer: str, nonce: int) -> str:
    """The address a CREATE from ``deployer`` at ``nonce`` lands at."""
    import rlp

    raw = rlp.encode([bytes.fromhex(deployer.removeprefix("0x")), int(nonce)])
    return to_checksum_address("0x" + keccak(raw)[12:].hex())


# ── JSON-RPC ──────────────────────────────────────────────────────────────────


class RpcError(LockboxError):
    pass


class JsonRpc:
    """A minimal JSON-RPC client (a source chain's, or a QRDX node's ``/rpc``)."""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, *params: Any) -> Any:
        import httpx

        self._id += 1
        try:
            body = httpx.post(
                self.url,
                json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": list(params)},
                timeout=self.timeout,
            ).json()
        except Exception as e:  # noqa: BLE001 — any transport failure is the same to a caller
            raise RpcError(f"{self.url}: {method}: {e}") from e
        if body.get("error"):
            raise RpcError(f"{self.url}: {method}: {body['error']}")
        return body.get("result")


def _call(rpc: JsonRpc, to: str, data: bytes, block: str = "latest") -> bytes:
    out = rpc.call("eth_call", {"to": to, "data": "0x" + data.hex()}, block)
    return bytes.fromhex(str(out or "0x").removeprefix("0x"))


def chain_id(rpc: JsonRpc) -> int:
    return int(rpc.call("eth_chainId"), 16)


def finalized_block(rpc: JsonRpc) -> int:
    """The source chain's finalized block — what the validators' watchers read deposits up to.
    LockboxError if the chain does not support the ``finalized`` tag (it cannot be bridged)."""
    block = rpc.call("eth_getBlockByNumber", "finalized", False)
    if not block or "number" not in block:
        raise LockboxError("the chain's RPC does not answer for the 'finalized' block tag")
    return int(block["number"], 16)


def has_code(rpc: JsonRpc, address: str) -> bool:
    return len(str(rpc.call("eth_getCode", address, "latest") or "0x")) > 2


def custodian_of(rpc: JsonRpc, lockbox: str) -> str:
    (addr,) = decode(["address"], _call(rpc, lockbox, SEL_CUSTODIAN))
    return to_checksum_address(addr)


def deposits_paused(rpc: JsonRpc, lockbox: str) -> bool:
    (paused,) = decode(["bool"], _call(rpc, lockbox, SEL_DEPOSITS_PAUSED))
    return bool(paused)


def is_released(rpc: JsonRpc, lockbox: str, withdrawal_id: int) -> bool:
    (done,) = decode(
        ["bool"], _call(rpc, lockbox, SEL_RELEASED + encode(["uint256"], [withdrawal_id]))
    )
    return bool(done)


def is_refunded(rpc: JsonRpc, lockbox: str, number: int) -> bool:
    (done,) = decode(["bool"], _call(rpc, lockbox, SEL_REFUNDED + encode(["uint256"], [number])))
    return bool(done)


def refund_delay(rpc: JsonRpc, lockbox: str) -> int:
    (delay,) = decode(["uint256"], _call(rpc, lockbox, SEL_REFUND_DELAY))
    return int(delay)


def block_time(rpc: JsonRpc, number: int, _cache: Optional[Dict[int, int]] = None) -> int:
    if _cache is not None and number in _cache:
        return _cache[number]
    t = int(rpc.call("eth_getBlockByNumber", hex(int(number)), False)["timestamp"], 16)
    if _cache is not None:
        _cache[number] = t
    return t


def token_balance(rpc: JsonRpc, token: str, holder: str) -> int:
    (units,) = decode(
        ["uint256"], _call(rpc, token, SEL_BALANCE_OF + encode(["address"], [holder]))
    )
    return int(units)


def _logs(
    rpc: JsonRpc, address: str, topic: str, from_block: int, to_block: int, chunk: int = 5000
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    start = from_block
    while start <= to_block:
        end = min(to_block, start + chunk - 1)
        out += (
            rpc.call(
                "eth_getLogs",
                {
                    "address": address,
                    "topics": [topic],
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                },
            )
            or []
        )
        start = end + 1
    return [log for log in out if not log.get("removed")]


@dataclass(frozen=True)
class Released:
    """A ``Released`` event: what the lockbox paid out for a withdrawal."""

    withdrawal_id: int
    token: str
    to: str
    units: int
    tx: str
    block: int


def released_events(rpc: JsonRpc, lockbox: str, from_block: int, to_block: int) -> List[Released]:
    events = []
    for log in _logs(rpc, lockbox, TOPIC_RELEASED, from_block, to_block):
        t = log["topics"]
        (units,) = decode(["uint256"], bytes.fromhex(log["data"].removeprefix("0x")))
        events.append(
            Released(
                withdrawal_id=int(t[1], 16),
                token=to_checksum_address("0x" + t[2][-40:]),
                to=to_checksum_address("0x" + t[3][-40:]),
                units=int(units),
                tx=log["transactionHash"],
                block=int(log["blockNumber"], 16),
            )
        )
    return events


@dataclass(frozen=True)
class DepositEvent:
    deposit_id: str  # as QRDX names it: "<chain>:<lockbox deposit id>"
    number: int  # the lockbox's deposit id
    token: str
    sender: str
    units: int
    recipient: str
    block: int
    time: int  # the deposit's block time, as the lockbox recorded it
    tx: str = ""


def deposit_events(
    rpc: JsonRpc, chain: int, lockbox: str, from_block: int, to_block: int
) -> List[DepositEvent]:
    events = []
    for log in _logs(rpc, lockbox, TOPIC_DEPOSIT, from_block, to_block):
        t = log["topics"]
        units, recipient, when = decode(
            ["uint256", "string", "uint256"], bytes.fromhex(log["data"].removeprefix("0x"))
        )
        number = int(t[1], 16)
        events.append(
            DepositEvent(
                deposit_id=f"{chain}:{number}",
                number=number,
                token=to_checksum_address("0x" + t[2][-40:]),
                sender=to_checksum_address("0x" + t[3][-40:]),
                units=int(units),
                recipient=recipient,
                block=int(log["blockNumber"], 16),
                time=int(when),
                tx=log["transactionHash"],
            )
        )
    return events


@dataclass(frozen=True)
class RefundedEvent:
    """A ``Refunded`` event: a deposit the custodian returned."""

    number: int
    token: str
    to: str
    units: int
    tx: str
    block: int
    time: int


def refunded_events(
    rpc: JsonRpc, lockbox: str, from_block: int, to_block: int
) -> List[RefundedEvent]:
    events = []
    times: Dict[int, int] = {}
    for log in _logs(rpc, lockbox, TOPIC_REFUNDED, from_block, to_block):
        t = log["topics"]
        (units,) = decode(["uint256"], bytes.fromhex(log["data"].removeprefix("0x")))
        number = int(log["blockNumber"], 16)
        events.append(
            RefundedEvent(
                number=int(t[1], 16),
                token=to_checksum_address("0x" + t[2][-40:]),
                to=to_checksum_address("0x" + t[3][-40:]),
                units=int(units),
                tx=log["transactionHash"],
                block=number,
                time=block_time(rpc, number, times),
            )
        )
    return events


# ── proving a deposit (BRIDGE_PROVE_DEPOSIT) ─────────────────────────────────────────


def deposit_slot(number: int) -> bytes:
    """The lockbox's storage slot of ``deposits[number]`` (QRDXLockbox keeps them at slot 4)."""
    from ..exchange.bridge import deposit_slot as slot

    return slot(number)


def deposit_proof(rpc: JsonRpc, lockbox: str, number: int, height: int) -> Dict[str, Any]:
    """``eth_getProof`` of the lockbox's account and ``deposits[number]`` at block ``height``."""
    return rpc.call("eth_getProof", lockbox, ["0x" + deposit_slot(number).hex()], hex(int(height)))


def prove_params(chain: int, deposit: DepositEvent, decimals: int, height: int, proof) -> Dict:
    """The parameters of a BRIDGE_PROVE_DEPOSIT for ``deposit`` against the attested head at
    ``height``, from ``deposit_proof``."""
    amount = Decimal(deposit.units).scaleb(-decimals)
    return {
        "deposit": {
            "chain": int(chain),
            "id": deposit.number,
            "token": deposit.token.lower(),
            "from": deposit.sender.lower(),
            "to": deposit.recipient,
            "amount": format(amount, "f"),
            "time": deposit.time,
        },
        "height": int(height),
        "account_proof": list(proof["accountProof"]),
        "storage_proof": list(proof["storageProof"][0]["proof"]),
    }


# ── signing and sending (a deployer's key, or a single-key test custodian's) ─────


def load_account(
    keystore: Optional[str], password: Optional[str], key_env: str = "QRDX_DEPLOYER_KEY"
):
    """An eth_account signer from an encrypted keystore file, or a hex key in ``key_env``."""
    import os

    from eth_account import Account

    if keystore:
        if password is None:
            import getpass

            password = getpass.getpass(f"password for {keystore}: ")
        return Account.from_key(Account.decrypt(json.loads(Path(keystore).read_text()), password))
    key = os.environ.get(key_env)
    if not key:
        raise LockboxError(f"no key: pass --keystore, or set {key_env}")
    return Account.from_key(key)


def build_tx(
    rpc: JsonRpc,
    sender: str,
    cid: int,
    to: Optional[str],
    data: bytes,
    legacy: bool = False,
    gas: Optional[int] = None,
) -> Dict[str, Any]:
    """An unsigned transaction with this chain's nonce, gas and fees: EIP-1559 where the chain's
    blocks carry a base fee, legacy (EIP-155) otherwise or when asked."""
    nonce = int(rpc.call("eth_getTransactionCount", sender, "pending"), 16)
    call: Dict[str, Any] = {"from": sender, "data": "0x" + data.hex()}
    if to:
        call["to"] = to
    if gas is None:
        gas = int(int(rpc.call("eth_estimateGas", call), 16) * 12 // 10) + 21_000
    tx: Dict[str, Any] = {
        "chainId": cid,
        "nonce": nonce,
        "gas": gas,
        "data": "0x" + data.hex(),
        "value": 0,
    }
    if to:
        tx["to"] = to_checksum_address(to)
    latest = rpc.call("eth_getBlockByNumber", "latest", False) or {}
    if legacy or not latest.get("baseFeePerGas"):
        tx["gasPrice"] = int(rpc.call("eth_gasPrice"), 16)
    else:
        tip = int(rpc.call("eth_maxPriorityFeePerGas"), 16)
        tx["maxPriorityFeePerGas"] = tip
        tx["maxFeePerGas"] = 2 * int(latest["baseFeePerGas"], 16) + tip
        tx["type"] = 2
    return tx


def send(rpc: JsonRpc, account, tx: Dict[str, Any], timeout: float = 300.0) -> Dict[str, Any]:
    """Sign ``tx`` with ``account``, send it, and wait for its receipt; LockboxError if it
    reverted or did not land in time."""
    signed = account.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    tx_hash = rpc.call("eth_sendRawTransaction", "0x" + bytes(raw).hex())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = rpc.call("eth_getTransactionReceipt", tx_hash)
        if receipt:
            if int(str(receipt.get("status", "0x1")), 16) != 1:
                raise LockboxError(f"transaction {tx_hash} reverted")
            return receipt
        time.sleep(1.0)
    raise LockboxError(f"transaction {tx_hash} not included within {timeout:.0f} s")


# ── QRDX's side ───────────────────────────────────────────────────────────────


def qrdx_finalized_height(rpc: JsonRpc) -> int:
    return int(rpc.call("qrdx_weakSubjectivityCheckpoint")["finalized"]["height"])


def qrdx_withdrawals(rpc: JsonRpc, from_id: int = 1, page: int = 1000) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    while True:
        batch = rpc.call("bridge_getWithdrawals", from_id, page) or []
        out += batch
        if len(batch) < page:
            return out
        from_id = int(batch[-1]["id"]) + 1


def qrdx_assets(rpc: JsonRpc) -> List[Dict[str, Any]]:
    return rpc.call("bridge_getAssets") or []


def qrdx_finalized_time(rpc: JsonRpc) -> int:
    """The timestamp of the node's finalized block: no block that could still mint a deposit
    is above it once it is past the deposit's window."""
    block = rpc.call("eth_getBlockByNumber", hex(qrdx_finalized_height(rpc)), False)
    return int(block["timestamp"], 16)


def agreed_refund_view(nodes: Sequence[JsonRpc], deposit_ids: Iterable[str]) -> "RefundView":
    """What every node agrees on for refunds: the deposit window (identical, or refused), the
    lowest finalized time any reports, and the deposits minted (a node that disagrees about
    one is refused)."""
    if not nodes:
        raise LockboxError("name at least one QRDX node")
    windows = {int(n.call("bridge_getGuardrails")["deposit_window"]) for n in nodes}
    if len(windows) != 1:
        raise LockboxError(f"QRDX nodes disagree on the deposit window: {sorted(windows)}")
    finalized_time = min(qrdx_finalized_time(n) for n in nodes)
    minted: Set[str] = set()
    for deposit_id in deposit_ids:
        answers = {bool(n.call("bridge_getDeposit", deposit_id).get("minted")) for n in nodes}
        if len(answers) != 1:
            raise LockboxError(f"QRDX nodes disagree on whether {deposit_id} was minted")
        if answers.pop():
            minted.add(deposit_id)
    return RefundView(windows.pop(), finalized_time, minted)


@dataclass
class QrdxView:
    """What the custodian's QRDX nodes agree on: the finalized height (the lowest any reports)
    and each withdrawal every node reports identically."""

    finalized: int
    withdrawals: List[Dict[str, Any]]
    assets: List[Dict[str, Any]]


def agreed_view(nodes: Sequence[JsonRpc], from_id: int = 1) -> QrdxView:
    """Read every node; LockboxError if any two report a withdrawal (or the assets) differently.
    A node behind the others is fine: only withdrawals all of them have are planned."""
    if not nodes:
        raise LockboxError("name at least one QRDX node")
    views = [
        (n.url, qrdx_finalized_height(n), qrdx_withdrawals(n, from_id), qrdx_assets(n))
        for n in nodes
    ]
    finalized = min(v[1] for v in views)
    common = min(len(v[2]) for v in views)
    first_url, _f, first_w, first_assets = views[0]
    for url, _height, withdrawals, assets in views[1:]:
        for a, b in zip(first_w[:common], withdrawals[:common], strict=True):
            if a != b:
                raise LockboxError(
                    f"QRDX nodes disagree on withdrawal {a.get('id')}: {first_url} and {url}"
                )
        if sorted(json.dumps(x, sort_keys=True) for x in first_assets) != sorted(
            json.dumps(x, sort_keys=True) for x in assets
        ):
            raise LockboxError(f"QRDX nodes disagree on the bridged assets: {first_url} and {url}")
    return QrdxView(finalized, first_w[:common], first_assets)


# ── planning ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Release:
    withdrawal_id: int
    token: str  # the source chain's token, checksummed
    to: str  # the recipient there, checksummed
    amount: str  # in the token's units, as QRDX recorded it
    units: int  # amount × 10^decimals
    height: int  # the QRDX block that burned it

    def calldata(self) -> bytes:
        return release_calldata(self.withdrawal_id, self.token, self.to, self.units)


@dataclass
class Plan:
    releases: List[Release] = field(default_factory=list)  # finalized, not released: to sign
    waiting: List[int] = field(default_factory=list)  # not finalized on QRDX yet
    released: List[int] = field(default_factory=list)  # already released by the lockbox
    other_chains: int = 0

    def batch_hash(self) -> str:
        """One hash of exactly what the batch pays: each signer computes it on its own node and
        they compare it before signing."""
        blob = json.dumps(
            [[r.withdrawal_id, r.token, r.to, r.units] for r in self.releases],
            separators=(",", ":"),
        )
        return "0x" + keccak(text=blob).hex()

    def calls(self) -> List[bytes]:
        return [r.calldata() for r in self.releases]

    def describe(self) -> str:
        return (
            f"Releases of QRDX withdrawals "
            f"{', '.join(str(r.withdrawal_id) for r in self.releases)}; batch {self.batch_hash()}"
        )


def _units(amount: str, decimals: int) -> int:
    v = Decimal(str(amount)).scaleb(decimals)
    if v != v.to_integral_value() or v <= 0:
        raise LockboxError(
            f"amount {amount} is not a whole number of base units ({decimals} decimals)"
        )
    return int(v)


def plan_releases(
    view: QrdxView, chain: int, released: Set[int], max_releases: Optional[int] = None
) -> Plan:
    """What the custodian should release now: this chain's withdrawals in finalized QRDX blocks
    that the lockbox has not released, in withdrawal order."""
    decimals = {
        (int(a["chain"]), str(a["source_token"]).lower()): int(a["decimals"]) for a in view.assets
    }
    plan = Plan()
    for w in view.withdrawals:
        wid = int(w["id"])
        if int(w["chain"]) != chain:
            plan.other_chains += 1
            continue
        if wid in released:
            plan.released.append(wid)
            continue
        if int(w["height"]) > view.finalized:
            plan.waiting.append(wid)
            continue
        key = (chain, str(w["token"]).lower())
        if key not in decimals:
            raise LockboxError(f"withdrawal {wid}: {w['token']} is not a bridged asset on {chain}")
        if max_releases is not None and len(plan.releases) >= max_releases:
            plan.waiting.append(wid)
            continue
        plan.releases.append(
            Release(
                withdrawal_id=wid,
                token=to_checksum_address(w["token"]),
                to=to_checksum_address(w["to"]),
                amount=str(w["amount"]),
                units=_units(w["amount"], decimals[key]),
                height=int(w["height"]),
            )
        )
    return plan


def released_ids(rpc: JsonRpc, lockbox: str, ids: Iterable[int]) -> Set[int]:
    return {wid for wid in ids if is_released(rpc, lockbox, wid)}


def safe_batch(
    chain: int, safe: str, lockbox: str, plan: Any, name: str = "QRDX bridge releases"
) -> Dict[str, Any]:
    """A plan (releases or refunds) as a Safe Transaction Builder batch: the signers import it
    in the Safe app (Transaction Builder), check it against ``batch_hash`` and sign there."""
    return {
        "version": "1.0",
        "chainId": str(chain),
        "createdAt": int(time.time() * 1000),
        "meta": {
            "name": name,
            "description": plan.describe(),
            "txBuilderVersion": "1.16.5",
            "createdFromSafeAddress": to_checksum_address(safe) if safe else "",
            "createdFromOwnerAddress": "",
        },
        "transactions": [
            {
                "to": to_checksum_address(lockbox),
                "value": "0",
                "data": "0x" + data.hex(),
                "contractMethod": None,
                "contractInputsValues": None,
            }
            for data in plan.calls()
        ],
    }


# ── refunds ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RefundView:
    window: int  # QRDX's deposit window (seconds)
    finalized_time: int  # the lowest finalized block time the custodian's nodes report
    minted: Set[str]  # deposit ids QRDX minted
    source_time: int = 0  # the source chain's latest block time
    refund_delay: int = 0  # the lockbox's refundDelay


@dataclass(frozen=True)
class Refund:
    deposit: DepositEvent

    @property
    def deposit_id(self) -> str:
        return self.deposit.deposit_id

    def calldata(self) -> bytes:
        return refund_calldata(self.deposit)


@dataclass
class RefundPlan:
    refunds: List[Refund] = field(default_factory=list)  # never mintable, not refunded: to sign
    window_open: List[str] = field(default_factory=list)  # QRDX could still mint these
    minted: List[str] = field(default_factory=list)
    refunded: List[str] = field(default_factory=list)  # already returned by the lockbox

    def batch_hash(self) -> str:
        blob = json.dumps(
            [
                [r.deposit.number, r.deposit.token, r.deposit.sender, r.deposit.units]
                for r in self.refunds
            ],
            separators=(",", ":"),
        )
        return "0x" + keccak(text=blob).hex()

    def calls(self) -> List[bytes]:
        return [r.calldata() for r in self.refunds]

    def describe(self) -> str:
        return (
            f"Refunds of lockbox deposits {', '.join(r.deposit_id for r in self.refunds)}; "
            f"batch {self.batch_hash()}"
        )


def refundable(deposit: DepositEvent, view: RefundView) -> bool:
    """Whether QRDX can never mint ``deposit`` and the lockbox will let it go: its window closed
    before the finalized QRDX block's time (QRDX's clock never runs backwards, so no block above
    it can count the deposit), no node reports it minted, and the lockbox's refundDelay passed."""
    return (
        deposit.deposit_id not in view.minted
        and view.finalized_time > deposit.time + view.window
        and view.source_time > deposit.time + view.refund_delay
    )


def plan_refunds(
    deposits: Sequence[DepositEvent],
    view: RefundView,
    refunded: Set[str],
    max_refunds: Optional[int] = None,
) -> RefundPlan:
    """The deposits to refund: never minted on QRDX and never mintable again, and not refunded
    yet (``refunded``: deposit ids the lockbox has returned). Each goes back to its depositor —
    the lockbox refuses anything else."""
    plan = RefundPlan()
    for d in sorted(deposits, key=lambda d: d.number):
        if d.deposit_id in view.minted:
            plan.minted.append(d.deposit_id)
        elif d.deposit_id in refunded:
            plan.refunded.append(d.deposit_id)
        elif not refundable(d, view):
            plan.window_open.append(d.deposit_id)
        elif max_refunds is None or len(plan.refunds) < max_refunds:
            plan.refunds.append(Refund(d))
    return plan


def reconcile_refunds(
    deposits: Sequence[DepositEvent], view: RefundView, events: Sequence[RefundedEvent]
) -> List[str]:
    """Alarms for any ``Refunded`` event that is not exactly one never-minted deposit, paid back
    in full to its depositor after its window closed. (The lockbox enforces most of this; the
    check that it was never minted on QRDX is the one only QRDX can make.)"""
    by_number = {d.number: d for d in deposits}
    alarms: List[str] = []
    seen: Dict[int, int] = {}
    for e in events:
        seen[e.number] = seen.get(e.number, 0) + 1
        d = by_number.get(e.number)
        if d is None:
            alarms.append(f"refund of an unknown deposit {e.number} in {e.tx}")
            continue
        if d.deposit_id in view.minted:
            alarms.append(f"deposit {d.deposit_id} was minted on QRDX AND refunded in {e.tx}")
        if (e.token, e.to, e.units) != (d.token, d.sender, d.units):
            alarms.append(
                f"deposit {d.deposit_id}: refunded {e.units} of {e.token} to {e.to}; it was "
                f"{d.units} of {d.token} from {d.sender}"
            )
        if e.time <= d.time + view.window:
            alarms.append(f"deposit {d.deposit_id} was refunded before its window closed ({e.tx})")
    alarms += [f"deposit {n} refunded {k} times" for n, k in seen.items() if k > 1]
    return alarms


# ── reconciling ───────────────────────────────────────────────────────────────


@dataclass
class Reconciliation:
    matched: List[int] = field(default_factory=list)
    pending: List[int] = field(default_factory=list)  # finalized on QRDX, not released yet
    waiting: List[int] = field(default_factory=list)  # not finalized on QRDX yet
    mismatched: List[str] = field(default_factory=list)  # released differently from the record
    unknown: List[str] = field(default_factory=list)  # released, but no such finalized withdrawal
    double: List[int] = field(default_factory=list)  # released more than once (cannot happen)

    @property
    def alarms(self) -> List[str]:
        return (
            [f"mismatch: {m}" for m in self.mismatched]
            + [f"unknown release: {u}" for u in self.unknown]
            + [f"released twice: {d}" for d in self.double]
        )


def reconcile(view: QrdxView, chain: int, events: Sequence[Released]) -> Reconciliation:
    """Every ``Released`` event must pay exactly a finalized withdrawal of this chain, once."""
    decimals = {
        (int(a["chain"]), str(a["source_token"]).lower()): int(a["decimals"]) for a in view.assets
    }
    records = {int(w["id"]): w for w in view.withdrawals if int(w["chain"]) == chain}
    out = Reconciliation()
    seen: Dict[int, int] = {}
    for e in events:
        seen[e.withdrawal_id] = seen.get(e.withdrawal_id, 0) + 1
        w = records.get(e.withdrawal_id)
        if w is None or int(w["height"]) > view.finalized:
            out.unknown.append(f"withdrawal {e.withdrawal_id} in {e.tx}")
            continue
        want = (
            to_checksum_address(w["token"]),
            to_checksum_address(w["to"]),
            _units(w["amount"], decimals[(chain, str(w["token"]).lower())]),
        )
        if (e.token, e.to, e.units) != want:
            out.mismatched.append(
                f"withdrawal {e.withdrawal_id}: paid {e.units} of {e.token} "
                f"to {e.to}; QRDX recorded {want[2]} of {want[0]} to {want[1]}"
            )
        elif seen[e.withdrawal_id] == 1:
            out.matched.append(e.withdrawal_id)
    out.double = sorted(wid for wid, n in seen.items() if n > 1)
    paid = set(seen)
    for wid, w in sorted(records.items()):
        if wid in paid:
            continue
        (out.waiting if int(w["height"]) > view.finalized else out.pending).append(wid)
    return out
