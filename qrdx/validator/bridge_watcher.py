"""
A validator's view of the bridge's source chains (docs/BRIDGE.md): the deposits made into each
chain's lockbox (``contracts/bridge/QRDXLockbox.sol``), read only up to that chain's
*finalized* block, for the validator's oracle votes to attest. A deposit is minted on QRDX once
votes carrying more than two thirds of the committee's stake attest it identically
(qrdx/exchange/bridge.py), so a validator that reads a reorganizable block, or a wrong amount,
only wastes its own attestation.

``QRDX_BRIDGE_SOURCES`` configures it, comma-separated:

    <chain id>=<JSON-RPC URL>@<lockbox address>   a source chain, e.g.
                                                  42161=https://arb1.example/rpc@0x…lockbox
    file:<path>                                   a JSON list of deposits (the testnet's
                                                  scripted source, like its price feed)

``QRDX_BRIDGE_FROM_BLOCK_<chain id>`` sets where a chain's scan starts (default: the lockbox's
deployment block, which the operator should set; otherwise the last 50,000 blocks). A validator
without a source attests nothing; the rest still reach a quorum if they hold enough stake.
"""

from __future__ import annotations

import json
import os
import threading
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional

from ..logger import get_logger

logger = get_logger(__name__)

# event Deposit(address indexed token, address indexed from, uint256 amount, string recipient)
DEPOSIT_EVENT = "Deposit(address,address,uint256,string)"
LOG_CHUNK = 2_000  # blocks per eth_getLogs request
DEFAULT_LOOKBACK = 50_000


def deposit_topic() -> str:
    from eth_utils import keccak

    return "0x" + keccak(text=DEPOSIT_EVENT).hex()


def decode_deposit_log(chain: int, log: Dict[str, Any], assets) -> Optional[Dict[str, Any]]:
    """A lockbox ``Deposit`` log as the vote attests it, or None if it is not a supported
    asset (the lockbox accepts any token; the chain mints only the configured ones)."""
    from eth_abi import decode

    topics = log.get("topics") or []
    if len(topics) < 3:
        return None
    token = "0x" + str(topics[1])[-40:].lower()
    asset = assets.get((int(chain), token))
    if asset is None:
        return None
    data = bytes.fromhex(str(log.get("data", "0x"))[2:])
    raw_amount, recipient = decode(["uint256", "string"], data)
    if raw_amount <= 0:
        return None
    amount = Decimal(raw_amount).scaleb(-asset.decimals)
    return {
        "chain": int(chain),
        "token": token,
        "tx": str(log["transactionHash"]).lower(),
        "log": int(str(log["logIndex"]), 0),  # hex from JSON-RPC
        "to": str(recipient).strip(),
        "amount": str(amount),
    }


class EvmSource:
    """One source chain's lockbox, scanned by JSON-RPC up to its finalized block."""

    def __init__(self, chain: int, rpc_url: str, lockbox: str, from_block: Optional[int] = None):
        self.chain, self.rpc_url, self.lockbox = int(chain), rpc_url, lockbox.lower()
        self.next_block = from_block
        self.head: Optional[Dict[str, Any]] = None  # the last finalized block seen
        self._id = 0

    def _call(self, method: str, params: List[Any]) -> Any:
        import httpx

        self._id += 1
        r = httpx.post(
            self.rpc_url,
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": self._id},
            timeout=10.0,
        )
        body = r.json()
        if body.get("error"):
            raise RuntimeError(f"chain {self.chain}: {method}: {body['error']}")
        return body.get("result")

    def poll(self, assets) -> List[Dict[str, Any]]:
        block = self._call("eth_getBlockByNumber", ["finalized", False])
        finalized = int(block["number"], 16)
        # The finalized head, for the chain's attested heads (docs/BRIDGE.md "Chain heads") —
        # never in the way of the deposits: a block without the fields reports no head.
        try:
            self.head = {
                "chain": self.chain,
                "height": finalized,
                "hash": str(block["hash"]).lower(),
                "state_root": str(block["stateRoot"]).lower(),
                "timestamp": int(block["timestamp"], 16),
            }
        except (KeyError, TypeError, ValueError):
            self.head = None
        if self.next_block is None:
            self.next_block = max(0, finalized - DEFAULT_LOOKBACK)
        out: List[Dict[str, Any]] = []
        topic = deposit_topic()
        while self.next_block <= finalized:
            to = min(finalized, self.next_block + LOG_CHUNK - 1)
            logs = self._call(
                "eth_getLogs",
                [
                    {
                        "address": self.lockbox,
                        "fromBlock": hex(self.next_block),
                        "toBlock": hex(to),
                        "topics": [topic],
                    }
                ],
            )
            for log in logs or []:
                if log.get("removed"):
                    continue
                try:
                    d = decode_deposit_log(self.chain, log, assets)
                except Exception as e:
                    logger.warning("bridge: chain %s: undecodable deposit log: %s", self.chain, e)
                    continue
                if d is not None:
                    out.append(d)
            self.next_block = to + 1
        return out


class FileSource:
    """A JSON list of deposits (the testnet's scripted source)."""

    def __init__(self, path: str):
        self.path = path

    def poll(self, assets) -> List[Dict[str, Any]]:
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


class BridgeWatcher:
    """Collects deposits from every source in a background thread (votes never wait on a
    source chain) and hands the vote the ones not yet minted, oldest first."""

    def __init__(self, sources: List[Any], interval: float = 15.0, start: bool = True):
        self.sources, self.interval = sources, interval
        self._seen: Dict[str, Dict[str, Any]] = {}  # deposit id → deposit, in arrival order
        self._lock = threading.Lock()
        if start:
            threading.Thread(target=self._run, daemon=True, name="bridge-watcher").start()

    def poll_once(self) -> None:
        from ..exchange.bridge import BridgeError, configured_assets, parse_deposit

        assets = configured_assets()
        for source in self.sources:
            try:
                found = source.poll(assets)
            except Exception as e:
                logger.warning("bridge: source %s: %s", getattr(source, "chain", source), e)
                continue
            for raw in found:
                try:
                    d = parse_deposit(raw, assets)
                except BridgeError as e:
                    logger.warning("bridge: skipping deposit %s: %s", raw, e)
                    continue
                with self._lock:
                    self._seen.setdefault(d.id, raw)

    def _run(self) -> None:
        while True:
            self.poll_once()
            time.sleep(self.interval)

    def heads(self) -> List[Dict[str, Any]]:
        """Each source's last finalized block seen (sources that report one)."""
        return [s.head for s in self.sources if getattr(s, "head", None)]

    def outstanding(self, minted, limit: int) -> List[Dict[str, Any]]:
        """Deposits seen and not yet minted (``minted``: the ids the chain has minted), oldest
        first, at most ``limit``. Minted ones are forgotten."""
        with self._lock:
            for deposit_id in [i for i in self._seen if i in minted]:
                del self._seen[deposit_id]
            return list(self._seen.values())[:limit]


def watcher_from_env(spec: Optional[str] = None) -> Optional[BridgeWatcher]:
    spec = (os.getenv("QRDX_BRIDGE_SOURCES", "") if spec is None else spec).strip()
    if not spec:
        return None
    sources: List[Any] = []
    for entry in (e.strip() for e in spec.split(",")):
        if not entry:
            continue
        if entry.startswith("file:"):
            sources.append(FileSource(entry[len("file:") :]))
            continue
        try:
            chain, rest = entry.split("=", 1)
            url, lockbox = rest.rsplit("@", 1)
            start = os.getenv(f"QRDX_BRIDGE_FROM_BLOCK_{int(chain)}")
            sources.append(EvmSource(int(chain), url, lockbox, int(start) if start else None))
        except ValueError:
            logger.warning("QRDX_BRIDGE_SOURCES entry %r is not chain=url@lockbox; ignored", entry)
    return BridgeWatcher(sources) if sources else None
