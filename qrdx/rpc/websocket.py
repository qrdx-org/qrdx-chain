"""
QRDX WebSocket JSON-RPC 2.0 Server with Subscriptions

Provides real-time event streaming:
  - eth_subscribe / eth_unsubscribe (Ethereum-compatible)
  - newHeads          — new block headers
  - newPendingTransactions — mempool arrivals
  - logs              — filtered contract event logs

Connection management:
  - Max connections enforced
  - Per-connection subscription limits
  - Ping/pong keepalive
  - Graceful shutdown
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from .server import RPCError, RPCErrorCode, RPCResponse, RPCServer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Subscription types
# ---------------------------------------------------------------------------

class SubscriptionType(str, Enum):
    """Supported subscription channels."""
    NEW_HEADS = "newHeads"
    NEW_PENDING_TRANSACTIONS = "newPendingTransactions"
    LOGS = "logs"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Subscription:
    """A single subscription held by a connection."""
    id: str
    sub_type: SubscriptionType
    filter_params: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)


@dataclass
class WSConnection:
    """Tracks one WebSocket client connection."""
    id: str
    subscriptions: Dict[str, Subscription] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_ping: float = field(default_factory=time.time)
    # send_fn will be set when binding to actual WebSocket transport
    send_fn: Optional[Callable] = None
    closed: bool = False

    @property
    def subscription_count(self) -> int:
        return len(self.subscriptions)


# ---------------------------------------------------------------------------
# WebSocket subscription manager
# ---------------------------------------------------------------------------

class WebSocketManager:
    """
    Manages WebSocket connections and subscriptions.

    This class is transport-agnostic — it manages subscription state
    and event dispatch.  The actual WebSocket I/O is handled by the
    transport layer (e.g. FastAPI/Starlette WebSocket).
    """

    def __init__(
        self,
        rpc_server: Optional[RPCServer] = None,
        max_connections: int = 100,
        max_subscriptions_per_conn: int = 100,
        ping_interval: float = 30.0,
    ):
        self.rpc_server = rpc_server
        self.max_connections = max_connections
        self.max_subscriptions_per_conn = max_subscriptions_per_conn
        self.ping_interval = ping_interval

        # Active connections
        self._connections: Dict[str, WSConnection] = {}

        # Subscription index: sub_type → set of (conn_id, sub_id)
        self._type_index: Dict[SubscriptionType, Set[tuple]] = {
            st: set() for st in SubscriptionType
        }

        # Stats
        self.total_connections_served: int = 0
        self.total_subscriptions_created: int = 0
        self.total_events_dispatched: int = 0

    # -- Connection lifecycle -----------------------------------------------

    def connect(self, send_fn: Optional[Callable] = None) -> WSConnection:
        """
        Register a new WebSocket connection.

        Args:
            send_fn: Async callable to send data to the client.

        Returns:
            WSConnection instance

        Raises:
            RPCError: if max connections exceeded
        """
        if len(self._connections) >= self.max_connections:
            raise RPCError(
                RPCErrorCode.LIMIT_EXCEEDED,
                f"Max WebSocket connections reached ({self.max_connections})"
            )

        conn_id = uuid.uuid4().hex[:16]
        conn = WSConnection(id=conn_id, send_fn=send_fn)
        self._connections[conn_id] = conn
        self.total_connections_served += 1
        logger.info("WS connect: %s (active=%d)", conn_id, len(self._connections))
        return conn

    def disconnect(self, conn_id: str) -> None:
        """
        Remove a connection and all its subscriptions.

        Args:
            conn_id: Connection ID to remove
        """
        conn = self._connections.pop(conn_id, None)
        if conn is None:
            return

        conn.closed = True
        # Clean up all subscriptions
        for sub_id, sub in conn.subscriptions.items():
            self._type_index[sub.sub_type].discard((conn_id, sub_id))
        conn.subscriptions.clear()

        logger.info("WS disconnect: %s (active=%d)", conn_id, len(self._connections))

    # -- Subscriptions ------------------------------------------------------

    def subscribe(
        self,
        conn_id: str,
        sub_type: str,
        filter_params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a subscription on a connection.

        Args:
            conn_id: Connection ID
            sub_type: Subscription type name (e.g. "newHeads")
            filter_params: Optional filter (for "logs" type)

        Returns:
            Subscription ID (hex string)

        Raises:
            RPCError: on invalid type, missing connection, or limit exceeded
        """
        conn = self._connections.get(conn_id)
        if conn is None:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Connection not found")

        # Validate type
        try:
            st = SubscriptionType(sub_type)
        except ValueError:
            raise RPCError(
                RPCErrorCode.INVALID_PARAMS,
                f"Unknown subscription type: {sub_type}. "
                f"Valid: {[t.value for t in SubscriptionType]}"
            )

        # Check limit
        if conn.subscription_count >= self.max_subscriptions_per_conn:
            raise RPCError(
                RPCErrorCode.LIMIT_EXCEEDED,
                f"Max subscriptions per connection reached ({self.max_subscriptions_per_conn})"
            )

        sub_id = uuid.uuid4().hex[:16]
        sub = Subscription(id=sub_id, sub_type=st, filter_params=filter_params)
        conn.subscriptions[sub_id] = sub
        self._type_index[st].add((conn_id, sub_id))
        self.total_subscriptions_created += 1

        logger.debug(
            "WS subscribe: conn=%s type=%s sub=%s",
            conn_id, sub_type, sub_id,
        )
        return sub_id

    def unsubscribe(self, conn_id: str, sub_id: str) -> bool:
        """
        Remove a subscription.

        Args:
            conn_id: Connection ID
            sub_id: Subscription ID

        Returns:
            True if removed, False if not found
        """
        conn = self._connections.get(conn_id)
        if conn is None:
            return False

        sub = conn.subscriptions.pop(sub_id, None)
        if sub is None:
            return False

        self._type_index[sub.sub_type].discard((conn_id, sub_id))
        logger.debug("WS unsubscribe: conn=%s sub=%s", conn_id, sub_id)
        return True

    # -- Event dispatch -----------------------------------------------------

    async def publish(
        self,
        sub_type: SubscriptionType,
        data: Any,
    ) -> int:
        """
        Publish an event to all subscribers of a given type.

        For ``logs`` subscriptions, *data* is filtered against each
        subscription's ``filter_params`` before delivery.

        Args:
            sub_type: Event type
            data: Event payload

        Returns:
            Number of notifications sent
        """
        targets = list(self._type_index.get(sub_type, set()))
        if not targets:
            return 0

        sent = 0
        for conn_id, sub_id in targets:
            conn = self._connections.get(conn_id)
            if conn is None or conn.closed:
                self._type_index[sub_type].discard((conn_id, sub_id))
                continue

            sub = conn.subscriptions.get(sub_id)
            if sub is None:
                self._type_index[sub_type].discard((conn_id, sub_id))
                continue

            # Log filtering
            if sub_type == SubscriptionType.LOGS and sub.filter_params:
                if not self._match_log_filter(data, sub.filter_params):
                    continue

            notification = {
                "jsonrpc": "2.0",
                "method": "eth_subscription",
                "params": {
                    "subscription": sub_id,
                    "result": data,
                },
            }

            if conn.send_fn:
                try:
                    await conn.send_fn(json.dumps(notification))
                    sent += 1
                except Exception:
                    logger.warning("Failed to send to conn %s, disconnecting", conn_id)
                    self.disconnect(conn_id)
            else:
                # No transport bound — used in testing
                sent += 1

        self.total_events_dispatched += sent
        return sent

    # -- Log filtering ------------------------------------------------------

    @staticmethod
    def _match_log_filter(
        log_entry: Dict[str, Any],
        filter_params: Dict[str, Any],
    ) -> bool:
        """
        Check if a log entry matches subscription filter params.

        Filter params can specify:
            - address: single address or list
            - topics: list of topic patterns (null = wildcard)
        """
        # Address filter
        if "address" in filter_params:
            addresses = filter_params["address"]
            if isinstance(addresses, str):
                addresses = [addresses]
            log_addr = log_entry.get("address", "")
            if log_addr.lower() not in [a.lower() for a in addresses]:
                return False

        # Topic filter
        if "topics" in filter_params:
            filter_topics = filter_params["topics"]
            log_topics = log_entry.get("topics", [])

            for i, ft in enumerate(filter_topics):
                if ft is None:
                    continue  # wildcard
                if i >= len(log_topics):
                    return False
                if isinstance(ft, list):
                    # OR match
                    if log_topics[i] not in ft:
                        return False
                elif log_topics[i] != ft:
                    return False

        return True

    # -- RPC handler --------------------------------------------------------

    async def handle_rpc_message(
        self,
        conn_id: str,
        raw_data: str,
    ) -> Optional[str]:
        """
        Handle a JSON-RPC message arriving on a WebSocket.

        Intercepts ``eth_subscribe`` and ``eth_unsubscribe``, delegates
        all other methods to the underlying RPCServer.

        Args:
            conn_id: Connection ID
            raw_data: Raw JSON string

        Returns:
            JSON response string, or None for notifications
        """
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError:
            return RPCResponse(
                error=RPCError(RPCErrorCode.PARSE_ERROR, "Parse error").to_dict()
            ).to_json()

        # Only handle single requests (no batch over WS for subscriptions)
        if isinstance(parsed, list):
            # Batch: delegate to RPCServer
            if self.rpc_server:
                return await self.rpc_server.handle_request(parsed)
            return RPCResponse(
                error=RPCError(RPCErrorCode.INTERNAL_ERROR, "No RPC server").to_dict()
            ).to_json()

        method = parsed.get("method", "")
        params = parsed.get("params", [])
        req_id = parsed.get("id")

        # --- eth_subscribe ---
        if method == "eth_subscribe":
            try:
                sub_type = params[0] if params else ""
                filter_params = params[1] if len(params) > 1 else None
                sub_id = self.subscribe(conn_id, sub_type, filter_params)
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": sub_id,
                })
            except RPCError as e:
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": e.to_dict(),
                })

        # --- eth_unsubscribe ---
        if method == "eth_unsubscribe":
            sub_id = params[0] if params else ""
            ok = self.unsubscribe(conn_id, sub_id)
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": ok,
            })

        # --- everything else → RPCServer ---
        if self.rpc_server:
            return await self.rpc_server.handle_request(parsed)

        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": RPCError(RPCErrorCode.INTERNAL_ERROR, "No RPC server").to_dict(),
        })

    # -- Diagnostics --------------------------------------------------------

    @property
    def active_connections(self) -> int:
        return len(self._connections)

    @property
    def active_subscriptions(self) -> int:
        return sum(c.subscription_count for c in self._connections.values())

    def get_stats(self) -> Dict[str, Any]:
        """Return manager statistics."""
        return {
            "active_connections": self.active_connections,
            "active_subscriptions": self.active_subscriptions,
            "total_connections_served": self.total_connections_served,
            "total_subscriptions_created": self.total_subscriptions_created,
            "total_events_dispatched": self.total_events_dispatched,
            "subscriptions_by_type": {
                st.value: len(subs) for st, subs in self._type_index.items()
            },
        }
