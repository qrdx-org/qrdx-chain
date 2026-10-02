#!/usr/bin/env python3
"""
QRDX node container healthcheck.

Probes the node's own operational-readiness surface (qrdx/node/main.py):

    /healthz   liveness  — the process is up and serving HTTP. Always 200.
    /readyz    readiness — the DB is reachable and a chain tip exists.
                           Returns 503 until the node can serve chain data.

By default BOTH must pass, so `depends_on: { condition: service_healthy }` in
compose means "this peer can actually serve chain data to me", which is what
dependent nodes need before they bootstrap against it.

Environment
  QRDX_NODE_PORT                   Port the node listens on            [3007]
  QRDX_HEALTHCHECK_HOST            Host to probe                       [127.0.0.1]
  QRDX_HEALTHCHECK_REQUIRE_READY   'false' to accept liveness only     [true]
  QRDX_HEALTHCHECK_TIMEOUT         Per-request timeout, seconds        [4]

Exit codes: 0 = healthy, 1 = unhealthy.

Uses only the standard library so the probe stays independent of the
application's dependency tree.
"""
import json
import os
import sys
import urllib.error
import urllib.request

TRUTHY = ("1", "true", "yes", "on")


def _log(msg: str) -> None:
    sys.stderr.write(f"[healthcheck] {msg}\n")


def _get(url: str, timeout: float):
    """Return (status_code, decoded_json_or_None). Raises on transport errors."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        # /readyz answers 503 with a JSON body while the node is still catching up.
        body = e.read()
        status = e.code

    try:
        return status, json.loads(body)
    except (ValueError, TypeError):
        return status, None


def main() -> int:
    port = os.getenv("QRDX_NODE_PORT", "3007")
    host = os.getenv("QRDX_HEALTHCHECK_HOST", "127.0.0.1")
    timeout = float(os.getenv("QRDX_HEALTHCHECK_TIMEOUT", "4"))
    require_ready = os.getenv("QRDX_HEALTHCHECK_REQUIRE_READY", "true").lower() in TRUTHY

    base = f"http://{host}:{port}"

    # --- Liveness -----------------------------------------------------------
    try:
        status, payload = _get(f"{base}/healthz", timeout)
    except Exception as e:  # connection refused, DNS, timeout
        _log(f"liveness probe failed: {e}")
        return 1

    if status != 200:
        _log(f"/healthz returned HTTP {status}")
        return 1

    if not require_ready:
        return 0

    # --- Readiness ----------------------------------------------------------
    try:
        status, payload = _get(f"{base}/readyz", timeout)
    except Exception as e:
        _log(f"readiness probe failed: {e}")
        return 1

    if status == 200 and isinstance(payload, dict) and payload.get("ready") is True:
        return 0

    height = payload.get("height") if isinstance(payload, dict) else None
    _log(f"not ready yet (HTTP {status}, height={height})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
