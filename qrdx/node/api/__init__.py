"""
The node's REST API, by area. Each module registers its routes on qrdx.node.main's app when
main imports it.
"""

import json
from datetime import datetime
from decimal import Decimal
from typing import Optional

from starlette.requests import Request


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            # Format Decimal as a string to preserve precision
            return "{:f}".format(o)
        if isinstance(o, datetime):
            # Format datetime to a standard ISO string
            return o.isoformat()
        return super().default(o)


async def verified_sender(request: Request) -> Optional[str]:
    """The peer that signed this request, or None (the routes' FastAPI dependency).

    It looks up qrdx.node.peers.get_verified_sender when called, not when a route is
    declared, so a route module can be imported before the peers module has finished
    loading.
    """
    from qrdx.node import peers

    return await peers.get_verified_sender(request)
