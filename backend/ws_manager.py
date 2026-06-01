"""WebSocket connection manager for real-time state broadcasting."""

import asyncio
import json
import logging
from typing import Set

logger = logging.getLogger(__name__)


def _safe_json_default(obj):
    """Fallback serializer for non-JSON-serializable objects."""
    logger.warning("Non-serializable type in WS broadcast: %s (%s)", type(obj).__name__, obj)
    return str(obj)


class ConnectionManager:
    def __init__(self):
        self._connections: Set = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket):
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)

    async def disconnect(self, websocket):
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast(self, data: dict):
        """Send state update to all connected clients."""
        if not self._connections:
            return
        message = json.dumps(data, default=_safe_json_default, ensure_ascii=False)
        dead = set()
        async with self._lock:
            targets = list(self._connections)
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        if dead:
            async with self._lock:
                self._connections -= dead

    @property
    def active_count(self) -> int:
        return len(self._connections)


manager = ConnectionManager()
