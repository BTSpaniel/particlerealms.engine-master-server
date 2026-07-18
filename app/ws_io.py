# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""WebSocket frame helpers that reject binary application messages cleanly."""

from __future__ import annotations

import asyncio

from fastapi import WebSocket, WebSocketDisconnect


async def receive_text_frame(websocket: WebSocket) -> str:
    message = await websocket.receive()
    message_type = message.get("type")
    if message_type == "websocket.disconnect":
        raise WebSocketDisconnect(code=message.get("code", 1000), reason=message.get("reason", ""))
    text = message.get("text")
    if message_type != "websocket.receive" or not isinstance(text, str):
        try:
            await websocket.close(code=1003, reason="text frames required")
        finally:
            raise WebSocketDisconnect(code=1003, reason="text frames required")
    return text


async def send_json_frame(websocket: WebSocket, value) -> None:
    """Serialize writes from the session control loop and relay writer."""
    lock = getattr(websocket, "_particle_send_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        setattr(websocket, "_particle_send_lock", lock)
    async with lock:
        timeout = getattr(websocket, "_particle_send_timeout", None)
        try:
            if timeout is None:
                await websocket.send_json(value)
            else:
                await asyncio.wait_for(websocket.send_json(value), timeout=timeout)
        except asyncio.TimeoutError as exc:
            try:
                await asyncio.wait_for(websocket.close(code=1013, reason="slow client"), timeout=1.0)
            except Exception:
                pass
            raise WebSocketDisconnect(code=1013, reason="slow client") from exc
