from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import WebSocket


@dataclass
class RealtimeState:
    clients: set[WebSocket] = field(default_factory=set)
    live_solves: deque[dict] = field(default_factory=lambda: deque(maxlen=200))
    first_blood: dict[str, dict] = field(default_factory=dict)


state = RealtimeState()


async def connect(ws: WebSocket) -> None:
    await ws.accept()
    state.clients.add(ws)


async def disconnect(ws: WebSocket) -> None:
    if ws in state.clients:
        state.clients.remove(ws)


async def broadcast(event: dict) -> None:
    dead = []
    for ws in state.clients:
        try:
            await ws.send_json(event)
        except Exception:  # noqa: BLE001
            dead.append(ws)
    for ws in dead:
        await disconnect(ws)


async def publish_solve_event(challenge_id: str, user_id: str, points: int) -> None:
    event = {
        'type': 'solve',
        'challenge_id': challenge_id,
        'user_id': user_id,
        'points': points,
        'ts': datetime.now(timezone.utc).isoformat(),
    }
    state.live_solves.appendleft(event)
    await broadcast(event)


async def publish_first_blood(challenge_id: str, user_id: str) -> None:
    if challenge_id in state.first_blood:
        return
    event = {
        'type': 'first_blood',
        'challenge_id': challenge_id,
        'user_id': user_id,
        'ts': datetime.now(timezone.utc).isoformat(),
    }
    state.first_blood[challenge_id] = event
    await broadcast(event)


def recent_feed(limit: int = 50) -> list[dict]:
    return list(state.live_solves)[:limit]


def fire_and_forget(coro):
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
    except RuntimeError:
        # No running loop (e.g., sync tests). Close coroutine to avoid warnings.
        try:
            coro.close()
        except Exception:
            pass


def record_solve_event(challenge_id: str, user_id: str, points: int, first_blood: bool = False) -> None:
    event = {
        'type': 'solve',
        'challenge_id': challenge_id,
        'user_id': user_id,
        'points': points,
        'ts': datetime.now(timezone.utc).isoformat(),
    }
    state.live_solves.appendleft(event)
    if first_blood and challenge_id not in state.first_blood:
        state.first_blood[challenge_id] = {
            'type': 'first_blood',
            'challenge_id': challenge_id,
            'user_id': user_id,
            'ts': datetime.now(timezone.utc).isoformat(),
        }
