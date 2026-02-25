"""Redis Pub/Sub bridge for cross-process WebSocket event delivery.

Problem: The agent orchestrator runs inside **Celery worker** processes,
but WebSocket connections live in the **FastAPI** process.  The in-memory
``ws_manager`` singleton in the Celery worker has 0 connected clients,
so all events published there are lost.

Solution: Every call to ``publish_event()`` pushes the event JSON into a
Redis Pub/Sub channel.  The FastAPI process runs a background subscriber
(``start_subscriber()``) that reads from that channel and forwards each
event to ``ws_manager`` for delivery to real WebSocket clients.

Usage
-----

**Publisher side** (Celery workers / anywhere)::

    from src.core.redis_pubsub import publish_event
    await publish_event(session_id, "tool_started", {...})

    # or sync-friendly:
    publish_event_sync(session_id, "tool_started", {...})

**Subscriber side** (FastAPI startup)::

    from src.core.redis_pubsub import start_subscriber, stop_subscriber
    # In lifespan:
    task = await start_subscriber()
    yield
    await stop_subscriber(task)
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis

from src.config import settings

logger = logging.getLogger(__name__)

CHANNEL = "webphomet:ws_events"

# ---------------------------------------------------------------------------
# Async Redis pool (lazy-init, for subscriber in FastAPI only)
# ---------------------------------------------------------------------------

_redis_pool: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
        )
    return _redis_pool


# ---------------------------------------------------------------------------
# Sync Redis client (for publisher side — reliable in Celery forks)
# ---------------------------------------------------------------------------

import redis as sync_redis
import threading

_sync_redis_local = threading.local()


def _get_sync_redis() -> sync_redis.Redis:
    """Get a per-thread sync Redis client (safe in forked Celery workers)."""
    if not hasattr(_sync_redis_local, "client") or _sync_redis_local.client is None:
        _sync_redis_local.client = sync_redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
        )
    return _sync_redis_local.client


# ---------------------------------------------------------------------------
# Publisher — called from Celery workers (or anywhere)
# ---------------------------------------------------------------------------


async def publish_event(
    session_id: str,
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Publish a WS event to Redis so the FastAPI subscriber can forward it.

    Uses sync Redis under the hood for reliability in Celery fork workers.
    """
    _publish_sync(session_id, event_type, data)


def _publish_sync(
    session_id: str,
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Sync publish — works everywhere (Celery workers, threads, etc.)."""
    message = json.dumps(
        {
            "type": event_type,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        },
        default=str,
    )
    try:
        r = _get_sync_redis()
        r.publish(CHANNEL, message)
    except Exception:
        logger.warning("Redis publish failed", exc_info=True)


def publish_event_sync(
    session_id: str,
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Explicit sync entry point for non-async callers."""
    _publish_sync(session_id, event_type, data)


# ---------------------------------------------------------------------------
# Subscriber — runs as a background asyncio task in the FastAPI process
# ---------------------------------------------------------------------------

_subscriber_task: asyncio.Task[None] | None = None


async def _subscriber_loop() -> None:
    """Subscribe to the Redis channel and forward events to ws_manager."""
    from src.core.ws_manager import ws_manager

    while True:
        try:
            r = await _get_redis()
            pubsub = r.pubsub()
            await pubsub.subscribe(CHANNEL)
            logger.info("Redis WS subscriber started on channel %s", CHANNEL)

            async for raw_msg in pubsub.listen():
                if raw_msg["type"] != "message":
                    continue
                try:
                    evt = json.loads(raw_msg["data"])
                    session_id = evt.get("session_id")
                    logger.info(
                        "Redis event received: type=%s session=%s conns=%d",
                        evt.get("type"),
                        session_id,
                        ws_manager.active_connections,
                    )
                    if session_id:
                        # Forward directly — ws_manager will deliver to WS clients
                        await ws_manager._deliver_raw(session_id, raw_msg["data"])
                    else:
                        await ws_manager._broadcast_raw(raw_msg["data"])
                except Exception:
                    logger.warning("Failed to forward Redis event", exc_info=True)

        except asyncio.CancelledError:
            logger.info("Redis WS subscriber cancelled")
            break
        except Exception:
            logger.warning("Redis subscriber error, reconnecting in 2s", exc_info=True)
            await asyncio.sleep(2)


async def start_subscriber() -> asyncio.Task[None]:
    """Start the background Redis subscriber task.  Call in FastAPI lifespan."""
    global _subscriber_task
    _subscriber_task = asyncio.create_task(_subscriber_loop())
    return _subscriber_task


async def stop_subscriber(task: asyncio.Task[None] | None = None) -> None:
    """Cancel the subscriber task.  Call on FastAPI shutdown."""
    global _subscriber_task, _redis_pool
    t = task or _subscriber_task
    if t and not t.done():
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    _subscriber_task = None
    if _redis_pool:
        await _redis_pool.aclose()
        _redis_pool = None
