"""Reusable middleware functions for the FastAPI app."""
from __future__ import annotations

import time
import uuid
import logging
from fastapi import Request, Response

logger = logging.getLogger("vigilink.backend.middleware")


async def add_request_id(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = rid
    start = time.time()
    logger.info("[req:%s] %s %s", rid, request.method, request.url.path)
    try:
        response: Response = await call_next(request)
    except Exception:
        logger.exception("[req:%s] handler error", rid)
        raise
    response.headers["X-Request-ID"] = rid
    logger.info("[req:%s] done %s in %.1fms", rid, request.url.path, (time.time() - start) * 1000)
    return response
