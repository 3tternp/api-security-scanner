"""
Baseline request cache: one benign, unmodified request per (path, method),
shared across rules within a scan, so rules can diff a probe response
against real baseline behavior instead of hardcoding absolute thresholds
(a fixed byte count, a fixed burst size, etc.) that vary per API.
"""
from typing import Dict, Optional
import asyncio
import httpx


class BaselineResponse:
    __slots__ = ("status_code", "content_length", "headers", "body", "elapsed_ms")

    def __init__(self, status_code: int, content_length: int, headers: dict, body: str, elapsed_ms: float):
        self.status_code = status_code
        self.content_length = content_length
        self.headers = headers
        self.body = body
        self.elapsed_ms = elapsed_ms


class BaselineCache:
    """Caches one baseline response per (method, path) for the duration of a scan."""

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self._cache: Dict[str, Optional[BaselineResponse]] = {}
        # Rules now run concurrently and share this cache, so a lock per key
        # coalesces simultaneous first-requests into a single HTTP call
        # instead of each rule firing its own duplicate baseline request.
        self._locks: Dict[str, asyncio.Lock] = {}

    def _key(self, method: str, path: str) -> str:
        return f"{method.upper()}:{path}"

    async def get(self, client: httpx.AsyncClient, method: str, path: str) -> Optional[BaselineResponse]:
        key = self._key(method, path)
        if key in self._cache:
            return self._cache[key]

        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._cache:
                return self._cache[key]

            result = None
            try:
                url = f"{self.target_url}{path}"
                resp = await client.request(method.upper(), url)
                result = BaselineResponse(
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    headers=dict(resp.headers),
                    body=resp.text,
                    elapsed_ms=resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0.0,
                )
            except Exception:
                result = None

            self._cache[key] = result
            return result
