from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from .errors import CloudflareError

RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    max_retries: int,
    sleeper: Callable[[float], None] = time.sleep,
    **kwargs: Any,
) -> httpx.Response:
    for attempt in range(max_retries + 1):
        try:
            response = client.request(method, url, **kwargs)
        except httpx.RequestError as exc:
            if attempt >= max_retries:
                raise CloudflareError(f"Cloudflare request failed: {exc}") from exc
            sleeper(float(2**attempt))
            continue
        if response.status_code not in RETRYABLE_STATUS or attempt >= max_retries:
            return response
        retry_after = response.headers.get("Retry-After")
        try:
            delay = max(0.0, float(retry_after)) if retry_after else float(2**attempt)
        except ValueError:
            delay = float(2**attempt)
        sleeper(delay)
    raise CloudflareError("Cloudflare request retry loop ended unexpectedly")
