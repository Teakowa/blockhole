from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Any

import httpx

from .errors import CloudflareError
from .http import request_with_retry
from .models import Observation
from .policy import normalize_ip

QUERY = """
query Requests($zone: String!, $start: DateTime!, $end: DateTime!) {
  viewer { zones(filter: {zoneTag: $zone}) {
    series: httpRequestsAdaptiveGroups(
      limit: 1000, filter: {datetime_geq: $start, datetime_lt: $end},
      orderBy: [count_DESC]
    ) {
      dimensions { clientIP edgeResponseStatus }
      count
    }
  } }
}
"""


def _error_message(payload: dict[str, Any]) -> str:
    errors = payload.get("errors") or payload.get("messages") or []
    return "; ".join(str(item.get("message", item)) for item in errors)


def parse_grouped(
    payload: dict[str, Any], zone_id: str, observed_at: datetime
) -> list[Observation]:
    if payload.get("errors"):
        raise CloudflareError(f"GraphQL error: {_error_message(payload)}")
    try:
        rows = payload["data"]["viewer"]["zones"][0]["series"]
    except (KeyError, IndexError, TypeError) as exc:
        raise CloudflareError("GraphQL response missing required series fields") from exc
    observations: list[Observation] = []
    for row in rows:
        try:
            dimensions = row["dimensions"]
            ip = normalize_ip(dimensions["clientIP"])
            response_status = int(dimensions["edgeResponseStatus"])
            count = int(row["count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CloudflareError("invalid grouped analytics row") from exc
        fingerprint = sha256(f"{zone_id}:{ip}:{observed_at.isoformat()}".encode()).hexdigest()[:16]
        observations.append(
            Observation(
                ip=ip,
                zone_id=zone_id,
                observed_at=observed_at,
                observed_requests=count,
                weighted_requests=float(count),
                error_requests=count if response_status >= 400 else 0,
                fingerprint=fingerprint,
            )
        )
    return observations


class AnalyticsClient:
    def __init__(self, client: httpx.Client, url: str, max_retries: int = 3) -> None:
        self.client = client
        self.url = url
        self.max_retries = max_retries

    def collect(self, zone_id: str, start: datetime, end: datetime) -> list[Observation]:
        response = request_with_retry(
            self.client,
            "POST",
            self.url,
            self.max_retries,
            json={
                "query": QUERY,
                "variables": {
                    "zone": zone_id,
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                },
            },
        )
        if response.status_code >= 400:
            raise CloudflareError(f"GraphQL HTTP {response.status_code}")
        return parse_grouped(response.json(), zone_id, end)
