from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from .errors import CloudflareError, SafetyError
from .http import request_with_retry
from .models import CloudflareItem, DesiredList


@dataclass(frozen=True)
class ListDiff:
    additions: tuple[CloudflareItem, ...]
    removals: tuple[str, ...]
    changes: tuple[CloudflareItem, ...]

    @property
    def identical(self) -> bool:
        return not (self.additions or self.removals or self.changes)


def diff_lists(desired: DesiredList, actual: list[CloudflareItem]) -> ListDiff:
    want = {item.ip: item for item in desired.items}
    have = {item.ip: item for item in actual}
    additions = tuple(want[ip] for ip in sorted(set(want) - set(have)))
    removals = tuple(sorted(set(have) - set(want)))
    changes = tuple(
        want[ip] for ip in sorted(set(want) & set(have)) if want[ip].comment != have[ip].comment
    )
    return ListDiff(additions, removals, changes)


class ListsClient:
    def __init__(
        self,
        client: httpx.Client,
        base_url: str,
        account_id: str,
        list_id: str,
        poll_interval: float = 2,
        poll_timeout: float = 120,
    ) -> None:
        self.client, self.base_url = client, base_url.rstrip("/")
        self.account_id, self.list_id = account_id, list_id
        self.poll_interval, self.poll_timeout = poll_interval, poll_timeout
        self.max_retries = 3

    @property
    def items_url(self) -> str:
        return f"{self.base_url}/accounts/{self.account_id}/rules/lists/{self.list_id}/items"

    def get_items(self) -> list[CloudflareItem]:
        response = request_with_retry(self.client, "GET", self.items_url, self.max_retries)
        if response.status_code >= 400:
            raise CloudflareError(f"list read HTTP {response.status_code}")
        try:
            return [
                CloudflareItem.model_validate(
                    {"ip": item["ip"], "comment": item.get("comment", "")}
                )
                for item in response.json().get("result", [])
            ]
        except (TypeError, ValueError) as exc:
            raise CloudflareError("invalid list response") from exc

    def replace(
        self, desired: DesiredList, allow_empty: bool = False, actual_count: int = 0
    ) -> None:
        if actual_count and not desired.items and not allow_empty:
            raise SafetyError("refusing to replace a non-empty remote list with an empty list")
        response = request_with_retry(
            self.client,
            "PUT",
            self.items_url,
            self.max_retries,
            json=[item.model_dump() for item in desired.items],
        )
        if response.status_code >= 400:
            raise CloudflareError(f"list write HTTP {response.status_code}")
        operation_id = response.json().get("result", {}).get("operation_id")
        if operation_id:
            self.wait(operation_id)
        self.verify(desired)

    def verify(self, desired: DesiredList) -> None:
        deadline = time.monotonic() + self.poll_timeout
        while True:
            if diff_lists(desired, self.get_items()).identical:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CloudflareError("remote list verification mismatch")
            time.sleep(min(self.poll_interval, remaining))

    def wait(self, operation_id: str) -> None:
        url = (
            f"{self.base_url}/accounts/{self.account_id}/rules/lists/bulk_operations/{operation_id}"
        )
        deadline = time.monotonic() + self.poll_timeout
        while time.monotonic() < deadline:
            response = request_with_retry(self.client, "GET", url, self.max_retries)
            if response.status_code >= 400:
                raise CloudflareError(f"operation poll HTTP {response.status_code}")
            result: dict[str, Any] = response.json().get("result", {})
            status = result.get("status")
            if status in {"completed", "success", "succeeded"}:
                return
            if status in {"failed", "error"}:
                raise CloudflareError(f"Cloudflare operation failed: {result}")
            time.sleep(self.poll_interval)
        raise CloudflareError("Cloudflare operation polling timed out")
