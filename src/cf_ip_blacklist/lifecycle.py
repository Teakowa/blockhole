from __future__ import annotations

from datetime import datetime, timedelta

from .config import Settings
from .models import IPRecord


def apply_lifecycle(
    record: IPRecord, settings: Settings, now: datetime, allowlisted: bool
) -> IPRecord:
    if allowlisted:
        record.status = "allowlisted"
        return record
    if record.status == "blocked" and record.expires_at and now >= record.expires_at:
        record.status = "cooldown"
    if record.status == "cooldown" and record.expires_at:
        cooldown_end = record.expires_at + timedelta(hours=settings.cooldown_hours)
        if now >= cooldown_end:
            record.status = "expired"
    if record.status in {"candidate", "blocked"} and record.last_evaluated < now:
        days = (now - record.last_evaluated).total_seconds() / 86400
        record.score = round(max(0, record.score - days * settings.score_decay_per_day), 4)
    return record


def active_records(records: dict[str, IPRecord], now: datetime) -> dict[str, IPRecord]:
    return {
        ip: record
        for ip, record in records.items()
        if record.status == "blocked" and record.expires_at is not None and record.expires_at > now
    }
