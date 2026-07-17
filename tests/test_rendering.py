from datetime import UTC, datetime, timedelta
from pathlib import Path

from cf_ip_blacklist.models import IPRecord, State
from cf_ip_blacklist.rendering import render


def test_render_active_ip(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    state = State(
        records={
            "192.0.2.1": IPRecord(
                first_seen=now,
                last_seen=now,
                last_evaluated=now,
                status="blocked",
                score=6,
                expires_at=now + timedelta(hours=1),
                reason_codes=["probe"],
            )
        }
    )
    desired = render(tmp_path, state, now)
    assert desired.items[0].ip == "192.0.2.1"
    assert (tmp_path / "dist/blacklist.txt").read_text() == "192.0.2.1\n"


def test_render_active_cidr(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    state = State(
        records={
            "192.0.2.0/24": IPRecord(
                first_seen=now,
                last_seen=now,
                last_evaluated=now,
                status="blocked",
                score=6,
                expires_at=now + timedelta(hours=1),
                reason_codes=["manual_import"],
            )
        }
    )
    desired = render(tmp_path, state, now)
    assert desired.items[0].ip == "192.0.2.0/24"
