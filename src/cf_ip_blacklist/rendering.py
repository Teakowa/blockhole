from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .lifecycle import active_records
from .models import CloudflareItem, DesiredList, State


def sorted_ips(ips: list[str]) -> list[str]:
    import ipaddress

    return sorted(
        ips,
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )


def render(root: Path, state: State, now: datetime) -> DesiredList:
    active = active_records(state.records, now)
    items: list[CloudflareItem] = []
    for ip in sorted_ips(list(active)):
        expires_at = active[ip].expires_at
        assert expires_at is not None
        items.append(
            CloudflareItem(
                ip=ip,
                comment=(
                    f"score={active[ip].score:g}; reasons={','.join(active[ip].reason_codes)}; "
                    f"expires={expires_at.isoformat()}"
                ),
            )
        )
    desired = DesiredList(items=items)
    dist = root / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "blacklist.txt").write_text("".join(f"{item.ip}\n" for item in items))
    (dist / "cloudflare-list.json").write_text(
        json.dumps(desired.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    )
    report = root / "reports/latest.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        "# Latest run\n\n"
        f"- Mode: generated\n- Evaluated at: {now.astimezone(UTC).isoformat()}\n"
        f"- Active blocked IPs: {len(items)}\n"
    )
    return desired
