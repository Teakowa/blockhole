from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from .analytics import AnalyticsClient
from .config import cloudflare_environment, load_settings
from .errors import BlacklistError, ConfigurationError
from .lifecycle import apply_lifecycle
from .models import Observation
from .policy import evaluate_observations, is_allowlisted, load_allowlist
from .rendering import render
from .state import load_state, utc_now, write_state
from .sync import ListsClient, diff_lists

ANALYTICS_CHECKPOINT = "analytics"


def _root() -> Path:
    return Path.cwd()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Maintain a cautious Cloudflare IP denylist.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "collect", "evaluate", "render", "sync"):
        sub.add_parser(name)
    run = sub.add_parser("run")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--lookback-hours", type=int)
    run.add_argument("--force-rebuild", action="store_true")
    run.add_argument("--allow-empty", action="store_true")
    run.add_argument("--report-path", type=Path, default=Path("reports/latest.md"))
    return parser


def _http_client(settings: object, token: str = "") -> httpx.Client:
    headers = {"User-Agent": "cf-ip-blacklist/0.1", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(headers=headers, timeout=httpx.Timeout(30.0, connect=10.0))


def validate(root: Path) -> None:
    settings = load_settings(root)
    networks = load_allowlist(str(settings.allowlist_path))
    state = load_state(settings.state_path)
    if settings.mode not in {"dry-run", "enforce"}:
        raise ConfigurationError("policy mode must be dry-run or enforce")
    if settings.lookback_hours <= settings.overlap_hours:
        raise ConfigurationError("lookback_hours must exceed overlap_hours")
    print(f"valid: {len(networks)} allowlist entries, {len(state.records)} state records")


def _collection_window(root: Path, lookback_hours: int | None = None) -> tuple[datetime, datetime]:
    settings = load_settings(root)
    state = load_state(settings.state_path)
    end = utc_now()
    checkpoint = state.checkpoints.get(ANALYTICS_CHECKPOINT)
    if checkpoint is not None and checkpoint < end:
        return checkpoint, end
    return end - timedelta(hours=lookback_hours or settings.lookback_hours), end


def _collect_window(root: Path, start: datetime, end: datetime) -> list[Observation]:
    settings = load_settings(root)
    token, _, _ = cloudflare_environment()
    if not settings.zone_ids:
        raise ConfigurationError("no zone IDs configured in config/policy.toml")
    with _http_client(settings, token) as client:
        analytics = AnalyticsClient(
            client,
            settings.graphql_url,
            settings.max_retries,
            settings.suspicious_path_patterns,
        )
        observations: list[Observation] = []
        for zone_id in settings.zone_ids:
            observations.extend(analytics.collect(zone_id, start, end))
    print(
        json.dumps(
            [item.model_dump(mode="json") for item in observations], indent=2, sort_keys=True
        )
    )
    return observations


def collect(root: Path, lookback_hours: int | None = None) -> list[Observation]:
    start, end = _collection_window(root, lookback_hours)
    return _collect_window(root, start, end)


def evaluate(
    root: Path,
    observations: list[Observation] | None = None,
    checkpoint: datetime | None = None,
) -> None:
    settings = load_settings(root)
    state = load_state(settings.state_path)
    now = utc_now()
    allowlist = load_allowlist(str(settings.allowlist_path))
    if observations is None:
        observations = []
    grouped: dict[str, list[Observation]] = {}
    for observation in observations:
        grouped.setdefault(observation.ip, []).append(observation)
    for ip, values in grouped.items():
        record = evaluate_observations(values, state.records.get(ip), settings, now)
        state.records[ip] = apply_lifecycle(record, settings, now, is_allowlisted(ip, allowlist))
    if checkpoint is None and observations:
        checkpoint = max(observation.observed_at for observation in observations)
    if checkpoint is not None:
        state.checkpoints[ANALYTICS_CHECKPOINT] = checkpoint
    write_state(settings.state_path, state)


def sync(root: Path, allow_empty: bool = False, dry_run: bool = False) -> None:
    settings = load_settings(root)
    token, account_id, list_id = cloudflare_environment()
    desired_path = root / "dist/cloudflare-list.json"
    from .models import DesiredList

    desired = DesiredList.model_validate_json(desired_path.read_text())
    with _http_client(settings, token) as client:
        lists = ListsClient(
            client,
            settings.api_base_url,
            account_id,
            list_id,
            settings.poll_interval_seconds,
            settings.poll_timeout_seconds,
        )
        actual = lists.get_items()
        diff = diff_lists(desired, actual)
        print(f"add={len(diff.additions)} remove={len(diff.removals)} change={len(diff.changes)}")
        if dry_run or settings.mode == "dry-run" or diff.identical:
            return
        lists.replace(desired, allow_empty=allow_empty, actual_count=len(actual))


def run(root: Path, args: argparse.Namespace) -> None:
    validate(root)
    start, end = _collection_window(root, args.lookback_hours)
    observations = _collect_window(root, start, end)
    evaluate(root, observations, checkpoint=end)
    desired = render(root, load_state(root / "data/state.json"), datetime.now(UTC))
    if not desired.items and not args.allow_empty:
        print("empty desired list rendered; remote synchronization remains fused")
    sync(root, allow_empty=args.allow_empty, dry_run=args.dry_run)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = _root()
    try:
        if args.command == "validate":
            validate(root)
        elif args.command == "collect":
            collect(root)
        elif args.command == "evaluate":
            evaluate(root)
        elif args.command == "render":
            render(root, load_state(root / "data/state.json"), utc_now())
        elif args.command == "sync":
            sync(root)
        else:
            run(root, args)
        return 0
    except BlacklistError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
