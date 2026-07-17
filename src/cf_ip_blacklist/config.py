from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError


@dataclass(frozen=True)
class Thresholds:
    min_weighted_requests: float
    min_distinct_paths: int
    min_suspicious_paths: int
    max_error_ratio: float
    block_score: float


@dataclass(frozen=True)
class Settings:
    root: Path
    mode: str
    lookback_hours: int
    overlap_hours: int
    block_ttl_hours: int
    cooldown_hours: int
    max_ttl_extensions: int
    score_decay_per_day: float
    thresholds: Thresholds
    graphql_url: str
    api_base_url: str
    timeout_seconds: float
    max_retries: int
    poll_interval_seconds: float
    poll_timeout_seconds: float
    zone_ids: tuple[str, ...]
    suspicious_path_patterns: tuple[str, ...] = ()

    @property
    def state_path(self) -> Path:
        return self.root / "data/state.json"

    @property
    def allowlist_path(self) -> Path:
        return self.root / "config/allowlist.txt"

    @property
    def policy_path(self) -> Path:
        return self.root / "config/policy.toml"


def load_settings(root: Path) -> Settings:
    try:
        raw = tomllib.loads((root / "config/policy.toml").read_text())
        threshold = raw["thresholds"]
        cloudflare = raw["cloudflare"]
        configured_zones = tuple(raw.get("zones", {}).get("ids", []))
        zone_ids = (
            tuple(
                item.strip()
                for item in os.environ.get("CLOUDFLARE_ZONE_IDS", "").split(",")
                if item.strip()
            )
            or configured_zones
        )
        return Settings(
            root=root,
            mode=raw["mode"],
            lookback_hours=int(raw["lookback_hours"]),
            overlap_hours=int(raw["overlap_hours"]),
            block_ttl_hours=int(raw["block_ttl_hours"]),
            cooldown_hours=int(raw["cooldown_hours"]),
            max_ttl_extensions=int(raw["max_ttl_extensions"]),
            score_decay_per_day=float(raw["score_decay_per_day"]),
            suspicious_path_patterns=tuple(raw.get("suspicious_path_patterns", [])),
            thresholds=Thresholds(**{k: threshold[k] for k in Thresholds.__annotations__}),
            graphql_url=cloudflare["graphql_url"],
            api_base_url=cloudflare["api_base_url"],
            timeout_seconds=float(cloudflare["timeout_seconds"]),
            max_retries=int(cloudflare["max_retries"]),
            poll_interval_seconds=float(cloudflare["poll_interval_seconds"]),
            poll_timeout_seconds=float(cloudflare["poll_timeout_seconds"]),
            zone_ids=zone_ids,
        )
    except (KeyError, TypeError, ValueError, OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"invalid policy configuration: {exc}") from exc


def cloudflare_environment() -> tuple[str, str, str]:
    values = tuple(
        os.environ.get(key, "")
        for key in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_LIST_ID")
    )
    if not all(values):
        raise ConfigurationError(
            "CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, and CLOUDFLARE_LIST_ID are required"
        )
    return values  # type: ignore[return-value]
