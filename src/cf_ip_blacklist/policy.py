from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from .config import Settings
from .models import IPRecord, Observation


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value}") from exc


def load_allowlist(path: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    with open(path) as handle:
        for line_number, raw in enumerate(handle, start=1):
            value = raw.split("#", 1)[0].strip()
            if not value:
                continue
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise ValueError(f"invalid allowlist entry at line {line_number}: {value}") from exc
    return tuple(networks)


def is_allowlisted(
    ip: str, networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in network for network in networks)


def evaluate_observations(
    observations: list[Observation], existing: IPRecord | None, settings: Settings, now: datetime
) -> IPRecord:
    if not observations and existing is None:
        raise ValueError("cannot evaluate an empty observation set without existing state")
    first_seen = min(
        (o.observed_at for o in observations), default=existing.first_seen if existing else now
    )
    last_seen = max(
        (o.observed_at for o in observations), default=existing.last_seen if existing else now
    )
    observed = sum(o.observed_requests for o in observations) + (
        existing.observed_requests if existing else 0
    )
    weighted = sum(o.weighted_requests for o in observations) + (
        existing.weighted_requests if existing else 0
    )
    paths = {path for observation in observations for path in observation.paths}
    distinct_paths = max(len(paths), existing.distinct_paths if existing else 0)
    suspicious = sum(o.suspicious_paths for o in observations) + (
        existing.suspicious_paths if existing else 0
    )
    errors = sum(o.error_requests for o in observations) + (
        existing.error_requests if existing else 0
    )
    zones = sorted(
        {o.zone_id for o in observations} | set(existing.source_zones if existing else [])
    )
    windows = (existing.observation_windows if existing else 0) + (1 if observations else 0)
    error_ratio = errors / observed if observed else 0
    reasons: list[str] = []
    score = 0.0
    if weighted >= settings.thresholds.min_weighted_requests:
        score += 2
        reasons.append("request_volume")
    if distinct_paths >= settings.thresholds.min_distinct_paths:
        score += 2
        reasons.append("path_breadth")
    if suspicious >= settings.thresholds.min_suspicious_paths:
        score += 3
        reasons.append("suspicious_paths")
    if error_ratio >= settings.thresholds.max_error_ratio and observed > 0:
        score += 1
        reasons.append("high_error_ratio")
    if windows >= 2:
        score += 2
        reasons.append("repeated_windows")
    if len(zones) >= 2:
        score += 1
        reasons.append("multiple_zones")
    status = existing.status if existing else "candidate"
    blocked_at = existing.block_started_at if existing else None
    expires_at = existing.expires_at if existing else None
    extensions = existing.ttl_extensions if existing else 0
    if score >= settings.thresholds.block_score and len(reasons) >= 2:
        status = "blocked"
        blocked_at = blocked_at or now
        if expires_at is None:
            expires_at = now + timedelta(hours=settings.block_ttl_hours)
    return IPRecord(
        first_seen=first_seen,
        last_seen=last_seen,
        last_evaluated=now,
        observed_requests=observed,
        weighted_requests=weighted,
        distinct_paths=distinct_paths,
        suspicious_paths=suspicious,
        error_requests=errors,
        observation_windows=windows,
        source_zones=zones,
        score=round(score, 4),
        status=status,
        reason_codes=sorted(set(reasons)),
        block_started_at=blocked_at,
        expires_at=expires_at,
        ttl_extensions=extensions,
    )
