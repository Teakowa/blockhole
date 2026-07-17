from datetime import UTC, datetime

from cf_ip_blacklist.config import Settings, Thresholds
from cf_ip_blacklist.models import Observation
from cf_ip_blacklist.policy import evaluate_observations, is_allowlisted, normalize_ip


def settings() -> Settings:
    return Settings(
        root=__import__("pathlib").Path("."),
        mode="dry-run",
        lookback_hours=24,
        overlap_hours=2,
        block_ttl_hours=72,
        cooldown_hours=24,
        max_ttl_extensions=3,
        score_decay_per_day=0.25,
        thresholds=Thresholds(100, 2, 2, 0.8, 6),
        graphql_url="",
        api_base_url="",
        timeout_seconds=30,
        max_retries=3,
        poll_interval_seconds=1,
        poll_timeout_seconds=10,
        zone_ids=("zone",),
    )


def test_ip_normalization_and_cidr_allowlist() -> None:
    import ipaddress

    assert normalize_ip(" 192.0.2.1 ") == "192.0.2.1"
    assert is_allowlisted("192.0.2.1", (ipaddress.ip_network("192.0.2.0/24"),))


def test_multiple_signals_are_required_for_block() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    observation = Observation(
        ip="192.0.2.1",
        zone_id="zone",
        observed_at=now,
        observed_requests=200,
        weighted_requests=200,
        paths=["/a", "/b"],
        suspicious_paths=2,
        error_requests=180,
        fingerprint="x",
    )
    record = evaluate_observations([observation], None, settings(), now)
    assert record.status == "blocked"
    assert "suspicious_paths" in record.reason_codes
