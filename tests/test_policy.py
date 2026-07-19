from datetime import UTC, datetime, timedelta

from cf_ip_blacklist.config import Settings, Thresholds
from cf_ip_blacklist.models import IPRecord, Observation
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
    assert is_allowlisted("192.0.2.0/25", (ipaddress.ip_network("192.0.2.0/24"),))


def test_multiple_signals_are_required_for_block() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    observation = Observation(
        ip="192.0.2.1",
        zone_id="zone",
        observed_at=now,
        observed_requests=200,
        weighted_requests=200,
        paths=["/a", "/b", "/c", "/d", "/e"],
        suspicious_paths=2,
        error_requests=180,
        fingerprint="x",
    )
    record = evaluate_observations([observation], None, settings(), now)
    assert record.status == "blocked"
    assert "suspicious_paths" in record.reason_codes


def test_high_volume_and_broad_paths_without_scanning_stays_candidate() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    observations = [
        Observation(
            ip="192.0.2.1",
            zone_id="zone-a",
            observed_at=now,
            observed_requests=300,
            weighted_requests=300,
            paths=["/a", "/b", "/c", "/d", "/e"],
            fingerprint="a",
        ),
        Observation(
            ip="192.0.2.1",
            zone_id="zone-b",
            observed_at=now,
            observed_requests=300,
            weighted_requests=300,
            paths=["/f", "/g", "/h", "/i", "/j"],
            fingerprint="b",
        ),
    ]

    record = evaluate_observations(observations, None, settings(), now)

    assert record.status == "candidate"
    assert record.suspicious_paths == 0


def test_one_scanning_path_is_not_enough_to_block() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    observation = Observation(
        ip="192.0.2.1",
        zone_id="zone",
        observed_at=now,
        observed_requests=300,
        weighted_requests=300,
        paths=["/a", "/b", "/c", "/d", "/e"],
        suspicious_paths=1,
        error_requests=270,
        fingerprint="x",
    )

    record = evaluate_observations([observation], None, settings(), now)

    assert record.status == "candidate"


def test_existing_block_without_scanning_features_is_released() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    existing = IPRecord(
        first_seen=now,
        last_seen=now,
        last_evaluated=now,
        observed_requests=4323,
        weighted_requests=5746,
        distinct_paths=114,
        suspicious_paths=0,
        error_requests=135,
        observation_windows=7,
        source_zones=["zone-a", "zone-b"],
        score=7,
        status="blocked",
        block_started_at=now,
        expires_at=now + timedelta(hours=1),
    )

    record = evaluate_observations([], existing, settings(), now)

    assert record.status == "candidate"
    assert record.block_started_at is None
    assert record.expires_at is None
