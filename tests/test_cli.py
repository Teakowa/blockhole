from datetime import UTC, datetime, timedelta

from cf_ip_blacklist.cli import _collection_window


def test_collection_starts_at_checkpoint_after_bootstrap(tmp_path, monkeypatch) -> None:
    now = datetime(2026, 7, 18, 1, tzinfo=UTC)
    checkpoint = now - timedelta(hours=1)

    class State:
        checkpoints = {"analytics": checkpoint}

    class Settings:
        lookback_hours = 24
        state_path = tmp_path / "state.json"

    monkeypatch.setattr("cf_ip_blacklist.cli.load_settings", lambda _: Settings())
    monkeypatch.setattr("cf_ip_blacklist.cli.load_state", lambda _: State())
    monkeypatch.setattr("cf_ip_blacklist.cli.utc_now", lambda: now)

    assert _collection_window(tmp_path) == (checkpoint, now)
