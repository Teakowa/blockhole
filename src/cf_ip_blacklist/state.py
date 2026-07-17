from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from .errors import ConfigurationError
from .models import State

CURRENT_SCHEMA_VERSION = 1


def load_state(path: Path) -> State:
    try:
        state = State.model_validate_json(path.read_text())
    except (OSError, ValueError) as exc:
        raise ConfigurationError(f"invalid state file {path}: {exc}") from exc
    if state.schema_version > CURRENT_SCHEMA_VERSION:
        raise ConfigurationError(f"unsupported future state schema: {state.schema_version}")
    return state


def write_state(path: Path, state: State) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(state.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def utc_now() -> datetime:
    return datetime.now(UTC)
