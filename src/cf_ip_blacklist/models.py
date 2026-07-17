from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["candidate", "blocked", "cooldown", "expired", "allowlisted"]


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    zone_id: str
    observed_at: datetime
    observed_requests: int = Field(ge=0)
    weighted_requests: float = Field(ge=0)
    paths: list[str] = Field(default_factory=list)
    suspicious_paths: int = Field(default=0, ge=0)
    error_requests: int = Field(default=0, ge=0)
    sampled: bool = False
    sample_interval: int | None = Field(default=None, ge=1)
    fingerprint: str


class IPRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    first_seen: datetime
    last_seen: datetime
    last_evaluated: datetime
    observed_requests: int = 0
    weighted_requests: float = 0
    distinct_paths: int = 0
    suspicious_paths: int = 0
    error_requests: int = 0
    observation_windows: int = 0
    source_zones: list[str] = Field(default_factory=list)
    score: float = 0
    status: Status = "candidate"
    reason_codes: list[str] = Field(default_factory=list)
    block_started_at: datetime | None = None
    expires_at: datetime | None = None
    ttl_extensions: int = 0


class State(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    checkpoints: dict[str, datetime] = Field(default_factory=dict)
    records: dict[str, IPRecord] = Field(default_factory=dict)


class CloudflareItem(BaseModel):
    ip: str
    comment: str


class DesiredList(BaseModel):
    items: list[CloudflareItem]
