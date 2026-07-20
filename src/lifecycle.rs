use crate::{
    config::Settings,
    error::{BlockholeError, Result},
    models::{IpRecord, Observation, RecordStatus, Subject},
    policy,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;

/// Compute the next state of an IP record in a single, idempotent pass.
///
/// Merges new observations, computes signal scores, applies time-based decay,
/// determines status transitions, and sets `last_evaluated = now`.
///
/// Calling this function twice with the same `now` and empty `observations`
/// on the result produces an identical record.
pub fn transition(
    previous: Option<&IpRecord>,
    observations: &[Observation],
    settings: &Settings,
    now: DateTime<Utc>,
    allowlisted: bool,
) -> Result<IpRecord> {
    // PermanentBlocked: update suppression flag only.
    if let Some(prev) = previous
        && let RecordStatus::PermanentBlocked {
            imported_at,
            ref source,
            ref reason,
            ..
        } = prev.status
    {
        return Ok(IpRecord {
            status: RecordStatus::PermanentBlocked {
                imported_at,
                source: source.clone(),
                reason: reason.clone(),
                suppressed_by_allowlist: allowlisted,
            },
            last_evaluated: now,
            ..prev.clone()
        });
    }

    // Allowlisted: merge observations for accounting, set Allowlisted status.
    if allowlisted {
        return allowlisted_transition(previous, observations, settings, now);
    }

    // No new observations: decay + time-based transitions only.
    if observations.is_empty() {
        let prev = previous.ok_or_else(|| {
            BlockholeError::Policy("cannot evaluate empty observations without state".into())
        })?;
        return no_observation_transition(prev, settings, now);
    }

    // New observations: score, decay, qualify, determine status.
    observed_transition(previous, observations, settings, now)
}

/// Handle allowlisted records: merge counters for book-keeping, always set
/// `Allowlisted` status.
fn allowlisted_transition(
    previous: Option<&IpRecord>,
    observations: &[Observation],
    settings: &Settings,
    now: DateTime<Utc>,
) -> Result<IpRecord> {
    if let Some(prev) = previous {
        if observations.is_empty() {
            return Ok(IpRecord {
                status: RecordStatus::Allowlisted,
                last_evaluated: now,
                ..prev.clone()
            });
        }
        let signals = policy::score_signals(observations, Some(prev), settings, now)?;
        let score = signals.raw_score;
        return Ok(build_record(signals, RecordStatus::Allowlisted, score, now));
    }
    if !observations.is_empty() {
        let signals = policy::score_signals(observations, None, settings, now)?;
        let score = signals.raw_score;
        return Ok(build_record(signals, RecordStatus::Allowlisted, score, now));
    }
    Err(BlockholeError::Policy(
        "cannot evaluate empty observations without state".into(),
    ))
}

/// Handle existing records without new observations: apply score decay and
/// time-based status transitions.
fn no_observation_transition(
    prev: &IpRecord,
    settings: &Settings,
    now: DateTime<Utc>,
) -> Result<IpRecord> {
    let elapsed_days = ((now - prev.last_evaluated).num_seconds() as f64 / 86_400.0).max(0.0);

    let score = match &prev.status {
        RecordStatus::Candidate | RecordStatus::TemporaryBlocked { .. } => {
            let decayed = (prev.score - elapsed_days * settings.score_decay_per_day).max(0.0);
            (decayed * 10_000.0).round() / 10_000.0
        }
        _ => prev.score,
    };

    let status = match &prev.status {
        RecordStatus::TemporaryBlocked { expires_at, .. } if now >= *expires_at => {
            RecordStatus::Cooldown {
                until: now + Duration::hours(settings.cooldown_hours),
            }
        }
        RecordStatus::Cooldown { until } if now >= *until => RecordStatus::Expired,
        s => s.clone(),
    };

    Ok(IpRecord {
        score,
        status,
        last_evaluated: now,
        ..prev.clone()
    })
}

/// Handle records with new observations: recompute signals, apply decay,
/// determine qualification, and set status.
fn observed_transition(
    previous: Option<&IpRecord>,
    observations: &[Observation],
    settings: &Settings,
    now: DateTime<Utc>,
) -> Result<IpRecord> {
    let signals = policy::score_signals(observations, previous, settings, now)?;
    let old_status = previous.map(|p| &p.status);

    // Elapsed time since last evaluation (zero for brand-new records).
    let elapsed_days = previous
        .map(|p| (now - p.last_evaluated).num_seconds() as f64 / 86_400.0)
        .unwrap_or(0.0)
        .max(0.0);

    // Determine status based on qualification.
    let status = if signals.qualifies_for_block {
        match old_status {
            Some(RecordStatus::TemporaryBlocked {
                started_at,
                expires_at,
                ttl_extensions,
            }) => RecordStatus::TemporaryBlocked {
                started_at: *started_at,
                expires_at: *expires_at,
                ttl_extensions: *ttl_extensions,
            },
            _ => RecordStatus::TemporaryBlocked {
                started_at: now,
                expires_at: now + Duration::hours(settings.block_ttl_hours),
                ttl_extensions: 0,
            },
        }
    } else {
        RecordStatus::Candidate
    };

    // Apply time-based transitions on the determined status.
    let status = match status {
        RecordStatus::TemporaryBlocked { expires_at, .. } if now >= expires_at => {
            RecordStatus::Cooldown {
                until: now + Duration::hours(settings.cooldown_hours),
            }
        }
        RecordStatus::Cooldown { until } if now >= until => RecordStatus::Expired,
        other => other,
    };

    // Apply decay based on final status (only Candidate / TemporaryBlocked).
    let score = match &status {
        RecordStatus::Candidate | RecordStatus::TemporaryBlocked { .. } => {
            let decayed =
                (signals.raw_score - elapsed_days * settings.score_decay_per_day).max(0.0);
            (decayed * 10_000.0).round() / 10_000.0
        }
        _ => signals.raw_score,
    };

    Ok(build_record(signals, status, score, now))
}

/// Construct an `IpRecord` from merged signals, a resolved status, a final
/// score, and evaluation time.
fn build_record(
    signals: policy::MergedSignals,
    status: RecordStatus,
    score: f64,
    now: DateTime<Utc>,
) -> IpRecord {
    IpRecord {
        schema_version: crate::state::CURRENT_SCHEMA,
        first_seen: signals.first_seen,
        last_seen: signals.last_seen,
        last_evaluated: now,
        observed_requests: signals.observed_requests,
        weighted_requests: signals.weighted_requests,
        distinct_paths: signals.distinct_paths,
        suspicious_paths: signals.suspicious_paths,
        error_requests: signals.error_requests,
        observation_windows: signals.observation_windows,
        source_zones: signals.source_zones,
        score,
        reason_codes: signals.reason_codes,
        status,
    }
}

pub fn active(
    records: &BTreeMap<Subject, IpRecord>,
    now: DateTime<Utc>,
) -> BTreeMap<Subject, IpRecord> {
    records
        .iter()
        .filter(|(_, r)| match r.status {
            RecordStatus::PermanentBlocked {
                suppressed_by_allowlist,
                ..
            } => !suppressed_by_allowlist,
            RecordStatus::TemporaryBlocked { expires_at, .. } => expires_at > now,
            _ => false,
        })
        .map(|(s, r)| (s.clone(), r.clone()))
        .collect()
}
