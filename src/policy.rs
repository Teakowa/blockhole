use crate::{
    config::{Settings, load_subject_file},
    error::{BlockholeError, Result},
    models::{IpRecord, Observation, RecordStatus, Subject},
};
use chrono::{DateTime, Duration, Utc};
use std::{collections::BTreeSet, path::Path};
pub fn allowlist(root: &Path) -> Result<Vec<Subject>> {
    load_subject_file(&root.join("config/allowlist.txt"))
}
pub fn permanent(root: &Path) -> Result<Vec<Subject>> {
    load_subject_file(&root.join("config/permanent-blocklist.txt"))
}
pub fn is_allowlisted(subject: &Subject, list: &[Subject]) -> bool {
    list.iter().any(|network| network.contains(subject))
}
pub fn evaluate(
    values: &[Observation],
    existing: Option<&IpRecord>,
    settings: &Settings,
    now: DateTime<Utc>,
) -> Result<IpRecord> {
    if values.is_empty() && existing.is_none() {
        return Err(BlockholeError::Policy(
            "cannot evaluate empty observations without state".into(),
        ));
    }
    if matches!(
        existing.map(|r| &r.status),
        Some(RecordStatus::PermanentBlocked { .. })
    ) {
        return Ok(existing.unwrap().clone());
    }
    let first_seen = values
        .iter()
        .map(|o| o.observed_at)
        .min()
        .or_else(|| existing.map(|r| r.first_seen))
        .unwrap_or(now);
    let last_seen = values
        .iter()
        .map(|o| o.observed_at)
        .max()
        .or_else(|| existing.map(|r| r.last_seen))
        .unwrap_or(now);
    let observed = values.iter().map(|o| o.observed_requests).sum::<u64>()
        + existing.map_or(0, |r| r.observed_requests);
    let weighted = values.iter().map(|o| o.weighted_requests).sum::<f64>()
        + existing.map_or(0.0, |r| r.weighted_requests);
    let paths: BTreeSet<_> = values
        .iter()
        .flat_map(|o| o.paths.iter().cloned())
        .collect();
    let distinct = paths.len() as u64;
    let distinct = distinct.max(existing.map_or(0, |r| r.distinct_paths));
    let suspicious = values.iter().map(|o| o.suspicious_paths).sum::<u64>()
        + existing.map_or(0, |r| r.suspicious_paths);
    let errors = values.iter().map(|o| o.error_requests).sum::<u64>()
        + existing.map_or(0, |r| r.error_requests);
    let mut zones: BTreeSet<String> = values.iter().map(|o| o.zone_id.clone()).collect();
    zones.extend(existing.map_or_else(Vec::new, |r| r.source_zones.clone()));
    let windows = existing.map_or(0, |r| r.observation_windows) + u64::from(!values.is_empty());
    let ratio = if observed == 0 {
        0.0
    } else {
        errors as f64 / observed as f64
    };
    let mut reasons = Vec::new();
    let mut score = 0.0;
    let w = &settings.weights;
    if weighted >= settings.thresholds.min_weighted_requests {
        score += w.request_volume;
        reasons.push("request_volume".into());
    }
    if distinct >= settings.thresholds.min_distinct_paths {
        score += w.path_breadth;
        reasons.push("path_breadth".into());
    }
    if suspicious >= settings.thresholds.min_suspicious_paths {
        score += w.suspicious_paths;
        reasons.push("suspicious_paths".into());
    }
    if ratio >= settings.thresholds.max_error_ratio && observed > 0 {
        score += w.high_error_ratio;
        reasons.push("high_error_ratio".into());
    }
    if windows >= 2 {
        score += w.repeated_windows;
        reasons.push("repeated_windows".into());
    }
    if zones.len() >= 2 {
        score += w.multiple_zones;
        reasons.push("multiple_zones".into());
    }
    let qualifies = score >= settings.thresholds.block_score
        && reasons.len() >= 2
        && suspicious >= settings.thresholds.min_suspicious_paths;
    let old_status = existing.map(|r| &r.status);
    let status = if qualifies {
        let (started, expires, ext) = match old_status {
            Some(RecordStatus::TemporaryBlocked {
                started_at,
                expires_at,
                ttl_extensions,
            }) => (*started_at, *expires_at, *ttl_extensions),
            _ => (now, now + Duration::hours(settings.block_ttl_hours), 0),
        };
        RecordStatus::TemporaryBlocked {
            started_at: started,
            expires_at: expires,
            ttl_extensions: ext,
        }
    } else {
        RecordStatus::Candidate
    };
    Ok(IpRecord {
        schema_version: 2,
        first_seen,
        last_seen,
        last_evaluated: now,
        observed_requests: observed,
        weighted_requests: weighted,
        distinct_paths: distinct,
        suspicious_paths: suspicious,
        error_requests: errors,
        observation_windows: windows,
        source_zones: zones.into_iter().collect(),
        score: (score * 10_000.0).round() / 10_000.0,
        reason_codes: {
            reasons.sort();
            reasons.dedup();
            reasons
        },
        status,
    })
}
pub fn merge_permanent(state: &mut crate::models::State, subjects: &[Subject], now: DateTime<Utc>) {
    let wanted: BTreeSet<_> = subjects.iter().cloned().collect();
    state.records.retain(|subject, record| {
        !matches!(record.status, RecordStatus::PermanentBlocked { .. }) || wanted.contains(subject)
    });
    for subject in subjects {
        let entry = state
            .records
            .entry(subject.clone())
            .or_insert_with(|| IpRecord {
                schema_version: 2,
                first_seen: now,
                last_seen: now,
                last_evaluated: now,
                observed_requests: 0,
                weighted_requests: 0.0,
                distinct_paths: 0,
                suspicious_paths: 0,
                error_requests: 0,
                observation_windows: 0,
                source_zones: Vec::new(),
                score: 0.0,
                reason_codes: vec!["manual_import".into()],
                status: RecordStatus::PermanentBlocked {
                    imported_at: now,
                    source: "config/permanent-blocklist.txt".into(),
                    reason: None,
                },
            });
        entry.status = RecordStatus::PermanentBlocked {
            imported_at: now,
            source: "config/permanent-blocklist.txt".into(),
            reason: None,
        };
    }
}
