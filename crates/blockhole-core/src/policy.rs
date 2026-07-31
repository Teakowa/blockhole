use crate::{
    config::Settings,
    error::{BlockholeError, Result},
    models::{IpRecord, Observation, RecordStatus, Subject},
};
use chrono::{DateTime, Utc};
use regex::RegexSet;
use std::collections::BTreeSet;

pub fn parse_subjects(text: &str, source: &str) -> Result<Vec<Subject>> {
    let mut result = Vec::new();
    for (line, raw) in text.lines().enumerate() {
        let value = raw.split('#').next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        result.push(Subject::parse(value).map_err(|error| {
            BlockholeError::Configuration(format!("{source}:{}: {error}", line + 1))
        })?);
    }
    result.sort();
    result.dedup();
    Ok(result)
}
pub fn is_allowlisted(subject: &Subject, list: &[Subject]) -> bool {
    list.iter().any(|network| network.contains(subject))
}
/// Aggregated observation counters and signal scores, without status or decay.
pub struct MergedSignals {
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub observed_requests: u64,
    pub weighted_requests: f64,
    pub distinct_paths: u64,
    pub suspicious_paths: u64,
    pub error_requests: u64,
    pub observation_windows: u64,
    pub sources: Vec<String>,
    pub raw_score: f64,
    pub reason_codes: Vec<String>,
    pub qualifies_for_block: bool,
}

/// Merge observations with existing record counters and compute signal scores.
///
/// Returns an error if both `observations` and `existing` are empty/None.
/// Does not determine status, apply decay, or set `last_evaluated`.
pub fn score_signals(
    observations: &[Observation],
    existing: Option<&IpRecord>,
    settings: &Settings,
    now: DateTime<Utc>,
) -> Result<MergedSignals> {
    let mut fingerprints = BTreeSet::new();
    let observations = observations
        .iter()
        .filter(|observation| {
            observation.fingerprint.is_empty()
                || fingerprints.insert(observation.fingerprint.as_str())
        })
        .collect::<Vec<_>>();
    if observations.is_empty() && existing.is_none() {
        return Err(BlockholeError::Policy(
            "cannot evaluate empty observations without state".into(),
        ));
    }
    let first_seen = observations
        .iter()
        .map(|o| o.observed_at)
        .min()
        .or_else(|| existing.map(|r| r.first_seen))
        .unwrap_or(now);
    let last_seen = observations
        .iter()
        .map(|o| o.observed_at)
        .max()
        .or_else(|| existing.map(|r| r.last_seen))
        .unwrap_or(now);
    let observed = observations
        .iter()
        .map(|o| o.observed_requests)
        .sum::<u64>()
        + existing.map_or(0, |r| r.observed_requests);
    let weighted = observations
        .iter()
        .map(|o| o.weighted_requests)
        .sum::<f64>()
        + existing.map_or(0.0, |r| r.weighted_requests);
    let paths: BTreeSet<_> = observations
        .iter()
        .flat_map(|o| o.paths.iter().cloned())
        .collect();
    let distinct = paths.len() as u64;
    let distinct = distinct.max(existing.map_or(0, |r| r.distinct_paths));
    let suspicious = observations
        .iter()
        .map(|observation| {
            observation
                .paths
                .iter()
                .filter(|path| settings.suspicious_path_set.is_match(path))
                .count() as u64
        })
        .sum::<u64>()
        + existing.map_or(0, |r| r.suspicious_paths);
    let errors = observations.iter().map(|o| o.error_requests).sum::<u64>()
        + existing.map_or(0, |r| r.error_requests);
    let mut sources: BTreeSet<String> = observations.iter().map(|o| o.source_id.clone()).collect();
    sources.extend(existing.map_or_else(Vec::new, |r| r.sources.clone()));
    let windows =
        existing.map_or(0, |r| r.observation_windows) + u64::from(!observations.is_empty());
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
    if sources.len() >= 2 {
        score += w.multiple_sources;
        reasons.push("multiple_sources".into());
    }
    let qualifies = score >= settings.thresholds.block_score
        && reasons.len() >= 2
        && suspicious >= settings.thresholds.min_suspicious_paths;
    reasons.sort();
    reasons.dedup();
    Ok(MergedSignals {
        first_seen,
        last_seen,
        observed_requests: observed,
        weighted_requests: weighted,
        distinct_paths: distinct,
        suspicious_paths: suspicious,
        error_requests: errors,
        observation_windows: windows,
        sources: sources.into_iter().collect(),
        raw_score: (score * 10_000.0).round() / 10_000.0,
        reason_codes: reasons,
        qualifies_for_block: qualifies,
    })
}

pub fn annotate_suspicious_paths(observations: &mut [Observation], pattern_set: &RegexSet) {
    for observation in observations {
        observation.suspicious_paths = observation
            .paths
            .iter()
            .filter(|path| pattern_set.is_match(path))
            .count() as u64;
    }
}

pub fn merge_permanent(state: &mut crate::models::State, subjects: &[Subject], now: DateTime<Utc>) {
    let wanted: BTreeSet<_> = subjects.iter().cloned().collect();
    state.records.retain(|subject, record| {
        !matches!(record.status, RecordStatus::PermanentBlocked { .. }) || wanted.contains(subject)
    });
    for subject in subjects {
        let existing_suppressed = state
            .records
            .get(subject)
            .and_then(|r| match &r.status {
                RecordStatus::PermanentBlocked {
                    suppressed_by_allowlist,
                    ..
                } => Some(*suppressed_by_allowlist),
                _ => None,
            })
            .unwrap_or(false);

        let entry = state
            .records
            .entry(subject.clone())
            .or_insert_with(|| IpRecord {
                schema_version: crate::state::CURRENT_SCHEMA,
                first_seen: now,
                last_seen: now,
                last_evaluated: now,
                observed_requests: 0,
                weighted_requests: 0.0,
                distinct_paths: 0,
                suspicious_paths: 0,
                error_requests: 0,
                observation_windows: 0,
                sources: Vec::new(),
                fingerprint_history: std::collections::BTreeMap::new(),
                score: 0.0,
                reason_codes: vec!["manual_import".into()],
                status: RecordStatus::PermanentBlocked {
                    imported_at: now,
                    source: "config/permanent-blocklist.txt".into(),
                    reason: None,
                    suppressed_by_allowlist: existing_suppressed,
                },
            });
        entry.status = RecordStatus::PermanentBlocked {
            imported_at: now,
            source: "config/permanent-blocklist.txt".into(),
            reason: None,
            suppressed_by_allowlist: existing_suppressed,
        };
    }
}
