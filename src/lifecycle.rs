use crate::{
    config::Settings,
    models::{IpRecord, RecordStatus, Subject},
};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;
pub fn apply(record: &mut IpRecord, settings: &Settings, now: DateTime<Utc>, allowlisted: bool) {
    if allowlisted {
        record.status = RecordStatus::Allowlisted;
        return;
    }
    match record.status {
        RecordStatus::TemporaryBlocked { expires_at, .. } if now >= expires_at => {
            record.status = RecordStatus::Cooldown {
                until: now + Duration::hours(settings.cooldown_hours),
            }
        }
        RecordStatus::Cooldown { until } if now >= until => record.status = RecordStatus::Expired,
        _ => {}
    }
    if matches!(
        record.status,
        RecordStatus::Candidate | RecordStatus::TemporaryBlocked { .. }
    ) {
        let days = (now - record.last_evaluated).num_seconds() as f64 / 86_400.0;
        if days > 0.0 {
            record.score = (record.score - days * settings.score_decay_per_day).max(0.0);
        }
    }
}
pub fn active(
    records: &BTreeMap<Subject, IpRecord>,
    now: DateTime<Utc>,
) -> BTreeMap<Subject, IpRecord> {
    records
        .iter()
        .filter(|(_, r)| match r.status {
            RecordStatus::PermanentBlocked { .. } => true,
            RecordStatus::TemporaryBlocked { expires_at, .. } => expires_at > now,
            _ => false,
        })
        .map(|(s, r)| (s.clone(), r.clone()))
        .collect()
}
