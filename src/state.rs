use crate::{
    error::{BlockholeError, Result},
    models::{IpRecord, RecordStatus, State, Subject},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, io::Write, path::Path};

pub const CURRENT_SCHEMA: u32 = 3;
#[derive(Deserialize)]
struct V1Record {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    last_evaluated: DateTime<Utc>,
    observed_requests: u64,
    weighted_requests: f64,
    distinct_paths: u64,
    suspicious_paths: u64,
    error_requests: u64,
    observation_windows: u64,
    source_zones: Vec<String>,
    score: f64,
    status: String,
    reason_codes: Vec<String>,
    block_started_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    ttl_extensions: u32,
}
#[derive(Deserialize)]
struct V1State {
    checkpoints: BTreeMap<String, DateTime<Utc>>,
    records: BTreeMap<String, V1Record>,
}
pub fn load(path: &Path) -> Result<State> {
    let text = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let version = value
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| BlockholeError::State("missing schema_version".into()))?
        as u32;
    if version > CURRENT_SCHEMA {
        return Err(BlockholeError::State(format!(
            "unsupported future state schema: {version}"
        )));
    }
    if version == CURRENT_SCHEMA {
        return serde_json::from_value(value).map_err(|e| BlockholeError::State(e.to_string()));
    }
    if version == 2 {
        return migrate_v2(value);
    }
    migrate_v1(serde_json::from_value(value).map_err(|e| BlockholeError::State(e.to_string()))?)
}
fn migrate_v2(value: serde_json::Value) -> Result<State> {
    let mut state: State =
        serde_json::from_value(value).map_err(|e| BlockholeError::State(e.to_string()))?;
    state.schema_version = CURRENT_SCHEMA;
    for record in state.records.values_mut() {
        record.schema_version = CURRENT_SCHEMA;
    }
    Ok(state)
}
fn migrate_v1(old: V1State) -> Result<State> {
    let mut records = BTreeMap::new();
    for (raw_key, old) in old.records {
        let key = Subject::parse(&raw_key)?;
        let status = match old.status.as_str() {
            "candidate" => RecordStatus::Candidate,
            "blocked" => {
                let started = old.block_started_at.ok_or_else(|| {
                    BlockholeError::State(format!(
                        "blocked record {raw_key} has no block_started_at"
                    ))
                })?;
                let expires = old.expires_at.ok_or_else(|| {
                    BlockholeError::State(format!("blocked record {raw_key} has no expires_at"))
                })?;
                RecordStatus::TemporaryBlocked {
                    started_at: started,
                    expires_at: expires,
                    ttl_extensions: old.ttl_extensions,
                }
            }
            "cooldown" => RecordStatus::Cooldown {
                until: old.expires_at.ok_or_else(|| {
                    BlockholeError::State(format!("cooldown record {raw_key} has no expires_at"))
                })?,
            },
            "expired" => RecordStatus::Expired,
            "allowlisted" => RecordStatus::Allowlisted,
            other => return Err(BlockholeError::State(format!("unknown v1 status {other}"))),
        };
        records.insert(
            key,
            IpRecord {
                schema_version: CURRENT_SCHEMA,
                first_seen: old.first_seen,
                last_seen: old.last_seen,
                last_evaluated: old.last_evaluated,
                observed_requests: old.observed_requests,
                weighted_requests: old.weighted_requests,
                distinct_paths: old.distinct_paths,
                suspicious_paths: old.suspicious_paths,
                error_requests: old.error_requests,
                observation_windows: old.observation_windows,
                source_zones: old.source_zones,
                score: old.score,
                reason_codes: old.reason_codes,
                status,
            },
        );
    }
    Ok(State {
        schema_version: CURRENT_SCHEMA,
        checkpoints: old.checkpoints,
        records,
    })
}
pub fn write(path: &Path, state: &State) -> Result<()> {
    let payload = serde_json::to_string_pretty(state)? + "\n";
    fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
    let temporary = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    Ok(())
}
pub fn empty() -> State {
    State {
        schema_version: CURRENT_SCHEMA,
        checkpoints: BTreeMap::new(),
        records: BTreeMap::new(),
    }
}
