use crate::{
    error::{BlockholeError, Result},
    models::Subject,
};
use regex::RegexSet;
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunMode {
    DryRun,
    Enforce,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Thresholds {
    pub min_weighted_requests: f64,
    pub min_distinct_paths: u64,
    pub min_suspicious_paths: u64,
    pub max_error_ratio: f64,
    pub block_score: f64,
}
#[derive(Clone, Debug, Deserialize)]
pub struct Weights {
    #[serde(default = "one")]
    pub request_volume: f64,
    #[serde(default)]
    pub path_breadth: f64,
    #[serde(default = "four")]
    pub suspicious_paths: f64,
    #[serde(default = "one")]
    pub high_error_ratio: f64,
    #[serde(default = "one")]
    pub repeated_windows: f64,
    #[serde(default)]
    #[serde(alias = "multiple_zones")]
    pub multiple_sources: f64,
}
fn one() -> f64 {
    1.0
}
fn four() -> f64 {
    4.0
}
#[derive(Clone)]
pub struct Settings {
    pub platform: String,
    pub mode: RunMode,
    pub lookback_hours: i64,
    pub overlap_hours: i64,
    pub block_ttl_hours: i64,
    pub cooldown_hours: i64,
    pub max_ttl_extensions: u32,
    pub score_decay_per_day: f64,
    pub thresholds: Thresholds,
    pub weights: Weights,
    pub suspicious_path_patterns: Vec<String>,
    pub suspicious_path_set: RegexSet,
}
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("platform", &self.platform)
            .field("mode", &self.mode)
            .field("suspicious_path_patterns", &self.suspicious_path_patterns)
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
struct Raw {
    schema_version: u32,
    platform: Platform,
    mode: RunMode,
    lookback_hours: i64,
    overlap_hours: i64,
    block_ttl_hours: i64,
    cooldown_hours: i64,
    max_ttl_extensions: u32,
    score_decay_per_day: f64,
    suspicious_path_patterns: Vec<String>,
    thresholds: Thresholds,
    #[serde(default)]
    signal_weights: Option<Weights>,
}
#[derive(Deserialize)]
struct Platform {
    name: String,
}
pub fn parse(text: &str) -> Result<Settings> {
    let raw: Raw =
        toml::from_str(text).map_err(|e| BlockholeError::Configuration(e.to_string()))?;
    Settings::try_from(raw)
}
impl TryFrom<Raw> for Settings {
    type Error = BlockholeError;
    fn try_from(raw: Raw) -> Result<Self> {
        if raw.schema_version != 1 {
            return Err(BlockholeError::UnsupportedSchema {
                version: raw.schema_version,
                expected: 1,
            });
        }
        if raw.lookback_hours <= raw.overlap_hours {
            return Err(BlockholeError::Configuration(
                "lookback_hours must exceed overlap_hours".into(),
            ));
        }
        if raw.platform.name.trim().is_empty() {
            return Err(BlockholeError::Configuration(
                "platform.name must not be empty".into(),
            ));
        }
        let suspicious_path_set = RegexSet::new(&raw.suspicious_path_patterns)
            .map_err(|e| BlockholeError::Configuration(format!("invalid regex pattern: {e}")))?;
        Ok(Settings {
            platform: raw.platform.name,
            mode: raw.mode,
            lookback_hours: raw.lookback_hours,
            overlap_hours: raw.overlap_hours,
            block_ttl_hours: raw.block_ttl_hours,
            cooldown_hours: raw.cooldown_hours,
            max_ttl_extensions: raw.max_ttl_extensions,
            score_decay_per_day: raw.score_decay_per_day,
            thresholds: raw.thresholds,
            weights: raw.signal_weights.unwrap_or(Weights {
                request_volume: 1.0,
                path_breadth: 0.0,
                suspicious_paths: 4.0,
                high_error_ratio: 1.0,
                repeated_windows: 1.0,
                multiple_sources: 0.0,
            }),
            suspicious_path_patterns: raw.suspicious_path_patterns,
            suspicious_path_set,
        })
    }
}
pub fn load_subject_file(path: &Path) -> Result<Vec<Subject>> {
    let mut result = Vec::new();
    for (line, raw) in fs::read_to_string(path)?.lines().enumerate() {
        let value = raw.split('#').next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        result.push(Subject::parse(value).map_err(|e| {
            BlockholeError::Configuration(format!("{}:{}: {e}", path.display(), line + 1))
        })?);
    }
    result.sort();
    result.dedup();
    Ok(result)
}
