use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Subject(pub IpNet);

impl Subject {
    pub fn parse(value: &str) -> crate::error::Result<Self> {
        let value = value.trim();
        let network: IpNet = (if value.contains('/') {
            value.parse::<IpNet>().map_err(|e| e.to_string())
        } else {
            let ip = value.parse::<std::net::IpAddr>().map_err(|e| e.to_string());
            ip.map(|ip| IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap())
        }
        .map_err(|e| {
            crate::error::BlockholeError::Policy(format!("invalid IP/CIDR {value}: {e}"))
        }))?;
        Ok(Self(network.trunc()))
    }
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
    pub fn contains(&self, other: &Subject) -> bool {
        self.0.contains(&other.0.network()) && self.0.prefix_len() <= other.0.prefix_len()
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Subject {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_str())
    }
}
impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub ip: Subject,
    pub zone_id: String,
    pub observed_at: DateTime<Utc>,
    pub observed_requests: u64,
    pub weighted_requests: f64,
    pub paths: Vec<String>,
    pub suspicious_paths: u64,
    pub error_requests: u64,
    pub sampled: bool,
    pub sample_interval: Option<f64>,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecordStatus {
    Candidate,
    TemporaryBlocked {
        started_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        ttl_extensions: u32,
    },
    Cooldown {
        until: DateTime<Utc>,
    },
    Expired,
    PermanentBlocked {
        imported_at: DateTime<Utc>,
        source: String,
        reason: Option<String>,
        #[serde(default)]
        suppressed_by_allowlist: bool,
    },
    Allowlisted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpRecord {
    pub schema_version: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_evaluated: DateTime<Utc>,
    pub observed_requests: u64,
    pub weighted_requests: f64,
    pub distinct_paths: u64,
    pub suspicious_paths: u64,
    pub error_requests: u64,
    pub observation_windows: u64,
    pub source_zones: Vec<String>,
    pub score: f64,
    pub reason_codes: Vec<String>,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub schema_version: u32,
    pub checkpoints: std::collections::BTreeMap<String, DateTime<Utc>>,
    pub records: std::collections::BTreeMap<Subject, IpRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CloudflareItem {
    pub ip: Subject,
    pub comment: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredList {
    pub items: Vec<CloudflareItem>,
}
