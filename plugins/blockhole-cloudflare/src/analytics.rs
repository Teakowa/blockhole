use crate::http::{plugin_error, request};
use blockhole_core::{
    error::{BlockholeError, Result},
    models::{Observation, Subject},
};
use chrono::{DateTime, Utc};
use regex::RegexSet;
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

const QUERY: &str = "query Requests($zone: String!, $start: DateTime!, $end: DateTime!) { viewer { zones(filter: {zoneTag: $zone}) { series: httpRequestsAdaptiveGroups(limit: 1000, filter: {datetime_geq: $start, datetime_lt: $end}, orderBy: [count_DESC]) { dimensions { clientIP edgeResponseStatus clientRequestPath } avg { sampleInterval } count } } } }";

#[derive(Deserialize)]
struct Payload {
    data: Option<Data>,
    errors: Option<Vec<ApiError>>,
}
#[derive(Deserialize)]
struct ApiError {
    message: String,
}
#[derive(Deserialize)]
struct Data {
    viewer: Viewer,
}
#[derive(Deserialize)]
struct Viewer {
    zones: Vec<Zone>,
}
#[derive(Deserialize)]
struct Zone {
    series: Vec<Row>,
}
#[derive(Deserialize)]
struct Row {
    dimensions: Dimensions,
    avg: Option<Average>,
    count: u64,
}
#[derive(Deserialize)]
struct Dimensions {
    #[serde(rename = "clientIP")]
    client_ip: String,
    #[serde(rename = "edgeResponseStatus")]
    status: u16,
    #[serde(rename = "clientRequestPath")]
    path: String,
}
#[derive(Deserialize)]
struct Average {
    #[serde(rename = "sampleInterval")]
    sample_interval: Option<f64>,
}

pub fn parse(
    payload: &str,
    source_id: &str,
    observed_at: DateTime<Utc>,
    pattern_set: &RegexSet,
) -> Result<Vec<Observation>> {
    let payload: Payload = serde_json::from_str(payload)?;
    if let Some(errors) = payload.errors {
        return Err(BlockholeError::Plugin(
            errors
                .into_iter()
                .map(|error| error.message)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    let rows = payload
        .data
        .ok_or_else(|| BlockholeError::Plugin("GraphQL response missing data".into()))?
        .viewer
        .zones
        .into_iter()
        .next()
        .ok_or_else(|| BlockholeError::Plugin("GraphQL response missing zone".into()))?
        .series;
    rows.into_iter()
        .map(|row| {
            let ip = Subject::parse(&row.dimensions.client_ip)?;
            let path = Url::parse(&format!(
                "https://placeholder.invalid{}",
                row.dimensions.path
            ))
            .map_err(|error| BlockholeError::Plugin(error.to_string()))?
            .path()
            .to_string();
            let interval = row
                .avg
                .and_then(|average| average.sample_interval)
                .unwrap_or(1.0);
            if !interval.is_finite() || interval <= 0.0 {
                return Err(BlockholeError::Plugin("invalid sample interval".into()));
            }
            let suspicious = pattern_set.is_match(&path);
            let mut hasher = Sha256::new();
            hasher.update(
                format!(
                    "{source_id}:{ip}:{path}:{}:{observed_at}",
                    row.dimensions.status
                )
                .as_bytes(),
            );
            let fingerprint = format!("{:x}", hasher.finalize())[..16].to_string();
            Ok(Observation {
                ip,
                source_id: source_id.into(),
                observed_at,
                observed_requests: row.count,
                weighted_requests: row.count as f64 * interval,
                paths: vec![path],
                suspicious_paths: u64::from(suspicious),
                error_requests: if row.dimensions.status >= 400 {
                    row.count
                } else {
                    0
                },
                sampled: interval > 1.0,
                sample_interval: (interval > 1.0).then_some(interval),
                fingerprint,
            })
        })
        .collect()
}

pub fn collect(
    client: &Client,
    url: &str,
    retries: usize,
    source_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    pattern_set: &RegexSet,
) -> Result<Vec<Observation>> {
    let body = serde_json::json!({
        "query": QUERY,
        "variables": {
            "zone": source_id,
            "start": start.to_rfc3339(),
            "end": end.to_rfc3339()
        }
    });
    let response = request(client, reqwest::Method::POST, url, retries, Some(body))?;
    if response.status().is_client_error() || response.status().is_server_error() {
        return Err(BlockholeError::Plugin(format!(
            "GraphQL HTTP {}",
            response.status()
        )));
    }
    let body = response.text().map_err(plugin_error)?;
    parse(&body, source_id, end, pattern_set)
}
