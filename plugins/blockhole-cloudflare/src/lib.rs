pub mod analytics;
mod http;
mod lists;

use blockhole_core::{
    error::{BlockholeError, Result},
    models::{DesiredList, Observation},
    plugin::{BlockDeployer, CollectionWindow, ObservationSource, SyncOptions},
    sync::ListDiff,
};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::{env, fs, path::Path, time::Duration};

pub use lists::ListsClient;

#[derive(Deserialize)]
struct PolicyFile {
    cloudflare: CloudflareConfig,
    zones: ZonesConfig,
}

#[derive(Deserialize)]
struct CloudflareConfig {
    graphql_url: String,
    api_base_url: String,
    timeout_seconds: f64,
    max_retries: usize,
    poll_interval_seconds: f64,
    poll_timeout_seconds: f64,
}

#[derive(Deserialize)]
struct ZonesConfig {
    ids: Vec<String>,
}

pub struct CloudflarePlugin {
    client: Client,
    graphql_url: String,
    api_base_url: String,
    account: String,
    list: String,
    max_retries: usize,
    poll_interval_seconds: f64,
    poll_timeout_seconds: f64,
    zone_ids: Vec<String>,
}

impl CloudflarePlugin {
    pub fn validate_config(root: &Path) -> Result<()> {
        let raw = load_policy_file(root)?;
        Self::validate_raw(&raw.cloudflare)
    }

    pub fn load(root: &Path) -> Result<Self> {
        let raw = load_policy_file(root)?;
        Self::from_config(raw)
    }

    fn from_config(raw: PolicyFile) -> Result<Self> {
        Self::validate_raw(&raw.cloudflare)?;
        let zone_ids = env::var("CLOUDFLARE_ZONE_IDS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .filter(|item| !item.trim().is_empty())
                    .map(|item| item.trim().to_string())
                    .collect()
            })
            .unwrap_or(raw.zones.ids);
        let (token, account, list) = credentials()?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|error| BlockholeError::Configuration(error.to_string()))?,
        );
        let client = Client::builder()
            .timeout(Duration::from_secs_f64(raw.cloudflare.timeout_seconds))
            .user_agent(format!(
                "blockhole-cloudflare/{}",
                env!("CARGO_PKG_VERSION")
            ))
            .default_headers(headers)
            .build()
            .map_err(crate::http::plugin_error)?;
        Ok(Self {
            client,
            graphql_url: raw.cloudflare.graphql_url,
            api_base_url: raw.cloudflare.api_base_url,
            account,
            list,
            max_retries: raw.cloudflare.max_retries,
            poll_interval_seconds: raw.cloudflare.poll_interval_seconds,
            poll_timeout_seconds: raw.cloudflare.poll_timeout_seconds,
            zone_ids,
        })
    }

    fn validate_raw(config: &CloudflareConfig) -> Result<()> {
        if config.graphql_url.is_empty() || config.api_base_url.is_empty() {
            return Err(BlockholeError::Configuration(
                "Cloudflare API URLs must not be empty".into(),
            ));
        }
        if config.timeout_seconds <= 0.0
            || !config.timeout_seconds.is_finite()
            || config.poll_interval_seconds < 0.0
            || !config.poll_interval_seconds.is_finite()
            || config.poll_timeout_seconds <= 0.0
            || !config.poll_timeout_seconds.is_finite()
        {
            return Err(BlockholeError::Configuration(
                "Cloudflare timeout settings are invalid".into(),
            ));
        }
        Ok(())
    }
}

impl ObservationSource for CloudflarePlugin {
    fn collect(&self, window: CollectionWindow) -> Result<Vec<Observation>> {
        if self.zone_ids.is_empty() {
            return Err(BlockholeError::Configuration(
                "no zone IDs configured in config/policy.toml".into(),
            ));
        }
        std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .zone_ids
                .iter()
                .map(|zone| {
                    scope.spawn(|| {
                        analytics::collect(
                            &self.client,
                            &self.graphql_url,
                            self.max_retries,
                            zone,
                            window.start,
                            window.end,
                        )
                    })
                })
                .collect();
            let mut all = Vec::new();
            for handle in handles {
                all.extend(handle.join().map_err(|_| {
                    BlockholeError::Plugin("zone collection thread panicked".into())
                })??);
            }
            Ok(all)
        })
    }
}

impl BlockDeployer for CloudflarePlugin {
    fn sync(&self, desired: &DesiredList, options: SyncOptions) -> Result<ListDiff> {
        let backend = ListsClient::new(
            self.client.clone(),
            &self.api_base_url,
            &self.account,
            &self.list,
            self.max_retries,
            self.poll_interval_seconds,
            self.poll_timeout_seconds,
        );
        blockhole_core::sync::reconcile(
            &backend,
            desired,
            options.dry_run,
            options.mode,
            options.allow_empty,
        )
    }
}

fn load_policy_file(root: &Path) -> Result<PolicyFile> {
    toml::from_str(&fs::read_to_string(root.join("config/policy.toml"))?)
        .map_err(|error| BlockholeError::Configuration(error.to_string()))
}

fn credentials() -> Result<(String, String, String)> {
    let get = |var: &'static str| env::var(var).map_err(|_| BlockholeError::MissingEnvVar { var });
    Ok((
        get("CLOUDFLARE_API_TOKEN")?,
        get("CLOUDFLARE_ACCOUNT_ID")?,
        get("CLOUDFLARE_LIST_ID")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{ListsClient, analytics};
    use blockhole_core::{
        config::RunMode,
        models::{BlockTarget, DesiredList, Subject},
        sync,
    };
    use chrono::{Duration, TimeZone, Utc};
    use reqwest::blocking::Client;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    fn read_request(stream: &mut TcpStream) -> (String, String) {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).unwrap();
            assert!(
                count > 0,
                "mock Cloudflare server received an incomplete request"
            );
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim().parse::<usize>().ok()?)
            })
            .unwrap_or(0);
        while bytes.len() < header_end + 4 + content_length {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).unwrap();
            assert!(
                count > 0,
                "mock Cloudflare server received a truncated body"
            );
            bytes.extend_from_slice(&buffer[..count]);
        }
        let body_start = header_end + 4;
        let body =
            String::from_utf8_lossy(&bytes[body_start..body_start + content_length]).to_string();
        (headers, body)
    }

    fn write_response(stream: &mut TcpStream, content_type: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn analytics_parser_strips_query_and_preserves_sampling() {
        let payload = r#"{"data":{"viewer":{"zones":[{"series":[{"dimensions":{"clientIP":"192.0.2.1","edgeResponseStatus":404,"clientRequestPath":"/.env?token=redacted"},"avg":{"sampleInterval":1.5},"count":3}]}]}}}"#;
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let observations = analytics::parse(payload, "zone", now).unwrap();
        assert_eq!(observations[0].paths, vec!["/.env"]);
        assert_eq!(observations[0].weighted_requests, 4.5);
        assert!(observations[0].sampled);
    }

    #[test]
    fn analytics_collects_from_a_graphql_http_mock() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, request_body) = read_request(&mut stream);
            assert!(headers.starts_with("POST /graphql HTTP/1.1"));
            assert!(request_body.contains("\"zone\":\"zone-a\""));
            assert!(request_body.contains("\"start\":\"2026-01-01T00:00:00+00:00\""));
            assert!(request_body.contains("\"end\":\"2026-01-01T01:00:00+00:00\""));

            let body = serde_json::json!({
                "data": {
                    "viewer": {
                        "zones": [{
                            "series": [{
                                "dimensions": {
                                    "clientIP": "192.0.2.8",
                                    "edgeResponseStatus": 404,
                                    "clientRequestPath": "/.env?token=redacted"
                                },
                                "avg": {"sampleInterval": 2.0},
                                "count": 3
                            }]
                        }]
                    }
                }
            })
            .to_string();
            write_response(&mut stream, "application/json", &body);
        });

        let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let end = start + Duration::hours(1);
        let observations = analytics::collect(
            &Client::new(),
            &format!("http://{address}/graphql"),
            0,
            "zone-a",
            start,
            end,
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].ip.to_string(), "192.0.2.8/32");
        assert_eq!(observations[0].paths, vec!["/.env"]);
        assert_eq!(observations[0].weighted_requests, 6.0);
        assert_eq!(observations[0].observed_at, end);
    }

    #[test]
    fn list_sync_uses_a_mock_read_replace_and_readback_cycle() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = read_request(&mut stream);
                assert!(headers.starts_with(
                    "GET /accounts/account/rules/lists/list/items?per_page=500 HTTP/1.1"
                ));
                assert!(body.is_empty());
                write_response(&mut stream, "application/json", r#"{"result":[]}"#);

                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = read_request(&mut stream);
                assert!(
                    headers.starts_with("PUT /accounts/account/rules/lists/list/items HTTP/1.1")
                );
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                    serde_json::json!([{"ip":"192.0.2.10/32","comment":"blockhole:test"}])
                );
                write_response(&mut stream, "application/json", r#"{"result":{}}"#);

                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = read_request(&mut stream);
                assert!(headers.starts_with(
                    "GET /accounts/account/rules/lists/list/items?per_page=500 HTTP/1.1"
                ));
                assert!(body.is_empty());
                write_response(
                    &mut stream,
                    "application/json",
                    r#"{"result":[{"ip":"192.0.2.10/32","comment":"blockhole:test"}]}"#,
                );
            });

        let client = ListsClient::new(
            Client::new(),
            &format!("http://{address}"),
            "account",
            "list",
            0,
            0.0,
            1.0,
        );
        let desired = DesiredList {
            items: vec![BlockTarget {
                subject: Subject::parse("192.0.2.10").unwrap(),
                comment: "blockhole:test".into(),
            }],
        };
        let diff = sync::reconcile(&client, &desired, false, RunMode::Enforce, false).unwrap();
        server.join().unwrap();

        assert_eq!(diff.additions, desired.items);
        assert!(diff.removals.is_empty());
        assert!(diff.changes.is_empty());
    }
}
