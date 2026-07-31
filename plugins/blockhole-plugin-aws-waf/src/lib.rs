use aws_config::{BehaviorVersion, Region};
use aws_sdk_wafv2::{Client as WafClient, types::Scope};
use blockhole_core::{
    error::{BlockholeError, Result},
    models::{BlockTarget, DesiredList, Observation, Subject},
    plugin::{BlockDeployer, ObservationSource, SyncOptions},
    sync::{self, BlockBackend, ListDiff},
};
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

const DEFAULT_SOURCE_ID: &str = "aws-waf";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressVersion {
    Ipv4,
    Ipv6,
}

#[derive(Deserialize)]
struct PolicyFile {
    aws_waf: AwsWafConfig,
}

#[derive(Deserialize)]
struct AwsWafConfig {
    log_path: PathBuf,
    region: String,
    scope: String,
    ip_set_name: String,
    ip_set_id: String,
    address_version: String,
    #[serde(default = "default_source_id")]
    source_id: String,
}

fn default_source_id() -> String {
    DEFAULT_SOURCE_ID.into()
}

pub struct AwsWafPlugin {
    log_path: PathBuf,
    source_id: String,
    address_version: AddressVersion,
    backend: AwsWafBackend,
}

impl AwsWafPlugin {
    pub fn validate_config(root: &Path) -> Result<()> {
        let config = load_policy_file(root)?;
        validate_config_values(&config.aws_waf).map(|_| ())
    }

    pub fn load(root: &Path) -> Result<Self> {
        let config = load_policy_file(root)?.aws_waf;
        let (scope, address_version) = validate_config_values(&config)?;
        let runtime = Arc::new(
            RuntimeBuilder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    BlockholeError::Plugin(format!("failed to create AWS runtime: {error}"))
                })?,
        );
        let region = Region::new(config.region.clone());
        let sdk_config = runtime.block_on(
            aws_config::defaults(BehaviorVersion::latest())
                .region(region)
                .load(),
        );

        Ok(Self {
            log_path: resolve_path(root, config.log_path),
            source_id: config.source_id,
            address_version,
            backend: AwsWafBackend {
                client: WafClient::new(&sdk_config),
                runtime,
                scope,
                ip_set_name: config.ip_set_name,
                ip_set_id: config.ip_set_id,
            },
        })
    }
}

impl ObservationSource for AwsWafPlugin {
    fn collect(
        &self,
        window: blockhole_core::plugin::CollectionWindow,
    ) -> Result<Vec<Observation>> {
        let contents = fs::read_to_string(&self.log_path)?;
        contents
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(line_number, line)| {
                parse_log_line_with_source(line, &self.source_id).map_err(|error| {
                    BlockholeError::Plugin(format!(
                        "invalid AWS WAF log {}:{}: {error}",
                        self.log_path.display(),
                        line_number + 1
                    ))
                })
            })
            .filter_map(|result| match result {
                Ok(observation)
                    if observation.observed_at >= window.start
                        && observation.observed_at < window.end =>
                {
                    Some(Ok(observation))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }
}

impl BlockDeployer for AwsWafPlugin {
    fn sync(&self, desired: &DesiredList, options: SyncOptions) -> Result<ListDiff> {
        let normalized = normalize_desired(desired, self.address_version)?;
        let diff = sync::reconcile(
            &self.backend,
            &normalized,
            options.dry_run,
            options.mode,
            options.allow_empty,
        )?;
        Ok(restore_comments(diff, desired))
    }
}

struct AwsWafBackend {
    client: WafClient,
    runtime: Arc<Runtime>,
    scope: Scope,
    ip_set_name: String,
    ip_set_id: String,
}

struct RemoteIpSet {
    items: Vec<BlockTarget>,
    lock_token: String,
}

impl AwsWafBackend {
    fn fetch(&self) -> Result<RemoteIpSet> {
        let output = self
            .runtime
            .block_on(
                self.client
                    .get_ip_set()
                    .name(&self.ip_set_name)
                    .id(&self.ip_set_id)
                    .scope(self.scope.clone())
                    .send(),
            )
            .map_err(|error| BlockholeError::Plugin(format!("AWS WAF GetIPSet failed: {error}")))?;
        let lock_token = output
            .lock_token()
            .ok_or_else(|| {
                BlockholeError::Plugin("AWS WAF GetIPSet returned no lock token".into())
            })?
            .to_string();
        let ip_set = output
            .ip_set()
            .ok_or_else(|| BlockholeError::Plugin("AWS WAF GetIPSet returned no IP set".into()))?;
        let items = ip_set
            .addresses()
            .iter()
            .map(|address| {
                Ok(BlockTarget {
                    subject: Subject::parse(address)?,
                    comment: String::new(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RemoteIpSet { items, lock_token })
    }
}

impl BlockBackend for AwsWafBackend {
    fn current(&self) -> Result<Vec<BlockTarget>> {
        Ok(self.fetch()?.items)
    }

    fn replace(&self, desired: &DesiredList) -> Result<()> {
        let remote = self.fetch()?;
        let mut addresses: Vec<String> = desired
            .items
            .iter()
            .map(|item| item.subject.to_string())
            .collect();
        addresses.sort();
        addresses.dedup();
        self.runtime
            .block_on(
                self.client
                    .update_ip_set()
                    .name(&self.ip_set_name)
                    .id(&self.ip_set_id)
                    .scope(self.scope.clone())
                    .set_addresses(Some(addresses))
                    .lock_token(remote.lock_token)
                    .send(),
            )
            .map_err(|error| {
                BlockholeError::Plugin(format!("AWS WAF UpdateIPSet failed: {error}"))
            })?;

        if !sync::diff(desired, &self.current()?).identical() {
            return Err(BlockholeError::Plugin(
                "AWS WAF IPSet verification mismatch".into(),
            ));
        }
        Ok(())
    }
}

pub fn parse_log_line(line: &str) -> Result<Observation> {
    parse_log_line_with_source(line, DEFAULT_SOURCE_ID)
}

fn parse_log_line_with_source(line: &str, source_id: &str) -> Result<Observation> {
    let record: WafLog = serde_json::from_str(line)
        .map_err(|error| BlockholeError::Plugin(format!("invalid AWS WAF log JSON: {error}")))?;
    let observed_at = Utc
        .timestamp_millis_opt(record.timestamp)
        .single()
        .ok_or_else(|| BlockholeError::Plugin("invalid AWS WAF log timestamp".into()))?;
    let path = normalize_path(&record.http_request.uri)?;
    let action = record.action.as_deref().unwrap_or("UNKNOWN");
    let status = record.response_code_sent.unwrap_or_default();
    let ip = Subject::parse(&record.http_request.client_ip)?;
    let fingerprint = format!("{source_id}:{ip}:{action}:{status}:{path}:{observed_at}");

    Ok(Observation {
        ip,
        source_id: source_id.into(),
        observed_at,
        observed_requests: 1,
        weighted_requests: 1.0,
        paths: vec![path.clone()],
        error_requests: u64::from(status >= 400),
        sampled: false,
        sample_interval: None,
        fingerprint,
    })
}

#[derive(Deserialize)]
struct WafLog {
    timestamp: i64,
    #[serde(default)]
    action: Option<String>,
    #[serde(rename = "responseCodeSent", default)]
    response_code_sent: Option<u16>,
    #[serde(rename = "httpRequest")]
    http_request: HttpRequest,
}

#[derive(Deserialize)]
struct HttpRequest {
    #[serde(rename = "clientIp")]
    client_ip: String,
    uri: String,
}

fn normalize_path(uri: &str) -> Result<String> {
    let path = uri.split('?').next().unwrap_or(uri);
    let path = path.split('#').next().unwrap_or(path);
    if path.is_empty() {
        return Err(BlockholeError::Plugin(
            "AWS WAF request URI is empty".into(),
        ));
    }
    Ok(path.to_string())
}

fn normalize_desired(desired: &DesiredList, version: AddressVersion) -> Result<DesiredList> {
    let items = desired
        .items
        .iter()
        .map(|item| {
            let is_ipv4 = item.subject.0.addr().is_ipv4();
            let matches = matches!(
                (version, is_ipv4),
                (AddressVersion::Ipv4, true) | (AddressVersion::Ipv6, false)
            );
            if !matches {
                return Err(BlockholeError::Configuration(format!(
                    "AWS WAF IPSet address version mismatch for {}",
                    item.subject
                )));
            }
            Ok(BlockTarget {
                subject: item.subject.clone(),
                comment: String::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DesiredList { items })
}

fn restore_comments(mut diff: ListDiff, desired: &DesiredList) -> ListDiff {
    let comments: BTreeMap<&Subject, &str> = desired
        .items
        .iter()
        .map(|item| (&item.subject, item.comment.as_str()))
        .collect();
    for item in diff.additions.iter_mut().chain(diff.changes.iter_mut()) {
        if let Some(comment) = comments.get(&item.subject) {
            item.comment = (*comment).to_string();
        }
    }
    diff
}

fn load_policy_file(root: &Path) -> Result<PolicyFile> {
    toml::from_str(&fs::read_to_string(root.join("config/policy.toml"))?)
        .map_err(|error| BlockholeError::Configuration(error.to_string()))
}

fn validate_config_values(config: &AwsWafConfig) -> Result<(Scope, AddressVersion)> {
    if config.log_path.as_os_str().is_empty() {
        return Err(BlockholeError::Configuration(
            "aws_waf.log_path must not be empty".into(),
        ));
    }
    if config.region.trim().is_empty() {
        return Err(BlockholeError::Configuration(
            "aws_waf.region must not be empty".into(),
        ));
    }
    if config.ip_set_name.trim().is_empty() {
        return Err(BlockholeError::Configuration(
            "aws_waf.ip_set_name must not be empty".into(),
        ));
    }
    if config.ip_set_id.trim().is_empty() {
        return Err(BlockholeError::Configuration(
            "aws_waf.ip_set_id must not be empty".into(),
        ));
    }
    if config.source_id.trim().is_empty() {
        return Err(BlockholeError::Configuration(
            "aws_waf.source_id must not be empty".into(),
        ));
    }

    let scope = match config.scope.trim().to_ascii_uppercase().as_str() {
        "REGIONAL" => Scope::Regional,
        "CLOUDFRONT" => {
            if config.region != "us-east-1" {
                return Err(BlockholeError::Configuration(
                    "aws_waf CloudFront scope requires region us-east-1".into(),
                ));
            }
            Scope::Cloudfront
        }
        value => {
            return Err(BlockholeError::Configuration(format!(
                "aws_waf.scope must be REGIONAL or CLOUDFRONT, got {value}"
            )));
        }
    };
    let address_version = match config.address_version.trim().to_ascii_uppercase().as_str() {
        "IPV4" => AddressVersion::Ipv4,
        "IPV6" => AddressVersion::Ipv6,
        value => {
            return Err(BlockholeError::Configuration(format!(
                "aws_waf.address_version must be IPV4 or IPV6, got {value}"
            )));
        }
    };
    Ok((scope, address_version))
}

fn resolve_path(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressVersion, AwsWafBackend, normalize_desired, parse_log_line};
    use super::{AwsWafConfig, validate_config_values};
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_wafv2::types::Scope;
    use blockhole_core::{
        models::{BlockTarget, DesiredList, Subject},
        sync::BlockBackend,
    };
    use serde_json::Value;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        sync::{Arc, Mutex},
        thread,
    };
    use tokio::runtime::Builder as RuntimeBuilder;

    fn read_request(stream: &mut TcpStream) -> (String, String) {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "mock AWS server received an incomplete request");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let line = line.to_ascii_lowercase();
                line.strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while bytes.len() < header_end + 4 + content_length {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "mock AWS server received a truncated body");
            bytes.extend_from_slice(&buffer[..count]);
        }
        let body_start = header_end + 4;
        let body =
            String::from_utf8_lossy(&bytes[body_start..body_start + content_length]).to_string();
        (headers, body)
    }

    fn write_response(stream: &mut TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn serve_waf_mock(
        listener: TcpListener,
        requests: Arc<Mutex<Vec<String>>>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let addresses = Arc::new(Mutex::new(vec!["192.0.2.1/32".to_string()]));
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = read_request(&mut stream);
                let target = headers.to_ascii_lowercase();
                if target.contains("getipset") {
                    requests.lock().unwrap().push("get_ip_set".into());
                    let addresses = addresses.lock().unwrap().clone();
                    let response = serde_json::json!({
                        "LockToken": "lock-token",
                        "IPSet": {
                            "Name": "blockhole",
                            "Id": "ip-set-id",
                            "Scope": "REGIONAL",
                            "Description": "",
                            "IPAddressVersion": "IPV4",
                            "Addresses": addresses
                        }
                    });
                    write_response(&mut stream, &response.to_string());
                } else if target.contains("updateipset") {
                    requests.lock().unwrap().push("update_ip_set".into());
                    let request: Value = serde_json::from_str(&body).unwrap();
                    let updated = request["Addresses"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|address| address.as_str().unwrap().to_string())
                        .collect::<Vec<_>>();
                    *addresses.lock().unwrap() = updated;
                    write_response(&mut stream, "{\"NextLockToken\":\"next-token\"}");
                } else {
                    panic!("unexpected AWS WAF operation: {headers}");
                }
            }
        })
    }

    #[test]
    fn parses_waf_json_log_into_normalized_observation() {
        let line = r#"{
            "timestamp": 1720000000123,
            "action": "BLOCK",
            "responseCodeSent": 403,
            "httpRequest": {
                "clientIp": "203.0.113.5",
                "country": "SG",
                "uri": "/admin/login?next=%2Fconsole#fragment",
                "args": "next=%2Fconsole",
                "httpVersion": "HTTP/2.0",
                "httpMethod": "GET",
                "requestId": "redacted"
            }
        }"#;
        let observation = parse_log_line(line).unwrap();

        assert_eq!(observation.ip, Subject::parse("203.0.113.5").unwrap());
        assert_eq!(observation.observed_requests, 1);
        assert_eq!(observation.weighted_requests, 1.0);
        assert_eq!(observation.paths, vec!["/admin/login"]);
        assert_eq!(observation.error_requests, 1);
        assert_eq!(observation.source_id, "aws-waf");
        assert!(
            observation
                .fingerprint
                .starts_with("aws-waf:203.0.113.5/32:BLOCK:403:/admin/login:")
        );
    }

    #[test]
    fn rejects_malformed_waf_json() {
        let error = parse_log_line("not-json").unwrap_err();

        assert!(error.to_string().contains("AWS WAF log"));
    }

    #[test]
    fn replaces_ip_set_with_get_update_and_readback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server = serve_waf_mock(listener, Arc::clone(&requests));
        let runtime = Arc::new(
            RuntimeBuilder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let sdk_config = runtime.block_on(
            aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .endpoint_url(endpoint)
                .test_credentials()
                .load(),
        );
        let backend = AwsWafBackend {
            client: super::WafClient::new(&sdk_config),
            runtime,
            scope: Scope::Regional,
            ip_set_name: "blockhole".into(),
            ip_set_id: "ip-set-id".into(),
        };
        let desired = DesiredList {
            items: vec![BlockTarget {
                subject: Subject::parse("192.0.2.2").unwrap(),
                comment: String::new(),
            }],
        };

        backend.replace(&desired).unwrap();
        server.join().unwrap();

        assert_eq!(
            *requests.lock().unwrap(),
            vec!["get_ip_set", "update_ip_set", "get_ip_set"]
        );
    }

    #[test]
    fn rejects_addresses_from_the_other_ip_family() {
        let desired = DesiredList {
            items: vec![BlockTarget {
                subject: Subject::parse("2001:db8::1").unwrap(),
                comment: "blockhole:auto".into(),
            }],
        };

        assert!(normalize_desired(&desired, AddressVersion::Ipv4).is_err());
        assert!(normalize_desired(&desired, AddressVersion::Ipv6).is_ok());
    }

    #[test]
    fn requires_cloudfront_to_use_us_east_1() {
        let config = AwsWafConfig {
            log_path: PathBuf::from("waf.jsonl"),
            region: "us-west-2".into(),
            scope: "CLOUDFRONT".into(),
            ip_set_name: "blockhole".into(),
            ip_set_id: "0123456789abcdef0123456789abcdef".into(),
            address_version: "IPV4".into(),
            source_id: "aws-waf".into(),
        };

        assert!(validate_config_values(&config).is_err());
    }
}
