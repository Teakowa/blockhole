use blockhole_core::{
    error::{BlockholeError, Result},
    models::{BlockTarget, DesiredList, Observation, Subject},
    plugin::{BlockDeployer, CollectionWindow, ObservationSource, SyncOptions},
    sync::{self, BlockBackend, ListDiff},
};
use chrono::{DateTime, Utc};
use regex::RegexSet;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Deserialize)]
struct PolicyFile {
    nginx: NginxConfig,
}

#[derive(Deserialize)]
struct NginxConfig {
    access_log: PathBuf,
    denylist_path: PathBuf,
    #[serde(default = "default_source_id")]
    source_id: String,
    #[serde(default)]
    reload: bool,
}

fn default_source_id() -> String {
    "nginx".into()
}

pub struct NginxPlugin {
    access_log: PathBuf,
    denylist_path: PathBuf,
    source_id: String,
    reload: bool,
}

impl NginxPlugin {
    pub fn validate_config(root: &Path) -> Result<()> {
        let config = load_policy_file(root)?;
        validate_config_values(&config.nginx)?;
        validate_paths(root, &config.nginx)
    }

    pub fn load(root: &Path) -> Result<Self> {
        let config = load_policy_file(root)?.nginx;
        validate_config_values(&config)?;
        validate_paths(root, &config)?;
        Ok(Self {
            access_log: resolve_path(root, config.access_log),
            denylist_path: resolve_path(root, config.denylist_path),
            source_id: config.source_id,
            reload: config.reload,
        })
    }
}

impl ObservationSource for NginxPlugin {
    fn collect(
        &self,
        window: CollectionWindow,
        suspicious_path_set: &RegexSet,
    ) -> Result<Vec<Observation>> {
        let contents = fs::read_to_string(&self.access_log)?;
        contents
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(line_number, line)| {
                parse_log_line(line, &self.source_id, suspicious_path_set).map_err(|error| {
                    BlockholeError::Plugin(format!(
                        "invalid nginx access log {}:{}: {error}",
                        self.access_log.display(),
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

impl BlockDeployer for NginxPlugin {
    fn sync(&self, desired: &DesiredList, options: SyncOptions) -> Result<ListDiff> {
        let backend = NginxBackend {
            path: &self.denylist_path,
            reload: self.reload,
        };
        sync::reconcile(
            &backend,
            desired,
            options.dry_run,
            options.mode,
            options.allow_empty,
        )
    }
}

struct NginxBackend<'a> {
    path: &'a Path,
    reload: bool,
}

impl BlockBackend for NginxBackend<'_> {
    fn current(&self) -> Result<Vec<BlockTarget>> {
        match fs::read_to_string(self.path) {
            Ok(contents) => parse_denylist(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    fn replace(&self, desired: &DesiredList) -> Result<()> {
        atomic_write(self.path, &render_denylist(desired))?;
        if self.reload {
            reload_nginx()?;
        }
        if !sync::diff(desired, &self.current()?).identical() {
            return Err(BlockholeError::Plugin(
                "nginx denylist verification mismatch".into(),
            ));
        }
        Ok(())
    }
}

pub fn parse_log_line(
    line: &str,
    source_id: &str,
    suspicious_path_set: &RegexSet,
) -> Result<Observation> {
    let ip = line
        .split_whitespace()
        .next()
        .ok_or_else(|| BlockholeError::Plugin("nginx log line is empty".into()))
        .and_then(Subject::parse)?;
    let timestamp_start = line
        .find('[')
        .ok_or_else(|| BlockholeError::Plugin("nginx log timestamp is missing".into()))?;
    let timestamp_end = line[timestamp_start + 1..]
        .find(']')
        .map(|offset| timestamp_start + 1 + offset)
        .ok_or_else(|| BlockholeError::Plugin("nginx log timestamp is unterminated".into()))?;
    let timestamp = &line[timestamp_start + 1..timestamp_end];
    let observed_at = DateTime::parse_from_str(timestamp, "%d/%b/%Y:%H:%M:%S %z")
        .or_else(|_| DateTime::parse_from_rfc3339(timestamp))
        .map_err(|error| BlockholeError::Plugin(format!("invalid nginx timestamp: {error}")))?
        .with_timezone(&Utc);

    let request_start = line[timestamp_end + 1..]
        .find('"')
        .map(|offset| timestamp_end + 1 + offset)
        .ok_or_else(|| BlockholeError::Plugin("nginx request is missing".into()))?;
    let request_end = line[request_start + 1..]
        .find('"')
        .map(|offset| request_start + 1 + offset)
        .ok_or_else(|| BlockholeError::Plugin("nginx request is unterminated".into()))?;
    let mut request_parts = line[request_start + 1..request_end].split_whitespace();
    request_parts
        .next()
        .ok_or_else(|| BlockholeError::Plugin("nginx request method is missing".into()))?;
    let target = request_parts
        .next()
        .ok_or_else(|| BlockholeError::Plugin("nginx request target is missing".into()))?;
    let path = normalize_path(target)?;
    let status = line[request_end + 1..]
        .split_whitespace()
        .next()
        .ok_or_else(|| BlockholeError::Plugin("nginx response status is missing".into()))?
        .parse::<u16>()
        .map_err(|error| {
            BlockholeError::Plugin(format!("invalid nginx response status: {error}"))
        })?;
    let suspicious = suspicious_path_set.is_match(&path);
    let mut hasher = Sha256::new();
    hasher.update(format!("{source_id}:{ip}:{path}:{status}:{observed_at}").as_bytes());

    Ok(Observation {
        ip,
        source_id: source_id.into(),
        observed_at,
        observed_requests: 1,
        weighted_requests: 1.0,
        paths: vec![path],
        suspicious_paths: u64::from(suspicious),
        error_requests: u64::from(status >= 400),
        sampled: false,
        sample_interval: None,
        fingerprint: format!("{:x}", hasher.finalize())[..16].to_string(),
    })
}

pub fn render_denylist(desired: &DesiredList) -> String {
    let mut items = desired.items.clone();
    items.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then_with(|| left.comment.cmp(&right.comment))
    });
    let mut output = String::new();
    for item in items {
        let comment = sanitize_comment(&item.comment);
        if !comment.is_empty() {
            output.push_str("# ");
            output.push_str(&comment);
            output.push('\n');
        }
        output.push_str("deny ");
        output.push_str(&item.subject.to_string());
        output.push_str(";\n");
    }
    output
}

fn parse_denylist(contents: &str) -> Result<Vec<BlockTarget>> {
    let mut pending_comment = None;
    let mut items = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix("# ") {
            pending_comment = Some(comment.to_string());
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let subject = line
            .strip_prefix("deny ")
            .and_then(|value| value.strip_suffix(';'))
            .ok_or_else(|| {
                BlockholeError::Plugin(format!(
                    "unsupported nginx denylist directive at line {}",
                    line_number + 1
                ))
            })
            .and_then(Subject::parse)?;
        items.push(BlockTarget {
            subject,
            comment: pending_comment.take().unwrap_or_default(),
        });
    }
    items.sort_by(|left, right| left.subject.cmp(&right.subject));
    Ok(items)
}

fn normalize_path(target: &str) -> Result<String> {
    let target = target.split('?').next().unwrap_or(target);
    let target = target.split('#').next().unwrap_or(target);
    let target = if let Some(offset) = target.find("://") {
        let authority = &target[offset + 3..];
        authority
            .find('/')
            .map(|path_start| &authority[path_start..])
            .unwrap_or("/")
    } else {
        target
    };
    if target.is_empty() {
        return Err(BlockholeError::Plugin("nginx request path is empty".into()));
    }
    Ok(target.to_string())
}

fn sanitize_comment(comment: &str) -> String {
    comment
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn atomic_write(path: &Path, contents: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let filename = path
        .file_name()
        .ok_or_else(|| BlockholeError::Configuration("nginx denylist path has no filename".into()))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{filename}.blockhole-{}.tmp", std::process::id()));
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

fn reload_nginx() -> Result<()> {
    let status = Command::new("nginx")
        .args(["-s", "reload"])
        .status()
        .map_err(|error| {
            BlockholeError::Plugin(format!("failed to execute nginx reload: {error}"))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(BlockholeError::Plugin(format!(
            "nginx reload exited with status {status}"
        )))
    }
}

fn load_policy_file(root: &Path) -> Result<PolicyFile> {
    toml::from_str(&fs::read_to_string(root.join("config/policy.toml"))?)
        .map_err(|error| BlockholeError::Configuration(error.to_string()))
}

fn validate_config_values(config: &NginxConfig) -> Result<()> {
    if config.access_log.as_os_str().is_empty() {
        return Err(BlockholeError::Configuration(
            "nginx.access_log must not be empty".into(),
        ));
    }
    if config.denylist_path.as_os_str().is_empty() {
        return Err(BlockholeError::Configuration(
            "nginx.denylist_path must not be empty".into(),
        ));
    }
    if config.source_id.trim().is_empty() {
        return Err(BlockholeError::Configuration(
            "nginx.source_id must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_paths(root: &Path, config: &NginxConfig) -> Result<()> {
    if resolve_path(root, config.access_log.clone())
        == resolve_path(root, config.denylist_path.clone())
    {
        return Err(BlockholeError::Configuration(
            "nginx.access_log and nginx.denylist_path must differ".into(),
        ));
    }
    Ok(())
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
    use super::{NginxPlugin, parse_denylist, parse_log_line, render_denylist};
    use blockhole_core::config::RunMode;
    use blockhole_core::models::{BlockTarget, DesiredList, Subject};
    use blockhole_core::plugin::{BlockDeployer, CollectionWindow, ObservationSource, SyncOptions};
    use chrono::{TimeZone, Utc};
    use regex::RegexSet;
    use std::fs;

    #[test]
    fn parses_combined_access_log_and_strips_query_string() {
        let patterns = RegexSet::new([r"(^|/)\.env($|/)"]).unwrap();
        let observation = parse_log_line(
            "192.0.2.1 - - [31/Jul/2026:12:00:00 +0000] \"GET /.env?token=secret HTTP/1.1\" 404 123 \"-\" \"curl/8.0\"",
            "nginx",
            &patterns,
        )
        .unwrap();

        assert_eq!(observation.ip, Subject::parse("192.0.2.1").unwrap());
        assert_eq!(observation.source_id, "nginx");
        assert_eq!(observation.paths, vec!["/.env"]);
        assert_eq!(observation.suspicious_paths, 1);
        assert_eq!(observation.error_requests, 1);
        assert_eq!(observation.observed_requests, 1);
    }

    #[test]
    fn renders_a_deterministic_nginx_include() {
        let desired = DesiredList {
            items: vec![BlockTarget {
                subject: Subject::parse("192.0.2.1").unwrap(),
                comment: "blockhole:auto:suspicious_paths".into(),
            }],
        };

        assert_eq!(
            render_denylist(&desired),
            "# blockhole:auto:suspicious_paths\ndeny 192.0.2.1/32;\n"
        );
    }

    #[test]
    fn rejects_unmanaged_nginx_directives_in_the_include() {
        assert!(parse_denylist("allow all;\n").is_err());
    }

    #[test]
    fn collects_the_window_and_reconciles_the_managed_include() {
        let root = std::env::temp_dir().join(format!(
            "blockhole-nginx-plugin-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(
            root.join("config/policy.toml"),
            "[nginx]\naccess_log = \"access.log\"\ndenylist_path = \"deny.conf\"\nsource_id = \"edge\"\nreload = false\n",
        )
        .unwrap();
        fs::write(
            root.join("access.log"),
            "192.0.2.1 - - [31/Jul/2026:12:00:00 +0000] \"GET /.env HTTP/1.1\" 404 123 \"-\" \"curl/8.0\"\n192.0.2.2 - - [30/Jul/2026:12:00:00 +0000] \"GET /.git/config HTTP/1.1\" 404 123 \"-\" \"curl/8.0\"\n",
        )
        .unwrap();

        let plugin = NginxPlugin::load(&root).unwrap();
        let observations = plugin
            .collect(
                CollectionWindow {
                    start: Utc.with_ymd_and_hms(2026, 7, 31, 11, 0, 0).unwrap(),
                    end: Utc.with_ymd_and_hms(2026, 7, 31, 13, 0, 0).unwrap(),
                },
                &RegexSet::new([r"(^|/)\.env($|/)"]).unwrap(),
            )
            .unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].source_id, "edge");

        let desired = DesiredList {
            items: vec![BlockTarget {
                subject: Subject::parse("192.0.2.1").unwrap(),
                comment: "blockhole:auto:suspicious_paths".into(),
            }],
        };
        let diff = plugin
            .sync(
                &desired,
                SyncOptions {
                    dry_run: false,
                    mode: RunMode::Enforce,
                    allow_empty: false,
                },
            )
            .unwrap();
        assert_eq!(diff.additions, desired.items);
        assert_eq!(
            fs::read_to_string(root.join("deny.conf")).unwrap(),
            "# blockhole:auto:suspicious_paths\ndeny 192.0.2.1/32;\n"
        );

        let dry_run_diff = plugin
            .sync(
                &desired,
                SyncOptions {
                    dry_run: true,
                    mode: RunMode::Enforce,
                    allow_empty: false,
                },
            )
            .unwrap();
        assert!(dry_run_diff.identical());
        let _ = fs::remove_dir_all(&root);
    }
}
