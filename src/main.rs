use blockhole::{
    analytics,
    config::{self, RunMode},
    error::{BlockholeError, Result},
    lifecycle,
    models::Observation,
    policy, render, state,
    sync::ListsClient,
};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use reqwest::blocking::Client;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "blockhole")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Validate,
    Collect {
        #[arg(long)]
        lookback_hours: Option<i64>,
    },
    Evaluate,
    Render {
        #[arg(long, default_value = "reports/latest.md")]
        report_path: PathBuf,
    },
    Sync {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        allow_empty: bool,
    },
    Run {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        lookback_hours: Option<i64>,
        #[arg(long)]
        allow_empty: bool,
        #[arg(long, default_value = "reports/latest.md")]
        report_path: PathBuf,
    },
}
fn main() -> std::process::ExitCode {
    match execute(std::env::args().skip(1).collect()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::from(2)
        }
    }
}
fn execute(args: Vec<String>) -> Result<()> {
    let cli = match Cli::try_parse_from(std::iter::once("blockhole".into()).chain(args)) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return Ok(());
        }
        Err(error) => return Err(BlockholeError::Configuration(error.to_string())),
    };
    let root = std::env::current_dir()?;
    match cli.command {
        Command::Validate => validate(&root),
        Command::Collect { lookback_hours } => {
            let settings = config::load(&root)?;
            let (start, end) = window(&settings, lookback_hours)?;
            let observations = collect(&settings, start, end)?;
            println!("{}", serde_json::to_string_pretty(&observations)?);
            Ok(())
        }
        Command::Evaluate => evaluate(&root, &[]),
        Command::Render { report_path } => {
            let settings = config::load(&root)?;
            let st = state::load(&settings.root.join("data/state.json"))?;
            render::render(&root, &st, Utc::now(), &report_path).map(|_| ())
        }
        Command::Sync {
            dry_run,
            allow_empty,
        } => sync(&root, dry_run, allow_empty),
        Command::Run {
            dry_run,
            lookback_hours,
            allow_empty,
            report_path,
        } => {
            validate(&root)?;
            let settings = config::load(&root)?;
            let (start, end) = window(&settings, lookback_hours)?;
            let observations = collect(&settings, start, end)?;
            evaluate_at(&root, &observations, end)?;
            let st = state::load(&root.join("data/state.json"))?;
            render::render(&root, &st, Utc::now(), &report_path)?;
            sync(&root, dry_run, allow_empty)
        }
    }
}
fn validate(root: &Path) -> Result<()> {
    let settings = config::load(root)?;
    let allow = policy::allowlist(root)?;
    let permanent = policy::permanent(root)?;
    let st = state::load(&settings.root.join("data/state.json"))?;
    println!(
        "valid: {} allowlist entries, {} permanent entries, {} state records",
        allow.len(),
        permanent.len(),
        st.records.len()
    );
    Ok(())
}
fn window(
    settings: &config::Settings,
    lookback: Option<i64>,
) -> Result<(chrono::DateTime<Utc>, chrono::DateTime<Utc>)> {
    let end = Utc::now();
    let st = state::load(&settings.root.join("data/state.json"))?;
    Ok((
        st.checkpoints
            .get("analytics")
            .copied()
            .unwrap_or(end - Duration::hours(lookback.unwrap_or(settings.lookback_hours))),
        end,
    ))
}
fn collect(
    settings: &config::Settings,
    start: chrono::DateTime<Utc>,
    end: chrono::DateTime<Utc>,
) -> Result<Vec<Observation>> {
    if settings.zone_ids.is_empty() {
        return Err(BlockholeError::Configuration(
            "no zone IDs configured in config/policy.toml".into(),
        ));
    }
    let (token, _, _) = config::credentials()?;
    let client = authenticated_client(token)?;
    std::thread::scope(|s| {
        let handles: Vec<_> = settings
            .zone_ids
            .iter()
            .map(|zone| {
                s.spawn(|| {
                    analytics::collect(
                        &client,
                        &settings.graphql_url,
                        settings.max_retries,
                        zone,
                        start,
                        end,
                        &settings.suspicious_path_set,
                    )
                })
            })
            .collect();
        let mut all = Vec::new();
        for handle in handles {
            all.extend(handle.join().map_err(|_| {
                BlockholeError::Cloudflare("zone collection thread panicked".into())
            })??);
        }
        Ok(all)
    })
}
fn evaluate(root: &Path, observations: &[Observation]) -> Result<()> {
    evaluate_at(root, observations, Utc::now())
}
fn evaluate_at(
    root: &Path,
    observations: &[Observation],
    checkpoint: chrono::DateTime<Utc>,
) -> Result<()> {
    let settings = config::load(root)?;
    let mut st = state::load(&root.join("data/state.json"))?;
    let allow = policy::allowlist(root)?;
    let permanent = policy::permanent(root)?;
    policy::merge_permanent(&mut st, &permanent, checkpoint);
    let mut grouped = std::collections::BTreeMap::<_, Vec<Observation>>::new();
    for observation in observations.iter().cloned() {
        grouped
            .entry(observation.ip.clone())
            .or_default()
            .push(observation);
    }
    for (subject, values) in grouped {
        let old = st.records.get(&subject);
        let mut record = policy::evaluate(&values, old, &settings, checkpoint)?;
        lifecycle::apply(
            &mut record,
            &settings,
            checkpoint,
            policy::is_allowlisted(&subject, &allow),
        );
        st.records.insert(subject, record);
    }
    for (subject, record) in &mut st.records {
        lifecycle::apply(
            record,
            &settings,
            checkpoint,
            policy::is_allowlisted(subject, &allow),
        );
    }
    st.checkpoints.insert("analytics".into(), checkpoint);
    state::write(&root.join("data/state.json"), &st)
}
fn sync(root: &Path, dry_run: bool, allow_empty: bool) -> Result<()> {
    let settings = config::load(root)?;
    let (token, account, list) = config::credentials()?;
    let desired: blockhole::models::DesiredList =
        serde_json::from_str(&fs::read_to_string(root.join("dist/cloudflare-list.json"))?)?;
    let client = authenticated_client(token)?;
    let lists = ListsClient::new(
        client,
        &settings.api_base_url,
        &account,
        &list,
        settings.max_retries,
        settings.poll_interval_seconds,
        settings.poll_timeout_seconds,
    );
    let actual = lists.get_items()?;
    let diff = blockhole::sync::diff(&desired, &actual);
    println!(
        "add={} remove={} change={}",
        diff.additions.len(),
        diff.removals.len(),
        diff.changes.len()
    );
    if !dry_run && settings.mode != RunMode::DryRun && !diff.identical() {
        lists.replace(&desired, actual.len(), allow_empty)?;
    }
    Ok(())
}

fn authenticated_client(token: String) -> Result<Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| BlockholeError::Configuration(e.to_string()))?,
    );
    Ok(Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("blockhole/0.2")
        .default_headers(headers)
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parse_render_and_run_report_path() {
        let run_cli = Cli::try_parse_from(["blockhole", "run", "--report-path", "custom_run.md"]);
        assert!(run_cli.is_ok());
        if let Command::Run { report_path, .. } = run_cli.unwrap().command {
            assert_eq!(report_path, PathBuf::from("custom_run.md"));
        } else {
            panic!("expected Run command");
        }

        let render_cli =
            Cli::try_parse_from(["blockhole", "render", "--report-path", "custom_render.md"]);
        assert!(render_cli.is_ok());
        if let Command::Render { report_path } = render_cli.unwrap().command {
            assert_eq!(report_path, PathBuf::from("custom_render.md"));
        } else {
            panic!("expected Render command");
        }

        let invalid_cli = Cli::try_parse_from(["blockhole", "run", "--force-rebuild"]);
        assert!(invalid_cli.is_err());
    }
}
