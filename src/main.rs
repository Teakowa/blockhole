use blockhole_core::{
    config,
    error::{BlockholeError, Result},
    lifecycle,
    models::Observation,
    plugin::{CollectionWindow, PlatformPlugin, SyncOptions},
    policy, render, state,
};
use blockhole_plugin_aws_waf::AwsWafPlugin;
use blockhole_plugin_cloudflare::CloudflarePlugin;
use blockhole_plugin_nginx::NginxPlugin;
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const VERSION: &str = match option_env!("BLOCKHOLE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser, Debug)]
#[command(name = "blockhole", version = VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand, Debug)]
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
        Command::Evaluate => evaluate_at(&root, &[], Utc::now()),
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
    validate_plugin(root, &settings.platform)?;
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
    let plugin = load_plugin(settings)?;
    let mut observations = plugin.collect(CollectionWindow { start, end })?;
    policy::annotate_suspicious_paths(&mut observations, &settings.suspicious_path_set);
    Ok(observations)
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

    // Collect all subjects that need processing (existing + newly observed).
    let all_subjects: std::collections::BTreeSet<_> = st
        .records
        .keys()
        .cloned()
        .chain(grouped.keys().cloned())
        .collect();

    // Single pass: transition each record exactly once.
    for subject in all_subjects {
        let previous = st.records.get(&subject);
        let obs = grouped.get(&subject).map_or(&[] as &[_], |v| v.as_slice());
        let record = lifecycle::transition(
            previous,
            obs,
            &settings,
            checkpoint,
            policy::is_allowlisted(&subject, &allow),
        )?;
        st.records.insert(subject, record);
    }

    st.checkpoints.insert("analytics".into(), checkpoint);
    state::write(&root.join("data/state.json"), &st)
}
fn sync(root: &Path, dry_run: bool, allow_empty: bool) -> Result<()> {
    let settings = config::load(root)?;
    let desired: blockhole_core::models::DesiredList =
        serde_json::from_str(&fs::read_to_string(root.join("dist/desired-blocks.json"))?)?;
    let plugin = load_plugin(&settings)?;
    let diff = plugin.sync(
        &desired,
        SyncOptions {
            dry_run,
            mode: settings.mode,
            allow_empty,
        },
    )?;
    println!(
        "add={} remove={} change={}",
        diff.additions.len(),
        diff.removals.len(),
        diff.changes.len()
    );
    Ok(())
}

fn load_plugin(settings: &config::Settings) -> Result<Box<dyn PlatformPlugin>> {
    match settings.platform.as_str() {
        "cloudflare" => Ok(Box::new(CloudflarePlugin::load(&settings.root)?)),
        "nginx" => Ok(Box::new(NginxPlugin::load(&settings.root)?)),
        "aws-waf" => Ok(Box::new(AwsWafPlugin::load(&settings.root)?)),
        name => Err(BlockholeError::Configuration(format!(
            "unsupported platform plugin: {name}"
        ))),
    }
}

fn validate_plugin(root: &Path, name: &str) -> Result<()> {
    match name {
        "cloudflare" => CloudflarePlugin::validate_config(root),
        "nginx" => NginxPlugin::validate_config(root),
        "aws-waf" => AwsWafPlugin::validate_config(root),
        name => Err(BlockholeError::Configuration(format!(
            "unsupported platform plugin: {name}"
        ))),
    }
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

    #[test]
    fn version_cli_output() {
        let version_cli = Cli::try_parse_from(["blockhole", "--version"]);
        assert!(version_cli.is_err());
        let err = version_cli.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(VERSION));
    }

    #[test]
    fn unknown_platform_plugin_is_rejected() {
        let error = validate_plugin(Path::new("."), "unknown").unwrap_err();
        assert!(
            matches!(error, BlockholeError::Configuration(message) if message.contains("unknown"))
        );
    }
}
