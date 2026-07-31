use crate::{
    error::Result,
    models::{BlockDecision, BlockTarget, DesiredList, EvaluationResult, State},
};
use chrono::{DateTime, Utc};
use std::{fs, path::Path};

pub fn evaluate_state(state: &State, now: DateTime<Utc>) -> Vec<EvaluationResult> {
    state
        .records
        .iter()
        .map(|(subject, record)| {
            EvaluationResult::from_record(subject.clone(), record.clone(), now)
        })
        .collect()
}

pub fn render_desired_list(results: &[EvaluationResult]) -> DesiredList {
    let mut items = results
        .iter()
        .filter_map(|result| {
            let comment = match &result.decision {
                BlockDecision::Permanent => "blockhole:permanent:manual".to_string(),
                BlockDecision::Temporary { expires_at } => format!(
                    "blockhole:auto:{}:expires={}",
                    result.record.reason_codes.join("+"),
                    expires_at.format("%Y-%m-%d")
                ),
                BlockDecision::Allow => return None,
            };
            Some(BlockTarget {
                subject: result.subject.clone(),
                comment,
            })
        })
        .collect::<Vec<_>>();
    items.sort_by(|a, b| a.subject.cmp(&b.subject));
    DesiredList { items }
}

pub fn render(
    root: &Path,
    state: &State,
    now: DateTime<Utc>,
    report_path: &Path,
) -> Result<DesiredList> {
    let desired = render_desired_list(&evaluate_state(state, now));
    fs::create_dir_all(root.join("dist"))?;
    fs::write(
        root.join("dist/blacklist.txt"),
        desired
            .items
            .iter()
            .map(|i| format!("{}\n", i.subject))
            .collect::<String>(),
    )?;
    fs::write(
        root.join("dist/desired-blocks.json"),
        serde_json::to_string_pretty(&desired)? + "\n",
    )?;
    let report_target = if report_path.is_relative() {
        root.join(report_path)
    } else {
        report_path.to_path_buf()
    };
    if let Some(parent) = report_target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &report_target,
        format!(
            "# Latest run\n\n- Mode: generated\n- Evaluated at: {}\n- Active blocked IPs: {}\n",
            now.to_rfc3339(),
            desired.items.len()
        ),
    )?;
    Ok(desired)
}
