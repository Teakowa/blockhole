use crate::{
    error::Result,
    lifecycle::active,
    models::{CloudflareItem, DesiredList, RecordStatus, State},
};
use chrono::{DateTime, Utc};
use std::{fs, path::Path};
pub fn render(
    root: &Path,
    state: &State,
    now: DateTime<Utc>,
    report_path: &Path,
) -> Result<DesiredList> {
    let active = active(&state.records, now);
    let mut items = Vec::new();
    for (subject, record) in active {
        let comment = match record.status {
            RecordStatus::PermanentBlocked { .. } => "blockhole:permanent:manual".to_string(),
            RecordStatus::TemporaryBlocked { expires_at, .. } => format!(
                "blockhole:auto:{}:expires={}",
                record.reason_codes.join("+"),
                expires_at.format("%Y-%m-%d")
            ),
            _ => continue,
        };
        items.push(CloudflareItem {
            ip: subject,
            comment,
        });
    }
    items.sort_by(|a, b| a.ip.cmp(&b.ip));
    let desired = DesiredList { items };
    fs::create_dir_all(root.join("dist"))?;
    fs::write(
        root.join("dist/blacklist.txt"),
        desired
            .items
            .iter()
            .map(|i| format!("{}\n", i.ip))
            .collect::<String>(),
    )?;
    fs::write(
        root.join("dist/cloudflare-list.json"),
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
