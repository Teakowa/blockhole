use blockhole_core::{error::Result, models::DesiredList};
use chrono::{DateTime, Utc};
use std::{fs, path::Path};

pub fn write_render_outputs(
    root: &Path,
    desired: &DesiredList,
    now: DateTime<Utc>,
    report_path: &Path,
) -> Result<()> {
    fs::create_dir_all(root.join("dist"))?;
    fs::write(
        root.join("dist/blacklist.txt"),
        desired
            .items
            .iter()
            .map(|item| format!("{}\n", item.subject))
            .collect::<String>(),
    )?;
    fs::write(
        root.join("dist/desired-blocks.json"),
        serde_json::to_string_pretty(desired)? + "\n",
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
        report_target,
        format!(
            "# Latest run\n\n- Mode: generated\n- Evaluated at: {}\n- Active blocked IPs: {}\n",
            now.to_rfc3339(),
            desired.items.len()
        ),
    )?;
    Ok(())
}
