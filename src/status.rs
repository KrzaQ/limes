//! `lim status` / `lim ps` — list running limes sandboxes.

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::context::{Context, LABEL};
use crate::docker;

#[derive(Deserialize)]
struct PsRow {
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Status")]
    status: String,
    /// Comma-separated `k=v` list, e.g. `limes=1,limes.workspace=/home/…`.
    #[serde(rename = "Labels")]
    labels: String,
}

impl PsRow {
    fn label(&self, key: &str) -> String {
        self.labels
            .split(',')
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
            .unwrap_or("")
            .to_string()
    }
}

pub fn status(ctx: &Context) -> Result<()> {
    if !docker::daemon_alive(ctx) {
        bail!("limes daemon not reachable at {} — run `lim bootstrap`", ctx.socket().display());
    }

    let out = docker::command(ctx)
        .args(["ps", "--filter", &format!("label={LABEL}=1"), "--format", "{{json .}}"])
        .output()?;
    if !out.status.success() {
        bail!("`docker ps` failed on the limes daemon");
    }

    let rows: Vec<PsRow> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;

    if rows.is_empty() {
        println!("no running limes sandboxes");
        return Ok(());
    }

    println!("{:<24} {:<10} {:<28} {}", "NAME", "CMD", "STATUS", "WORKSPACE");
    for r in &rows {
        let cmd = r.label(&format!("{LABEL}.cmd"));
        let workspace = r.label(&format!("{LABEL}.workspace"));
        println!(
            "{:<24} {:<10} {:<28} {}",
            r.names,
            truncate(&cmd, 10),
            truncate(&r.status, 28),
            workspace
        );
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let keep: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{keep}\u{2026}")
    }
}
