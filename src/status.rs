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

    // SHELLS replaces the old CMD column. With joining, `limes.cmd` records only the
    // invocation that *created* the sandbox and says nothing about the shells in it now —
    // the label is kept (status/stop/prune key off the schema) but it is no longer honest
    // to present it as describing the sandbox. The shell count is the interesting number.
    println!("{:<40} {:>6} {:<24} WORKSPACE", "NAME", "SHELLS", "STATUS");
    for r in &rows {
        let workspace = r.label(&format!("{LABEL}.workspace"));
        println!(
            "{:<40} {:>6} {:<24} {}",
            truncate(&r.names, 40),
            docker::exec_count(ctx, &r.names),
            truncate(&r.status, 24),
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
