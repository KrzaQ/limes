//! `lim status` / `lim ps` — list running limes sandboxes, their child containers, and any
//! orphans on the daemon.

use std::collections::HashSet;

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
    /// `"running"`, `"exited"`, `"created"`, … — distinguishes a live sandbox (whose children
    /// have a parent) from a stopped one.
    #[serde(rename = "State", default)]
    state: String,
    /// Comma-separated `k=v` list, e.g. `limes=1,limes.workspace=/home/…`.
    #[serde(rename = "Labels")]
    labels: String,
}

impl PsRow {
    fn label(&self, key: &str) -> &str {
        self.labels.split(',').find_map(|kv| kv.strip_prefix(&format!("{key}="))).unwrap_or("")
    }

    /// Whether this container is a limes *sandbox* (as opposed to one a sandbox created).
    fn is_sandbox(&self) -> bool {
        self.label(LABEL) == "1"
    }

    /// The sandbox that created this container, or `""` if it carries no owner label.
    fn owner(&self) -> &str {
        self.label(&format!("{LABEL}.owner"))
    }
}

pub fn status(ctx: &Context) -> Result<()> {
    if !docker::daemon_alive(ctx) {
        bail!("limes daemon not reachable at {} — run `lim bootstrap`", ctx.socket().display());
    }

    // One sweep of *every* container on the dedicated daemon — sandboxes, their children, and
    // anything orphaned — so counts and orphan detection agree and cost a single docker call.
    let out = docker::command(ctx).args(["ps", "-a", "--format", "{{json .}}"]).output()?;
    if !out.status.success() {
        bail!("`docker ps` failed on the limes daemon");
    }
    let rows: Vec<PsRow> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;

    // Running sandboxes are the listing; their names are also what tells an owned child from an
    // orphan below.
    let sandboxes: Vec<&PsRow> =
        rows.iter().filter(|r| r.is_sandbox() && r.state == "running").collect();
    let running: HashSet<&str> = sandboxes.iter().map(|r| r.names.as_str()).collect();

    if sandboxes.is_empty() {
        println!("no running limes sandboxes");
    } else {
        // SHELLS is the live `docker exec` count; CHILDREN is the containers this sandbox
        // created (see `docker_proxy`), stopped ones included since they'll be reaped too.
        println!("{:<36} {:>6} {:>8} {:<20} WORKSPACE", "NAME", "SHELLS", "CHILDREN", "STATUS");
        for r in &sandboxes {
            let children = rows.iter().filter(|c| c.owner() == r.names).count();
            println!(
                "{:<36} {:>6} {:>8} {:<20} {}",
                truncate(&r.names, 36),
                docker::exec_count(ctx, &r.names),
                children,
                truncate(&r.status, 20),
                r.label(&format!("{LABEL}.workspace")),
            );
        }
    }

    // Orphans: not a sandbox, and no *running* sandbox owns it — a child whose parent exited
    // (the leak this whole feature fixes), or a container started outside the ownership model.
    // Surfaced, not reaped: reaping on demand is a follow-up on `prune`.
    let orphans = rows.iter().filter(|r| !r.is_sandbox() && !running.contains(r.owner())).count();
    if orphans > 0 {
        let plural = if orphans == 1 { "" } else { "s" };
        println!("\n{orphans} orphaned container{plural} (no live parent) — see `lim docker ps`");
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
