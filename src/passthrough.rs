//! `lim docker` / `compose` / `exec` / `stop` / `prune`.
//!
//! All target the limes daemon explicitly, so `lim docker ps` shows only limes's
//! own objects and `lim prune` can never reach another daemon's images or volumes.

use std::io::{self, Write};
use std::os::unix::process::CommandExt;

use anyhow::{Result, bail};

use crate::context::{Context, LABEL};
use crate::docker;
use crate::sandbox;

/// `lim docker …` → replace this process with `docker --host <limes> …`.
pub fn docker(ctx: &Context, args: &[String]) -> Result<()> {
    let mut cmd = docker::command(ctx);
    cmd.args(args);
    // exec() only returns if it fails to replace the process.
    Err(cmd.exec().into())
}

/// `lim compose …` → `docker --host <limes> compose …`.
pub fn compose(ctx: &Context, args: &[String]) -> Result<()> {
    let mut cmd = docker::command(ctx);
    cmd.arg("compose").args(args);
    Err(cmd.exec().into())
}

/// Open another shell (or command) inside a running sandbox.
///
/// The same path a bare `lim` takes when it joins, rather than a second implementation:
/// two join paths would drift, and this one already lacked the terminal variables. Unlike
/// the passthroughs above it cannot `exec()` away, because it has to outlive the shell to
/// decide whether it was the last one out.
pub fn exec(ctx: &Context, instance: &str, cmd: &[String]) -> Result<()> {
    let cmd: Vec<String> =
        if cmd.is_empty() { vec!["zsh".into(), "-l".into()] } else { cmd.to_vec() };

    let in_flight = sandbox::in_flight(ctx, instance)?;
    // No `-w`: `lim exec` names a sandbox, not a workspace, and the host cwd it was invoked
    // from need not exist inside it.
    let code = sandbox::join(ctx, instance, None, &cmd, &crate::run::term_env())?;

    drop(in_flight);
    sandbox::release(ctx, instance)?;
    std::process::exit(code);
}

/// Stop named sandboxes, or every running one with `--all`.
pub fn stop(ctx: &Context, all: bool, instances: &[String]) -> Result<()> {
    if !docker::daemon_alive(ctx) {
        bail!("limes daemon not reachable — nothing to stop");
    }
    let targets: Vec<String> = if all {
        running_ids(ctx)?
    } else if instances.is_empty() {
        bail!("nothing to stop: name a sandbox (see `lim status`) or pass --all");
    } else {
        instances.to_vec()
    };

    if targets.is_empty() {
        println!("no running limes sandboxes");
        return Ok(());
    }

    let mut cmd = docker::command(ctx);
    cmd.arg("stop").args(&targets);
    docker::run(cmd)
}

/// Reclaim space on the limes daemon. Safe by construction: the daemon has its own
/// data-root, so this can only ever remove limes's own containers/images/volumes.
pub fn prune(ctx: &Context, force: bool) -> Result<()> {
    if !docker::daemon_alive(ctx) {
        bail!("limes daemon not reachable — nothing to prune");
    }
    println!(
        "This prunes the limes daemon only (data-root {}):\n  \
         stopped containers, unused images, build cache, and unused volumes.",
        ctx.data_root().display()
    );
    if !force && !confirm("Proceed? [y/N] ")? {
        println!("aborted");
        return Ok(());
    }
    let mut cmd = docker::command(ctx);
    cmd.args(["system", "prune", "-af", "--volumes"]);
    docker::run(cmd)
}

/// IDs of running containers stamped with the limes label.
fn running_ids(ctx: &Context) -> Result<Vec<String>> {
    let out = docker::command(ctx)
        .args(["ps", "-q", "--filter", &format!("label={LABEL}=1")])
        .output()?;
    if !out.status.success() {
        bail!("`docker ps` failed on the limes daemon");
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}
