//! Helpers for invoking `docker` against the dedicated limes daemon.
//!
//! Every docker call limes makes is explicitly pointed at the limes socket via
//! `--host`, so the user's ambient `DOCKER_HOST` / default context is never touched
//! and the bare host shell keeps talking to the rootful daemon.

use std::process::Command;

use anyhow::{Result, bail};

use crate::context::{Context, LABEL};

/// A `docker --host unix://…limes-docker.sock` command, ready for more args.
pub fn command(ctx: &Context) -> Command {
    let mut c = Command::new("docker");
    c.arg("--host").arg(ctx.docker_host());
    c
}

/// Run a docker command to completion, propagating its exit status as an error.
pub fn run(mut cmd: Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("failed to exec docker: {e} (is docker installed?)"))?;
    if !status.success() {
        bail!("docker exited with {status}");
    }
    Ok(())
}

/// True if the limes daemon answers `docker info`.
pub fn daemon_alive(ctx: &Context) -> bool {
    command(ctx)
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether the limes daemon is running rootless, or `None` if it could not be asked.
///
/// `run` passes `-u 0:0` on the strength of this: rootless means container uid 0 is the
/// invoking user, rootful means it is actually root. `docker info` lists `rootless` among
/// its security options.
pub fn daemon_rootless(ctx: &Context) -> Option<bool> {
    let out = command(ctx)
        .args(["info", "--format", "{{range .SecurityOptions}}{{println .}}{{end}}"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).contains("rootless"))
}

/// True if a container by this name exists *and* is running.
///
/// The container name is a total function of the workspace path, so this lookup is the
/// whole discovery mechanism — no `docker ps --filter label=…` scan is needed.
pub fn container_running(ctx: &Context, name: &str) -> bool {
    inspect(ctx, name, "{{.State.Running}}").as_deref() == Some("true")
}

/// How many `docker exec` sessions are live in this container.
///
/// Measured on Docker 29.6.2: finished execs are *pruned* from `.ExecIDs`, so this is an
/// exact count of attached shells rather than a running total. That is what makes it usable
/// as the teardown signal, and why no per-exec `Running` lookup (API-only) is needed.
///
/// It counts shells, not processes — deliberately. `docker top` would keep a sandbox alive
/// for any stray background process, which is a leak with no bound; the cost of this choice
/// is that backgrounding a build and leaving does not keep the sandbox up.
pub fn exec_count(ctx: &Context, name: &str) -> usize {
    inspect(ctx, name, "{{len .ExecIDs}}").and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Full `docker inspect` JSON for a container — the raw material for comparing a running
/// sandbox against a requested policy, without a fingerprint label that could go stale.
pub fn inspect_json(ctx: &Context, name: &str) -> Result<String> {
    let out = command(ctx)
        .args(["inspect", name])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to exec docker: {e}"))?;
    if !out.status.success() {
        bail!("could not inspect `{name}`: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// One `docker inspect --format` field, or `None` if the container is absent.
fn inspect(ctx: &Context, name: &str, format: &str) -> Option<String> {
    let out = command(ctx)
        .args(["inspect", "--format", format, name])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Remove a container, ignoring "no such container". Used to clear a stopped leftover
/// before recreating: `--rm` should have reaped it, so reaching this is already unusual.
pub fn remove_quietly(ctx: &Context, name: &str) {
    let _ = command(ctx)
        .args(["rm", "-f", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Stop a container, tolerating one that has already gone.
pub fn stop_quietly(ctx: &Context, name: &str) {
    let _ = command(ctx)
        .args(["stop", "-t", "1", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Remove every container `name`'s sandbox created — those the in-sandbox proxy stamped with
/// `limes.owner=<name>` — so a sandbox's containers die with it. Includes stopped ones (`-a`),
/// which a fixture may have left behind.
///
/// Tolerant and quiet by design: it runs on the teardown path, where a container that is
/// already gone or a momentary daemon hiccup must never turn into an error the user sees on
/// their way out of a shell.
pub fn reap_owned(ctx: &Context, name: &str) {
    let out = command(ctx)
        .args(["ps", "-aq", "--filter", &format!("label={LABEL}.owner={name}")])
        .stderr(std::process::Stdio::null())
        .output();
    let ids: Vec<String> = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => return,
    };
    if ids.is_empty() {
        return;
    }
    let _ = command(ctx)
        .args(["rm", "-f"])
        .args(&ids)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// True if the limes image is present on the limes daemon.
pub fn image_present(ctx: &Context) -> bool {
    command(ctx)
        .args(["image", "inspect", crate::context::IMAGE_TAG])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
