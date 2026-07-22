//! Helpers for invoking `docker` against the dedicated limes daemon.
//!
//! Every docker call limes makes is explicitly pointed at the limes socket via
//! `--host`, so the user's ambient `DOCKER_HOST` / default context is never touched
//! and the bare host shell keeps talking to the rootful daemon.

use std::process::Command;

use anyhow::{Result, bail};

use crate::context::Context;

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
