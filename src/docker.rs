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
