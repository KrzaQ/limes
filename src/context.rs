//! Host facts and well-known limes paths, resolved once at startup.

use std::path::PathBuf;

use anyhow::{Context as _, Result};

/// Image tag built by `lim build` and run by `lim run`.
pub const IMAGE_TAG: &str = "limes:local";
/// systemd user unit name for the dedicated rootless daemon.
pub const SERVICE: &str = "limes-docker.service";
/// Label stamped on every container, and the filter key for `status`/`stop`/`prune`.
pub const LABEL: &str = "limes";

/// Everything limes needs to know about the host it runs on.
pub struct Context {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub xdg_runtime_dir: PathBuf,
}

impl Context {
    pub fn detect() -> Result<Self> {
        // getuid/getgid never fail and need no error handling.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set")?;
        let xdg_runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
        Ok(Self { uid, gid, home, xdg_runtime_dir })
    }

    /// The dedicated limes daemon socket — never the system/rootful one.
    pub fn socket(&self) -> PathBuf {
        self.xdg_runtime_dir.join("limes-docker.sock")
    }

    /// `unix://…` form for `docker --host` / `DOCKER_HOST`.
    pub fn docker_host(&self) -> String {
        format!("unix://{}", self.socket().display())
    }

    /// Dedicated data-root, so cleanup/prune only ever touches limes's own subtree,
    /// never images or volumes from any other Docker daemon.
    pub fn data_root(&self) -> PathBuf {
        self.home.join(".local/share/limes/docker")
    }

    pub fn service_file(&self) -> PathBuf {
        self.home.join(".config/systemd/user").join(SERVICE)
    }
}
