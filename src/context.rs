//! Host facts and well-known limes paths, resolved once at startup.

use std::path::PathBuf;

use anyhow::{Context as _, Result};

/// Image tag built by `lim build` and run by `lim run`.
#[cfg(target_os = "linux")]
pub const IMAGE_TAG: &str = "limes:local";
/// systemd user unit name for the dedicated rootless daemon.
#[cfg(target_os = "linux")]
pub const SERVICE: &str = "limes-docker.service";
/// Label stamped on every container, and the filter key for `status`/`stop`/`prune`.
#[cfg(target_os = "linux")]
pub const LABEL: &str = "limes";

/// Everything limes needs to know about the host it runs on.
pub struct Context {
    pub uid: u32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub gid: u32,
    pub home: PathBuf,
    pub xdg_runtime_dir: PathBuf,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Context {
    pub fn detect() -> Result<Self> {
        // getuid/getgid never fail and need no error handling.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let home = std::env::var_os("HOME").map(PathBuf::from).context("HOME is not set")?;
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

    /// Generated `/etc/passwd` and `/etc/group`, presenting container uid 0 as the invoking
    /// user (see `identity.rs`). They sit beside the socket in `$XDG_RUNTIME_DIR` — per-user
    /// tmpfs, so they never outlive the login session — and are rewritten on every run.
    pub fn passwd_file(&self) -> PathBuf {
        self.xdg_runtime_dir.join("limes-passwd")
    }

    pub fn group_file(&self) -> PathBuf {
        self.xdg_runtime_dir.join("limes-group")
    }

    /// Dedicated data-root, so cleanup/prune only ever touches limes's own subtree,
    /// never images or volumes from any other Docker daemon.
    pub fn data_root(&self) -> PathBuf {
        self.home.join(".local/share/limes/docker")
    }

    #[cfg(target_os = "linux")]
    pub fn service_file(&self) -> PathBuf {
        self.home.join(".config/systemd/user").join(SERVICE)
    }

    /// The vendored rootless launcher, written here by `bootstrap` and run by the
    /// systemd unit — so setup needs no AUR / `docker-ce-rootless-extras` package.
    pub fn launcher_path(&self) -> PathBuf {
        self.home.join(".local/share/limes/bin/dockerd-rootless.sh")
    }

    /// `~/.config/limes` (honoring `$XDG_CONFIG_HOME`).
    fn config_dir(&self) -> PathBuf {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home.join(".config"))
            .join("limes")
    }

    /// Per-machine config file (standing default mounts, future settings).
    /// Unmanaged, like `~/.gitconfig` — never symlinked from a dotfiles repo.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir().join("config.toml")
    }

    /// Drop-in config dir: whole `*.toml` files owned by tools/installers (e.g. dotfiles).
    pub fn config_d_dir(&self) -> PathBuf {
        self.config_dir().join("config.d")
    }
}
