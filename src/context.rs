//! Host facts and well-known limes paths, resolved once at startup.

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};

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
    /// The host's own hostname, which the sandbox mirrors by default (see `sandbox_hostname`).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub hostname: String,
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
        Ok(Self { uid, gid, home, xdg_runtime_dir, hostname: detect_hostname() })
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

    /// Per-sandbox lock, serialising *create-and-initialise* across concurrent `lim`s.
    ///
    /// It sits in `$XDG_RUNTIME_DIR` for the same reason the identity files do — per-user
    /// tmpfs, so a lock can never outlive the login session that made it.
    pub fn lock_file(&self, name: &str) -> PathBuf {
        self.xdg_runtime_dir.join(format!("{name}.lock"))
    }

    /// Held *shared* by every `lim` from before it looks for the sandbox until after its
    /// shell exits. Teardown takes it exclusively, so "nobody else is in flight" is a
    /// question the kernel answers rather than something limes has to write down.
    pub fn shells_file(&self, name: &str) -> PathBuf {
        self.xdg_runtime_dir.join(format!("{name}.shells"))
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

/// Longest hostname the kernel will accept. `HOST_NAME_MAX` is 64 including the NUL.
const HOSTNAME_MAX: usize = 63;

/// `gethostname(2)`. A failure here is not worth refusing to start a sandbox over, so it
/// falls back the way `run`'s `/etc` reads do — the sandbox is still perfectly usable with
/// a generic hostname.
fn detect_hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "localhost".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// The hostname to give the sandbox: the host's own, optionally suffixed.
///
/// Mirroring is the default because "it should feel exactly like the host" is the whole
/// feature. The cost — per-host state (caches, history, anything shipping a hostname to a
/// remote) merging between host and sandbox — is real but small, and the `LIM` prompt badge
/// and `$LIMES_VERSION` already answer "where am I". The suffix exists for people who do
/// want them distinguishable.
///
/// Without it the sandbox reports the container ID, which changes every run and reads as
/// noise.
pub fn sandbox_hostname(base: &str, suffix: Option<&str>) -> Result<String> {
    let Some(suffix) = suffix.filter(|s| !s.is_empty()) else {
        return Ok(truncate(base));
    };
    // Zsh's `%m` truncates at the first dot, so `krzaq.limes` renders as plain `krzaq`:
    // the feature appears to do nothing at all, and the next hour goes into the wrong
    // place. Refuse, and say which shell behaviour is responsible.
    if suffix.contains('.') {
        bail!(
            "hostname suffix `{suffix}` contains a dot\n  \
             zsh's `%m` truncates at the first dot, so the suffix would be invisible in \
             your prompt — use `-` instead"
        );
    }
    if let Some(c) = suffix.chars().find(|c| !c.is_ascii_alphanumeric() && *c != '-') {
        bail!(
            "hostname suffix `{suffix}` contains `{c}`; only letters, digits and `-` are allowed"
        );
    }
    // Naive append, including for an FQDN: `box.lan` + `limes` gives `box.lan-limes`, not
    // `box-limes.lan`. Inserting after the first label is prettier and more surprising.
    //
    // If that overflows, trim the *base* rather than the tail: the suffix is the whole
    // point of asking for one, so it is the part that must survive.
    let room = HOSTNAME_MAX.saturating_sub(suffix.len() + 1);
    Ok(format!("{}-{suffix}", truncate_to(base, room)))
}

fn truncate(s: &str) -> String {
    truncate_to(s, HOSTNAME_MAX)
}

fn truncate_to(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_suffix_mirrors_the_host() {
        assert_eq!(sandbox_hostname("krzaq", None).unwrap(), "krzaq");
        assert_eq!(sandbox_hostname("krzaq", Some("")).unwrap(), "krzaq", "empty means none");
    }

    /// The trap this rejection exists for: zsh `%m` would silently swallow the suffix.
    #[test]
    fn a_dotted_suffix_is_rejected_naming_the_reason() {
        let err = sandbox_hostname("krzaq", Some("box.lan")).unwrap_err().to_string();
        assert!(err.contains("%m"), "the error must name the cause: {err}");
    }

    #[test]
    fn an_invalid_character_is_rejected() {
        assert!(sandbox_hostname("krzaq", Some("a b")).is_err());
        assert!(sandbox_hostname("krzaq", Some("a/b")).is_err());
    }

    /// Naive append, deliberately: `box-limes.lan` is prettier and more surprising.
    #[test]
    fn an_fqdn_base_appends_rather_than_inserting() {
        assert_eq!(sandbox_hostname("box.lan", Some("limes")).unwrap(), "box.lan-limes");
    }

    /// The suffix is why you asked, so overflow eats the base, not the suffix.
    #[test]
    fn overflow_trims_the_base_and_keeps_the_suffix() {
        let long = "a".repeat(80);
        let h = sandbox_hostname(&long, Some("limes")).unwrap();
        assert_eq!(h.len(), HOSTNAME_MAX);
        assert!(h.ends_with("-limes"), "got: {h}");
        assert_eq!(sandbox_hostname(&long, None).unwrap().len(), HOSTNAME_MAX);
    }
}
