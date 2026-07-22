//! Mount engine: a policy per path, depth-sorted so nested rules apply.
//!
//! A `Mount` is **not** a bind mount, despite the name. It is a policy for one path
//! *inside the sandbox*, which each backend renders its own way: a `-v` bind or a
//! `--tmpfs` on Linux, an SBPL rule on macOS. `Hide` has no host side at all, which is
//! why the field is `path` rather than `host`.
//!
//! Every mode still governs `/path` → `/path`. The same-path invariant is intact; `Hide`
//! simply has no source to differ from.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

/// What a path's policy is inside the sandbox.
///
/// `Mount` must stay `PartialEq` — `run::dedupe` compares and copies whole kinds, and the
/// precedence tests rest on that — so any payload here has to be `Copy + Eq`. `Hide`'s is:
/// the host mode to give the shadow, which is the one thing about a hidden directory that
/// is not simply "empty".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Bind the host path in, read-only.
    Ro,
    /// Bind the host path in, writable.
    Rw,
    /// Shadow the path with an empty tmpfs: it exists inside, but the host's contents
    /// are unreachable. Subtractive — a hole punched in some broader mount.
    ///
    /// Carries the host directory's mode. A fabricated 0755 over a host 0700 *widens* the
    /// directory relative to the host, which is the same class of bug as the one the
    /// invented-directory mirroring fixes; the sandbox should never invent a mode.
    Hide(u32),
}

/// A single path policy request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub path: PathBuf,
    pub kind: Kind,
}

impl Mount {
    pub fn ro(p: PathBuf) -> Self {
        Self { path: p, kind: Kind::Ro }
    }
    pub fn rw(p: PathBuf) -> Self {
        Self { path: p, kind: Kind::Rw }
    }
    pub fn hide(p: PathBuf, mode: u32) -> Self {
        Self { path: p, kind: Kind::Hide(mode) }
    }

    /// Lower this policy to the docker-level view: a same-path bind, or a tmpfs shadow.
    ///
    /// `Ro`/`Rw` stay same-path (`/path:/path[:ro]`) so absolute paths baked into build
    /// artifacts (compile_commands.json, ccache, diagnostics) stay valid on both sides.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn flatten(&self) -> MountArg {
        match self.kind {
            Kind::Ro => MountArg::Bind(Bind::same_path(&self.path, true)),
            Kind::Rw => MountArg::Bind(Bind::same_path(&self.path, false)),
            // An empty tmpfs shadows whatever the parent bind put there, and unlike binding
            // an empty directory it needs no host path to point at. Docker's --tmpfs
            // defaults (rw,noexec,nosuid,nodev) are what a hidden dir wants; `mode` is
            // pinned explicitly for the same reason `run`'s $HOME tmpfs pins it — so the
            // result never depends on which uid the container happens to run as — and it is
            // the *host's* mode, so hiding a directory never widens it.
            Kind::Hide(mode) => MountArg::Tmpfs(Tmpfs::new(&self.path, &mode_opt(mode))),
        }
    }
}

/// One entry as docker actually sees it. This is the level `docker inspect` reports at —
/// `Mounts` for the binds, `HostConfig.Tmpfs` for the rest — which is what lets a running
/// container be compared against a requested policy without a fingerprint label.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum MountArg {
    Bind(Bind),
    Tmpfs(Tmpfs),
}

/// A bind with an explicit destination.
///
/// Same-path is still the rule — `Mount` models it and everything user-facing goes through
/// that. This exists for the short list that legitimately differs: the generated
/// `/etc/passwd` and `/etc/group`, and the gpg and docker sockets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub src: String,
    pub dst: String,
    pub ro: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tmpfs {
    pub path: String,
    pub opts: String,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Bind {
    pub fn same_path(p: &Path, ro: bool) -> Self {
        let p = p.display().to_string();
        Self { src: p.clone(), dst: p, ro }
    }
    pub fn new(src: impl Into<String>, dst: impl Into<String>, ro: bool) -> Self {
        Self { src: src.into(), dst: dst.into(), ro }
    }
    pub fn to_args(&self) -> Vec<String> {
        let Self { src, dst, ro } = self;
        let spec = if *ro { format!("{src}:{dst}:ro") } else { format!("{src}:{dst}") };
        vec!["-v".into(), spec]
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Tmpfs {
    pub fn new(path: &Path, opts: &str) -> Self {
        Self { path: path.display().to_string(), opts: opts.into() }
    }
    pub fn to_args(&self) -> Vec<String> {
        vec!["--tmpfs".into(), format!("{}:{}", self.path, self.opts)]
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl MountArg {
    pub fn to_args(&self) -> Vec<String> {
        match self {
            MountArg::Bind(b) => b.to_args(),
            MountArg::Tmpfs(t) => t.to_args(),
        }
    }
}

/// A `--tmpfs` `mode=` option from a host `st_mode`, masked to the permission bits.
///
/// Always leading-zero, so the value reads as octal at a glance and a setgid directory
/// renders `mode=02775` rather than a `2775` that looks decimal.
pub fn mode_opt(mode: u32) -> String {
    format!("mode=0{:o}", mode & 0o7777)
}

/// Canonicalize a user-supplied path (realpath); errors if it does not exist,
/// since a same-path bind mount of a missing host path is always a mistake.
///
/// `Kind::Hide` does *not* come through here — see `resolve_hide`, which is exempt from
/// the must-exist rule on purpose.
pub fn canonicalize(p: &Path) -> Result<PathBuf> {
    p.canonicalize().with_context(|| format!("cannot mount {}: no such path on host", p.display()))
}

/// Resolve a `hide` target, shared by the CLI flag and config so the two can't drift.
///
/// `Ok(None)` means "nothing to do": a path that isn't on the host has no contents to
/// shadow, so hiding it is a no-op rather than an error. This is the one exemption from
/// the must-exist invariant, and it is deliberate — a *synced* config drop-in wants to
/// name credential dirs that exist on only some machines.
///
/// Directories only. `--tmpfs` cannot shadow a file, and quietly doing nothing for one
/// would be a silent hole in something people reach for to hide secrets.
///
/// Returns the host mode alongside the path: the `stat` that proves the path is a directory
/// already carries it, so mirroring it onto the shadow costs no extra syscall.
pub fn resolve_hide(p: &Path) -> Result<Option<(PathBuf, u32)>> {
    use std::os::unix::fs::MetadataExt;

    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot hide {}", p.display())),
    };
    if !meta.is_dir() {
        bail!(
            "cannot hide {}: hide applies to directories; hide its parent directory instead",
            p.display()
        );
    }
    // Canonical because seatbelt matches the *resolved* path — see `seatbelt.rs`.
    Ok(Some((canonicalize(p)?, meta.mode())))
}

/// Order mounts parent-before-child so nested holes apply correctly regardless of
/// the order the user passed them. Docker sorts internally too, but we do it
/// defensively and to make `--dry-run` output deterministic and readable.
pub fn sort_for_nesting(mounts: &mut [Mount]) {
    mounts.sort_by(|a, b| {
        let da = a.path.components().count();
        let db = b.path.components().count();
        da.cmp(&db).then_with(|| a.path.cmp(&b.path))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flag pair per kind. `Hide` is the reason a `Mount` cannot lower to a bare
    /// bind-spec string: it is a `--tmpfs`, not a `-v`.
    #[test]
    fn flatten_renders_each_kind() {
        assert_eq!(Mount::ro("/a".into()).flatten().to_args(), ["-v", "/a:/a:ro"]);
        assert_eq!(Mount::rw("/a".into()).flatten().to_args(), ["-v", "/a:/a"]);
        assert_eq!(
            Mount::hide("/a".into(), 0o755).flatten().to_args(),
            ["--tmpfs", "/a:mode=0755"]
        );
    }

    /// The shadow takes the host's mode, so hiding a 0700 credential dir never leaves it
    /// world-readable inside — a fabricated 0755 would have *widened* it.
    #[test]
    fn a_hidden_dir_keeps_the_hosts_mode() {
        assert_eq!(
            Mount::hide("/a".into(), 0o700).flatten().to_args(),
            ["--tmpfs", "/a:mode=0700"]
        );
        // Full `st_mode` in, permission bits out — and a setgid bit survives the round trip.
        assert_eq!(mode_opt(0o040751), "mode=0751");
        assert_eq!(mode_opt(0o2775), "mode=02775");
    }

    /// The escape hatch for the few mounts whose destination legitimately differs.
    #[test]
    fn a_bind_can_name_a_differing_destination() {
        assert_eq!(
            Bind::new("/run/limes-passwd", "/etc/passwd", true).to_args(),
            ["-v", "/run/limes-passwd:/etc/passwd:ro"]
        );
    }

    /// Missing is a no-op, not an error — the documented exemption from must-exist.
    #[test]
    fn resolve_hide_skips_a_missing_path() {
        let p = Path::new("/nonexistent-limes-hide-probe/nope");
        assert_eq!(resolve_hide(p).expect("missing hide is not an error"), None);
    }

    /// A file cannot be shadowed by a tmpfs, and silently ignoring one would leave a hole
    /// in exactly the feature people use to hide credentials.
    #[test]
    fn resolve_hide_rejects_a_file() {
        let err = resolve_hide(Path::new("/etc/passwd")).expect_err("a file must not hide");
        assert!(err.to_string().contains("directories"), "got: {err}");
    }
}
