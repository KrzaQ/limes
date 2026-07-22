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
/// Deliberately payload-free, so `Mount` stays `PartialEq` — `run::dedupe` compares and
/// copies whole kinds, and the precedence tests rest on that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Bind the host path in, read-only.
    Ro,
    /// Bind the host path in, writable.
    Rw,
    /// Shadow the path with an empty tmpfs: it exists inside, but the host's contents
    /// are unreachable. Subtractive — a hole punched in some broader mount.
    Hide,
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
    pub fn hide(p: PathBuf) -> Self {
        Self { path: p, kind: Kind::Hide }
    }

    /// The docker flag pair for this mount.
    ///
    /// Returns the whole pair rather than a bare `-v` value, because not every mode is a
    /// bind: `Hide` is a `--tmpfs`. `Ro`/`Rw` stay same-path (`/path:/path[:ro]`) so
    /// absolute paths baked into build artifacts (compile_commands.json, ccache,
    /// diagnostics) stay valid on both sides.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn to_args(&self) -> Vec<String> {
        let p = self.path.display();
        match self.kind {
            Kind::Ro => vec!["-v".into(), format!("{p}:{p}:ro")],
            // An empty tmpfs shadows whatever the parent bind put there, and unlike binding
            // an empty directory it needs no host path to point at. Docker's --tmpfs
            // defaults (rw,noexec,nosuid,nodev) are what a hidden dir wants; `mode` is
            // pinned explicitly for the same reason `run`'s $HOME tmpfs pins it — so the
            // result never depends on which uid the container happens to run as.
            Kind::Hide => vec!["--tmpfs".into(), format!("{p}:mode=0755")],
            Kind::Rw => vec!["-v".into(), format!("{p}:{p}")],
        }
    }
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
pub fn resolve_hide(p: &Path) -> Result<Option<PathBuf>> {
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
    Ok(Some(canonicalize(p)?))
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

    /// The flag pair per kind. `Hide` is the reason `to_args` returns a `Vec` at all:
    /// it is not a `-v`, so a bare bind-spec string could not express it.
    #[test]
    fn to_args_renders_each_kind() {
        assert_eq!(Mount::ro("/a".into()).to_args(), ["-v", "/a:/a:ro"]);
        assert_eq!(Mount::rw("/a".into()).to_args(), ["-v", "/a:/a"]);
        assert_eq!(Mount::hide("/a".into()).to_args(), ["--tmpfs", "/a:mode=0755"]);
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
