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

/// The mode Docker gives a directory it has to fabricate for a mount destination.
const DOCKER_INVENTS_AT: u32 = 0o755;

/// Directories the sandbox will *invent*, and the host mode each should carry.
///
/// The tmpfs `$HOME` starts empty, so Docker fabricates the whole ancestor chain of every
/// bind destination under it — at 0755, whatever the host has. `~/.gnupg` arriving 0755
/// instead of 0700 is why gpg warns about unsafe permissions on every invocation inside a
/// sandbox; `~/.local` and `~/.local/share` are wrong the same way, and each same-path
/// mount a future forward or agent adds repeats it silently.
///
/// The answer is not a list of paths to fix — that is another blocklist, with `hide`'s rot
/// problem, asking for a preference where none exists. The correct mode is not a matter of
/// taste, it is whatever the host has.
///
/// The predicate that matters is **"did Docker have to invent this?"** A directory arriving
/// through a bind is the host's own inode and already carries the host's mode. "Is it a
/// mount destination" is only an approximation of that — an ancestor *under* a bind was not
/// invented either.
///
/// `mode_of` is injected so the rule stays testable against a fabricated host, the way
/// `seatbelt` and `identity` stay testable off-platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn invented_dirs(
    mounts: &[MountArg],
    home: &Path,
    mode_of: &dyn Fn(&Path) -> Option<u32>,
) -> Vec<(PathBuf, u32)> {
    // Destination, and whether it brings the host's own mode with it.
    let dests: Vec<(PathBuf, bool)> = mounts
        .iter()
        .map(|m| match m {
            MountArg::Bind(b) => (PathBuf::from(&b.dst), true),
            MountArg::Tmpfs(t) => (PathBuf::from(&t.path), false),
        })
        .collect();

    let mut out: Vec<(PathBuf, u32)> = Vec::new();
    for (dst, _) in &dests {
        for a in dst.ancestors().skip(1) {
            // Strictly below `$HOME`. Excluding `$HOME` itself is deliberate, not luck:
            // `run` pins it to `mode=1777` for reasons recorded there, and mirroring the
            // host's 0755 onto it would quietly undo them.
            if a == home || !a.starts_with(home) {
                continue;
            }
            if out.iter().any(|(p, _)| p == a) || !is_invented(a, &dests) {
                continue;
            }
            let Some(mode) = mode_of(a) else {
                continue; // Nothing to mirror.
            };
            // What Docker would have made it anyway, so emitting only adds noise to
            // `--dry-run` — and keeping the common case invisible there is worth a line.
            if mode & 0o7777 == DOCKER_INVENTS_AT {
                continue;
            }
            out.push((a.to_path_buf(), mode));
        }
    }
    // Shallowest-first, for the reason `sort_for_nesting` gives: stable, diffable output.
    out.sort_by(|(a, _), (b, _)| {
        a.components().count().cmp(&b.components().count()).then_with(|| a.cmp(b))
    });
    out
}

/// Whether Docker has to fabricate `p`, rather than it arriving through a mount.
fn is_invented(p: &Path, dests: &[(PathBuf, bool)]) -> bool {
    // A mount of its own: a bind brings the host's mode with it, and a tmpfs was already
    // given one — by `hide`, or by `invented_dirs` on an earlier pass.
    if dests.iter().any(|(d, _)| d == p) {
        return false;
    }
    // Otherwise the *deepest* mount it sits under decides. A bind supplies the directory
    // from the host, mode included; a tmpfs — the `$HOME` one included — supplies nothing,
    // which is exactly why the chain has to be fabricated in the first place.
    dests
        .iter()
        .filter(|(d, _)| p.starts_with(d) && p != d)
        .max_by_key(|(d, _)| d.components().count())
        .is_none_or(|(_, from_host)| !*from_host)
}

/// `stat(2)`'s mode, or `None` when the path cannot be stat'd — the real `mode_of`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn host_mode(p: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.mode())
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

    const HOME: &str = "/home/u";

    fn bind(dst: &str) -> MountArg {
        MountArg::Bind(Bind::new(dst, dst, true))
    }

    fn tmpfs(path: &str) -> MountArg {
        MountArg::Tmpfs(Tmpfs::new(Path::new(path), "mode=0700"))
    }

    /// A fabricated host: only the paths named here exist, with the modes given. Anything
    /// else is unstattable, which is the `None` branch of the rule.
    fn host(modes: &'static [(&'static str, u32)]) -> impl Fn(&Path) -> Option<u32> {
        move |p: &Path| modes.iter().find(|(path, _)| Path::new(path) == p).map(|(_, mode)| *mode)
    }

    fn invented(mounts: &[MountArg], modes: &'static [(&'static str, u32)]) -> Vec<(PathBuf, u32)> {
        invented_dirs(mounts, Path::new(HOME), &host(modes))
    }

    /// The motivating case: `~/.gnupg` exists only because Docker fabricates it to hang the
    /// pubring bind on, so it must not land 0755 when the host says 0700.
    #[test]
    fn an_invented_ancestor_takes_the_hosts_mode() {
        assert_eq!(
            invented(&[bind("/home/u/.gnupg/pubring.kbx")], &[("/home/u/.gnupg", 0o40700)]),
            vec![(PathBuf::from("/home/u/.gnupg"), 0o40700)]
        );
    }

    /// `$HOME` is pinned to `mode=1777` by `run` on purpose; mirroring the host's mode onto
    /// it would quietly undo that, so it must never appear however the walk is written.
    #[test]
    fn home_itself_is_never_emitted() {
        let out = invented(
            &[tmpfs(HOME), bind("/home/u/.gnupg/pubring.kbx")],
            &[(HOME, 0o40700), ("/home/u/.gnupg", 0o40700)],
        );
        assert!(out.iter().all(|(p, _)| p != Path::new(HOME)), "{out:?}");
    }

    /// Outside `$HOME` the container's filesystem is the image plus the `/usr` mirror, not
    /// an empty tmpfs — a deliberate scope, so the gpg socket's `/run/user/$uid` is left be.
    #[test]
    fn a_destination_outside_home_yields_nothing() {
        assert!(
            invented(&[bind("/run/user/1000/gnupg/S.gpg-agent")], &[("/run/user/1000", 0o40700)])
                .is_empty()
        );
    }

    /// A bind's own destination arrives as the host's inode, mode included.
    #[test]
    fn an_ancestor_that_is_itself_a_bind_is_skipped() {
        assert!(
            invented(
                &[bind("/home/u/.config"), bind("/home/u/.config/opencode")],
                &[("/home/u/.config", 0o40700)]
            )
            .is_empty()
        );
    }

    /// The rule that "is it a mount destination" only approximates. `~/.config/gh` is not
    /// itself mounted, but it arrives *through* the `~/.config` bind — so it was never
    /// invented, already has the host's mode, and sits on a read-only mount besides.
    #[test]
    fn an_ancestor_reached_through_a_bind_is_skipped() {
        assert!(
            invented(
                &[bind("/home/u/.config"), bind("/home/u/.config/gh/hosts.yml")],
                &[("/home/u/.config", 0o40700), ("/home/u/.config/gh", 0o40700),]
            )
            .is_empty()
        );
    }

    /// The mirror image: a tmpfs supplies nothing, so a directory under one *is* invented.
    /// This is what stops a `hide` from hiding the rule as well as the contents.
    #[test]
    fn an_ancestor_reached_through_a_tmpfs_is_still_emitted() {
        assert_eq!(
            invented(
                &[tmpfs("/home/u/.config"), bind("/home/u/.config/gh/hosts.yml")],
                &[("/home/u/.config/gh", 0o40700)]
            ),
            vec![(PathBuf::from("/home/u/.config/gh"), 0o40700)]
        );
    }

    /// 0755 is what Docker makes it anyway, so emitting would be noise in `--dry-run`.
    #[test]
    fn an_ancestor_docker_would_get_right_is_skipped() {
        assert!(
            invented(&[bind("/home/u/.ssh/known_hosts")], &[("/home/u/.ssh", 0o40755)]).is_empty()
        );
    }

    #[test]
    fn an_unstattable_ancestor_is_skipped() {
        assert!(invented(&[bind("/home/u/.gnupg/pubring.kbx")], &[]).is_empty());
    }

    /// Two mounts sharing a chain must not emit it twice, and the output is shallowest-first
    /// so `--dry-run` reads in nesting order and diffs cleanly between runs.
    #[test]
    fn a_shared_chain_is_emitted_once_shallowest_first() {
        assert_eq!(
            invented(
                &[bind("/home/u/.local/bin/claude"), bind("/home/u/.local/share/claude")],
                &[
                    ("/home/u/.local", 0o40700),
                    ("/home/u/.local/bin", 0o40755),
                    ("/home/u/.local/share", 0o40700),
                ]
            ),
            vec![
                (PathBuf::from("/home/u/.local"), 0o40700),
                (PathBuf::from("/home/u/.local/share"), 0o40700),
            ]
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
