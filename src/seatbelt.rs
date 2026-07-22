//! SBPL profile generation for the macOS backend.
//!
//! The macOS sandbox is Seatbelt (`sandbox-exec`), not a container. Nothing is mirrored
//! because the process already *is* on the host — so everything `run.rs` does to
//! reconstruct a userland collapses, and what's left is the write policy. This module is
//! that policy: it turns the same `Mount` list the Linux path feeds to `-v` into SBPL.
//!
//! Deliberately platform-independent so it can be unit-tested off a Mac; only the
//! *execution* of the profile is `cfg`-gated.
//!
//! ## Rule ordering is load-bearing
//!
//! Seatbelt resolves same-operation rules **last-match-wins**, so emitting mounts
//! shallowest-first puts the deeper, more specific rule where it wins. That is exactly
//! what `mounts::sort_for_nesting` already produces for Docker, which is why the
//! precedence engine ports unchanged. Do not emit unsorted.
//!
//! Two traps, both measured (see `MACOS-BACKEND.md`):
//!
//! - **Paths must be canonical.** Seatbelt matches the *resolved* path, so a rule naming
//!   `/tmp/x` never fires — the real path is `/private/tmp/x`. `mounts::canonicalize` is
//!   realpath, so the mount table is already safe; keep it that way.
//! - **Never emit a narrower operation than `file-write*`.** A `(deny file-write-unlink)`
//!   is *not* overridden by a later `(allow file-write*)` — specific operation beats
//!   wildcard regardless of order — so a stray narrow deny would make files undeletable
//!   inside `--rw` regions with no ordering fix available.

use std::path::Path;

use crate::mounts::{Kind, Mount};

/// Device files and pty plumbing an ordinary shell needs before `(deny file-write*)`
/// stops breaking it. Without these, `echo > /dev/null` and `mktemp` fail — long before
/// any project tooling is involved.
///
/// The pty block is not optional despite looking like it: *inheriting* a tty works
/// without it, so a bare `lim` at a terminal looks fine, and then anything that
/// *allocates* one (tmux, node-pty, an agent spawning a shell) dies on `openpty`.
const PREAMBLE: &str = r#"; Everything is permitted except writes — the sandbox bounds what can be
; changed, not what can be seen or run. Reads, network, mach services and GUI
; access are all left alone (Murphy, not Machiavelli).
(allow default)
(deny file-write*)

; Device files a shell cannot work without.
(allow file-write* (literal "/dev/null"))
(allow file-write* (literal "/dev/zero"))
(allow file-write* (literal "/dev/dtracehelper"))
(allow file-write* (subpath "/dev/fd"))
(allow file-write* (regex #"^/dev/tty"))

; Pseudo-terminal allocation (tmux, node-pty, agents spawning shells).
(allow pseudo-tty)
(allow file-ioctl (literal "/dev/ptmx") (regex #"^/dev/ttys"))
(allow file-read* file-write* (literal "/dev/ptmx") (regex #"^/dev/ttys"))"#;

/// Build the SBPL profile for a run.
///
/// `mounts` must already be deduped and depth-sorted — see the ordering note above.
/// `tmpdir` should be the *resolved* temp dir (`/private/var/folders/…`).
pub fn profile(mounts: &[Mount], tmpdir: &Path) -> String {
    let mut s = String::from("(version 1)\n\n");
    s.push_str(PREAMBLE);

    s.push_str("\n\n; Temp dir.\n");
    s.push_str(&format!("(allow file-write* (subpath {}))\n", quote(tmpdir)));

    s.push_str("\n; Mount table — shallowest first, so nested rules override their parent.\n");
    for m in mounts {
        s.push_str(&rule(m));
        s.push('\n');
    }
    s
}

/// One mount as one SBPL rule.
///
/// Note `ro` emits an explicit **deny**, rather than being the no-op the design notes
/// first assumed. Under a `(deny file-write*)` base a top-level `--ro` is indeed
/// redundant — but a `--ro` *nested inside* a `--rw` is not, and must re-deny the hole.
/// Emitting unconditionally is both simpler and correct; the redundant case is harmless.
///
/// `hide` is the profile's **first read restriction** — everything else here is a write
/// policy under `(allow default)`. That makes `doctor`'s "reads are unrestricted" claim
/// conditional, which is why it now says *except paths declared `hide`*.
///
/// It also means `hide` diverges between the backends in kind, not just in strength:
/// Linux shadows the path with an empty *writable* tmpfs, so an app that recreates its
/// config on a missing dir just works; here the same app gets EPERM. Neither is wrong —
/// Seatbelt has no union mount to offer — but they are not the same behaviour, and code
/// that self-heals on one will error on the other.
///
/// Both operations named below are wildcards, so the "never narrower than `file-write*`"
/// warning above is satisfied: that warning is about *write* operations specifically, and
/// `file-read*` is a different operation class.
fn rule(m: &Mount) -> String {
    let p = quote(&m.path);
    match m.kind {
        Kind::Ro => format!("(deny file-write* (subpath {p}))"),
        Kind::Rw => format!("(allow file-write* (subpath {p}))"),
        // The mode a Linux hide carries is meaningless here: there is no shadow directory to
        // give a mode to, only a denial of the host's own.
        Kind::Hide(_) => format!("(deny file-read* file-write* (subpath {p}))"),
    }
}

/// SBPL string literal. Backslash first, or the escaping eats itself.
fn quote(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', r"\\").replace('"', r#"\""#);
    format!("\"{s}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mkprofile(mounts: &[Mount]) -> String {
        profile(mounts, Path::new("/private/var/folders/xx/T"))
    }

    #[test]
    fn rw_allows_and_ro_denies() {
        let p = mkprofile(&[Mount::rw("/a".into()), Mount::ro("/b".into())]);
        assert!(p.contains(r#"(allow file-write* (subpath "/a"))"#));
        assert!(p.contains(r#"(deny file-write* (subpath "/b"))"#));
    }

    /// The whole reason `sort_for_nesting` ports: the deeper rule must come later, because
    /// Seatbelt takes the last match. A `--ro` hole inside a `--rw` tree only works if the
    /// deny is emitted after the allow.
    #[test]
    fn nested_ro_hole_is_emitted_after_its_parent() {
        let mut m = vec![Mount::ro("/a/b/secret".into()), Mount::rw("/a".into())];
        crate::mounts::sort_for_nesting(&mut m);
        let p = mkprofile(&m);
        let parent = p.find(r#"(allow file-write* (subpath "/a"))"#).expect("parent rule");
        let child = p.find(r#"(deny file-write* (subpath "/a/b/secret"))"#).expect("child rule");
        assert!(parent < child, "parent must precede child or the hole never applies");
    }

    #[test]
    fn preamble_has_the_measured_essentials() {
        let p = mkprofile(&[]);
        for needed in [
            r#"(deny file-write*)"#,
            r#"(literal "/dev/null")"#,
            r#"(allow pseudo-tty)"#,
            r#"(regex #"^/dev/ttys")"#,
            r#"(subpath "/private/var/folders/xx/T")"#,
        ] {
            assert!(p.contains(needed), "profile missing {needed}\n{p}");
        }
    }

    /// `hide` is the only rule that restricts *reads*, and it must restrict writes too —
    /// an empty-but-writable hole would still let a process plant files where the host
    /// tree it is shadowing lives.
    #[test]
    fn hide_denies_both_reads_and_writes() {
        let p = mkprofile(&[Mount::hide("/a".into(), 0o755)]);
        assert!(p.contains(r#"(deny file-read* file-write* (subpath "/a"))"#), "got: {p}");
    }

    /// Same ordering guarantee as the nested-ro case: a `hide` inside a broad `ro` mount
    /// is the whole point of the mode, and Seatbelt takes the *last* matching rule.
    #[test]
    fn nested_hide_is_emitted_after_its_parent() {
        let mut m = vec![Mount::hide("/a/b/creds".into(), 0o700), Mount::ro("/a".into())];
        crate::mounts::sort_for_nesting(&mut m);
        let p = mkprofile(&m);
        let parent = p.find(r#"(deny file-write* (subpath "/a"))"#).expect("parent rule");
        let child = p.find(r#"(subpath "/a/b/creds")"#).expect("child rule");
        assert!(parent < child, "parent must precede child or the hole never applies");
    }

    /// Emitting anything narrower than `file-write*` would be unfixable by ordering.
    #[test]
    fn never_emits_a_narrow_write_operation() {
        let p = mkprofile(&[
            Mount::rw("/a".into()),
            Mount::ro("/b".into()),
            Mount::hide("/c".into(), 0o755),
        ]);
        for narrow in ["file-write-unlink", "file-write-create", "file-write-data"] {
            assert!(!p.contains(narrow), "profile must not name {narrow}");
        }
    }

    #[test]
    fn quotes_are_escaped() {
        let p = mkprofile(&[Mount::rw(PathBuf::from(r#"/a"b\c"#))]);
        assert!(p.contains(r#""/a\"b\\c""#), "got: {p}");
    }
}
