//! The approval store for `.limes.local.toml` project files.
//!
//! A project file lives in the workspace — the one tree limes mounts **read-write** — so a
//! sandboxed process can write its own next-run policy. Appending `"~/.ssh" = "ro"` to it
//! and waiting for the next `lim` is not a Machiavelli attack; it is exactly the over-eager
//! agent limes exists to confine, and the same file arrives pre-populated in any repo you
//! clone. So a project file is obeyed only after an explicit approval recorded *outside* the
//! sandbox's reach, and any edit revokes it until re-approved. direnv gates `.envrc` the
//! same way, and for the same reason.
//!
//! Two files per entry under `Context::trust_dir()`, neither carrying any framing:
//!
//! ```text
//! <key>.toml    the approved bytes, verbatim
//! <key>.path    the absolute path they were approved at, verbatim
//! ```
//!
//! Storing the **content** rather than a digest of it is the point: a digest can only say
//! "this changed", and the refusal needs to say *what* changed. That the record is a byte
//! copy also makes the comparison `==` on whole files, with nothing to parse, strip or
//! escape — a header line inside one record would have to be stripped before comparing, and
//! would break outright on a path containing a newline, which Linux permits.
//!
//! **The key is a lookup key, not a security primitive.** All the security is in that byte
//! equality, which is why a hand-rolled FNV-1a is enough and no hashing crate is pulled in.
//! A collision would put two paths on one record; `<key>.path` catches that and the entry
//! reads as untrusted, which is the direction to fail.
//!
//! The store root is a parameter rather than read from `Context` so the tests can point at a
//! temp dir. Nothing here is platform-specific — it is file bytes and string work — so it
//! compiles and tests on both backends, like `config` and `forward`.
//!
//! The second half of the file is `lim trust` itself: `init`, `add`, `list`, `revoke`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use crate::context::Context;
use crate::local;
use crate::{IgnoreTarget, TrustAction};

/// What the store knows about one project file.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// Approved, and unchanged since.
    Trusted,
    /// Approved once, but the file has been edited. Carries the bytes that *were* approved,
    /// so the refusal can show the delta rather than merely asserting one exists.
    Changed(Vec<u8>),
    /// Never approved — or approved so incompletely that the record cannot be trusted (see
    /// `record`, which treats every doubt as this).
    Untrusted,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a over the path's raw bytes, hex. Total, stable across runs and machines, and
/// fixed-length, which is all the store asks of it — see the module docs on why a
/// cryptographic hash would be answering a question nobody is asking.
pub fn key(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut h = FNV_OFFSET;
    for b in path.as_os_str().as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("{h:016x}")
}

/// The two record paths for `path`: content, then the path sidecar.
fn record_paths(store: &Path, path: &Path) -> (PathBuf, PathBuf) {
    let k = key(path);
    (store.join(format!("{k}.toml")), store.join(format!("{k}.path")))
}

/// The approved bytes for `path`, if the store holds a complete and matching record.
///
/// Every failure — no record, an unreadable one, a half-written one, a sidecar naming some
/// other file — collapses to `None`, i.e. not approved. There is no case where being unsure
/// should resolve towards granting a mount.
fn record(store: &Path, path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let (content_file, path_file) = record_paths(store, path);
    let recorded_path = std::fs::read(&path_file).ok()?;
    // A sidecar naming a different file means the two paths collided on one key. Vanishingly
    // unlikely, and caught rather than honored.
    if recorded_path.as_slice() != path.as_os_str().as_bytes() {
        return None;
    }
    std::fs::read(&content_file).ok()
}

/// Compare the file's current bytes against what was approved.
///
/// `current` is passed in rather than read here because the caller must read the file
/// *once* and use those same bytes to both compare and parse — reading twice would leave a
/// window where the approved bytes and the parsed bytes differ.
pub fn check(store: &Path, path: &Path, current: &[u8]) -> Status {
    match record(store, path) {
        None => Status::Untrusted,
        Some(approved) if approved == current => Status::Trusted,
        Some(approved) => Status::Changed(approved),
    }
}

/// Approve `bytes` as the content of `path`.
///
/// The content record is written before the sidecar, so an interrupted `add` leaves a
/// `.toml` with no `.path`: `record` reads that as untrusted, the next `lim` refuses, and
/// the next `lim trust add` overwrites it. The reverse order would instead leave an entry
/// that `list` shows with no content behind it.
pub fn add(store: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    std::fs::create_dir_all(store)
        .with_context(|| format!("creating the trust store at {}", store.display()))?;
    let (content_file, path_file) = record_paths(store, path);
    write_atomic(&content_file, bytes)?;
    write_atomic(&path_file, path.as_os_str().as_bytes())
}

/// Withdraw approval for `path`. Absent records are not an error — the post-condition is
/// "this path is not approved", and it already held.
pub fn revoke(store: &Path, path: &Path) -> Result<()> {
    let (content_file, path_file) = record_paths(store, path);
    for f in [path_file, content_file] {
        match std::fs::remove_file(&f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", f.display())),
        }
    }
    Ok(())
}

/// Every complete record in the store, as (path, approved bytes), path-sorted.
///
/// This is what the `.path` sidecar is for: without it the store is a directory of opaque
/// keys, and "what have I approved anywhere?" — the question you ask before revoking
/// something — has no answer. Incomplete entries are skipped rather than reported, since
/// they are exactly the ones that grant nothing.
pub fn list(store: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let entries = match std::fs::read_dir(store) {
        Ok(e) => e,
        // An absent store is an empty one, not a failure: nothing has been approved yet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", store.display())),
    };

    let mut out = Vec::new();
    for entry in entries.filter_map(std::result::Result::ok) {
        let p = entry.path();
        if p.extension().is_some_and(|x| x == "path") {
            let Ok(raw) = std::fs::read(&p) else { continue };
            let path = PathBuf::from(os_string(&raw));
            // Round-trip through `record` rather than reading the sibling directly, so the
            // listing can never disagree with what `check` would decide about the same entry.
            if let Some(bytes) = record(store, &path) {
                out.push((path, bytes));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn os_string(raw: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(raw.to_vec())
}

/// Write via a temp file and rename, so a record is never observed half-written — a reader
/// racing a re-approval sees either the old bytes or the new ones, never a prefix of one.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("installing {}", path.display()))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
}

// ── `lim trust` ─────────────────────────────────────────────────────────────────────────

/// The starter file `lim trust init` writes. A real file rather than a string literal, the
/// way `image/Dockerfile` and the vendored launcher are, so it stays lintable and diffable.
const TEMPLATE: &str = include_str!("../limes.local.toml.template");

pub fn command(ctx: &Context, action: TrustAction) -> Result<()> {
    let store = ctx.trust_dir();
    let cwd = std::env::current_dir()?;
    match action {
        TrustAction::Init => init(&cwd),
        TrustAction::Add { ignore } => cmd_add(&store, ctx, &cwd, ignore),
        TrustAction::List { all } => cmd_list(&store, ctx, &cwd, all),
        TrustAction::Revoke { paths } => cmd_revoke(&store, ctx, &cwd, paths),
    }
}

/// Write the template — and pointedly do *not* approve it. "Nothing is trusted except by
/// `lim trust add`" is a rule with no exceptions, and an exception here is exactly how
/// someone ends up believing the gate is advisory.
fn init(cwd: &Path) -> Result<()> {
    let path = cwd.join(local::FILE_NAME);
    if path.exists() {
        bail!("{} already exists — edit it, then run `lim trust add`", path.display());
    }
    std::fs::write(&path, TEMPLATE).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}", path.display());
    println!("edit it, then run `lim trust add` to approve it");
    Ok(())
}

fn cmd_add(store: &Path, ctx: &Context, cwd: &Path, ignore: Option<IgnoreTarget>) -> Result<()> {
    let found = local::survey(store, &ctx.home, cwd)?;
    if found.is_empty() {
        bail!(
            "no {} found here or in any parent directory — `lim trust init` writes one",
            local::FILE_NAME
        );
    }

    let mut approved = 0;
    for f in &found {
        if f.status == Status::Trusted {
            println!("already approved  {}", f.path.display());
            continue;
        }
        println!("\n{}", f.path.display());
        print!("{}", local::summary(f));
        add(store, &f.path, &f.bytes)?;
        approved += 1;
    }
    if approved == 0 {
        return Ok(());
    }
    println!("\napproved {approved} file(s)");

    // Offered only after the approval is on disk, and reported separately, so a Ctrl-C at
    // the prompt below can never leave any doubt about whether the thing you came for
    // happened.
    offer_ignore(cwd, ignore)
}

fn cmd_list(store: &Path, ctx: &Context, cwd: &Path, all: bool) -> Result<()> {
    if all {
        let records = list(store)?;
        if records.is_empty() {
            println!("nothing approved (store: {})", store.display());
            return Ok(());
        }
        for (path, _) in records {
            // A record whose file is gone grants nothing, but it is still clutter, and the
            // only way to see it is here — `lim trust revoke <path>` removes it.
            let gone = if path.exists() { "" } else { "  (file gone)" };
            println!("{}{gone}", path.display());
        }
        return Ok(());
    }

    let found = local::survey(store, &ctx.home, cwd)?;
    if found.is_empty() {
        println!("no {} in effect here", local::FILE_NAME);
        return Ok(());
    }
    for f in &found {
        let state = match f.status {
            Status::Trusted => "approved",
            Status::Changed(_) => "changed",
            Status::Untrusted => "unapproved",
        };
        println!("  {state:<10}  {}", f.path.display());
    }
    // One trailing line rather than the instruction repeated in every row: the column stays
    // scannable, and the paths — the part you are actually reading — stay aligned.
    if found.iter().any(|f| f.status != Status::Trusted) {
        println!("\nrun `lim trust add` to approve the above");
    }
    Ok(())
}

fn cmd_revoke(store: &Path, ctx: &Context, cwd: &Path, paths: Vec<PathBuf>) -> Result<()> {
    // Named paths are taken as given — that is the only way to clear a record whose file has
    // since been deleted, which discovery by definition cannot find.
    let targets: Vec<PathBuf> = if paths.is_empty() {
        local::discover(&ctx.home, cwd)
    } else {
        paths.into_iter().map(|p| absolutize(cwd, &p)).collect()
    };
    if targets.is_empty() {
        println!("no {} in effect here", local::FILE_NAME);
        return Ok(());
    }
    for path in targets {
        revoke(store, &path)?;
        println!("revoked {}", path.display());
    }
    Ok(())
}

fn absolutize(cwd: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() { p.to_path_buf() } else { cwd.join(p) }
}

// ── the ignore rule ─────────────────────────────────────────────────────────────────────

/// Offer to teach git to ignore `.limes.local.toml`.
///
/// Skipped entirely when it would be moot — no repo, or a rule already covering the file,
/// which is every repo after the first if `global` was chosen once. **`lim trust add` never
/// depends on a tty**; only this step does, and without one it degrades to a printed hint,
/// so `ssh host lim trust add` still works.
fn offer_ignore(cwd: &Path, choice: Option<IgnoreTarget>) -> Result<()> {
    let Some(top) = git_toplevel(cwd) else { return Ok(()) };
    if already_ignored(cwd) {
        return Ok(());
    }

    let choice = match choice {
        Some(c) => c,
        None if is_tty() => prompt(&top)?,
        None => {
            println!(
                "\nnote: {} is not ignored by git here.\n      \
                 `lim trust add --ignore global|gitignore|exclude` can fix that.",
                local::FILE_NAME
            );
            return Ok(());
        }
    };

    let file = match choice {
        IgnoreTarget::None => return Ok(()),
        IgnoreTarget::Global => global_excludes_file()?,
        IgnoreTarget::Gitignore => top.join(".gitignore"),
        IgnoreTarget::Exclude => top.join(".git/info/exclude"),
    };
    append_line(&file, local::FILE_NAME)?;
    // Naming the file is the point, not politeness: `.gitignore` and a dotfiles-managed
    // global ignore are both tracked somewhere, so this just made some repo dirty.
    println!("added `{}` to {}", local::FILE_NAME, file.display());
    Ok(())
}

fn prompt(top: &Path) -> Result<IgnoreTarget> {
    println!("\n{} is not ignored by git. Add it to:", local::FILE_NAME);
    println!("  1) core.excludesFile      every repo on this machine");
    println!("  2) .gitignore             this repo, shared with everyone who clones it");
    println!("  3) .git/info/exclude      this repo, only for you");
    println!("  4) nothing                ({} stays visible to git)", top.display());
    print!("choice [1-4, default 4]: ");
    std::io::stdout().flush().ok();

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(match line.trim() {
        "1" => IgnoreTarget::Global,
        "2" => IgnoreTarget::Gitignore,
        "3" => IgnoreTarget::Exclude,
        _ => IgnoreTarget::None,
    })
}

fn is_tty() -> bool {
    // SAFETY: isatty on a constant fd has no preconditions and no side effects.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

fn git(cwd: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git").current_dir(cwd).args(args).output().ok()
}

fn git_toplevel(cwd: &Path) -> Option<PathBuf> {
    let out = git(cwd, &["rev-parse", "--show-toplevel"])?;
    out.status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

fn already_ignored(cwd: &Path) -> bool {
    git(cwd, &["check-ignore", "-q", local::FILE_NAME]).is_some_and(|o| o.status.success())
}

/// Where git's machine-wide ignore file lives. Asked rather than assumed: `core.excludesFile`
/// may well point somewhere other than the XDG default, and appending to the wrong file
/// would look like it worked.
fn global_excludes_file() -> Result<PathBuf> {
    if let Some(out) = git(Path::new("."), &["config", "--get", "core.excludesFile"])
        && out.status.success()
    {
        let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !raw.is_empty() {
            let expanded = shellexpand::full(&raw)
                .with_context(|| format!("expanding core.excludesFile `{raw}`"))?;
            return Ok(PathBuf::from(expanded.as_ref()));
        }
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .context("neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(base.join("git/ignore"))
}

/// Append `line` unless the file already has it verbatim, creating the file and its parents.
fn append_line(file: &Path, line: &str) -> Result<()> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .with_context(|| format!("opening {}", file.display()))?;
    // A file that does not end in a newline would otherwise get our rule glued onto its last
    // line, silently changing that rule as well as failing to add ours.
    let sep = if existing.is_empty() || existing.ends_with('\n') { "" } else { "\n" };
    writeln!(f, "{sep}{line}").with_context(|| format!("appending to {}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store of this test's own, so the suite never touches the real one and parallel
    /// tests never touch each other's.
    fn store(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("limes-trust-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp store");
        dir
    }

    #[test]
    fn the_key_is_stable_and_path_specific() {
        let a = Path::new("/home/u/p/.limes.local.toml");
        assert_eq!(key(a), key(a), "the same path must always key the same record");
        assert_ne!(key(a), key(Path::new("/home/u/q/.limes.local.toml")));
    }

    #[test]
    fn an_unknown_file_is_untrusted() {
        let s = store("unknown");
        assert_eq!(check(&s, Path::new("/home/u/p/.limes.local.toml"), b"x"), Status::Untrusted);
    }

    #[test]
    fn approved_bytes_read_back_as_trusted() {
        let s = store("roundtrip");
        let p = Path::new("/home/u/p/.limes.local.toml");
        add(&s, p, b"[mounts]\n").unwrap();
        assert_eq!(check(&s, p, b"[mounts]\n"), Status::Trusted);
    }

    /// The whole point of storing content rather than a digest: the refusal gets the bytes
    /// it needs to say *what* changed.
    #[test]
    fn an_edit_reads_as_changed_and_carries_the_old_bytes() {
        let s = store("changed");
        let p = Path::new("/home/u/p/.limes.local.toml");
        add(&s, p, b"[mounts]\n").unwrap();
        assert_eq!(
            check(&s, p, b"[mounts]\n\"/x\" = \"rw\"\n"),
            Status::Changed(b"[mounts]\n".into())
        );
    }

    /// An `add` interrupted between the two writes leaves a content record with no sidecar.
    /// That must read as untrusted — the failure direction has to be towards refusing.
    #[test]
    fn a_record_without_its_sidecar_is_untrusted() {
        let s = store("orphan");
        let p = Path::new("/home/u/p/.limes.local.toml");
        add(&s, p, b"[mounts]\n").unwrap();
        std::fs::remove_file(record_paths(&s, p).1).unwrap();
        assert_eq!(check(&s, p, b"[mounts]\n"), Status::Untrusted);
    }

    /// The sidecar's other job: a key shared by two paths must not let one path's approval
    /// stand in for the other's.
    #[test]
    fn a_sidecar_naming_another_file_is_untrusted() {
        let s = store("collision");
        let p = Path::new("/home/u/p/.limes.local.toml");
        add(&s, p, b"[mounts]\n").unwrap();
        std::fs::write(record_paths(&s, p).1, "/home/u/elsewhere/.limes.local.toml").unwrap();
        assert_eq!(check(&s, p, b"[mounts]\n"), Status::Untrusted);
    }

    #[test]
    fn revoke_withdraws_approval_and_tolerates_absence() {
        let s = store("revoke");
        let p = Path::new("/home/u/p/.limes.local.toml");
        add(&s, p, b"[mounts]\n").unwrap();
        revoke(&s, p).unwrap();
        assert_eq!(check(&s, p, b"[mounts]\n"), Status::Untrusted);
        revoke(&s, p).expect("revoking an unapproved path is a no-op, not an error");
    }

    #[test]
    fn list_reports_complete_records_only() {
        let s = store("list");
        let good = Path::new("/home/u/a/.limes.local.toml");
        let half = Path::new("/home/u/b/.limes.local.toml");
        add(&s, good, b"a\n").unwrap();
        add(&s, half, b"b\n").unwrap();
        std::fs::remove_file(record_paths(&s, half).0).unwrap();

        let listed = list(&s).unwrap();
        assert_eq!(listed, vec![(good.to_path_buf(), b"a\n".to_vec())]);
    }

    /// A file not ending in a newline would otherwise get the rule glued onto its last line,
    /// silently changing that rule as well as failing to add ours.
    #[test]
    fn append_line_does_not_glue_onto_an_unterminated_last_line() {
        let dir = store("append");
        let f = dir.join("ignore");
        std::fs::write(&f, "*.o").unwrap();
        append_line(&f, ".limes.local.toml").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "*.o\n.limes.local.toml\n");
    }

    #[test]
    fn append_line_is_idempotent_and_creates_missing_parents() {
        let dir = store("append-twice");
        let f = dir.join("nested/deeper/ignore");
        append_line(&f, ".limes.local.toml").unwrap();
        append_line(&f, ".limes.local.toml").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), ".limes.local.toml\n");
    }

    #[test]
    fn listing_an_absent_store_is_empty_not_an_error() {
        let missing =
            std::env::temp_dir().join(format!("limes-trust-{}-absent", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        assert!(list(&missing).unwrap().is_empty());
    }
}
