//! Per-project config: `.limes.local.toml`, found by walking up from the workspace.
//!
//! Some mounts belong to one project and nowhere else. Saying so in the global config puts
//! the answer a long way from the question and grows a file that is already carrying
//! machine-wide settings; saying it in a `make lim` target hides it from `lim exec`,
//! `lim status` and `policy.rs`, and loses it the moment you `cd` into a subdirectory.
//!
//! The file is **untracked by design** — `.local` in the name says so, and the paths inside
//! it are absolute host paths that only mean anything on this machine. `.limes.toml` is
//! deliberately unclaimed, left for a possible committed variant with stricter rules.
//!
//! **Every file found must be approved before it is obeyed** (`trust.rs`). The gate is not
//! ceremony: the workspace is mounted read-write, so without it a sandboxed process could
//! append a mount to its own project config and have the next `lim` honor it. A useful
//! side effect is that the gate is a *tripwire* — an approval failure nobody caused by hand
//! means something inside a sandbox reached for its own policy.
//!
//! ## Walking up
//!
//! Every `.limes.local.toml` from the workspace up to (not including) `$HOME` applies,
//! **shallowest-first**, so one file at `~/code/prd/git-kiekert` covers every repo beneath
//! it — including ones cloned next month — and a per-repo file refines rather than replaces
//! it. It is also what makes `cd src && lim` behave: the file at the repo root is still
//! found, where stopping at the workspace directory would silently drop its mounts.
//!
//! A workspace outside `$HOME` simply never meets the ceiling and walks to `/`, which needs
//! no second rule.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use crate::config::{self, MountSpec, Resolved, ToolchainSpec};
use crate::trust::{self, Status};

/// The filename limes looks for. See the module docs on why not `.limes.toml`.
pub const FILE_NAME: &str = ".limes.local.toml";

/// What a project file may say.
///
/// A deliberately smaller surface than `config::Config`, not a reuse of it: `data_root`,
/// `host_network`, `gpu` and `[forward]` are daemon- and credential-level decisions that
/// belong to the machine, not to whichever directory you happen to be standing in.
/// `deny_unknown_fields` turns writing one here into an error naming the file, rather than
/// a setting that silently never happens — the same reasoning `Config` documents.
///
/// The two tables it *does* carry reuse config's spec types verbatim, so `hide`,
/// `link = "parent"`, `optional` and the toolchain recipes behave identically in both.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Local {
    #[serde(default)]
    mounts: HashMap<String, MountSpec>,
    #[serde(default)]
    toolchains: HashMap<String, ToolchainSpec>,
}

impl Local {
    /// Resolve to mounts and symlinks, with relative paths taken against `dir` — the
    /// directory the file itself sits in, not the cwd.
    fn resolve(&self, dir: &Path) -> Result<Resolved> {
        config::resolve_specs(&self.mounts, &self.toolchains, Some(dir))
    }

    /// What the file asks for, as `(subject, mode)` pairs, sorted.
    ///
    /// Rendered from the *spec* rather than from resolved mounts on purpose: this is what
    /// `lim trust add` prints before approving, and what a changed file is diffed on, so it
    /// has to work for an entry whose path does not exist on this host — which is exactly
    /// the case when a recorded old version names something since deleted.
    fn entries(&self, dir: &Path) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .mounts
            .iter()
            .map(|(raw, spec)| (display_path(raw, dir), spec.mode().as_str().to_string()))
            .chain(
                self.toolchains
                    .iter()
                    .map(|(n, s)| (format!("toolchain {n}"), s.mode().as_str().to_string())),
            )
            .collect();
        out.sort();
        out
    }
}

/// A path as the user would recognise it: expanded when that succeeds, and made absolute
/// against the file's own directory. Falls back to the raw text, since this is only ever
/// display — an unexpandable path is a complaint for `resolve` to make, with its context.
fn display_path(raw: &str, dir: &Path) -> String {
    let Ok(expanded) = shellexpand::full(raw) else { return raw.to_string() };
    let p = PathBuf::from(expanded.as_ref());
    if p.is_relative() { dir.join(p).display().to_string() } else { p.display().to_string() }
}

/// One project file on disk, with the store's verdict on it.
pub struct Found {
    pub path: PathBuf,
    /// Read **once**, and used to both compare against the record and parse. Reading twice
    /// would leave a window in which the bytes approved and the bytes obeyed differ.
    pub bytes: Vec<u8>,
    pub status: Status,
}

impl Found {
    /// The directory the file sits in — the base for its relative paths.
    fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("/"))
    }
}

/// Every `.limes.local.toml` from `workspace` up to (not including) `$HOME`, shallowest-first.
///
/// `take_while` rather than an explicit ceiling check: a workspace with no `$HOME` ancestor
/// never matches, so it walks to `/` without needing a second rule for that case.
pub fn discover(home: &Path, workspace: &Path) -> Vec<PathBuf> {
    // The cwd is `getcwd(3)` and so already kernel-resolved, while `$HOME` need not be.
    // Comparing the two unresolved would miss the ceiling on a symlinked home — the same
    // asymmetry `run::check_workspace` handles.
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let mut found: Vec<PathBuf> = workspace
        .ancestors()
        .take_while(|p| *p != home)
        .map(|d| d.join(FILE_NAME))
        .filter(|f| f.is_file())
        .collect();
    // `ancestors` yields deepest-first; the precedence chain wants the opposite, so that a
    // per-repo file lands after — and therefore wins over — the shared one above it.
    found.reverse();
    found
}

/// Discover the project files and ask the store about each. No parsing, no policy.
///
/// Shared by `load` and by `lim trust`, so the set of files the two talk about can never
/// disagree.
pub fn survey(store: &Path, home: &Path, workspace: &Path) -> Result<Vec<Found>> {
    discover(home, workspace)
        .into_iter()
        .map(|path| {
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let status = trust::check(store, &path, &bytes);
            Ok(Found { path, bytes, status })
        })
        .collect()
}

/// The project files' contribution to the mount table, or a refusal naming what to approve.
///
/// Nothing is resolved until *everything* is trusted: a run that honored the approved files
/// and skipped the rest would be a policy nobody wrote down, and the sandbox it produced
/// would be reproducible only by knowing which files were approved at the time.
pub fn load(store: &Path, home: &Path, workspace: &Path) -> Result<Resolved> {
    let found = survey(store, home, workspace)?;
    if let Some(report) = refusal(&found) {
        bail!(report);
    }

    let mut out = Resolved { mounts: Vec::new(), symlinks: Vec::new() };
    for f in &found {
        // Name the file. `resolve_specs`' errors are phrased for the global config, where
        // there is only one file it could have meant; here there may be several, in
        // directories the reader is not currently standing in.
        let resolved = parse(&f.bytes, &f.path)?
            .resolve(f.dir())
            .with_context(|| format!("in {}", f.path.display()))?;
        out.mounts.extend(resolved.mounts);
        out.symlinks.extend(resolved.symlinks);
    }
    Ok(out)
}

/// Parse project-file bytes, naming the file and — for the keys deliberately not accepted
/// here — why. Serde's bare "unknown field" would be true but unhelpful: the reader's next
/// question is always whether the key is misspelled or merely out of place.
pub fn parse(bytes: &[u8], path: &Path) -> Result<Local> {
    let text = std::str::from_utf8(bytes)
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
    toml::from_str::<Local>(text).map_err(|e| {
        let hint = ["forward", "data_root", "host_network", "gpu", "hostname_suffix"]
            .iter()
            .find(|k| e.message().contains(**k))
            .map(|k| {
                format!(
                    "\n  `{k}` is a machine-wide setting and is only accepted in \
                     ~/.config/limes/config.toml — a project cannot decide it"
                )
            })
            .unwrap_or_default();
        anyhow::anyhow!("parsing {}: {e}{hint}", path.display())
    })
}

/// The refusal text when any file is unapproved, or `None` when every one is trusted.
fn refusal(found: &[Found]) -> Option<String> {
    if found.iter().all(|f| f.status == Status::Trusted) {
        return None;
    }

    let mut s = String::from("refusing to run: an unapproved project file is in effect\n");
    for f in found {
        match &f.status {
            Status::Trusted => {}
            Status::Untrusted => {
                s.push_str(&format!("\n  {} — never approved\n", f.path.display()));
                s.push_str(&grants(f));
            }
            Status::Changed(old) => {
                s.push_str(&format!("\n  {} — changed since it was approved\n", f.path.display()));
                s.push_str(&delta(f, old));
            }
        }
    }
    // Naming the command matters more than it looks: a refusal that does not say what to run
    // is the kind people route around, and the way around this one is to stop using project
    // files at all.
    s.push_str("\nreview the above, then run `lim trust add` to approve it");
    Some(s)
}

/// What a file would grant, one indented line each.
fn grants(f: &Found) -> String {
    let Ok(local) = parse(&f.bytes, &f.path) else {
        return "      (does not parse — `lim trust add` will report why)\n".into();
    };
    let entries = local.entries(f.dir());
    if entries.is_empty() {
        return "      (grants nothing)\n".into();
    }
    entries.iter().map(|(subject, mode)| format!("      + {subject}  {mode}\n")).collect()
}

/// What changed between the approved bytes and the current ones.
///
/// Diffed on the *specs*, not on resolved mounts and not on raw text: the specs are what the
/// approval was really about, and comparing them needs no filesystem, so a recorded entry
/// naming a path since deleted still produces a readable answer instead of an error.
fn delta(f: &Found, old: &[u8]) -> String {
    let (Ok(before), Ok(after)) = (parse(old, &f.path), parse(&f.bytes, &f.path)) else {
        return "      (one of the two versions does not parse; showing nothing)\n".into();
    };
    let (before, after) = (before.entries(f.dir()), after.entries(f.dir()));

    let mut s = String::new();
    for e in &before {
        if !after.contains(e) {
            s.push_str(&format!("      - {}  {}\n", e.0, e.1));
        }
    }
    for e in &after {
        if !before.contains(e) {
            s.push_str(&format!("      + {}  {}\n", e.0, e.1));
        }
    }
    // Equal specs, different bytes: a comment or whitespace edit. Say so, rather than
    // printing an empty diff under a heading that promised one.
    if s.is_empty() {
        "      (no change to what it grants — comments or formatting)\n".into()
    } else {
        s
    }
}

/// The lines `lim trust add` prints before approving a file.
pub fn summary(f: &Found) -> String {
    grants(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch tree of this test's own, so nothing depends on the machine's real layout.
    fn tree(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("limes-local-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp tree");
        d
    }

    fn write(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(FILE_NAME), body).unwrap();
    }

    #[test]
    fn discovery_is_shallowest_first() {
        let root = tree("order");
        let deep = root.join("a/b");
        write(&root.join("a"), "[mounts]\n");
        write(&deep, "[mounts]\n");

        let found = discover(&root, &deep);
        assert_eq!(
            found,
            vec![root.join("a").join(FILE_NAME), deep.join(FILE_NAME)],
            "a per-repo file must land after the shared one above it, so it wins"
        );
    }

    /// The ceiling: a file in `$HOME` itself is `config.toml`'s job, not a project's.
    #[test]
    fn the_walk_stops_below_home() {
        let home = tree("ceiling");
        let ws = home.join("code/proj");
        write(&home, "[mounts]\n");
        write(&ws, "[mounts]\n");

        assert_eq!(discover(&home, &ws), vec![ws.join(FILE_NAME)]);
    }

    /// A workspace with no `$HOME` ancestor must not walk forever looking for a ceiling it
    /// will never meet — it simply exhausts at `/`.
    #[test]
    fn a_workspace_outside_home_walks_to_the_root() {
        let root = tree("outside");
        let ws = root.join("srv/work");
        write(&ws, "[mounts]\n");

        let elsewhere = tree("outside-home");
        assert_eq!(discover(&elsewhere, &ws), vec![ws.join(FILE_NAME)]);
    }

    #[test]
    fn machine_wide_keys_are_refused_with_a_reason() {
        let err = parse(b"[forward]\ngpg = false\n", Path::new("/p/.limes.local.toml"))
            .map(|_| ())
            .expect_err("[forward] must not be accepted in a project file");
        let msg = err.to_string();
        assert!(
            msg.contains("machine-wide"),
            "the error must say why, not just \"unknown\": {msg}"
        );
        assert!(msg.contains("/p/.limes.local.toml"), "and must name the file: {msg}");
    }

    #[test]
    fn data_root_is_refused_too() {
        assert!(parse(b"data_root = \"/x\"\n", Path::new("/p/.limes.local.toml")).is_err());
    }

    /// The non-obvious semantic the template has to teach: relative means *next to this
    /// file*, not next to the cwd, which varies with the subdirectory `lim` ran from.
    #[test]
    fn a_relative_path_resolves_against_the_files_own_directory() {
        let local =
            parse(b"[mounts]\n\"../sibling\" = \"rw\"\n", Path::new("/p/q/.limes.local.toml"))
                .unwrap();
        let entries = local.entries(Path::new("/p/q"));
        assert_eq!(entries, vec![("/p/q/../sibling".to_string(), "rw".to_string())]);
    }

    #[test]
    fn an_unapproved_file_refuses_and_names_the_command() {
        let root = tree("refuse");
        write(&root, "[mounts]\n\"/tmp\" = \"ro\"\n");
        let store = root.join("store");

        let err = load(&store, &root.join("nonexistent-home"), &root)
            .map(|_| ())
            .expect_err("an unapproved file must refuse");
        let msg = err.to_string();
        assert!(msg.contains("never approved"), "{msg}");
        assert!(msg.contains("lim trust add"), "the refusal must say what to run: {msg}");
        assert!(msg.contains("+ /tmp  ro"), "and must show what it would grant: {msg}");
    }

    #[test]
    fn approving_it_lets_the_run_proceed() {
        let root = tree("approve");
        write(&root, "[mounts]\n\"/tmp\" = \"ro\"\n");
        let store = root.join("store");
        let file = root.join(FILE_NAME);
        trust::add(&store, &file, &std::fs::read(&file).unwrap()).unwrap();

        let resolved = load(&store, &root.join("nonexistent-home"), &root).expect("trusted");
        assert_eq!(resolved.mounts, vec![crate::mounts::Mount::ro("/tmp".into())]);
    }

    /// The tripwire case: bytes that differ from the approved ones refuse, and the refusal
    /// shows the delta rather than merely asserting one exists.
    #[test]
    fn an_edit_refuses_and_shows_the_delta() {
        let root = tree("edit");
        write(&root, "[mounts]\n\"/tmp\" = \"ro\"\n");
        let store = root.join("store");
        let file = root.join(FILE_NAME);
        trust::add(&store, &file, &std::fs::read(&file).unwrap()).unwrap();

        write(&root, "[mounts]\n\"/tmp\" = \"rw\"\n");
        let msg = load(&store, &root.join("nonexistent-home"), &root)
            .map(|_| ())
            .expect_err("an edited file must refuse")
            .to_string();
        assert!(msg.contains("changed since"), "{msg}");
        assert!(msg.contains("- /tmp  ro"), "the old grant must show as removed: {msg}");
        assert!(msg.contains("+ /tmp  rw"), "the new one as added: {msg}");
    }

    /// A comment-only edit still refuses — the approval is on bytes — but must not print an
    /// empty diff under a heading that promised one.
    #[test]
    fn a_cosmetic_edit_says_so_rather_than_showing_an_empty_diff() {
        let root = tree("cosmetic");
        write(&root, "[mounts]\n\"/tmp\" = \"ro\"\n");
        let store = root.join("store");
        let file = root.join(FILE_NAME);
        trust::add(&store, &file, &std::fs::read(&file).unwrap()).unwrap();

        write(&root, "# a note\n[mounts]\n\"/tmp\" = \"ro\"\n");
        let msg = load(&store, &root.join("nonexistent-home"), &root)
            .map(|_| ())
            .expect_err("changed bytes refuse even when the policy is identical")
            .to_string();
        assert!(msg.contains("comments or formatting"), "{msg}");
    }

    /// Deeper file last means deeper file wins, once `run::dedupe` collapses the pair.
    #[test]
    fn a_nested_file_is_resolved_after_the_one_above_it() {
        let root = tree("nesting");
        let deep = root.join("proj");
        write(&root, "[mounts]\n\"/tmp\" = \"ro\"\n");
        write(&deep, "[mounts]\n\"/tmp\" = \"rw\"\n");
        let store = root.join("store");
        for f in [root.join(FILE_NAME), deep.join(FILE_NAME)] {
            trust::add(&store, &f, &std::fs::read(&f).unwrap()).unwrap();
        }

        let resolved = load(&store, &root.join("nonexistent-home"), &deep).unwrap();
        assert_eq!(
            resolved.mounts,
            vec![crate::mounts::Mount::ro("/tmp".into()), crate::mounts::Mount::rw("/tmp".into())],
            "shallowest-first, so dedupe's last-wins gives the nested file the say"
        );
    }
}
