//! Per-machine config: `~/.config/limes/config.toml` plus `config.d/*.toml` drop-ins.
//!
//! Standing default mounts, path-as-key so TOML's unique-key rule dedups for free.
//! `config.toml` is hand-written and unmanaged (like `~/.gitconfig`); `config.d/` holds
//! whole files owned by tools/installers (e.g. dotfiles ships one). Both are merged, with
//! `config.toml` winning on a key collision.
//!
//! ```toml
//! [mounts]
//! "/storage"             = "ro"                          # shorthand
//! "~/scratch"            = { mode = "rw" }
//! "~/.zshrc"             = { mode = "ro", link = "parent" }   # recreate the symlink,
//!                                                             # mount its target's dir
//! "~/.zshrc.local"       = { mode = "ro", optional = true }   # skip if absent
//! "~/.config/gh"         = "hide"                             # empty inside; a hole in
//!                                                             # a broader mount above
//!
//! [forward]
//! gpg = false                                                 # never forward gpg here
//! ```
//!
//! `[forward]` carries standing on/off switches for the credential and socket forwards,
//! for the same reason `[mounts]` exists: a preference that holds for every run on this
//! machine belongs in a file, not in a flag you retype each time.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use serde::Deserialize;

use crate::context::Context;
use crate::mounts::{self, Mount};

/// `deny_unknown_fields` so a key in the wrong place is an error rather than a silence.
/// Serde's default is to ignore what it doesn't recognise, which turns a mount written at
/// the top level instead of under `[mounts]` -- or a typo in `data_root` -- into a setting
/// that simply never happens, with limes reporting nothing at all.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    mounts: HashMap<String, MountSpec>,
    #[serde(default)]
    forward: Forward,
    /// Standing suffix for the sandbox hostname; `None` means mirror the host verbatim.
    /// `Option` for the same reason `Forward`'s fields are — so drop-ins merge field-by-field.
    #[serde(default)]
    hostname_suffix: Option<String>,
    /// Where the dedicated daemon keeps its images and layers; `None` means the default
    /// under `$HOME`. Exists because that default is unusable on a machine whose `$HOME`
    /// is a filesystem overlayfs won't stack on — see `util::unsupported_upperdir_fs`.
    #[serde(default)]
    data_root: Option<String>,
    /// Whether to give the sandbox the generated system gitconfig (see
    /// `identity::SYSTEM_GITCONFIG`); `None` means the built-in default, which is on.
    /// `Option` for the same reason `Forward`'s fields are — field-by-field drop-in merge.
    #[serde(default)]
    system_gitconfig: Option<bool>,
    /// Give the sandbox the host network (rootlesskit's namespace, not the real host's).
    /// `None` means the built-in default, which is on — see `RunSpec::host_network`.
    #[serde(default)]
    host_network: Option<bool>,
    /// Host toolchains to mirror in, keyed by name (`rbenv`, `uv`), each with a mode.
    /// Empty unless a config asks: nothing is mounted by surprise. Merged across drop-ins
    /// like `[mounts]`, so a later file can restate a toolchain at a different mode.
    #[serde(default)]
    toolchains: HashMap<String, ToolchainSpec>,
}

/// A toolchain's `"ro"` shorthand or `{ mode = "ro", optional = true }` long form —
/// deliberately the same shape as `MountSpec`, since it is the same idea for a named tree.
#[derive(Deserialize)]
#[serde(untagged)]
enum ToolchainSpec {
    Short(ToolchainMode),
    Long {
        mode: ToolchainMode,
        /// Skip silently when the toolchain isn't installed, instead of failing. Off by
        /// default: a toolchain named in config is one you expect to be there, and a silent
        /// skip is how "why is ruby the system one inside?" becomes a debugging session.
        #[serde(default)]
        optional: bool,
    },
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ToolchainMode {
    /// Installed versions/tools visible and runnable, but not mutable from inside.
    Ro,
    /// Also installable from inside — `gem install`, `uv tool install` reach the host tree.
    Rw,
    /// ro base with an ephemeral writable upper: install inside without touching the host.
    /// Parses today but is refused at resolve time until overlay mounts exist.
    Overlay,
}

impl ToolchainSpec {
    fn mode(&self) -> ToolchainMode {
        match self {
            ToolchainSpec::Short(m) => *m,
            ToolchainSpec::Long { mode, .. } => *mode,
        }
    }
    fn optional(&self) -> bool {
        matches!(self, ToolchainSpec::Long { optional: true, .. })
    }
}

/// What a known toolchain occupies on disk. `primary` is the presence indicator — its
/// absence is what `optional` guards; the rest are mounted only if they happen to exist,
/// since caches and managed-version dirs are created on first use.
struct Recipe {
    primary: &'static str,
    /// Mounted at the toolchain's chosen mode.
    install: &'static [&'static str],
    /// Always mounted read-write: a read-only cache is a footgun (uv can't install even
    /// into a writable in-tree venv), not protection, and the versions dir is the thing the
    /// mode is actually guarding.
    cache: &'static [&'static str],
}

/// The recipes limes ships. Adding a toolchain is a line here plus a mention in the docs;
/// the recipe is layout knowledge (where rbenv/uv live), never a policy about enabling them.
fn recipe(name: &str) -> Option<Recipe> {
    match name {
        "rbenv" => Some(Recipe { primary: "~/.rbenv", install: &["~/.rbenv"], cache: &[] }),
        "uv" => Some(Recipe {
            primary: "~/.local/bin/uv",
            install: &["~/.local/bin/uv", "~/.local/share/uv"],
            cache: &["~/.cache/uv"],
        }),
        _ => None,
    }
}

/// Standing on/off switches for the credential and socket forwards.
///
/// `Option<bool>` rather than `bool` is load-bearing: it distinguishes "this file says
/// nothing about gpg" from "this file says gpg = false", which is what lets a drop-in and
/// `config.toml` merge field-by-field instead of one clobbering the other wholesale.
/// `None` throughout means "fall back to the built-in default".
#[derive(Deserialize, Default, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub ssh: Option<bool>,
    pub gpg: Option<bool>,
    /// Forward `S.gpg-agent` rather than `S.gpg-agent.extra`. Defaults to *off*, unlike
    /// every other switch here — see `RunArgs::gpg_unrestricted`.
    pub gpg_unrestricted: Option<bool>,
    pub rosa: Option<bool>,
    pub docker: Option<bool>,
}

impl Forward {
    /// Overlay `other` onto `self`: every `Some` in `other` wins, every `None` leaves the
    /// earlier value standing.
    fn merge(&mut self, other: Forward) {
        self.ssh = other.ssh.or(self.ssh);
        self.gpg = other.gpg.or(self.gpg);
        self.gpg_unrestricted = other.gpg_unrestricted.or(self.gpg_unrestricted);
        self.rosa = other.rosa.or(self.rosa);
        self.docker = other.docker.or(self.docker);
    }
}

/// `"ro"` shorthand or the `{ mode = "ro", … }` long form. The bare-string form stays
/// valid forever; the table carries optional per-path behaviour.
#[derive(Deserialize)]
#[serde(untagged)]
enum MountSpec {
    Short(Mode),
    Long {
        mode: Mode,
        /// `"parent"`: the key is a symlink — recreate it inside and mount its target's
        /// parent dir (so siblings, e.g. zsh `plugins/`, come along).
        #[serde(default)]
        link: Option<Link>,
        /// Skip silently if the path doesn't exist, instead of hard-failing.
        /// Redundant with `mode = "hide"`, which is always optional; harmless there.
        #[serde(default)]
        optional: bool,
    },
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Ro,
    Rw,
    /// Shadow the path with an empty dir. Subtractive: the point is to punch a hole in a
    /// broader mount (`~/.config` ro, minus the credential dirs inside it).
    Hide,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Link {
    Parent,
}

impl MountSpec {
    fn mode(&self) -> Mode {
        match self {
            MountSpec::Short(m) => *m,
            MountSpec::Long { mode, .. } => *mode,
        }
    }
    fn link(&self) -> Option<Link> {
        match self {
            MountSpec::Long { link, .. } => *link,
            _ => None,
        }
    }
    fn optional(&self) -> bool {
        matches!(self, MountSpec::Long { optional: true, .. })
    }
}

/// A symlink to (re)create inside the sandbox, mirroring the host.
pub struct SymlinkSpec {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub link: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub target: PathBuf,
}

/// Mounts and symlinks a config asks for.
pub struct Resolved {
    pub mounts: Vec<Mount>,
    pub symlinks: Vec<SymlinkSpec>,
}

/// Merge `config.toml` with every `config.d/*.toml`, or `None` if none exist.
/// Drop-ins are applied filename-sorted first, then `config.toml`, so the hand-written
/// file wins on a key collision. Parse/IO errors hard-fail with the file path.
pub fn load(ctx: &Context) -> Result<Option<Config>> {
    let mut merged: HashMap<String, MountSpec> = HashMap::new();
    let mut forward = Forward::default();
    let mut hostname_suffix: Option<String> = None;
    let mut data_root: Option<String> = None;
    let mut system_gitconfig: Option<bool> = None;
    let mut host_network: Option<bool> = None;
    let mut toolchains: HashMap<String, ToolchainSpec> = HashMap::new();
    let mut found = false;

    if let Ok(entries) = std::fs::read_dir(ctx.config_d_dir()) {
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        for f in files {
            let cfg = parse(&f)?;
            merged.extend(cfg.mounts);
            forward.merge(cfg.forward);
            hostname_suffix = cfg.hostname_suffix.or(hostname_suffix);
            data_root = cfg.data_root.or(data_root);
            system_gitconfig = cfg.system_gitconfig.or(system_gitconfig);
            host_network = cfg.host_network.or(host_network);
            toolchains.extend(cfg.toolchains);
            found = true;
        }
    }
    if let Some(cfg) = parse_optional(&ctx.config_file())? {
        merged.extend(cfg.mounts);
        forward.merge(cfg.forward);
        hostname_suffix = cfg.hostname_suffix.or(hostname_suffix);
        data_root = cfg.data_root.or(data_root);
        system_gitconfig = cfg.system_gitconfig.or(system_gitconfig);
        host_network = cfg.host_network.or(host_network);
        toolchains.extend(cfg.toolchains);
        found = true;
    }

    Ok(found.then_some(Config {
        mounts: merged,
        forward,
        hostname_suffix,
        data_root,
        system_gitconfig,
        host_network,
        toolchains,
    }))
}

fn parse(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn parse_optional(path: &Path) -> Result<Option<Config>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            Ok(Some(toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

impl Config {
    /// The standing forward switches, for `forward::Forwards::resolve` to layer CLI over.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn forward(&self) -> Forward {
        self.forward
    }

    /// The standing hostname suffix, for the CLI flag to override.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn hostname_suffix(&self) -> Option<&str> {
        self.hostname_suffix.as_deref()
    }

    /// The standing system-gitconfig switch, for the CLI flag pair to override.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn system_gitconfig(&self) -> Option<bool> {
        self.system_gitconfig
    }

    /// The standing host-network switch, for the CLI flag pair to override.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn host_network(&self) -> Option<bool> {
        self.host_network
    }

    /// The configured data-root, expanded. Absolute is required: the path is written into
    /// a systemd unit, which has no working directory to resolve it against, so a relative
    /// value would land somewhere neither of us intended.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn data_root(&self) -> Result<Option<PathBuf>> {
        let Some(raw) = self.data_root.as_deref() else { return Ok(None) };
        let expanded = shellexpand::full(raw)
            .with_context(|| format!("expanding config `data_root = \"{raw}\"`"))?;
        let path = PathBuf::from(expanded.as_ref());
        if !path.is_absolute() {
            bail!("config `data_root = \"{raw}\"` must be an absolute path");
        }
        Ok(Some(path))
    }

    /// Turn config entries into mounts (+ symlinks to recreate). Missing paths hard-fail
    /// unless `optional`, matching CLI `--ro`/`--rw`.
    pub fn resolve(&self) -> Result<Resolved> {
        let mut mounts = Vec::new();
        let mut symlinks = Vec::new();

        for (raw, spec) in &self.mounts {
            let expanded = shellexpand::full(raw)
                .with_context(|| format!("expanding config mount path `{raw}`"))?;
            let path = PathBuf::from(expanded.as_ref());
            let mode = spec.mode();

            // `hide` has no host source to bind, so it resolves on its own terms: a
            // missing path is a silent no-op (nothing to shadow), and a file is a hard
            // error rather than a mount that quietly fails to hide anything.
            if mode == Mode::Hide {
                if spec.link().is_some() {
                    bail!(
                        "config mount `{raw}`: link=\"parent\" cannot combine with \
                         mode=\"hide\" — it would hide the symlink target's parent dir"
                    );
                }
                if let Some((p, mode)) = mounts::resolve_hide(&path)? {
                    mounts.push(Mount::hide(p, mode));
                }
                continue;
            }

            match spec.link() {
                Some(Link::Parent) => {
                    let is_symlink = std::fs::symlink_metadata(&path)
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false);
                    if !is_symlink {
                        if spec.optional() && !path.exists() {
                            continue;
                        }
                        bail!(
                            "config mount `{raw}`: link=\"parent\" requires a symlink, \
                             but {} is {}",
                            path.display(),
                            if path.exists() { "not one" } else { "missing" }
                        );
                    }
                    let target = std::fs::canonicalize(&path)
                        .with_context(|| format!("resolving symlink `{raw}`"))?;
                    let parent = target
                        .parent()
                        .ok_or_else(|| anyhow!("config mount `{raw}`: target has no parent dir"))?
                        .to_path_buf();
                    symlinks.push(SymlinkSpec { link: path, target });
                    mounts.push(mount(mode, parent));
                }
                None => {
                    if spec.optional() && !path.exists() {
                        continue;
                    }
                    mounts.push(mount(mode, mounts::canonicalize(&path)?));
                }
            }
        }

        self.resolve_toolchains(&mut mounts)?;
        Ok(Resolved { mounts, symlinks })
    }

    /// Append the mounts for every enabled toolchain. Same tier as `[mounts]`, so it rides
    /// the same dedupe/sort and an explicit `--ro`/`--rw` still wins.
    fn resolve_toolchains(&self, mounts: &mut Vec<Mount>) -> Result<()> {
        let expand = |raw: &str| -> Result<PathBuf> {
            Ok(PathBuf::from(
                shellexpand::full(raw)
                    .with_context(|| format!("expanding toolchain path `{raw}`"))?
                    .into_owned(),
            ))
        };

        for (name, spec) in &self.toolchains {
            let Some(r) = recipe(name) else {
                bail!("unknown toolchain `{name}` (known: rbenv, uv)");
            };
            let mode = match spec.mode() {
                ToolchainMode::Ro => Mode::Ro,
                ToolchainMode::Rw => Mode::Rw,
                ToolchainMode::Overlay => bail!(
                    "toolchain `{name}`: mode \"overlay\" is not implemented yet — use \
                     \"ro\" or \"rw\""
                ),
            };

            // Presence is the primary path. Absent + optional is a silent skip; absent and
            // not optional is the loud failure the user asked for -- a toolchain named in
            // config is one you meant to have, and quietly falling back to the system copy
            // is the confusing outcome.
            let primary = expand(r.primary)?;
            if !primary.exists() {
                if spec.optional() {
                    continue;
                }
                bail!(
                    "toolchain `{name}` is enabled but not installed ({} is missing) — \
                     mark it `{{ mode = \"{}\", optional = true }}` to skip when absent",
                    primary.display(),
                    if mode == Mode::Rw { "rw" } else { "ro" }
                );
            }

            // Everything present is mounted; a missing cache/version dir is skipped, not an
            // error -- those are created on first use, so a fresh install lacks them.
            for raw in r.install {
                let path = expand(raw)?;
                if path.exists() {
                    mounts.push(mount(mode, mounts::canonicalize(&path)?));
                }
            }
            for raw in r.cache {
                let path = expand(raw)?;
                if path.exists() {
                    mounts.push(Mount::rw(mounts::canonicalize(&path)?));
                }
            }
        }
        Ok(())
    }
}

/// The two modes that are host binds. `Hide` never reaches here — it short-circuits
/// earlier in `resolve`, because it has no host source and its own existence rules.
fn mount(mode: Mode, path: PathBuf) -> Mount {
    match mode {
        Mode::Ro => Mount::ro(path),
        Mode::Rw => Mount::rw(path),
        Mode::Hide => unreachable!("hide is resolved before this point"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str) -> Config {
        toml::from_str(s).expect("valid config")
    }

    #[test]
    fn forward_defaults_to_all_unset() {
        let c = parse_str("[mounts]\n");
        assert_eq!(c.forward.gpg, None);
        assert_eq!(c.forward.rosa, None);
    }

    #[test]
    fn forward_parses_booleans() {
        let c = parse_str("[forward]\ngpg = false\nrosa = true\n");
        assert_eq!(c.forward.gpg, Some(false));
        assert_eq!(c.forward.rosa, Some(true));
        assert_eq!(c.forward.ssh, None, "unmentioned keys stay unset");
    }

    /// A typo in a forward name must not silently do nothing — `deny_unknown_fields`
    /// turns it into a parse error naming the file.
    #[test]
    fn forward_rejects_unknown_key() {
        assert!(toml::from_str::<Config>("[forward]\ngpgg = false\n").is_err());
    }

    /// The `untagged` MountSpec is what gives a new mode both spellings for free; assert
    /// it, since nothing else would notice if the shorthand quietly stopped parsing.
    #[test]
    fn hide_parses_in_both_forms() {
        let c = parse_str("[mounts]\n\"/a\" = \"hide\"\n\"/b\" = { mode = \"hide\" }\n");
        assert_eq!(c.mounts["/a"].mode(), Mode::Hide);
        assert_eq!(c.mounts["/b"].mode(), Mode::Hide);
    }

    /// `link = "parent"` mounts the *target's parent dir*, so combining it with `hide`
    /// would hide a directory the user never named. Refuse rather than surprise.
    #[test]
    fn hide_rejects_link_parent() {
        let c = parse_str("[mounts]\n\"/a\" = { mode = \"hide\", link = \"parent\" }\n");
        let err = c.resolve().map(|_| ()).expect_err("hide + link must not resolve");
        assert!(err.to_string().contains("cannot combine"), "got: {err}");
    }

    #[test]
    fn unknown_toolchain_is_rejected() {
        let c = parse_str("[toolchains]\nnope = \"ro\"\n");
        let err = c.resolve().map(|_| ()).expect_err("unknown toolchain must fail");
        assert!(err.to_string().contains("unknown toolchain"), "got: {err}");
    }

    #[test]
    fn overlay_mode_is_refused_for_now() {
        let c = parse_str("[toolchains]\nuv = { mode = \"overlay\" }\n");
        let err = c.resolve().map(|_| ()).expect_err("overlay must fail until implemented");
        assert!(err.to_string().contains("overlay"), "got: {err}");
    }

    /// Presence keys off the primary path. A toolchain named non-optional whose primary is
    /// absent must fail loudly rather than silently leaving the sandbox on the system copy.
    #[test]
    fn non_optional_missing_toolchain_fails_loud() {
        // `~` expands to $HOME; point it somewhere with no toolchains so the primary path
        // cannot exist, without depending on the test machine's real home.
        let prev = std::env::var_os("HOME");
        // SAFETY: single-threaded test; restored below.
        unsafe { std::env::set_var("HOME", "/nonexistent-limes-test-home") };
        let c = parse_str("[toolchains]\nrbenv = \"ro\"\n");
        let res = c.resolve().map(|_| ());
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let err = res.expect_err("missing non-optional toolchain must fail");
        assert!(err.to_string().contains("not installed"), "got: {err}");
    }

    /// The drop-in merge: `config.toml` is applied last and wins, but only on the keys it
    /// actually names — everything else a drop-in set must survive.
    #[test]
    fn later_file_wins_per_field() {
        let mut f = parse_str("[forward]\ngpg = false\nrosa = false\n").forward;
        f.merge(parse_str("[forward]\ngpg = true\n").forward);
        assert_eq!(f.gpg, Some(true), "config.toml overrides the drop-in");
        assert_eq!(f.rosa, Some(false), "untouched key survives the merge");
        assert_eq!(f.ssh, None);
    }
}
