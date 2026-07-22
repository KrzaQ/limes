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
    pub rosa: Option<bool>,
    pub docker: Option<bool>,
}

impl Forward {
    /// Overlay `other` onto `self`: every `Some` in `other` wins, every `None` leaves the
    /// earlier value standing.
    fn merge(&mut self, other: Forward) {
        self.ssh = other.ssh.or(self.ssh);
        self.gpg = other.gpg.or(self.gpg);
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
            found = true;
        }
    }
    if let Some(cfg) = parse_optional(&ctx.config_file())? {
        merged.extend(cfg.mounts);
        forward.merge(cfg.forward);
        hostname_suffix = cfg.hostname_suffix.or(hostname_suffix);
        data_root = cfg.data_root.or(data_root);
        system_gitconfig = cfg.system_gitconfig.or(system_gitconfig);
        found = true;
    }

    Ok(found.then_some(Config {
        mounts: merged,
        forward,
        hostname_suffix,
        data_root,
        system_gitconfig,
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
        Ok(Resolved { mounts, symlinks })
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
