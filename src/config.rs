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
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use serde::Deserialize;

use crate::context::Context;
use crate::mounts::{self, Mount};

#[derive(Deserialize)]
pub struct Config {
    #[serde(default)]
    mounts: HashMap<String, MountSpec>,
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
        #[serde(default)]
        optional: bool,
    },
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Ro,
    Rw,
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
    pub link: PathBuf,
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
    let mut found = false;

    if let Ok(entries) = std::fs::read_dir(ctx.config_d_dir()) {
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        for f in files {
            merged.extend(parse(&f)?.mounts);
            found = true;
        }
    }
    if let Some(cfg) = parse_optional(&ctx.config_file())? {
        merged.extend(cfg.mounts);
        found = true;
    }

    Ok(found.then_some(Config { mounts: merged }))
}

fn parse(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn parse_optional(path: &Path) -> Result<Option<Config>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

impl Config {
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

fn mount(mode: Mode, path: PathBuf) -> Mount {
    match mode {
        Mode::Ro => Mount::ro(path),
        Mode::Rw => Mount::rw(path),
    }
}
