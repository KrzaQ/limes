//! Per-machine config file: `~/.config/limes/config.toml`.
//!
//! Standing default mounts, path-as-key so TOML's unique-key rule dedups for free
//! (a path can't be listed both ro and rw). File order is irrelevant — mounts are
//! depth-sorted downstream. Unmanaged and machine-specific, like `~/.gitconfig`;
//! every path it names must exist (hard-fail), matching CLI `--ro`/`--rw` behaviour.
//!
//! ```toml
//! [mounts]
//! "/storage"             = "ro"
//! "~/code/misc/dotfiles" = "ro"
//! "~/scratch"            = { mode = "rw" }
//! ```

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use serde::Deserialize;

use crate::context::Context;
use crate::mounts::{self, Mount};

#[derive(Deserialize)]
pub struct Config {
    #[serde(default)]
    mounts: HashMap<String, MountSpec>,
}

/// `"ro"` shorthand or the `{ mode = "ro" }` long form. Only `mode` exists today; the
/// table shape reserves room for future per-path params without breaking the shorthand.
#[derive(Deserialize)]
#[serde(untagged)]
enum MountSpec {
    Short(Mode),
    Long { mode: Mode },
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Ro,
    Rw,
}

impl MountSpec {
    fn mode(&self) -> Mode {
        match self {
            MountSpec::Short(m) => *m,
            MountSpec::Long { mode } => *mode,
        }
    }
}

/// Load the config file, or `None` if it does not exist. Parse/IO errors hard-fail
/// with the file path in the message.
pub fn load(ctx: &Context) -> Result<Option<Config>> {
    let path = ctx.config_file();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let config: Config =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(config))
}

impl Config {
    /// Expand (`~`/`$VAR`) and canonicalize each configured path into a Mount.
    /// A path that does not exist is a hard error, same as a CLI `--ro`/`--rw`.
    pub fn to_mounts(&self) -> Result<Vec<Mount>> {
        let mut out = Vec::with_capacity(self.mounts.len());
        for (raw, spec) in &self.mounts {
            let expanded = shellexpand::full(raw)
                .with_context(|| format!("expanding config mount path `{raw}`"))?;
            let path = mounts::canonicalize(std::path::Path::new(expanded.as_ref()))?;
            out.push(match spec.mode() {
                Mode::Ro => Mount::ro(path),
                Mode::Rw => Mount::rw(path),
            });
        }
        Ok(out)
    }
}
