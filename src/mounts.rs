//! Mount engine: `--ro`/`--rw` → same-path `-v` args, depth-sorted for nesting.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// A single same-path bind mount request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub host: PathBuf,
    pub read_only: bool,
}

impl Mount {
    pub fn ro(p: PathBuf) -> Self {
        Self { host: p, read_only: true }
    }
    pub fn rw(p: PathBuf) -> Self {
        Self { host: p, read_only: false }
    }

    /// `-v /path:/path[:ro]` — same path inside and out, so absolute paths baked into
    /// build artifacts (compile_commands.json, ccache, diagnostics) stay valid both sides.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn to_arg(&self) -> String {
        let p = self.host.display();
        if self.read_only {
            format!("{p}:{p}:ro")
        } else {
            format!("{p}:{p}")
        }
    }
}

/// Canonicalize a user-supplied path (realpath); errors if it does not exist,
/// since a same-path bind mount of a missing host path is always a mistake.
pub fn canonicalize(p: &Path) -> Result<PathBuf> {
    p.canonicalize()
        .with_context(|| format!("cannot mount {}: no such path on host", p.display()))
}

/// Order mounts parent-before-child so nested holes apply correctly regardless of
/// the order the user passed them. Docker sorts internally too, but we do it
/// defensively and to make `--dry-run` output deterministic and readable.
pub fn sort_for_nesting(mounts: &mut [Mount]) {
    mounts.sort_by(|a, b| {
        let da = a.host.components().count();
        let db = b.host.components().count();
        da.cmp(&db).then_with(|| a.host.cmp(&b.host))
    });
}
