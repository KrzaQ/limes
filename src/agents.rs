//! Auto-detect host coding agents and mount them in.
//!
//! Mirroring `/usr` does not pick up `claude`/`opencode` — they live under `$HOME`
//! (`~/.local`, `~/.opencode`). We resolve each on `PATH` and, if present, mount its
//! program tree read-only and its state/auth dir read-write, so it runs authenticated
//! inside the sandbox. We never mount `~/.local` wholesale — it may hold other creds.

use std::path::{Path, PathBuf};

use crate::RunArgs;
use crate::context::Context;
use crate::mounts::Mount;

struct AgentSpec {
    name: &'static str,
    bin: &'static str,
    /// Program files (read-only), relative to `$HOME`.
    ro: &'static [&'static str],
    /// State / auth dirs (read-write), relative to `$HOME`.
    rw: &'static [&'static str],
}

const SPECS: &[AgentSpec] = &[
    AgentSpec {
        name: "claude",
        bin: "claude",
        ro: &[".local/bin/claude", ".local/share/claude"],
        rw: &[".claude"],
    },
    AgentSpec {
        name: "opencode",
        bin: "opencode",
        ro: &[".opencode"],
        rw: &[".local/share/opencode", ".config/opencode"],
    },
];

/// Mounts for every detected, non-opted-out agent, plus their names (for messaging).
pub struct Detected {
    pub mounts: Vec<Mount>,
    pub names: Vec<String>,
}

pub fn detect(ctx: &Context, args: &RunArgs) -> Detected {
    let mut mounts = Vec::new();
    let mut names = Vec::new();
    if args.no_agents {
        return Detected { mounts, names };
    }
    for spec in SPECS {
        let opted_out = match spec.name {
            "claude" => args.no_claude,
            "opencode" => args.no_opencode,
            _ => false,
        };
        if opted_out || find_in_path(spec.bin).is_none() {
            continue;
        }
        names.push(spec.name.to_string());
        for rel in spec.ro {
            let p = ctx.home.join(rel);
            if p.exists() {
                mounts.push(Mount::ro(p));
            }
        }
        for rel in spec.rw {
            let p = ctx.home.join(rel);
            if p.exists() {
                mounts.push(Mount::rw(p));
            }
        }
    }
    Detected { mounts, names }
}

/// Locate an executable by scanning `PATH`, like `command -v`.
fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|cand| is_executable(cand))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
