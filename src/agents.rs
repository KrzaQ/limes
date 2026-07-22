//! Auto-detect host coding agents and mount them in.
//!
//! Mirroring `/usr` does not pick up `claude`/`opencode` — they live under `$HOME`
//! (`~/.local`, `~/.opencode`). We resolve each on `PATH` and, if present, mount its
//! program tree read-only and its state/auth dir read-write, so it runs authenticated
//! inside the sandbox. We never mount `~/.local` wholesale — it may hold other creds.

use crate::RunArgs;
use crate::config::SymlinkSpec;
use crate::context::Context;
use crate::mounts::Mount;
use crate::util::find_in_path;

struct AgentSpec {
    name: &'static str,
    bin: &'static str,
    /// Program files (read-only), relative to `$HOME`.
    ro: &'static [&'static str],
    /// State / auth dirs (read-write), relative to `$HOME`.
    rw: &'static [&'static str],
    /// Symlinks to *recreate* rather than mount, relative to `$HOME`.
    ///
    /// Docker flattens a symlink when it mounts it, so a launcher that finds its runtime
    /// next to its own resolved path (`realpath "$0"`) computes the wrong directory inside.
    /// Same problem, same fix as config's `link = "parent"` — except here the target tree
    /// is already covered by `ro`/`rw`, so this only re-points the name at it.
    links: &'static [&'static str],
}

const SPECS: &[AgentSpec] = &[
    AgentSpec {
        name: "claude",
        bin: "claude",
        // `.local/bin/claude` is a symlink too, but it resolves to a single self-contained
        // binary, so the flattened copy works and is left as a plain mount.
        ro: &[".local/bin/claude", ".local/share/claude"],
        rw: &[".claude", ".claude.json"],
        links: &[],
    },
    AgentSpec {
        name: "opencode",
        bin: "opencode",
        ro: &[".opencode"],
        rw: &[".local/share/opencode", ".config/opencode"],
        links: &[],
    },
    // `.config/cursor` holds auth.json. It is a *shared agent credential*, like `~/.claude`
    // — deliberately mounted so the agent runs authenticated inside — not key material the
    // oracle rule is about. Worth stating because a broad `~/.config` mount plus a `hide`
    // blocklist will otherwise sweep it up as "an auth.json, hide it" and quietly break
    // cursor-agent in the sandbox; config `hide` is pushed after agents and would win.
    AgentSpec {
        name: "cursor",
        bin: "cursor-agent",
        ro: &[],
        // The version tree is read-write because that is where cursor-agent installs its
        // own updates, the way opencode writes `.local/share/opencode`. An agent that
        // corrupts its own install is recoverable; one that cannot update is a papercut
        // every session.
        rw: &[".local/share/cursor-agent", ".config/cursor", ".cursor"],
        // `.local/bin/cursor-agent` → `.local/share/cursor-agent/versions/<v>/cursor-agent`,
        // a bash launcher that does `SCRIPT_DIR=$(dirname $(realpath $0))` and then execs
        // `$SCRIPT_DIR/node`. Mounted (and so flattened) it lands in `.local/bin`, where
        // there is no node, and dies. Recreated, it resolves into the version tree above.
        links: &[".local/bin/cursor-agent"],
    },
];

/// Mounts for every detected, non-opted-out agent, plus their names (for messaging).
pub struct Detected {
    pub mounts: Vec<Mount>,
    /// Symlinks the sandbox has to recreate; see `AgentSpec::links`. Linux-only: nothing
    /// is mounted on macOS, so the host's own symlinks are simply still there.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub symlinks: Vec<SymlinkSpec>,
    pub names: Vec<String>,
}

pub fn detect(ctx: &Context, args: &RunArgs) -> Detected {
    let mut mounts = Vec::new();
    let mut symlinks = Vec::new();
    let mut names = Vec::new();
    if args.no_agents {
        return Detected { mounts, symlinks, names };
    }
    for spec in SPECS {
        let opted_out = match spec.name {
            "claude" => args.no_claude,
            "opencode" => args.no_opencode,
            "cursor" => args.no_cursor,
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
        // Resolve on the host, so the sandbox gets the version the host would have run —
        // not whatever a stale symlink text happens to say. A path that isn't a symlink
        // (a distro package, a hand-installed binary) is left alone: mounting it is then
        // the caller's business, and silently doing nothing beats fabricating a link.
        for rel in spec.links {
            let link = ctx.home.join(rel);
            if let Ok(target) = std::fs::canonicalize(&link)
                && target != link
            {
                symlinks.push(SymlinkSpec { link, target });
            }
        }
    }
    Detected { mounts, symlinks, names }
}
