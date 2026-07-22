//! Credential and socket forwarding: ssh-agent, gpg-agent, rosa, and the limes daemon.
//!
//! Every forward here hands the sandbox the *use* of something without the thing itself.
//! The SSH agent signs but never yields a private key; the GPG *extra* socket is the
//! restricted one; rosa brokers secrets behind a human approval gate on a tty the sandbox
//! cannot reach. That asymmetry is the whole point — mounting `~/.ssh`, `~/.gnupg` or
//! rosa's encrypted store would defeat it, so don't.
//!
//! All four are on by default and resolve **built-in default → config `[forward]` → CLI
//! flag**, matching how `[mounts]` layers under `--ro`/`--rw`. Each also no-ops silently
//! when the thing it forwards isn't there (no agent running, no socket), so the defaults
//! stay harmless on a host that has none of them.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::RunArgs;
use crate::config;
use crate::context::Context;
use crate::mounts::{Bind, Mount};
use crate::util::find_in_path;

/// Which forwards are live for this run.
pub struct Forwards {
    pub ssh: bool,
    pub gpg: bool,
    pub rosa: bool,
    pub docker: bool,
}

impl Forwards {
    /// Layer CLI flags over config over the built-in default (on).
    pub fn resolve(args: &RunArgs, cfg: Option<config::Forward>) -> Self {
        let cfg = cfg.unwrap_or_default();
        Self {
            ssh: enabled(tri(args.ssh, args.no_ssh), cfg.ssh),
            gpg: enabled(tri(args.gpg, args.no_gpg), cfg.gpg),
            rosa: enabled(tri(args.rosa, args.no_rosa), cfg.rosa),
            docker: enabled(tri(args.docker, args.no_docker), cfg.docker),
        }
    }
}

/// Built-in default → config → CLI. Everything forwards unless something says otherwise.
fn enabled(cli: Option<bool>, cfg: Option<bool>) -> bool {
    cli.or(cfg).unwrap_or(true)
}

/// Collapse a `--x` / `--no-x` pair into a tri-state. clap's `overrides_with` makes the
/// last flag on the command line the winner, so at most one of these is ever set.
fn tri(yes: bool, no: bool) -> Option<bool> {
    match (yes, no) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Where the rosa broker listens: `$ROSA_SOCK`, else `rosa.sock` in the runtime dir.
/// `Context::detect` already resolved `XDG_RUNTIME_DIR` (falling back to `/run/user/$uid`),
/// so this needs no path logic of its own.
pub fn rosa_socket(ctx: &Context) -> PathBuf {
    std::env::var_os("ROSA_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| ctx.xdg_runtime_dir.join("rosa.sock"))
}

/// The rosa client binary, if it is somewhere the `/usr` mirror won't already supply.
///
/// rosa typically lives in `~/.cargo/bin`, which is neither under the mirrored `/usr` nor
/// in the tmpfs `$HOME` — so without this the sandbox gets a socket and nothing able to
/// speak to it. Same problem, and same fix, as `agents.rs` has for `claude`.
pub fn rosa_client() -> Option<PathBuf> {
    find_in_path("rosa").filter(|p| !p.starts_with("/usr"))
}

/// Same-path mounts rosa needs: the broker socket and (when it isn't already covered by
/// the `/usr` mirror) the client binary.
///
/// These go through the normal `Mount` list rather than raw `-v` args so they inherit
/// dedupe, depth-sorting and the usual precedence — an explicit `--ro`/`--rw` on either
/// path still wins. The encrypted store is *not* here and must never be: it lives in
/// `$HOME`, which the tmpfs shadows, so the sandbox can request secrets but never read
/// them at rest.
pub fn rosa_mounts(ctx: &Context, on: bool) -> Vec<Mount> {
    let mut m = Vec::new();
    if !on {
        return m;
    }
    let sock = rosa_socket(ctx);
    if !sock.exists() {
        return m; // `rosa serve` isn't running — nothing to forward.
    }
    m.push(Mount::rw(sock));
    if let Some(bin) = rosa_client() {
        m.push(Mount::ro(bin));
    }
    m
}

/// Every enabled forward's non-`Mount` pieces: the sockets whose destination differs from
/// their source, and the env vars that point tools at them.
///
/// Returned rather than pushed straight onto a `Command`, so that everything docker will
/// see ends up in one `RunSpec`. Comparing a running sandbox against a requested policy
/// means enumerating *all* of it; a forward that emitted its own args directly would be
/// invisible to that comparison, and would go on being invisible as forwards are added.
#[derive(Default)]
pub struct Pieces {
    pub binds: Vec<Bind>,
    pub env: Vec<String>,
}

pub fn pieces(ctx: &Context, f: &Forwards) -> Pieces {
    let mut p = Pieces::default();
    if f.ssh {
        add_ssh_agent(&mut p);
    }
    if f.gpg {
        add_gpg_agent(&mut p, ctx);
    }
    if f.rosa {
        add_rosa_env(&mut p, ctx);
    }
    if f.docker {
        add_docker_socket(&mut p, ctx);
    }
    p
}

/// Forward the SSH agent (a signing oracle, not the keys).
fn add_ssh_agent(p: &mut Pieces) {
    if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
        let sock = Path::new(&sock);
        if sock.exists() {
            p.binds.push(Bind::same_path(sock, false));
            p.env.push("SSH_AUTH_SOCK".into());
        }
    }
}

/// Forward the GPG *extra* (restricted) socket onto the container's normal agent
/// socket path, plus the public keyring read-only. Secret keys stay in the host agent.
fn add_gpg_agent(p: &mut Pieces, ctx: &Context) {
    let Ok(out) = Command::new("gpgconf").args(["--list-dir", "agent-extra-socket"]).output()
    else {
        return;
    };
    if !out.status.success() {
        return;
    }
    let extra = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if extra.is_empty() || !Path::new(&extra).exists() {
        return;
    }
    let dest = format!("/run/user/{}/gnupg/S.gpg-agent", ctx.uid);
    p.binds.push(Bind::new(extra, dest, false));
    let pubring = ctx.home.join(".gnupg/pubring.kbx");
    if pubring.exists() {
        p.binds.push(Bind::same_path(&pubring, true));
    }
}

/// Point the client at the socket explicitly. The container sets no `XDG_RUNTIME_DIR`, so
/// relying on rosa's own fallback would make resolution depend on a variable that isn't
/// there; naming the path removes the guesswork. The mount itself is a `Mount` (see
/// `rosa_mounts`) because it is same-path.
fn add_rosa_env(p: &mut Pieces, ctx: &Context) {
    let sock = rosa_socket(ctx);
    if sock.exists() {
        p.env.push(format!("ROSA_SOCK={}", sock.display()));
    }
}

/// Mount the limes daemon's own socket into the container as the normal docker
/// socket, so tools inside drive the same daemon (docker-outside-of-docker). Nothing
/// is nested: fixtures the sandbox starts are siblings on the limes daemon, not dind.
fn add_docker_socket(p: &mut Pieces, ctx: &Context) {
    p.binds.push(Bind::new(ctx.socket().display().to_string(), "/var/run/docker.sock", false));
    p.env.push("DOCKER_HOST=unix:///var/run/docker.sock".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_on() {
        assert!(enabled(None, None));
    }

    #[test]
    fn config_overrides_default() {
        assert!(!enabled(None, Some(false)));
        assert!(enabled(None, Some(true)));
    }

    /// The invariant that justifies having a positive flag at all: a standing `false` in
    /// config must still be overridable for a single run.
    #[test]
    fn cli_overrides_config_both_ways() {
        assert!(enabled(Some(true), Some(false)));
        assert!(!enabled(Some(false), Some(true)));
    }

    #[test]
    fn tri_collapses_flag_pair() {
        assert_eq!(tri(false, false), None);
        assert_eq!(tri(true, false), Some(true));
        assert_eq!(tri(false, true), Some(false));
    }
}
