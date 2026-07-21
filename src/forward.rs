//! Credential and socket forwarding: ssh-agent, gpg-agent, and the limes daemon.
//!
//! Every forward here hands the sandbox the *use* of something without the thing itself.
//! The SSH agent signs but never yields a private key, and the GPG *extra* socket is the
//! restricted one. That asymmetry is the whole point — mounting `~/.ssh` or `~/.gnupg`
//! wholesale would defeat it, so don't.
//!
//! All three are on by default and resolve **built-in default → config `[forward]` → CLI
//! flag**, matching how `[mounts]` layers under `--ro`/`--rw`. Each also no-ops silently
//! when the thing it forwards isn't there (no agent running, no socket), so the defaults
//! stay harmless on a host that has none of them.

use std::path::Path;
use std::process::Command;

use crate::RunArgs;
use crate::config;
use crate::context::Context;

/// Which forwards are live for this run.
pub struct Forwards {
    pub ssh: bool,
    pub gpg: bool,
    pub docker: bool,
}

impl Forwards {
    /// Layer CLI flags over config over the built-in default (on).
    pub fn resolve(args: &RunArgs, cfg: Option<config::Forward>) -> Self {
        let cfg = cfg.unwrap_or_default();
        Self {
            ssh: enabled(tri(args.ssh, args.no_ssh), cfg.ssh),
            gpg: enabled(tri(args.gpg, args.no_gpg), cfg.gpg),
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

/// Add every enabled forward's non-`Mount` pieces: the sockets whose destination differs
/// from their source, and the env vars that point tools at them.
pub fn apply(cmd: &mut Command, ctx: &Context, f: &Forwards) {
    if f.ssh {
        add_ssh_agent(cmd);
    }
    if f.gpg {
        add_gpg_agent(cmd, ctx);
    }
    if f.docker {
        add_docker_socket(cmd, ctx);
    }
}

/// Forward the SSH agent (a signing oracle, not the keys).
fn add_ssh_agent(cmd: &mut Command) {
    if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
        let sock = Path::new(&sock);
        if sock.exists() {
            let s = sock.display();
            cmd.args(["-v", &format!("{s}:{s}")]);
            cmd.args(["-e", "SSH_AUTH_SOCK"]);
        }
    }
}

/// Forward the GPG *extra* (restricted) socket onto the container's normal agent
/// socket path, plus the public keyring read-only. Secret keys stay in the host agent.
fn add_gpg_agent(cmd: &mut Command, ctx: &Context) {
    let Ok(out) = Command::new("gpgconf")
        .args(["--list-dir", "agent-extra-socket"])
        .output()
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
    cmd.args(["-v", &format!("{extra}:{dest}")]);
    let pubring = ctx.home.join(".gnupg/pubring.kbx");
    if pubring.exists() {
        let p = pubring.display();
        cmd.args(["-v", &format!("{p}:{p}:ro")]);
    }
}

/// Mount the limes daemon's own socket into the container as the normal docker
/// socket, so tools inside drive the same daemon (docker-outside-of-docker). Nothing
/// is nested: fixtures the sandbox starts are siblings on the limes daemon, not dind.
fn add_docker_socket(cmd: &mut Command, ctx: &Context) {
    let sock = ctx.socket();
    cmd.args(["-v", &format!("{}:/var/run/docker.sock", sock.display())]);
    cmd.args(["-e", "DOCKER_HOST=unix:///var/run/docker.sock"]);
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
