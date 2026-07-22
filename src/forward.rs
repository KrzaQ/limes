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
    /// Hand over `S.gpg-agent` instead of the restricted `S.gpg-agent.extra`.
    pub gpg_unrestricted: bool,
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
            // The only switch here that defaults off — giving away the confirmation is a
            // decision, not a default.
            gpg_unrestricted: tri(args.gpg_unrestricted, args.no_gpg_unrestricted)
                .or(cfg.gpg_unrestricted)
                .unwrap_or(false),
            rosa: enabled(tri(args.rosa, args.no_rosa), cfg.rosa),
            docker: enabled(tri(args.docker, args.no_docker), cfg.docker),
        }
    }
}

/// Built-in default → config → CLI. Everything forwards unless something says otherwise.
///
/// `pub(crate)` because the generated system gitconfig (`run.rs`) is not a forward but
/// resolves identically, and one copy of this rule is better than two that can drift.
pub(crate) fn enabled(cli: Option<bool>, cfg: Option<bool>) -> bool {
    cli.or(cfg).unwrap_or(true)
}

/// Collapse a `--x` / `--no-x` pair into a tri-state. clap's `overrides_with` makes the
/// last flag on the command line the winner, so at most one of these is ever set.
pub(crate) fn tri(yes: bool, no: bool) -> Option<bool> {
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
        add_gpg_agent(&mut p, ctx, f.gpg_unrestricted);
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

/// Forward a GPG agent socket onto the container's normal agent socket path, plus the
/// keyring files read-only. Secret keys stay in the host agent either way.
///
/// `unrestricted` picks `S.gpg-agent` over `S.gpg-agent.extra`. The extra socket confirms
/// every use of a key through pinentry, which is the guard that makes forwarding it to a
/// sandbox reasonable — but gpg-agent will not trust a *client-supplied* tty for that
/// confirmation, so a tty-only pinentry has nowhere to draw it and every signature fails
/// with `Operation cancelled`, cached passphrase or not. On such a host the choice is
/// between this switch and not signing from a sandbox at all.
///
/// What it costs is exact: for as long as the passphrase is cached, anything in the
/// sandbox can sign as you without being asked. The key itself still never enters.
fn add_gpg_agent(p: &mut Pieces, ctx: &Context, unrestricted: bool) {
    let which = if unrestricted { "agent-socket" } else { "agent-extra-socket" };
    let Some(extra) = gpgconf_dir(which) else {
        return;
    };
    if !Path::new(&extra).exists() {
        return;
    }
    // Ask gpg where it lives rather than assuming `~/.gnupg`, so `$GNUPGHOME` is honored —
    // we are already shelling out to `gpgconf` for the socket, so this costs one more call.
    // The fallback keeps the old behaviour for a gpg too old to answer.
    let homedir =
        gpgconf_dir("homedir").map(PathBuf::from).unwrap_or_else(|| ctx.home.join(".gnupg"));
    // Into the *homedir*, not `/run/user/<uid>/gnupg`, because that is where the client
    // inside will look. gnupg uses `/run/user/<uid>/gnupg` only when `/run/user/<uid>`
    // exists and otherwise falls back to the homedir -- and the sandbox runs as uid 0,
    // whose `/run/user/0` does not exist. Forwarding to the host uid's path put the socket
    // somewhere nothing inside ever consulted: gpg found no agent, reported "No secret key"
    // for a key the host signs with happily, and nothing named the socket.
    let dest = homedir.join("S.gpg-agent");
    p.binds.push(Bind::new(extra, dest.display().to_string(), false));
    p.binds.extend(gnupg_binds(&homedir));
}

/// One `gpgconf --list-dir` entry, or `None` if gpg cannot be asked.
fn gpgconf_dir(key: &str) -> Option<String> {
    let out = Command::new("gpgconf").args(["--list-dir", key]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if dir.is_empty() { None } else { Some(dir) }
}

/// The files from a gpg homedir worth binding read-only, skipping any that are absent.
///
/// **Neither is key material**, so the oracle rule is intact: `pubring.kbx` is public by
/// definition, and `trustdb.gpg` holds ownertrust *assignments* — the same class. Without
/// the trustdb every signature verifies but reports unknown validity, so
/// `git log --format=%G?` is uniformly `U`, and a status that never varies is a status
/// nobody reads.
///
/// Mounting the trustdb read-only costs `gpg: Note: trustdb not writable` on verbose
/// operations. A note, not an error — and a write to a trustdb inside an ephemeral sandbox
/// would be meaningless anyway. If it ever grates, copy it into `$XDG_RUNTIME_DIR` and bind
/// *that* writable, exactly as `identity.rs` does for the generated `/etc/passwd`.
fn gnupg_binds(homedir: &Path) -> Vec<Bind> {
    ["pubring.kbx", "trustdb.gpg"]
        .iter()
        .map(|f| homedir.join(f))
        .filter(|p| p.exists())
        .map(|p| Bind::same_path(&p, true))
        .collect()
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

    /// Each file rides on its own existence, so a host with no trustdb is unaffected and one
    /// with a trustdb stops reporting every signature as unknown-validity.
    #[test]
    fn gnupg_binds_take_whichever_files_exist() {
        let dir = std::env::temp_dir().join(format!("limes-gnupg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp homedir");

        assert!(gnupg_binds(&dir).is_empty(), "an empty homedir mounts nothing");

        std::fs::write(dir.join("pubring.kbx"), "").unwrap();
        let one = gnupg_binds(&dir);
        assert_eq!(one.len(), 1, "{one:?}");
        assert!(one[0].src.ends_with("pubring.kbx"), "{one:?}");

        std::fs::write(dir.join("trustdb.gpg"), "").unwrap();
        let both = gnupg_binds(&dir);
        assert_eq!(both.len(), 2, "the trustdb joins the pubring: {both:?}");
        // Read-only and same-path: these are oracles the sandbox reads, never writes.
        assert!(both.iter().all(|b| b.ro && b.src == b.dst), "{both:?}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tri_collapses_flag_pair() {
        assert_eq!(tri(false, false), None);
        assert_eq!(tri(true, false), Some(true));
        assert_eq!(tri(false, true), Some(false));
    }
}
