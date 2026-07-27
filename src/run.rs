//! The default action: assemble and exec a sandbox.
//!
//! Two backends. On Linux that means `docker run` against the dedicated rootless daemon,
//! with the host userland mirrored in. On macOS it means `sandbox-exec` with a generated
//! SBPL profile — no container, because the process is already on the host and there is
//! nothing to mirror (see `MACOS-BACKEND.md`).
//!
//! **The mount table is shared.** Both backends consume the same deduped, depth-sorted
//! `Vec<Mount>` produced by the same precedence chain; only the final translation differs
//! — docker flags on one side, SBPL rules on the other.

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
use anyhow::Context as _;
use anyhow::{Result, bail};

use crate::RunArgs;
use crate::agents;
use crate::config;
use crate::context::{self, Context};
#[cfg(target_os = "linux")]
use crate::identity;
use crate::local;
use crate::mounts::{self, Mount};
#[cfg(target_os = "linux")]
use crate::mounts::{Bind, MountArg, Tmpfs};

#[cfg(target_os = "linux")]
use crate::context::{IMAGE_TAG, LABEL};
#[cfg(target_os = "linux")]
use crate::docker;
#[cfg(target_os = "linux")]
use crate::forward::{self, Forwards};
#[cfg(target_os = "linux")]
use crate::sandbox;

/// Assemble the mount table: the shared half of both backends.
///
/// Order is least-to-most explicit; `dedupe` then collapses exact-path collisions with
/// last-wins, and `sort_for_nesting` orders parent-before-child. That ordering is what
/// makes nesting work on *both* backends — Docker layers the binds, Seatbelt takes the
/// last matching rule.
fn assemble_mounts(
    ctx: &Context,
    args: &RunArgs,
    cfg: &Option<config::Config>,
    local: config::Resolved,
    workspace: &Path,
    extra: Vec<Mount>,
) -> Result<config::Resolved> {
    let mut mounts = default_mounts(ctx);
    mounts.extend(extra);
    // Workspace is read-write by default.
    mounts.push(Mount::rw(workspace.to_path_buf()));
    // Standing defaults from config.toml + config.d/*.toml (override the implicit
    // conveniences above, but still lose to the explicit CLI flags below). `link`
    // entries additionally produce symlinks to recreate inside the sandbox.
    let mut symlinks: Vec<config::SymlinkSpec> = Vec::new();
    let mut env: Vec<config::EnvEntry> = Vec::new();
    if let Some(cfg) = cfg {
        let resolved = cfg.resolve()?;
        mounts.extend(resolved.mounts);
        symlinks = resolved.symlinks;
        env = resolved.env;
    }
    // Approved `.limes.local.toml` files, already ordered shallowest-first by `local::load`
    // so a per-repo file beats the shared one above it. More specific than the machine's
    // config, less so than a flag typed for this run.
    mounts.extend(local.mounts);
    symlinks.extend(local.symlinks);
    // Same tier order for `[env]` as for `[mounts]` — and it is only *this* order that the
    // two share. Env has no nesting to sort and no exact-path collisions to resolve, so it
    // leaves here as a plain list; `resolve_env` collapses it against the layers this
    // function never sees (the built-ins, the forwards, the CLI).
    env.extend(local.env);
    // User-supplied holes (canonicalized; must exist on host). `--rw` after `--ro`
    // so a path given both ways ends up writable, and `--hide` after both: it is the
    // safety direction, so `--rw X --hide X` hides.
    //
    // The paths named here are remembered for `workspace_downgrade`: typing one is a
    // deliberate choice, and the warning is only for the silent kind.
    let mut cli_named: Vec<PathBuf> = Vec::new();
    for p in &args.ro {
        let p = mounts::canonicalize(p)?;
        cli_named.push(p.clone());
        mounts.push(Mount::ro(p));
    }
    for p in &args.rw {
        mounts.push(Mount::rw(mounts::canonicalize(p)?));
    }
    for p in &args.hide {
        // Missing is a no-op rather than an error — see `mounts::resolve_hide`.
        if let Some((p, mode)) = mounts::resolve_hide(p)? {
            cli_named.push(p.clone());
            mounts.push(Mount::hide(p, mode));
        }
    }

    guard_trust_store(&mounts, &ctx.trust_dir())?;
    dedupe(&mut mounts);
    mounts::sort_for_nesting(&mut mounts);
    if let Some(what) = workspace_downgrade(&mounts, workspace, &cli_named) {
        let w = workspace.display();
        eprintln!("limes: warning: the workspace {w} is {what} inside the sandbox");
        eprintln!(
            "limes: a `[mounts]` entry (config.toml, config.d/*.toml or an approved \
             .limes.local.toml) names it, and those layers beat the workspace's own \
             read-write default — pass `--rw {w}` to override for this run"
        );
    }
    Ok(config::Resolved { mounts, symlinks, env })
}

/// Whether the resolved table has taken the workspace away from the caller, and how.
///
/// The workspace is the one tree limes exists to make writable, so a table handing it back
/// read-only is nearly always an accident rather than a choice. The mechanism is the
/// documented precedence chain working exactly as specified: `[mounts]` sits *after* the
/// workspace, so a config entry naming the workspace path — a machine-wide drop-in that
/// mounts some repo `ro`, say — collides on the exact path and wins by last-wins `dedupe`.
/// Nothing else says so, and the symptom is an `EROFS` from an editor that names neither
/// the config file nor the collision.
///
/// **Warn, never refuse.** A read-only workspace is a legitimate thing to want (inspecting
/// a tree you would rather not touch), and the point of the precedence chain is that the
/// later layer means what it says. This only reports that nobody typed it *this run*.
///
/// A path named on the CLI is therefore silent: `--ro .` is someone asking for precisely
/// this outcome, and warning about what was just typed is the noise that teaches people to
/// stop reading warnings. Nesting is silent too, and correctly — a `--ro` on some ancestor
/// leaves the workspace its own deeper, writable mount, which is the feature.
fn workspace_downgrade(
    mounts: &[Mount],
    workspace: &Path,
    cli_named: &[PathBuf],
) -> Option<&'static str> {
    if cli_named.iter().any(|p| p == workspace) {
        return None;
    }
    match mounts.iter().find(|m| m.path == workspace)?.kind {
        mounts::Kind::Rw => None,
        mounts::Kind::Ro => Some("read-only"),
        mounts::Kind::Hide(_) => Some("hidden"),
    }
}

/// The project files' contribution, or nothing when `--no-local` says so.
///
/// Shared by both backends rather than inlined twice: the gate has to be impossible to
/// reach one path without, and a second copy is how one of them ends up not calling it.
fn local_mounts(ctx: &Context, args: &RunArgs, workspace: &Path) -> Result<config::Resolved> {
    if args.no_local {
        return Ok(config::Resolved::empty());
    }
    local::load(&ctx.trust_dir(), &ctx.home, workspace)
}

/// Refuse any policy that would let the sandbox write the trust store.
///
/// The whole of `local.rs`'s gate rests on the approvals living somewhere the sandbox
/// cannot reach. Nothing mounts `~/.local` wholesale today — `agents.rs` avoids it
/// deliberately — but a config drop-in is free to, and the failure would be *silent*: the
/// gate would keep printing refusals and keep approving whatever a sandbox had written.
/// Checked before `dedupe` so a widening entry cannot be collapsed away before we look.
///
/// Only `Rw` matters. A `Hide` over the store leaves it unwritable and unreadable inside,
/// which is the status quo; `Ro` hands over an approval ledger that grants nothing on its
/// own, and the store's own contents are not secrets.
fn guard_trust_store(mounts: &[Mount], trust_dir: &Path) -> Result<()> {
    // Both sides resolved as far as they exist, not compared as written: `starts_with` is
    // component-wise, so a `..` in either path would fake a match, and — the direction that
    // actually matters — a symlinked `~/.local` would hide a real one.
    let store = mounts::resolve_existing(trust_dir);
    for m in mounts.iter().filter(|m| m.kind == mounts::Kind::Rw) {
        if store.starts_with(mounts::resolve_existing(&m.path)) {
            bail!(
                "refusing to run: `{}` is mounted read-write, which puts the project-file \
                 trust store ({}) inside the sandbox.\n  \
                 A sandbox that can write its own approvals is not gated at all — narrow \
                 that mount, or hide the store inside it.",
                m.path.display(),
                trust_dir.display()
            );
        }
    }
    Ok(())
}

/// Variables limes sets itself and then relies on, which no config or flag may restate.
///
/// Not a taste rule. `HOME` is *computed against* in two other places — `mounts::invented_dirs`
/// keys the fabricated-directory scan off `ctx.home`, and `identity::passwd` bakes it into the
/// `/etc/passwd` that makes uid 0 present as the user — so overriding it here does not produce
/// a differently-configured sandbox, it produces an inconsistent one, with a `$HOME` the mount
/// table knows nothing about. `LIMES_VERSION` is the marker scripts detect the sandbox with
/// (`[[ -n $LIMES_VERSION ]]`); a forgeable one is worse than none.
///
/// `XDG_RUNTIME_DIR` is deliberately *not* here. It names a directory that is mounted, so a
/// wrong value is caught by the mount table rather than by a rule, and pointing it elsewhere
/// is a thing someone may legitimately want.
const RESERVED_ENV: &[&str] = &["HOME", "LIMES_VERSION"];

/// The name half of a `NAME=VALUE` entry (or the whole thing, for the bare `-e NAME` form).
fn env_name(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(n, _)| n)
}

/// Collapse duplicate names, last wins, keeping the first occurrence's position.
///
/// The same shape as `dedupe` for mounts, and for the same reason: the layers are pushed
/// least-to-most explicit, so "last wins" *is* the precedence rule. Position is kept from
/// the first occurrence purely so `--dry-run` reads in tier order.
///
/// Canonicalising here rather than leaving it to Docker is load-bearing now that `policy`
/// compares the environment exactly — a spec holding two entries for one name would be
/// compared against whichever single one the daemon chose to record.
fn dedupe_env(env: &mut Vec<String>) {
    let mut out: Vec<String> = Vec::new();
    for e in env.drain(..) {
        match out.iter_mut().find(|x| env_name(x) == env_name(&e)) {
            Some(existing) => *existing = e,
            None => out.push(e),
        }
    }
    *env = out;
}

/// Normalise one `-e` argument to `NAME=VALUE`.
///
/// The bare `-e NAME` form means "whatever the host has", and it is resolved *here* rather
/// than handed to Docker to look up. Two reasons: the spec has to hold what docker is
/// actually told, or `policy` compares a `NAME` against the daemon's `NAME=value` and refuses
/// every join; and Docker drops a bare name whose variable is unset without a word, which is
/// the silent-wrong-answer this codebase spends its error messages avoiding. A missing one is
/// a hard error instead, the same way a mount path that does not exist is.
fn cli_env(raw: &str) -> Result<String> {
    if let Some((name, _)) = raw.split_once('=') {
        if name.is_empty() {
            bail!("`-e {raw}`: an environment variable name cannot be empty");
        }
        return Ok(raw.to_string());
    }
    let value = std::env::var(raw).map_err(|_| {
        anyhow::anyhow!(
            "`-e {raw}` passes the host's `{raw}` through, but it is not set — \
             write `-e {raw}=<value>` to give one"
        )
    })?;
    Ok(format!("{raw}={value}"))
}

/// The sandbox's environment, assembled least-to-most explicit:
///
/// ```text
/// built-ins → system gitconfig → forwards → config.toml/config.d → .limes.local.toml → -e
/// ```
///
/// Config sits on the same side of the forwards as the CLI does, because it is the user
/// speaking too — just less specifically. `dedupe_env` then applies last-wins across the lot.
///
/// **This is where the layers meet, and so it is where they are checked.** `config.rs` and
/// `local.rs` each hand over a plain map and validate nothing; putting `RESERVED_ENV` in
/// either would leave the other free to set `HOME`, and a duplicated rule is one that drifts.
#[cfg(target_os = "linux")]
fn resolve_env(
    ctx: &Context,
    args: &RunArgs,
    system_gitconfig: bool,
    forwarded: Vec<String>,
    configured: Vec<config::EnvEntry>,
) -> Result<Vec<String>> {
    let mut env = vec![
        format!("HOME={}", ctx.home.display()),
        // Marker so shells/scripts/tooling inside can tell they're in a limes sandbox:
        // presence means "inside limes", value is the version. It's the crate version, so
        // it never drifts from Cargo.toml / `lim --version`.
        concat!("LIMES_VERSION=", env!("CARGO_PKG_VERSION")).to_string(),
        // Mirrored from the host rather than translated to the container's uid 0: every
        // other path limes mirrors is identical inside and out, and a literal
        // `/run/user/1000` in a script or unit file has to keep meaning what it means on
        // the host. gnupg is unaffected either way -- it keys off `/run/user/<uid>`
        // existing, not off this variable.
        format!("XDG_RUNTIME_DIR={}", ctx.xdg_runtime_dir.display()),
    ];
    // Point git's *system* config tier at the file mounted above. Nothing else supplies one
    // inside — `/etc/gitconfig` is not among the `/etc` handful `default_mounts` mirrors —
    // so this suppresses nothing that was reachable anyway.
    if system_gitconfig {
        env.push(format!("GIT_CONFIG_SYSTEM={}", ctx.gitconfig_file().display()));
    }
    // Forward env before the user's, so an explicit `-e` still wins over what a forward sets.
    env.extend(forwarded);

    for e in configured {
        check_name(&e.name, &e.source)?;
        env.push(format!("{}={}", e.name, e.value));
    }
    for raw in &args.env {
        let entry = cli_env(raw)?;
        check_name(env_name(&entry), "`-e`")?;
        env.push(entry);
    }

    dedupe_env(&mut env);
    Ok(env)
}

/// Refuse a name limes cannot honor, naming where it came from and why.
///
/// The `=` rule is not cosmetic. A TOML key is an arbitrary string, so `"HOME=x" = ""`
/// renders as `HOME=x=` — which Docker reads as `HOME` with the value `x=`, walking straight
/// past `RESERVED_ENV`. Rejecting the separator in a name closes that, and it costs nothing:
/// no environment variable can contain one anyway.
#[cfg(target_os = "linux")]
fn check_name(name: &str, source: &str) -> Result<()> {
    if name.is_empty() {
        bail!("{source} sets a variable with an empty name");
    }
    if name.contains('=') {
        bail!(
            "{source} sets `{name}`, but an environment variable name cannot contain `=` — \
             the name is the key, the value goes on the right of it"
        );
    }
    if RESERVED_ENV.contains(&name) {
        bail!(
            "{source} sets `{name}`, which limes sets itself and depends on elsewhere — \
             a sandbox with a different one is broken, not differently configured"
        );
    }
    Ok(())
}

/// Everything docker will be told about this sandbox, in one value.
///
/// Assembled up front rather than pushed onto a `Command` as each piece is computed,
/// because joining a running sandbox has to compare a *requested* policy against a
/// *running* one. That comparison must enumerate all of it — the mount table, the identity
/// binds, the forwarded sockets, the scratch tmpfs, the hostname — and any piece that
/// emitted its own args on the side would be silently missing from it, and would stay
/// missing as more pieces are added.
///
/// Deliberately absent: `TERM`/`COLORTERM`, which describe the terminal a *shell* is
/// attached to rather than the sandbox, and are passed per-exec.
#[cfg(target_os = "linux")]
pub struct RunSpec {
    pub name: String,
    pub hostname: String,
    pub workspace: PathBuf,
    /// Every mount docker will make, in emission order: the identity binds, the scratch
    /// tmpfs, the forwarded sockets, then the deduped depth-sorted table. Relative order
    /// within this list is load-bearing — it is what layers a `hide` over its parent.
    pub mounts: Vec<MountArg>,
    /// `NAME=VALUE`, deduped last-wins in tier order — see `resolve_env`. Canonical rather
    /// than merely appended, because `policy` compares it exactly against `docker inspect`.
    pub env: Vec<String>,
    pub labels: Vec<String>,
    pub symlinks: Vec<config::SymlinkSpec>,
    /// Whether the container joins the host network (rootlesskit's namespace). Part of the
    /// spec, so the join-policy diff refuses to attach a bridge shell to a host-net sandbox.
    pub host_network: bool,
    /// GPU device nodes to pass (`--device`), resolved from the host at build time. Part of
    /// the spec so the join-policy diff refuses to attach a no-GPU shell to a GPU sandbox.
    pub devices: Vec<String>,
    /// Whether to launch the in-sandbox Docker API proxy from the init prelude. Tracks the
    /// docker forward: on means tools inside get a labeled socket whose containers are reaped
    /// on teardown. Not compared by the policy diff itself — but the `/run/limes` tmpfs and
    /// hidden socket mounts it rides with are, which is what keeps a join honest.
    pub docker_proxy: bool,
    pub cmd: Vec<String>,
}

/// Resolve the whole sandbox policy. Also returns the detected agent names, which are for
/// the user-facing message only and deliberately not part of the spec.
#[cfg(target_os = "linux")]
fn build_spec(ctx: &Context, args: &RunArgs) -> Result<(RunSpec, Vec<String>)> {
    let workspace = std::env::current_dir()?;
    check_workspace(ctx, &workspace)?;

    // Config feeds both the mounts below and the forwards further down, so load it once
    // up front. `--no-config` means *entirely* ignored, forwards included.
    let cfg = if args.no_config { None } else { config::load(ctx)? };
    let forwards = Forwards::resolve(args, cfg.as_ref().map(|c| c.forward()));

    // Project files, gated on the trust store — this is where an unapproved or edited
    // `.limes.local.toml` refuses the run, before anything has been created.
    let local = local_mounts(ctx, args, &workspace)?;

    // Auto-detected agents (program files ro, state dirs rw), plus rosa's socket and
    // client binary — both same-path, so they ride the normal precedence chain rather
    // than being bolted on as raw binds the way ssh/gpg have to be.
    let detected = agents::detect(ctx, args);
    let mut extra = detected.mounts.clone();
    extra.extend(forward::rosa_mounts(ctx, forwards.rosa));

    // The generated system gitconfig, which stops git rebuilding its index on every run
    // inside — see `identity::SYSTEM_GITCONFIG` for why uid 0 causes that. Resolved the
    // same way the forwards are (built-in default → config → CLI), though it forwards
    // nothing, so it reuses their helpers rather than restating the rule.
    //
    // It rides `extra` rather than `default_mounts` because that is the seam that has the
    // resolved switch; the tier is the same either way, so config and `--ro`/`--rw` still
    // override the path. Written here, before the table is assembled, because a mount whose
    // path does not exist is a hard error.
    let system_gitconfig = forward::enabled(
        forward::tri(args.system_gitconfig, args.no_system_gitconfig),
        cfg.as_ref().and_then(|c| c.system_gitconfig()),
    );
    if system_gitconfig {
        std::fs::write(ctx.gitconfig_file(), identity::SYSTEM_GITCONFIG)
            .with_context(|| format!("writing {}", ctx.gitconfig_file().display()))?;
        extra.push(Mount::ro(ctx.gitconfig_file()));
    }

    let host_network = forward::enabled(
        forward::tri(args.host_network, args.no_host_network),
        cfg.as_ref().and_then(|c| c.host_network()),
    );

    // GPU on by default, but that only means "pass what's there": on a machine with no GPU
    // `gpu_devices` is empty and the default costs nothing. `--no-gpu` forces it empty even
    // where a GPU exists.
    let devices = if forward::enabled(
        forward::tri(args.gpu, args.no_gpu),
        cfg.as_ref().and_then(|c| c.gpu()),
    ) {
        gpu_devices()
    } else {
        Vec::new()
    };

    let assembled = assemble_mounts(ctx, args, &cfg, local, &workspace, extra)?;
    let table = assembled.mounts;
    let mut symlinks = assembled.symlinks;
    // An agent's launcher symlink is recreated the same way config's `link = "parent"`
    // entries are — one prelude, one mechanism.
    symlinks.extend(detected.symlinks);

    // uid 0 has to *look* like the human, or `whoami` says root and every mounted file
    // lists as root. These, with the gpg and docker sockets in `forward.rs`, are the only
    // mounts whose destination differs from their source.
    std::fs::write(
        ctx.passwd_file(),
        identity::passwd(&read_etc("/etc/passwd"), ctx.uid, &ctx.home),
    )
    .with_context(|| format!("writing {}", ctx.passwd_file().display()))?;
    std::fs::write(ctx.group_file(), identity::group(&read_etc("/etc/group"), ctx.gid))
        .with_context(|| format!("writing {}", ctx.group_file().display()))?;
    let mut mounts = vec![
        MountArg::Bind(Bind::new(path_str(&ctx.passwd_file()), "/etc/passwd", true)),
        MountArg::Bind(Bind::new(path_str(&ctx.group_file()), "/etc/group", true)),
    ];

    // Writable, ephemeral scratch: /tmp and an empty HOME the shell can write to.
    // The bind mounts below layer real dotfiles/state on top of the HOME tmpfs.
    //
    // `mode=1777` is belt-and-braces. A tmpfs defaults to 1777, but when `-w` names a path
    // *inside* it — which it does whenever the workspace lives under $HOME — Docker creates
    // that directory chain and leaves the tmpfs root owned by uid 0 at 0755. That is
    // harmless while we run as uid 0, but it silently breaks the symlink prelude (and
    // anything else writing to $HOME) the moment the container user is anyone else. Keep it
    // pinned so the mode never depends on the uid. Matches /tmp, which the image chmods.
    mounts.push(MountArg::Tmpfs(Tmpfs::new(Path::new("/tmp"), "exec")));
    mounts.push(MountArg::Tmpfs(Tmpfs::new(&ctx.home, "exec,mode=1777")));
    // The session runtime dir, at the host's path and with `$XDG_RUNTIME_DIR` set to it
    // below. Host config routinely computes a path from that variable -- an ssh-agent
    // socket is the usual one -- and with the variable unset those expand to nonsense
    // (`$XDG_RUNTIME_DIR/ssh-agent.socket` becomes `/ssh-agent.socket`), silently
    // overwriting a socket limes had forwarded correctly. A login shell inside would then
    // find no agent while `lim ssh-add -l`, which runs no login shell, worked.
    //
    // A tmpfs rather than nothing, so the directory exists even when no forward puts a
    // socket in it, and 0700 because that is what the spec promises anything writing here.
    // It is scaffolding: the forwarded sockets mount on top of it, so it has to come first.
    mounts.push(MountArg::Tmpfs(Tmpfs::new(&ctx.xdg_runtime_dir, "mode=0700")));
    // A writable home for the docker proxy's listen socket: the rootfs is read-only, so the
    // proxy (see `docker_proxy`) has nowhere to `bind()` without this. Only when the docker
    // forward is on, so a `--no-docker` sandbox carries neither the tmpfs nor the proxy — and
    // the policy diff then correctly refuses to cross the two.
    if forwards.docker {
        mounts.push(MountArg::Tmpfs(Tmpfs::new(Path::new(forward::PROXY_LISTEN_DIR), "mode=0700")));
    }
    // Everything above is scaffolding that exists before any host path is mirrored, which
    // is what makes it the right place to splice the invented directories into below.
    let scaffolding = mounts.len();

    // Forwarded credentials & sockets, then the table. The table comes last so its
    // depth-sorted order survives into the arg list, which is what layers a `hide` over
    // the parent mount it punches a hole in.
    let pieces = forward::pieces(ctx, &forwards);
    mounts.extend(pieces.binds.into_iter().map(MountArg::Bind));
    mounts.extend(table.iter().map(Mount::flatten));

    // Give every directory Docker has to fabricate under the tmpfs $HOME the mode its host
    // counterpart has, instead of the 0755 Docker invents. See `mounts::invented_dirs` —
    // without it `~/.gnupg` lands 0755 and gpg warns about unsafe permissions on every
    // invocation. Declared as a tmpfs rather than chmod'd in the prelude so it lands in
    // `docker inspect`, and `policy` therefore compares it when joining for free.
    //
    // `exec` because Docker's --tmpfs defaults include `noexec` and `~/.local` holds
    // binaries — the same reason the $HOME tmpfs above passes it.
    let invented: Vec<MountArg> = mounts::invented_dirs(&mounts, &ctx.home, &mounts::host_mode)
        .into_iter()
        .map(|(p, mode)| {
            MountArg::Tmpfs(Tmpfs::new(&p, &format!("exec,{}", mounts::mode_opt(mode))))
        })
        .collect();
    // Spliced in shallowest-first ahead of the mounts they hold, so `--dry-run` reads in
    // nesting order. Docker sorts destinations itself, so this is for the reader.
    mounts.splice(scaffolding..scaffolding, invented);

    let env = resolve_env(ctx, args, system_gitconfig, pieces.env, assembled.env)?;

    // Mirror the host's hostname. Without this the sandbox reports the container ID, which
    // changes every run and reads as noise. CLI beats config, as everywhere else.
    let suffix =
        args.hostname_suffix.as_deref().or_else(|| cfg.as_ref().and_then(|c| c.hostname_suffix()));

    let spec = RunSpec {
        name: args.name.clone().unwrap_or_else(|| derive_name(&workspace)),
        hostname: context::sandbox_hostname(&ctx.hostname, suffix)?,
        // Labels — what makes status/exec/stop/prune possible.
        labels: vec![
            format!("{LABEL}=1"),
            format!("{LABEL}.workspace={}", workspace.display()),
            format!("{LABEL}.cmd={}", cmd_label(args)),
        ],
        workspace,
        mounts,
        env,
        symlinks,
        host_network,
        devices,
        docker_proxy: forwards.docker,
        cmd: if args.cmd.is_empty() { vec!["zsh".into(), "-l".into()] } else { args.cmd.clone() },
    };
    Ok((spec, detected.names))
}

#[cfg(target_os = "linux")]
impl RunSpec {
    /// Render as `docker run` arguments (everything after `docker --host …`).
    ///
    /// Detached, because the container is no longer *a shell* — it is a supervisor that
    /// shells attach to. `--init` is not decoration: see `sandbox`'s module docs.
    pub fn to_run_args(&self) -> Vec<String> {
        let mut a: Vec<String> =
            ["run", "-d", "--init", "--rm"].iter().map(|s| s.to_string()).collect();

        // Identity: run as the human, with a matching HOME.
        //
        // `-u 0:0` is that human, not root. The rootless daemon's user namespace maps the
        // invoking user to container uid 0; container uids 1.. come from the subuid range
        // and own none of the host's files, so `-u {uid}:{gid}` produces a sandbox where the
        // workspace, `~/.claude` and every 0700 dotfile are unreadable and unwritable. Do not
        // "fix" this back. It is safe only because `docker::command` pins every call to
        // limes' own rootless daemon — against a rootful one this would be real root, which
        // is what `doctor`'s rootless check guards. The posture below still applies.
        push(&mut a, ["-u", "0:0"]);
        push(&mut a, ["-w", &path_str(&self.workspace)]);
        push(&mut a, ["--hostname", &self.hostname]);
        // Rootless `--network host` is rootlesskit's namespace, not the real host's, so it
        // does not expose the machine's own services -- but it is where published ports
        // land, which the default bridge cannot reach. `--hostname` still applies over it
        // (verified on the rootless daemon), so hostname mirroring is unaffected.
        if self.host_network {
            push(&mut a, ["--network", "host"]);
        }
        // GPU device nodes. Verified to work under the full posture below (cap-drop ALL,
        // read-only, no-new-privileges) -- passing a device grants access to it, not a
        // capability, so nothing here has to be relaxed.
        for dev in &self.devices {
            push(&mut a, ["--device", dev]);
        }

        // Security posture: no new privileges, drop all caps, read-only rootfs, seccomp
        // left enabled. Never --privileged — the sandbox bounds reach, it doesn't grant it.
        push(&mut a, ["--security-opt", "no-new-privileges"]);
        push(&mut a, ["--cap-drop", "ALL"]);
        a.push("--read-only".into());

        push(&mut a, ["--name", &self.name]);
        for l in &self.labels {
            push(&mut a, ["--label", l]);
        }
        for e in &self.env {
            push(&mut a, ["-e", e]);
        }
        for m in &self.mounts {
            a.extend(m.to_args());
        }

        a.push(IMAGE_TAG.into());
        // PID 1 is a supervisor that does nothing, so that no shell owns any other's fate.
        // The busybox is the image's own, at a path host mounts never shadow — the shell
        // this replaces depended on the `/usr` mirror having arrived.
        a.extend([sandbox::BUSYBOX, "sleep", "infinity"].iter().map(|s| s.to_string()));
        a
    }

    /// The one-shot script that makes a freshly created container usable.
    ///
    /// Docker flattens symlinks on mount, so the host's home symlinks are recreated in the
    /// tmpfs `$HOME` — this is what makes self-locating config (zsh plugin paths derived
    /// from `~/.zshrc`'s own resolved location) work inside.
    ///
    /// It runs against the *container*, not a shell, because it mutates state every shell
    /// shares. The marker guard makes it idempotent, so a joiner can run it unconditionally
    /// and still repair a sandbox whose creator died before initialising it.
    pub fn init_script(&self) -> String {
        let proxy = if self.docker_proxy { proxy_launch(&self.name) } else { String::new() };
        format!(
            "[ -e {m} ] && exit 0; {proxy}{}: > {m}",
            symlink_prelude(&self.symlinks),
            m = sandbox::READY_MARKER
        )
    }
}

/// The launch line for the in-sandbox Docker API proxy, backgrounded and stdio-detached.
///
/// Detached (`>/dev/null 2>&1 &`) so it outlives the one-shot init exec — reparented to tini
/// (PID 1's `--init`), which reaps it — while `sleep infinity` stays PID 1 and no shell owns
/// it. A proxy crash then breaks docker for the sandbox but never takes a shell or its work
/// down. Prepended inside `init_script`'s readiness-marker guard, so it starts exactly once.
///
/// The flags here must match the `__docker-proxy` subcommand in `main.rs`; a test pins that.
#[cfg(target_os = "linux")]
fn proxy_launch(name: &str) -> String {
    format!(
        "{lim} __docker-proxy --upstream {up} --listen {listen} --owner {owner} >/dev/null 2>&1 & ",
        lim = forward::LIM_BIN,
        up = forward::PROXY_UPSTREAM,
        listen = forward::PROXY_LISTEN,
        owner = shell_quote(name),
    )
}

#[cfg(target_os = "linux")]
fn push(out: &mut Vec<String>, pair: [&str; 2]) {
    out.extend(pair.iter().map(|s| s.to_string()));
}

/// The GPU device nodes to pass into the sandbox, empty when the host has no GPU (which is
/// what makes the on-by-default safe -- nothing to pass, nothing happens).
///
/// DRM *render* nodes (`/dev/dri/renderD*`) are the unprivileged GPU interface and all a
/// sandbox needs -- enough for EGL/GBM, which is what an Xvfb or any GL workload trips over
/// when the host's nvidia userland is present but no device is. `card*` nodes are left out
/// on purpose: they carry modesetting/display control the sandbox has no business with.
/// `/dev/nvidia*` (the compute/control nodes) come along when present, for CUDA and
/// `nvidia-smi`; the `nvidia-caps` directory and anything not a character device is skipped.
#[cfg(target_os = "linux")]
fn gpu_devices() -> Vec<String> {
    use std::os::unix::fs::FileTypeExt;

    let is_char = |p: &std::path::Path| {
        std::fs::metadata(p).map(|m| m.file_type().is_char_device()).unwrap_or(false)
    };
    let named = |dir: &str, keep: &dyn Fn(&str) -> bool| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| is_char(p) && p.file_name().and_then(|n| n.to_str()).is_some_and(keep))
            .map(|p| p.display().to_string())
            .collect();
        v.sort();
        v
    };

    let mut devs = named("/dev/dri", &|n| n.starts_with("renderD"));
    devs.extend(named("/dev", &|n| n.starts_with("nvidia")));
    devs
}

/// The terminal is host state, so mirror it. `-t` otherwise makes Docker invent
/// `TERM=xterm` — 8 colours — and a 256-colour prompt or a themed TUI renders washed out
/// inside a sandbox that has the host's own terminfo mounted at /usr/share/terminfo.
///
/// Kept out of `RunSpec` on purpose: these describe the terminal a given *shell* is
/// attached to, not the sandbox, and a second shell can be attached to a different one.
#[cfg(target_os = "linux")]
pub fn term_env() -> Vec<String> {
    ["TERM", "COLORTERM"]
        .iter()
        .filter_map(|var| std::env::var(var).ok().map(|v| format!("{var}={v}")))
        .collect()
}

/// Run, or *join*: a second `lim` in the same workspace attaches to the sandbox already
/// there rather than building a second one beside it. See `sandbox`'s module docs for why.
#[cfg(target_os = "linux")]
pub fn run(ctx: &Context, args: &RunArgs) -> Result<()> {
    let (spec, agent_names) = build_spec(ctx, args)?;
    let env = term_env();

    if args.dry_run {
        // Show what would actually happen — a create only when nothing is running, and in
        // either case the exec that attaches this shell.
        if !docker::container_running(ctx, &spec.name) {
            let mut create = docker::command(ctx);
            create.args(spec.to_run_args());
            println!("{}", render(&create));
        }
        let join = sandbox::join_command(ctx, &spec.name, Some(&spec.workspace), &spec.cmd, &env);
        println!("{}", render(&join));
        return Ok(());
    }

    preflight(ctx)?;

    // Held across "find or create" *and* the shell itself, so another `lim`'s teardown
    // cannot stop the sandbox in the window before this shell exists to be counted.
    let in_flight = sandbox::in_flight(ctx, &spec.name)?;
    let created = sandbox::ensure_running(ctx, &spec)?;
    if created && !agent_names.is_empty() {
        eprintln!("limes: agents available: {}", agent_names.join(", "));
    }
    let code = sandbox::join(ctx, &spec.name, Some(&spec.workspace), &spec.cmd, &env)?;

    drop(in_flight);
    sandbox::release(ctx, &spec.name)?;
    std::process::exit(code);
}

/// The macOS backend: generate an SBPL profile and hand it to `sandbox-exec`.
///
/// Notice how much is *absent* versus the Linux path — no image, no daemon preflight, no
/// uid/gid translation, no credential forwarding, no symlink prelude. All of it existed to
/// reconstruct the host inside a container; here the process is the host already. What is
/// left is the mount table and a write policy.
#[cfg(target_os = "macos")]
pub fn run(ctx: &Context, args: &RunArgs) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let workspace = std::env::current_dir()?;
    let cfg = if args.no_config { None } else { config::load(ctx)? };
    let local = local_mounts(ctx, args, &workspace)?;

    // Agents still matter, but only for their *state* dirs: the program files are already
    // on the host and readable, while `~/.claude` must be writable under the base deny.
    let detected = agents::detect(ctx, args);
    // `.env` is ignored here: `sandbox-exec` replaces this process, so the sandbox inherits
    // the host environment whole and there is no allowlist for `[env]` to add to. Giving it
    // the Linux meaning would mean filtering the inherited environment down to the declared
    // set — a real behaviour change for the experimental backend, not a wiring detail.
    let assembled = assemble_mounts(ctx, args, &cfg, local, &workspace, detected.mounts.clone())?;
    let mounts = assembled.mounts;

    // Seatbelt matches resolved paths, so the temp dir must be canonical
    // (`/private/var/folders/…`); `canonicalize` is realpath.
    let tmpdir = std::env::temp_dir();
    let tmpdir = tmpdir.canonicalize().unwrap_or(tmpdir);
    let profile = crate::seatbelt::profile(&mounts, &tmpdir);

    let inner: Vec<String> =
        if args.cmd.is_empty() { vec!["zsh".into(), "-l".into()] } else { args.cmd.clone() };

    // `-p` takes the profile inline, so there is no temp file to write, secure, or clean
    // up after exec.
    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-p").arg(&profile).args(&inner);

    // Same marker the Linux backend passes as `-e`. `exec` inherits our environment, so
    // without this the sandbox is invisible to anything inside it — shell prompts and
    // scripts detect limes with `[[ -n $LIMES_VERSION ]]`, and a sandbox you cannot tell
    // you are in is worse than no sandbox.
    cmd.env("LIMES_VERSION", env!("CARGO_PKG_VERSION"));

    if args.dry_run {
        println!("{profile}");
        let quoted: Vec<String> = inner.iter().map(|a| shell_quote(a)).collect();
        println!(
            "\n# LIMES_VERSION={} sandbox-exec -p '<the profile above>' {}",
            env!("CARGO_PKG_VERSION"),
            quoted.join(" ")
        );
        return Ok(());
    }

    if !detected.names.is_empty() {
        eprintln!("limes: agents available: {}", detected.names.join(", "));
    }
    // exec() only returns if it fails to replace the process.
    Err(cmd.exec().into())
}

/// Read one of the host's `/etc` identity files. An unreadable one is not fatal: `identity`
/// falls back to a synthesised entry, which beats refusing to start the sandbox.
#[cfg(target_os = "linux")]
fn read_etc(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Host-userland mirror + the `/etc` handful + non-shell credential/state files. Shell
/// rc files are deliberately not here — they arrive via the dotfiles `config.d` drop-in,
/// which recreates their symlinks so self-locating config resolves correctly. This keeps
/// limes free of shell-specific knowledge.
#[cfg(target_os = "linux")]
fn default_mounts(ctx: &Context) -> Vec<Mount> {
    let mut m = Vec::new();

    // Host userland, read-only: the box gets the host's exact tools/compilers.
    // The image supplies the /bin→usr/bin (etc.) symlinks that resolve into this.
    m.push(Mount::ro("/usr".into()));

    // The /etc handful — never /etc wholesale (Docker owns resolv.conf/hosts).
    // `passwd`/`group` are deliberately absent: `run` mounts generated ones instead, so that
    // container uid 0 resolves to the invoking user. The trade is that files owned by *other*
    // host users render as bare numeric uids inside, which is the lesser confusion.
    //
    // `/etc/alternatives` is Debian's indirection layer, and without it a Debian host's
    // /usr is half-broken inside: `/usr/bin/vim` is a symlink to `/etc/alternatives/vim`,
    // as are `editor`, `pager`, `x-terminal-emulator` and ~200 more, so the tools are all
    // mounted and none of them resolve. `exists()` skips it on distros that have no such
    // system (Arch), which is why this never showed up there.
    //
    // `/etc/ca-certificates` is the same shape of trap on Arch: `/etc/ssl` is mounted, but
    // the bundle every TLS client opens through it — `/etc/ssl/certs/ca-certificates.crt` —
    // is a symlink to `/etc/ca-certificates/extracted/tls-ca-bundle.pem`, so without this
    // the mount is a directory of dangling links and *nothing* inside can verify a
    // certificate: `curl` fails with "error adding trust anchors", `cargo fetch` with an
    // SSL peer-certificate error naming neither /etc nor the missing file. Debian keeps a
    // real file at that path and has no such directory, so `exists()` skips it there.
    for p in [
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/ld.so.cache",
        "/etc/localtime",
        "/etc/alternatives",
    ] {
        let p = Path::new(p);
        if p.exists() {
            m.push(Mount::ro(p.into()));
        }
    }

    // git identity/signing config, read-only.
    let gitconfig = ctx.home.join(".gitconfig");
    if gitconfig.exists() {
        m.push(Mount::ro(gitconfig));
    }
    let known_hosts = ctx.home.join(".ssh/known_hosts");
    if known_hosts.exists() {
        m.push(Mount::ro(known_hosts));
    }

    // Claude state/auth, read-write (shared with host; auto-mode via host settings).
    let claude = ctx.home.join(".claude");
    if claude.exists() {
        m.push(Mount::rw(claude));
    }

    m
}

/// macOS needs almost none of the Linux default mounts: `/usr` and the `/etc` handful are
/// the host's own and already readable, and reads are unrestricted under Murphy anyway.
/// What survives is the one entry that must be *writable* — Claude Code's state dir, which
/// it rewrites on auth-token refresh.
#[cfg(target_os = "macos")]
fn default_mounts(ctx: &Context) -> Vec<Mount> {
    let mut m = Vec::new();
    let claude = ctx.home.join(".claude");
    if claude.exists() {
        m.push(Mount::rw(claude));
    }
    m
}

/// Verify the daemon is up and the image is built before running.
#[cfg(target_os = "linux")]
fn preflight(ctx: &Context) -> Result<()> {
    if !docker::daemon_alive(ctx) {
        bail!(
            "limes daemon is not reachable at {}\n  run `lim bootstrap`, then `lim doctor`",
            ctx.socket().display()
        );
    }
    if !docker::image_present(ctx) {
        bail!("image `{IMAGE_TAG}` is not built — run `lim build`");
    }
    Ok(())
}

/// Collapse exact-path collisions, last entry winning. Combined with the
/// least-to-most-explicit push order above, this lets a user `--ro`/`--rw` override
/// the workspace default or an internal default on the very same path.
fn dedupe(mounts: &mut Vec<Mount>) {
    let mut out: Vec<Mount> = Vec::new();
    for m in mounts.drain(..) {
        if let Some(existing) = out.iter_mut().find(|e| e.path == m.path) {
            // The *whole* kind, not some field of it: copying less than this quietly
            // breaks last-wins the moment a mode carries more than read-only-ness.
            existing.kind = m.kind;
        } else {
            out.push(m);
        }
    }
    *mounts = out;
}

/// Cap on a generated container name. Self-imposed — Docker names have no meaningful
/// length limit — and it exists so `lim status` stays scannable.
#[cfg(target_os = "linux")]
const NAME_MAX: usize = 64;

/// Refuse the one workspace that cannot work: `$HOME` itself.
///
/// The sandbox shadows `$HOME` with an empty tmpfs *and* binds the workspace read-write, so
/// naming $HOME as the workspace asks docker for both on one path. What docker says back is
/// "Duplicate mount point: /home/you" -- a complaint about an argument list the caller never
/// wrote, naming neither the tmpfs nor the cwd that produced it. Say it in limes' terms
/// before we get that far.
#[cfg(target_os = "linux")]
fn check_workspace(ctx: &Context, workspace: &Path) -> Result<()> {
    // getcwd is already canonical; $HOME need not be, and comparing a symlinked home
    // against a resolved cwd would miss the very case this exists to catch.
    let home = ctx.home.canonicalize().unwrap_or_else(|_| ctx.home.clone());
    if workspace == home {
        bail!(
            "the workspace is $HOME ({}), which limes shadows with an empty tmpfs so that a \
             sandbox never gets your home wholesale -- the workspace mount and that tmpfs \
             cannot share a path.\ncd into a project directory and re-run.",
            workspace.display()
        );
    }
    Ok(())
}

/// Container name from the **whole** workspace path, not its basename.
///
/// `~/a/test` and `~/b/test` would otherwise both be `limes-test`. Today that surfaces as a
/// confusing Docker name conflict; once `lim` joins a running sandbox it would silently drop
/// you into a sandbox for a *different tree*, mounted read-write.
///
/// A name that is a total function of the path *is* the lookup — `docker inspect <name>`
/// either hits or it does not — so joining needs no `docker ps --filter label=…` scan.
/// `current_dir()` is `getcwd(3)`, already kernel-resolved, so no symlink component survives
/// into the name; two paths aliasing one directory are deliberately out of scope.
///
/// Sanitising flattens `/a/b-c` and `/a-b/c` onto the same name. That collision is accepted
/// and caught downstream by asserting the `limes.workspace` label after the lookup.
#[cfg(target_os = "linux")]
fn derive_name(workspace: &Path) -> String {
    let raw = workspace.to_string_lossy();
    // Non-alphanumerics to `-`; the `limes-` prefix then satisfies Docker's
    // `[a-zA-Z0-9][a-zA-Z0-9_.-]*` leading-character rule for free.
    let sanitized: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let body = sanitized.trim_matches('-');
    if body.is_empty() {
        return "limes-root".into(); // `/`
    }
    if body.len() + "limes-".len() <= NAME_MAX {
        return format!("limes-{body}");
    }
    // Truncate the *front* and append a hash of the full path. The tail is the
    // recognizable part, and truncating the tail instead would collide exactly where
    // paths are most similar — sibling directories.
    let keep = NAME_MAX - "limes-".len() - 1 - 8;
    let tail: String = body.chars().skip(body.chars().count() - keep).collect();
    format!("limes-{}-{:08x}", tail.trim_start_matches('-'), fnv1a(&raw) as u32)
}

/// FNV-1a, inline and deliberately not `DefaultHasher`: the std hasher is documented as
/// unstable across Rust releases, so a toolchain upgrade would silently rename every
/// long-path sandbox and orphan the containers already running under the old names.
#[cfg(target_os = "linux")]
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(target_os = "linux")]
fn cmd_label(args: &RunArgs) -> String {
    if args.cmd.is_empty() { "zsh".into() } else { args.cmd.join(" ") }
}

#[cfg(target_os = "linux")]
fn path_str(p: &Path) -> String {
    p.display().to_string()
}

/// A `sh` script that recreates each symlink in the (writable tmpfs) home, then execs the
/// real command passed as positional parameters (`sh -c '…' limes <cmd…>` → `"$@"`).
#[cfg(target_os = "linux")]
fn symlink_prelude(symlinks: &[config::SymlinkSpec]) -> String {
    let mut s = String::new();
    for sl in symlinks {
        if let Some(parent) = sl.link.parent() {
            s.push_str(&format!(
                "mkdir -p {} 2>/dev/null; ",
                shell_quote(&parent.display().to_string())
            ));
        }
        s.push_str(&format!(
            "ln -sfn {} {}; ",
            shell_quote(&sl.target.display().to_string()),
            shell_quote(&sl.link.display().to_string()),
        ));
    }
    s
}

/// Render a Command as a copy-pasteable shell line for `--dry-run`.
#[cfg(target_os = "linux")]
fn render(cmd: &Command) -> String {
    let mut parts = vec![cmd.get_program().to_string_lossy().to_string()];
    for a in cmd.get_args() {
        parts.push(shell_quote(&a.to_string_lossy()));
    }
    parts.join(" ")
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_=:/.,@".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env chain's precedence rule, in the same shape the mount one has: the layers are
    /// pushed least-to-most explicit, so a later entry for a name simply replaces the earlier.
    /// This is how a `-e` beats `[env]`, and how `[env]` beats what a forward set.
    #[test]
    fn dedupe_env_is_last_wins_in_tier_order() {
        let mut e = vec![
            "SSH_AUTH_SOCK=/forwarded".to_string(),
            "RUST_LOG=info".to_string(),
            "SSH_AUTH_SOCK=/mine".to_string(),
        ];
        dedupe_env(&mut e);
        assert_eq!(
            e,
            vec!["SSH_AUTH_SOCK=/mine".to_string(), "RUST_LOG=info".to_string()],
            "the later value wins, at the earlier one's position"
        );
    }

    /// A value may contain `=`; only the first one separates. Splitting on all of them would
    /// make `FOO=a=b` and `FOO=a=c` look like different variables and both survive dedupe.
    #[test]
    fn env_name_splits_on_the_first_equals_only() {
        assert_eq!(env_name("GIT_SSH_COMMAND=ssh -o X=y"), "GIT_SSH_COMMAND");
        let mut e = vec!["A=x=1".to_string(), "A=x=2".to_string()];
        dedupe_env(&mut e);
        assert_eq!(e, vec!["A=x=2".to_string()]);
    }

    /// `-e NAME` means "whatever the host has", and limes resolves it rather than letting
    /// Docker do the lookup — the spec has to hold what docker is actually told, or `policy`
    /// compares a bare `NAME` against the daemon's `NAME=value` and refuses every join.
    #[test]
    fn a_bare_cli_env_is_resolved_from_the_host() {
        // SAFETY: single-threaded test; the name is this test's own.
        unsafe { std::env::set_var("LIMES_TEST_BARE", "value") };
        assert_eq!(cli_env("LIMES_TEST_BARE").unwrap(), "LIMES_TEST_BARE=value");
        assert_eq!(cli_env("A=b").unwrap(), "A=b", "the explicit form passes through");
    }

    /// Docker drops a bare `-e` whose variable is unset without a word. That silence is the
    /// failure worth avoiding: say so, and say what to write instead.
    #[test]
    fn a_bare_cli_env_that_is_unset_fails_loud() {
        let err = cli_env("LIMES_TEST_DEFINITELY_UNSET").expect_err("an unset name must fail");
        assert!(err.to_string().contains("not set"), "got: {err}");
        assert!(err.to_string().contains("=<value>"), "must name a way out: {err}");
    }

    /// `HOME` is computed against by `mounts::invented_dirs` and `identity::passwd`, so a
    /// config or flag that restates it produces an inconsistent sandbox rather than a
    /// differently-configured one. Refuse, and say which side asked.
    #[test]
    fn reserved_names_are_refused_with_their_source() {
        let err = check_name("HOME", "config").expect_err("HOME must be refused");
        assert!(err.to_string().contains("config sets `HOME`"), "got: {err}");
        assert!(check_name("LIMES_VERSION", "`-e`").is_err());
        assert!(check_name("RUST_LOG", "config").is_ok(), "ordinary names are untouched");
    }

    /// A TOML key is an arbitrary string, so `"HOME=x" = ""` would render as `HOME=x=` —
    /// which Docker reads as `HOME` with the value `x=`, walking straight past the reserved
    /// list. The name is checked before it is joined to its value, so it cannot.
    #[test]
    fn a_name_containing_the_separator_cannot_smuggle_a_reserved_one() {
        let err = check_name("HOME=x", "config").expect_err("`=` in a name must be refused");
        assert!(err.to_string().contains("cannot contain `=`"), "got: {err}");
        assert!(check_name("", "config").is_err(), "nor an empty name");
    }

    /// Last-wins on an exact path is what makes the whole precedence chain work — it is
    /// how a `--ro` beats a config mount, and how either beats the rosa/agent defaults.
    #[test]
    fn dedupe_keeps_last_mode_and_original_order() {
        let mut m = vec![Mount::rw("/a".into()), Mount::ro("/b".into()), Mount::ro("/a".into())];
        dedupe(&mut m);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0], Mount::ro("/a".into()), "later ro downgrades the earlier rw");
        assert_eq!(m[1], Mount::ro("/b".into()));
    }

    /// Last-wins has to hold across *differing* kinds, not just ro-vs-rw — otherwise
    /// `--hide` on a path some default already mounts silently does nothing.
    #[test]
    fn dedupe_is_last_wins_across_kinds() {
        let mut m = vec![Mount::rw("/a".into()), Mount::hide("/a".into(), 0o700)];
        dedupe(&mut m);
        assert_eq!(m, vec![Mount::hide("/a".into(), 0o700)], "hide beats an earlier rw");

        let mut m = vec![Mount::hide("/a".into(), 0o700), Mount::ro("/a".into())];
        dedupe(&mut m);
        assert_eq!(m, vec![Mount::ro("/a".into())], "and is itself overridable");
    }

    /// The case this warning exists for, and the one that produced it: a machine-wide
    /// drop-in mounts a repo `ro` so its symlinks resolve inside every *other* sandbox, and
    /// then one day that repo is the workspace. `[mounts]` is a later tier, so it collides
    /// on the exact path and wins — correct by the precedence chain, and completely silent.
    #[test]
    fn a_config_entry_over_the_workspace_is_reported() {
        let ws = Path::new("/home/u/code/dotfiles");
        let m = vec![Mount::ro(ws.into())];
        assert_eq!(workspace_downgrade(&m, ws, &[]), Some("read-only"));

        let m = vec![Mount::hide(ws.into(), 0o755)];
        assert_eq!(workspace_downgrade(&m, ws, &[]), Some("hidden"), "hide is worse, not better");

        let m = vec![Mount::rw(ws.into())];
        assert_eq!(workspace_downgrade(&m, ws, &[]), None, "the default must stay quiet");
    }

    /// Typing `--ro .` is asking for exactly this, so it must not warn. A warning fired by
    /// what the user just typed is the kind that teaches people to stop reading them.
    #[test]
    fn an_explicitly_named_workspace_is_not_reported() {
        let ws = Path::new("/home/u/code/dotfiles");
        let m = vec![Mount::ro(ws.into())];
        assert_eq!(workspace_downgrade(&m, ws, &[ws.into()]), None);
    }

    /// Nesting is not a downgrade. `--ro ~/code` with the workspace beneath it leaves the
    /// workspace its own deeper, writable mount — the headline feature, and it would be
    /// absurd for it to warn.
    #[test]
    fn a_read_only_ancestor_is_not_a_downgrade() {
        let ws = Path::new("/home/u/code/dotfiles");
        let m = vec![Mount::ro("/home/u/code".into()), Mount::rw(ws.into())];
        assert_eq!(workspace_downgrade(&m, ws, &[]), None);
    }

    /// The assertion `local.rs`'s whole gate rests on. Nothing mounts `~/.local` wholesale
    /// today, but a config drop-in could, and the resulting hole would be silent: refusals
    /// would still print while the sandbox quietly approved its own files.
    #[test]
    fn an_rw_mount_over_the_trust_store_is_refused() {
        let store = Path::new("/home/u/.local/share/limes/trust");
        let err = guard_trust_store(&[Mount::rw("/home/u/.local/share".into())], store)
            .expect_err("an rw ancestor of the store must refuse");
        assert!(err.to_string().contains("trust store"), "got: {err}");

        guard_trust_store(&[Mount::rw("/home/u/code".into())], store)
            .expect("an unrelated rw mount is fine");
        guard_trust_store(&[Mount::ro("/home/u/.local/share".into())], store)
            .expect("read-only grants nothing the gate depends on");
    }

    /// The store's own directory, not just an ancestor of it — the obvious way to write the
    /// check tests `starts_with` in the wrong direction and misses the exact match.
    #[test]
    fn an_rw_mount_of_the_store_itself_is_refused() {
        let store = Path::new("/home/u/.local/share/limes/trust");
        assert!(guard_trust_store(&[Mount::rw(store.to_path_buf())], store).is_err());
    }

    /// `starts_with` is component-wise, so an unresolved `..` makes an unrelated store look
    /// contained. Found by a smoke test whose `XDG_DATA_HOME` happened to be written that
    /// way; the same lexical comparison hides a real containment behind a symlink, which is
    /// the direction worth caring about.
    #[test]
    fn dot_dot_components_do_not_fake_containment() {
        let tmp = std::env::temp_dir().canonicalize().unwrap_or_else(|_| "/tmp".into());
        let ws = tmp.join("limes-guard-ws");
        let store = ws.join("../limes-guard-store/trust");
        guard_trust_store(&[Mount::rw(ws)], &store)
            .expect("`..` climbs back out of the mount, so the store is not inside it");
    }

    /// What `dedupe`'s "copy the *whole* kind" comment is about, now that a kind carries
    /// more than read-only-ness: keeping the variant but not its payload would silently
    /// leave the earlier mode in place.
    #[test]
    fn dedupe_replaces_the_kinds_payload_too() {
        let mut m = vec![Mount::hide("/a".into(), 0o755), Mount::hide("/a".into(), 0o700)];
        dedupe(&mut m);
        assert_eq!(m, vec![Mount::hide("/a".into(), 0o700)]);
    }

    /// The proxy launch must name the exact flags `__docker-proxy` declares in `main.rs`, and
    /// be a detached background job — a typo here would only surface as a dead `DOCKER_HOST`
    /// inside a real sandbox.
    #[cfg(target_os = "linux")]
    #[test]
    fn proxy_launch_matches_the_hidden_subcommand() {
        let s = proxy_launch("limes-proj");
        assert!(s.contains("/limes/lim __docker-proxy"), "{s}");
        assert!(s.contains("--upstream /limes/docker.sock"), "{s}");
        assert!(s.contains("--listen /run/limes/docker.sock"), "{s}");
        assert!(s.contains("--owner limes-proj"), "{s}");
        assert!(s.trim_end().ends_with('&'), "must be backgrounded: {s}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn derive_name_sanitizes_the_whole_path() {
        assert_eq!(derive_name(Path::new("/home/u/my.proj")), "limes-home-u-my-proj");
    }

    /// The reason the name is the whole path: sibling trees with the same basename must
    /// not share a sandbox, or joining hands you someone else's tree mounted read-write.
    #[cfg(target_os = "linux")]
    #[test]
    fn derive_name_distinguishes_equal_basenames() {
        assert_ne!(
            derive_name(Path::new("/home/u/a/test")),
            derive_name(Path::new("/home/u/b/test"))
        );
    }

    /// Flattening non-alphanumerics means these two *do* collide. Asserted so the
    /// limitation is documented rather than discovered — the `limes.workspace` label
    /// assertion after the lookup is what turns it into an error instead of a silent join.
    #[cfg(target_os = "linux")]
    #[test]
    fn derive_name_flattening_collision_is_known() {
        assert_eq!(derive_name(Path::new("/a/b-c")), derive_name(Path::new("/a-b/c")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn derive_name_falls_back_at_the_root() {
        assert_eq!(derive_name(Path::new("/")), "limes-root");
    }

    /// Truncation must stay bounded, keep the recognizable tail, be a pure function of the
    /// path, and still tell apart two paths that differ only in the part it cut off.
    #[cfg(target_os = "linux")]
    #[test]
    fn derive_name_truncates_long_paths_with_a_hash() {
        let long =
            Path::new("/home/u/very/deeply/nested/monorepo/services/backend/api/handlers/v2");
        let n = derive_name(long);
        assert!(n.len() <= NAME_MAX, "{n} is {} chars", n.len());
        assert!(n.starts_with("limes-"));
        assert!(n.contains("handlers-v2"), "the tail is the recognizable part: {n}");
        assert_eq!(n, derive_name(long), "must be deterministic");

        let sibling =
            Path::new("/home/u/very/deeply/nested/monorepo/services/frontend/api/handlers/v2");
        assert_ne!(
            n,
            derive_name(sibling),
            "differing only in the truncated head must still differ"
        );
    }
}
