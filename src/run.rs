//! The default action: assemble and exec `docker run` for a sandbox.

use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};

use crate::RunArgs;
use crate::agents;
use crate::config;
use crate::context::{Context, IMAGE_TAG, LABEL};
use crate::docker;
use crate::mounts::{self, Mount};

pub fn run(ctx: &Context, args: &RunArgs) -> Result<()> {
    let workspace = std::env::current_dir()?;

    // ── Same-path mounts ────────────────────────────────────────────
    // Order matters: on an exact-path collision the *last* entry wins, so this runs
    // from least to most explicit — internal defaults, then the workspace, then the
    // user's own flags, which therefore override everything before them.
    let mut mounts = default_mounts(ctx);
    // Auto-detected agents (program files ro, state dirs rw).
    let detected = agents::detect(ctx, args);
    mounts.extend(detected.mounts);
    // Workspace is read-write by default.
    mounts.push(Mount::rw(workspace.clone()));
    // Standing defaults from ~/.config/limes/config.toml (override the implicit
    // conveniences above, but still lose to the explicit CLI flags below).
    if !args.no_config {
        if let Some(cfg) = config::load(ctx)? {
            mounts.extend(cfg.to_mounts()?);
        }
    }
    // User-supplied holes (canonicalized; must exist on host). `--rw` after `--ro`
    // so a path given both ways ends up writable.
    for p in &args.ro {
        mounts.push(Mount::ro(mounts::canonicalize(p)?));
    }
    for p in &args.rw {
        mounts.push(Mount::rw(mounts::canonicalize(p)?));
    }

    dedupe(&mut mounts);
    mounts::sort_for_nesting(&mut mounts);

    // ── docker run ──────────────────────────────────────────────────
    let mut cmd = docker::command(ctx);
    cmd.arg("run").arg("--rm").arg("-it");

    // Identity: run as the human, with a matching HOME.
    cmd.args(["-u", &format!("{}:{}", ctx.uid, ctx.gid)]);
    cmd.args(["-e", &format!("HOME={}", ctx.home.display())]);
    cmd.args(["-w", &path_str(&workspace)]);

    // Marker so shells/scripts/tooling inside can tell they're in a limes sandbox:
    // presence means "inside limes", value is the version. It's the crate version, so
    // it never drifts from Cargo.toml / `lim --version`.
    cmd.args(["-e", concat!("LIMES_VERSION=", env!("CARGO_PKG_VERSION"))]);

    // Security posture: no new privileges, drop all caps, read-only rootfs, seccomp
    // left enabled. Never --privileged — the sandbox bounds reach, it doesn't grant it.
    cmd.args(["--security-opt", "no-new-privileges"]);
    cmd.args(["--cap-drop", "ALL"]);
    cmd.arg("--read-only");

    // Writable, ephemeral scratch: /tmp and an empty HOME the shell can write to.
    // The bind mounts below layer real dotfiles/state on top of the HOME tmpfs.
    cmd.args(["--tmpfs", "/tmp:exec"]);
    cmd.args(["--tmpfs", &format!("{}:exec", ctx.home.display())]);

    // Labels — what makes status/exec/stop/prune possible.
    let name = args.name.clone().unwrap_or_else(|| derive_name(&workspace));
    cmd.args(["--name", &name]);
    cmd.args(["--label", &format!("{LABEL}=1")]);
    cmd.args(["--label", &format!("{LABEL}.workspace={}", workspace.display())]);
    cmd.args(["--label", &format!("{LABEL}.cmd={}", cmd_label(args))]);

    // Forwarded credentials & sockets (dest may differ from source → not Mounts).
    add_ssh_agent(&mut cmd);
    add_gpg_agent(&mut cmd, ctx);
    add_docker_socket(&mut cmd, ctx);

    // User env passthrough.
    for e in &args.env {
        cmd.args(["-e", e]);
    }

    // All same-path mounts.
    for m in &mounts {
        cmd.args(["-v", &m.to_arg()]);
    }

    cmd.arg(IMAGE_TAG);
    if args.cmd.is_empty() {
        cmd.args(["zsh", "-l"]);
    } else {
        cmd.args(&args.cmd);
    }

    if args.dry_run {
        println!("{}", render(&cmd));
        return Ok(());
    }

    preflight(ctx)?;
    if !detected.names.is_empty() {
        eprintln!("limes: agents available: {}", detected.names.join(", "));
    }
    docker::run(cmd)
}

/// Host-userland mirror + the `/etc` handful + creds that are plain read files.
/// These use literal paths (no canonicalize): dotfiles in `$HOME` are symlinks into
/// a repo, and we want them mounted at the `$HOME` path, letting docker resolve the
/// symlink source itself.
fn default_mounts(ctx: &Context) -> Vec<Mount> {
    let mut m = Vec::new();

    // Host userland, read-only: the box gets the host's exact tools/compilers.
    // The image supplies the /bin→usr/bin (etc.) symlinks that resolve into this.
    m.push(Mount::ro("/usr".into()));

    // The /etc handful — never /etc wholesale (Docker owns resolv.conf/hosts).
    for p in ["/etc/passwd", "/etc/group", "/etc/ssl", "/etc/ld.so.cache", "/etc/localtime"] {
        let p = Path::new(p);
        if p.exists() {
            m.push(Mount::ro(p.into()));
        }
    }

    // Shell config (symlinks into the dotfiles repo resolve host-side).
    for rel in [".zshenv", ".zprofile", ".zprofile.local", ".zshrc", ".zshrc.local"] {
        let p = ctx.home.join(rel);
        if p.exists() {
            m.push(Mount::ro(p));
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

/// Verify the daemon is up and the image is built before running.
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
        if let Some(existing) = out.iter_mut().find(|e| e.host == m.host) {
            existing.read_only = m.read_only;
        } else {
            out.push(m);
        }
    }
    *mounts = out;
}

fn derive_name(workspace: &Path) -> String {
    let base = workspace
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "root".into());
    let sanitized: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    format!("limes-{}", sanitized.trim_matches('-'))
}

fn cmd_label(args: &RunArgs) -> String {
    if args.cmd.is_empty() { "zsh".into() } else { args.cmd.join(" ") }
}

fn path_str(p: &Path) -> String {
    p.display().to_string()
}

/// Render a Command as a copy-pasteable shell line for `--dry-run`.
fn render(cmd: &Command) -> String {
    let mut parts = vec![cmd.get_program().to_string_lossy().to_string()];
    for a in cmd.get_args() {
        parts.push(shell_quote(&a.to_string_lossy()));
    }
    parts.join(" ")
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_=:/.,@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}
