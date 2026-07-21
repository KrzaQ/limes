//! The default action: assemble and exec a sandbox.
//!
//! Two backends. On Linux that means `docker run` against the dedicated rootless daemon,
//! with the host userland mirrored in. On macOS it means `sandbox-exec` with a generated
//! SBPL profile — no container, because the process is already on the host and there is
//! nothing to mirror (see `MACOS-BACKEND.md`).
//!
//! **The mount table is shared.** Both backends consume the same deduped, depth-sorted
//! `Vec<Mount>` produced by the same precedence chain; only the final translation differs
//! — `-v` args on one side, SBPL rules on the other.

use std::path::Path;
use std::process::Command;

use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::bail;

use crate::RunArgs;
use crate::agents;
use crate::config;
use crate::context::Context;
use crate::mounts::{self, Mount};

#[cfg(target_os = "linux")]
use crate::context::{IMAGE_TAG, LABEL};
#[cfg(target_os = "linux")]
use crate::docker;
#[cfg(target_os = "linux")]
use crate::forward::{self, Forwards};

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
    workspace: &Path,
    extra: Vec<Mount>,
) -> Result<(Vec<Mount>, Vec<config::SymlinkSpec>)> {
    let mut mounts = default_mounts(ctx);
    mounts.extend(extra);
    // Workspace is read-write by default.
    mounts.push(Mount::rw(workspace.to_path_buf()));
    // Standing defaults from config.toml + config.d/*.toml (override the implicit
    // conveniences above, but still lose to the explicit CLI flags below). `link`
    // entries additionally produce symlinks to recreate inside the sandbox.
    let mut symlinks: Vec<config::SymlinkSpec> = Vec::new();
    if let Some(cfg) = cfg {
        let resolved = cfg.resolve()?;
        mounts.extend(resolved.mounts);
        symlinks = resolved.symlinks;
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
    Ok((mounts, symlinks))
}

#[cfg(target_os = "linux")]
pub fn run(ctx: &Context, args: &RunArgs) -> Result<()> {
    let workspace = std::env::current_dir()?;

    // Config feeds both the mounts below and the forwards further down, so load it once
    // up front. `--no-config` means *entirely* ignored, forwards included.
    let cfg = if args.no_config { None } else { config::load(ctx)? };
    let forwards = Forwards::resolve(args, cfg.as_ref().map(|c| c.forward()));

    // Auto-detected agents (program files ro, state dirs rw), plus rosa's socket and
    // client binary — both same-path, so they ride the normal precedence chain rather
    // than being bolted on as raw `-v` args the way ssh/gpg have to be.
    let detected = agents::detect(ctx, args);
    let mut extra = detected.mounts.clone();
    extra.extend(forward::rosa_mounts(ctx, forwards.rosa));
    let (mounts, symlinks) = assemble_mounts(ctx, args, &cfg, &workspace, extra)?;

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
    //
    // `mode=1777` is load-bearing, not decoration. A tmpfs defaults to 1777, but when `-w`
    // names a path *inside* it — which it does whenever the workspace lives under $HOME —
    // Docker creates that directory chain and leaves the tmpfs root root-owned 0755. The
    // container then runs as the invoking uid and cannot write its own $HOME, which breaks
    // the symlink prelude below and anything else that writes there. Setting the mode
    // explicitly survives that. Matches /tmp, which the image already chmods to 1777.
    cmd.args(["--tmpfs", "/tmp:exec"]);
    cmd.args(["--tmpfs", &format!("{}:exec,mode=1777", ctx.home.display())]);

    // Labels — what makes status/exec/stop/prune possible.
    let name = args.name.clone().unwrap_or_else(|| derive_name(&workspace));
    cmd.args(["--name", &name]);
    cmd.args(["--label", &format!("{LABEL}=1")]);
    cmd.args(["--label", &format!("{LABEL}.workspace={}", workspace.display())]);
    cmd.args(["--label", &format!("{LABEL}.cmd={}", cmd_label(args))]);

    // Forwarded credentials & sockets. Before the user env passthrough below, so an
    // explicit `-e` still wins over anything a forward sets.
    forward::apply(&mut cmd, ctx, &forwards);

    // User env passthrough.
    for e in &args.env {
        cmd.args(["-e", e]);
    }

    // All same-path mounts.
    for m in &mounts {
        cmd.args(["-v", &m.to_arg()]);
    }

    cmd.arg(IMAGE_TAG);
    let inner: Vec<String> =
        if args.cmd.is_empty() { vec!["zsh".into(), "-l".into()] } else { args.cmd.clone() };
    if symlinks.is_empty() {
        cmd.args(&inner);
    } else {
        // docker flattens symlinks on mount, so recreate the host's home symlinks in the
        // tmpfs home before exec'ing — this is what makes self-locating config (e.g. zsh
        // plugin paths derived from ~/.zshrc's own resolved location) work in the sandbox.
        cmd.args(["sh", "-c", &symlink_prelude(&symlinks), "limes"]);
        cmd.args(&inner);
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

    // Agents still matter, but only for their *state* dirs: the program files are already
    // on the host and readable, while `~/.claude` must be writable under the base deny.
    let detected = agents::detect(ctx, args);
    let (mounts, _symlinks) =
        assemble_mounts(ctx, args, &cfg, &workspace, detected.mounts.clone())?;

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
    for p in ["/etc/passwd", "/etc/group", "/etc/ssl", "/etc/ld.so.cache", "/etc/localtime"] {
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
        if let Some(existing) = out.iter_mut().find(|e| e.host == m.host) {
            existing.read_only = m.read_only;
        } else {
            out.push(m);
        }
    }
    *mounts = out;
}

#[cfg(target_os = "linux")]
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
    s.push_str("exec \"$@\"");
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

    #[cfg(target_os = "linux")]
    #[test]
    fn derive_name_sanitizes_workspace() {
        assert_eq!(derive_name(Path::new("/home/u/my.proj")), "limes-my-proj");
    }
}
