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

use std::path::Path;
use std::process::Command;

use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context as _, bail};

use crate::RunArgs;
use crate::agents;
use crate::config;
use crate::context::{self, Context};
#[cfg(target_os = "linux")]
use crate::identity;
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
    // so a path given both ways ends up writable, and `--hide` after both: it is the
    // safety direction, so `--rw X --hide X` hides.
    for p in &args.ro {
        mounts.push(Mount::ro(mounts::canonicalize(p)?));
    }
    for p in &args.rw {
        mounts.push(Mount::rw(mounts::canonicalize(p)?));
    }
    for p in &args.hide {
        // Missing is a no-op rather than an error — see `mounts::resolve_hide`.
        if let Some(p) = mounts::resolve_hide(p)? {
            mounts.push(Mount::hide(p));
        }
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
    let (mounts, mut symlinks) = assemble_mounts(ctx, args, &cfg, &workspace, extra)?;
    // An agent's launcher symlink is recreated the same way config's `link = "parent"`
    // entries are — one prelude, one mechanism.
    symlinks.extend(detected.symlinks);

    // ── docker run ──────────────────────────────────────────────────
    let mut cmd = docker::command(ctx);
    cmd.arg("run").arg("--rm").arg("-it");

    // Identity: run as the human, with a matching HOME.
    //
    // `-u 0:0` is that human, not root. The rootless daemon's user namespace maps the
    // invoking user to container uid 0; container uids 1.. come from the subuid range and
    // own none of the host's files, so `-u {uid}:{gid}` produces a sandbox where the
    // workspace, `~/.claude` and every 0700 dotfile are unreadable and unwritable. Do not
    // "fix" this back. It is safe only because `docker::command` pins every call to limes'
    // own rootless daemon — against a rootful one this would be real root, which is what
    // `doctor`'s rootless check guards. --cap-drop/no-new-privileges/read-only still apply.
    cmd.args(["-u", "0:0"]);
    cmd.args(["-e", &format!("HOME={}", ctx.home.display())]);
    cmd.args(["-w", &path_str(&workspace)]);

    // Mirror the host's hostname. Without this the sandbox reports the container ID, which
    // changes every run and reads as noise. CLI beats config, as everywhere else.
    let suffix =
        args.hostname_suffix.as_deref().or_else(|| cfg.as_ref().and_then(|c| c.hostname_suffix()));
    cmd.args(["--hostname", &context::sandbox_hostname(&ctx.hostname, suffix)?]);

    // ...and uid 0 has to *look* like the human, or `whoami` says root and every mounted
    // file lists as root. These are the only mounts whose destination differs from their
    // source, so — like the gpg and docker sockets in `forward.rs` — they are raw `-v` args
    // rather than `Mount`s, which model same-path binds only.
    std::fs::write(
        ctx.passwd_file(),
        identity::passwd(&read_etc("/etc/passwd"), ctx.uid, &ctx.home),
    )
    .with_context(|| format!("writing {}", ctx.passwd_file().display()))?;
    std::fs::write(ctx.group_file(), identity::group(&read_etc("/etc/group"), ctx.gid))
        .with_context(|| format!("writing {}", ctx.group_file().display()))?;
    cmd.args(["-v", &format!("{}:/etc/passwd:ro", ctx.passwd_file().display())]);
    cmd.args(["-v", &format!("{}:/etc/group:ro", ctx.group_file().display())]);

    // Marker so shells/scripts/tooling inside can tell they're in a limes sandbox:
    // presence means "inside limes", value is the version. It's the crate version, so
    // it never drifts from Cargo.toml / `lim --version`.
    cmd.args(["-e", concat!("LIMES_VERSION=", env!("CARGO_PKG_VERSION"))]);

    // The terminal is host state, so mirror it. `-t` otherwise makes Docker invent
    // `TERM=xterm` — 8 colours — and a 256-colour prompt or a themed TUI renders washed out
    // inside a sandbox that has the host's own terminfo mounted at /usr/share/terminfo.
    // Passed before the user's `-e` below, so `--env TERM=…` still wins for one run.
    for var in ["TERM", "COLORTERM"] {
        if let Ok(v) = std::env::var(var) {
            cmd.args(["-e", &format!("{var}={v}")]);
        }
    }

    // Security posture: no new privileges, drop all caps, read-only rootfs, seccomp
    // left enabled. Never --privileged — the sandbox bounds reach, it doesn't grant it.
    cmd.args(["--security-opt", "no-new-privileges"]);
    cmd.args(["--cap-drop", "ALL"]);
    cmd.arg("--read-only");

    // Writable, ephemeral scratch: /tmp and an empty HOME the shell can write to.
    // The bind mounts below layer real dotfiles/state on top of the HOME tmpfs.
    //
    // `mode=1777` is belt-and-braces. A tmpfs defaults to 1777, but when `-w` names a path
    // *inside* it — which it does whenever the workspace lives under $HOME — Docker creates
    // that directory chain and leaves the tmpfs root owned by uid 0 at 0755. That is
    // harmless while we run as uid 0, but it silently breaks the symlink prelude below (and
    // anything else writing to $HOME) the moment the container user is anyone else. Keep it
    // pinned so the mode never depends on the uid. Matches /tmp, which the image chmods.
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

    // The mount table. Each entry renders its own flag pair — `-v` for the binds,
    // `--tmpfs` for a `hide` — so a mode is never forced into being a bind.
    for m in &mounts {
        cmd.args(m.to_args());
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
    for p in ["/etc/ssl", "/etc/ld.so.cache", "/etc/localtime"] {
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

    /// Last-wins has to hold across *differing* kinds, not just ro-vs-rw — otherwise
    /// `--hide` on a path some default already mounts silently does nothing.
    #[test]
    fn dedupe_is_last_wins_across_kinds() {
        let mut m = vec![Mount::rw("/a".into()), Mount::hide("/a".into())];
        dedupe(&mut m);
        assert_eq!(m, vec![Mount::hide("/a".into())], "hide beats an earlier rw");

        let mut m = vec![Mount::hide("/a".into()), Mount::ro("/a".into())];
        dedupe(&mut m);
        assert_eq!(m, vec![Mount::ro("/a".into())], "and is itself overridable");
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
