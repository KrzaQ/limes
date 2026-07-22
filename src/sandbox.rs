//! Container lifetime: create once, join many, tear down when the last shell leaves.
//!
//! `run.rs` decides *what* a sandbox is; this module decides *when one exists*. The split
//! matters because a second `lim` in the same workspace no longer builds a second sandbox —
//! it attaches to the first.
//!
//! ## Why joining rather than a second container
//!
//! The mirror principle. Two terminals on a host are two shells on **one machine**, sharing
//! `$HOME`, `/tmp` and the process table. Two containers would give two tmpfs `$HOME`s, so a
//! file written in one shell would simply be missing in the other and `ps` would not show
//! the other's build. That surprise has no good explanation.
//!
//! ## Shape
//!
//! PID 1 is a trivial supervisor (`sleep infinity`) and **every** shell, the first included,
//! is a `docker exec`. All shells are therefore peers: none owns the others' fate, and the
//! first one to exit no longer takes the rest down with it.
//!
//! `--init` on the supervisor is load-bearing, not decoration. `sleep` never calls `wait()`,
//! so orphaned processes reparented to it accumulate as zombies for the container's
//! lifetime — measured. Today's shell-as-PID-1 hides this because a shell reaps; a
//! supervisor does not. Docker's tini (`docker-init`) does, and was verified compatible with
//! `--read-only`, `--cap-drop ALL` and `no-new-privileges` together.
//!
//! ## The lock
//!
//! One host-side `flock` serialises *check → create → initialise*, closing two races with
//! one mechanism:
//!
//! - **create** — two `lim`s in a fresh workspace both seeing no container and both issuing
//!   `docker run` with the same name, which is the raw error this whole feature removes;
//! - **readiness** — `docker run -d` returns once the process has *started*, not once the
//!   symlink prelude has finished, so a shell could otherwise land in a `$HOME` with no
//!   dotfiles in it.
//!
//! It is held on an fd, so `kill -9` releases it. That is the same property that rules out a
//! counter file for teardown: a stale count either leaks containers forever or kills a live
//! one.

use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use crate::context::Context;
use crate::docker;
use crate::run::RunSpec;

/// An `flock`, released when dropped — or by the kernel when the process dies, which is
/// what makes it immune to the staleness that rules out a counter file.
pub struct Lock(#[allow(dead_code)] std::fs::File);

impl Lock {
    /// Blocks until whoever is creating the sandbox has finished initialising it.
    fn exclusive(path: &Path) -> Result<Self> {
        Self::take(path, libc::LOCK_EX).map(|l| l.expect("blocking lock cannot fail softly"))
    }

    fn shared(path: &Path) -> Result<Self> {
        Self::take(path, libc::LOCK_SH).map(|l| l.expect("blocking lock cannot fail softly"))
    }

    /// `None` when someone else holds it — a question, not a wait.
    fn try_exclusive(path: &Path) -> Result<Option<Self>> {
        Self::take(path, libc::LOCK_EX | libc::LOCK_NB)
    }

    fn take(path: &Path, op: libc::c_int) -> Result<Option<Self>> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("opening lock {}", path.display()))?;
        if unsafe { libc::flock(f.as_raw_fd(), op) } != 0 {
            let e = std::io::Error::last_os_error();
            if op & libc::LOCK_NB != 0 && e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(e).with_context(|| format!("locking {}", path.display()));
        }
        Ok(Some(Self(f)))
    }
}

/// Register this `lim` as in-flight for `name`, for as long as the returned guard lives.
///
/// Take it *before* looking for the sandbox and hold it until the shell has exited. It is
/// what stops another `lim`'s teardown from stopping the container in the window between
/// "the sandbox exists" and "my shell is attached", when `ExecIDs` is still zero.
///
/// The alternative — noticing the failure afterwards and retrying — is not safe: retrying
/// means running the user's command a second time, and `lim run -- make install` must not
/// be re-run because of a lifetime race.
pub fn in_flight(ctx: &Context, name: &str) -> Result<Lock> {
    Lock::shared(&ctx.shells_file(name))
}

/// Make sure a sandbox for `spec` exists and is initialised, creating it if not.
///
/// Returns whether it created one, so the caller can say so.
pub fn ensure_running(ctx: &Context, spec: &RunSpec) -> Result<bool> {
    let _lock = Lock::exclusive(&ctx.lock_file(&spec.name))?;

    let created = !docker::container_running(ctx, &spec.name);
    if created {
        // `--rm` should have reaped any stopped leftover; clear it defensively rather than
        // failing on a name conflict with a corpse.
        docker::remove_quietly(ctx, &spec.name);
        create(ctx, spec)?;
    }
    // Always run, even when joining: a creator that died between `docker run` and this step
    // would otherwise leave a sandbox whose `$HOME` has no dotfiles, and nothing would say
    // so. The script no-ops when the marker is already there, so the steady-state cost is
    // one exec. Re-running it unconditionally is *not* an option — `ln -sfn` is not atomic,
    // so a joiner would briefly yank `~/.zshrc` from under a shell that is starting up.
    initialize(ctx, spec)?;
    Ok(created)
}

fn create(ctx: &Context, spec: &RunSpec) -> Result<()> {
    let mut cmd = docker::command(ctx);
    cmd.args(spec.to_run_args());
    let out = cmd.output().context("failed to exec docker")?;
    if !out.status.success() {
        bail!(
            "could not create sandbox {}: {}",
            spec.name,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Run the symlink prelude inside the container, once.
///
/// It mutates the shared tmpfs `$HOME`, so it belongs to the *container*, not to a shell.
fn initialize(ctx: &Context, spec: &RunSpec) -> Result<()> {
    let mut cmd = docker::command(ctx);
    cmd.args(["exec", &spec.name, BUSYBOX, "sh", "-c", &spec.init_script()]);
    let out = cmd.output().context("failed to exec docker")?;
    if !out.status.success() {
        // A half-initialised sandbox is worse than none: tear it down rather than hand out
        // shells whose dotfiles silently never arrived.
        docker::remove_quietly(ctx, &spec.name);
        bail!(
            "could not initialise sandbox {}: {}",
            spec.name,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The rescue busybox, at a path no host mount ever shadows.
pub const BUSYBOX: &str = "/limes/busybox";

/// Marker written once the prelude has run; the readiness signal a joiner waits on.
pub const READY_MARKER: &str = "/tmp/.limes-ready";

/// Attach a shell to a running sandbox and wait for it.
///
/// `cwd` and the terminal variables are per-shell on purpose: `docker exec` takes its own
/// `-w` and `-e`, which is what makes joining from a subdirectory land you where you
/// actually are rather than back at the workspace root.
///
/// Deliberately **not** `exec()` process replacement, unlike the other passthroughs: this
/// process has to outlive the shell in order to run the teardown check below.
pub fn join(
    ctx: &Context,
    name: &str,
    cwd: Option<&Path>,
    cmd: &[String],
    env: &[String],
) -> Result<i32> {
    status_code(join_command(ctx, name, cwd, cmd, env))
}

/// The `docker exec` `join` would run — also what `--dry-run` prints, so the two cannot
/// describe different things.
pub fn join_command(
    ctx: &Context,
    name: &str,
    cwd: Option<&Path>,
    cmd: &[String],
    env: &[String],
) -> Command {
    let mut c = docker::command(ctx);
    c.args(["exec", "-it"]);
    if let Some(cwd) = cwd {
        c.args(["-w", &cwd.display().to_string()]);
    }
    for e in env {
        c.args(["-e", e]);
    }
    c.arg(name);
    c.args(cmd);
    c
}

/// Stop the sandbox if this was its last shell.
///
/// Call after dropping the `in_flight` guard. The shell count comes from the daemon rather
/// than from anything limes writes down — the same principle `doctor` follows — and the
/// in-flight lock covers the gap the daemon cannot see: a `lim` that has found the sandbox
/// but not yet attached, whose shell does not exist to be counted.
///
/// Under the create lock too, so two `lim`s exiting together cannot both observe zero and
/// both issue a stop.
pub fn release(ctx: &Context, name: &str) -> Result<()> {
    let _lock = Lock::exclusive(&ctx.lock_file(name))?;
    // Someone else still in flight: leave the sandbox alone. Non-blocking on purpose —
    // this is a question about the present, and waiting for an answer would mean waiting
    // for their whole shell.
    let Some(_alone) = Lock::try_exclusive(&ctx.shells_file(name))? else {
        return Ok(());
    };
    if docker::exec_count(ctx, name) == 0 {
        docker::stop_quietly(ctx, name);
    }
    Ok(())
}

/// Run to completion, returning the child's exit code the way a shell would report it.
fn status_code(mut cmd: Command) -> Result<i32> {
    let status = cmd.status().context("failed to exec docker")?;
    Ok(exit_code(status))
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    // A signalled child has no exit code; report it the way a shell does.
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}
