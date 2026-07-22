//! `lim bootstrap` (host setup) and `lim build` (image build).

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

use crate::BootstrapArgs;
use crate::context::{Context, IMAGE_TAG, SERVICE};
use crate::docker;
use crate::util::{self, find_in_path};

const DOCKERFILE: &str = include_str!("../image/Dockerfile");
/// Rootless launcher, vendored from Moby (Apache-2.0). We ship our own copy so setup
/// needs only official-repo packages — no AUR / docker-ce-rootless-extras.
const LAUNCHER: &str = include_str!("../vendor/dockerd-rootless.sh");

pub fn build(ctx: &Context, no_cache: bool) -> Result<()> {
    if !docker::daemon_alive(ctx) {
        bail!(
            "limes daemon not reachable at {} — run `lim bootstrap` first",
            ctx.socket().display()
        );
    }
    println!("limes: building {IMAGE_TAG} (no build context — Dockerfile via stdin)");

    let mut cmd = docker::command(ctx);
    cmd.args(["build", "-t", IMAGE_TAG]);
    if no_cache {
        cmd.arg("--no-cache");
    }
    // `docker build -` reads a bare Dockerfile from stdin with no context.
    cmd.arg("-").stdin(Stdio::piped());

    let mut child = cmd.spawn().context("failed to start docker build")?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(DOCKERFILE.as_bytes())
        .context("failed to send Dockerfile")?;
    let status = child.wait()?;
    if !status.success() {
        bail!("docker build failed ({status})");
    }
    println!("limes: image {IMAGE_TAG} built");
    Ok(())
}

pub fn bootstrap(ctx: &Context, args: &BootstrapArgs) -> Result<()> {
    let dry = args.dry_run;
    println!("limes bootstrap{}:\n", if dry { " (dry run)" } else { "" });

    // ── 1. Prerequisites that need root / package installs ──────────
    // We only *name* what's missing and let you install it your way — limes stays
    // distro-agnostic and never prints a package-manager command that might be wrong
    // for your system.
    let missing = missing_prereqs();
    if !missing.is_empty() {
        println!("Missing prerequisites (each needs root to install or configure):\n");
        for m in &missing {
            println!("  • {m}");
        }
        println!(
            "\nInstall these with your distro's package manager, then re-run `lim bootstrap`.\n\
             They set up rootless Docker: https://docs.docker.com/engine/security/rootless/\n\
             subuid/subgid ranges are added with `usermod --add-subuids/--add-subgids <user>`.\n"
        );
        if !dry {
            bail!("prerequisites missing (see above)");
        }
        println!("(dry run: continuing to show remaining steps)\n");
    }

    // ── 1b. A data-root the daemon can actually stack an overlay on ──
    // Checked here, before the unit is written and the daemon started, because the
    // failure it prevents surfaces much later and much further away: the daemon comes up
    // fine and the *first image build* dies in buildkit with an EINVAL on a cache mount,
    // naming neither the data-root nor the filesystem.
    let data_root = ctx.data_root();
    if let Some(fs) = util::unsupported_upperdir_fs(&data_root) {
        bail!(
            "data-root {} is on {fs}, which cannot hold an overlayfs upperdir — the daemon \
             would start but every image build would fail.\n\
             Point it at a filesystem that can (ext4, xfs, btrfs) by adding to \
             ~/.config/limes/config.toml:\n\n    \
             data_root = \"/var/lib/limes/$USER/docker\"\n\n\
             The directory is created on the next `lim bootstrap`; it needs to be one you \
             own and can write.",
            data_root.display()
        );
    }

    // ── 2. Vendored rootless launcher ───────────────────────────────
    let launcher_path = ctx.launcher_path();
    if dry {
        println!("would write launcher to {}", launcher_path.display());
    } else {
        std::fs::create_dir_all(launcher_path.parent().unwrap())
            .with_context(|| format!("creating {}", launcher_path.parent().unwrap().display()))?;
        std::fs::write(&launcher_path, LAUNCHER)
            .with_context(|| format!("writing {}", launcher_path.display()))?;
        std::fs::set_permissions(&launcher_path, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod {}", launcher_path.display()))?;
        println!("wrote {}", launcher_path.display());
    }

    // ── 3. systemd user unit for the dedicated rootless daemon ──────
    let unit_path = ctx.service_file();
    let unit = unit_file(&data_root);
    // A daemon already running from the old unit keeps its old data-root and socket:
    // `enable --now` starts a stopped service but will not restart a live one, so without
    // this the rewritten unit sits on disk describing a daemon that isn't what's running.
    let unit_changed = std::fs::read_to_string(&unit_path).map(|old| old != unit).unwrap_or(true);
    if dry {
        println!("would write {}:\n{}", unit_path.display(), indent(&unit));
    } else {
        std::fs::create_dir_all(unit_path.parent().unwrap())
            .with_context(|| format!("creating {}", unit_path.parent().unwrap().display()))?;
        std::fs::create_dir_all(&data_root)
            .with_context(|| format!("creating data-root {}", data_root.display()))?;
        std::fs::write(&unit_path, unit)
            .with_context(|| format!("writing {}", unit_path.display()))?;
        println!("wrote {}", unit_path.display());
    }

    // ── 4. Enable + start the service, enable linger ────────────────
    systemd(dry, &["--user", "daemon-reload"])?;
    systemd(dry, &["--user", "enable", "--now", SERVICE])?;
    // Only when the unit actually changed: a restart takes every running sandbox's
    // containers with it, which is not something a re-run of an idempotent command should
    // do for free.
    if unit_changed && systemctl_active(SERVICE) {
        println!("unit changed — restarting {SERVICE}");
        systemd(dry, &["--user", "restart", SERVICE])?;
    }
    loginctl_linger(dry)?;

    // ── 5. Wait for the socket, then build the image ────────────────
    if dry {
        println!("would wait for {} and build {IMAGE_TAG}", ctx.socket().display());
        return Ok(());
    }
    if !wait_for_socket(ctx) {
        bail!(
            "daemon socket {} did not appear — check `systemctl --user status {SERVICE}`",
            ctx.socket().display()
        );
    }
    build(ctx, false)?;

    println!("\nbootstrap complete. Verify with `lim doctor`.");
    Ok(())
}

/// Prerequisites limes cannot install itself (need root / package manager).
fn missing_prereqs() -> Vec<String> {
    let mut missing = Vec::new();
    // We vendor dockerd-rootless.sh ourselves; it needs rootlesskit + dockerd + a network
    // backend on PATH, all in official repos (no AUR / docker-ce-rootless-extras).
    for bin in ["dockerd", "rootlesskit", "slirp4netns", "newuidmap"] {
        if find_in_path(bin).is_none() {
            missing.push(format!("`{bin}` not on PATH"));
        }
    }
    let user = std::env::var("USER").unwrap_or_default();
    for file in ["/etc/subuid", "/etc/subgid"] {
        let has = std::fs::read_to_string(file)
            .map(|s| s.lines().any(|l| l.starts_with(&format!("{user}:"))))
            .unwrap_or(false);
        if !has {
            missing.push(format!("no subordinate-id range for {user} in {file}"));
        }
    }
    missing
}

/// The systemd **user** unit — dedicated data-root and socket, mirroring Docker's
/// official rootless unit but namespaced to limes.
///
/// `%h` and `%t` are systemd's own specifiers, left for it to expand; the data-root is the
/// only thing substituted here.
fn unit_file(data_root: &Path) -> String {
    // The data-root is the one interpolated value: it is configurable, so it can point
    // outside `$HOME` and `%h` can no longer stand in for it. Quoted because systemd
    // splits ExecStart on whitespace and a path may contain some.
    format!(
        "[Unit]\n\
         Description=limes dedicated rootless Docker daemon\n\
         Documentation=https://docs.docker.com/go/rootless/\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\n\
         ExecStart=%h/.local/share/limes/bin/dockerd-rootless.sh --data-root \"{}\" --host unix://%t/limes-docker.sock\n\
         ExecReload=/bin/kill -s HUP $MAINPID\n\
         TimeoutSec=0\n\
         RestartSec=2\n\
         Restart=always\n\
         StartLimitBurst=3\n\
         StartLimitInterval=60s\n\
         LimitNOFILE=infinity\n\
         LimitNPROC=infinity\n\
         LimitCORE=infinity\n\
         TasksMax=infinity\n\
         Delegate=yes\n\
         Type=notify\n\
         NotifyAccess=all\n\
         KillMode=mixed\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        data_root.display()
    )
}

/// Whether systemd currently has the unit running — the question `enable --now` doesn't
/// ask. Any failure to run `systemctl` reads as "not active", which errs toward not
/// restarting something we cannot see.
fn systemctl_active(service: &str) -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn systemd(dry: bool, args: &[&str]) -> Result<()> {
    if dry {
        println!("would run: systemctl {}", args.join(" "));
        return Ok(());
    }
    let status = Command::new("systemctl").args(args).status()?;
    if !status.success() {
        bail!("systemctl {} failed", args.join(" "));
    }
    Ok(())
}

fn loginctl_linger(dry: bool) -> Result<()> {
    if dry {
        println!("would run: loginctl enable-linger");
        return Ok(());
    }
    // Idempotent; ignore failure (already enabled, or no seat) — doctor reports truth.
    let _ = Command::new("loginctl").arg("enable-linger").status();
    Ok(())
}

fn wait_for_socket(ctx: &Context) -> bool {
    let sock = ctx.socket();
    for _ in 0..50 {
        if sock.exists() && docker::daemon_alive(ctx) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    false
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("    {l}\n")).collect()
}
