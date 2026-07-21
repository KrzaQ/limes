//! `lim bootstrap` (host setup) and `lim build` (image build).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

use crate::BootstrapArgs;
use crate::context::{Context, IMAGE_TAG, SERVICE};
use crate::docker;

const DOCKERFILE: &str = include_str!("../image/Dockerfile");

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
    let missing = missing_prereqs();
    if !missing.is_empty() {
        println!("Prerequisites missing — these need root and can't be automated:\n");
        for m in &missing {
            println!("  • {m}");
        }
        println!(
            "\nInstall them, then re-run `lim bootstrap`. On Arch, typically:\n\
             \n  sudo pacman -S --needed slirp4netns rootlesskit docker\
             \n  # subuid/subgid ranges for your user:\
             \n  sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 \"$USER\"\
             \n  grep -q ^\"$USER\": /etc/subuid /etc/subgid   # verify\n"
        );
        if !dry {
            bail!("prerequisites missing (see above)");
        }
        println!("(dry run: continuing to show remaining steps)\n");
    }

    // ── 2. systemd user unit for the dedicated rootless daemon ──────
    let unit_path = ctx.service_file();
    let unit = render_unit();
    if dry {
        println!("would write {}:\n{}", unit_path.display(), indent(&unit));
    } else {
        std::fs::create_dir_all(unit_path.parent().unwrap())
            .with_context(|| format!("creating {}", unit_path.parent().unwrap().display()))?;
        std::fs::create_dir_all(ctx.data_root())
            .with_context(|| format!("creating data-root {}", ctx.data_root().display()))?;
        std::fs::write(&unit_path, &unit)
            .with_context(|| format!("writing {}", unit_path.display()))?;
        println!("wrote {}", unit_path.display());
    }

    // ── 3. Enable + start the service, enable linger ────────────────
    systemd(dry, &["--user", "daemon-reload"])?;
    systemd(dry, &["--user", "enable", "--now", SERVICE])?;
    loginctl_linger(dry)?;

    // ── 4. Wait for the socket, then build the image ────────────────
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
    for bin in ["slirp4netns", "rootlesskit", "dockerd-rootless.sh", "newuidmap"] {
        if which(bin).is_none() {
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
fn render_unit() -> String {
    format!(
        "[Unit]\n\
         Description=limes dedicated rootless Docker daemon\n\
         Documentation=https://docs.docker.com/go/rootless/\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\n\
         ExecStart=dockerd-rootless.sh --data-root %h/.local/share/limes/docker --host unix://%t/limes-docker.sock\n\
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
         WantedBy=default.target\n"
    )
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

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("    {l}\n")).collect()
}
