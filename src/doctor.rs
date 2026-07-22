//! `lim doctor` — a health report for the limes installation.
//!
//! Every open item that used to require "verify empirically on this host" (rootless
//! prereqs, userns, port driver, linger) is a line here.

use std::path::Path;
use std::process::Command;

use anyhow::Result;

use crate::context::Context;
#[cfg(target_os = "linux")]
use crate::context::{IMAGE_TAG, SERVICE};
#[cfg(target_os = "linux")]
use crate::docker;
use crate::forward;
use crate::util::find_in_path;

enum Health {
    Ok,
    Warn,
    Fail,
}

impl Health {
    fn glyph(&self) -> &'static str {
        match self {
            Health::Ok => "\u{2713}",   // ✓
            Health::Warn => "\u{25CB}", // ○
            Health::Fail => "\u{2717}", // ✗
        }
    }
}

struct Report {
    lines: Vec<(Health, String, String)>,
}

impl Report {
    fn new() -> Self {
        Self { lines: Vec::new() }
    }
    fn add(&mut self, h: Health, label: &str, detail: impl Into<String>) {
        self.lines.push((h, label.to_string(), detail.into()));
    }
    fn print(&self) {
        for (h, label, detail) in &self.lines {
            println!("  {} {:<24} {}", h.glyph(), label, detail);
        }
    }
    fn any_fail(&self) -> bool {
        self.lines.iter().any(|(h, ..)| matches!(h, Health::Fail))
    }
}

#[cfg(target_os = "linux")]
pub fn doctor(ctx: &Context) -> Result<()> {
    let mut r = Report::new();

    // ── Rootless prerequisites ──────────────────────────────────────
    // The vendored launcher needs these on PATH; all are in official repos.
    for bin in ["dockerd", "rootlesskit", "slirp4netns", "newuidmap", "newgidmap"] {
        match find_in_path(bin) {
            Some(p) => r.add(Health::Ok, bin, p.display().to_string()),
            None => r.add(Health::Fail, bin, "not found — install from your distro's repos"),
        }
    }

    let user = username();
    for (file, label) in [("/etc/subuid", "subuid"), ("/etc/subgid", "subgid")] {
        if file_has_prefix(file, &format!("{user}:")) {
            r.add(Health::Ok, label, format!("{user} mapped"));
        } else {
            r.add(Health::Fail, label, format!("no entry for {user} in {file}"));
        }
    }

    // ── Kernel / security ───────────────────────────────────────────
    match read_sysctl("kernel/unprivileged_userns_clone") {
        Some(v) if v == "1" => r.add(Health::Ok, "userns", "unprivileged user namespaces enabled"),
        Some(_) => {
            r.add(Health::Fail, "userns", "unprivileged user namespaces disabled (sysctl=0)")
        }
        None => r.add(Health::Ok, "userns", "no sysctl gate (enabled)"),
    }
    match read_sysctl("kernel/apparmor_restrict_unprivileged_userns") {
        Some(v) if v == "1" => r.add(
            Health::Warn,
            "apparmor userns",
            "restricted — rootless needs an AppArmor userns profile (Docker's rootless-extras \
             package bundles one; see docs.docker.com/engine/security/rootless/ troubleshooting)",
        ),
        _ => r.add(Health::Ok, "apparmor userns", "unrestricted"),
    }

    // ── Daemon / service ────────────────────────────────────────────
    if ctx.launcher_path().exists() {
        r.add(Health::Ok, "launcher", ctx.launcher_path().display().to_string());
    } else {
        r.add(
            Health::Fail,
            "launcher",
            "vendored dockerd-rootless.sh missing — run `lim bootstrap`",
        );
    }
    if ctx.service_file().exists() {
        r.add(Health::Ok, "service unit", ctx.service_file().display().to_string());
    } else {
        r.add(Health::Fail, "service unit", format!("{SERVICE} missing — run `lim bootstrap`"));
    }
    match systemctl_active(SERVICE) {
        true => r.add(Health::Ok, "service active", SERVICE),
        false => r.add(Health::Fail, "service active", format!("{SERVICE} not active")),
    }
    if linger_enabled(&user) {
        r.add(Health::Ok, "linger", format!("enabled for {user}"));
    } else {
        r.add(
            Health::Warn,
            "linger",
            "disabled — daemon won't survive logout (`loginctl enable-linger`)",
        );
    }
    if ctx.socket().exists() {
        r.add(Health::Ok, "socket", ctx.socket().display().to_string());
    } else {
        r.add(Health::Fail, "socket", format!("{} absent", ctx.socket().display()));
    }
    if docker::daemon_alive(ctx) {
        r.add(Health::Ok, "daemon", "responds to `docker info`");
    } else {
        r.add(Health::Fail, "daemon", "unreachable on the limes socket");
    }

    // Load-bearing, not informational: `run` passes `-u 0:0` because the rootless mapping
    // makes container uid 0 the invoking user. Against a rootful daemon that same flag is
    // real root with the host's whole filesystem one `-v` away, so if this ever reports
    // Fail, stop using the sandbox rather than trusting it.
    match docker::daemon_rootless(ctx) {
        Some(true) => r.add(Health::Ok, "rootless", "daemon runs in a user namespace"),
        Some(false) => r.add(
            Health::Fail,
            "rootless",
            "daemon is NOT rootless — `lim run` uses -u 0:0 and would be real root here",
        ),
        None => r.add(Health::Warn, "rootless", "could not determine (daemon unreachable?)"),
    }

    // ── Image ───────────────────────────────────────────────────────
    if docker::image_present(ctx) {
        r.add(Health::Ok, "image", IMAGE_TAG);
    } else {
        r.add(Health::Fail, "image", format!("{IMAGE_TAG} not built — run `lim build`"));
    }

    // ── Optional forwards ───────────────────────────────────────────
    // Never a Fail: a sandbox without rosa is fine. But a socket with no client — or a
    // client with no socket — silently forwards nothing, and that half-state is the
    // confusing one, so name both halves.
    let sock = forward::rosa_socket(ctx).display().to_string();
    let (health, detail) = match (Path::new(&sock).exists(), find_in_path("rosa")) {
        (true, Some(bin)) => (Health::Ok, format!("{sock} (client {})", bin.display())),
        (true, None) => (Health::Warn, format!("{sock} present, but no `rosa` on PATH")),
        (false, Some(_)) => (Health::Warn, format!("no socket at {sock}; is `rosa serve` up?")),
        (false, None) => (Health::Warn, "not installed (optional secret broker)".into()),
    };
    r.add(health, "rosa", detail);

    println!("limes doctor:");
    r.print();
    if r.any_fail() {
        println!("\nSome checks failed. `lim bootstrap` sets up what it can and prints the rest.");
    } else {
        println!("\nAll good.");
    }
    Ok(())
}

/// macOS has no daemon, no image and no prerequisites — roughly half the Linux report
/// evaporates rather than porting. What replaces it is a statement of what this platform
/// does *not* enforce: the design notes are explicit that omitting a check must never read
/// as passing it.
#[cfg(target_os = "macos")]
pub fn doctor(ctx: &Context) -> Result<()> {
    let mut r = Report::new();

    match find_in_path("sandbox-exec") {
        Some(p) => r.add(Health::Ok, "sandbox-exec", p.display().to_string()),
        None => r.add(Health::Fail, "sandbox-exec", "not found — the backend cannot run"),
    }
    // Seatbelt matches resolved paths, so a temp dir that is a symlink would silently
    // produce rules that never fire.
    let tmp = std::env::temp_dir();
    match tmp.canonicalize() {
        Ok(c) if c == tmp => r.add(Health::Ok, "tmpdir", c.display().to_string()),
        Ok(c) => r.add(
            Health::Ok,
            "tmpdir",
            format!("{} (resolved from {})", c.display(), tmp.display()),
        ),
        Err(e) => r.add(Health::Fail, "tmpdir", format!("cannot resolve {}: {e}", tmp.display())),
    }
    // A generated profile is worth proving loadable before a real run needs it.
    match probe_profile() {
        Ok(()) => r.add(Health::Ok, "profile", "generated profile loads and confines writes"),
        Err(e) => r.add(Health::Fail, "profile", e.to_string()),
    }

    let sock = forward::rosa_socket(ctx).display().to_string();
    let (health, detail) = match (Path::new(&sock).exists(), find_in_path("rosa")) {
        (true, Some(bin)) => (Health::Ok, format!("{sock} (client {})", bin.display())),
        (true, None) => (Health::Warn, format!("{sock} present, but no `rosa` on PATH")),
        (false, Some(_)) => (Health::Warn, format!("no socket at {sock}; is `rosa serve` up?")),
        (false, None) => (Health::Warn, "not installed (optional secret broker)".into()),
    };
    r.add(health, "rosa", detail);

    println!("limes doctor (macOS / Seatbelt backend):");
    r.print();

    // Stated, not omitted. Each of these is a guarantee the Linux backend gives and this
    // one does not; a reader comparing the two reports must not have to infer it.
    println!("\nNot enforced on this platform:");
    for line in [
        "process isolation  — no PID namespace; `ps` sees the whole host",
        "network isolation  — no netns; network filtering is an explicit non-goal",
        "read confinement   — reads are unrestricted except paths declared `hide`",
        "container lifecycle— no objects to list, stop or prune (those subcommands are Linux-only)",
    ] {
        println!("  · {line}");
    }
    println!("\nEnforced: write confinement, inherited by every descendant process and");
    println!("not escapable by re-invoking sandbox-exec.");

    if r.any_fail() {
        println!("\nSome checks failed.");
    }
    Ok(())
}

/// Load a minimal generated profile and confirm it actually denies a write. Catches an
/// unloadable profile (a syntax slip in the generator) before a real run hits it.
#[cfg(target_os = "macos")]
fn probe_profile() -> Result<()> {
    use crate::mounts::Mount;
    let tmp = std::env::temp_dir();
    let tmp = tmp.canonicalize().unwrap_or(tmp);
    let profile = crate::seatbelt::profile(&[Mount::ro("/".into())], &tmp);
    let target = tmp.join("limes-doctor-probe");
    let _ = std::fs::remove_file(&target);
    let out = Command::new("sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .arg("/usr/bin/touch")
        .arg(&target)
        .output()?;
    if target.exists() {
        let _ = std::fs::remove_file(&target);
        anyhow::bail!("profile loaded but did NOT confine writes");
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("failed to parse") || err.contains("sandbox_compile") {
        anyhow::bail!("generated profile does not compile: {}", err.trim());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

#[cfg(target_os = "linux")]
fn file_has_prefix(file: &str, prefix: &str) -> bool {
    std::fs::read_to_string(file).map(|s| s.lines().any(|l| l.starts_with(prefix))).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn read_sysctl(rel: &str) -> Option<String> {
    let p = Path::new("/proc/sys").join(rel);
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn systemctl_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", unit])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linger_enabled(user: &str) -> bool {
    // Authoritative marker file; avoids parsing loginctl output.
    Path::new("/var/lib/systemd/linger").join(user).exists()
}
