//! `lim doctor` — a health report for the limes installation.
//!
//! Every open item that used to require "verify empirically on this host" (rootless
//! prereqs, userns, port driver, linger) is a line here.

use std::path::Path;
use std::process::Command;

use anyhow::Result;

use crate::context::{Context, IMAGE_TAG, SERVICE};
use crate::docker;

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

pub fn doctor(ctx: &Context) -> Result<()> {
    let mut r = Report::new();

    // ── Rootless prerequisites ──────────────────────────────────────
    for bin in ["newuidmap", "newgidmap", "slirp4netns", "rootlesskit", "dockerd-rootless.sh"] {
        match which(bin) {
            Some(p) => r.add(Health::Ok, bin, p),
            None => r.add(Health::Fail, bin, "not found — install rootless docker + slirp4netns"),
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
        Some(_) => r.add(Health::Fail, "userns", "unprivileged user namespaces disabled (sysctl=0)"),
        None => r.add(Health::Ok, "userns", "no sysctl gate (enabled)"),
    }
    match read_sysctl("kernel/apparmor_restrict_unprivileged_userns") {
        Some(v) if v == "1" => {
            r.add(Health::Warn, "apparmor userns", "restricted — a profile may be needed (Ubuntu 24.04+)")
        }
        _ => r.add(Health::Ok, "apparmor userns", "unrestricted"),
    }

    // ── Daemon / service ────────────────────────────────────────────
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
        r.add(Health::Warn, "linger", "disabled — daemon won't survive logout (`loginctl enable-linger`)");
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

    // ── Image ───────────────────────────────────────────────────────
    if docker::image_present(ctx) {
        r.add(Health::Ok, "image", IMAGE_TAG);
    } else {
        r.add(Health::Fail, "image", format!("{IMAGE_TAG} not built — run `lim build`"));
    }

    println!("limes doctor:");
    r.print();
    if r.any_fail() {
        println!("\nSome checks failed. `lim bootstrap` sets up what it can and prints the rest.");
    } else {
        println!("\nAll good.");
    }
    Ok(())
}

fn which(bin: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
        .map(|p| p.display().to_string())
}

fn username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

fn file_has_prefix(file: &str, prefix: &str) -> bool {
    std::fs::read_to_string(file)
        .map(|s| s.lines().any(|l| l.starts_with(prefix)))
        .unwrap_or(false)
}

fn read_sysctl(rel: &str) -> Option<String> {
    let p = Path::new("/proc/sys").join(rel);
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn systemctl_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", unit])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

fn linger_enabled(user: &str) -> bool {
    // Authoritative marker file; avoids parsing loginctl output.
    Path::new("/var/lib/systemd/linger").join(user).exists()
}
