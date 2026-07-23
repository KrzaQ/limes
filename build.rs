//! Embed the git commit into the binary so `lim --version` names the exact build it came from
//! — the thing you want when a sandbox mounts *some* `lim` and you need to know which.
//!
//! Best-effort: a build from a tarball with no git available just reports `unknown`.

use std::process::Command;

fn main() {
    let git = |args: &[&str]| -> Option<Vec<u8>> {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| o.stdout)
    };

    let commit = git(&["rev-parse", "--short", "HEAD"])
        .map(|o| String::from_utf8_lossy(&o).trim().to_string())
        .filter(|s| !s.is_empty());
    // `-uno`: untracked files (stray notes, build artifacts) don't change what the binary is
    // built from, so they must not mark it dirty — only modifications to tracked source do.
    let dirty = git(&["status", "--porcelain", "-uno"]).map(|o| !o.is_empty()).unwrap_or(false);

    let desc = match commit {
        Some(c) if dirty => format!("{c}-dirty"),
        Some(c) => c,
        None => "unknown".into(),
    };
    println!("cargo:rustc-env=LIMES_GIT={desc}");

    // Rebuild when the checked-out commit or the working tree's staged state moves, so the
    // stamp doesn't go stale. (Absent in a git-less build; cargo ignores missing paths.)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}
