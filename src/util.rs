//! Small shared helpers.

use std::path::{Path, PathBuf};

/// Locate an executable by scanning `PATH`, like `command -v`.
///
/// Used both to detect host tooling limes mounts in (agents, the rosa client) and to
/// check the rootless prerequisites in `bootstrap`/`doctor`. The executable-bit check
/// matters for the former: a non-executable file on `PATH` is not something the sandbox
/// could run, so reporting it as found would be a lie either way.
pub fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|dir| dir.join(bin)).find(|cand| is_executable(cand))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}
