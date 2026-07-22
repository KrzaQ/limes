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

/// Filesystems the kernel refuses as an overlayfs `upperdir`, by `statfs` magic.
///
/// Docker's snapshotter puts its layers on the data-root and stacks an overlay over them,
/// so a data-root on one of these cannot work — the mount fails with `EINVAL`, and what
/// surfaces is a buildkit stack trace about a cache mount rather than a word about the
/// filesystem. ecryptfs is the one that bites in practice: distro installers offer
/// "encrypt my home directory", and the default data-root lives in `$HOME`.
///
/// Deliberately a blocklist of the known-bad rather than an allowlist of the known-good:
/// the long tail of working filesystems is much longer than this list, and refusing to
/// bootstrap on something merely unrecognised would be wrong.
#[cfg(target_os = "linux")]
const UNSUPPORTED_UPPERDIR: &[(i64, &str)] =
    &[(0xf15f, "ecryptfs"), (0x6969, "nfs"), (0x65735546, "fuse"), (0x794c7630, "overlayfs")];

/// The name of `path`'s filesystem if it cannot hold an overlayfs `upperdir`.
///
/// `None` means "no known problem", which includes the case where `statfs` fails — an
/// unreadable path is a different complaint, raised by whoever needs the path to exist.
#[cfg(target_os = "linux")]
pub fn unsupported_upperdir_fs(path: &Path) -> Option<&'static str> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // statfs walks up to the nearest existing ancestor: bootstrap checks the data-root
    // before creating it, and asking about a path that isn't there yet would tell us
    // nothing. The filesystem is a property of the mount point, so the ancestor's answer
    // is the child's answer.
    let existing = path.ancestors().find(|p| p.exists())?;
    let c = CString::new(existing.as_os_str().as_bytes()).ok()?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut buf) } != 0 {
        return None;
    }
    let magic = buf.f_type as i64;
    UNSUPPORTED_UPPERDIR.iter().find(|(m, _)| *m == magic).map(|(_, name)| *name)
}
