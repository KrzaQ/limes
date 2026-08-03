# Directory modes in the tmpfs `$HOME` (and gpg's trustdb)

Design notes in the style of `MACOS-BACKEND.md`. Everything marked *measured* was run
against `7c47341` on this host. Neither change is implemented. Linux only — macOS mounts
nothing, so the host's own directories, modes included, are simply still there.

## Symptom

In any repo with signed commits, inside a sandbox:

```
gpg: WARNING: unsafe permissions on homedir '/home/krzaq/.gnupg'
7c47341 U
```

## Diagnosis (measured)

```
$ lim sh -c 'ls -ldn $HOME/.gnupg; ls -A $HOME/.gnupg'
drwxr-xr-x 2 0 0 60 Jul 22 06:33 /home/krzaq/.gnupg
pubring.kbx
```

Two independent faults, which is why one fix does not silence both:

1. **Mode.** `forward.rs` binds `~/.gnupg/pubring.kbx` same-path. That directory does not
   exist in the tmpfs `$HOME`, so Docker creates the intermediate chain — at 0755. GnuPG
   requires no more than 0700 on its homedir and warns on every invocation. The host's own
   `~/.gnupg` is 0700; nothing outside the sandbox is misconfigured.
2. **Trust.** Only `pubring.kbx` is mounted, so gpg has the public key but no ownertrust:
   the signature verifies, its validity is unknown, and git reports `U` rather than `G`.

Both fixes verified in-sandbox: `chmod 700 $HOME/.gnupg` removes the warning, and
`--ro ~/.gnupg/trustdb.gpg` turns the same two commits from `U` into `G`.

## Decision 1: mirror the host's mode onto implicitly created directories

**Not a config knob.** The obvious shape — a list of paths to chmod — is another blocklist
to maintain, with the same rot problem as `hide`, and it asks the user for a preference
where none exists: the correct mode is not a matter of taste, it is whatever the host has.
Mirroring is also what this tool is *for*, and it fixes `~/.ssh` and `~/.local` in passing
without anyone having to notice they were wrong.

**Rule.** For every mount and bind destination that lies under `$HOME`, walk its ancestors
up to — but excluding — `$HOME`. For each ancestor, emit `chmod <host mode> <path>` into the
startup prelude.

Skip an ancestor when:

- **It is itself a mount destination.** Docker gives it the mounted directory's own mode, so
  there is nothing to fix — and a `chmod` against a read-only mount fails with `EROFS`,
  printing an error on every run. That failure mode is not hypothetical: it is exactly what
  a `link = "parent"` entry under the read-only `~/.config` does today.
- **It does not exist on the host.** There is then no mode to mirror. Ordinary mounts cannot
  hit this (a mount path must exist, so its ancestors do too), but `hide` is exempt from
  must-exist and can name a path whose parent is absent.
- **The host mode is already 0755.** A no-op chmod, and leaving it out keeps the common
  case invisible in `--dry-run`.

Details worth getting right:

- **`$HOME` itself is excluded, deliberately.** The tmpfs is pinned to `mode=1777` for
  reasons recorded in `run.rs`; mirroring the host's 0755 onto it would quietly undo that.
  Exclude it in the code, not by luck, and say why.
- **Modes only, never ownership.** Everything in the sandbox is uid 0, which *is* the
  invoking user.
- **Emit shallowest-first**, so `--dry-run` output is stable and diffable — the same reason
  the mount table is depth-sorted.
- **It belongs in the supervisor's startup**, since `f0eaff5` moved the prelude there: once
  at container creation, before any shell exists, not per `docker exec`.

## Decision 2: mount `trustdb.gpg` read-only, next to `pubring.kbx`

Add it to `add_gpg` in `forward.rs`, in the same shape as the pubring: bound read-only, and
silently skipped when the file is absent.

**Why it does not violate the oracle rule.** `trustdb.gpg` holds ownertrust assignments, not
key material — the same class as the `pubring.kbx` already mounted. What it buys is that
signature status stops being uniformly `U`. A status that is always the same is a status
nobody reads, which is the alarm-fatigue argument that took the root colouring out of the
prompt: keep the signal meaningful or drop it entirely.

**The cost, measured:** `gpg: Note: trustdb not writable` on verbose operations
(`git log --show-signature`). A note, not an error. `gpg --check-trustdb` additionally fails
with `trustdb rec 30: write failed (n=-1): Bad file descriptor` — expected, since it is
trying to rewrite a read-only file, and not an operation anyone runs inside a sandbox.

**The alternative, if that note ever grates:** copy the host's trustdb into
`$XDG_RUNTIME_DIR` at run time and bind *that* read-write, which makes it writable and
ephemeral and silences the note. The precedent exists — it is exactly what `identity.rs`
does for the generated `/etc/passwd` and `/etc/group`, so it would want a `trustdb_file()`
accessor in `context.rs` alongside `passwd_file()`. Deliberately not the first move: it adds
a per-run copy and a well-known path to buy the suppression of one informational line, and
writes to a trustdb inside a sandbox are meaningless anyway.

## Tests

Keep the daemon out of it, the way `seatbelt.rs` and `identity.rs` stay testable off-platform.

- Make the chmod list a **pure function** of `(mount paths, $HOME, mode lookup) → Vec<(PathBuf, u32)>`,
  with the mode lookup injected so tests can fake a host. Cover: a nested mount yields its
  ancestors; a path outside `$HOME` yields nothing; `$HOME` never appears in the output; an
  ancestor that is itself a mount is skipped; an ancestor missing on the host is skipped.
- `forward.rs`: the gpg pieces include the trustdb when present and omit it when absent,
  mirroring whatever the pubring already has.

## Verification

```sh
cd ~/code/misc/limes
script -qec "lim sh -c '
  ls -ldn \$HOME/.gnupg;
  GIT_PAGER=cat git log --format=\"%h %G?\" -2;
  gpg --list-keys 2>&1 | head -3'" /dev/null
```

Expect `drwx------`, two `G` lines, and no unsafe-permissions warning. `GIT_PAGER=cat`
matters: `lim` allocates a tty, so `git log` opens a pager and `script` captures the
alternate-screen escapes instead of the output.
