# macOS backend — design notes

Status: **experimental backend implemented and working on macOS 26.5 arm64** (2026-07-21).
Originally written the same day as design-only notes; the design survived contact.

`lim` and `lim run` work: writes are confined to the mount table, `--rw`/`--ro` nesting
resolves correctly, and zsh, pty allocation, GUI and Apple Events all work inside. `lim
doctor` reports a macOS-specific check list. The container subcommands fail loudly rather
than silently doing nothing. What is *not* done is Q1 — the writable set is the measured
floor plus the mount table, so real toolchains will hit denials that need adding.

Implementation notes, where they differ from what was planned, are marked **[impl]** below.

Open questions 2 and 3 were **settled empirically on 2026-07-21** against macOS 26.5
(build 25F71, arm64) — see the answers inline below. Question 1 is partly settled: the
device/temp minimum was measured, but the full writable set cannot be lifted from
sandbox-runtime as originally hoped (see Prior art) and must be derived. Questions 4 and 5
remain open.

## Goal

Run `lim` on macOS with the same contract it has on Linux: *"as if I'm on the host, with
safety wheels on"*. The motivating use case is running Claude Code in **auto mode** (the
classifier-based permission mode) without leaving the agent unsandboxed.

Threat model is unchanged from `CLAUDE.md` — Murphy, not Machiavelli. Confining inadvertent
damage, not defending against a deliberately malicious process.

**Explicit non-goal: network filtering.** Not wanted, don't build it.

## The load-bearing conclusion: Seatbelt, not a container

A Linux container on macOS is **incoherent**, not merely hard. Mirroring is the whole
feature (`run.rs:141` mounts the host `/usr` read-only so a binary built inside links against
the same `libQt6Core.so.6` it would outside). macOS `/usr` is Mach-O + dyld + libSystem —
there is no way to mount it into a Linux container and have anything link. A Lima/UTM Linux
VM doesn't rescue it either: you'd mirror the *VM's* `/usr`, so a binary built inside is an
ELF the Mac cannot run natively. **Don't spend time re-deriving this.** Docker Desktop /
colima / OrbStack are all the same dead end.

The macOS answer is **Seatbelt** — `sandbox-exec` with an SBPL profile. The process runs
natively (real dyld, real frameworks, GUI possible) with kernel-enforced restrictions on what
it may write. The sandbox is inherited by every descendant process, so `lim run` →
`zsh -l` → `claude` → `bash` → `npm` all stay inside; you cannot escape by spawning.

*Verified 2026-07-21:* writes stay denied at every depth through `sh` → `zsh` → `sh`, and a
sandboxed process cannot re-invoke `sandbox-exec` to widen its own policy — the nested call
fails with `sandbox_apply: Operation not permitted` (rc 71) even when handed a fully
permissive profile written from outside. Seatbelt narrows and never widens, which is a
stronger guarantee than mere inheritance.

The key economy: **on macOS the mirroring is free.** Nearly everything in `run.rs` exists to
reconstruct "the host" inside a container that starts out as not-the-host. On macOS the
process *is* on the host, so all of that machinery collapses to nothing and what remains is
just the write policy. The macOS backend is *smaller* than the Linux one, not larger.

## Prior art — crib from this, don't derive

Claude Code ships a Seatbelt-based sandbox for its Bash tool on macOS (`/sandbox`,
configured under a `sandbox` key in `settings.json`). The same primitives are published
standalone as [`@anthropic-ai/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime)
(Seatbelt on macOS, bubblewrap + socat on Linux), which can wrap a whole process rather than
just Bash.

This is a working implementation of most of what the macOS backend needs. Read its profile
before writing ours.

**Correction (2026-07-21, after reading the source): it does not ship a writable-path list.**
The premise that one could be lifted from it is wrong. `generateWriteRules` in
`src/sandbox/macos-sandbox-utils.ts` takes a caller-supplied `allowOnly` array and, given no
write config at all, emits a bare `(allow file-write*)`. The tool is primarily a *network* and
*read*-restriction harness; write restriction is an opt-in whose contents are the caller's
problem. Repo-wide there is no reference to `Library/Caches` or `DerivedData` at all. Q1 has
to be derived, not lifted.

What *is* worth taking from it, and has been verified here:

- the device-file essentials and the pty block (both reproduced under Q1 below);
- `macGetMandatoryDenyPatterns` — a list of paths that execute code later if written, which is
  a genuinely good idea limes should steal (see "Dangerous files" below);
- independent corroboration of the Q2 ordering result: its read-rule generator is built on
  `(allow …)` → `(deny broad …)` → `(allow narrow …)` with the comment "allowWithinDeny takes
  precedence over denyOnly", which is last-wins by construction.

Note that Claude Code's own sandbox does **not** substitute for limes here: it covers Bash
subprocesses only. Read/Edit/Write go through the permission system, so in auto mode a
classifier is the only thing between the model and the filesystem for file tools. Wrapping
the entire `claude` process — what limes does — puts the kernel there instead. That is the
reason this backend is worth building.

## The mapping

| limes on Linux | macOS backend |
|---|---|
| `docker run` | `sandbox-exec -f <profile> zsh -l` |
| `-v /usr:ro` mirror, the `/etc` handful, `ld.so.cache` | **deleted** — SIP already protects `/System`, `/usr`, `/bin`, `/sbin` |
| `--read-only` rootfs | `(deny file-write*)` as the base rule |
| `Mount::rw(p)` | `(allow file-write* (subpath p))` |
| `Mount::ro(p)` | **[impl]** `(deny file-write* (subpath p))` — *not* the no-op assumed here; see below |
| uid/gid, `/etc/passwd`, `/etc/group` | **deleted** — no identity translation |
| `symlink_prelude` (`run.rs:110-118`, `config.rs` `link = "parent"`) | **deleted** — nothing flattens symlinks; `link` becomes a no-op |
| tmpfs `$HOME` | **no equivalent** — see Open Question 2 |
| `--cap-drop ALL`, `no-new-privileges`, seccomp | mostly n/a |
| ssh / gpg / rosa forwarding (`forward.rs`) | **free** — same host, the agents just work |
| `config.d` mount table | unchanged — becomes the profile generator's input |

The dotfiles `config.d/dotfiles.toml` drop-in works as-is: its keys are home-relative and
machine-independent, and `link = "parent"` degrades harmlessly to a no-op.

**[impl] `Mount::ro` is not a no-op.** The table above assumed it was, on the reasoning that
reads are free and the base rule already denies writes. That holds for a *top-level* `--ro`,
but not for one nested inside a `--rw`: `--rw ~/code --ro ~/code/secret` needs the inner deny
emitted, or the parent's allow covers the hole. Emitting a deny unconditionally is both
simpler and correct — the top-level case is merely redundant. Verified end to end: a `--ro`
inside the read-write workspace denies the write.

## What is lost, and must be said out loud

- **No container ⇒ no container lifecycle.** `status.rs`, `passthrough.rs` (`stop`/`prune`/
  `exec`/`docker`/`compose`), and the whole `LABEL` discovery scheme are Docker-object
  management. A sandboxed process is just a process. Decide deliberately whether these
  become process-table queries or Linux-only subcommands — don't let `lim status` silently
  return nothing on macOS.
- **No PID or network isolation.** Acceptable under the threat model, but `doctor.rs` must
  not report a clean bill of health for checks it isn't running. The macOS doctor should say
  which guarantees are absent, not just omit their lines.
- **Rootless Docker's entire purpose is container-escape hardening** — irrelevant to Murphy.
  This is why roughly half of `bootstrap.rs` and `doctor.rs` (prereq detection, the vendored
  launcher, the systemd unit, linger, subuid/subgid, the AppArmor branch) simply *evaporates*
  on macOS rather than needing a port.

## Dangerous files — worth stealing, and it exposes a Linux gap

sandbox-runtime denies writes to a fixed set of paths whose common property is that writing
them **executes code later, outside the sandbox**:

```
.gitconfig  .gitmodules  .bashrc  .bash_profile  .zshrc  .zprofile
.profile    .ripgreprc   .mcp.json                          (DANGEROUS_FILES)
.vscode/    .idea/       .claude/commands/  .claude/agents/ (directories)
.git/hooks/            always denied
.git/config            denied unless allowGitConfig
```

`.git` is deliberately *not* denied wholesale — git needs it writable — so they block the two
paths inside it that execute.

This is a precise fit for the Murphy model, and sharper than the doc's original `~/.claude/
settings.json` example: the harm isn't the write, it's that the sandbox's boundary is spatial
while the damage is *temporal*. A confined process cannot hurt you now; the file it wrote runs
unconfined at your next shell start or `git commit`.

**That reasoning applies to limes on Linux today, and there is a live gap.** `$HOME` is tmpfs,
so a stray `~/.zshrc` write evaporates with the container — that half is already covered, by
construction rather than by policy. But **the workspace is mounted `rw`, so `.git/hooks/` in
it persists and executes on the host at the next git operation**, entirely outside the
sandbox. Same for `.vscode/tasks.json`. Whether to carve those out is a real decision, not an
obvious yes: writing a pre-commit hook is a legitimate thing to ask an agent to do, so a blunt
deny trades a genuine capability for the protection. Worth deciding deliberately rather than
by default — and note it is a `mounts.rs`/`run.rs` question on both platforms, not a macOS one.

If it is implemented on macOS, mind the operation-specificity trap in Q2: expressing it with
`file-write-unlink` denies would silently make files undeletable inside `--rw` regions.

## Open questions — 2 and 3 settled, 1 partly, 4 and 5 still open

**1. The writable set.** *Still open, but the floor is now measured.* This is the bulk of the
work and it fails *confusingly* rather than safely: miss a path and builds break in ways that
don't point at the sandbox. Known candidates: `~/Library/Caches`,
`~/Library/Developer/Xcode/DerivedData`, `~/.cargo/registry`, `~/.npm`, `$TMPDIR`. **Lift this
list from sandbox-runtime's profile rather than deriving it.**

The confusing-failure prediction is correct and bites immediately. Under a bare
`(deny file-write*)`, `echo hi > /dev/null` fails with `/bin/sh: /dev/null: Operation not
permitted` and `mktemp` fails on `/var/folders/…` — before any project tooling is involved
at all. The measured minimum for an ordinary shell to stop erroring:

```
(allow file-write* (literal "/dev/null"))
(allow file-write* (literal "/dev/zero"))
(allow file-write* (literal "/dev/dtracehelper"))
(allow file-write* (subpath "/dev/fd"))
(allow file-write* (regex #"^/dev/tty"))
(allow file-write* (subpath "<resolved $TMPDIR>"))
```

`$TMPDIR` must be resolved (`/private/var/folders/…`, not `/var/folders/…`) for the same
reason `/tmp` rules don't match — see Q2's canonicalization note. This is the floor, not the
answer; project toolchains need much more, and since sandbox-runtime turns out not to supply
that list (see Prior art), it has to be built from the tools actually used.

**Ptys need explicit rules, and this is not optional.** A write-restricted profile denies
`openpty` outright — `script(1)` fails with `openpty: Operation not permitted`. *Inheriting*
an existing tty is fine (`zsh -l -c` works without any pty rule), so a bare `lim` attached to
your terminal would appear to work, and then anything that *allocates* a pty inside it — tmux,
node-pty, and Claude Code itself when it spawns shells — would break. Include these
unconditionally rather than behind a flag:

```
(allow pseudo-tty)
(allow file-ioctl (literal "/dev/ptmx") (regex #"^/dev/ttys"))
(allow file-read* file-write* (literal "/dev/ptmx") (regex #"^/dev/ttys"))
```

**2. Does a deny nest inside an allow?** **SETTLED — yes, in both directions. SBPL is
last-matching-rule-wins, not deny-always-wins.** The third-party claim was simply wrong;
Claude Code does not need to be computing complements.

Measured, with `(allow default)` then `(deny file-write*)` as the base and only the trailing
rules varying:

| rules, in order | outer | inner |
|---|---|---|
| `allow (subpath BASE)` then `deny (literal BASE/p)` | ALLOW | **DENY** |
| `deny (literal BASE/p)` then `allow (subpath BASE)` | ALLOW | **ALLOW** |
| `allow (subpath BASE)` then `deny (subpath BASE/inner)` | ALLOW | **DENY** |
| `deny (subpath BASE)` then `allow (subpath BASE/inner)` | DENY | **ALLOW** |

Rows 1 and 2 are the same two rules in the opposite order and give opposite results, which
pins the semantics: within one operation, **order alone decides, and the later rule wins.**

**Refinement — order only decides *within* an operation.** A rule naming a narrower operation
beats a wildcard one regardless of order. Measured, for `file-write-unlink`:

| rules, in order | create | unlink |
|---|---|---|
| `allow file-write* (subpath D)` | ALLOW | ALLOW |
| `deny file-write-unlink` then `allow file-write*` | ALLOW | **DENY** |
| `allow file-write*` then `deny file-write-unlink` | ALLOW | **DENY** |
| `deny file-write-unlink`, `allow file-write*`, `allow file-write-unlink` | ALLOW | ALLOW |

Rows 2 and 3 are order-swapped and agree, so the wildcard never overrides the specific
operation; row 4 shows only a same-operation rule can. The accurate model is therefore
**more specific operation wins; ties broken by order, last one first.**

This does not bite limes as designed — its mount table only ever produces `file-write*` rules,
which keeps it in the order-decides regime where `sort_for_nesting` is correct. It would bite
immediately if narrow-operation rules were ever added (the "dangerous files" hardening below
is the obvious temptation): a `(deny file-write-unlink)` anywhere would make files
undeletable inside `--rw` regions, and no amount of reordering would fix it. Re-allow the
same operation explicitly, as row 4 does.

Two consequences that settle the design:

- **`sort_for_nesting()` ports unchanged and is exactly right.** It already orders mounts
  parent-before-child, so emitting rules in that order puts the deeper, more specific rule
  later — where it wins. The precedence engine needs no macOS analog; it *is* the analog.
  Nested config entries need no hand-flattening.
- The `~/.claude` carve-out works as hoped: `allow (subpath ~/.claude)` followed by
  `deny (literal ~/.claude/settings.json)` yields a writable auth token and an unwritable
  settings file. Verified end to end.

**Canonicalization gotcha, found while testing:** SBPL matches the *resolved* path. A rule
naming `/tmp/x` never matches, because the real path is `/private/tmp/x` — the write is
denied while the profile looks correct, which is precisely the confusing failure mode Q1
warns about. limes is already safe here: `mounts::canonicalize` is `realpath`, so every path
in the mount table is resolved before it would reach a generator. Do not lose that property.

**3. GUI / WindowServer access.** **SETTLED — GUI parity comes free, provided the profile
restricts only `file-write*` and leaves `mach-lookup` alone.**

Under the proposed shape (`(allow default)` + `(deny file-write*)` + the mount table),
CoreGraphics reports the real display (`display=1 1512x982`), AppKit's `NSApplication.shared`
connects, and `osascript` drives Finder. No mach rules of any kind were needed.

The mechanism was confirmed by breaking it deliberately: adding
`(deny mach-lookup (global-name "com.apple.windowserver.active"))` to an otherwise open
profile drops CoreGraphics to `display_id=0`. So the service name matters — it just never
comes up unless you deny it.

One trap for anyone tempted to tighten this later: a `(deny default)` profile whose *only*
mach rule is `(allow mach-lookup (global-name "com.apple.windowserver.active"))` is enough
for CoreGraphics but **not** for AppKit, which aborts with `Failure on line 688 in function
id scheduleApplication…`. Full GUI needs blanket `mach-lookup`. That is fine here — under
Murphy, the axis being defended is file writes, not mach services — but it means the minimal
windowserver allow is a false economy.

Also: the `-600` Apple Events failure in Claude Code's docs is a property of **Claude Code's
profile**, not of Seatbelt. `osascript` works normally under ours.

**4. Known tool friction on Seatbelt** (from Claude Code's troubleshooting docs; assume it
applies to us): Go-based CLIs (`gh`, `gcloud`, `terraform`) fail TLS verification; `docker` is
flatly incompatible; `jest` needs `--no-watchman`. We may want an `excludedCommands`
equivalent, or may decide that's out of scope.

**5. `sandbox-exec` is marked deprecated** in its man page and has been for over a decade,
while Apple continues to ship and depend on it (and Claude Code ships on it). It works today;
there is no stability contract. Accept this or don't build the backend.

## Files that change

- `context.rs` — platform split. Everything Docker-shaped (`socket()`, `docker_host()`,
  `data_root()`, `service_file()`, `launcher_path()`, `IMAGE_TAG`, `SERVICE`, `LABEL`) is
  Linux-only. `config_dir()` / `config_file()` / `config_d_dir()` stay shared.
- `bootstrap.rs` — `cfg(target_os = "macos")` short-circuits: no prereqs, no launcher, no
  systemd unit, no linger, no image build. Possibly a no-op that just prints "nothing to do".
- `doctor.rs` — per-platform check list. Drop rootlesskit/subuid/userns/linger/systemctl/
  image rows; add profile-generation and `sandbox-exec` availability. State the absent
  guarantees explicitly (see "What is lost").
- `run.rs` — the real work. `default_mounts()` drops `/usr` and the `/etc` handful. A new
  profile-emitter replaces the `docker run` assembly. **The mount-precedence engine
  (`dedupe`, push order, config layering) ports unchanged and should not be touched** — it is
  the part of limes worth keeping, and its output is just as good an input to an SBPL
  generator as to a `-v` list.
- `forward.rs` — largely a no-op on macOS; the sockets are already reachable. Keep `rosa`'s
  same-path `Mount` handling if it costs nothing.
- `image/Dockerfile`, `vendor/dockerd-rootless.sh` — Linux-only, untouched.

`--dry-run` should print the generated SBPL profile plus the `sandbox-exec` line, mirroring
what it does for `docker run` today. That's the fastest way to iterate without a working
sandbox, and matches the existing convention in `CLAUDE.md`.

## Suggested order

1. ~~Test Open Questions 2 and 3 on a Mac~~ — **done 2026-07-21.** Neither invalidated a
   design choice; Q2 strengthened one (`sort_for_nesting` is the emission order, unchanged).
2. ~~Read sandbox-runtime's profile; extract the writable-path list (Q1).~~ — **done
   2026-07-21, and the list isn't there.** Its device/pty blocks and its dangerous-files list
   were worth taking; the writable set was not, because it doesn't ship one. Q1 now needs
   deriving from the toolchains actually used, which is the only thing still blocking the
   generator — the rule *semantics* are fully settled.
3. Platform-split `context.rs` / `bootstrap.rs` / `doctor.rs` — mechanical, independent of
   the above.
4. ~~Write the profile generator~~ — **done**, as `src/seatbelt.rs`. It is deliberately
   compiled on both platforms (pure string work) so its tests run in a Linux dev loop; only
   execution is `cfg`-gated. `run.rs` now shares `assemble_mounts` between backends, so the
   precedence chain has exactly one implementation.
5. ~~Decide the fate of `status` / `stop` / `prune` / `exec`~~ — **provisionally decided**:
   the CLI surface stays identical across platforms so `--help` and the docs don't fork, and
   the container subcommands `bail!` on macOS naming themselves Linux-only. Loud beats silent,
   per "What is lost". Revisit if any of them turn out to have a sensible process-table
   analogue.

Still to do: Q1's writable set (run real builds, collect denials), Q4 tool friction, Q5.

A note on iterating from Linux: `cargo check --target x86_64-apple-darwin` typechecks
`cfg(target_os = "macos")` branches without an Apple SDK, because `check` does not link. So
the platform split and the generator can both be written and typechecked on the Linux box;
only running them needs the Mac.
