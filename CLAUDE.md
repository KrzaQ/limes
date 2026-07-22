# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`limes` is a Rust CLI (binary name **`lim`**) that runs a shell or command inside a container
which **mirrors the host userland read-only**, carves explicit read-write holes, and talks
only to a **dedicated rootless Docker daemon**. See `README.md` for the full design and
threat model.

Key framing for any change: limes confines *inadvertent* damage (an agent `rm -rf`-ing
outside the workspace, reading `~/.ssh`, an over-eager `docker system prune`). It is
explicitly **not** a defense against a deliberately malicious process — that's why mounting
a Docker socket and mirroring `/usr` is acceptable here. Don't "harden" against threats
outside that model, and don't weaken the invariants that hold it up.

## Commands

```
make build      # cargo build
make release    # cargo build --release  → target/release/lim
make test       # cargo test  (unit tests for the precedence logic; no integration tests)
make install    # cargo install --path .
make fmt        # cargo fmt
make clippy     # cargo clippy --all-targets
make hooks      # enable the pre-commit fmt check (per-clone, opt-in)
make unhooks    # disable it
```

**The tree is rustfmt-clean and must stay that way.** `rustfmt.toml` sets
`use_small_heuristics = "Max"`, which keeps short calls, literals and structs on one line
— stock rustfmt explodes them across four and reads nothing like the rest of the codebase.
Run `make fmt` before committing; `make hooks` installs a pre-commit check that refuses
otherwise. The hook checks rather than reformats, so the index never diverges from what you
reviewed.

`Makefile.local` is untracked and machine-local (`-include`d by the Makefile); don't
reference or commit it.

The fastest way to check runtime behavior without a working daemon is `lim --dry-run`,
which prints the fully assembled, copy-pasteable `docker run` line and exits.

## Invariants

These are load-bearing; breaking one silently defeats the tool.

- **Every docker invocation goes through `docker::command(ctx)`**, which pins
  `--host unix://$XDG_RUNTIME_DIR/limes-docker.sock`. Never shell out to bare `docker` —
  the user's ambient `DOCKER_HOST`/context must stay pointed at their own daemon, and
  `lim prune`'s safety rests entirely on the limes daemon having its own data-root.
- **Same-path mounts only** (`/path:/path[:ro]`). Absolute paths baked into
  `compile_commands.json`, ccache, and diagnostics must resolve identically inside and out.
  `Mount` in `mounts.rs` has no notion of a differing destination — the few things that do
  need a different destination (SSH/GPG sockets, the docker socket) build their `-v` args by
  hand in `run.rs`.
- **Never `--privileged`.** The container runs with `--read-only` rootfs, `--cap-drop ALL`,
  `no-new-privileges`, seccomp on, with tmpfs `/tmp` and tmpfs `$HOME`.
- **`-u 0:0`, and that *is* the invoking user.** The rootless daemon's user namespace maps
  the invoking user to container uid 0; container uids 1.. come from the subuid range and own
  none of the host's files. Passing `-u {uid}:{gid}` therefore yields a sandbox where the
  workspace, `~/.claude` and every 0700 dotfile are unreadable and unwritable — it looks
  right and is completely broken. `identity.rs` generates the `/etc/passwd` and `/etc/group`
  that make uid 0 resolve to the user's real name, home and login shell, and those two are
  the only mounts whose destination differs from their source. This is safe *only* because
  every docker call is pinned to limes' own rootless daemon; `doctor`'s `rootless` check is
  what guards it, and a Fail there means real root.
- **Credentials are forwarded as oracles, never as key material**: the SSH agent socket, the
  GPG *extra* (restricted) socket, the rosa broker socket, `~/.gitconfig` ro. Don't mount
  `~/.ssh`, `~/.gnupg`, or rosa's encrypted store (`~/.secrets.json.gpg`, named by
  `~/.config/rosa/config.toml`) — the store staying invisible depends only on `$HOME` being
  tmpfs, so any mount that reaches into `$HOME` risks undoing it. Note `agents.rs`
  deliberately never mounts `~/.local` wholesale for the same reason.
- **A mount path that doesn't exist on the host is a hard error**, not a silently-created
  empty dir. The only exception is config's `optional = true`.

## Two backends

Linux runs `docker run` against the dedicated rootless daemon. macOS (experimental) runs
`sandbox-exec` with a generated SBPL profile — there is no container, because the process is
already on the host and there is nothing to mirror. `MACOS-BACKEND.md` is the design record
and includes the measured Seatbelt semantics; read it before touching `seatbelt.rs`.

**The mount table is the shared half.** Both backends consume the same deduped, depth-sorted
`Vec<Mount>` from `assemble_mounts` in `run.rs`; only the final translation differs (`-v`
args vs SBPL rules). Depth-sorting is load-bearing on both — Docker layers the binds, and
Seatbelt takes the *last matching rule*, so shallowest-first puts the specific rule where it
wins. That correspondence is why the precedence engine ports unchanged; don't break it.

Platform gating convention: `bootstrap`/`docker`/`passthrough`/`status` are
`#[cfg(target_os = "linux")]` modules. `seatbelt` and `forward` compile everywhere with
`cfg_attr(…, allow(dead_code))`, so their pure logic stays unit-testable in a Linux dev loop.
The clap surface is deliberately identical on both platforms — the container subcommands
`bail!` on macOS naming themselves Linux-only rather than silently succeeding.

## Architecture

`main.rs` is pure clap wiring: it builds a `Context` and dispatches to one module per
subcommand. `context.rs` resolves host facts once (uid/gid/HOME/XDG_RUNTIME_DIR) and owns
every well-known limes path and constant (`IMAGE_TAG`, `SERVICE`, `LABEL`, socket,
data-root, config dir). New paths belong there, not inlined at the call site.

**`run.rs` — the default action.** The interesting logic is mount precedence. Mounts are
pushed **least-to-most explicit**, then `dedupe()` collapses exact-path collisions with
*last wins*, then `sort_for_nesting()` orders parent-before-child:

```
built-in defaults  →  detected agents  →  rosa  →  workspace (rw)  →  config.toml/config.d  →  --ro  →  --rw  →  --hide
```

So a config entry overrides an implicit default, a CLI flag overrides config, and `--rw`
beats `--ro` for the same path in a single run. `--hide` is last because it is the safety
direction. Order of the pushes *is* the policy — changing it changes user-visible
precedence.

A `Mount` is **not** a bind mount: it is a policy for one path *inside* the sandbox, which
each backend renders its own way (`-v`, `--tmpfs`, or an SBPL rule). `Kind` is deliberately
payload-free so `Mount` stays `PartialEq` — `dedupe` copies the whole kind, and copying any
less quietly breaks last-wins for a mode that carries more than read-only-ness.

**`forward.rs`** owns the four credential/socket forwards (ssh, gpg, rosa, docker) and
resolves each one **built-in default (on) → config `[forward]` → CLI flag**, mirroring how
mounts layer. The paired `--gpg`/`--no-gpg` flags exist so the CLI can beat config in
*both* directions; they rely on clap `overrides_with` for last-one-wins. Anything
same-path (rosa's socket and client binary) is expressed as a `Mount` so it inherits the
precedence chain above; only forwards whose destination differs from their source (gpg,
docker) build raw `-v` args. Each forward no-ops silently when its target is absent, which
is what makes on-by-default safe.

**Nesting vs. collision** are different mechanisms: exact-path duplicates are resolved by
`dedupe`; *nested* paths (`--ro ~/code --rw ~/code/project`) are two separate mounts that
Docker layers, which is why depth-sorting matters.

**`config.rs`** parses `~/.config/limes/config.toml` plus `config.d/*.toml` drop-ins
(filename-sorted drop-ins first, `config.toml` last so it wins). It carries two tables:
`[mounts]`, where path-as-TOML-key gives uniqueness for free, and `[forward]`, whose
fields are `Option<bool>` precisely so drop-ins merge field-by-field — `None` means "this
file said nothing", which is what stops one file from clobbering another's unrelated keys. `link = "parent"` exists because Docker flattens a symlink when it
mounts it: instead limes mounts the target's *parent directory* and emits a `SymlinkSpec`,
which `run.rs` turns into an `sh -c 'ln -sfn …; exec "$@"'` prelude that recreates the
symlink in the tmpfs `$HOME` before exec'ing the real command. This is what makes
self-locating shell config (zsh plugin paths derived from `~/.zshrc`'s own resolved
location) work. Deliberately, limes has **no shell-specific knowledge** — rc files arrive
via a dotfiles-owned `config.d` drop-in, not from `default_mounts()`. `mode = "hide"`
shadows a subpath of a broad mount with an empty tmpfs — directories only, and the one
mode exempt from the must-exist rule (nothing to shadow is a no-op, so a *synced* drop-in
can name credential dirs that exist on only some machines). A sibling `overlay` mode
(ephemeral writes over a host tree, via a `local`-driver overlayfs volume) is wanted but
unbuilt — it rests on a bind nested *inside* an overlay volume, which is untested and is
the live case today, since `~/.config/opencode` sits inside the drop-in's `~/.config`.

**`bootstrap.rs`** writes the vendored `vendor/dockerd-rootless.sh` (from Moby, Apache-2.0,
`include_str!`'d into the binary) to `~/.local/share/limes/bin`, renders a `limes-docker.service`
systemd **user** unit, starts it, and builds the image. It only ever *names* missing
prerequisites (`dockerd`, `rootlesskit`, `slirp4netns`, `newuidmap`, subuid/subgid ranges) —
it never runs a package manager, so limes stays distro-agnostic. Vendoring the launcher is
what removes the AUR / `docker-ce-rootless-extras` dependency; keep it that way.

**`image/Dockerfile`** is `include_str!`'d and fed to `docker build -` with **no build
context**. The image is near-scratch on purpose: usr-merge symlinks (`/bin`, `/lib`, `/lib64`
→ `usr/…`) that resolve into the host `/usr` mounted at runtime, empty mountpoints, and a
static rescue busybox at `/limes` (a path host mounts never shadow). If you add anything to
the image, justify why it can't come from the host mirror.

**`sandbox.rs` owns container lifetime**; `run.rs` owns policy. A second `lim` in a
workspace **joins** the first — PID 1 is a `sleep infinity` supervisor and every shell,
the first included, is a `docker exec`, so no shell owns another's fate. Three things there
are load-bearing and each was measured, not assumed:

- **`--init`.** `sleep` never calls `wait()`, so orphans reparented to it pile up as
  zombies for the container's lifetime. A shell-as-PID-1 hid this because shells reap.
- **`ExecIDs` is the teardown signal.** Docker prunes finished execs from it, so it is an
  exact count of *attached shells* — not processes, which is why no stray background
  daemon can pin a sandbox open forever. The cost is that backgrounding a build and
  leaving does not keep the sandbox up.
- **Two flocks in `$XDG_RUNTIME_DIR`.** `<name>.lock` serialises check→create→initialise,
  closing both the create race and the readiness race (`docker run -d` returns before the
  symlink prelude has finished). `<name>.shells` is held *shared* by every `lim` across its
  whole run and taken *exclusively* by teardown, which covers the gap the daemon cannot
  see: a `lim` that has found the sandbox but not yet attached, whose shell does not exist
  to be counted. Retrying instead would be wrong — it would re-run the user's command.

**`policy.rs` is what makes joining safe.** Before attaching to an existing sandbox, the
resolved `RunSpec` is compared against `docker inspect` — *not* against a fingerprint
label, which would be a second copy of the truth able to go stale. Deriving from the daemon
also means the human-readable diff falls out for free, and printing it is not optional: a
bare "policy mismatch, refusing" is the kind of error people route around by always passing
`--name`, which disables joining entirely. Any difference refuses; env and cwd are exempt
because `docker exec` carries its own `-e`/`-w` and they are per-shell. This is why
`RunSpec` must hold *everything* docker is told — a piece that emitted its own args on the
side would be invisible here, and silently stay invisible.

**Discovery is the name, not a label scan.** `derive_name` is a total function of the
workspace path, so `docker inspect <name>` either hits or it does not. Sandboxes are still
stamped `limes=1`, `limes.workspace=…`, `limes.cmd=…`, and `status.rs`/`passthrough.rs`
filter on `limes=1`; changing that schema breaks `status`/`stop`/`prune` together. Note
`limes.cmd` records only the invocation that *created* the sandbox, so `status` shows a
shell count rather than presenting it as describing the sandbox.

**`passthrough.rs`** uses `exec()` (process replacement) for `docker`/`compose` so the tty
and exit status pass through cleanly, but `Command::status()` for `exec`/`stop`/`prune`,
which need to run code afterward — `exec` because it shares the join-then-maybe-tear-down
path with `run`, and a replaced process could not do the teardown check.

`doctor.rs` is the empirical answer to "is this host set up correctly" — every rootless
prerequisite, kernel gate, and service state has a line there. When you add a runtime
requirement, add a doctor check for it.

## Conventions

- Module-level `//!` docs explain *why* the module exists and what invariant it upholds;
  inline comments explain non-obvious ordering or security decisions. Match that density —
  the codebase reads as prose-with-code, not code-with-noise.
- `anyhow` throughout; errors are user-facing and say what to run next
  (`"run \`lim bootstrap\`, then \`lim doctor\`"`).
- `LIMES_VERSION` is set from `env!("CARGO_PKG_VERSION")` so it can never drift from
  `Cargo.toml` / `lim --version`. Scripts detect the sandbox with `[[ -n $LIMES_VERSION ]]`.
- `config.toml.example` and the README's Configuration section must be updated together
  whenever config gains an option.
