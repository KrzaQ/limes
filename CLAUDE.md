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
```

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
  `no-new-privileges`, seccomp on, as the invoking uid:gid, with tmpfs `/tmp` and tmpfs
  `$HOME`.
- **Credentials are forwarded as oracles, never as key material**: the SSH agent socket, the
  GPG *extra* (restricted) socket, the rosa broker socket, `~/.gitconfig` ro. Don't mount
  `~/.ssh`, `~/.gnupg`, or rosa's encrypted store (`~/.secrets.json.gpg`, named by
  `~/.config/rosa/config.toml`) — the store staying invisible depends only on `$HOME` being
  tmpfs, so any mount that reaches into `$HOME` risks undoing it. Note `agents.rs`
  deliberately never mounts `~/.local` wholesale for the same reason.
- **A mount path that doesn't exist on the host is a hard error**, not a silently-created
  empty dir. The only exception is config's `optional = true`.

## Architecture

`main.rs` is pure clap wiring: it builds a `Context` and dispatches to one module per
subcommand. `context.rs` resolves host facts once (uid/gid/HOME/XDG_RUNTIME_DIR) and owns
every well-known limes path and constant (`IMAGE_TAG`, `SERVICE`, `LABEL`, socket,
data-root, config dir). New paths belong there, not inlined at the call site.

**`run.rs` — the default action.** The interesting logic is mount precedence. Mounts are
pushed **least-to-most explicit**, then `dedupe()` collapses exact-path collisions with
*last wins*, then `sort_for_nesting()` orders parent-before-child:

```
built-in defaults  →  detected agents  →  rosa  →  workspace (rw)  →  config.toml/config.d  →  --ro  →  --rw
```

So a config entry overrides an implicit default, a CLI flag overrides config, and `--rw`
beats `--ro` for the same path in a single run. Order of the pushes *is* the policy —
changing it changes user-visible precedence.

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
via a dotfiles-owned `config.d` drop-in, not from `default_mounts()`.

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

**Container labels drive discovery.** Every sandbox is stamped `limes=1`,
`limes.workspace=…`, `limes.cmd=…`; `status.rs` and `passthrough.rs` filter on `limes=1`.
Changing the label schema breaks `status`/`stop`/`prune` together.

**`passthrough.rs`** uses `exec()` (process replacement) for `docker`/`compose`/`exec` so the
tty and exit status pass through cleanly, but `Command::status()` for `stop`/`prune` which
need to run code afterward.

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
