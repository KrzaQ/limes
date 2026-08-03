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
- **The sandbox never invents a directory mode.** The tmpfs `$HOME` starts empty, so Docker
  fabricates the ancestor chain of every mount under it — at 0755, whatever the host has.
  That is why `~/.gnupg` used to arrive 0755 and gpg warned about unsafe permissions on every
  invocation. `mounts::invented_dirs` emits a mode-pinned `--tmpfs` for each such directory,
  and `Kind::Hide` carries its host mode for the same reason. **Declared, not chmod'd**: a
  prelude `chmod` would be invisible to `policy`'s join diff, and `sandbox::initialize`
  discards stderr unless the script's *last* command fails, so a wrong skip rule would be
  silent rather than noisy. The predicate is "did Docker have to invent this?" — a directory
  reached *through* a bind was not, so "is it a mount destination" only approximates it.
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
  `~/.ssh` or `~/.gnupg` — the tmpfs `$HOME` is the only thing keeping them out, so any
  mount that reaches into `$HOME` risks undoing it. Note `agents.rs` deliberately never
  mounts `~/.local` wholesale for the same reason. rosa's encrypted store
  (`~/.config/rosa/secrets.json.gpg`) is the exception that got a mechanism instead of a
  rule: since rosa put its socket beside the store, `forward::rosa_mounts` shadows
  `~/.config/rosa` outright rather than trusting nobody to mount `~/.config`.
- **A mount path that doesn't exist on the host is a hard error**, not a silently-created
  empty dir. The only exception is config's `optional = true`.
- **A project file is policy the sandbox can write, so it is gated.** `.limes.local.toml`
  lives in the workspace — the one tree mounted read-write — so obeying one unconditionally
  would let anything inside grant itself a mount by appending to it. `trust.rs` records a
  byte-exact copy of what was approved under `$XDG_DATA_HOME/limes/trust/`, and any
  difference refuses the run *and prints the delta*, for the same reason `policy.rs` prints
  its diff. The gate rests entirely on the store being unreachable from inside:
  `run::guard_trust_store` hard-fails if any `rw` mount contains it, `doctor` reports the
  standing half of that, and both compare via `mounts::resolve_existing` rather than
  lexically — a symlinked ancestor would otherwise hide a real containment. Never make the
  store `$XDG_CONFIG_HOME`-shaped: that directory is synced by dotfiles, and an approval is
  of one file's bytes *on one machine*.

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
built-in defaults  →  detected agents  →  rosa  →  system gitconfig  →  workspace (rw)  →  config.toml/config.d  →  .limes.local.toml  →  --ro  →  --rw  →  --hide
```

So a config entry overrides an implicit default, a CLI flag overrides config, and `--rw`
beats `--ro` for the same path in a single run. `--hide` is last because it is the safety
direction. Order of the pushes *is* the policy — changing it changes user-visible
precedence.

The workspace rides that chain like anything else, so a `[mounts]` entry naming it takes it
read-only — correct by the chain, and silent enough to read as a broken sandbox rather than
as config. `workspace_downgrade` reports that after `dedupe` has settled, and only when no
CLI flag named the path. Deliberately a warning and not a refusal: `lim --ro .` is a real
thing to want, and the later layer is *supposed* to win.

**`resolve_env` is the same chain for the environment**, and only that chain is shared:

```
HOME/LIMES_VERSION/XDG_RUNTIME_DIR  →  GIT_CONFIG_SYSTEM  →  forwards  →  config.toml/config.d  →  .limes.local.toml  →  -e
```

`dedupe_env` then collapses duplicate names last-wins, mirroring `dedupe`. Canonicalising
here rather than leaving it to Docker is load-bearing now that `policy` compares the
environment exactly. Env has no nesting to sort and no default-mirror to carve holes in — the
sandbox environment starts nearly *empty*, so the language is additive and there is no
`hide` direction to design. `[env]` is deliberately plain key/value: no expansion, and no
form that reads the host's environment, which would be the first mechanism to hand a sandbox
key material rather than an oracle. `RESERVED_ENV` (`HOME`, `LIMES_VERSION`) is refused
because limes computes against both elsewhere. **The check lives in `run.rs`, not in
`config.rs`** — that is where the layers meet, and a copy in either config module would
leave the other free to set `HOME`.

A `Mount` is **not** a bind mount: it is a policy for one path *inside* the sandbox, which
each backend renders its own way (`-v`, `--tmpfs`, or an SBPL rule). `Kind` must stay
`Copy + Eq` so `Mount` stays `PartialEq` — `dedupe` copies the whole kind, and copying any
less quietly breaks last-wins for a mode that carries more than read-only-ness. `Hide`
*does* carry more: the host directory's mode, so a hidden path is never wider inside than
out.

`run.rs` also generates the **system gitconfig** (`identity::SYSTEM_GITCONFIG`, mounted
same-path and named by `GIT_CONFIG_SYSTEM`), which is not a convenience: without
`core.checkStat = minimal` every git command inside re-hashes the work tree and rewrites
the index, because uid 0 does not match the uid the index recorded — the one piece of the
`-u 0:0` fallout that isn't merely cosmetic. It is git's **lowest** tier on purpose, so
`~/.gitconfig` (still mounted verbatim, ro) and any repo override it; it must never be set
in the user's own config instead, where it would follow them onto the host and weaken a
check that costs nothing there. Resolves like a forward (default on → config
`system_gitconfig` → `--system-gitconfig`/`--no-system-gitconfig`) and reuses
`forward::enabled`/`tri` for it, but deliberately does not join `Forwards` — it forwards
nothing, and that module's "oracle, never key material" framing is worth keeping exact.

**`forward.rs`** owns the four credential/socket forwards (ssh, gpg, rosa, docker) and
resolves each one **built-in default (on) → config `[forward]` → CLI flag**, mirroring how
mounts layer. The paired `--gpg`/`--no-gpg` flags exist so the CLI can beat config in
*both* directions; they rely on clap `overrides_with` for last-one-wins. Anything
same-path (rosa's socket, client binary and store shadow) is expressed as a `Mount` so it
inherits the precedence chain above; only forwards whose destination differs from their
source (gpg, docker) build raw `-v` args. Each forward no-ops silently when its target is
absent, which is what makes on-by-default safe — with one deliberate exception: rosa's
store shadow is emitted even under `--no-rosa`, since declining to forward the broker is
not a request to expose the secrets.

`rosa_socket` **asks `rosa sock`** rather than deriving the path. limes used to carry a
copy of rosa's rule, and when rosa moved the socket out of `$XDG_RUNTIME_DIR` the copy went
stale — a missing socket reads as "no agent running", so the forward silently disappeared
rather than failing. Any other tool's path that tool can print is worth asking for.

**Nesting vs. collision** are different mechanisms: exact-path duplicates are resolved by
`dedupe`; *nested* paths (`--ro ~/code --rw ~/code/project`) are two separate mounts that
Docker layers, which is why depth-sorting matters.

**`config.rs`** parses `~/.config/limes/config.toml` plus `config.d/*.toml` drop-ins
(filename-sorted drop-ins first, `config.toml` last so it wins). Its tables split by how
they merge: `[mounts]` and `[env]` are keyed maps, where path- or name-as-TOML-key gives
uniqueness and whole-key last-wins for free; `[forward]`'s fields are `Option<bool>`
precisely so drop-ins merge field-by-field — `None` means "this file said nothing", which is
what stops one file from clobbering another's unrelated keys. `[env]` values are `String`,
so a non-string is a parse error rather than a coercion, and the map is a `BTreeMap` so a
layer's contribution is name-ordered and identical run to run — which matters because the
environment is part of the join policy, and a diff that depended on TOML map ordering would
come and go. `link = "parent"` exists because Docker flattens a symlink when it
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

**`local.rs` + `trust.rs`** are the per-project half of config. `local.rs` walks from the
workspace up to (not including) `$HOME` collecting `.limes.local.toml`, applies them
**shallowest-first** — so a file at `~/code/work` covers every repo beneath it and a
per-repo file refines rather than replaces it — and slots the result between config and the
CLI flags. Its schema is deliberately *smaller* than `Config`'s (`[mounts]`, `[toolchains]`
and `[env]` only) but shares config's spec types through `config::resolve_specs`, so `hide`,
`link = "parent"`, `optional` and the toolchain recipes cannot drift between the two; the
one difference is that a relative path resolves against **the file's own directory**, not
the cwd, which varies with the subdirectory `lim` was run from. `[env]` has no spec type to
share — it is plain key/value — so what must not drift is its *validation*, and that is why
`run::check_name` owns it rather than either config module. It is accepted here at all
because the table is only literals; `check_name` also refuses a name containing `=`, since a
TOML key is an arbitrary string and `"HOME=x" = ""` would otherwise render as `HOME=x=` and
walk straight past `RESERVED_ENV`. An `[env]` entry shows its **value** in the trust diff —
a `PATH` gaining a directory is the whole of what changed, and `env PATH  (set)` would hide
exactly the thing worth looking at. `trust.rs` is the approval
store plus the `lim trust init|add|list|revoke` verbs. It stores the approved *bytes*, not a
digest, because a digest can only say "this changed" and the refusal has to say what;
the filename key is a hand-rolled FNV-1a and is explicitly **not** a security primitive —
all of it rests on the byte comparison, with a `.path` sidecar to catch a collision and fail
closed. Bare `lim trust` lists rather than approving: the command typed reflexively after a
refusal must show, never grant.

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
`--name`, which disables joining entirely. Any difference refuses. This is why
`RunSpec` must hold *everything* docker is told — a piece that emitted its own args on the
side would be invisible here, and silently stay invisible.

**Only cwd is exempt**, because `docker exec` carries its own `-w`. The *environment* is
compared: `docker run` bakes it into the container, so a second `lim` carrying a different
`[env]` or `-e` cannot apply it, and dropping it silently is the failure this module exists
to stop. Two consequences. Everything reaching `RunSpec.env` must be a full `NAME=VALUE` —
Docker's bare `-e NAME` form resolves on the way in, so it would never reach the spec and
would read as a difference on every join (`run::cli_env` resolves the CLI form for exactly
this reason; `forward.rs` spells its entries out for the same one). And the requested side
must add `context::IMAGE_ENV`, the image's own `ENV`, which `docker inspect` reports in the
same list — without it the image's `PATH` is a variable only the running sandbox has, and
*every* join refuses on the first try. That constant restates the Dockerfile, which is only
safe because `bootstrap`'s `image_env_matches_the_dockerfile` pins the two together.

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
- `config.toml.example`, `limes.local.toml.template` and the README's Configuration section
  must be updated together whenever either config surface gains an option. The template is
  the only documentation a project file gets at the point of use, so it has to state the
  trust rule and what is *not* accepted there, not just the syntax.
