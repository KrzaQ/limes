# limes

A host-mirroring sandbox for running coding agents (Claude Code, opencode) and dev
commands. `limes` drops you into `zsh` inside a container that **mirrors your host
userland read-only**, carves out **explicit read-write holes**, and talks only to a
**dedicated rootless Docker daemon**. The command is `lim`.

The name is Latin *limes* — the fortified Roman frontier, and the root of the word
*limit*.

## Threat model

`limes` confines **inadvertent** damage: an agent running `rm -rf` outside the
workspace, reading `~/.ssh` or `~/.aws`, wandering into `/etc`, or an over-eager
`docker system prune` taking out unrelated services. It is **not** built to stop a
deliberately malicious agent, and it does not defend against kernel-level container
escape. That scope is what makes mounting a Docker socket and mirroring the host
userland acceptable — the escalation paths they open require *intent*, not an accident.

If you need to contain a hostile process, use a VM, not this.

## What it does

- **Mirrors the host userland** (`/usr`) read-only, so the box has your exact tools and
  compiler versions with zero per-project toolchain setup. The image itself is nearly
  empty — just usr-merge symlinks, mountpoints, and a rescue busybox.
- **Same-path mounts** (`/path` → `/path`) so absolute paths in `compile_commands.json`,
  `ccache`, and diagnostics stay valid inside and out.
- **Explicit read-write holes** via repeatable `--ro`/`--rw`. Nesting works in any order:
  `--ro ~/code --rw ~/code/project` makes `~/code` read-only with a writable window.
- **Ephemeral by construction**: read-only rootfs, a tmpfs `/tmp`, and a tmpfs `$HOME`.
  Nothing persists except your explicit `--rw` mounts, and `~/.claude`.
- **Auto-detects agents**: if `claude` / `opencode` are on your host `PATH`, their
  program files are mounted read-only and their auth/state read-write, so they run
  already signed in. Opt out with `--no-agents` / `--no-claude` / `--no-opencode`.
- **Forwards credentials, never keys**: the SSH agent socket, the GPG *extra* (restricted)
  socket, and `~/.gitconfig` — the container can *use* your keys while the agent is
  unlocked but cannot read them out.
- **Dedicated rootless daemon** with its own data-root, so `lim prune` can only ever
  remove limes's own containers/images/volumes — never anything on your system daemon.
- **Sets `LIMES_VERSION`** inside the sandbox — presence tells a shell/script it's running
  in limes (`[[ -n $LIMES_VERSION ]]`), and the value is the limes version.

## Usage

```
lim                       # zsh in a sandbox of $PWD (read-write)
lim run -- make test      # run a command instead of a shell
lim --ro ~/code --rw ~/code/project    # read-only tree with a writable window
lim --dry-run             # print the docker run it would execute, and stop
lim --no-agents           # don't mount claude/opencode
lim --no-gpg --no-docker  # turn off individual forwards for one run

lim bootstrap             # one-time: set up the rootless daemon + build the image
lim doctor                # health check of the installation
lim build                 # (re)build the image
lim status                # list running sandboxes
lim exec <name>           # a second shell into a running sandbox
lim stop --all            # stop running sandboxes
lim prune                 # reclaim space (safe: dedicated daemon)
lim docker ps             # run docker against the limes daemon
```

## Setup

`lim bootstrap` names any missing prerequisites and stops (it never runs a package manager
for you). They're all in **official repos** — `docker`, `rootlesskit`, `slirp4netns`, and
`shadow` (for `newuidmap`) — so there's no AUR package on Arch and no
`docker-ce-rootless-extras` on Debian/Ubuntu: limes vendors the rootless launcher
(`dockerd-rootless.sh`, from Moby, Apache-2.0) and installs it to `~/.local/share/limes/bin`
itself. Once the prerequisites and subuid/subgid ranges are in place, bootstrap writes a
`limes-docker.service` user unit, starts it, and builds the image. Run `lim doctor` any time
to see what's missing.

Auto mode inside the container relies on your host `~/.claude` settings — remove any
`permissions.disableAutoMode` and set `"defaultMode": "acceptEdits"` in
`~/.claude/settings.json` if you want `claude --permission-mode auto` available.

## Configuration

Standing default mounts live in `~/.config/limes/config.toml` (honoring
`$XDG_CONFIG_HOME`). It's **per-machine and hand-written** — not something you sync,
since it names absolute paths that differ across machines (same idea as `~/.gitconfig`).

```toml
[mounts]
"/storage"    = "ro"                          # shorthand for { mode = "ro" }
"~/scratch"   = { mode = "rw" }
"~/.zshrc"    = { mode = "ro", link = "parent" }   # recreate the symlink, mount its dir
"~/.zshrc.local" = { mode = "ro", optional = true } # skip if absent
```

A `[forward]` table carries standing on/off switches for the credential and socket
forwards, for the same reason: a machine where you never want GPG forwarded shouldn't need
a flag on every run.

```toml
[forward]
ssh    = true    # SSH agent socket           (default: on)
gpg    = false   # GPG extra agent socket     (default: on)
docker = false   # the limes docker socket    (default: on)
```

All four are on by default and each no-ops silently when the thing it forwards isn't there,
so the defaults stay harmless on a host running none of them. Every one has a matching pair
of flags — `--gpg` / `--no-gpg`, `--docker` / `--no-docker`, and so on — and the CLI wins
over config in *both* directions, so a standing `gpg = false` is still escapable with
`--gpg` for a single run. `docker = false` drops the socket *and* `DOCKER_HOST`, so nothing
inside is left pointing at a socket that isn't there.

The path is the key (so a path can't be listed twice), `~` and `$VAR` are expanded, and
`"ro"` is shorthand for `{ mode = "ro" }`. Every path must exist — a missing one is a hard
error, just like a bad `--ro`/`--rw` — unless `optional = true`, which skips it. Config
mounts override the built-in defaults but lose to CLI flags, so `--rw <path>` still wins for
a single run, and `--no-config` ignores config entirely. See `config.toml.example`.

**`link = "parent"`** handles symlinked dotfiles. docker flattens a symlink when it mounts
it, so a config like `~/.zshrc` that finds its plugins relative to its *own* resolved path
would break inside the sandbox. With `link = "parent"`, limes instead **recreates the
symlink** inside (pointing at the same target) and mounts the target's **parent directory**
ro — so siblings like a zsh `plugins/` dir come along, and self-locating config resolves
exactly as on the host.

**Drop-ins:** alongside `config.toml`, limes also reads `~/.config/limes/config.d/*.toml`
(merged, `config.toml` winning on collisions). `config.toml` is yours to hand-write;
`config.d/` is for whole files owned by tools or installers — e.g. a dotfiles repo can ship
one declaring its shell rc files with `link = "parent"`, so your full shell environment
mirrors into the sandbox without limes needing to know anything about it.

## Building

```
cargo build --release      # produces target/release/lim
cargo install --path .     # installs `lim` into ~/.cargo/bin
```
