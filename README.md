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
"/storage"             = "ro"
"~/code/misc/dotfiles" = "ro"          # so shell startup can reach repo-relative files
"~/scratch"            = { mode = "rw" }
```

The path is the key (so a path can't be listed twice), `~` and `$VAR` are expanded, and
`"ro"` is shorthand for `{ mode = "ro" }`. Every path must exist — a missing one is a hard
error, just like a bad `--ro`/`--rw`. Config mounts override the built-in defaults but lose
to CLI flags, so `--rw <path>` still wins for a single run, and `--no-config` ignores the
file entirely. See `config.toml.example`.

A common use is mounting your **dotfiles repo read-only**: limes mounts your individual
`.zshrc`/`.zprofile` (as resolved symlinks) but not the repo they live in, so anything
those files source by repo-relative path (zsh plugins, helpers) isn't present without it.

## Building

```
cargo build --release      # produces target/release/lim
cargo install --path .     # installs `lim` into ~/.cargo/bin
```
