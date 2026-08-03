# Two more mount modes: `overlay` and `hide`

Design notes in the style of `MACOS-BACKEND.md`: what was measured, what the shape should
be, and the traps found the hard way. Everything marked *measured* was run on this host
(Arch, kernel 7.0.12-arch1-1, Docker 29.6.2 against limes' own rootless daemon) on
2026-07-21/22.

**Status: `hide` is built, `overlay` is not.** They were split deliberately. `hide` closes a
standing violation of the credentials-as-oracles invariant and had exactly one runtime
unknown, since resolved. `overlay` is ergonomics, and rests on a case flagged below as
untested — a bind nested *inside* an overlay volume — whose failure mode is silent
(opencode stops persisting state and nothing says so). Probe that before writing it.

## Why

`$HOME` is a tmpfs, so nothing under it exists inside the sandbox unless something mounts
it. As of today the dotfiles drop-in mounts the whole of `~/.config` read-only, which is
measurably better than nothing — all 35 entries visible, `mc` reads its `ini` instead of
dying on "Cannot create /home/krzaq/.config/mc directory" — but it is a compromise that is
simultaneously too strict and too loose:

- **Too strict.** `mc`, `htop`, `lazygit` and friends rewrite their config on exit. Under
  `ro` they fail. Measured: `touch ~/.config/probe` → `Read-only file system`.
- **Too loose.** The same mount hands the sandbox `~/.config/gh/hosts.yml` (a GitHub OAuth
  token), `~/.config/secrets/`, and `~/.config/filezilla/recentservers.xml`. That collides
  with the standing invariant that credentials reach the sandbox as *oracles* (agent
  sockets), never as key material. The user has accepted this knowingly for now; it is the
  reason `hide` is wanted, not a thing to shrug at.

`overlay` fixes the first, `hide` fixes the second, and the two compose: mount `~/.config`
as `overlay`, hide the three credential dirs inside it.

## Mode 1: `overlay`

**Semantics.** Reads see the host tree. Writes go to an ephemeral upper layer and are
discarded when the sandbox exits. The host tree is never modified.

Docker's built-in `local` volume driver can mount an overlayfs, so this needs no new
runtime, no fuse, and no privileged helper. **Measured working end to end**: 35 entries
visible inside, writes captured in the upperdir, host tree untouched afterwards.

```
docker volume create --driver local \
  --opt type=overlay --opt device=overlay \
  --opt o=lowerdir=/home/krzaq/.config,upperdir=/run/user/1000/limes/upper,workdir=/run/user/1000/limes/work \
  limes-overlay-config
docker run … -v limes-overlay-config:/home/krzaq/.config …
```

**Trap, cost me a while:** the three directories are comma-separated inside a *single*
`o=`. Using `:` (the more natural-looking separator, and what the mount(8) syntax suggests)
produces an ENOENT that reads as "your lowerdir doesn't exist" and sends you looking in
completely the wrong place.

**Use the anonymous form**, which `--rm` reaps automatically — measured. A named volume
survives the run and has to be cleaned up by hand, which is exactly the state that would
silently turn "ephemeral" into "persistent":

```
--mount type=volume,dst=<path>,volume-driver=local,\
volume-opt=type=overlay,volume-opt=device=overlay,\
"volume-opt=o=lowerdir=<lower>,upperdir=<upper>,workdir=<work>"
```

### What has to change

- **`config.rs`** — add `Overlay` to `Mode`. The `untagged` enum means the `"~/.config" =
  "overlay"` shorthand and the `{ mode = "overlay", optional = true }` long form both come
  for free.
- **`mounts.rs`** — *done, shipped with `hide`.* `Mount { path, kind }` with
  `Kind = Ro | Rw | Hide`; add an `Overlay` variant. `dedupe` already copies the whole kind,
  and `to_args() -> Vec<String>` already returns the whole flag pair, so a `--mount` with
  several comma-joined options fits without further surgery. `to_args` will need a
  `&Context` for the scratch dirs — it takes none today, on purpose.
- **`context.rs`** — the scratch dirs are well-known paths, so they belong there, not
  inlined at the call site. Suggest `$XDG_RUNTIME_DIR/limes/<container-name>/<slug>/{upper,work}`.
- **`run.rs`** — **wipe the scratch dirs at start, not at exit.** A crashed or killed run
  must not leave an upper that a later run silently resurrects; container names are derived
  from the workspace basename, so collisions between runs are the normal case, not an edge
  one. Ephemeral-that-sometimes-isn't is worse than no overlay at all.

### Constraints to check before relying on it

- **upper and work must be on the same filesystem**, and that filesystem must be usable as
  an overlayfs upper (needs `trusted.*` xattrs). `$XDG_RUNTIME_DIR` is tmpfs here and it
  worked on this kernel — but tmpfs-as-upper is comparatively recent, so re-verify rather
  than assume, and fall back to `~/.local/share/limes/scratch` if a target kernel refuses.
- **Nesting a bind inside an overlay is the live case and is untested.** The dotfiles
  drop-in mounts `~/.config` while `agents.rs` mounts `~/.config/opencode` read-write
  *inside* it. With plain binds Docker layers them and it works (verified in the current
  `ro` setup). With a volume as the parent, verify — if it breaks, opencode's state stops
  persisting and nothing announces it.
- **macOS has no overlay.** Seatbelt is a write policy over the real filesystem; there is no
  union mount to reach for. Degrade `overlay` to `ro` there (a warning on stderr, not a hard
  error — a profile that still runs beats one that refuses). Whatever you choose,
  `MACOS-BACKEND.md`'s rule applies: an unenforced guarantee must never read as an enforced
  one, so `doctor`'s "Not enforced on this platform" list gains a line.

## Mode 2: `hide` — **built**

Landed together with the `Kind` refactor below. Everything this section proposed held up;
what follows is the record, with the decisions taken at implementation time marked.

**Semantics.** The path exists inside the sandbox but is empty; the host's contents are
unreachable. The point is a subtractive hole punched in a broad mount — `~/.config` ro,
minus the three credential dirs.

- **Linux:** `--tmpfs <path>` shadows whatever the parent bind put there. Simplest option,
  and unlike binding an empty directory it needs no host path to point at.
- **Measured, and it was the one real unknown:** a `--tmpfs` at a subpath *does* layer over
  a `-v` bind at a shallower path when both are passed to one `docker run`. Verified end to
  end with `~/.config` ro + `--hide ~/.config/gh`: 35 parent entries still visible, hidden
  dir 0 entries, `hosts.yml` gone, writes inside it absent from the host afterwards, and the
  nested `~/.config/opencode` rw bind unaffected.
- **Precedence falls out of the existing engine.** `hide` entries are `Mount`s keyed by
  path like everything else, so `sort_for_nesting` puts `~/.config` before
  `~/.config/gh` and the shadow lands on top. Don't special-case it.
- **Directories only** *(decided at implementation)*. `--tmpfs` cannot shadow a file, and
  the alternative — binding a generated empty file — needs a well-known path in `context.rs`,
  a file written each run, and a second branch in `to_args`. Hiding a file is a hard error
  naming its parent instead. Every motivating case (`gh`, `secrets`, `filezilla`) is a
  directory, and you would hide the directory anyway. Revisit only if a real case turns up.
- **The "path must exist on the host" invariant.** Hiding a path that isn't there is a
  harmless no-op, and a *synced* drop-in wants to name paths that exist on only some
  machines. `hide` is exempt from the hard error; `mounts::resolve_hide` carries that
  reasoning in its doc comment, and `canonicalize`'s comment points at it, so neither reads
  as an oversight.
- **`link = "parent"` combined with `hide` is rejected** *(decided at implementation)* — it
  would hide the symlink *target's* parent directory, i.e. a path the user never named.
- **macOS:** `(deny file-read* file-write* (subpath …))`. Two notes before touching
  `seatbelt.rs`'s `rule()`: the "never emit narrower than `file-write*`" warning there is
  about *write* operations — a read deny is a different operation class and is fine — and
  under `(allow default)` this would be the profile's first read restriction, so `doctor`'s
  flat "reads are unrestricted" line needs qualifying. It now reads *"reads are unrestricted
  except paths declared `hide`"*.
- **The two backends diverge in kind, not just in strength.** Linux gives an empty
  *writable* tmpfs, so an app that recreates its config on a missing dir just works;
  Seatbelt gives EPERM, so the same app errors. Recorded in `rule()`'s doc comment.

### The `Kind` refactor, done ahead of `overlay`

`Mount { host, read_only: bool }` became `Mount { path, kind: Kind }` with
`Kind = Ro | Rw | Hide`, and `to_arg() -> String` became `to_args() -> Vec<String>` (the
whole flag pair, because `Hide` is a `--tmpfs`, not a `-v`). `Kind` is payload-free on
purpose so `Mount` stays `PartialEq`, which `dedupe` and the precedence tests rest on.

`host` → `path` because the field names a path *inside* the sandbox: `Hide` has no host
side. This does not weaken the same-path invariant — every mode still governs
`/path` → `/path`.

Note this leaves **two** translation sites, `Mount::to_args` and `seatbelt::rule`, and that
is correct: the backends genuinely differ. What must not fork is the table *semantics*
(`Kind`, `dedupe`, `sort_for_nesting`), which stay in `mounts.rs`. `agents.rs` and
`forward.rs` needed no changes at all — they only ever touch the `Mount::ro`/`rw`
constructors, which is the shape to preserve when `Overlay` is added.

When `overlay` lands it will need the scratch dirs from `Context`, so `to_args` will have to
take a `&Context`. It deliberately does not yet — an unused parameter added in advance is a
parameter nobody can tell is unused.

## Bonus, measured: `link = "parent"` breaks under a read-only parent

With `~/.config` mounted `ro`, adding

```toml
"~/.config/git/config" = { mode = "ro", link = "parent" }
```

prints this on **every** run, because the symlink prelude tries to `ln` into a read-only
mount:

```
ln: failed to create symbolic link '/home/krzaq/.config/git/config': Read-only file system
```

The recreation is redundant here: the symlink already arrived with the parent's mount, and
only its *target's* parent dir was actually missing. Either skip the `ln` when the link path
already sits inside a mounted region, or add a `link = "target"` that mounts the target's
parent and emits no `SymlinkSpec`. Worth re-checking after `overlay` lands — under an
overlay the `ln` succeeds and the whole problem may evaporate, which would make this a
non-feature.

## Don't forget

`config.toml.example` and the README's Configuration section are updated *together* with any
config change (repo convention). Both new modes want their shorthand form shown.

Tests worth having, matching where the existing ones live: `config.rs` parses both shorthand
and long form; `mounts.rs` dedupe is last-wins across *differing* kinds; `seatbelt.rs` emits
the hide deny after its parent's rule; and a unit test on the `--mount` string builder,
because that argument is fiddly enough that eyeballing `--dry-run` will not catch a wrong
separator (see the trap above).

## Verification recipe

`lim` allocates a tty, so wrap non-interactive runs in `script`:

```sh
cd ~/some/workspace
script -qec "lim sh -c '
  ls \$HOME/.config | wc -l;                       # host entries visible
  touch \$HOME/.config/probe && echo WRITE-OK;     # overlay: OK, ro: denied
  ls \$HOME/.config/gh;                            # hide: empty
  touch \$HOME/.config/opencode/probe && echo NESTED-RW-OK'" /dev/null
ls ~/.config/probe        # must NOT exist on the host
ls ~/.config/opencode/probe   # must exist — the nested bind still persists
```
