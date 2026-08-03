# Adding a `pipx` toolchain recipe

Handoff note. Written 2026-07-25 from the wcs-core side, where the absence of this
feature is what prompted it. Nothing here is implemented yet — the design decision
below was made with the user, and the code is left to you.

## Why

`pipx` is how a lot of hosts install Python CLI tools, and it is currently invisible
inside a sandbox. Concretely: wcs-core's `make configure` shells out to `conan`, the
host has conan installed via pipx, and inside `lim` it is simply not there —
`make configure` dies with `conan: No such file or directory`.

The workaround is to reinstall conan inside the sandbox every time, because parts of
`~/.local` are per-instance tmpfs and do not survive. That is a real cost: it happened
during a wcs-core session, cost a detour mid-task, and will recur on every fresh
instance for every pipx-installed tool.

`[toolchains]` is the right home for this. It already exists to solve exactly this
shape of problem for rbenv, rust, uv, npm and nvm, and `pipx` belongs in that list.

## The obstacle

pipx has two halves, and only one of them is statically nameable.

```
~/.local/share/pipx/venvs/<app>/     one venv per installed app
~/.local/share/pipx/shared/          the pip/setuptools venv pipx installs *with*
~/.local/bin/<app>                   symlink into the venv above — this is what PATH sees
~/.cache/pipx/                       download cache
```

`<app>` is whatever the user happened to install. A `Recipe`'s `install`/`cache` lists
are `&'static [&'static str]`, so they cannot name the launchers — and a recipe that
mounts only the venv tree mirrors several gigabytes that nothing on `PATH` can invoke.
On this host that tree is ~5 G and the only reason to mount it is to run `conan`.

So the launchers have to be discovered on the host at resolve time. That is the whole
of the problem; everything else is an ordinary recipe.

## The decision

**Recreate the launchers as symlinks**, via the existing `SymlinkSpec` mechanism.

The tree already has both possible treatments, in `src/agents.rs`:

- `claude` bind-mounts `.local/bin/claude` and lets the mount flatten the symlink into
  its target. Fine there because the target is one self-contained binary.
- `cursor-agent` is relinked instead, because flattening put the launcher somewhere its
  `SCRIPT_DIR=$(dirname $(realpath $0))` lookup could not find its `node`.

pipx launchers would survive flattening — they carry an absolute shebang into the venv
(`#!/home/krzaq/.local/share/pipx/venvs/conan/bin/python`), which still resolves once
the venv tree is mounted at the identical path. So this was a genuine choice, not a
forced one. Relinking won on cost: mounting each launcher means a bind mount per
installed app, scaling with how many things the user has pipx-installed, and buys
nothing over N symlinks into a tree that is mounted anyway.

## Implementation sketch

All in `src/config.rs` unless noted.

**1. Mark the recipe as having discovered launchers.** `Recipe` (~line 133) gains a
field; an enum rather than a `bool` because the discovery rule is pipx-specific layout
knowledge, not a generic capability:

```rust
enum Launchers { None, Pipx }
```

The five existing recipes take `Launchers::None`. There is no struct-update shorthand
available in a `const` initializer, so this touches all of them.

**2. The recipe itself**, alongside the others in `RECIPES` (~line 151):

```rust
Recipe {
    name: "pipx",
    primary: "~/.local/share/pipx",
    install: &["~/.local/share/pipx"],
    cache: &["~/.cache/pipx"],
    launchers: Launchers::Pipx,
},
```

`shared/` sits under the `install` path deliberately — it is the venv pipx installs
*with*, so a `pipx install` from inside a `rw` mount needs it present.

**3. Discovery. Enumerate the host's `~/.local/bin`, not each venv's `bin/`.** This is
the one part with a trap in it. A pipx venv contains the console scripts of the app's
*dependencies* too — conan's venv carries `distro` and `normalizer` — and pipx exposes
only the app's own. Reading the host's existing links instead mirrors exactly what the
host put on `PATH`, with no guessing:

```rust
fn pipx_launchers(bin_dir: &Path, venvs: &Path) -> Vec<SymlinkSpec>
```

Keep every `~/.local/bin` entry that is a symlink and whose canonicalized target is
under `~/.local/share/pipx/venvs`. Sort the result — `read_dir` order is arbitrary and
`--dry-run` output should be reproducible. A missing `~/.local/bin` is an empty result,
not an error; `primary` has already established that pipx itself is installed.

**4. Plumbing.** `resolve_toolchains` currently takes `&mut Vec<Mount>` and is called
at `config.rs:539`, inside `resolve_specs`, which already owns a `symlinks` vec
(declared line 484) and returns `Resolved { mounts, symlinks }` on the next line. Give
it `&mut Vec<SymlinkSpec>` as well and push there. The seam is clean — no new field on
`Resolved`, and `run.rs`'s `symlink_prelude` (line 810) already applies whatever lands
in it.

Note it will be the first recipe to produce a symlink, so the doc comment above
`RECIPES` — "Adding a toolchain is an entry here plus a mention in the docs" — is no
longer quite true and should say so.

**5. Docs.** The known-name list appears in four places and they should not drift:
`config.rs:68` (the `toolchains` field comment), `limes.local.toml.template:23`,
`config.toml.example:83`, and `README.md:254`.

**6. Tests.** `config.rs` has a `#[cfg(test)] mod tests` with parse/precedence coverage
(e.g. `parse_str("[toolchains]\nrbenv = \"ro\"\n")` at line 719). At minimum: `pipx`
parses and resolves. The discovery function is worth a test against a `tempfile` tree
with a decoy — a `~/.local/bin` symlink pointing *outside* the venvs dir, which must be
left alone — since that is the behaviour the "enumerate the host's bin" decision exists
to get right.

Per `CLAUDE.md`: `make fmt` (the tree is rustfmt-clean with
`use_small_heuristics = "Max"`), `make test`, `make clippy`.

## Scope note: this does not cover conan's cache

pipx delivers the *tool*. Conan's package cache is `~/.conan2` — 4.9 G of prebuilt
packages on this host, unrelated to pipx and owned by conan — and it must be **`rw`**:
conan writes locks and metadata even when it downloads nothing, so a read-only cache
fails outright rather than degrading. It also holds the profiles `conan profile detect`
writes, so mounting it is what stops every fresh sandbox needing a re-detect.

That stays a project-level `[mounts]` entry. wcs-core's `.limes.local.toml` currently
carries three mounts as a stopgap; once this lands, two of them collapse into
`[toolchains] pipx = "ro"` and only `~/.conan2 = "rw"` remains.

Whether conan deserves its own recipe (`primary: "~/.conan2"`) is a separate question,
and worth asking only if a second project wants the same thing — one consumer is not
yet a pattern.

## Verifying it end to end

The honest test is the case that prompted this, from a wcs-core checkout with
`[toolchains] pipx = "ro"` and `~/.conan2 = "rw"` approved via `lim trust add`:

```
lim -- bash -lc 'which conan && conan --version'
lim -- bash -lc 'cd /home/krzaq/code/kqsolutions/wcs-core && make configure'
```

`which conan` proves the launcher landed on `PATH`; `conan --version` proves the
shebang resolved into the mounted venv, which a flattened-symlink approach would also
have to satisfy; `make configure` proves the shared `~/.conan2` cache is usable, which
is the part that makes this worth doing rather than just correct — it should resolve
`fmt/[~11]` from cache instead of building it.
