# Sandbox identity: naming, hostname, and running `lim` twice

Design notes, in the style of `MACOS-BACKEND.md` — decisions and the reasoning behind them,
not a spec. Three linked changes, none implemented yet. They are ordered by dependency: the
naming change stands alone and the join semantics rest on it, so do them in that order.

Linux only. On macOS there is no container to name, share or tear down; `lim` there is
always a fresh `sandbox-exec`, and none of this applies.

## 1. Container name = the whole workspace path

`derive_name` in `run.rs` uses the workspace **basename**, so `~/a/test` and `~/b/test` both
become `limes-test`. Today that surfaces as a confusing Docker name-conflict error. Once
`lim` joins a running sandbox (§3), the same collision silently drops you into a sandbox for
a *different* tree — with that tree mounted read-write. That is the one failure mode in this
whole document with real damage potential, and it is Murphy, not Machiavelli.

Use the absolute path instead: non-alphanumerics to `-`, prefixed with `limes-`.

```
/home/krzaq/code/misc/limes  →  limes-home-krzaq-code-misc-limes
/home/krzaq/tmp/erste/test   →  limes-home-krzaq-tmp-erste-test
```

- Docker's rule is `[a-zA-Z0-9][a-zA-Z0-9_.-]*`; the `limes-` prefix satisfies the
  leading-character requirement for free.
- `current_dir()` is `getcwd(3)`, already kernel-resolved, so no symlink component survives
  into the name. Two paths that alias the same directory through bind mounts or a network
  filesystem are **deliberately out of scope** — a decision, not an oversight.
- Keep the existing `limes-root` fallback for `/`, rather than emitting a bare `limes-`.
- **If the name exceeds a cap, truncate the front and append a short hash of the full path.**
  The tail is the recognizable part, and the hash keeps the function total. Truncating the
  tail instead would collide exactly where paths are most similar — sibling directories.
- **Do not shorten `$HOME` away** to save 12 characters. It reintroduces ambiguity
  (`/code/x` vs `~/code/x`) in exchange for cosmetics. The name is an identifier, not UI: if
  the long form reads badly in `lim status`, that is the display's problem, and it already
  has the `limes.workspace` label to show `~/code/misc/limes` instead.

**The payoff is more than tidiness.** A name that is a total function of the path *is* the
lookup: `docker inspect limes-home-krzaq-tmp-erste-test` either hits or it does not, so §3
needs no `docker ps --filter label=…` scan. The `limes.workspace` label stops being the join
key and becomes a one-line assertion after the lookup — worth keeping precisely because it
catches the flattening collision (`/a/b-c` and `/a-b/c` both give `a-b-c`) and turns it into
an error rather than a silent join. It costs nothing, since §3 inspects the container anyway.

## 2. Hostname

Today the sandbox reports the container ID (`eec4158214b0`), because nothing passes
`--hostname`. It changes every run and reads as noise.

**Default to the host's own hostname, verbatim.** This was argued both ways. Distinctness
would keep per-host state (caches, history files, anything shipping a hostname to a remote)
from merging between host and sandbox — but "it should feel exactly like the host" is the
whole feature, and the merge is a small cost. Mirror wins; the LIM prompt badge and the
`$LIMES_VERSION` marker already answer "where am I".

Resolve it in `context.rs` alongside uid/gid/HOME — it is the same kind of once-per-run host
fact, and that module is where those live.

One knob for people who *do* want them distinguishable, in the usual two places:
`hostname_suffix` in config, `--hostname-suffix` on the CLI, CLI winning — the same shape as
the `[forward]` switches. A full `--hostname` override is deliberately **not** added: a
suffix covers the real want, and a second knob in the same dimension muddies precedence for
no gain. Add it when something actually needs it.

Two details that will otherwise bite:

- **Reject a suffix containing a dot, with an error saying why.** Zsh's `%m` truncates at the
  first dot, so `krzaq.limes` renders as plain `krzaq` — the feature appears to do nothing,
  and the next hour goes into the wrong place. (This is exactly how the white-`LIM` bug
  presented before `TERM` was forwarded.)
- **FQDN hosts.** `box.lan` plus a suffix gives `box.lan-limes` by naive append, versus
  `box-limes.lan` by inserting after the first label. Take the simple append and say so in
  the `config.toml.example` comment; the clever version is more surprising than it is pretty.
  Truncate the result to 63 characters either way.

Hostname is fixed at container creation, so it belongs in the policy comparison in §3.

`config.toml.example` and the README's Configuration section are updated together with any
config change — repo convention.

## 3. Running `lim` twice in the same workspace

Today: a raw Docker `name already in use` error. That is an accidental deny, and the worst of
both options.

**Decision: join the running sandbox.** The mirror principle settles it — two terminals on
the host are two shells on *one machine*, sharing `/tmp`, `$HOME` and the process table. Two
containers would give two separate tmpfs `$HOME`s, so a file written in one shell would be
missing in the other and `ps` would not show the other's build. That surprise has no good
explanation. `passthrough::exec` already performs the join manually, so the mechanism exists;
what is missing is lifetime and a policy check.

### 3a. Lifetime — the actual work

Today the first shell is PID 1 under `--rm`. If it exits, the container dies and takes every
joined shell with it.

Make **PID 1 a trivial supervisor** — the image's static busybox at `/limes`, `sleep
infinity` — and make *every* shell, the first included, a `docker exec -it`. Then all shells
are peers and no shell owns the others' fate.

Consequences to handle:

- **The symlink prelude moves to the supervisor.** It mutates the shared tmpfs `$HOME`, so it
  must run **once at container creation** (`sh -c '<prelude>; exec sleep infinity'`), not per
  shell. Running it per exec would be redundant at best and racy at worst.
- **`TERM`/`COLORTERM` become per-exec, not per-container.** They describe the terminal a
  given shell is attached to, and a second shell can be in a different one. Pass them on each
  `docker exec -e`, and keep them out of the §3c comparison for the same reason.
- **Exit status** must still be the shell's. `docker exec` returns it, and
  `passthrough::exec` already uses `exec()` process replacement to pass tty and status
  through cleanly — same trick.

### 3b. Teardown

Last shell out stops the container; `--rm` then reaps it.

**Do not keep a counter file** — it goes stale the first time something is `kill -9`ed, and a
stale count either leaks containers forever or kills a live one. Derive the answer from the
daemon instead, the same principle `doctor` follows.

**This is the one thing to measure before building.** Two candidate sources, neither verified:

- `docker inspect --format '{{.ExecIDs}}'` — needs checking whether finished execs are
  pruned from that list or accumulate for the container's lifetime. If they accumulate, the
  count is useless without per-exec `Running` state, which the CLI does not expose (the API's
  `/exec/{id}/json` does).
- `docker top <name>` — count what is actually running. Fragile in an interesting way: a
  background build the user deliberately left would keep the sandbox alive, which is arguably
  correct, while a stray daemon would keep it alive forever, which is not.

Measure both, then choose; document which and why, because the next reader will wonder.

Two smaller points: two `lim`s exiting simultaneously can both observe zero and both issue a
stop — tolerate the loser's "no such container" rather than reporting it. And `lim status`
should show the shell count per sandbox, since with joining that number is now the
interesting one.

### 3c. Policy mismatch — fail loudly, and show the diff

If the resolved policy differs from the running container's, **refuse**. Joining would hand
you a shell whose mounts are not the ones you typed, and silently.

**Compare against `docker inspect` directly; do not add a fingerprint label.** `Mounts`
carries the binds, `HostConfig.Tmpfs` the hide entries and the tmpfs `$HOME`/`/tmp`,
`Config.Hostname` the §2 value. Deriving from the daemon means nothing can go stale, and —
the real reason — the human-readable diff falls out for free. Forwards need no special
handling, since the sockets *are* mounts.

**Printing the difference is not optional.** A bare "policy mismatch, refusing" is the kind of
error people route around by always passing `--name`, which quietly disables the whole
feature. Show both sides — `running sandbox has: --rw /extra` / `you asked for: (nothing)` —
so the next action is obvious: re-run with the flag, or take a separate sandbox.

**Exempt env and cwd.** `docker exec` takes its own `-e` and `-w`, so they are per-shell and
need not match. That is what makes joining from a subdirectory land the new shell where you
actually are, rather than back at the workspace root.

Net behaviour:

| you run | result |
|---|---|
| `lim` in the same workspace, same config | joins the running sandbox |
| `lim --rw /extra` where a plain one runs | refuses, prints the diff, suggests the flag or `--name` |
| `lim` in `~/b/test` while `~/a/test` runs | separate sandbox — different name, per §1 |

### 3d. If you defer the join

Ship the deny properly: detect the running sandbox and say *"a sandbox for this workspace is
already running; `lim exec <name>` to join it, or `--name x` for a separate one."* Ten
minutes, removes the raw Docker error, and forecloses nothing.

## Tests

Matching where the existing ones live — the pure logic is unit-tested and the daemon call is
kept out of it, the way `seatbelt.rs` and `identity.rs` are testable off-platform:

- `derive_name`: path → name; the `/a/b-c` vs `/a-b/c` collision; the `/` fallback; and
  truncation-plus-hash being deterministic and length-bounded.
- hostname: dot in the suffix is rejected; FQDN append; 63-char truncation.
- policy diff: make it a pure function of `(resolved mounts, parsed inspect JSON) → Vec<Diff>`
  and test it against a fixture. This is the piece most likely to regress silently, since a
  wrong answer here still produces a working shell.
