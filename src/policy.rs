//! Comparing a requested policy against the sandbox already running.
//!
//! Joining is only safe while the sandbox you land in is the one you asked for. If it is
//! not, you get a shell whose mounts are not the ones you typed — with no sign of it —
//! which is precisely the silent-wrong-answer this whole feature has to avoid.
//!
//! **Compared against `docker inspect`, not against a fingerprint label.** A label would be
//! a second copy of the truth, able to go stale; the daemon cannot. The real payoff is that
//! a *human-readable diff falls out for free*, and printing it is not optional: a bare
//! "policy mismatch, refusing" is the kind of error people route around by always passing
//! `--name`, which quietly disables joining altogether.
//!
//! Forwards need no special handling — their sockets *are* mounts, so they appear here like
//! anything else. The environment is compared too: it is baked into the container by
//! `docker run`, so a second `lim` carrying different `[env]` or `-e` cannot apply it — and
//! silently dropping it is the same wrong-shell-without-a-sign this module exists to stop.
//!
//! Only the *working directory* is exempt, because `docker exec` takes its own `-w`. That is
//! what lets a join from a subdirectory land where you actually are. `TERM`/`COLORTERM` are
//! exempt by construction rather than by rule: they describe a shell's terminal, not the
//! sandbox, so they are never in the spec (see `run::term_env`).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use crate::mounts::MountArg;
use crate::run::RunSpec;

/// The slice of `docker inspect` this comparison needs.
#[derive(Deserialize)]
pub struct Inspect {
    #[serde(rename = "Mounts")]
    mounts: Vec<InspectMount>,
    #[serde(rename = "Config")]
    config: InspectConfig,
    #[serde(rename = "HostConfig")]
    host_config: InspectHostConfig,
}

#[derive(Deserialize)]
struct InspectMount {
    #[serde(rename = "Source")]
    source: String,
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "RW")]
    rw: bool,
}

#[derive(Deserialize)]
struct InspectConfig {
    #[serde(rename = "Hostname")]
    hostname: String,
    /// Everything `-e` set *plus* the image's own `ENV` — see `requested_env` for why the
    /// requested side has to account for the latter before the two can be compared.
    #[serde(rename = "Env", default)]
    env: Vec<String>,
}

#[derive(Deserialize)]
struct InspectHostConfig {
    /// Absent rather than empty when a container has no tmpfs at all.
    #[serde(rename = "Tmpfs")]
    tmpfs: Option<std::collections::HashMap<String, String>>,
    /// `"host"` for host networking, otherwise a bridge/network name. Compared so a
    /// bridge shell is never attached to a host-network sandbox or vice versa.
    #[serde(rename = "NetworkMode", default)]
    network_mode: String,
    /// Passed-through device nodes; compared so a no-GPU shell can't join a GPU sandbox.
    #[serde(rename = "Devices", default)]
    devices: Vec<InspectDevice>,
}

#[derive(Deserialize)]
struct InspectDevice {
    #[serde(rename = "PathOnHost")]
    path_on_host: String,
}

/// `docker inspect` always returns an array, even for one container.
pub fn parse(json: &str) -> Result<Inspect> {
    let mut v: Vec<Inspect> = serde_json::from_str(json).context("parsing `docker inspect`")?;
    if v.is_empty() {
        bail!("`docker inspect` returned no container");
    }
    Ok(v.remove(0))
}

/// One way the running sandbox and the requested one disagree.
#[derive(Debug, PartialEq, Eq)]
pub enum Diff {
    /// The running sandbox has a mount that was not asked for. Joining would hand out more
    /// than was requested.
    OnlyRunning(String),
    /// Asked for, but not in the running sandbox. Joining would silently drop it.
    OnlyRequested(String),
    Differs {
        what: String,
        running: String,
        requested: String,
    },
}

/// Compare, exactly. Any difference at all is a difference — one rule, statable in a
/// sentence, rather than a per-field judgement about which mismatches are tolerable.
pub fn diff(spec: &RunSpec, running: &Inspect) -> Vec<Diff> {
    let mut out = Vec::new();

    if spec.hostname != running.config.hostname {
        out.push(Diff::Differs {
            what: "hostname".into(),
            running: running.config.hostname.clone(),
            requested: spec.hostname.clone(),
        });
    }

    let want_net = if spec.host_network { "host" } else { "bridge" };
    // Docker reports the bridge case as "default", "bridge" or a network name; only "host"
    // is the one that matters to distinguish, so compare against that rather than guessing
    // the exact bridge spelling.
    let running_host_net = running.host_config.network_mode == "host";
    if spec.host_network != running_host_net {
        out.push(Diff::Differs {
            what: "network".into(),
            running: running.host_config.network_mode.clone(),
            requested: want_net.into(),
        });
    }

    // The environment, rendered as the flags you would type — same treatment as mounts, and
    // in both directions: a variable only the running sandbox has is a shell configured by
    // someone else's config, and one only requested would be silently dropped on the way in.
    let want: BTreeSet<String> =
        requested_env(spec).into_iter().map(|e| format!("-e {e}")).collect();
    let have: BTreeSet<String> = running.config.env.iter().map(|e| format!("-e {e}")).collect();
    out.extend(have.difference(&want).cloned().map(Diff::OnlyRunning));
    out.extend(want.difference(&have).cloned().map(Diff::OnlyRequested));

    // Devices are set-compared like mounts: a GPU passed to one and not the other is exactly
    // the kind of silent difference a join must refuse.
    let want_dev: BTreeSet<String> = spec.devices.iter().map(|d| format!("--device {d}")).collect();
    let have_dev: BTreeSet<String> = running
        .host_config
        .devices
        .iter()
        .map(|d| format!("--device {}", d.path_on_host))
        .collect();
    out.extend(have_dev.difference(&want_dev).cloned().map(Diff::OnlyRunning));
    out.extend(want_dev.difference(&have_dev).cloned().map(Diff::OnlyRequested));

    // Rendered as the flags you would type, so the diff is directly actionable rather than
    // a structural dump the reader has to translate.
    let want: BTreeSet<String> = spec.mounts.iter().map(render_spec_mount).collect();
    let have: BTreeSet<String> = running
        .mounts
        .iter()
        .map(|m| bind_str(&m.source, &m.destination, !m.rw))
        .chain(running.host_config.tmpfs.iter().flatten().map(|(path, opts)| tmpfs_str(path, opts)))
        .collect();

    out.extend(have.difference(&want).cloned().map(Diff::OnlyRunning));
    out.extend(want.difference(&have).cloned().map(Diff::OnlyRequested));
    out
}

/// The environment the running container *would* have, given this spec.
///
/// `docker inspect` reports the image's own `ENV` in `Config.Env` alongside everything `-e`
/// added, so the spec alone is never the whole picture — comparing it directly would report
/// the image's `PATH` as a variable only the running sandbox has, on every single join.
/// `context::IMAGE_ENV` is that baseline, and it is *underneath* the spec: a `-e PATH=…`
/// replaces the image's entry rather than adding a second one, which is what Docker does.
fn requested_env(spec: &RunSpec) -> Vec<String> {
    let mut merged: BTreeMap<&str, &str> = BTreeMap::new();
    for e in crate::context::IMAGE_ENV.iter().copied().chain(spec.env.iter().map(String::as_str)) {
        let (name, value) = e.split_once('=').unwrap_or((e, ""));
        merged.insert(name, value);
    }
    merged.into_iter().map(|(n, v)| format!("{n}={v}")).collect()
}

fn render_spec_mount(m: &MountArg) -> String {
    match m {
        MountArg::Bind(b) => bind_str(&b.src, &b.dst, b.ro),
        MountArg::Tmpfs(t) => tmpfs_str(&t.path, &t.opts),
    }
}

fn bind_str(src: &str, dst: &str, ro: bool) -> String {
    if ro { format!("-v {src}:{dst}:ro") } else { format!("-v {src}:{dst}") }
}

fn tmpfs_str(path: &str, opts: &str) -> String {
    format!("--tmpfs {path}:{opts}")
}

/// The refusal, with both sides shown and a next action named.
pub fn describe(name: &str, diffs: &[Diff]) -> String {
    let mut s = format!(
        "refusing to join `{name}`: it is running with a different policy than you asked for\n"
    );
    for d in diffs {
        s.push('\n');
        match d {
            Diff::OnlyRunning(what) => {
                s.push_str(&format!("  running sandbox has:  {what}\n"));
                s.push_str("  you asked for:        (nothing)\n");
            }
            Diff::OnlyRequested(what) => {
                s.push_str("  running sandbox has:  (nothing)\n");
                s.push_str(&format!("  you asked for:        {what}\n"));
            }
            Diff::Differs { what, running, requested } => {
                s.push_str(&format!("  running sandbox {what}:  {running}\n"));
                s.push_str(&format!("  you asked for:  {}{requested}\n", " ".repeat(what.len())));
            }
        }
    }
    s.push_str(
        "\njoin it with the flags it was created with, or use `--name <other>` for a \
         separate sandbox",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mounts::{Bind, Tmpfs};
    use std::path::PathBuf;

    /// A fixture in the shape `docker inspect` actually returns — array-wrapped, `RW`
    /// rather than `Mode`, tmpfs as a map, and `Config.Env` carrying the image's own `ENV`
    /// as well as what `-e` set. Verified against Docker 29.6.2.
    fn fixture() -> Inspect {
        parse(&format!(
            r#"[{{
              "Mounts": [
                {{"Type":"bind","Source":"/usr","Destination":"/usr","Mode":"ro","RW":false}},
                {{"Type":"bind","Source":"/w","Destination":"/w","Mode":"","RW":true}}
              ],
              "Config": {{"Hostname": "krzaq", "Env": ["{image}", "HOME=/home/u"]}},
              "HostConfig": {{"Tmpfs": {{"/tmp": "exec"}}}}
            }}]"#,
            image = crate::context::IMAGE_ENV[0]
        ))
        .expect("fixture parses")
    }

    fn spec(mounts: Vec<MountArg>, hostname: &str) -> RunSpec {
        RunSpec {
            name: "limes-w".into(),
            hostname: hostname.into(),
            workspace: PathBuf::from("/w"),
            mounts,
            env: vec!["HOME=/home/u".into()],
            labels: vec![],
            symlinks: vec![],
            host_network: false,
            devices: vec![],
            docker_proxy: false,
            cmd: vec!["zsh".into()],
        }
    }

    fn matching() -> Vec<MountArg> {
        vec![
            MountArg::Bind(Bind::new("/usr", "/usr", true)),
            MountArg::Bind(Bind::new("/w", "/w", false)),
            MountArg::Tmpfs(Tmpfs { path: "/tmp".into(), opts: "exec".into() }),
        ]
    }

    #[test]
    fn an_identical_policy_produces_no_diff() {
        assert_eq!(diff(&spec(matching(), "krzaq"), &fixture()), vec![]);
    }

    /// The working directory is per-shell — `docker exec` carries its own `-w` — so it must
    /// never block a join. That is what lets a join from a subdirectory land where you are.
    #[test]
    fn cwd_is_exempt() {
        let mut s = spec(matching(), "krzaq");
        s.workspace = PathBuf::from("/w/deep/subdir");
        assert_eq!(diff(&s, &fixture()), vec![]);
    }

    /// The environment is *not* exempt. `docker run` bakes it into the container, so a second
    /// `lim` whose `[env]` or `-e` differs cannot apply it — and applying it silently only
    /// halfway is worse than refusing. Both directions are reported.
    #[test]
    fn a_differing_env_is_reported() {
        let mut s = spec(matching(), "krzaq");
        s.env = vec!["HOME=/home/u".into(), "RUST_LOG=debug".into()];
        assert_eq!(diff(&s, &fixture()), vec![Diff::OnlyRequested("-e RUST_LOG=debug".into())]);

        let mut s = spec(matching(), "krzaq");
        s.env = vec![];
        assert_eq!(diff(&s, &fixture()), vec![Diff::OnlyRunning("-e HOME=/home/u".into())]);
    }

    /// The image sets its own `PATH`, and `docker inspect` reports it in the same list as
    /// everything `-e` added. Without `IMAGE_ENV` on the requested side that variable is one
    /// only the running sandbox has — so *every* join would refuse, on the first try, over a
    /// difference nobody created.
    #[test]
    fn the_images_own_env_is_not_a_difference() {
        assert_eq!(diff(&spec(matching(), "krzaq"), &fixture()), vec![]);
    }

    /// …but it is a baseline, not a floor: a spec that sets `PATH` replaces the image's entry
    /// rather than colliding with it, which is what Docker itself does.
    #[test]
    fn a_spec_env_overrides_the_image_baseline() {
        let mut s = spec(matching(), "krzaq");
        s.env.push("PATH=/only/mine".into());
        assert_eq!(
            diff(&s, &fixture()),
            vec![
                Diff::OnlyRunning(format!("-e {}", crate::context::IMAGE_ENV[0])),
                Diff::OnlyRequested("-e PATH=/only/mine".into()),
            ]
        );
    }

    /// Asking for *less* than the sandbox has still refuses: joining would hand out access
    /// that was not requested, and silence there is the failure worth avoiding.
    #[test]
    fn a_mount_only_the_running_sandbox_has_is_reported() {
        let mut m = matching();
        m.retain(|x| !matches!(x, MountArg::Bind(b) if b.src == "/usr"));
        assert_eq!(
            diff(&spec(m, "krzaq"), &fixture()),
            vec![Diff::OnlyRunning("-v /usr:/usr:ro".into())]
        );
    }

    #[test]
    fn a_mount_only_requested_is_reported() {
        let mut m = matching();
        m.push(MountArg::Bind(Bind::new("/extra", "/extra", false)));
        assert_eq!(
            diff(&spec(m, "krzaq"), &fixture()),
            vec![Diff::OnlyRequested("-v /extra:/extra".into())]
        );
    }

    /// A `hide` is a tmpfs, so it has to be compared as one — a diff engine that only
    /// looked at `Mounts` would let a sandbox without the hole masquerade as one with it.
    #[test]
    fn a_differing_hide_is_reported() {
        let mut m = matching();
        m.push(MountArg::Tmpfs(Tmpfs { path: "/w/.config/gh".into(), opts: "mode=0755".into() }));
        assert_eq!(
            diff(&spec(m, "krzaq"), &fixture()),
            vec![Diff::OnlyRequested("--tmpfs /w/.config/gh:mode=0755".into())]
        );
    }

    /// A no-GPU shell must not join a GPU sandbox: it would silently get device access it
    /// never asked for (or, the other way, miss the device it did).
    #[test]
    fn a_differing_device_is_reported() {
        let mut s = spec(matching(), "krzaq");
        s.devices = vec!["/dev/dri/renderD128".into()]; // fixture has no Devices
        assert_eq!(
            diff(&s, &fixture()),
            vec![Diff::OnlyRequested("--device /dev/dri/renderD128".into())]
        );
    }

    /// A bridge shell must not attach to a host-network sandbox: joining would put the
    /// shell on a different network than the mounts were reasoned about on.
    #[test]
    fn a_differing_network_is_reported() {
        let mut s = spec(matching(), "krzaq");
        s.host_network = true; // fixture's HostConfig has no NetworkMode -> bridge
        assert_eq!(
            diff(&s, &fixture()),
            vec![Diff::Differs {
                what: "network".into(),
                running: "".into(),
                requested: "host".into(),
            }]
        );
    }

    #[test]
    fn a_differing_hostname_is_reported() {
        let d = diff(&spec(matching(), "krzaq-limes"), &fixture());
        assert_eq!(
            d,
            vec![Diff::Differs {
                what: "hostname".into(),
                running: "krzaq".into(),
                requested: "krzaq-limes".into(),
            }]
        );
    }

    /// The message has to show both sides and name a next action, or people route around
    /// the refusal with `--name` and lose the feature entirely.
    #[test]
    fn the_refusal_shows_both_sides_and_a_way_out() {
        let msg = describe("limes-w", &[Diff::OnlyRequested("-v /extra:/extra".into())]);
        assert!(msg.contains("running sandbox has:  (nothing)"), "{msg}");
        assert!(msg.contains("you asked for:        -v /extra:/extra"), "{msg}");
        assert!(msg.contains("--name"), "must name a way out: {msg}");
    }
}
