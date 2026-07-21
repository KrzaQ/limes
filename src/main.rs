//! limes / `lim` — a host-mirroring sandbox.
//!
//! Runs `zsh` (or any command) inside a container that mirrors the host userland
//! read-only, carves explicit read-write holes, and talks only to a dedicated
//! rootless Docker daemon. See `README.md` for the design and threat model.

mod agents;
mod config;
mod context;
mod doctor;
mod mounts;
mod run;
mod util;

// The container backend. On macOS there is no daemon, no image and no container object,
// so these have nothing to manage — see `MACOS-BACKEND.md`.
#[cfg(target_os = "linux")]
mod bootstrap;
#[cfg(target_os = "linux")]
mod docker;
#[cfg(target_os = "linux")]
mod passthrough;
#[cfg(target_os = "linux")]
mod status;

// The Seatbelt backend. Compiled everywhere on purpose: profile generation is pure string
// work, so keeping it off the cfg gate means its tests run in the Linux dev loop too.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod seatbelt;

// Forward resolution is shared; only the docker `-v` emission is Linux-shaped.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod forward;

use std::path::PathBuf;

use anyhow::Result;
#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use clap::{Args, Parser, Subcommand};

use context::Context;

#[derive(Parser)]
#[command(name = "lim", version, about = "A host-mirroring sandbox for agents and dev commands")]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    /// Default action (bare `lim`) is `run` — these flags apply to it.
    #[command(flatten)]
    run: RunArgs,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run zsh (or CMD) in a fresh sandbox [default]
    Run(RunArgs),
    /// One-time host setup: rootless daemon + image
    Bootstrap(BootstrapArgs),
    /// Report installation health
    Doctor,
    /// List running limes sandboxes
    #[command(alias = "ps")]
    Status,
    /// Pass a command through to the limes daemon: `lim docker ps`
    Docker {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Pass a command through to `docker compose` on the limes daemon
    Compose {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Open a second shell into a running sandbox
    Exec {
        /// Container name or id (see `lim status`)
        instance: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Stop running sandboxes
    Stop {
        /// Stop all running limes sandboxes
        #[arg(long)]
        all: bool,
        /// Container names or ids to stop
        instances: Vec<String>,
    },
    /// Reclaim space on the limes daemon (safe: dedicated data-root)
    Prune {
        /// Do not prompt for confirmation
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Build (or rebuild) the limes image
    Build {
        /// Build without the layer cache
        #[arg(long)]
        no_cache: bool,
    },
}

impl Commands {
    /// Subcommand name, for the Linux-only diagnostic on other platforms.
    #[cfg(not(target_os = "linux"))]
    fn name(&self) -> &'static str {
        match self {
            Commands::Run(_) => "run",
            Commands::Bootstrap(_) => "bootstrap",
            Commands::Doctor => "doctor",
            Commands::Status => "status",
            Commands::Docker { .. } => "docker",
            Commands::Compose { .. } => "compose",
            Commands::Exec { .. } => "exec",
            Commands::Stop { .. } => "stop",
            Commands::Prune { .. } => "prune",
            Commands::Build { .. } => "build",
        }
    }
}

#[derive(Args, Clone)]
pub struct RunArgs {
    /// Mount PATH read-only (same path inside), repeatable
    #[arg(long = "ro", value_name = "PATH")]
    pub ro: Vec<PathBuf>,
    /// Mount PATH read-write (same path inside), repeatable
    #[arg(long = "rw", value_name = "PATH")]
    pub rw: Vec<PathBuf>,
    /// Print the assembled `docker run` and exit without running it
    #[arg(long)]
    pub dry_run: bool,
    /// Pass an environment variable through (NAME=VALUE or NAME), repeatable
    #[arg(short = 'e', long = "env", value_name = "ENV")]
    pub env: Vec<String>,
    /// Name for the sandbox container (default: derived from workspace)
    #[arg(long)]
    pub name: Option<String>,
    /// Do not auto-detect and mount any host agents
    #[arg(long)]
    pub no_agents: bool,
    /// Do not auto-detect and mount host claude
    #[arg(long)]
    pub no_claude: bool,
    /// Do not auto-detect and mount host opencode
    #[arg(long)]
    pub no_opencode: bool,
    /// Ignore ~/.config/limes/config.toml for this run
    #[arg(long)]
    pub no_config: bool,

    // Credential/socket forwards. Each is on by default and settable standing in config
    // `[forward]`; the paired flags let one run override config either way, so a standing
    // `gpg = false` is still escapable with `--gpg`.
    /// Forward the SSH agent socket (default)
    #[arg(long = "ssh", overrides_with = "no_ssh")]
    pub ssh: bool,
    /// Do not forward the SSH agent socket
    #[arg(long = "no-ssh", overrides_with = "ssh")]
    pub no_ssh: bool,
    /// Forward the GPG extra (restricted) agent socket (default)
    #[arg(long = "gpg", overrides_with = "no_gpg")]
    pub gpg: bool,
    /// Do not forward the GPG agent socket
    #[arg(long = "no-gpg", overrides_with = "gpg")]
    pub no_gpg: bool,
    /// Forward the rosa secret-broker socket and client (default)
    #[arg(long = "rosa", overrides_with = "no_rosa")]
    pub rosa: bool,
    /// Do not forward the rosa secret broker
    #[arg(long = "no-rosa", overrides_with = "rosa")]
    pub no_rosa: bool,
    /// Forward the limes docker socket (default)
    #[arg(long = "docker", overrides_with = "no_docker")]
    pub docker: bool,
    /// Do not forward the limes docker socket
    #[arg(long = "no-docker", overrides_with = "docker")]
    pub no_docker: bool,
    /// Command to run in the sandbox (default: an interactive login zsh)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub cmd: Vec<String>,
}

#[derive(Args)]
pub struct BootstrapArgs {
    /// Show what would be done without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = Context::detect()?;

    match cli.command {
        None => run::run(&ctx, &cli.run),
        Some(Commands::Run(args)) => run::run(&ctx, &args),
        Some(Commands::Doctor) => doctor::doctor(&ctx),

        #[cfg(target_os = "linux")]
        Some(Commands::Bootstrap(args)) => bootstrap::bootstrap(&ctx, &args),
        #[cfg(target_os = "linux")]
        Some(Commands::Status) => status::status(&ctx),
        #[cfg(target_os = "linux")]
        Some(Commands::Docker { args }) => passthrough::docker(&ctx, &args),
        #[cfg(target_os = "linux")]
        Some(Commands::Compose { args }) => passthrough::compose(&ctx, &args),
        #[cfg(target_os = "linux")]
        Some(Commands::Exec { instance, cmd }) => passthrough::exec(&ctx, &instance, &cmd),
        #[cfg(target_os = "linux")]
        Some(Commands::Stop { all, instances }) => passthrough::stop(&ctx, all, &instances),
        #[cfg(target_os = "linux")]
        Some(Commands::Prune { force }) => passthrough::prune(&ctx, force),
        #[cfg(target_os = "linux")]
        Some(Commands::Build { no_cache }) => bootstrap::build(&ctx, no_cache),

        // The CLI surface stays identical across platforms so `--help` and the docs don't
        // fork, but these subcommands manage Docker objects and a rootless daemon, neither
        // of which exists under Seatbelt. Failing loudly is the point: the design notes
        // specifically warn against letting `lim status` silently return nothing here.
        #[cfg(not(target_os = "linux"))]
        Some(other) => bail!(
            "`lim {}` is Linux-only — the macOS backend is Seatbelt, not containers, so there \
             is no daemon, image or container object to manage.\n  \
             `lim` and `lim run` work; `lim doctor` reports what this platform does and \
             doesn't enforce.",
            other.name()
        ),
    }
}
