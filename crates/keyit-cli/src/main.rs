//! Keyit CLI entry point.
//!
//! The Keyit protocol is still under active design. This binary
//! implements local project initialization (`keyit init`), local
//! environment genesis (`keyit env add`), encrypted push/pull, local
//! status/diff, and the first signed invite/join/approval workflow.
//!
//! Run `keyit --help`, `keyit --version`, or `keyit init --help`.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use keyit_cli::access::{
    run_approve, run_invite_create, run_join, run_revoke, ApproveOptions, InviteCreateOptions,
    JoinOptions, JoinTarget, RevokeOptions,
};
use keyit_cli::environment::{run_env_add, EnvAddOptions};
use keyit_cli::init::{run_init, InitOptions};
use keyit_cli::inspect::{
    run_env_list, run_revision_list, run_whoami, EnvListOptions, RevisionListOptions, WhoamiOptions,
};
use keyit_cli::local_state::{
    run_diff, run_status, DiffOptions, DiffState, KeyDiffStatus, LocalFileState, StatusOptions,
};
use keyit_cli::relay_client::RelayHttpClient;
use keyit_cli::revision::{run_pull, run_push, PullOptions, PushOptions};
use keyit_protocol::ids::{DeviceId, InviteId};
use keyit_protocol::primitives::Timestamp;
use keyit_protocol::records::Role;

/// Keyit: portable private state for software projects.
#[derive(Parser, Debug)]
#[command(name = "keyit", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize a new Keyit project in the current directory.
    ///
    /// Creates `keyit.toml` in the repository and writes signed project
    /// state to the local Keyit data directory. Does not create
    /// environments, read `.env`, publish secrets, or contact a relay.
    Init {
        /// Human-readable project label. Defaults to the current
        /// directory's name.
        #[arg(long = "project-label")]
        project_label: Option<String>,
        /// Default relay URL recorded in the project genesis. Defaults
        /// to `https://relay.keyit.sh`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
        /// Overwrite existing Keyit locator/state if this directory was
        /// already initialized.
        #[arg(long)]
        force: bool,
    },
    /// Manage Keyit environments.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Show this device's local Keyit identity and project membership.
    Whoami,
    /// Show local Keyit environment state.
    Status {
        /// Optional environment label or `kve_...` ID.
        environment: Option<String>,
    },
    /// Show local key-level dotenv differences without values.
    Diff {
        /// Optional environment label or `kve_...` ID.
        environment: Option<String>,
    },
    /// Create a local encrypted revision from a mapped dotenv file.
    Push {
        /// Environment label or `kve_...` ID.
        environment: String,
        /// Optional non-secret summary. Must not contain secret values.
        #[arg(long = "summary")]
        summary: Option<String>,
        /// Filesystem-backed relay directory to publish to.
        #[arg(long = "relay-dir")]
        relay_dir: Option<std::path::PathBuf>,
        /// HTTP relay URL override, e.g. `http://127.0.0.1:7878`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
    },
    /// Materialize the latest local encrypted revision into the mapped dotenv file.
    Pull {
        /// Environment label or `kve_...` ID.
        environment: String,
        /// Filesystem-backed relay directory to fetch from before materializing.
        #[arg(long = "relay-dir")]
        relay_dir: Option<std::path::PathBuf>,
        /// HTTP relay URL override, e.g. `http://127.0.0.1:7878`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
        /// Replace the local dotenv file even when it has local changes.
        #[arg(long)]
        force: bool,
    },
    /// Create and inspect project invites.
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
    /// Request access to a Keyit project through an invite.
    Join {
        /// Invite ID (`kvi_...`) or invite bundle path to join through.
        invite_id: String,
        /// Environment label or `kve_...` ID to request. Repeatable.
        #[arg(long = "env")]
        environments: Vec<String>,
        /// Human-readable local device label recorded on the request.
        #[arg(long = "device-label")]
        device_label: Option<String>,
        /// HTTP relay URL override, e.g. `https://relay.example.com`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
    },
    /// Approve a device's pending join request.
    Approve {
        /// Joining device ID (`kvd_...`) to approve.
        device_id: String,
        /// Role to grant: owner, admin, or member.
        #[arg(long, default_value = "member")]
        role: String,
        /// HTTP relay URL override, e.g. `https://relay.example.com`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
    },
    /// Revoke a device's future access.
    Revoke {
        /// Device ID (`kvd_...`) to revoke.
        device_id: String,
        /// Environment label or `kve_...` ID affected by rotation. Repeatable.
        #[arg(long = "env")]
        environments: Vec<String>,
        /// Optional non-secret reason.
        #[arg(long)]
        reason: Option<String>,
        /// HTTP relay URL override, e.g. `https://relay.example.com`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
    },
    /// Inspect local encrypted revision metadata.
    Revision {
        #[command(subcommand)]
        command: RevisionCommand,
    },
    /// Check relay health and readiness.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Print shell completion script.
    Completions {
        /// Shell to generate completions for.
        shell: Shell,
    },
    /// Print version information.
    Version,
}

#[derive(Subcommand, Debug)]
enum EnvCommand {
    /// List configured environments and local revision pointers.
    List,
    /// Create a signed environment genesis record.
    ///
    /// Records the local file mapping but does not read the file,
    /// publish encrypted payloads, or contact a relay.
    Add {
        /// Human-readable environment label, e.g. `development`.
        environment_label: String,
        /// Machine-local dotenv path hint, e.g. `.env.local`.
        local_path: std::path::PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum RevisionCommand {
    /// List local encrypted revision metadata for an environment.
    List {
        /// Environment label or `kve_...` ID.
        environment: String,
    },
}

#[derive(Subcommand, Debug)]
enum RelayCommand {
    /// Check the hosted relay or another HTTP(S) relay.
    Check {
        /// Relay URL to check. Defaults to `https://relay.keyit.sh`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum InviteCommand {
    /// Create a signed invite.
    Create {
        /// Environment label or `kve_...` ID this invite may request. Repeatable.
        #[arg(long = "env")]
        environments: Vec<String>,
        /// Unix timestamp when this invite expires.
        #[arg(long = "expires-at")]
        expires_at: u64,
        /// Maximum successful joins this invite may produce.
        #[arg(long = "max-uses", default_value_t = 1)]
        max_uses: u32,
        /// HTTP relay URL override, e.g. `https://relay.example.com`.
        #[arg(long = "relay-url")]
        relay_url: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        None => {
            let mut command = Cli::command();
            let _ = command.print_help();
            println!();
            ExitCode::SUCCESS
        }
        Some(Command::Init {
            project_label,
            relay_url,
            force,
        }) => run_init_command(project_label, relay_url, force),
        Some(Command::Env { command }) => match command {
            EnvCommand::List => run_env_list_command(),
            EnvCommand::Add {
                environment_label,
                local_path,
            } => run_env_add_command(environment_label, local_path),
        },
        Some(Command::Whoami) => run_whoami_command(),
        Some(Command::Status { environment }) => run_status_command(environment),
        Some(Command::Diff { environment }) => run_diff_command(environment),
        Some(Command::Push {
            environment,
            summary,
            relay_dir,
            relay_url,
        }) => run_push_command(environment, summary, relay_dir, relay_url),
        Some(Command::Pull {
            environment,
            relay_dir,
            relay_url,
            force,
        }) => run_pull_command(environment, relay_dir, relay_url, force),
        Some(Command::Invite { command }) => match command {
            InviteCommand::Create {
                environments,
                expires_at,
                max_uses,
                relay_url,
            } => run_invite_create_command(environments, expires_at, max_uses, relay_url),
        },
        Some(Command::Join {
            invite_id,
            environments,
            device_label,
            relay_url,
        }) => run_join_command(invite_id, environments, device_label, relay_url),
        Some(Command::Approve {
            device_id,
            role,
            relay_url,
        }) => run_approve_command(device_id, role, relay_url),
        Some(Command::Revoke {
            device_id,
            environments,
            reason,
            relay_url,
        }) => run_revoke_command(device_id, environments, reason, relay_url),
        Some(Command::Revision { command }) => match command {
            RevisionCommand::List { environment } => run_revision_list_command(environment),
        },
        Some(Command::Relay { command }) => match command {
            RelayCommand::Check { relay_url } => run_relay_check_command(relay_url),
        },
        Some(Command::Completions { shell }) => run_completions_command(shell),
        Some(Command::Version) => {
            println!("keyit {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}

fn run_whoami_command() -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_whoami(WhoamiOptions {
        project_root,
        keyit_data_dir,
        now: current_timestamp(),
    }) {
        Ok(outcome) => {
            println!("Project {} ({})", outcome.project_label, outcome.project_id);
            println!("Device {}", outcome.device_id);
            println!("  active member:          {}", yes_no(outcome.active));
            println!(
                "  accessible environments: {}",
                outcome.accessible_environment_count
            );
            println!(
                "  signing public key:     {}",
                outcome.signing_public_key_hex
            );
            println!(
                "  encryption public key:  {}",
                outcome.encryption_public_key_hex
            );
            println!(
                "  signing key ref:        {}",
                outcome.signing_key_ref.display()
            );
            println!(
                "  encryption key ref:     {}",
                outcome.encryption_key_ref.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_env_list_command() -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_env_list(EnvListOptions {
        project_root,
        keyit_data_dir,
    }) {
        Ok(outcome) => {
            println!("Project {}", outcome.project_id);
            if outcome.environments.is_empty() {
                println!("No environments configured. Run `keyit env add <label> <path>`.");
                return ExitCode::SUCCESS;
            }

            for env in outcome.environments {
                println!();
                println!("Environment {} ({})", env.label, env.environment_id);
                println!("  local path:   {}", env.local_path.display());
                println!(
                    "  latest:       {}",
                    env.latest_revision_id
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or("none")
                );
                println!(
                    "  materialized: {}",
                    env.materialized_revision_id
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or("none")
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_revision_list_command(environment: String) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_revision_list(RevisionListOptions {
        project_root,
        keyit_data_dir,
        environment,
    }) {
        Ok(outcome) => {
            println!(
                "Revisions for {} ({}) in project {}",
                outcome.label, outcome.environment_id, outcome.project_id
            );
            if outcome.revisions.is_empty() {
                println!("No local encrypted revisions yet.");
                return ExitCode::SUCCESS;
            }

            for revision in outcome.revisions {
                println!();
                println!("Revision {}", revision.revision_id);
                println!(
                    "  parent:     {}",
                    revision
                        .parent_revision_id
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or("none")
                );
                println!("  author:     {}", revision.author_device_id);
                println!("  created at: {}", revision.created_at.unix_seconds());
                println!(
                    "  summary:    {}",
                    revision.change_summary.as_deref().unwrap_or("none")
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_completions_command(shell: Shell) -> ExitCode {
    let mut command = Cli::command();
    generate(shell, &mut command, "keyit", &mut std::io::stdout());
    ExitCode::SUCCESS
}

fn run_relay_check_command(relay_url: Option<String>) -> ExitCode {
    let relay_url = relay_url.unwrap_or_else(|| keyit_cli::init::DEFAULT_RELAY_URL.to_string());
    match RelayHttpClient::new(&relay_url).and_then(|client| client.check()) {
        Ok(outcome) => {
            println!("Relay {}", outcome.relay_url);
            println!("  health:    HTTP {}", outcome.health_status);
            println!("  readiness: HTTP {}", outcome.readiness_status);
            if outcome.ready {
                println!("  status:    ready");
                ExitCode::SUCCESS
            } else {
                println!("  status:    not ready");
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_init_command(
    project_label: Option<String>,
    relay_url: Option<String>,
    force: bool,
) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let now = current_timestamp();

    let options = InitOptions {
        project_root,
        keyit_data_dir,
        project_label,
        relay_url,
        force,
        now,
    };

    match run_init(options) {
        Ok(outcome) => {
            println!("Initialized Keyit project {}", outcome.project_id,);
            println!("  locator:            keyit.toml");
            println!(
                "  local state:        {}",
                outcome.layout.keyit_dir.display()
            );
            println!("  project label:      {}", outcome.project_label);
            println!("  default relay URL:  {}", outcome.default_relay_url);
            println!("  creator device:     {}", outcome.creator_device_id);
            println!(
                "  device signing key: {} (reused if it already existed; never stored in the repo)",
                outcome.device_signing_key_path.display()
            );
            println!(
                "  device encryption key: {} (reused if it already existed; never stored in the repo)",
                outcome.device_encryption_key_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_env_add_command(environment_label: String, local_path: std::path::PathBuf) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let options = EnvAddOptions {
        project_root,
        keyit_data_dir,
        environment_label,
        local_path,
        now: current_timestamp(),
    };

    match run_env_add(options) {
        Ok(outcome) => {
            println!(
                "Added Keyit environment {} ({})",
                outcome.environment_label, outcome.environment_id
            );
            println!("  project:    {}", outcome.project_id);
            println!("  local path: {}", outcome.local_path.display());
            println!("  metadata:   {}", outcome.layout.environment_dir.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_status_command(environment: Option<String>) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_status(StatusOptions {
        project_root,
        keyit_data_dir,
        environment,
    }) {
        Ok(outcome) => {
            println!("Project {}", outcome.project_id);
            if outcome.environments.is_empty() {
                println!("No environments configured. Run `keyit env add <label> <path>`.");
                return ExitCode::SUCCESS;
            }

            for env in outcome.environments {
                println!();
                println!("Environment {} ({})", env.label, env.environment_id);
                println!("  local path: {}", env.local_path.display());
                println!(
                    "  latest:     {}",
                    env.latest_revision_id
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or("none")
                );
                println!(
                    "  local base: {}",
                    env.materialized_revision_id
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or("none")
                );
                match env.state {
                    LocalFileState::Present { key_count } => {
                        println!("  state:      local file present, {key_count} keys parsed");
                    }
                    LocalFileState::Missing => {
                        println!("  state:      local file missing");
                    }
                    LocalFileState::Invalid { reason } => {
                        println!("  state:      local file invalid ({reason})");
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_diff_command(environment: Option<String>) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_diff(DiffOptions {
        project_root,
        keyit_data_dir,
        environment,
    }) {
        Ok(outcome) => {
            println!("Project {}", outcome.project_id);
            if outcome.environments.is_empty() {
                println!("No environments configured. Run `keyit env add <label> <path>`.");
                return ExitCode::SUCCESS;
            }

            for env in outcome.environments {
                println!();
                println!("Environment {} ({})", env.label, env.environment_id);
                println!("  local path: {}", env.local_path.display());
                println!(
                    "  baseline:   {}",
                    env.baseline_revision_id
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or("empty (no local revisions yet)")
                );
                match env.state {
                    DiffState::Missing => {
                        println!("  diff:       local file missing");
                    }
                    DiffState::Invalid { reason } => {
                        println!("  diff:       local file invalid ({reason})");
                    }
                    DiffState::NoChanges => {
                        println!("  diff:       no keys");
                    }
                    DiffState::Keys(keys) => {
                        for diff in keys {
                            let status = match diff.status {
                                KeyDiffStatus::Added => "added",
                                KeyDiffStatus::Modified => "modified",
                                KeyDiffStatus::Removed => "removed",
                            };
                            println!("  {status:<10} {}", diff.key);
                        }
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_push_command(
    environment: String,
    summary: Option<String>,
    relay_dir: Option<std::path::PathBuf>,
    relay_url: Option<String>,
) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_push(PushOptions {
        project_root,
        keyit_data_dir,
        environment,
        change_summary: summary,
        relay_dir,
        relay_url,
        now: current_timestamp(),
    }) {
        Ok(outcome) => {
            println!(
                "Created local encrypted revision {} for {} ({})",
                outcome.revision_id, outcome.label, outcome.environment_id
            );
            println!("  project:  {}", outcome.project_id);
            println!("  keys:     {}", outcome.key_count);
            println!("  revision: {}", outcome.revision_path.display());
            println!("  payload:  {}", outcome.payload_path.display());
            if let (Some(revision), Some(payload)) =
                (&outcome.relay_revision_path, &outcome.relay_payload_path)
            {
                println!("  relay revision: {}", revision.display());
                println!("  relay payload:  {}", payload.display());
            }
            if let Some(relay_url) = &outcome.relay_url {
                println!("  relay:    published to {relay_url}");
            }
            if outcome.rotation_cleared {
                println!("  rotation: cleared post-revocation rotation requirement");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_pull_command(
    environment: String,
    relay_dir: Option<std::path::PathBuf>,
    relay_url: Option<String>,
    force: bool,
) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_pull(PullOptions {
        project_root,
        keyit_data_dir,
        environment,
        relay_dir,
        relay_url,
        force,
        now: current_timestamp(),
    }) {
        Ok(outcome) => {
            println!(
                "Materialized local revision {} for {} ({})",
                outcome.revision_id, outcome.label, outcome.environment_id
            );
            println!("  project:    {}", outcome.project_id);
            println!("  local path: {}", outcome.local_path.display());
            println!("  keys:       {}", outcome.key_count);
            if outcome.fetched_from_relay {
                if let Some(relay_url) = &outcome.relay_url {
                    println!("  relay:      fetched latest encrypted revision from {relay_url}");
                } else {
                    println!("  relay:      fetched latest encrypted revision");
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_invite_create_command(
    environments: Vec<String>,
    expires_at: u64,
    max_uses: u32,
    relay_url: Option<String>,
) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_invite_create(InviteCreateOptions {
        project_root,
        keyit_data_dir,
        environments,
        expires_at: Timestamp::from_unix_seconds(expires_at),
        max_uses,
        relay_url,
        now: current_timestamp(),
    }) {
        Ok(outcome) => {
            println!("Created invite {}", outcome.invite_id);
            println!("  project:      {}", outcome.project_id);
            println!("  environments: {}", outcome.allowed_environment_ids.len());
            println!("  record:       {}", outcome.path.display());
            println!("  bundle:       {}", outcome.bundle_path.display());
            if let Some(relay_url) = &outcome.relay_url {
                println!("  relay:        published to {relay_url}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_join_command(
    invite_id: String,
    environments: Vec<String>,
    device_label: Option<String>,
    relay_url: Option<String>,
) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let target = match InviteId::parse(&invite_id) {
        Ok(id) => JoinTarget::InviteId(id),
        Err(err) if invite_id.starts_with("kvi_") => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
        Err(_) => JoinTarget::BundlePath(std::path::PathBuf::from(invite_id)),
    };

    match run_join(JoinOptions {
        project_root,
        keyit_data_dir,
        target,
        requested_environments: environments,
        device_label: device_label.unwrap_or_else(|| "local-device".to_string()),
        relay_url,
        now: current_timestamp(),
    }) {
        Ok(outcome) => {
            println!("Created join request for {}", outcome.joining_device_id);
            println!("  project:      {}", outcome.project_id);
            println!("  invite:       {}", outcome.invite_id);
            println!(
                "  environments: {}",
                outcome.requested_environment_ids.len()
            );
            println!("  record:       {}", outcome.path.display());
            if outcome.fetched_invite_from_relay {
                println!("  invite:       fetched from relay");
            }
            if let Some(relay_url) = &outcome.relay_url {
                println!("  relay:        published to {relay_url}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_approve_command(device_id: String, role: String, relay_url: Option<String>) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let joining_device_id = match DeviceId::parse(&device_id) {
        Ok(id) => id,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let role = match parse_role_arg(&role) {
        Ok(role) => role,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::FAILURE;
        }
    };

    match run_approve(ApproveOptions {
        project_root,
        keyit_data_dir,
        joining_device_id,
        role,
        relay_url,
        now: current_timestamp(),
    }) {
        Ok(outcome) => {
            println!("Approved device {}", outcome.approved_device_id);
            println!("  project:      {}", outcome.project_id);
            println!("  role:         {}", outcome.role.as_str());
            println!("  environments: {}", outcome.approved_environment_ids.len());
            println!("  record:       {}", outcome.path.display());
            if outcome.fetched_join_request_from_relay {
                println!("  join request: fetched from relay");
            }
            if let Some(relay_url) = &outcome.relay_url {
                println!("  relay:        published to {relay_url}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_revoke_command(
    device_id: String,
    environments: Vec<String>,
    reason: Option<String>,
    relay_url: Option<String>,
) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: could not determine the current directory: {err}");
            return ExitCode::FAILURE;
        }
    };

    let keyit_data_dir = match keyit_cli::device_key::default_keyit_data_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let revoked_device_id = match DeviceId::parse(&device_id) {
        Ok(id) => id,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run_revoke(RevokeOptions {
        project_root,
        keyit_data_dir,
        revoked_device_id,
        affected_environments: environments,
        reason,
        relay_url,
        now: current_timestamp(),
    }) {
        Ok(outcome) => {
            println!("Revoked device {}", outcome.revoked_device_id);
            println!("  project:      {}", outcome.project_id);
            println!("  environments: {}", outcome.affected_environment_ids.len());
            println!("  record:       {}", outcome.path.display());
            if !outcome.rotation_required_paths.is_empty() {
                println!("  rotation:     required; run `keyit push <environment>` for each affected environment");
            }
            if let Some(relay_url) = &outcome.relay_url {
                println!("  relay:        published to {relay_url}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn parse_role_arg(value: &str) -> Result<Role, String> {
    match value {
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        "member" => Ok(Role::Member),
        other => Err(format!(
            "unknown role \"{other}\"; expected owner, admin, or member"
        )),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn current_timestamp() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Timestamp::from_unix_seconds(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_with_no_arguments() {
        Cli::try_parse_from(["keyit"]).expect("cli should parse with no arguments");
    }

    #[test]
    fn links_against_protocol_crate() {
        assert_eq!(
            keyit_protocol::ProtocolVersion::CURRENT,
            keyit_protocol::ProtocolVersion::V1
        );
    }

    #[test]
    fn parses_init_with_no_flags() {
        let cli = Cli::try_parse_from(["keyit", "init"]).expect("init should parse with no flags");
        match cli.command {
            Some(Command::Init {
                project_label,
                relay_url,
                force,
            }) => {
                assert_eq!(project_label, None);
                assert_eq!(relay_url, None);
                assert!(!force);
            }
            other => panic!("expected Command::Init, got {other:?}"),
        }
    }

    #[test]
    fn parses_init_with_all_flags() {
        let cli = Cli::try_parse_from([
            "keyit",
            "init",
            "--project-label",
            "my-project",
            "--relay-url",
            "https://relay.example.com",
            "--force",
        ])
        .expect("init should parse with all flags");

        match cli.command {
            Some(Command::Init {
                project_label,
                relay_url,
                force,
            }) => {
                assert_eq!(project_label.as_deref(), Some("my-project"));
                assert_eq!(relay_url.as_deref(), Some("https://relay.example.com"));
                assert!(force);
            }
            other => panic!("expected Command::Init, got {other:?}"),
        }
    }

    #[test]
    fn parses_env_add() {
        let cli = Cli::try_parse_from(["keyit", "env", "add", "development", ".env.local"])
            .expect("env add should parse");

        match cli.command {
            Some(Command::Env {
                command:
                    EnvCommand::Add {
                        environment_label,
                        local_path,
                    },
            }) => {
                assert_eq!(environment_label, "development");
                assert_eq!(local_path, std::path::PathBuf::from(".env.local"));
            }
            other => panic!("expected Command::Env/Add, got {other:?}"),
        }
    }

    #[test]
    fn parses_env_list() {
        let cli = Cli::try_parse_from(["keyit", "env", "list"]).expect("env list should parse");

        match cli.command {
            Some(Command::Env {
                command: EnvCommand::List,
            }) => {}
            other => panic!("expected Command::Env/List, got {other:?}"),
        }
    }

    #[test]
    fn parses_whoami() {
        let cli = Cli::try_parse_from(["keyit", "whoami"]).expect("whoami should parse");

        match cli.command {
            Some(Command::Whoami) => {}
            other => panic!("expected Command::Whoami, got {other:?}"),
        }
    }

    #[test]
    fn parses_status_with_optional_environment() {
        let cli =
            Cli::try_parse_from(["keyit", "status", "development"]).expect("status should parse");

        match cli.command {
            Some(Command::Status { environment }) => {
                assert_eq!(environment.as_deref(), Some("development"));
            }
            other => panic!("expected Command::Status, got {other:?}"),
        }
    }

    #[test]
    fn parses_diff_with_optional_environment() {
        let cli = Cli::try_parse_from(["keyit", "diff", "development"]).expect("diff should parse");

        match cli.command {
            Some(Command::Diff { environment }) => {
                assert_eq!(environment.as_deref(), Some("development"));
            }
            other => panic!("expected Command::Diff, got {other:?}"),
        }
    }

    #[test]
    fn parses_push_with_summary() {
        let cli = Cli::try_parse_from([
            "keyit",
            "push",
            "development",
            "--summary",
            "rotate API key",
        ])
        .expect("push should parse");

        match cli.command {
            Some(Command::Push {
                environment,
                summary,
                relay_dir,
                relay_url,
            }) => {
                assert_eq!(environment, "development");
                assert_eq!(summary.as_deref(), Some("rotate API key"));
                assert_eq!(relay_dir, None);
                assert_eq!(relay_url, None);
            }
            other => panic!("expected Command::Push, got {other:?}"),
        }
    }

    #[test]
    fn parses_pull() {
        let cli = Cli::try_parse_from(["keyit", "pull", "development"]).expect("pull should parse");

        match cli.command {
            Some(Command::Pull {
                environment,
                relay_dir,
                relay_url,
                force,
            }) => {
                assert_eq!(environment, "development");
                assert_eq!(relay_dir, None);
                assert_eq!(relay_url, None);
                assert!(!force);
            }
            other => panic!("expected Command::Pull, got {other:?}"),
        }
    }

    #[test]
    fn parses_pull_with_force() {
        let cli = Cli::try_parse_from(["keyit", "pull", "development", "--force"])
            .expect("pull should parse");

        match cli.command {
            Some(Command::Pull { force, .. }) => {
                assert!(force);
            }
            other => panic!("expected Command::Pull, got {other:?}"),
        }
    }

    #[test]
    fn parses_push_with_relay_dir() {
        let cli =
            Cli::try_parse_from(["keyit", "push", "development", "--relay-dir", "/tmp/relay"])
                .expect("push should parse");

        match cli.command {
            Some(Command::Push { relay_dir, .. }) => {
                assert_eq!(relay_dir, Some(std::path::PathBuf::from("/tmp/relay")));
            }
            other => panic!("expected Command::Push, got {other:?}"),
        }
    }

    #[test]
    fn parses_push_with_relay_url() {
        let cli = Cli::try_parse_from([
            "keyit",
            "push",
            "development",
            "--relay-url",
            "http://127.0.0.1:7878",
        ])
        .expect("push should parse");

        match cli.command {
            Some(Command::Push { relay_url, .. }) => {
                assert_eq!(relay_url.as_deref(), Some("http://127.0.0.1:7878"));
            }
            other => panic!("expected Command::Push, got {other:?}"),
        }
    }

    #[test]
    fn parses_pull_with_relay_url() {
        let cli = Cli::try_parse_from([
            "keyit",
            "pull",
            "development",
            "--relay-url",
            "http://127.0.0.1:7878",
        ])
        .expect("pull should parse");

        match cli.command {
            Some(Command::Pull { relay_url, .. }) => {
                assert_eq!(relay_url.as_deref(), Some("http://127.0.0.1:7878"));
            }
            other => panic!("expected Command::Pull, got {other:?}"),
        }
    }

    #[test]
    fn parses_relay_check_with_default_url() {
        let cli = Cli::try_parse_from(["keyit", "relay", "check"]).expect("relay check parses");

        match cli.command {
            Some(Command::Relay {
                command: RelayCommand::Check { relay_url },
            }) => {
                assert_eq!(relay_url, None);
            }
            other => panic!("expected Command::Relay/Check, got {other:?}"),
        }
    }

    #[test]
    fn parses_relay_check_with_custom_url() {
        let cli = Cli::try_parse_from([
            "keyit",
            "relay",
            "check",
            "--relay-url",
            "https://relay.example.com",
        ])
        .expect("relay check parses");

        match cli.command {
            Some(Command::Relay {
                command: RelayCommand::Check { relay_url },
            }) => {
                assert_eq!(relay_url.as_deref(), Some("https://relay.example.com"));
            }
            other => panic!("expected Command::Relay/Check, got {other:?}"),
        }
    }

    #[test]
    fn parses_revision_list() {
        let cli = Cli::try_parse_from(["keyit", "revision", "list", "development"])
            .expect("revision list should parse");

        match cli.command {
            Some(Command::Revision {
                command: RevisionCommand::List { environment },
            }) => {
                assert_eq!(environment, "development");
            }
            other => panic!("expected Command::Revision/List, got {other:?}"),
        }
    }

    #[test]
    fn parses_completions() {
        let cli =
            Cli::try_parse_from(["keyit", "completions", "zsh"]).expect("completions should parse");

        match cli.command {
            Some(Command::Completions { shell }) => assert_eq!(shell, Shell::Zsh),
            other => panic!("expected Command::Completions, got {other:?}"),
        }
    }

    #[test]
    fn parses_version_command() {
        let cli = Cli::try_parse_from(["keyit", "version"]).expect("version should parse");

        match cli.command {
            Some(Command::Version) => {}
            other => panic!("expected Command::Version, got {other:?}"),
        }
    }

    #[test]
    fn parses_invite_create() {
        let cli = Cli::try_parse_from([
            "keyit",
            "invite",
            "create",
            "--env",
            "development",
            "--expires-at",
            "1755900000",
            "--max-uses",
            "2",
        ])
        .expect("invite create should parse");

        match cli.command {
            Some(Command::Invite {
                command:
                    InviteCommand::Create {
                        environments,
                        expires_at,
                        max_uses,
                        relay_url,
                    },
            }) => {
                assert_eq!(environments, vec!["development"]);
                assert_eq!(expires_at, 1_755_900_000);
                assert_eq!(max_uses, 2);
                assert_eq!(relay_url, None);
            }
            other => panic!("expected Command::Invite/Create, got {other:?}"),
        }
    }

    #[test]
    fn parses_join() {
        let invite_id = "kvi_kakptlz2nbh52zfhoxa4jrjs5ztldolmwvvr2aqxburetntwj52q";
        let cli = Cli::try_parse_from([
            "keyit",
            "join",
            invite_id,
            "--env",
            "development",
            "--device-label",
            "workstation",
        ])
        .expect("join should parse");

        match cli.command {
            Some(Command::Join {
                invite_id: parsed_invite_id,
                environments,
                device_label,
                relay_url,
            }) => {
                assert_eq!(parsed_invite_id, invite_id);
                assert_eq!(environments, vec!["development"]);
                assert_eq!(device_label.as_deref(), Some("workstation"));
                assert_eq!(relay_url, None);
            }
            other => panic!("expected Command::Join, got {other:?}"),
        }
    }

    #[test]
    fn parses_approve() {
        let device_id = "kvd_nk4bzt42f6dmnt5lgw5pimjmcfzu6tsdj2yayhgpzvf5vw6d2rba";
        let cli = Cli::try_parse_from(["keyit", "approve", device_id, "--role", "admin"])
            .expect("approve should parse");

        match cli.command {
            Some(Command::Approve {
                device_id: parsed_device_id,
                role,
                relay_url,
            }) => {
                assert_eq!(parsed_device_id, device_id);
                assert_eq!(role, "admin");
                assert_eq!(relay_url, None);
            }
            other => panic!("expected Command::Approve, got {other:?}"),
        }
    }

    #[test]
    fn parses_revoke() {
        let device_id = "kvd_nk4bzt42f6dmnt5lgw5pimjmcfzu6tsdj2yayhgpzvf5vw6d2rba";
        let cli = Cli::try_parse_from([
            "keyit",
            "revoke",
            device_id,
            "--env",
            "development",
            "--reason",
            "rotated laptop",
        ])
        .expect("revoke should parse");

        match cli.command {
            Some(Command::Revoke {
                device_id: parsed_device_id,
                environments,
                reason,
                relay_url,
            }) => {
                assert_eq!(parsed_device_id, device_id);
                assert_eq!(environments, vec!["development"]);
                assert_eq!(reason.as_deref(), Some("rotated laptop"));
                assert_eq!(relay_url, None);
            }
            other => panic!("expected Command::Revoke, got {other:?}"),
        }
    }
}
