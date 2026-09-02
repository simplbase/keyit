//! Keyit Relay entry point.
//!
//! The Keyit Relay is the untrusted, internet-accessible service that
//! stores and distributes encrypted Keyit state and protocol metadata. It
//! is designed to never see plaintext secrets.
//!
//! This binary serves the minimal v1 HTTP relay API backed by the
//! filesystem store.
//!
//! Run `keyit-relay --help` or `keyit-relay --version`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use keyit_relay::{
    serve_http_blocking_with_options, CleanupPolicy, FileRelayStore, RelayHttpLimits,
    RelayServerOptions, StoragePolicy,
};

/// Keyit Relay: untrusted storage and distribution for encrypted Keyit state.
#[derive(Parser, Debug)]
#[command(name = "keyit-relay", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Serve the v1 HTTP relay API.
    Serve {
        /// Filesystem storage root. Defaults to KEYIT_RELAY_ROOT.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Address to bind, e.g. 127.0.0.1:8787. Defaults to KEYIT_RELAY_ADDR or 127.0.0.1:8787.
        #[arg(long)]
        addr: Option<String>,
        /// Public externally visible URL, e.g. https://relay.example.com. Defaults to KEYIT_RELAY_PUBLIC_URL.
        #[arg(long = "public-url")]
        public_url: Option<String>,
        /// Runtime mode: dev or production. Defaults to KEYIT_RELAY_MODE or dev.
        #[arg(long)]
        mode: Option<String>,
        /// Maximum HTTP header bytes.
        #[arg(long = "max-header-bytes")]
        max_header_bytes: Option<usize>,
        /// Maximum signed HTTP request body bytes.
        #[arg(long = "max-body-bytes")]
        max_body_bytes: Option<usize>,
        /// Maximum authorization envelope bytes inside a signed request.
        #[arg(long = "max-authorization-bytes")]
        max_authorization_bytes: Option<usize>,
        /// Maximum relay payload envelope bytes inside a signed request.
        #[arg(long = "max-request-payload-bytes")]
        max_request_payload_bytes: Option<usize>,
        /// Maximum revision metadata bytes stored by the relay.
        #[arg(long = "max-revision-metadata-bytes")]
        max_revision_metadata_bytes: Option<usize>,
        /// Maximum encrypted payload bytes stored by the relay.
        #[arg(long = "max-encrypted-payload-bytes")]
        max_encrypted_payload_bytes: Option<usize>,
        /// Maximum revision objects per project/environment. 0 disables
        /// this cap; unset keeps the built-in production-safe default.
        #[arg(long = "max-revisions-per-environment")]
        max_revisions_per_environment: Option<usize>,
        /// Maximum projects a single creator device may publish to
        /// this relay. 0 or unset disables this cap.
        #[arg(long = "max-projects-per-device")]
        max_projects_per_device: Option<usize>,
        /// Maximum environments per project. 0 or unset disables this
        /// cap.
        #[arg(long = "max-environments-per-project")]
        max_environments_per_project: Option<usize>,
        /// Maximum active devices per project. 0 or unset disables this
        /// cap.
        #[arg(long = "max-devices-per-project")]
        max_devices_per_project: Option<usize>,
        /// Days of inactivity after which a project is eligible for
        /// retention cleanup. 0 or unset disables retention. Recorded
        /// for configuration/documentation only: this relay does not
        /// yet delete inactive projects.
        #[arg(long = "inactive-retention-days")]
        inactive_retention_days: Option<u32>,
        /// Maximum requests per peer IP per minute. Use 0 to disable.
        #[arg(long = "rate-limit-per-minute")]
        rate_limit_per_minute: Option<u32>,
        /// Print resolved runtime configuration before serving.
        #[arg(long = "print-config")]
        print_config: bool,
    },
    /// Inspect or clean relay storage.
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
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
enum MaintenanceCommand {
    /// Print relay storage inventory and integrity status.
    Inspect {
        /// Filesystem storage root. Defaults to KEYIT_RELAY_ROOT.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Remove expired nonce, temporary, and stale lock files.
    Cleanup {
        /// Filesystem storage root. Defaults to KEYIT_RELAY_ROOT.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Replay nonce retention in seconds.
        #[arg(long = "nonce-ttl-seconds")]
        nonce_ttl_seconds: Option<u64>,
        /// Temporary file retention in seconds.
        #[arg(long = "temp-ttl-seconds")]
        temp_ttl_seconds: Option<u64>,
        /// Stale publish lock retention in seconds.
        #[arg(long = "stale-lock-ttl-seconds")]
        stale_lock_ttl_seconds: Option<u64>,
        /// Report what would be removed without deleting files.
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        None => ExitCode::SUCCESS,
        Some(Command::Serve {
            root,
            addr,
            public_url,
            mode,
            max_header_bytes,
            max_body_bytes,
            max_authorization_bytes,
            max_request_payload_bytes,
            max_revision_metadata_bytes,
            max_encrypted_payload_bytes,
            max_revisions_per_environment,
            max_projects_per_device,
            max_environments_per_project,
            max_devices_per_project,
            inactive_retention_days,
            rate_limit_per_minute,
            print_config,
        }) => {
            let config = match RelayRuntimeConfig::resolve(RelayRuntimeInputs {
                root,
                addr,
                public_url,
                mode,
                max_header_bytes,
                max_body_bytes,
                max_authorization_bytes,
                max_request_payload_bytes,
                max_revision_metadata_bytes,
                max_encrypted_payload_bytes,
                max_revisions_per_environment,
                max_projects_per_device,
                max_environments_per_project,
                max_devices_per_project,
                inactive_retention_days,
                rate_limit_per_minute,
            }) {
                Ok(config) => config,
                Err(message) => {
                    eprintln!("error: {message}");
                    return ExitCode::FAILURE;
                }
            };
            if print_config {
                println!("relay root:       {}", config.root.display());
                println!("relay bind addr:  {}", config.addr);
                println!("relay mode:       {}", config.mode.as_str());
                println!(
                    "relay public URL: {}",
                    config.public_url.as_deref().unwrap_or("not set")
                );
                println!("health check:     /healthz");
                println!("readiness check:  /readyz");
                println!(
                    "limits:           body={} payload={} metadata={} revisions/env={} rate/min={}",
                    config.server_options.http_limits.max_body_bytes,
                    config.store_policy.max_encrypted_payload_bytes,
                    config.store_policy.max_revision_metadata_bytes,
                    fmt_count_limit(config.store_policy.max_revisions_per_environment),
                    config.server_options.rate_limit_per_minute
                );
                println!(
                    "hosted limits:    projects/device={} environments/project={} devices/project={} inactive-retention={}",
                    fmt_count_limit(config.store_policy.max_projects_per_device),
                    fmt_count_limit(config.store_policy.max_environments_per_project),
                    fmt_count_limit(config.store_policy.max_devices_per_project),
                    fmt_retention_days(config.server_options.inactive_retention_days),
                );
            }
            let store = FileRelayStore::with_policy(&config.root, config.store_policy.clone());
            if let Err(err) = store.check_ready() {
                eprintln!("error: relay storage is not ready: {err}");
                return ExitCode::FAILURE;
            }
            eprintln!(
                "event=relay_start mode={} addr={} root={} public_url={} rate_limit_per_minute={}",
                config.mode.as_str(),
                config.addr,
                config.root.display(),
                config.public_url.as_deref().unwrap_or(""),
                config.server_options.rate_limit_per_minute
            );
            match serve_http_blocking_with_options(store, &config.addr, config.server_options) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Command::Maintenance { command }) => run_maintenance_command(command),
        Some(Command::Completions { shell }) => {
            let mut command = Cli::command();
            generate(shell, &mut command, "keyit-relay", &mut std::io::stdout());
            ExitCode::SUCCESS
        }
        Some(Command::Version) => {
            println!("keyit-relay {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}

fn run_maintenance_command(command: MaintenanceCommand) -> ExitCode {
    match command {
        MaintenanceCommand::Inspect { root } => {
            let root = match resolve_root(root) {
                Ok(root) => root,
                Err(message) => {
                    eprintln!("error: {message}");
                    return ExitCode::FAILURE;
                }
            };
            let store = FileRelayStore::new(&root);
            match store.verify_integrity() {
                Ok(report) => {
                    println!("relay root:      {}", root.display());
                    println!("projects:        {}", report.inventory.project_count);
                    println!("environments:    {}", report.inventory.environment_count);
                    println!("revisions:       {}", report.inventory.revision_count);
                    println!("payloads:        {}", report.inventory.payload_count);
                    println!("nonces:          {}", report.inventory.nonce_count);
                    println!("bytes:           {}", report.inventory.total_bytes);
                    println!("integrity clean: {}", yes_no(report.is_clean()));
                    println!("malformed revisions: {}", report.malformed_revisions.len());
                    println!("missing payloads:     {}", report.missing_payloads.len());
                    println!(
                        "bad latest pointers:  {}",
                        report.malformed_latest_pointers.len()
                    );
                    if report.is_clean() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        MaintenanceCommand::Cleanup {
            root,
            nonce_ttl_seconds,
            temp_ttl_seconds,
            stale_lock_ttl_seconds,
            dry_run,
        } => {
            let root = match resolve_root(root) {
                Ok(root) => root,
                Err(message) => {
                    eprintln!("error: {message}");
                    return ExitCode::FAILURE;
                }
            };
            let mut policy = CleanupPolicy::default();
            if let Some(seconds) = nonce_ttl_seconds {
                policy.nonce_ttl = Duration::from_secs(seconds);
            }
            if let Some(seconds) = temp_ttl_seconds {
                policy.temp_file_ttl = Duration::from_secs(seconds);
            }
            if let Some(seconds) = stale_lock_ttl_seconds {
                policy.stale_lock_ttl = Duration::from_secs(seconds);
            }
            policy.dry_run = dry_run;
            let store = FileRelayStore::new(&root);
            match store.cleanup_storage(&policy, SystemTime::now()) {
                Ok(report) => {
                    println!("relay root:        {}", root.display());
                    println!("dry run:           {}", yes_no(dry_run));
                    println!("nonce files:       {}", report.nonce_files_removed);
                    println!("temporary files:   {}", report.temp_files_removed);
                    println!("stale lock files:  {}", report.lock_files_removed);
                    println!("bytes removable:   {}", report.bytes_removed);
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn fmt_count_limit(value: usize) -> String {
    if value == 0 {
        "unlimited".to_string()
    } else {
        value.to_string()
    }
}

fn fmt_retention_days(days: u32) -> String {
    if days == 0 {
        "disabled".to_string()
    } else {
        format!("{days}d")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayRuntimeConfig {
    root: PathBuf,
    addr: String,
    public_url: Option<String>,
    mode: RelayMode,
    store_policy: StoragePolicy,
    server_options: RelayServerOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayRuntimeInputs {
    root: Option<PathBuf>,
    addr: Option<String>,
    public_url: Option<String>,
    mode: Option<String>,
    max_header_bytes: Option<usize>,
    max_body_bytes: Option<usize>,
    max_authorization_bytes: Option<usize>,
    max_request_payload_bytes: Option<usize>,
    max_revision_metadata_bytes: Option<usize>,
    max_encrypted_payload_bytes: Option<usize>,
    max_revisions_per_environment: Option<usize>,
    max_projects_per_device: Option<usize>,
    max_environments_per_project: Option<usize>,
    max_devices_per_project: Option<usize>,
    inactive_retention_days: Option<u32>,
    rate_limit_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayMode {
    Dev,
    Production,
}

impl RelayMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "dev" => Ok(Self::Dev),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "unknown relay mode \"{other}\"; expected dev or production"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Production => "production",
        }
    }
}

impl RelayRuntimeConfig {
    fn resolve(inputs: RelayRuntimeInputs) -> Result<Self, String> {
        let root = match inputs.root {
            Some(root) => root,
            None => non_empty_env("KEYIT_RELAY_ROOT")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    "relay storage root is required; pass --root or set KEYIT_RELAY_ROOT"
                        .to_string()
                })?,
        };
        let addr = inputs
            .addr
            .or_else(|| non_empty_env("KEYIT_RELAY_ADDR"))
            .unwrap_or_else(|| "127.0.0.1:8787".to_string());
        let public_url = inputs
            .public_url
            .or_else(|| non_empty_env("KEYIT_RELAY_PUBLIC_URL"));
        let mode = RelayMode::parse(
            inputs
                .mode
                .or_else(|| non_empty_env("KEYIT_RELAY_MODE"))
                .unwrap_or_else(|| "dev".to_string())
                .as_str(),
        )?;
        validate_deployment_inputs(&root, public_url.as_deref(), mode)?;
        let default_storage = StoragePolicy::default();
        let default_http = RelayHttpLimits::default();
        let store_policy = StoragePolicy {
            max_revision_metadata_bytes: resolve_usize(
                inputs.max_revision_metadata_bytes,
                "KEYIT_RELAY_MAX_REVISION_METADATA_BYTES",
                default_storage.max_revision_metadata_bytes,
            )?,
            max_encrypted_payload_bytes: resolve_usize(
                inputs.max_encrypted_payload_bytes,
                "KEYIT_RELAY_MAX_ENCRYPTED_PAYLOAD_BYTES",
                default_storage.max_encrypted_payload_bytes,
            )?,
            max_revisions_per_environment: resolve_usize(
                inputs.max_revisions_per_environment,
                "KEYIT_RELAY_MAX_REVISIONS_PER_ENVIRONMENT",
                default_storage.max_revisions_per_environment,
            )?,
            max_projects_per_device: resolve_usize(
                inputs.max_projects_per_device,
                "KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE",
                default_storage.max_projects_per_device,
            )?,
            max_environments_per_project: resolve_usize(
                inputs.max_environments_per_project,
                "KEYIT_RELAY_MAX_ENVIRONMENTS_PER_PROJECT",
                default_storage.max_environments_per_project,
            )?,
            max_devices_per_project: resolve_usize(
                inputs.max_devices_per_project,
                "KEYIT_RELAY_MAX_DEVICES_PER_PROJECT",
                default_storage.max_devices_per_project,
            )?,
        };
        let http_limits = RelayHttpLimits {
            max_header_bytes: resolve_usize(
                inputs.max_header_bytes,
                "KEYIT_RELAY_MAX_HEADER_BYTES",
                default_http.max_header_bytes,
            )?,
            max_body_bytes: resolve_usize(
                inputs.max_body_bytes,
                "KEYIT_RELAY_MAX_BODY_BYTES",
                default_http.max_body_bytes,
            )?,
            max_authorization_bytes: resolve_usize(
                inputs.max_authorization_bytes,
                "KEYIT_RELAY_MAX_AUTHORIZATION_BYTES",
                default_http.max_authorization_bytes,
            )?,
            max_request_payload_bytes: resolve_usize(
                inputs.max_request_payload_bytes,
                "KEYIT_RELAY_MAX_REQUEST_PAYLOAD_BYTES",
                default_http.max_request_payload_bytes,
            )?,
        };
        if http_limits.max_request_payload_bytes > http_limits.max_body_bytes {
            return Err(
                "KEYIT_RELAY_MAX_REQUEST_PAYLOAD_BYTES must be less than or equal to max body bytes"
                    .to_string(),
            );
        }
        let default_server = RelayServerOptions::default();
        let server_options = RelayServerOptions {
            http_limits,
            rate_limit_per_minute: resolve_u32(
                inputs.rate_limit_per_minute,
                "KEYIT_RELAY_RATE_LIMIT_PER_MINUTE",
                default_server.rate_limit_per_minute,
            )?,
            inactive_retention_days: resolve_u32(
                inputs.inactive_retention_days,
                "KEYIT_RELAY_INACTIVE_RETENTION_DAYS",
                default_server.inactive_retention_days,
            )?,
        };
        Ok(Self {
            root,
            addr,
            public_url,
            mode,
            store_policy,
            server_options,
        })
    }
}

fn validate_deployment_inputs(
    root: &Path,
    public_url: Option<&str>,
    mode: RelayMode,
) -> Result<(), String> {
    if mode == RelayMode::Production {
        if !root.is_absolute() {
            return Err("production relay root must be an absolute path".to_string());
        }
        let Some(public_url) = public_url else {
            return Err(
                "production relay requires --public-url or KEYIT_RELAY_PUBLIC_URL".to_string(),
            );
        };
        if !public_url.starts_with("https://") {
            return Err("production relay public URL must start with https://".to_string());
        }
    }
    Ok(())
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn resolve_root(root: Option<PathBuf>) -> Result<PathBuf, String> {
    match root {
        Some(root) => Ok(root),
        None => non_empty_env("KEYIT_RELAY_ROOT")
            .map(PathBuf::from)
            .ok_or_else(|| {
                "relay storage root is required; pass --root or set KEYIT_RELAY_ROOT".to_string()
            }),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn resolve_usize(
    explicit: Option<usize>,
    env_name: &str,
    default_value: usize,
) -> Result<usize, String> {
    if let Some(value) = explicit {
        return Ok(value);
    }
    match non_empty_env(env_name) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|err| format!("{env_name} must be a positive integer: {err}")),
        None => Ok(default_value),
    }
}

fn resolve_u32(explicit: Option<u32>, env_name: &str, default_value: u32) -> Result<u32, String> {
    if let Some(value) = explicit {
        return Ok(value);
    }
    match non_empty_env(env_name) {
        Some(value) => value
            .parse::<u32>()
            .map_err(|err| format!("{env_name} must be a non-negative integer: {err}")),
        None => Ok(default_value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_with_no_arguments() {
        Cli::try_parse_from(["keyit-relay"]).expect("cli should parse with no arguments");
    }

    #[test]
    fn parses_serve() {
        let cli = Cli::try_parse_from([
            "keyit-relay",
            "serve",
            "--root",
            "/tmp/keyit-relay",
            "--addr",
            "127.0.0.1:9999",
        ])
        .expect("serve should parse");
        match cli.command {
            Some(Command::Serve {
                root,
                addr,
                public_url,
                mode,
                max_header_bytes,
                max_body_bytes,
                max_authorization_bytes,
                max_request_payload_bytes,
                max_revision_metadata_bytes,
                max_encrypted_payload_bytes,
                max_revisions_per_environment,
                max_projects_per_device,
                max_environments_per_project,
                max_devices_per_project,
                inactive_retention_days,
                rate_limit_per_minute,
                print_config,
            }) => {
                assert_eq!(root, Some(PathBuf::from("/tmp/keyit-relay")));
                assert_eq!(addr.as_deref(), Some("127.0.0.1:9999"));
                assert_eq!(public_url, None);
                assert_eq!(mode, None);
                assert_eq!(max_header_bytes, None);
                assert_eq!(max_body_bytes, None);
                assert_eq!(max_authorization_bytes, None);
                assert_eq!(max_request_payload_bytes, None);
                assert_eq!(max_revision_metadata_bytes, None);
                assert_eq!(max_encrypted_payload_bytes, None);
                assert_eq!(max_revisions_per_environment, None);
                assert_eq!(max_projects_per_device, None);
                assert_eq!(max_environments_per_project, None);
                assert_eq!(max_devices_per_project, None);
                assert_eq!(inactive_retention_days, None);
                assert_eq!(rate_limit_per_minute, None);
                assert!(!print_config);
            }
            other => panic!("expected serve command, got {other:?}"),
        }
    }

    #[test]
    fn parses_serve_limits() {
        let cli = Cli::try_parse_from([
            "keyit-relay",
            "serve",
            "--root",
            "/tmp/keyit-relay",
            "--mode",
            "production",
            "--public-url",
            "https://relay.example",
            "--max-body-bytes",
            "1234",
            "--max-encrypted-payload-bytes",
            "1000",
            "--max-projects-per-device",
            "3",
            "--max-environments-per-project",
            "3",
            "--max-devices-per-project",
            "5",
            "--inactive-retention-days",
            "30",
            "--rate-limit-per-minute",
            "7",
        ])
        .expect("serve should parse limits");
        match cli.command {
            Some(Command::Serve {
                mode,
                public_url,
                max_body_bytes,
                max_encrypted_payload_bytes,
                max_projects_per_device,
                max_environments_per_project,
                max_devices_per_project,
                inactive_retention_days,
                rate_limit_per_minute,
                ..
            }) => {
                assert_eq!(mode.as_deref(), Some("production"));
                assert_eq!(public_url.as_deref(), Some("https://relay.example"));
                assert_eq!(max_body_bytes, Some(1234));
                assert_eq!(max_encrypted_payload_bytes, Some(1000));
                assert_eq!(max_projects_per_device, Some(3));
                assert_eq!(max_environments_per_project, Some(3));
                assert_eq!(max_devices_per_project, Some(5));
                assert_eq!(inactive_retention_days, Some(30));
                assert_eq!(rate_limit_per_minute, Some(7));
            }
            other => panic!("expected serve command, got {other:?}"),
        }
    }

    #[test]
    fn parses_maintenance_inspect() {
        let cli = Cli::try_parse_from([
            "keyit-relay",
            "maintenance",
            "inspect",
            "--root",
            "/tmp/keyit-relay",
        ])
        .expect("maintenance inspect should parse");

        match cli.command {
            Some(Command::Maintenance {
                command: MaintenanceCommand::Inspect { root },
            }) => {
                assert_eq!(root, Some(PathBuf::from("/tmp/keyit-relay")));
            }
            other => panic!("expected maintenance inspect command, got {other:?}"),
        }
    }

    #[test]
    fn parses_maintenance_cleanup() {
        let cli = Cli::try_parse_from([
            "keyit-relay",
            "maintenance",
            "cleanup",
            "--root",
            "/tmp/keyit-relay",
            "--nonce-ttl-seconds",
            "60",
            "--temp-ttl-seconds",
            "30",
            "--stale-lock-ttl-seconds",
            "10",
            "--dry-run",
        ])
        .expect("maintenance cleanup should parse");

        match cli.command {
            Some(Command::Maintenance {
                command:
                    MaintenanceCommand::Cleanup {
                        root,
                        nonce_ttl_seconds,
                        temp_ttl_seconds,
                        stale_lock_ttl_seconds,
                        dry_run,
                    },
            }) => {
                assert_eq!(root, Some(PathBuf::from("/tmp/keyit-relay")));
                assert_eq!(nonce_ttl_seconds, Some(60));
                assert_eq!(temp_ttl_seconds, Some(30));
                assert_eq!(stale_lock_ttl_seconds, Some(10));
                assert!(dry_run);
            }
            other => panic!("expected maintenance cleanup command, got {other:?}"),
        }
    }

    #[test]
    fn parses_completions() {
        let cli = Cli::try_parse_from(["keyit-relay", "completions", "bash"])
            .expect("completions should parse");
        match cli.command {
            Some(Command::Completions { shell }) => assert_eq!(shell, Shell::Bash),
            other => panic!("expected completions command, got {other:?}"),
        }
    }

    #[test]
    fn parses_version_command() {
        let cli = Cli::try_parse_from(["keyit-relay", "version"]).expect("version should parse");
        match cli.command {
            Some(Command::Version) => {}
            other => panic!("expected version command, got {other:?}"),
        }
    }

    #[test]
    fn runtime_config_uses_flags_before_env() {
        let previous_root = std::env::var_os("KEYIT_RELAY_ROOT");
        let from_env = std::env::temp_dir().join("keyit-relay-from-env");
        let from_flag = std::env::temp_dir().join("keyit-relay-from-flag");
        std::env::set_var("KEYIT_RELAY_ROOT", &from_env);

        let config = RelayRuntimeConfig::resolve(runtime_inputs(
            Some(from_flag.clone()),
            Some("127.0.0.1:9999".to_string()),
            Some("https://relay.example".to_string()),
        ))
        .expect("config");

        match previous_root {
            Some(value) => std::env::set_var("KEYIT_RELAY_ROOT", value),
            None => std::env::remove_var("KEYIT_RELAY_ROOT"),
        }

        assert_eq!(config.root, from_flag);
        assert_eq!(config.addr, "127.0.0.1:9999");
        assert_eq!(config.public_url.as_deref(), Some("https://relay.example"));
    }

    #[test]
    fn production_mode_requires_https_public_url() {
        let root = std::env::temp_dir().join("keyit-relay-production-test");
        let err = RelayRuntimeConfig::resolve(RelayRuntimeInputs {
            mode: Some("production".to_string()),
            ..runtime_inputs(Some(root.clone()), None, None)
        })
        .expect_err("production without public URL should fail");
        assert!(err.contains("public-url"));

        let err = RelayRuntimeConfig::resolve(RelayRuntimeInputs {
            mode: Some("production".to_string()),
            ..runtime_inputs(Some(root), None, Some("http://relay.example".to_string()))
        })
        .expect_err("production without HTTPS should fail");
        assert!(err.contains("https://"));
    }

    #[test]
    fn runtime_config_resolves_limits() {
        let config = RelayRuntimeConfig::resolve(RelayRuntimeInputs {
            max_body_bytes: Some(2048),
            max_request_payload_bytes: Some(1024),
            max_encrypted_payload_bytes: Some(1024),
            max_revisions_per_environment: Some(9),
            max_projects_per_device: Some(3),
            max_environments_per_project: Some(3),
            max_devices_per_project: Some(5),
            inactive_retention_days: Some(30),
            rate_limit_per_minute: Some(3),
            ..runtime_inputs(
                Some(std::env::temp_dir().join("keyit-relay-limits-test")),
                None,
                None,
            )
        })
        .expect("config");

        assert_eq!(config.server_options.http_limits.max_body_bytes, 2048);
        assert_eq!(config.store_policy.max_encrypted_payload_bytes, 1024);
        assert_eq!(config.store_policy.max_revisions_per_environment, 9);
        assert_eq!(config.store_policy.max_projects_per_device, 3);
        assert_eq!(config.store_policy.max_environments_per_project, 3);
        assert_eq!(config.store_policy.max_devices_per_project, 5);
        assert_eq!(config.server_options.inactive_retention_days, 30);
        assert_eq!(config.server_options.rate_limit_per_minute, 3);
    }

    #[test]
    fn runtime_config_defaults_new_limits_to_unlimited() {
        let config = RelayRuntimeConfig::resolve(runtime_inputs(
            Some(std::env::temp_dir().join("keyit-relay-defaults-test")),
            None,
            None,
        ))
        .expect("config");

        assert_eq!(config.store_policy.max_projects_per_device, 0);
        assert_eq!(config.store_policy.max_environments_per_project, 0);
        assert_eq!(config.store_policy.max_devices_per_project, 0);
        assert_eq!(config.server_options.inactive_retention_days, 0);
        assert_eq!(config.store_policy.max_revisions_per_environment, 10_000);
    }

    #[test]
    fn runtime_config_zero_disables_revisions_per_environment_cap() {
        let config = RelayRuntimeConfig::resolve(RelayRuntimeInputs {
            max_revisions_per_environment: Some(0),
            ..runtime_inputs(
                Some(std::env::temp_dir().join("keyit-relay-zero-test")),
                None,
                None,
            )
        })
        .expect("config");

        assert_eq!(config.store_policy.max_revisions_per_environment, 0);
    }

    #[test]
    fn runtime_config_rejects_invalid_hosted_limit_values() {
        let previous = std::env::var_os("KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE");
        std::env::set_var("KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE", "not-a-number");
        let result = RelayRuntimeConfig::resolve(runtime_inputs(
            Some(std::env::temp_dir().join("keyit-relay-invalid-env-test")),
            None,
            None,
        ));
        match previous {
            Some(value) => std::env::set_var("KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE", value),
            None => std::env::remove_var("KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE"),
        }
        let err = result.expect_err("invalid limit value should fail startup");
        assert!(err.contains("KEYIT_RELAY_MAX_PROJECTS_PER_DEVICE"));
    }

    fn runtime_inputs(
        root: Option<PathBuf>,
        addr: Option<String>,
        public_url: Option<String>,
    ) -> RelayRuntimeInputs {
        RelayRuntimeInputs {
            root,
            addr,
            public_url,
            mode: None,
            max_header_bytes: None,
            max_body_bytes: None,
            max_authorization_bytes: None,
            max_request_payload_bytes: None,
            max_revision_metadata_bytes: None,
            max_encrypted_payload_bytes: None,
            max_revisions_per_environment: None,
            max_projects_per_device: None,
            max_environments_per_project: None,
            max_devices_per_project: None,
            inactive_retention_days: None,
            rate_limit_per_minute: None,
        }
    }

    #[test]
    fn links_against_protocol_crate() {
        assert_eq!(
            keyit_protocol::ProtocolVersion::CURRENT,
            keyit_protocol::ProtocolVersion::V1
        );
    }
}
