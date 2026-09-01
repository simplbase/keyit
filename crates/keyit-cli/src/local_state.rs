//! Local environment status and key-level diff.
//!
//! Status/diff stay local-only: they inspect mapped dotenv files and,
//! when present, decrypt the latest local encrypted revision as the
//! baseline. They never print secret values.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use keyit_protocol::dotenv::DotenvDocument;
use keyit_protocol::ids::{EnvironmentId, ProjectId, RevisionId};

use crate::error::CliError;
use crate::keyit_dir;
use crate::revision;

/// Inputs to [`run_status`].
#[derive(Debug, Clone)]
pub struct StatusOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub environment: Option<String>,
}

/// Inputs to [`run_diff`].
#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub environment: Option<String>,
}

/// Local project status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusOutcome {
    pub project_id: ProjectId,
    pub environments: Vec<EnvironmentStatus>,
}

/// Local key-level diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffOutcome {
    pub project_id: ProjectId,
    pub environments: Vec<EnvironmentDiff>,
}

/// Status for one environment mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentStatus {
    pub environment_id: EnvironmentId,
    pub label: String,
    pub local_path: PathBuf,
    pub latest_revision_id: Option<RevisionId>,
    pub materialized_revision_id: Option<RevisionId>,
    pub state: LocalFileState,
}

/// Diff for one environment mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentDiff {
    pub environment_id: EnvironmentId,
    pub label: String,
    pub local_path: PathBuf,
    pub baseline_revision_id: Option<RevisionId>,
    pub state: DiffState,
}

/// Local dotenv file state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalFileState {
    Present { key_count: usize },
    Missing,
    Invalid { reason: String },
}

/// Key-level diff state for an environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffState {
    Missing,
    Invalid { reason: String },
    NoChanges,
    Keys(Vec<KeyDiff>),
}

/// A key-level change, never including the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDiff {
    pub key: String,
    pub status: KeyDiffStatus,
}

/// Key-level change status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDiffStatus {
    Added,
    Modified,
    Removed,
}

/// Runs local `keyit status`.
pub fn run_status(options: StatusOptions) -> Result<StatusOutcome, CliError> {
    let layout = revision::require_project(&options.project_root, &options.keyit_data_dir)?;
    let project = revision::load_project(&layout)?;

    let environments = revision::load_environment_refs(&layout, options.environment.as_deref())?
        .into_iter()
        .map(|env| {
            let local_path = revision::resolve_local_path(&options.project_root, &env.local_path);
            let latest_revision_id = keyit_dir::read_latest_local_revision(&env.layout)?
                .map(|bundle| bundle.revision.revision_id);
            let materialized_revision_id = keyit_dir::read_materialized_revision_id(&env.layout)?;
            let state = match read_dotenv(&local_path) {
                Ok(Some(doc)) => LocalFileState::Present {
                    key_count: doc.entries().len(),
                },
                Ok(None) => LocalFileState::Missing,
                Err(err) => LocalFileState::Invalid {
                    reason: err.to_string(),
                },
            };
            Ok(EnvironmentStatus {
                environment_id: env.record.environment_id,
                label: env.record.environment_label,
                local_path: env.local_path,
                latest_revision_id,
                materialized_revision_id,
                state,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;

    Ok(StatusOutcome {
        project_id: project.project_id,
        environments,
    })
}

/// Runs local `keyit diff`.
pub fn run_diff(options: DiffOptions) -> Result<DiffOutcome, CliError> {
    let layout = revision::require_project(&options.project_root, &options.keyit_data_dir)?;
    let project = revision::load_project(&layout)?;

    let environments = revision::load_environment_refs(&layout, options.environment.as_deref())?
        .into_iter()
        .map(|env| {
            let baseline = revision::decrypt_latest_revision(
                &options.keyit_data_dir,
                &project,
                &layout,
                &env.record,
                &env.layout,
            )?;
            let baseline_revision_id = baseline
                .as_ref()
                .map(|decrypted| decrypted.revision.revision_id.clone());
            let baseline_map = baseline
                .as_ref()
                .map(|decrypted| document_map(&decrypted.document))
                .unwrap_or_default();

            let local_path = revision::resolve_local_path(&options.project_root, &env.local_path);
            let state = match read_dotenv(&local_path) {
                Ok(Some(local_doc)) => {
                    let diffs = diff_documents(&baseline_map, &document_map(&local_doc));
                    if diffs.is_empty() {
                        DiffState::NoChanges
                    } else {
                        DiffState::Keys(diffs)
                    }
                }
                Ok(None) => DiffState::Missing,
                Err(err) => DiffState::Invalid {
                    reason: err.to_string(),
                },
            };
            Ok(EnvironmentDiff {
                environment_id: env.record.environment_id,
                label: env.record.environment_label,
                local_path: env.local_path,
                baseline_revision_id,
                state,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;

    Ok(DiffOutcome {
        project_id: project.project_id,
        environments,
    })
}

fn read_dotenv(path: &Path) -> Result<Option<DotenvDocument>, keyit_protocol::ProtocolError> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(keyit_protocol::ProtocolError::MalformedRecord {
                record: "dotenv/v1",
                reason: format!("failed to read \"{}\": {err}", path.display()),
            });
        }
    };
    DotenvDocument::parse(&content).map(Some)
}

fn document_map(document: &DotenvDocument) -> BTreeMap<String, String> {
    document
        .entries()
        .iter()
        .map(|entry| (entry.key().to_string(), entry.value().to_string()))
        .collect()
}

fn diff_documents(
    baseline: &BTreeMap<String, String>,
    local: &BTreeMap<String, String>,
) -> Vec<KeyDiff> {
    let keys: BTreeSet<&String> = baseline.keys().chain(local.keys()).collect();
    keys.into_iter()
        .filter_map(|key| match (baseline.get(key), local.get(key)) {
            (None, Some(_)) => Some(KeyDiff {
                key: key.clone(),
                status: KeyDiffStatus::Added,
            }),
            (Some(_), None) => Some(KeyDiff {
                key: key.clone(),
                status: KeyDiffStatus::Removed,
            }),
            (Some(a), Some(b)) if a != b => Some(KeyDiff {
                key: key.clone(),
                status: KeyDiffStatus::Modified,
            }),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::{run_env_add, EnvAddOptions};
    use crate::init::{run_init, InitOptions};
    use crate::revision::{run_push, PushOptions};
    use keyit_protocol::primitives::Timestamp;

    struct Fixture {
        _project_dir: tempfile::TempDir,
        _data_dir: tempfile::TempDir,
        project_root: PathBuf,
        keyit_data_dir: PathBuf,
    }

    fn fixture() -> Fixture {
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let data_dir = tempfile::tempdir().expect("data tempdir");
        let project_root = project_dir.path().to_path_buf();
        let keyit_data_dir = data_dir.path().to_path_buf();
        run_init(InitOptions {
            project_root: project_root.clone(),
            keyit_data_dir: keyit_data_dir.clone(),
            project_label: None,
            relay_url: Some("file://local-test-relay".to_string()),
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_400),
        })
        .expect("init");
        run_env_add(EnvAddOptions {
            project_root: project_root.clone(),
            keyit_data_dir: keyit_data_dir.clone(),
            environment_label: "development".to_string(),
            local_path: PathBuf::from(".env.local"),
            now: Timestamp::from_unix_seconds(1_755_878_500),
        })
        .expect("env add");
        Fixture {
            _project_dir: project_dir,
            _data_dir: data_dir,
            project_root,
            keyit_data_dir,
        }
    }

    #[test]
    fn status_reports_missing_file() {
        let fx = fixture();
        let outcome = run_status(StatusOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir,
            environment: None,
        })
        .expect("status");

        assert!(matches!(
            outcome.environments[0].state,
            LocalFileState::Missing
        ));
    }

    #[test]
    fn status_reports_present_file_without_values() {
        let fx = fixture();
        fs::write(
            fx.project_root.join(".env.local"),
            "API_KEY=secret\nLOG_LEVEL=debug\n",
        )
        .expect("write dotenv");

        let outcome = run_status(StatusOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir,
            environment: Some("development".to_string()),
        })
        .expect("status");

        assert_eq!(
            outcome.environments[0].state,
            LocalFileState::Present { key_count: 2 }
        );
    }

    #[test]
    fn diff_reports_keys_as_added_without_values_before_first_revision() {
        let fx = fixture();
        fs::write(
            fx.project_root.join(".env.local"),
            "API_KEY=super-secret\nLOG_LEVEL=debug\n",
        )
        .expect("write dotenv");

        let outcome = run_diff(DiffOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir,
            environment: None,
        })
        .expect("diff");

        let DiffState::Keys(keys) = &outcome.environments[0].state else {
            panic!("expected key diff");
        };
        assert_eq!(
            keys,
            &[
                KeyDiff {
                    key: "API_KEY".to_string(),
                    status: KeyDiffStatus::Added,
                },
                KeyDiff {
                    key: "LOG_LEVEL".to_string(),
                    status: KeyDiffStatus::Added,
                }
            ]
        );
    }

    #[test]
    fn diff_reports_modified_and_removed_keys_against_latest_revision() {
        let fx = fixture();
        fs::write(
            fx.project_root.join(".env.local"),
            "API_KEY=super-secret\nLOG_LEVEL=debug\n",
        )
        .expect("write dotenv");
        let pushed = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("push");

        fs::write(
            fx.project_root.join(".env.local"),
            "API_KEY=changed\nNEW_KEY=value\n",
        )
        .expect("write dotenv");

        let outcome = run_diff(DiffOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir,
            environment: Some("development".to_string()),
        })
        .expect("diff");

        assert_eq!(
            outcome.environments[0].baseline_revision_id,
            Some(pushed.revision_id)
        );
        let DiffState::Keys(keys) = &outcome.environments[0].state else {
            panic!("expected key diff");
        };
        assert_eq!(
            keys,
            &[
                KeyDiff {
                    key: "API_KEY".to_string(),
                    status: KeyDiffStatus::Modified,
                },
                KeyDiff {
                    key: "LOG_LEVEL".to_string(),
                    status: KeyDiffStatus::Removed,
                },
                KeyDiff {
                    key: "NEW_KEY".to_string(),
                    status: KeyDiffStatus::Added,
                }
            ]
        );
    }

    #[test]
    fn invalid_dotenv_is_reported_without_failing_status() {
        let fx = fixture();
        fs::write(fx.project_root.join(".env.local"), "1BAD=value\n").expect("write dotenv");

        let outcome = run_status(StatusOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir,
            environment: None,
        })
        .expect("status");

        assert!(matches!(
            outcome.environments[0].state,
            LocalFileState::Invalid { .. }
        ));
    }

    #[test]
    fn unknown_environment_selector_fails() {
        let fx = fixture();
        let err = run_status(StatusOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir,
            environment: Some("staging".to_string()),
        })
        .unwrap_err();

        assert!(matches!(err, CliError::EnvironmentNotFound { .. }));
    }

    #[test]
    fn status_requires_init() {
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let data_dir = tempfile::tempdir().expect("data tempdir");
        let err = run_status(StatusOptions {
            project_root: project_dir.path().to_path_buf(),
            keyit_data_dir: data_dir.path().to_path_buf(),
            environment: None,
        })
        .unwrap_err();

        assert!(matches!(err, CliError::NotInitialized { .. }));
    }
}
