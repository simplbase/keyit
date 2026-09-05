//! Keyit Relay storage primitives.
//!
//! This crate remains untrusted infrastructure: it stores signed/public
//! metadata and encrypted payload bytes, never plaintext dotenv values
//! or unwrapped DEKs. The filesystem store writes a deterministic v1
//! relay envelope that the HTTP API can serve directly.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::HEXLOWER;
use keyit_protocol::canonical::{self, CanonicalBytes, Canonicalize};
use keyit_protocol::ids::{DeviceId, EnvironmentId, InviteId, ProjectId, RevisionId};
use keyit_protocol::primitives::{
    HashBytes, NonceBytes, PublicKeyBytes, SignatureBytes, SigningPublicKeyBytes, Timestamp,
};
use keyit_protocol::records::{Approval, JoinRequest, ProjectGenesis, Revision, Revocation, Role};
use keyit_protocol::signing::{self, SigningKeyPair};
use keyit_protocol::version::ProtocolVersion;
use serde::Deserialize;

/// Errors produced by relay storage.
#[derive(Debug)]
pub enum RelayStoreError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    NotFound {
        path: PathBuf,
    },
    Malformed {
        path: PathBuf,
        reason: String,
    },
    Conflict {
        project_id: ProjectId,
        environment_id: EnvironmentId,
        expected_parent_revision_id: Option<RevisionId>,
        actual_latest_revision_id: Option<RevisionId>,
    },
    Replay {
        project_id: ProjectId,
        device_id: DeviceId,
    },
    Busy {
        path: PathBuf,
    },
    Quota {
        reason: String,
    },
    /// A join request tried to redeem an invite that has already
    /// produced `max_uses` distinct join requests.
    InviteExhausted {
        invite_id: InviteId,
        max_uses: u32,
    },
}

impl RelayStoreError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl std::fmt::Display for RelayStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "relay I/O error at \"{}\": {source}", path.display())
            }
            Self::NotFound { path } => {
                write!(f, "relay object was not found at \"{}\"", path.display())
            }
            Self::Malformed { path, reason } => {
                write!(
                    f,
                    "relay object at \"{}\" is malformed: {reason}",
                    path.display()
                )
            }
            Self::Conflict {
                project_id,
                environment_id,
                expected_parent_revision_id,
                actual_latest_revision_id,
            } => write!(
                f,
                "relay conflict for project {project_id} environment {environment_id}: expected parent {}, actual latest {}",
                expected_parent_revision_id
                    .as_ref()
                    .map(|id| id.as_str())
                    .unwrap_or("none"),
                actual_latest_revision_id
                    .as_ref()
                    .map(|id| id.as_str())
                    .unwrap_or("none")
            ),
            Self::Replay {
                project_id,
                device_id,
            } => write!(
                f,
                "relay replay protection rejected a repeated signed request for project {project_id} from device {device_id}"
            ),
            Self::Busy { path } => {
                write!(f, "relay object is busy at \"{}\"", path.display())
            }
            Self::Quota { reason } => write!(f, "relay storage quota rejected object: {reason}"),
            Self::InviteExhausted {
                invite_id,
                max_uses,
            } => write!(
                f,
                "invite {invite_id} has already reached its maximum of {max_uses} use(s)"
            ),
        }
    }
}

impl std::error::Error for RelayStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Filesystem-backed untrusted relay store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRelayStore {
    root: PathBuf,
    policy: StoragePolicy,
}

/// Filesystem storage limits enforced before writing relay objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePolicy {
    pub max_revision_metadata_bytes: usize,
    pub max_encrypted_payload_bytes: usize,
    /// Maximum revision objects per project/environment. `0` disables this cap.
    pub max_revisions_per_environment: usize,
    /// Maximum projects a single creator device may publish. `0` disables this cap.
    pub max_projects_per_device: usize,
    /// Maximum environments per project. `0` disables this cap.
    pub max_environments_per_project: usize,
    /// Maximum active devices per project. `0` disables this cap.
    pub max_devices_per_project: usize,
}

impl Default for StoragePolicy {
    fn default() -> Self {
        Self {
            max_revision_metadata_bytes: 256 * 1024,
            max_encrypted_payload_bytes: 1024 * 1024,
            max_revisions_per_environment: 10_000,
            max_projects_per_device: 0,
            max_environments_per_project: 0,
            max_devices_per_project: 0,
        }
    }
}

impl FileRelayStore {
    /// Creates a store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_policy(root, StoragePolicy::default())
    }

    /// Creates a store rooted at `root` with an explicit storage policy.
    pub fn with_policy(root: impl Into<PathBuf>, policy: StoragePolicy) -> Self {
        Self {
            root: root.into(),
            policy,
        }
    }

    /// Returns the store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the active filesystem storage policy.
    pub fn policy(&self) -> &StoragePolicy {
        &self.policy
    }

    /// Checks that the relay root can be created and written.
    pub fn check_ready(&self) -> Result<(), RelayStoreError> {
        fs::create_dir_all(&self.root).map_err(|e| RelayStoreError::io(&self.root, e))?;
        let probe = self.root.join(".readyz");
        atomic_write(&probe, b"ok")?;
        fs::remove_file(&probe).map_err(|e| RelayStoreError::io(&probe, e))
    }

    /// Returns a storage inventory suitable for backup/restore checks.
    pub fn inventory(&self) -> Result<RelayStorageInventory, RelayStoreError> {
        let mut inventory = RelayStorageInventory::default();
        if !self.root.exists() {
            return Ok(inventory);
        }
        collect_inventory(&self.root, &mut inventory)
    }

    /// Verifies that relay revision envelopes and sidecar payload files
    /// are internally consistent with their storage paths.
    pub fn verify_integrity(&self) -> Result<RelayIntegrityReport, RelayStoreError> {
        let inventory = self.inventory()?;
        let mut report = RelayIntegrityReport {
            inventory,
            malformed_revisions: Vec::new(),
            missing_payloads: Vec::new(),
            malformed_latest_pointers: Vec::new(),
        };
        let projects_dir = self.root.join("projects");
        if !projects_dir.exists() {
            return Ok(report);
        }
        for project in read_dir_paths(&projects_dir)? {
            let Some(project_name) = file_name_str(&project) else {
                continue;
            };
            let Ok(project_id) = ProjectId::parse(project_name) else {
                continue;
            };
            let environments_dir = project.join("environments");
            if !environments_dir.exists() {
                continue;
            }
            for environment in read_dir_paths(&environments_dir)? {
                let Some(environment_name) = file_name_str(&environment) else {
                    continue;
                };
                let Ok(environment_id) = EnvironmentId::parse(environment_name) else {
                    continue;
                };
                let layout = self.layout(&project_id, &environment_id);
                if layout.latest_file.exists()
                    && self
                        .latest_revision_id(&project_id, &environment_id)
                        .is_err()
                {
                    report
                        .malformed_latest_pointers
                        .push(layout.latest_file.clone());
                }
                if !layout.revisions_dir.exists() {
                    continue;
                }
                for revision_path in read_dir_paths(&layout.revisions_dir)? {
                    if !revision_path.is_file() {
                        continue;
                    }
                    let Some(stem) = revision_path.file_stem().and_then(|stem| stem.to_str())
                    else {
                        report.malformed_revisions.push(revision_path);
                        continue;
                    };
                    let Ok(revision_id) = RevisionId::parse(stem) else {
                        report.malformed_revisions.push(revision_path);
                        continue;
                    };
                    if self
                        .fetch_revision(&project_id, &environment_id, &revision_id)
                        .is_err()
                    {
                        report.malformed_revisions.push(revision_path.clone());
                    }
                    let payload_path = layout.payload_file(&revision_id);
                    if !payload_path.exists() {
                        report.missing_payloads.push(payload_path);
                    }
                }
            }
        }
        report.malformed_revisions.sort();
        report.missing_payloads.sort();
        report.malformed_latest_pointers.sort();
        Ok(report)
    }

    /// Removes expired nonce, temporary, and stale lock files.
    pub fn cleanup_storage(
        &self,
        policy: &CleanupPolicy,
        now: SystemTime,
    ) -> Result<CleanupReport, RelayStoreError> {
        let mut report = CleanupReport::default();
        if !self.root.exists() {
            return Ok(report);
        }
        cleanup_dir(&self.root, policy, now, &mut report)?;
        Ok(report)
    }

    /// Publishes one encrypted revision object.
    pub fn publish_revision(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        revision_id: &RevisionId,
        revision_metadata: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<PublishedRevision, RelayStoreError> {
        self.publish_revision_unchecked(
            project_id,
            environment_id,
            revision_id,
            None,
            revision_metadata,
            encrypted_payload,
        )
    }

    /// Publishes one encrypted revision if the relay's latest pointer
    /// still matches the caller's expected parent revision.
    pub fn publish_revision_checked(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        revision_id: &RevisionId,
        parent_revision_id: Option<&RevisionId>,
        revision_metadata: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<PublishedRevision, RelayStoreError> {
        self.validate_storage_policy(revision_metadata, encrypted_payload)?;
        let layout = self.prepare_environment_layout(project_id, environment_id)?;
        let _lock = PublishLock::acquire(&layout.lock_file)?;
        let actual_latest = self.latest_revision_id(project_id, environment_id)?;
        if actual_latest.as_ref() != parent_revision_id {
            return Err(RelayStoreError::Conflict {
                project_id: project_id.clone(),
                environment_id: environment_id.clone(),
                expected_parent_revision_id: parent_revision_id.cloned(),
                actual_latest_revision_id: actual_latest,
            });
        }
        self.write_locked_revision(LockedRevisionWrite {
            layout: &layout,
            project_id,
            environment_id,
            revision_id,
            parent_revision_id,
            revision_metadata,
            encrypted_payload,
        })
    }

    fn publish_revision_unchecked(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        revision_id: &RevisionId,
        parent_revision_id: Option<&RevisionId>,
        revision_metadata: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<PublishedRevision, RelayStoreError> {
        self.validate_storage_policy(revision_metadata, encrypted_payload)?;
        let layout = self.prepare_environment_layout(project_id, environment_id)?;
        let _lock = PublishLock::acquire(&layout.lock_file)?;
        self.write_locked_revision(LockedRevisionWrite {
            layout: &layout,
            project_id,
            environment_id,
            revision_id,
            parent_revision_id,
            revision_metadata,
            encrypted_payload,
        })
    }

    fn prepare_environment_layout(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
    ) -> Result<RelayLayout, RelayStoreError> {
        let layout = self.layout(project_id, environment_id);
        fs::create_dir_all(&layout.environment_dir)
            .map_err(|e| RelayStoreError::io(&layout.environment_dir, e))?;
        fs::create_dir_all(&layout.revisions_dir)
            .map_err(|e| RelayStoreError::io(&layout.revisions_dir, e))?;
        fs::create_dir_all(&layout.payloads_dir)
            .map_err(|e| RelayStoreError::io(&layout.payloads_dir, e))?;
        Ok(layout)
    }

    fn write_locked_revision(
        &self,
        write: LockedRevisionWrite<'_>,
    ) -> Result<PublishedRevision, RelayStoreError> {
        self.ensure_revision_quota(write.layout, write.revision_id)?;

        let revision_path = write.layout.revision_file(write.revision_id);
        let payload_path = write.layout.payload_file(write.revision_id);
        let envelope = RelayRevisionEnvelope {
            project_id: write.project_id.clone(),
            environment_id: write.environment_id.clone(),
            revision_id: write.revision_id.clone(),
            parent_revision_id: write.parent_revision_id.cloned(),
            revision_metadata: write.revision_metadata.to_vec(),
            encrypted_payload: write.encrypted_payload.to_vec(),
        };
        atomic_write(&revision_path, &envelope.encode())?;
        atomic_write(&payload_path, write.encrypted_payload)?;
        atomic_write(
            &write.layout.latest_file,
            write.revision_id.as_str().as_bytes(),
        )?;

        Ok(PublishedRevision {
            revision_id: write.revision_id.clone(),
            revision_path,
            payload_path,
        })
    }

    fn validate_storage_policy(
        &self,
        revision_metadata: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<(), RelayStoreError> {
        if revision_metadata.len() > self.policy.max_revision_metadata_bytes {
            return Err(RelayStoreError::Quota {
                reason: format!(
                    "revision metadata is {} bytes, limit is {}",
                    revision_metadata.len(),
                    self.policy.max_revision_metadata_bytes
                ),
            });
        }
        if encrypted_payload.len() > self.policy.max_encrypted_payload_bytes {
            return Err(RelayStoreError::Quota {
                reason: format!(
                    "encrypted payload is {} bytes, limit is {}",
                    encrypted_payload.len(),
                    self.policy.max_encrypted_payload_bytes
                ),
            });
        }
        Ok(())
    }

    fn ensure_revision_quota(
        &self,
        layout: &RelayLayout,
        revision_id: &RevisionId,
    ) -> Result<(), RelayStoreError> {
        if self.policy.max_revisions_per_environment == 0 {
            return Ok(());
        }
        if layout.revision_file(revision_id).exists() {
            return Ok(());
        }
        if !layout.revisions_dir.exists() {
            return Ok(());
        }
        let mut count = 0usize;
        for entry in fs::read_dir(&layout.revisions_dir)
            .map_err(|e| RelayStoreError::io(&layout.revisions_dir, e))?
        {
            let entry = entry.map_err(|e| RelayStoreError::io(&layout.revisions_dir, e))?;
            if entry.path().is_file() {
                count += 1;
            }
        }
        if count >= self.policy.max_revisions_per_environment {
            return Err(RelayStoreError::Quota {
                reason: format!(
                    "environment already has {count} revisions, limit is {}",
                    self.policy.max_revisions_per_environment
                ),
            });
        }
        Ok(())
    }

    /// Fetches the latest encrypted revision for an environment.
    pub fn fetch_latest_revision(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
    ) -> Result<Option<StoredRevision>, RelayStoreError> {
        let layout = self.layout(project_id, environment_id);
        if !layout.latest_file.exists() {
            return Ok(None);
        }

        let Some(revision_id) = self.latest_revision_id(project_id, environment_id)? else {
            return Ok(None);
        };
        self.fetch_revision(project_id, environment_id, &revision_id)
            .map(Some)
    }

    /// Fetches one encrypted revision by ID.
    pub fn fetch_revision(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        revision_id: &RevisionId,
    ) -> Result<StoredRevision, RelayStoreError> {
        let layout = self.layout(project_id, environment_id);
        let revision_path = layout.revision_file(revision_id);
        let payload_path = layout.payload_file(revision_id);

        let revision_bytes = fs::read(&revision_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RelayStoreError::NotFound {
                    path: revision_path.clone(),
                }
            } else {
                RelayStoreError::io(&revision_path, e)
            }
        })?;
        let envelope = RelayRevisionEnvelope::decode(&revision_bytes).map_err(|reason| {
            RelayStoreError::Malformed {
                path: revision_path.clone(),
                reason,
            }
        })?;
        if envelope.project_id != *project_id
            || envelope.environment_id != *environment_id
            || envelope.revision_id != *revision_id
        {
            return Err(RelayStoreError::Malformed {
                path: revision_path,
                reason: "relay envelope IDs do not match requested path".to_string(),
            });
        }

        Ok(StoredRevision {
            revision_id: revision_id.clone(),
            parent_revision_id: envelope.parent_revision_id,
            revision_metadata: envelope.revision_metadata,
            encrypted_payload: envelope.encrypted_payload,
            revision_path,
            payload_path,
        })
    }

    /// Publishes one signed access record as opaque bytes.
    pub fn publish_access_record(
        &self,
        project_id: &ProjectId,
        kind: AccessRecordKind,
        object_id: &str,
        record: &[u8],
    ) -> Result<PathBuf, RelayStoreError> {
        let path = self.access_record_file(project_id, kind, object_id);
        self.write_access_record(&path, record)
    }

    /// Publishes a project genesis record after enforcing the creator-device cap.
    pub fn publish_project_genesis_checked(
        &self,
        project_id: &ProjectId,
        record: &[u8],
    ) -> Result<PathBuf, RelayStoreError> {
        let path = self.access_record_file(
            project_id,
            AccessRecordKind::ProjectGenesis,
            project_id.as_str(),
        );
        if self.policy.max_projects_per_device == 0 || path.exists() {
            return self.write_access_record(&path, record);
        }
        let locks_dir = self.root.join("locks");
        fs::create_dir_all(&locks_dir).map_err(|e| RelayStoreError::io(&locks_dir, e))?;
        let _lock = PublishLock::acquire(&locks_dir.join("project-quota.lock"))?;
        if !path.exists() {
            let parsed = parse_relay_project_genesis_record(record).map_err(|reason| {
                RelayStoreError::Malformed {
                    path: path.clone(),
                    reason,
                }
            })?;
            let count = self.count_projects_for_creator(&parsed.creator_device_id)?;
            if count >= self.policy.max_projects_per_device {
                return Err(RelayStoreError::Quota {
                    reason: format!(
                        "device {} already has {count} project(s) on this relay, limit is {}",
                        parsed.creator_device_id, self.policy.max_projects_per_device
                    ),
                });
            }
        }
        self.write_access_record(&path, record)
    }

    /// Publishes an environment genesis record after enforcing the project cap.
    pub fn publish_environment_checked(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        record: &[u8],
    ) -> Result<PathBuf, RelayStoreError> {
        let path = self.access_record_file(
            project_id,
            AccessRecordKind::Environment,
            environment_id.as_str(),
        );
        if self.policy.max_environments_per_project == 0 || path.exists() {
            return self.write_access_record(&path, record);
        }
        let lock_path = self.project_quota_lock_path(project_id, "environment-quota.lock");
        let lock_dir = lock_path.parent().expect("lock path has parent");
        fs::create_dir_all(lock_dir).map_err(|e| RelayStoreError::io(lock_dir, e))?;
        let _lock = PublishLock::acquire(&lock_path)?;
        if !path.exists() {
            let dir = path.parent().expect("access record file has parent");
            let count = count_regular_files(dir)?;
            if count >= self.policy.max_environments_per_project {
                return Err(RelayStoreError::Quota {
                    reason: format!(
                        "project {project_id} already has {count} environment(s), limit is {}",
                        self.policy.max_environments_per_project
                    ),
                });
            }
        }
        self.write_access_record(&path, record)
    }

    /// Publishes an approval record after enforcing the active-device cap.
    pub fn publish_approval_checked(
        &self,
        project_id: &ProjectId,
        device_id: &DeviceId,
        record: &[u8],
    ) -> Result<PathBuf, RelayStoreError> {
        let path =
            self.access_record_file(project_id, AccessRecordKind::Approval, device_id.as_str());
        if self.policy.max_devices_per_project == 0 || path.exists() {
            return self.write_access_record(&path, record);
        }
        let lock_path = self.project_quota_lock_path(project_id, "device-quota.lock");
        let lock_dir = lock_path.parent().expect("lock path has parent");
        fs::create_dir_all(lock_dir).map_err(|e| RelayStoreError::io(lock_dir, e))?;
        let _lock = PublishLock::acquire(&lock_path)?;
        if !path.exists() {
            let approvals_dir = path.parent().expect("access record file has parent");
            let active = self.count_active_devices(project_id, approvals_dir)?;
            if active >= self.policy.max_devices_per_project {
                return Err(RelayStoreError::Quota {
                    reason: format!(
                        "project {project_id} already has {active} active device(s), limit is {}",
                        self.policy.max_devices_per_project
                    ),
                });
            }
        }
        self.write_access_record(&path, record)
    }

    fn write_access_record(&self, path: &Path, record: &[u8]) -> Result<PathBuf, RelayStoreError> {
        self.validate_access_record_policy(record)?;
        let parent = path.parent().expect("access record file has parent");
        fs::create_dir_all(parent).map_err(|e| RelayStoreError::io(parent, e))?;
        atomic_write(path, record)?;
        Ok(path.to_path_buf())
    }

    fn project_quota_lock_path(&self, project_id: &ProjectId, lock_name: &str) -> PathBuf {
        self.root
            .join("projects")
            .join(project_id.as_str())
            .join("access")
            .join(lock_name)
    }

    /// Counts project genesis records by creator device.
    fn count_projects_for_creator(
        &self,
        creator_device_id: &str,
    ) -> Result<usize, RelayStoreError> {
        let projects_dir = self.root.join("projects");
        if !projects_dir.exists() {
            return Ok(0);
        }
        let mut count = 0usize;
        for project_dir in read_dir_paths(&projects_dir)? {
            if !project_dir.is_dir() {
                continue;
            }
            let Some(other_project_id) = file_name_str(&project_dir) else {
                continue;
            };
            let record_path = project_dir
                .join("access")
                .join(AccessRecordKind::ProjectGenesis.as_str())
                .join(format!("{other_project_id}.keyit"));
            let Ok(bytes) = fs::read(&record_path) else {
                continue;
            };
            let Ok(other) = parse_relay_project_genesis_record(&bytes) else {
                continue;
            };
            if other.creator_device_id == creator_device_id {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Counts the creator plus approved devices without matching revocations.
    fn count_active_devices(
        &self,
        project_id: &ProjectId,
        approvals_dir: &Path,
    ) -> Result<usize, RelayStoreError> {
        let revocations_dir = self
            .root
            .join("projects")
            .join(project_id.as_str())
            .join("access")
            .join(AccessRecordKind::Revocation.as_str());
        let mut active = 1usize;
        if approvals_dir.exists() {
            for entry in read_dir_paths(approvals_dir)? {
                if !entry.is_file() {
                    continue;
                }
                let Some(stem) = entry.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if revocations_dir.join(format!("{stem}.keyit")).exists() {
                    continue;
                }
                active += 1;
            }
        }
        Ok(active)
    }

    /// Publishes a `JoinRequest` access record after enforcing the
    /// referenced invite's `max_uses`.
    ///
    /// Every other access record kind is stored as opaque bytes by
    /// [`publish_access_record`](Self::publish_access_record) — the
    /// relay never needs to understand a `ProjectGenesis`, `Approval`,
    /// or `Revocation` to store or serve it. A `JoinRequest` is
    /// different: `max_uses` is only meaningful if *something* counts
    /// how many join requests an invite has already produced, and the
    /// relay is the one participant that can see every device's
    /// attempt (a device only ever sees its own). So this method
    /// mirrors the pattern `parse_revision_metadata` already
    /// establishes for revision metadata: the relay independently
    /// decodes the small TOML fields it needs from the join
    /// request/invite bytes `keyit-cli` publishes, without depending on
    /// `keyit-cli` itself.
    ///
    /// Enforcement:
    ///
    /// - The referenced invite must already be stored on this relay,
    ///   active, and unexpired (an expired or revoked invite fails here
    ///   even if a modified/buggy client skipped the local check
    ///   `keyit-cli` normally does first).
    /// - Counts *distinct joining device IDs* that have already
    ///   published a join request for the same `invite_id` on this
    ///   project; a device re-publishing its own join request (e.g.
    ///   retrying after a network error) is idempotent and never
    ///   consumes an additional use — this is what keeps a replayed
    ///   invite bundle from bypassing the limit, since replaying it
    ///   from the *same* device just re-writes that device's own
    ///   record.
    /// - Once that count reaches the invite's `max_uses`, further join
    ///   requests from a *new* device are rejected with
    ///   [`RelayStoreError::InviteExhausted`] (surfaced over HTTP as
    ///   `409 Conflict`).
    ///
    /// The check-then-write is guarded by a per-invite
    /// [`PublishLock`] so two devices redeeming the last remaining use
    /// concurrently cannot both succeed.
    pub fn publish_join_request_checked(
        &self,
        project_id: &ProjectId,
        device_id: &DeviceId,
        record: &[u8],
        now_unix_seconds: u64,
    ) -> Result<PathBuf, RelayStoreError> {
        self.validate_access_record_policy(record)?;
        let join_request_path = self.access_record_file(
            project_id,
            AccessRecordKind::JoinRequest,
            device_id.as_str(),
        );
        let join_request_toml = parse_relay_join_request_record(record).map_err(|reason| {
            RelayStoreError::Malformed {
                path: join_request_path.clone(),
                reason,
            }
        })?;
        if join_request_toml.joining_device_id != device_id.as_str() {
            return Err(RelayStoreError::Malformed {
                path: join_request_path,
                reason: "join request joining_device_id does not match the request path"
                    .to_string(),
            });
        }
        let invite_id = InviteId::parse(&join_request_toml.invite_id).map_err(|e| {
            RelayStoreError::Malformed {
                path: join_request_path.clone(),
                reason: e.to_string(),
            }
        })?;

        let lock_dir = self.join_request_locks_dir(project_id);
        fs::create_dir_all(&lock_dir).map_err(|e| RelayStoreError::io(&lock_dir, e))?;
        let lock_path = lock_dir.join(format!("{}.lock", invite_id.as_str()));
        let _lock = PublishLock::acquire(&lock_path)?;

        let invite_path =
            self.access_record_file(project_id, AccessRecordKind::Invite, invite_id.as_str());
        let Some(invite_bytes) =
            self.fetch_access_record(project_id, AccessRecordKind::Invite, invite_id.as_str())?
        else {
            return Err(RelayStoreError::NotFound { path: invite_path });
        };
        let invite_toml = parse_relay_invite_record(&invite_bytes).map_err(|reason| {
            RelayStoreError::Malformed {
                path: invite_path.clone(),
                reason,
            }
        })?;
        if invite_toml.status != "active" {
            return Err(RelayStoreError::Malformed {
                path: invite_path,
                reason: format!("invite {invite_id} is not active"),
            });
        }
        if invite_toml.expires_at <= now_unix_seconds {
            return Err(RelayStoreError::Malformed {
                path: invite_path,
                reason: format!("invite {invite_id} has expired"),
            });
        }

        let already_used =
            self.count_join_requests_for_invite(project_id, &invite_id, device_id)?;
        if already_used >= invite_toml.max_uses as usize {
            return Err(RelayStoreError::InviteExhausted {
                invite_id,
                max_uses: invite_toml.max_uses,
            });
        }

        let parent = join_request_path
            .parent()
            .expect("access record file has parent");
        fs::create_dir_all(parent).map_err(|e| RelayStoreError::io(parent, e))?;
        atomic_write(&join_request_path, record)?;
        Ok(join_request_path)
    }

    fn join_request_locks_dir(&self, project_id: &ProjectId) -> PathBuf {
        self.root
            .join("projects")
            .join(project_id.as_str())
            .join("access")
            .join("join-request-locks")
    }

    /// Counts join requests already stored for `project_id` that decode
    /// to the same `invite_id`, excluding `excluding_device_id`'s own.
    /// A join request that fails to decode (should not happen for
    /// anything this relay itself accepted) is skipped rather than
    /// failing the whole count.
    fn count_join_requests_for_invite(
        &self,
        project_id: &ProjectId,
        invite_id: &InviteId,
        excluding_device_id: &DeviceId,
    ) -> Result<usize, RelayStoreError> {
        let dir = self
            .root
            .join("projects")
            .join(project_id.as_str())
            .join("access")
            .join(AccessRecordKind::JoinRequest.as_str());
        if !dir.exists() {
            return Ok(0);
        }
        let mut count = 0usize;
        for entry in fs::read_dir(&dir).map_err(|e| RelayStoreError::io(&dir, e))? {
            let entry = entry.map_err(|e| RelayStoreError::io(&dir, e))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if stem == excluding_device_id.as_str() {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(other) = parse_relay_join_request_record(&bytes) else {
                continue;
            };
            if other.invite_id == invite_id.as_str() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Fetches one signed access record by type and object ID.
    pub fn fetch_access_record(
        &self,
        project_id: &ProjectId,
        kind: AccessRecordKind,
        object_id: &str,
    ) -> Result<Option<Vec<u8>>, RelayStoreError> {
        let path = self.access_record_file(project_id, kind, object_id);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(RelayStoreError::io(path, source)),
        }
    }

    fn validate_access_record_policy(&self, record: &[u8]) -> Result<(), RelayStoreError> {
        if record.len() > self.policy.max_revision_metadata_bytes {
            return Err(RelayStoreError::Quota {
                reason: format!(
                    "access record is {} bytes, limit is {}",
                    record.len(),
                    self.policy.max_revision_metadata_bytes
                ),
            });
        }
        Ok(())
    }

    /// Returns the latest pointer without fetching the object body.
    pub fn latest_revision_id(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
    ) -> Result<Option<RevisionId>, RelayStoreError> {
        let layout = self.layout(project_id, environment_id);
        if !layout.latest_file.exists() {
            return Ok(None);
        }

        let raw_revision_id = fs::read_to_string(&layout.latest_file)
            .map_err(|e| RelayStoreError::io(&layout.latest_file, e))?;
        RevisionId::parse(raw_revision_id.trim())
            .map(Some)
            .map_err(|e| RelayStoreError::Malformed {
                path: layout.latest_file,
                reason: e.to_string(),
            })
    }

    /// Records a signed request nonce and rejects repeats for the same
    /// project/device pair.
    pub fn remember_request_nonce(
        &self,
        project_id: &ProjectId,
        device_id: &DeviceId,
        nonce: &[u8],
    ) -> Result<(), RelayStoreError> {
        let nonce_dir = self
            .root
            .join("projects")
            .join(project_id.as_str())
            .join("request-nonces")
            .join(device_id.as_str());
        fs::create_dir_all(&nonce_dir).map_err(|e| RelayStoreError::io(&nonce_dir, e))?;
        let nonce_file = nonce_dir.join(HEXLOWER.encode(nonce));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&nonce_file)
        {
            Ok(mut file) => file
                .write_all(b"seen")
                .map_err(|e| RelayStoreError::io(&nonce_file, e)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(RelayStoreError::Replay {
                    project_id: project_id.clone(),
                    device_id: device_id.clone(),
                })
            }
            Err(source) => Err(RelayStoreError::io(&nonce_file, source)),
        }
    }

    fn layout(&self, project_id: &ProjectId, environment_id: &EnvironmentId) -> RelayLayout {
        let environment_dir = self
            .root
            .join("projects")
            .join(project_id.as_str())
            .join("environments")
            .join(environment_id.as_str());
        RelayLayout {
            environment_dir: environment_dir.clone(),
            revisions_dir: environment_dir.join("revisions"),
            payloads_dir: environment_dir.join("payloads"),
            latest_file: environment_dir.join("latest"),
            lock_file: environment_dir.join("publish.lock"),
        }
    }

    fn access_record_file(
        &self,
        project_id: &ProjectId,
        kind: AccessRecordKind,
        object_id: &str,
    ) -> PathBuf {
        self.root
            .join("projects")
            .join(project_id.as_str())
            .join("access")
            .join(kind.as_str())
            .join(format!("{object_id}.keyit"))
    }
}

/// Signed access record families stored by the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRecordKind {
    ProjectGenesis,
    MembershipGenesis,
    Environment,
    Invite,
    JoinRequest,
    Approval,
    Revocation,
}

impl AccessRecordKind {
    fn parse(segment: &str) -> Option<Self> {
        match segment {
            "project-genesis" => Some(Self::ProjectGenesis),
            "membership-genesis" => Some(Self::MembershipGenesis),
            "environments" => Some(Self::Environment),
            "invites" => Some(Self::Invite),
            "join-requests" => Some(Self::JoinRequest),
            "approvals" => Some(Self::Approval),
            "revocations" => Some(Self::Revocation),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProjectGenesis => "project-genesis",
            Self::MembershipGenesis => "membership-genesis",
            Self::Environment => "environments",
            Self::Invite => "invites",
            Self::JoinRequest => "join-requests",
            Self::Approval => "approvals",
            Self::Revocation => "revocations",
        }
    }

    fn validate_object_id(self, value: &str) -> Result<(), ApiError> {
        match self {
            Self::ProjectGenesis => {
                ProjectId::parse(value).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            }
            Self::MembershipGenesis => {
                if value != "genesis" {
                    return Err(ApiError::BadRequest(
                        "membership genesis object id must be genesis".to_string(),
                    ));
                }
            }
            Self::Environment => {
                EnvironmentId::parse(value).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            }
            Self::Invite => {
                InviteId::parse(value).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            }
            Self::JoinRequest | Self::Approval | Self::Revocation => {
                DeviceId::parse(value).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            }
        }
        Ok(())
    }
}

/// Counts and byte totals for relay storage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayStorageInventory {
    pub project_count: usize,
    pub environment_count: usize,
    pub revision_count: usize,
    pub payload_count: usize,
    pub nonce_count: usize,
    pub total_bytes: u64,
}

/// Result of validating stored relay objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayIntegrityReport {
    pub inventory: RelayStorageInventory,
    pub malformed_revisions: Vec<PathBuf>,
    pub missing_payloads: Vec<PathBuf>,
    pub malformed_latest_pointers: Vec<PathBuf>,
}

impl RelayIntegrityReport {
    pub fn is_clean(&self) -> bool {
        self.malformed_revisions.is_empty()
            && self.missing_payloads.is_empty()
            && self.malformed_latest_pointers.is_empty()
    }
}

/// Retention policy for relay maintenance cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPolicy {
    pub nonce_ttl: Duration,
    pub temp_file_ttl: Duration,
    pub stale_lock_ttl: Duration,
    pub dry_run: bool,
}

impl Default for CleanupPolicy {
    fn default() -> Self {
        Self {
            nonce_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            temp_file_ttl: Duration::from_secs(24 * 60 * 60),
            stale_lock_ttl: Duration::from_secs(15 * 60),
            dry_run: false,
        }
    }
}

/// Cleanup operation summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub nonce_files_removed: usize,
    pub temp_files_removed: usize,
    pub lock_files_removed: usize,
    pub bytes_removed: u64,
}

fn collect_inventory(
    path: &Path,
    inventory: &mut RelayStorageInventory,
) -> Result<RelayStorageInventory, RelayStoreError> {
    if path.is_file() {
        let metadata = fs::metadata(path).map_err(|e| RelayStoreError::io(path, e))?;
        inventory.total_bytes += metadata.len();
        if path.extension().and_then(|extension| extension.to_str()) == Some("keyit") {
            inventory.revision_count += 1;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("payload") {
            inventory.payload_count += 1;
        } else if is_nonce_file(path) {
            inventory.nonce_count += 1;
        }
        return Ok(inventory.clone());
    }

    if path.ends_with("projects") {
        inventory.project_count += read_dir_paths(path)?
            .into_iter()
            .filter(|entry| entry.is_dir())
            .count();
    }
    if path.ends_with("environments") {
        inventory.environment_count += read_dir_paths(path)?
            .into_iter()
            .filter(|entry| entry.is_dir())
            .count();
    }
    for entry in read_dir_paths(path)? {
        collect_inventory(&entry, inventory)?;
    }
    Ok(inventory.clone())
}

fn cleanup_dir(
    path: &Path,
    policy: &CleanupPolicy,
    now: SystemTime,
    report: &mut CleanupReport,
) -> Result<(), RelayStoreError> {
    for entry in read_dir_paths(path)? {
        if entry.is_dir() {
            cleanup_dir(&entry, policy, now, report)?;
            continue;
        }
        let Some(kind) = cleanup_kind(&entry) else {
            continue;
        };
        let metadata = fs::metadata(&entry).map_err(|e| RelayStoreError::io(&entry, e))?;
        let modified = metadata
            .modified()
            .map_err(|e| RelayStoreError::io(&entry, e))?;
        let age = now
            .duration_since(modified)
            .unwrap_or_else(|_| Duration::from_secs(0));
        if age < kind.ttl(policy) {
            continue;
        }
        match kind {
            CleanupKind::Nonce => report.nonce_files_removed += 1,
            CleanupKind::Temp => report.temp_files_removed += 1,
            CleanupKind::Lock => report.lock_files_removed += 1,
        }
        report.bytes_removed += metadata.len();
        if !policy.dry_run {
            fs::remove_file(&entry).map_err(|e| RelayStoreError::io(&entry, e))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupKind {
    Nonce,
    Temp,
    Lock,
}

impl CleanupKind {
    fn ttl(self, policy: &CleanupPolicy) -> Duration {
        match self {
            Self::Nonce => policy.nonce_ttl,
            Self::Temp => policy.temp_file_ttl,
            Self::Lock => policy.stale_lock_ttl,
        }
    }
}

fn cleanup_kind(path: &Path) -> Option<CleanupKind> {
    let name = path.file_name().and_then(|name| name.to_str())?;
    if is_nonce_file(path) {
        Some(CleanupKind::Nonce)
    } else if name.starts_with('.') && name.ends_with(".tmp") {
        Some(CleanupKind::Temp)
    } else if name == "publish.lock" {
        Some(CleanupKind::Lock)
    } else {
        None
    }
}

fn is_nonce_file(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "request-nonces")
}

fn read_dir_paths(path: &Path) -> Result<Vec<PathBuf>, RelayStoreError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| RelayStoreError::io(path, e))? {
        paths.push(entry.map_err(|e| RelayStoreError::io(path, e))?.path());
    }
    paths.sort();
    Ok(paths)
}

fn count_regular_files(dir: &Path) -> Result<usize, RelayStoreError> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in fs::read_dir(dir).map_err(|e| RelayStoreError::io(dir, e))? {
        let entry = entry.map_err(|e| RelayStoreError::io(dir, e))?;
        if entry.path().is_file() {
            count += 1;
        }
    }
    Ok(count)
}

fn file_name_str(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

struct PublishLock {
    path: PathBuf,
}

impl PublishLock {
    fn acquire(path: &Path) -> Result<Self, RelayStoreError> {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                file.write_all(b"locked")
                    .map_err(|e| RelayStoreError::io(path, e))?;
                Ok(Self {
                    path: path.to_path_buf(),
                })
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(RelayStoreError::Busy {
                    path: path.to_path_buf(),
                })
            }
            Err(source) => Err(RelayStoreError::io(path, source)),
        }
    }
}

impl Drop for PublishLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct LockedRevisionWrite<'a> {
    layout: &'a RelayLayout,
    project_id: &'a ProjectId,
    environment_id: &'a EnvironmentId,
    revision_id: &'a RevisionId,
    parent_revision_id: Option<&'a RevisionId>,
    revision_metadata: &'a [u8],
    encrypted_payload: &'a [u8],
}

/// The relay's own clock, in Unix seconds. Used only for the
/// server-side invite-expiry defense-in-depth check in
/// [`FileRelayStore::publish_join_request_checked`] — `keyit-cli`
/// always checks expiry against its own clock first, so this is a
/// backstop against a modified or buggy client, not the primary check.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RelayStoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| RelayStoreError::io(parent, e))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("relay-object"),
        stamp
    ));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| RelayStoreError::io(&tmp_path, e))?;
        file.write_all(bytes)
            .map_err(|e| RelayStoreError::io(&tmp_path, e))?;
        file.sync_all()
            .map_err(|e| RelayStoreError::io(&tmp_path, e))?;
    }
    fs::rename(&tmp_path, path).map_err(|e| RelayStoreError::io(path, e))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedRevision {
    pub revision_id: RevisionId,
    pub revision_path: PathBuf,
    pub payload_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRevision {
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub revision_metadata: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub revision_path: PathBuf,
    pub payload_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Put,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub body: Vec<u8>,
    pub peer_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// In-process relay counters rendered by `/metrics`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayMetrics {
    pub requests_total: u64,
    pub request_bytes_total: u64,
    pub response_bytes_total: u64,
    pub published_revisions_total: u64,
    pub fetched_revisions_total: u64,
    pub rate_limited_total: u64,
    pub responses_by_status: BTreeMap<u16, u64>,
}

impl RelayMetrics {
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "keyit_relay_requests_total {}\n",
            self.requests_total
        ));
        out.push_str(&format!(
            "keyit_relay_request_bytes_total {}\n",
            self.request_bytes_total
        ));
        out.push_str(&format!(
            "keyit_relay_response_bytes_total {}\n",
            self.response_bytes_total
        ));
        out.push_str(&format!(
            "keyit_relay_published_revisions_total {}\n",
            self.published_revisions_total
        ));
        out.push_str(&format!(
            "keyit_relay_fetched_revisions_total {}\n",
            self.fetched_revisions_total
        ));
        out.push_str(&format!(
            "keyit_relay_rate_limited_total {}\n",
            self.rate_limited_total
        ));
        for (status, count) in &self.responses_by_status {
            out.push_str(&format!(
                "keyit_relay_responses_total{{status=\"{}\"}} {}\n",
                status, count
            ));
        }
        out
    }

    fn record_response(
        &mut self,
        method: HttpMethod,
        path: &str,
        request_bytes: usize,
        response: &RelayHttpResponse,
        rate_limited: bool,
    ) {
        self.requests_total += 1;
        self.request_bytes_total += request_bytes as u64;
        self.response_bytes_total += response.body.len() as u64;
        *self.responses_by_status.entry(response.status).or_insert(0) += 1;
        if response.status == 201 && method == HttpMethod::Put {
            self.published_revisions_total += 1;
        }
        if response.status == 200 && method == HttpMethod::Get && path.contains("/revisions/") {
            self.fetched_revisions_total += 1;
        }
        if rate_limited {
            self.rate_limited_total += 1;
        }
    }
}

/// HTTP-layer limits enforced before expensive parsing/storage work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHttpLimits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_authorization_bytes: usize,
    pub max_request_payload_bytes: usize,
}

impl Default for RelayHttpLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 2 * 1024 * 1024,
            max_authorization_bytes: 512 * 1024,
            max_request_payload_bytes: 1536 * 1024,
        }
    }
}

/// Blocking server options for production deployment hardening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServerOptions {
    pub http_limits: RelayHttpLimits,
    pub rate_limit_per_minute: u32,
    /// Days of inactivity before a project is eligible for cleanup. `0` disables retention.
    pub inactive_retention_days: u32,
}

impl Default for RelayServerOptions {
    fn default() -> Self {
        Self {
            http_limits: RelayHttpLimits::default(),
            rate_limit_per_minute: 120,
            inactive_retention_days: 0,
        }
    }
}

/// Handles the concrete Keyit relay HTTP API route set.
///
/// Supported routes:
///
/// - `PUT /v1/projects/<kvp>/environments/<kve>/revisions/<kvr>`
/// - `GET /v1/projects/<kvp>/environments/<kve>/revisions/latest`
/// - `GET /v1/projects/<kvp>/environments/<kve>/revisions/<kvr>`
pub fn handle_http_request(store: &FileRelayStore, request: RelayHttpRequest) -> RelayHttpResponse {
    handle_http_request_with_limits(store, request, &RelayHttpLimits::default())
}

/// Handles one Keyit relay HTTP request with explicit HTTP limits.
pub fn handle_http_request_with_limits(
    store: &FileRelayStore,
    request: RelayHttpRequest,
    limits: &RelayHttpLimits,
) -> RelayHttpResponse {
    match handle_http_request_inner(store, request, limits) {
        Ok(response) => response,
        Err(ApiError::BadRequest(message)) => RelayHttpResponse {
            status: 400,
            body: message.into_bytes(),
        },
        Err(ApiError::PayloadTooLarge(message)) => RelayHttpResponse {
            status: 413,
            body: message.into_bytes(),
        },
        Err(ApiError::NotFound) => RelayHttpResponse {
            status: 404,
            body: b"not found".to_vec(),
        },
        Err(ApiError::Conflict(message)) => RelayHttpResponse {
            status: 409,
            body: message.into_bytes(),
        },
        Err(ApiError::Unauthorized(message)) => RelayHttpResponse {
            status: 401,
            body: message.into_bytes(),
        },
        Err(ApiError::Forbidden(message)) => RelayHttpResponse {
            status: 403,
            body: message.into_bytes(),
        },
        Err(ApiError::ServiceUnavailable(message)) => RelayHttpResponse {
            status: 503,
            body: message.into_bytes(),
        },
        Err(ApiError::Internal(message)) => RelayHttpResponse {
            status: 500,
            body: message.into_bytes(),
        },
    }
}

/// Handles one request and records in-process metrics.
pub fn handle_http_request_observed(
    store: &FileRelayStore,
    request: RelayHttpRequest,
    limits: &RelayHttpLimits,
    metrics: &mut RelayMetrics,
) -> RelayHttpResponse {
    let method = request.method;
    let path = request.path.clone();
    let request_bytes = request.body.len();
    let response = if method == HttpMethod::Get && path == "/metrics" {
        RelayHttpResponse {
            status: 200,
            body: metrics.render_text().into_bytes(),
        }
    } else {
        handle_http_request_with_limits(store, request, limits)
    };
    metrics.record_response(method, &path, request_bytes, &response, false);
    eprintln!(
        "event=relay_request method={} path={} status={} request_bytes={} response_bytes={}",
        method.as_str(),
        path,
        response.status,
        request_bytes,
        response.body.len()
    );
    response
}

/// Serves the v1 relay HTTP API with a small blocking HTTP/1.1 loop.
pub fn serve_http_blocking(
    store: FileRelayStore,
    addr: impl ToSocketAddrs,
) -> Result<(), std::io::Error> {
    serve_http_blocking_with_options(store, addr, RelayServerOptions::default())
}

/// Serves the v1 relay HTTP API with explicit production-hardening options.
pub fn serve_http_blocking_with_options(
    store: FileRelayStore,
    addr: impl ToSocketAddrs,
    options: RelayServerOptions,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(addr)?;
    let mut rate_limiter = RelayRateLimiter::new(options.rate_limit_per_minute);
    let mut metrics = RelayMetrics::default();
    for stream in listener.incoming() {
        let mut stream = stream?;
        let peer_addr = stream.peer_addr().ok();
        let response = match read_http_request_with_limits(&mut stream, &options.http_limits) {
            Ok(mut request) => {
                request.peer_addr = peer_addr;
                if let Some(peer_addr) = request.peer_addr {
                    if !rate_limiter.allow(peer_addr) {
                        let response = RelayHttpResponse {
                            status: 429,
                            body: b"rate limit exceeded".to_vec(),
                        };
                        metrics.record_response(
                            request.method,
                            &request.path,
                            request.body.len(),
                            &response,
                            true,
                        );
                        eprintln!(
                            "event=relay_request method={} path={} status={} request_bytes={} response_bytes={} rate_limited=true",
                            request.method.as_str(),
                            request.path,
                            response.status,
                            request.body.len(),
                            response.body.len()
                        );
                        response
                    } else {
                        handle_http_request_observed(
                            &store,
                            request,
                            &options.http_limits,
                            &mut metrics,
                        )
                    }
                } else {
                    handle_http_request_observed(
                        &store,
                        request,
                        &options.http_limits,
                        &mut metrics,
                    )
                }
            }
            Err(message) => RelayHttpResponse {
                status: 400,
                body: message.into_bytes(),
            },
        };
        write_http_response(&mut stream, response)?;
    }
    Ok(())
}

#[derive(Debug)]
struct RelayRateLimiter {
    max_per_minute: u32,
    buckets: HashMap<String, RateBucket>,
}

impl RelayRateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            buckets: HashMap::new(),
        }
    }

    fn allow(&mut self, peer_addr: SocketAddr) -> bool {
        if self.max_per_minute == 0 {
            return true;
        }
        let now = Instant::now();
        let key = peer_addr.ip().to_string();
        let bucket = self.buckets.entry(key).or_insert(RateBucket {
            window_started_at: now,
            count: 0,
        });
        if now.duration_since(bucket.window_started_at) >= Duration::from_secs(60) {
            bucket.window_started_at = now;
            bucket.count = 0;
        }
        if bucket.count >= self.max_per_minute {
            return false;
        }
        bucket.count += 1;
        true
    }
}

#[derive(Debug)]
struct RateBucket {
    window_started_at: Instant,
    count: u32,
}

fn handle_http_request_inner(
    store: &FileRelayStore,
    request: RelayHttpRequest,
    limits: &RelayHttpLimits,
) -> Result<RelayHttpResponse, ApiError> {
    if request.method == HttpMethod::Get && request.path == "/healthz" {
        return Ok(RelayHttpResponse {
            status: 200,
            body: b"ok\n".to_vec(),
        });
    }
    if request.method == HttpMethod::Get && request.path == "/readyz" {
        store.check_ready().map_err(ApiError::from_store)?;
        return Ok(RelayHttpResponse {
            status: 200,
            body: b"ready\n".to_vec(),
        });
    }
    if request.body.len() > limits.max_body_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "request body is {} bytes, limit is {}",
            request.body.len(),
            limits.max_body_bytes
        )));
    }

    if let Some(route) = parse_access_route(&request.path)? {
        route.kind.validate_object_id(&route.object_id)?;
        return match request.method {
            HttpMethod::Put if route.kind == AccessRecordKind::JoinRequest => {
                let device_id = DeviceId::parse(&route.object_id)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
                store
                    .publish_join_request_checked(
                        &route.project_id,
                        &device_id,
                        &request.body,
                        unix_now(),
                    )
                    .map_err(ApiError::from_store)?;
                Ok(RelayHttpResponse {
                    status: 201,
                    body: Vec::new(),
                })
            }
            HttpMethod::Put if route.kind == AccessRecordKind::ProjectGenesis => {
                store
                    .publish_project_genesis_checked(&route.project_id, &request.body)
                    .map_err(ApiError::from_store)?;
                Ok(RelayHttpResponse {
                    status: 201,
                    body: Vec::new(),
                })
            }
            HttpMethod::Put if route.kind == AccessRecordKind::Environment => {
                let environment_id = EnvironmentId::parse(&route.object_id)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
                store
                    .publish_environment_checked(&route.project_id, &environment_id, &request.body)
                    .map_err(ApiError::from_store)?;
                Ok(RelayHttpResponse {
                    status: 201,
                    body: Vec::new(),
                })
            }
            HttpMethod::Put if route.kind == AccessRecordKind::Approval => {
                let device_id = DeviceId::parse(&route.object_id)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
                store
                    .publish_approval_checked(&route.project_id, &device_id, &request.body)
                    .map_err(ApiError::from_store)?;
                Ok(RelayHttpResponse {
                    status: 201,
                    body: Vec::new(),
                })
            }
            HttpMethod::Put => {
                store
                    .publish_access_record(
                        &route.project_id,
                        route.kind,
                        &route.object_id,
                        &request.body,
                    )
                    .map_err(ApiError::from_store)?;
                Ok(RelayHttpResponse {
                    status: 201,
                    body: Vec::new(),
                })
            }
            HttpMethod::Get => {
                let Some(bytes) = store
                    .fetch_access_record(&route.project_id, route.kind, &route.object_id)
                    .map_err(ApiError::from_store)?
                else {
                    return Err(ApiError::NotFound);
                };
                Ok(RelayHttpResponse {
                    status: 200,
                    body: bytes,
                })
            }
        };
    }

    let route = parse_revision_route(&request.path)?;
    let signed_request =
        RelaySignedRequestEnvelope::decode(&request.body).map_err(ApiError::BadRequest)?;
    validate_signed_request_limits(&signed_request, limits)?;
    let access_state = signed_request
        .verify(&request.method, &request.path, &route.environment_id)
        .map_err(ApiError::Unauthorized)?;
    store
        .remember_request_nonce(
            &route.project_id,
            &signed_request.auth.device_id,
            &signed_request.auth.nonce,
        )
        .map_err(ApiError::from_store)?;

    match (request.method, route.revision_selector.as_str()) {
        (HttpMethod::Put, "latest") => Err(ApiError::BadRequest(
            "cannot publish to the latest alias".to_string(),
        )),
        (HttpMethod::Put, _) => {
            let revision_id = RevisionId::parse(&route.revision_selector)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let envelope = RelayRevisionEnvelope::decode(&signed_request.payload)
                .map_err(ApiError::BadRequest)?;
            if envelope.project_id != route.project_id
                || envelope.environment_id != route.environment_id
                || envelope.revision_id != revision_id
            {
                return Err(ApiError::BadRequest(
                    "route IDs do not match relay envelope IDs".to_string(),
                ));
            }
            validate_publish_authorization(
                &access_state,
                &signed_request.auth.device_id,
                &envelope,
            )
            .map_err(ApiError::Forbidden)?;
            store
                .publish_revision_checked(
                    &envelope.project_id,
                    &envelope.environment_id,
                    &envelope.revision_id,
                    envelope.parent_revision_id.as_ref(),
                    &envelope.revision_metadata,
                    &envelope.encrypted_payload,
                )
                .map_err(ApiError::from_store)?;
            Ok(RelayHttpResponse {
                status: 201,
                body: Vec::new(),
            })
        }
        (HttpMethod::Get, "latest") => {
            let Some(stored) = store
                .fetch_latest_revision(&route.project_id, &route.environment_id)
                .map_err(ApiError::from_store)?
            else {
                return Err(ApiError::NotFound);
            };
            Ok(RelayHttpResponse {
                status: 200,
                body: stored
                    .to_envelope(&route.project_id, &route.environment_id)
                    .encode(),
            })
        }
        (HttpMethod::Get, _) => {
            let revision_id = RevisionId::parse(&route.revision_selector)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let stored = store
                .fetch_revision(&route.project_id, &route.environment_id, &revision_id)
                .map_err(ApiError::from_store)?;
            Ok(RelayHttpResponse {
                status: 200,
                body: stored
                    .to_envelope(&route.project_id, &route.environment_id)
                    .encode(),
            })
        }
    }
}

fn validate_signed_request_limits(
    signed_request: &RelaySignedRequestEnvelope,
    limits: &RelayHttpLimits,
) -> Result<(), ApiError> {
    let authorization_len = signed_request.authorization.encode().len();
    if authorization_len > limits.max_authorization_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "authorization envelope is {authorization_len} bytes, limit is {}",
            limits.max_authorization_bytes
        )));
    }
    if signed_request.payload.len() > limits.max_request_payload_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "signed request payload is {} bytes, limit is {}",
            signed_request.payload.len(),
            limits.max_request_payload_bytes
        )));
    }
    Ok(())
}

fn read_http_request_with_limits(
    stream: &mut impl Read,
    limits: &RelayHttpLimits,
) -> Result<RelayHttpRequest, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > limits.max_header_bytes {
            return Err(format!(
                "HTTP headers are {} bytes, limit is {}",
                buffer.len(),
                limits.max_header_bytes
            ));
        }
    }
    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "HTTP header terminator not found".to_string())?
        + 4;
    let headers = std::str::from_utf8(&buffer[..header_end])
        .map_err(|e| format!("HTTP headers are not UTF-8: {e}"))?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = match request_parts.next() {
        Some("GET") => HttpMethod::Get,
        Some("PUT") => HttpMethod::Put,
        Some(other) => return Err(format!("unsupported HTTP method {other}")),
        None => return Err("missing HTTP method".to_string()),
    };
    let path = request_parts
        .next()
        .ok_or_else(|| "missing HTTP path".to_string())?
        .to_string();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|e| format!("invalid Content-Length: {e}"))?
        .unwrap_or(0);

    let mut body = buffer[header_end..].to_vec();
    if content_length > limits.max_body_bytes {
        return Err(format!(
            "HTTP body is {content_length} bytes, limit is {}",
            limits.max_body_bytes
        ));
    }
    while body.len() < content_length {
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("HTTP body ended before Content-Length".to_string());
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok(RelayHttpRequest {
        method,
        path,
        body,
        peer_addr: None,
    })
}

fn write_http_response(
    stream: &mut impl Write,
    response: RelayHttpResponse,
) -> Result<(), std::io::Error> {
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n",
        response.status,
        reason,
        response.body.len()
    )?;
    stream.write_all(&response.body)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevisionRoute {
    project_id: ProjectId,
    environment_id: EnvironmentId,
    revision_selector: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccessRoute {
    project_id: ProjectId,
    kind: AccessRecordKind,
    object_id: String,
}

fn parse_access_route(path: &str) -> Result<Option<AccessRoute>, ApiError> {
    let path = path.split_once('?').map(|(path, _)| path).unwrap_or(path);
    let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
    if segments.len() < 4
        || segments[0] != "v1"
        || segments[1] != "projects"
        || segments[3] != "access"
    {
        return Ok(None);
    }
    if segments.len() != 6 {
        return Err(ApiError::BadRequest(
            "unknown relay access route".to_string(),
        ));
    }
    let kind = AccessRecordKind::parse(segments[4])
        .ok_or_else(|| ApiError::BadRequest("unknown relay access record kind".to_string()))?;
    Ok(Some(AccessRoute {
        project_id: ProjectId::parse(segments[2])
            .map_err(|e| ApiError::BadRequest(e.to_string()))?,
        kind,
        object_id: segments[5].to_string(),
    }))
}

fn parse_revision_route(path: &str) -> Result<RevisionRoute, ApiError> {
    let path = path.split_once('?').map(|(path, _)| path).unwrap_or(path);
    let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
    if segments.len() != 7
        || segments[0] != "v1"
        || segments[1] != "projects"
        || segments[3] != "environments"
        || segments[5] != "revisions"
    {
        return Err(ApiError::BadRequest("unknown relay route".to_string()));
    }
    Ok(RevisionRoute {
        project_id: ProjectId::parse(segments[2])
            .map_err(|e| ApiError::BadRequest(e.to_string()))?,
        environment_id: EnvironmentId::parse(segments[4])
            .map_err(|e| ApiError::BadRequest(e.to_string()))?,
        revision_selector: segments[6].to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApiError {
    BadRequest(String),
    PayloadTooLarge(String),
    NotFound,
    Conflict(String),
    Unauthorized(String),
    Forbidden(String),
    ServiceUnavailable(String),
    Internal(String),
}

impl ApiError {
    fn from_store(err: RelayStoreError) -> Self {
        match err {
            RelayStoreError::NotFound { .. } => Self::NotFound,
            RelayStoreError::Malformed { reason, .. } => Self::BadRequest(reason),
            RelayStoreError::Conflict { .. } => Self::Conflict(err.to_string()),
            RelayStoreError::Replay { .. } => Self::Unauthorized(err.to_string()),
            RelayStoreError::Busy { .. } => Self::ServiceUnavailable(err.to_string()),
            RelayStoreError::Quota { .. } => Self::PayloadTooLarge(err.to_string()),
            RelayStoreError::InviteExhausted { .. } => Self::Conflict(err.to_string()),
            RelayStoreError::Io { .. } => Self::Internal(err.to_string()),
        }
    }
}

impl StoredRevision {
    pub fn to_envelope(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
    ) -> RelayRevisionEnvelope {
        RelayRevisionEnvelope {
            project_id: project_id.clone(),
            environment_id: environment_id.clone(),
            revision_id: self.revision_id.clone(),
            parent_revision_id: self.parent_revision_id.clone(),
            revision_metadata: self.revision_metadata.clone(),
            encrypted_payload: self.encrypted_payload.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySignedRequestEnvelope {
    pub auth: RelayRequestAuth,
    pub authorization: RelayAuthorizationEnvelope,
    pub payload: Vec<u8>,
}

impl RelaySignedRequestEnvelope {
    /// Stable wire magic; every encoded request envelope starts with
    /// these bytes. Changing it would break compatibility with every
    /// `keyit`/`keyit-relay` build that only recognizes this exact
    /// prefix.
    const MAGIC: &'static [u8] = b"keyit-relay-request-v1\n";

    pub fn sign(input: RelayRequestSigningInput<'_>) -> Self {
        let signing_public_key = input.signing_keypair.public_key();
        let auth = RelayRequestAuth {
            device_id: input.device_id,
            signing_public_key,
            created_at: input.created_at,
            nonce: input.nonce,
            signature: zero_signature_field(),
        };
        let mut envelope = Self {
            auth,
            authorization: input.authorization,
            payload: input.payload,
        };
        envelope.auth.signature = input.signing_keypair.sign(
            RelayRequestAuth::SIGN_LABEL,
            &envelope.signing_preimage(input.method, input.path),
        );
        envelope
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(Self::MAGIC);
        push_field(&mut out, self.auth.device_id.as_str().as_bytes());
        push_field(&mut out, self.auth.signing_public_key.as_bytes());
        push_field(&mut out, &self.auth.created_at.unix_seconds().to_be_bytes());
        push_field(&mut out, &self.auth.nonce);
        push_field(&mut out, self.auth.signature.as_bytes());
        push_field(&mut out, &self.authorization.encode());
        push_field(&mut out, &self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = bytes;
        if !cursor.starts_with(Self::MAGIC) {
            return Err("missing relay request envelope magic".to_string());
        }
        cursor = &cursor[Self::MAGIC.len()..];

        let device_id =
            DeviceId::parse(read_string(&mut cursor, "device_id")?).map_err(|e| e.to_string())?;
        let signing_public_key =
            SigningPublicKeyBytes::from_bytes(read_field(&mut cursor, "signing_public_key")?)
                .map_err(|e| e.to_string())?;
        let created_at_bytes = read_field(&mut cursor, "created_at")?;
        let created_at =
            Timestamp::from_unix_seconds(read_u64_field("created_at", created_at_bytes)?);
        let nonce = read_field(&mut cursor, "nonce")?.to_vec();
        let signature = SignatureBytes::from_bytes(read_field(&mut cursor, "signature")?)
            .map_err(|e| e.to_string())?;
        let authorization =
            RelayAuthorizationEnvelope::decode(read_field(&mut cursor, "authorization")?)?;
        let payload = read_field(&mut cursor, "payload")?.to_vec();
        if !cursor.is_empty() {
            return Err("trailing bytes after relay request envelope".to_string());
        }
        Ok(Self {
            auth: RelayRequestAuth {
                device_id,
                signing_public_key,
                created_at,
                nonce,
                signature,
            },
            authorization,
            payload,
        })
    }

    fn verify(
        &self,
        method: &HttpMethod,
        path: &str,
        environment_id: &EnvironmentId,
    ) -> Result<RelayAccessState, String> {
        if self.auth.nonce.len() < 16 {
            return Err("signed relay request nonce must be at least 16 bytes".to_string());
        }
        let access_state = self.authorization.verify()?;
        let device = access_state.device(&self.auth.device_id).ok_or_else(|| {
            format!(
                "device {} is not active in authorization context",
                self.auth.device_id
            )
        })?;
        if device.signing_public_key != self.auth.signing_public_key {
            return Err("request signing public key does not match authorized device".to_string());
        }
        if !device.can_access_environment(environment_id) {
            return Err(format!(
                "device {} is not authorized for environment {environment_id}",
                self.auth.device_id
            ));
        }
        signing::verify(
            RelayRequestAuth::SIGN_LABEL,
            &self.signing_preimage(*method, path),
            &self.auth.signing_public_key,
            &self.auth.signature,
        )
        .map_err(|e| e.to_string())?;
        Ok(access_state)
    }

    fn signing_preimage<'a>(
        &'a self,
        method: HttpMethod,
        path: &'a str,
    ) -> RelayRequestPreimage<'a> {
        RelayRequestPreimage {
            method,
            path,
            device_id: &self.auth.device_id,
            created_at: self.auth.created_at,
            nonce: &self.auth.nonce,
            authorization_hash: canonical::canonical_hash(
                "keyit:v1:relay-authorization-envelope",
                &self.authorization,
            ),
            payload: &self.payload,
        }
    }
}

#[derive(Debug)]
pub struct RelayRequestSigningInput<'a> {
    pub method: HttpMethod,
    pub path: &'a str,
    pub payload: Vec<u8>,
    pub authorization: RelayAuthorizationEnvelope,
    pub device_id: DeviceId,
    pub signing_keypair: &'a SigningKeyPair,
    pub created_at: Timestamp,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRequestAuth {
    pub device_id: DeviceId,
    pub signing_public_key: SigningPublicKeyBytes,
    pub created_at: Timestamp,
    pub nonce: Vec<u8>,
    pub signature: SignatureBytes,
}

impl RelayRequestAuth {
    pub const SIGN_LABEL: &'static str = "keyit:v1:sign:relay-request";
}

#[derive(Debug, Clone)]
struct RelayRequestPreimage<'a> {
    method: HttpMethod,
    path: &'a str,
    device_id: &'a DeviceId,
    created_at: Timestamp,
    nonce: &'a [u8],
    authorization_hash: HashBytes,
    payload: &'a [u8],
}

impl Canonicalize for RelayRequestPreimage<'_> {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.method.as_str());
        buf.push_str(self.path);
        buf.push_str(self.device_id.as_str());
        buf.push_u64(self.created_at.unix_seconds());
        buf.push_bytes(self.nonce);
        buf.push_bytes(self.authorization_hash.as_bytes());
        buf.push_bytes(self.payload);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAuthorizationEnvelope {
    pub project: ProjectGenesis,
    pub join_requests: Vec<JoinRequest>,
    pub approvals: Vec<Approval>,
    pub revocations: Vec<Revocation>,
}

impl RelayAuthorizationEnvelope {
    /// Stable wire magic; every encoded authorization envelope starts
    /// with these bytes. Changing it would break compatibility with
    /// every `keyit`/`keyit-relay` build that only recognizes this
    /// exact prefix.
    const MAGIC: &'static [u8] = b"keyit-relay-authorization-v1\n";

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(Self::MAGIC);
        push_field(&mut out, &encode_project_genesis(&self.project));
        push_list_fields(&mut out, &self.join_requests, encode_join_request);
        push_list_fields(&mut out, &self.approvals, encode_approval);
        push_list_fields(&mut out, &self.revocations, encode_revocation);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = bytes;
        if !cursor.starts_with(Self::MAGIC) {
            return Err("missing relay authorization envelope magic".to_string());
        }
        cursor = &cursor[Self::MAGIC.len()..];
        let project = decode_project_genesis(read_field(&mut cursor, "project")?)?;
        let join_requests = read_list_fields(&mut cursor, "join_requests", decode_join_request)?;
        let approvals = read_list_fields(&mut cursor, "approvals", decode_approval)?;
        let revocations = read_list_fields(&mut cursor, "revocations", decode_revocation)?;
        if !cursor.is_empty() {
            return Err("trailing bytes after relay authorization envelope".to_string());
        }
        Ok(Self {
            project,
            join_requests,
            approvals,
            revocations,
        })
    }

    pub fn verify(&self) -> Result<RelayAccessState, String> {
        self.project.verify_signature().map_err(|e| e.to_string())?;

        let mut join_requests = BTreeMap::new();
        for request in &self.join_requests {
            request.verify_signature().map_err(|e| e.to_string())?;
            if request.project_id != self.project.project_id {
                return Err("join request belongs to a different project".to_string());
            }
            join_requests.insert(
                request.joining_device_id.as_str().to_string(),
                request.clone(),
            );
        }

        let mut devices = BTreeMap::new();
        devices.insert(
            self.project.creator_device_id.as_str().to_string(),
            RelayAuthorizedDevice {
                device_id: self.project.creator_device_id.clone(),
                signing_public_key: self.project.creator_device_public_identity,
                role: Role::Owner,
                environment_ids: Vec::new(),
            },
        );

        let mut approvals = self.approvals.clone();
        approvals.sort_by_key(|approval| approval.created_at.unix_seconds());
        for approval in approvals {
            if approval.project_id != self.project.project_id {
                return Err("approval belongs to a different project".to_string());
            }
            let signer = devices
                .get(approval.approved_by_device_id.as_str())
                .ok_or_else(|| "approval signer is not active".to_string())?;
            if !signer.can_manage_access() {
                return Err("approval signer cannot manage access".to_string());
            }
            approval
                .verify_signature(&signer.signing_public_key)
                .map_err(|e| e.to_string())?;
            let request = join_requests
                .get(approval.approved_device_id.as_str())
                .ok_or_else(|| "approval target has no join request".to_string())?;
            if signer.role != Role::Owner {
                ensure_subset(&approval.approved_environment_ids, &signer.environment_ids)?;
            }
            devices.insert(
                approval.approved_device_id.as_str().to_string(),
                RelayAuthorizedDevice {
                    device_id: approval.approved_device_id,
                    signing_public_key: request.joining_device_public_identity,
                    role: approval.role,
                    environment_ids: approval.approved_environment_ids,
                },
            );
        }

        let mut revocations = self.revocations.clone();
        revocations.sort_by_key(|revocation| revocation.created_at.unix_seconds());
        for revocation in revocations {
            if revocation.project_id != self.project.project_id {
                return Err("revocation belongs to a different project".to_string());
            }
            let signer = devices
                .get(revocation.revoked_by_device_id.as_str())
                .ok_or_else(|| "revocation signer is not active".to_string())?;
            if !signer.can_manage_access() {
                return Err("revocation signer cannot manage access".to_string());
            }
            revocation
                .verify_signature(&signer.signing_public_key)
                .map_err(|e| e.to_string())?;
            devices.remove(revocation.revoked_device_id.as_str());
        }

        Ok(RelayAccessState { devices })
    }
}

impl Canonicalize for RelayAuthorizationEnvelope {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_bytes(&self.encode());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAccessState {
    devices: BTreeMap<String, RelayAuthorizedDevice>,
}

impl RelayAccessState {
    pub fn device(&self, device_id: &DeviceId) -> Option<&RelayAuthorizedDevice> {
        self.devices.get(device_id.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAuthorizedDevice {
    pub device_id: DeviceId,
    pub signing_public_key: SigningPublicKeyBytes,
    pub role: Role,
    pub environment_ids: Vec<EnvironmentId>,
}

impl RelayAuthorizedDevice {
    pub fn can_manage_access(&self) -> bool {
        matches!(self.role, Role::Owner | Role::Admin)
    }

    pub fn can_access_environment(&self, environment_id: &EnvironmentId) -> bool {
        self.role == Role::Owner || self.environment_ids.contains(environment_id)
    }
}

fn validate_publish_authorization(
    access_state: &RelayAccessState,
    request_device_id: &DeviceId,
    envelope: &RelayRevisionEnvelope,
) -> Result<(), String> {
    let revision = parse_revision_metadata(&envelope.revision_metadata)?;
    if revision.project_id != envelope.project_id
        || revision.environment_id != envelope.environment_id
        || revision.revision_id != envelope.revision_id
        || revision.parent_revision_id != envelope.parent_revision_id
    {
        return Err("revision metadata does not match relay envelope".to_string());
    }
    if &revision.author_device_id != request_device_id {
        return Err("request signer must match revision author".to_string());
    }
    let author = access_state
        .device(&revision.author_device_id)
        .ok_or_else(|| "revision author is not active".to_string())?;
    if !author.can_access_environment(&revision.environment_id) {
        return Err("revision author is not authorized for this environment".to_string());
    }
    revision
        .verify_signature(&author.signing_public_key)
        .map_err(|e| e.to_string())?;
    let derived_revision_id = RevisionId::derive(
        &revision.project_id,
        &revision.environment_id,
        revision.parent_revision_hash.as_ref(),
        &revision.payload_hash,
        &revision.author_device_id,
        revision.created_at,
    );
    if derived_revision_id != revision.revision_id {
        return Err("revision_id does not match revision metadata".to_string());
    }
    Ok(())
}

/// Deterministic v1 relay object envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRevisionEnvelope {
    pub project_id: ProjectId,
    pub environment_id: EnvironmentId,
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub revision_metadata: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

impl RelayRevisionEnvelope {
    /// Stable wire magic; every encoded revision envelope starts with
    /// these bytes. Changing it would break compatibility with every
    /// `keyit`/`keyit-relay` build that only recognizes this exact
    /// prefix.
    const MAGIC: &'static [u8] = b"keyit-relay-revision-v1\n";

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(Self::MAGIC);
        push_field(&mut out, self.project_id.as_str().as_bytes());
        push_field(&mut out, self.environment_id.as_str().as_bytes());
        push_field(&mut out, self.revision_id.as_str().as_bytes());
        push_field(
            &mut out,
            self.parent_revision_id
                .as_ref()
                .map(|id| id.as_str().as_bytes())
                .unwrap_or_default(),
        );
        push_field(&mut out, &self.revision_metadata);
        push_field(&mut out, &self.encrypted_payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = bytes;
        if !cursor.starts_with(Self::MAGIC) {
            return Err("missing relay revision envelope magic".to_string());
        }
        cursor = &cursor[Self::MAGIC.len()..];

        let project_id =
            ProjectId::parse(read_string(&mut cursor, "project_id")?).map_err(|e| e.to_string())?;
        let environment_id = EnvironmentId::parse(read_string(&mut cursor, "environment_id")?)
            .map_err(|e| e.to_string())?;
        let revision_id = RevisionId::parse(read_string(&mut cursor, "revision_id")?)
            .map_err(|e| e.to_string())?;
        let parent = read_field(&mut cursor, "parent_revision_id")?;
        let parent_revision_id = if parent.is_empty() {
            None
        } else {
            Some(
                RevisionId::parse(
                    std::str::from_utf8(parent)
                        .map_err(|e| format!("parent_revision_id is not UTF-8: {e}"))?,
                )
                .map_err(|e| e.to_string())?,
            )
        };
        let revision_metadata = read_field(&mut cursor, "revision_metadata")?.to_vec();
        let encrypted_payload = read_field(&mut cursor, "encrypted_payload")?.to_vec();
        if !cursor.is_empty() {
            return Err("trailing bytes after relay revision envelope".to_string());
        }
        Ok(Self {
            project_id,
            environment_id,
            revision_id,
            parent_revision_id,
            revision_metadata,
            encrypted_payload,
        })
    }
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_string<'a>(cursor: &mut &'a [u8], field: &str) -> Result<&'a str, String> {
    let bytes = read_field(cursor, field)?;
    std::str::from_utf8(bytes).map_err(|e| format!("{field} is not UTF-8: {e}"))
}

fn read_field<'a>(cursor: &mut &'a [u8], field: &str) -> Result<&'a [u8], String> {
    if cursor.len() < 8 {
        return Err(format!("{field} length prefix is truncated"));
    }
    let mut len = [0u8; 8];
    len.copy_from_slice(&cursor[..8]);
    let len = u64::from_be_bytes(len) as usize;
    *cursor = &cursor[8..];
    if cursor.len() < len {
        return Err(format!("{field} body is truncated"));
    }
    let value = &cursor[..len];
    *cursor = &cursor[len..];
    Ok(value)
}

fn read_u64_field(field: &str, bytes: &[u8]) -> Result<u64, String> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| format!("{field} is {} bytes, expected 8", bytes.len()))?;
    Ok(u64::from_be_bytes(bytes))
}

fn push_list_fields<T>(out: &mut Vec<u8>, values: &[T], encode: fn(&T) -> Vec<u8>) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        push_field(out, &encode(value));
    }
}

fn read_list_fields<T>(
    cursor: &mut &[u8],
    field: &str,
    decode: fn(&[u8]) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    if cursor.len() < 8 {
        return Err(format!("{field} item count is truncated"));
    }
    let mut count = [0u8; 8];
    count.copy_from_slice(&cursor[..8]);
    let count = u64::from_be_bytes(count);
    *cursor = &cursor[8..];

    let mut values = Vec::with_capacity(count as usize);
    for index in 0..count {
        values.push(decode(read_field(cursor, &format!("{field}[{index}]"))?)?);
    }
    Ok(values)
}

fn encode_project_genesis(project: &ProjectGenesis) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, project.protocol_version.as_str().as_bytes());
    push_field(&mut out, project.project_id.as_str().as_bytes());
    push_field(&mut out, project.genesis_nonce.as_bytes());
    push_field(&mut out, &project.created_at.unix_seconds().to_be_bytes());
    push_field(&mut out, project.creator_device_id.as_str().as_bytes());
    push_field(&mut out, project.creator_device_public_identity.as_bytes());
    push_field(&mut out, project.project_label.as_bytes());
    push_field(&mut out, project.default_relay_url.as_bytes());
    push_field(
        &mut out,
        &u64::from(project.canonicalization_version).to_be_bytes(),
    );
    push_field(&mut out, project.signature.as_bytes());
    out
}

fn decode_project_genesis(bytes: &[u8]) -> Result<ProjectGenesis, String> {
    let mut cursor = bytes;
    let protocol_version = read_string(&mut cursor, "protocol_version")?
        .parse::<ProtocolVersion>()
        .map_err(|e| e.to_string())?;
    let project_id =
        ProjectId::parse(read_string(&mut cursor, "project_id")?).map_err(|e| e.to_string())?;
    let genesis_nonce = NonceBytes::from_bytes(read_field(&mut cursor, "genesis_nonce")?);
    let created_at = Timestamp::from_unix_seconds(read_u64_field(
        "created_at",
        read_field(&mut cursor, "created_at")?,
    )?);
    let creator_device_id = DeviceId::parse(read_string(&mut cursor, "creator_device_id")?)
        .map_err(|e| e.to_string())?;
    let creator_device_public_identity = SigningPublicKeyBytes::from_bytes(read_field(
        &mut cursor,
        "creator_device_public_identity",
    )?)
    .map_err(|e| e.to_string())?;
    let project_label = read_string(&mut cursor, "project_label")?.to_string();
    let default_relay_url = read_string(&mut cursor, "default_relay_url")?.to_string();
    let canonicalization_version = read_u64_field(
        "canonicalization_version",
        read_field(&mut cursor, "canonicalization_version")?,
    )? as u32;
    let signature = SignatureBytes::from_bytes(read_field(&mut cursor, "signature")?)
        .map_err(|e| e.to_string())?;
    if !cursor.is_empty() {
        return Err("trailing bytes after project genesis".to_string());
    }
    Ok(ProjectGenesis {
        protocol_version,
        project_id,
        genesis_nonce,
        created_at,
        creator_device_id,
        creator_device_public_identity,
        project_label,
        default_relay_url,
        canonicalization_version,
        signature,
    })
}

fn encode_join_request(request: &JoinRequest) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, request.project_id.as_str().as_bytes());
    push_field(&mut out, request.invite_id.as_str().as_bytes());
    push_field(&mut out, request.joining_device_id.as_str().as_bytes());
    push_field(&mut out, request.joining_device_public_identity.as_bytes());
    push_field(
        &mut out,
        request.joining_device_encryption_public_key.as_bytes(),
    );
    push_list_fields(&mut out, &request.requested_environment_ids, |id| {
        id.as_str().as_bytes().to_vec()
    });
    push_field(&mut out, request.device_label.as_bytes());
    push_field(&mut out, &request.created_at.unix_seconds().to_be_bytes());
    push_field(&mut out, request.proof_signature.as_bytes());
    out
}

fn decode_join_request(bytes: &[u8]) -> Result<JoinRequest, String> {
    let mut cursor = bytes;
    let project_id =
        ProjectId::parse(read_string(&mut cursor, "project_id")?).map_err(|e| e.to_string())?;
    let invite_id =
        InviteId::parse(read_string(&mut cursor, "invite_id")?).map_err(|e| e.to_string())?;
    let joining_device_id = DeviceId::parse(read_string(&mut cursor, "joining_device_id")?)
        .map_err(|e| e.to_string())?;
    let joining_device_public_identity = SigningPublicKeyBytes::from_bytes(read_field(
        &mut cursor,
        "joining_device_public_identity",
    )?)
    .map_err(|e| e.to_string())?;
    let joining_device_encryption_public_key = PublicKeyBytes::from_bytes(read_field(
        &mut cursor,
        "joining_device_encryption_public_key",
    )?)
    .map_err(|e| e.to_string())?;
    let requested_environment_ids =
        read_list_fields(&mut cursor, "requested_environment_ids", |bytes| {
            let value = std::str::from_utf8(bytes)
                .map_err(|e| format!("requested_environment_id is not UTF-8: {e}"))?;
            EnvironmentId::parse(value).map_err(|e| e.to_string())
        })?;
    let device_label = read_string(&mut cursor, "device_label")?.to_string();
    let created_at = Timestamp::from_unix_seconds(read_u64_field(
        "created_at",
        read_field(&mut cursor, "created_at")?,
    )?);
    let proof_signature = SignatureBytes::from_bytes(read_field(&mut cursor, "proof_signature")?)
        .map_err(|e| e.to_string())?;
    if !cursor.is_empty() {
        return Err("trailing bytes after join request".to_string());
    }
    Ok(JoinRequest {
        project_id,
        invite_id,
        joining_device_id,
        joining_device_public_identity,
        joining_device_encryption_public_key,
        requested_environment_ids,
        device_label,
        created_at,
        proof_signature,
    })
}

fn encode_approval(approval: &Approval) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, approval.project_id.as_str().as_bytes());
    push_field(&mut out, approval.approved_device_id.as_str().as_bytes());
    push_list_fields(&mut out, &approval.approved_environment_ids, |id| {
        id.as_str().as_bytes().to_vec()
    });
    push_field(&mut out, approval.role.as_str().as_bytes());
    push_field(&mut out, approval.approved_by_device_id.as_str().as_bytes());
    push_field(&mut out, &approval.created_at.unix_seconds().to_be_bytes());
    push_field(&mut out, approval.signature.as_bytes());
    out
}

fn decode_approval(bytes: &[u8]) -> Result<Approval, String> {
    let mut cursor = bytes;
    let project_id =
        ProjectId::parse(read_string(&mut cursor, "project_id")?).map_err(|e| e.to_string())?;
    let approved_device_id = DeviceId::parse(read_string(&mut cursor, "approved_device_id")?)
        .map_err(|e| e.to_string())?;
    let approved_environment_ids =
        read_list_fields(&mut cursor, "approved_environment_ids", |bytes| {
            let value = std::str::from_utf8(bytes)
                .map_err(|e| format!("approved_environment_id is not UTF-8: {e}"))?;
            EnvironmentId::parse(value).map_err(|e| e.to_string())
        })?;
    let role = parse_role(read_string(&mut cursor, "role")?)?;
    let approved_by_device_id = DeviceId::parse(read_string(&mut cursor, "approved_by_device_id")?)
        .map_err(|e| e.to_string())?;
    let created_at = Timestamp::from_unix_seconds(read_u64_field(
        "created_at",
        read_field(&mut cursor, "created_at")?,
    )?);
    let signature = SignatureBytes::from_bytes(read_field(&mut cursor, "signature")?)
        .map_err(|e| e.to_string())?;
    if !cursor.is_empty() {
        return Err("trailing bytes after approval".to_string());
    }
    Ok(Approval {
        project_id,
        approved_device_id,
        approved_environment_ids,
        role,
        approved_by_device_id,
        created_at,
        signature,
    })
}

fn encode_revocation(revocation: &Revocation) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, revocation.project_id.as_str().as_bytes());
    push_field(&mut out, revocation.revoked_device_id.as_str().as_bytes());
    push_list_fields(&mut out, &revocation.affected_environment_ids, |id| {
        id.as_str().as_bytes().to_vec()
    });
    push_field(
        &mut out,
        revocation.revoked_by_device_id.as_str().as_bytes(),
    );
    push_field(
        &mut out,
        &revocation.created_at.unix_seconds().to_be_bytes(),
    );
    push_field(
        &mut out,
        revocation
            .reason_optional
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    push_field(&mut out, revocation.signature.as_bytes());
    out
}

fn decode_revocation(bytes: &[u8]) -> Result<Revocation, String> {
    let mut cursor = bytes;
    let project_id =
        ProjectId::parse(read_string(&mut cursor, "project_id")?).map_err(|e| e.to_string())?;
    let revoked_device_id = DeviceId::parse(read_string(&mut cursor, "revoked_device_id")?)
        .map_err(|e| e.to_string())?;
    let affected_environment_ids =
        read_list_fields(&mut cursor, "affected_environment_ids", |bytes| {
            let value = std::str::from_utf8(bytes)
                .map_err(|e| format!("affected_environment_id is not UTF-8: {e}"))?;
            EnvironmentId::parse(value).map_err(|e| e.to_string())
        })?;
    let revoked_by_device_id = DeviceId::parse(read_string(&mut cursor, "revoked_by_device_id")?)
        .map_err(|e| e.to_string())?;
    let created_at = Timestamp::from_unix_seconds(read_u64_field(
        "created_at",
        read_field(&mut cursor, "created_at")?,
    )?);
    let reason = read_string(&mut cursor, "reason_optional")?;
    let reason_optional = if reason.is_empty() {
        None
    } else {
        Some(reason.to_string())
    };
    let signature = SignatureBytes::from_bytes(read_field(&mut cursor, "signature")?)
        .map_err(|e| e.to_string())?;
    if !cursor.is_empty() {
        return Err("trailing bytes after revocation".to_string());
    }
    Ok(Revocation {
        project_id,
        revoked_device_id,
        affected_environment_ids,
        revoked_by_device_id,
        created_at,
        reason_optional,
        signature,
    })
}

fn parse_role(value: &str) -> Result<Role, String> {
    match value {
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        "member" => Ok(Role::Member),
        _ => Err(format!("unsupported role {value}")),
    }
}

fn ensure_subset(requested: &[EnvironmentId], allowed: &[EnvironmentId]) -> Result<(), String> {
    for environment_id in requested {
        if !allowed.contains(environment_id) {
            return Err(format!(
                "approval grants environment {environment_id} outside signer scope"
            ));
        }
    }
    Ok(())
}

/// Project genesis fields needed for relay-side creator-device quotas.
#[derive(Debug, Deserialize)]
struct RelayProjectGenesisRecordToml {
    creator_device_id: String,
}

fn parse_relay_project_genesis_record(
    bytes: &[u8],
) -> Result<RelayProjectGenesisRecordToml, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| format!("project genesis record is not UTF-8: {e}"))?;
    toml::from_str(text).map_err(|e| format!("project genesis record TOML is malformed: {e}"))
}

/// The small subset of `keyit-cli`'s `InviteToml` fields
/// [`FileRelayStore::publish_join_request_checked`] needs to enforce
/// `max_uses`. Deliberately independent of `keyit-cli`'s own TOML
/// struct (same reasoning as [`RelayRevisionMetadataToml`] below): this
/// crate does not depend on `keyit-cli`, and the wire format is TOML by
/// convention, not a `keyit-protocol` byte encoding.
#[derive(Debug, Deserialize)]
struct RelayInviteRecordToml {
    max_uses: u32,
    status: String,
    expires_at: u64,
}

fn parse_relay_invite_record(bytes: &[u8]) -> Result<RelayInviteRecordToml, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| format!("invite record is not UTF-8: {e}"))?;
    toml::from_str(text).map_err(|e| format!("invite record TOML is malformed: {e}"))
}

/// The small subset of `keyit-cli`'s `JoinRequestToml` fields
/// [`FileRelayStore::publish_join_request_checked`] needs.
#[derive(Debug, Deserialize)]
struct RelayJoinRequestRecordToml {
    invite_id: String,
    joining_device_id: String,
}

fn parse_relay_join_request_record(bytes: &[u8]) -> Result<RelayJoinRequestRecordToml, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| format!("join request record is not UTF-8: {e}"))?;
    toml::from_str(text).map_err(|e| format!("join request record TOML is malformed: {e}"))
}

#[derive(Debug, Deserialize)]
struct RelayRevisionMetadataToml {
    revision_id: String,
    project_id: String,
    environment_id: String,
    parent_revision_id: Option<String>,
    parent_revision_hash: Option<String>,
    payload_hash: String,
    encrypted_payload_ref: String,
    author_device_id: String,
    created_at: u64,
    change_summary: Option<String>,
    signature: String,
}

fn parse_revision_metadata(bytes: &[u8]) -> Result<Revision, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| format!("revision metadata is not UTF-8: {e}"))?;
    let toml: RelayRevisionMetadataToml =
        toml::from_str(text).map_err(|e| format!("revision metadata TOML is malformed: {e}"))?;
    Ok(Revision {
        revision_id: RevisionId::parse(&toml.revision_id).map_err(|e| e.to_string())?,
        project_id: ProjectId::parse(&toml.project_id).map_err(|e| e.to_string())?,
        environment_id: EnvironmentId::parse(&toml.environment_id).map_err(|e| e.to_string())?,
        parent_revision_id: toml
            .parent_revision_id
            .as_deref()
            .map(RevisionId::parse)
            .transpose()
            .map_err(|e| e.to_string())?,
        parent_revision_hash: toml
            .parent_revision_hash
            .as_deref()
            .map(decode_hash)
            .transpose()?,
        payload_hash: decode_hash(&toml.payload_hash)?,
        encrypted_payload_ref: toml.encrypted_payload_ref,
        author_device_id: DeviceId::parse(&toml.author_device_id).map_err(|e| e.to_string())?,
        created_at: Timestamp::from_unix_seconds(toml.created_at),
        change_summary: toml.change_summary,
        signature: SignatureBytes::from_bytes(&decode_hex(&toml.signature, "signature")?)
            .map_err(|e| e.to_string())?,
    })
}

fn decode_hash(value: &str) -> Result<HashBytes, String> {
    let bytes = decode_hex(value, "hash")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("hash is {} bytes, expected 32", bytes.len()))?;
    Ok(HashBytes::from_sha256_digest(bytes))
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    HEXLOWER
        .decode(value.as_bytes())
        .map_err(|e| format!("{field} is not valid lowercase hex: {e}"))
}

fn zero_signature_field() -> SignatureBytes {
    SignatureBytes::from_bytes(&[0u8; 64]).expect("64 zero bytes is a validly-shaped signature")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayLayout {
    environment_dir: PathBuf,
    revisions_dir: PathBuf,
    payloads_dir: PathBuf,
    latest_file: PathBuf,
    lock_file: PathBuf,
}

impl RelayLayout {
    fn revision_file(&self, revision_id: &RevisionId) -> PathBuf {
        self.revisions_dir
            .join(format!("{}.keyit", revision_id.as_str()))
    }

    fn payload_file(&self, revision_id: &RevisionId) -> PathBuf {
        self.payloads_dir
            .join(format!("{}.payload", revision_id.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyit_protocol::primitives::NonceBytes;
    use keyit_protocol::signing::SignedRecord;
    use keyit_protocol::version::ProtocolVersion;

    fn ids() -> (ProjectId, EnvironmentId, RevisionId) {
        (
            ProjectId::new_unchecked_for_test(
                "erbbbzeeg63fk2mau4betkmtngjuunjefebuz345ppjfhm57fqaq",
            ),
            EnvironmentId::new_unchecked_for_test(
                "ma5cxb5xg5ajk7idru24aivg3pbc3xyvpxzojqbn65xnuztfpg2q",
            ),
            RevisionId::new_unchecked_for_test(
                "fmqu3xzteyawkgnpzmti6y3choalsgtfezjhozuojuba3b65sb4a",
            ),
        )
    }

    #[derive(Debug)]
    struct SignedRequestContext {
        project_id: ProjectId,
        signing_keypair: SigningKeyPair,
        device_id: DeviceId,
    }

    fn signed_request(
        context: &SignedRequestContext,
        method: HttpMethod,
        path: &str,
        payload: Vec<u8>,
        timestamp: u64,
        nonce: &[u8],
    ) -> RelayHttpRequest {
        let mut project = ProjectGenesis {
            protocol_version: ProtocolVersion::V1,
            project_id: context.project_id.clone(),
            genesis_nonce: NonceBytes::from_bytes(b"relay-test-nonce".to_vec()),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            creator_device_id: context.device_id.clone(),
            creator_device_public_identity: context.signing_keypair.public_key(),
            project_label: "relay-test".to_string(),
            default_relay_url: "http://127.0.0.1:7878".to_string(),
            canonicalization_version: 1,
            signature: zero_signature_field(),
        };
        project.signature = context
            .signing_keypair
            .sign(ProjectGenesis::SIGN_LABEL, &project);
        let authorization = RelayAuthorizationEnvelope {
            project,
            join_requests: Vec::new(),
            approvals: Vec::new(),
            revocations: Vec::new(),
        };
        RelayHttpRequest {
            method,
            path: path.to_string(),
            body: RelaySignedRequestEnvelope::sign(RelayRequestSigningInput {
                method,
                path,
                payload,
                authorization,
                device_id: context.device_id.clone(),
                signing_keypair: &context.signing_keypair,
                created_at: Timestamp::from_unix_seconds(timestamp),
                nonce: nonce.to_vec(),
            })
            .encode(),
            peer_addr: None,
        }
    }

    fn signed_revision_metadata(
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        device_id: &DeviceId,
        signing_keypair: &SigningKeyPair,
    ) -> (RevisionId, Vec<u8>) {
        let payload_hash = HashBytes::from_sha256_digest([7u8; 32]);
        let revision_id = RevisionId::derive(
            project_id,
            environment_id,
            None,
            &payload_hash,
            device_id,
            Timestamp::from_unix_seconds(1_755_878_500),
        );
        let mut revision = Revision {
            revision_id: revision_id.clone(),
            project_id: project_id.clone(),
            environment_id: environment_id.clone(),
            parent_revision_id: None,
            parent_revision_hash: None,
            payload_hash,
            encrypted_payload_ref: format!("local://{revision_id}/payload"),
            author_device_id: device_id.clone(),
            created_at: Timestamp::from_unix_seconds(1_755_878_500),
            change_summary: None,
            signature: zero_signature_field(),
        };
        revision.signature = signing_keypair.sign(Revision::SIGN_LABEL, &revision);
        let metadata = format!(
            "revision_id = \"{}\"\nproject_id = \"{}\"\nenvironment_id = \"{}\"\npayload_hash = \"{}\"\nencrypted_payload_ref = \"{}\"\nauthor_device_id = \"{}\"\ncreated_at = {}\nsignature = \"{}\"\npayload_algorithm = \"keyit:v1:aes-256-gcm:environment-payload\"\npayload_nonce = \"000000000000000000000000\"\nwrapped_deks = []\n",
            revision.revision_id,
            revision.project_id,
            revision.environment_id,
            HEXLOWER.encode(revision.payload_hash.as_bytes()),
            revision.encrypted_payload_ref,
            revision.author_device_id,
            revision.created_at.unix_seconds(),
            HEXLOWER.encode(revision.signature.as_bytes()),
        )
        .into_bytes();
        (revision_id, metadata)
    }

    #[test]
    fn publish_and_fetch_latest_revision_round_trips_opaque_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, revision_id) = ids();

        store
            .publish_revision(
                &project_id,
                &environment_id,
                &revision_id,
                b"revision metadata",
                b"encrypted payload",
            )
            .expect("publish");

        let stored = store
            .fetch_latest_revision(&project_id, &environment_id)
            .expect("fetch")
            .expect("latest revision");
        assert_eq!(stored.revision_id, revision_id);
        assert_eq!(stored.parent_revision_id, None);
        assert_eq!(stored.revision_metadata, b"revision metadata");
        assert_eq!(stored.encrypted_payload, b"encrypted payload");
    }

    #[test]
    fn missing_latest_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, _) = ids();

        let latest = store
            .fetch_latest_revision(&project_id, &environment_id)
            .expect("fetch");
        assert!(latest.is_none());
    }

    #[test]
    fn publish_and_fetch_access_record_round_trips_opaque_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, _, _) = ids();
        let invite_id = InviteId::new_unchecked_for_test(
            "2zhkcaqrbescvu66ekiphjeuloworxw3enrjtp3lr23on5gff5ua",
        );

        store
            .publish_access_record(
                &project_id,
                AccessRecordKind::Invite,
                invite_id.as_str(),
                b"signed invite bytes",
            )
            .expect("publish access record");

        let stored = store
            .fetch_access_record(&project_id, AccessRecordKind::Invite, invite_id.as_str())
            .expect("fetch access record")
            .expect("record");
        assert_eq!(stored, b"signed invite bytes");
    }

    /// Test-only helpers for [`FileRelayStore::publish_join_request_checked`]
    /// enforcement: minimal invite/join-request TOML bytes matching
    /// [`RelayInviteRecordToml`] / [`RelayJoinRequestRecordToml`], and a
    /// fixed "now" so expiry can be tested deterministically.
    mod invite_max_uses {
        use super::*;

        const NOW: u64 = 1_800_000_000;

        fn invite_record(max_uses: u32, status: &str, expires_at: u64) -> Vec<u8> {
            format!("max_uses = {max_uses}\nstatus = \"{status}\"\nexpires_at = {expires_at}\n")
                .into_bytes()
        }

        fn join_request_record(invite_id: &InviteId, joining_device_id: &DeviceId) -> Vec<u8> {
            format!("invite_id = \"{invite_id}\"\njoining_device_id = \"{joining_device_id}\"\n")
                .into_bytes()
        }

        fn store_with_invite(
            max_uses: u32,
            status: &str,
            expires_at: u64,
        ) -> (tempfile::TempDir, FileRelayStore, ProjectId, InviteId) {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::new(dir.path());
            let project_id = ProjectId::new_unchecked_for_test(&"g".repeat(52));
            let invite_id = InviteId::new_unchecked_for_test(&"d".repeat(52));
            store
                .publish_access_record(
                    &project_id,
                    AccessRecordKind::Invite,
                    invite_id.as_str(),
                    &invite_record(max_uses, status, expires_at),
                )
                .expect("seed invite record");
            (dir, store, project_id, invite_id)
        }

        #[test]
        fn single_use_invite_is_redeemable_once() {
            let (_dir, store, project_id, invite_id) = store_with_invite(1, "active", NOW + 1000);
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));

            let result = store.publish_join_request_checked(
                &project_id,
                &device_a,
                &join_request_record(&invite_id, &device_a),
                NOW,
            );

            assert!(
                result.is_ok(),
                "first redemption should succeed: {result:?}"
            );
        }

        #[test]
        fn second_redemption_of_single_use_invite_fails_with_clear_error() {
            let (_dir, store, project_id, invite_id) = store_with_invite(1, "active", NOW + 1000);
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));
            let device_b = DeviceId::new_unchecked_for_test(&"b".repeat(52));

            store
                .publish_join_request_checked(
                    &project_id,
                    &device_a,
                    &join_request_record(&invite_id, &device_a),
                    NOW,
                )
                .expect("first device redeems the invite");

            let second = store.publish_join_request_checked(
                &project_id,
                &device_b,
                &join_request_record(&invite_id, &device_b),
                NOW,
            );

            match second {
                Err(RelayStoreError::InviteExhausted {
                    invite_id: rejected_invite_id,
                    max_uses,
                }) => {
                    assert_eq!(rejected_invite_id, invite_id);
                    assert_eq!(max_uses, 1);
                    let message = RelayStoreError::InviteExhausted {
                        invite_id: rejected_invite_id,
                        max_uses,
                    }
                    .to_string();
                    assert!(
                        message.contains("already reached its maximum of 1 use"),
                        "error message should be a clear, user-facing explanation: {message}"
                    );
                }
                other => panic!("expected InviteExhausted, got {other:?}"),
            }
        }

        #[test]
        fn multi_use_invite_allows_exactly_the_configured_number() {
            let (_dir, store, project_id, invite_id) = store_with_invite(2, "active", NOW + 1000);
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));
            let device_b = DeviceId::new_unchecked_for_test(&"b".repeat(52));
            let device_c = DeviceId::new_unchecked_for_test(&"c".repeat(52));

            store
                .publish_join_request_checked(
                    &project_id,
                    &device_a,
                    &join_request_record(&invite_id, &device_a),
                    NOW,
                )
                .expect("first of two uses should succeed");
            store
                .publish_join_request_checked(
                    &project_id,
                    &device_b,
                    &join_request_record(&invite_id, &device_b),
                    NOW,
                )
                .expect("second of two uses should succeed");

            let third = store.publish_join_request_checked(
                &project_id,
                &device_c,
                &join_request_record(&invite_id, &device_c),
                NOW,
            );

            assert!(
                matches!(
                    third,
                    Err(RelayStoreError::InviteExhausted { max_uses: 2, .. })
                ),
                "a third device should be rejected once max_uses is reached: {third:?}"
            );
        }

        #[test]
        fn expired_invite_is_rejected_even_with_uses_remaining() {
            let (_dir, store, project_id, invite_id) = store_with_invite(5, "active", NOW - 1);
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));

            let result = store.publish_join_request_checked(
                &project_id,
                &device_a,
                &join_request_record(&invite_id, &device_a),
                NOW,
            );

            match result {
                Err(RelayStoreError::Malformed { reason, .. }) => {
                    assert!(
                        reason.contains("expired"),
                        "expected an expiry error, got: {reason}"
                    );
                }
                other => panic!("expected an expired-invite error, got {other:?}"),
            }
        }

        #[test]
        fn replaying_the_same_device_join_request_does_not_consume_an_extra_use() {
            let (_dir, store, project_id, invite_id) = store_with_invite(1, "active", NOW + 1000);
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));
            let device_b = DeviceId::new_unchecked_for_test(&"b".repeat(52));

            store
                .publish_join_request_checked(
                    &project_id,
                    &device_a,
                    &join_request_record(&invite_id, &device_a),
                    NOW,
                )
                .expect("first redemption succeeds");

            // Replaying the *same* device's join request (e.g. retrying
            // the same invite bundle after a network error) must be
            // idempotent, not count as a second use.
            let replay = store.publish_join_request_checked(
                &project_id,
                &device_a,
                &join_request_record(&invite_id, &device_a),
                NOW,
            );
            assert!(
                replay.is_ok(),
                "the same device replaying its own join request should be idempotent: {replay:?}"
            );

            // A genuinely different device must still be rejected: the
            // replay above did not silently grant it a free use.
            let other_device = store.publish_join_request_checked(
                &project_id,
                &device_b,
                &join_request_record(&invite_id, &device_b),
                NOW,
            );
            assert!(
                matches!(
                    other_device,
                    Err(RelayStoreError::InviteExhausted { max_uses: 1, .. })
                ),
                "replaying device_a's own request must not let device_b bypass max_uses: {other_device:?}"
            );
        }
    }

    #[test]
    fn health_check_does_not_require_signed_project_request() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());

        let response = handle_http_request(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Get,
                path: "/healthz".to_string(),
                body: Vec::new(),
                peer_addr: None,
            },
        );

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok\n");
    }

    #[test]
    fn readiness_check_verifies_storage_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());

        let response = handle_http_request(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Get,
                path: "/readyz".to_string(),
                body: Vec::new(),
                peer_addr: None,
            },
        );

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ready\n");
    }

    #[test]
    fn storage_policy_rejects_oversized_payloads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::with_policy(
            dir.path(),
            StoragePolicy {
                max_revision_metadata_bytes: 100,
                max_encrypted_payload_bytes: 4,
                max_revisions_per_environment: 10,
                max_projects_per_device: 0,
                max_environments_per_project: 0,
                max_devices_per_project: 0,
            },
        );
        let (project_id, environment_id, revision_id) = ids();

        let err = store
            .publish_revision(
                &project_id,
                &environment_id,
                &revision_id,
                b"metadata",
                b"payload",
            )
            .expect_err("oversized payload should fail");
        assert!(matches!(err, RelayStoreError::Quota { .. }));
    }

    #[test]
    fn storage_policy_rejects_revision_count_over_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::with_policy(
            dir.path(),
            StoragePolicy {
                max_revision_metadata_bytes: 100,
                max_encrypted_payload_bytes: 100,
                max_revisions_per_environment: 1,
                max_projects_per_device: 0,
                max_environments_per_project: 0,
                max_devices_per_project: 0,
            },
        );
        let (project_id, environment_id, first_revision_id) = ids();
        let second_revision_id = RevisionId::new_unchecked_for_test(
            "e6g2ph2r4afg3divn6cm6s3k2oz3zz22ie4zqq6r56ljveqlx7va",
        );

        store
            .publish_revision(
                &project_id,
                &environment_id,
                &first_revision_id,
                b"metadata",
                b"payload",
            )
            .expect("first publish");
        let err = store
            .publish_revision(
                &project_id,
                &environment_id,
                &second_revision_id,
                b"metadata",
                b"payload",
            )
            .expect_err("second publish should exceed revision count");
        assert!(matches!(err, RelayStoreError::Quota { .. }));
    }

    #[test]
    fn zero_revisions_per_environment_disables_the_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::with_policy(
            dir.path(),
            StoragePolicy {
                max_revision_metadata_bytes: 100,
                max_encrypted_payload_bytes: 100,
                max_revisions_per_environment: 0,
                max_projects_per_device: 0,
                max_environments_per_project: 0,
                max_devices_per_project: 0,
            },
        );
        let (project_id, environment_id, first_revision_id) = ids();
        let second_revision_id = RevisionId::new_unchecked_for_test(
            "e6g2ph2r4afg3divn6cm6s3k2oz3zz22ie4zqq6r56ljveqlx7va",
        );

        store
            .publish_revision(
                &project_id,
                &environment_id,
                &first_revision_id,
                b"metadata",
                b"payload",
            )
            .expect("first publish");
        store
            .publish_revision(
                &project_id,
                &environment_id,
                &second_revision_id,
                b"metadata",
                b"payload",
            )
            .expect("second publish should not be capped when the limit is 0");
    }

    mod hosted_relay_limits {
        use super::*;

        fn policy_with(
            max_projects_per_device: usize,
            max_environments_per_project: usize,
            max_devices_per_project: usize,
        ) -> StoragePolicy {
            StoragePolicy {
                max_projects_per_device,
                max_environments_per_project,
                max_devices_per_project,
                ..StoragePolicy::default()
            }
        }

        fn project_genesis_record(creator_device_id: &DeviceId) -> Vec<u8> {
            format!("creator_device_id = \"{creator_device_id}\"\n").into_bytes()
        }

        #[test]
        fn project_cap_rejects_a_second_project_from_the_same_creator_device() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(1, 0, 0));
            let creator = DeviceId::new_unchecked_for_test(&"c".repeat(52));
            let project_a = ProjectId::new_unchecked_for_test(&"p".repeat(52));
            let project_b = ProjectId::new_unchecked_for_test(&"q".repeat(52));

            store
                .publish_project_genesis_checked(&project_a, &project_genesis_record(&creator))
                .expect("first project should be allowed");

            let err = store
                .publish_project_genesis_checked(&project_b, &project_genesis_record(&creator))
                .expect_err("second project from the same device should be rejected");
            assert!(matches!(err, RelayStoreError::Quota { .. }));
        }

        #[test]
        fn project_cap_of_zero_is_unlimited() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 0, 0));
            let creator = DeviceId::new_unchecked_for_test(&"c".repeat(52));
            let project_a = ProjectId::new_unchecked_for_test(&"p".repeat(52));
            let project_b = ProjectId::new_unchecked_for_test(&"q".repeat(52));

            store
                .publish_project_genesis_checked(&project_a, &project_genesis_record(&creator))
                .expect("first project should be allowed");
            store
                .publish_project_genesis_checked(&project_b, &project_genesis_record(&creator))
                .expect("second project should be allowed when the cap is disabled");
        }

        #[test]
        fn project_cap_allows_republishing_the_same_project_idempotently() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(1, 0, 0));
            let creator = DeviceId::new_unchecked_for_test(&"c".repeat(52));
            let project_a = ProjectId::new_unchecked_for_test(&"p".repeat(52));

            store
                .publish_project_genesis_checked(&project_a, &project_genesis_record(&creator))
                .expect("first publish should be allowed");
            store
                .publish_project_genesis_checked(&project_a, &project_genesis_record(&creator))
                .expect("re-publishing the same project should stay idempotent");
        }

        #[test]
        fn project_cap_tracks_devices_independently() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(1, 0, 0));
            let device_a = DeviceId::new_unchecked_for_test(&"c".repeat(52));
            let device_b = DeviceId::new_unchecked_for_test(&"e".repeat(52));
            let project_a = ProjectId::new_unchecked_for_test(&"p".repeat(52));
            let project_b = ProjectId::new_unchecked_for_test(&"q".repeat(52));

            store
                .publish_project_genesis_checked(&project_a, &project_genesis_record(&device_a))
                .expect("device a's first project should be allowed");
            store
                .publish_project_genesis_checked(&project_b, &project_genesis_record(&device_b))
                .expect("a different device's first project should also be allowed");
        }

        #[test]
        fn environment_cap_rejects_a_fourth_environment() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 3, 0));
            let (project_id, _, _) = ids();
            let env_a = EnvironmentId::new_unchecked_for_test(&"1".repeat(52));
            let env_b = EnvironmentId::new_unchecked_for_test(&"2".repeat(52));
            let env_c = EnvironmentId::new_unchecked_for_test(&"3".repeat(52));
            let env_d = EnvironmentId::new_unchecked_for_test(&"4".repeat(52));

            for environment_id in [&env_a, &env_b, &env_c] {
                store
                    .publish_environment_checked(&project_id, environment_id, b"env genesis")
                    .expect("environments within the cap should be allowed");
            }

            let err = store
                .publish_environment_checked(&project_id, &env_d, b"env genesis")
                .expect_err("the fourth environment should exceed the cap");
            assert!(matches!(err, RelayStoreError::Quota { .. }));
        }

        #[test]
        fn environment_cap_of_zero_is_unlimited() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 0, 0));
            let (project_id, _, _) = ids();

            for index in 0..5 {
                let environment_id =
                    EnvironmentId::new_unchecked_for_test(&index.to_string().repeat(52));
                store
                    .publish_environment_checked(&project_id, &environment_id, b"env genesis")
                    .expect("environments should never be capped when the limit is 0");
            }
        }

        #[test]
        fn environment_cap_allows_republishing_the_same_environment_idempotently() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 1, 0));
            let (project_id, environment_id, _) = ids();

            store
                .publish_environment_checked(&project_id, &environment_id, b"env genesis v1")
                .expect("first publish should be allowed");
            store
                .publish_environment_checked(&project_id, &environment_id, b"env genesis v1")
                .expect("re-publishing the same environment should stay idempotent");
        }

        #[test]
        fn device_cap_rejects_a_device_beyond_the_cap() {
            let dir = tempfile::tempdir().expect("tempdir");
            // Cap of 2 total active devices: the project creator/owner
            // (implicit) plus one approved device.
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 0, 2));
            let (project_id, _, _) = ids();
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));
            let device_b = DeviceId::new_unchecked_for_test(&"b".repeat(52));

            store
                .publish_approval_checked(&project_id, &device_a, b"approval a")
                .expect("first approved device should be within the cap");

            let err = store
                .publish_approval_checked(&project_id, &device_b, b"approval b")
                .expect_err("a second approved device should exceed the cap");
            assert!(matches!(err, RelayStoreError::Quota { .. }));
        }

        #[test]
        fn device_cap_of_zero_is_unlimited() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 0, 0));
            let (project_id, _, _) = ids();

            for index in 0..5 {
                let device_id = DeviceId::new_unchecked_for_test(&index.to_string().repeat(52));
                store
                    .publish_approval_checked(&project_id, &device_id, b"approval")
                    .expect("devices should never be capped when the limit is 0");
            }
        }

        #[test]
        fn device_cap_frees_a_slot_after_revocation() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 0, 2));
            let (project_id, _, _) = ids();
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));
            let device_b = DeviceId::new_unchecked_for_test(&"b".repeat(52));

            store
                .publish_approval_checked(&project_id, &device_a, b"approval a")
                .expect("first approved device should be within the cap");
            store
                .publish_access_record(
                    &project_id,
                    AccessRecordKind::Revocation,
                    device_a.as_str(),
                    b"revocation a",
                )
                .expect("revoking device a should be allowed");

            store
                .publish_approval_checked(&project_id, &device_b, b"approval b")
                .expect("device b should take the slot device a's revocation freed");
        }

        #[test]
        fn device_cap_allows_reapproving_an_already_approved_device_idempotently() {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = FileRelayStore::with_policy(dir.path(), policy_with(0, 0, 2));
            let (project_id, _, _) = ids();
            let device_a = DeviceId::new_unchecked_for_test(&"a".repeat(52));

            store
                .publish_approval_checked(&project_id, &device_a, b"approval a v1")
                .expect("first approval should be allowed");
            store
                .publish_approval_checked(&project_id, &device_a, b"approval a v2")
                .expect("re-approving (e.g. a role change) should stay idempotent");
        }
    }

    #[test]
    fn inventory_and_integrity_report_clean_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, revision_id) = ids();

        store
            .publish_revision(
                &project_id,
                &environment_id,
                &revision_id,
                b"revision metadata",
                b"encrypted payload",
            )
            .expect("publish");
        store
            .remember_request_nonce(
                &project_id,
                &DeviceId::new_unchecked_for_test(
                    "nk4bzt42f6dmnt5lgw5pimjmcfzu6tsdj2yayhgpzvf5vw6d2rba",
                ),
                b"nonce for inventory",
            )
            .expect("nonce");

        let report = store.verify_integrity().expect("integrity");
        assert!(report.is_clean());
        assert_eq!(report.inventory.project_count, 1);
        assert_eq!(report.inventory.environment_count, 1);
        assert_eq!(report.inventory.revision_count, 1);
        assert_eq!(report.inventory.payload_count, 1);
        assert_eq!(report.inventory.nonce_count, 1);
        assert!(report.inventory.total_bytes > 0);
    }

    #[test]
    fn integrity_reports_missing_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, revision_id) = ids();

        let published = store
            .publish_revision(
                &project_id,
                &environment_id,
                &revision_id,
                b"revision metadata",
                b"encrypted payload",
            )
            .expect("publish");
        fs::remove_file(published.payload_path).expect("remove payload");

        let report = store.verify_integrity().expect("integrity");
        assert!(!report.is_clean());
        assert_eq!(report.missing_payloads.len(), 1);
    }

    #[test]
    fn cleanup_removes_expired_nonces_temp_files_and_locks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, _) = ids();
        let device_id = DeviceId::new_unchecked_for_test(
            "nk4bzt42f6dmnt5lgw5pimjmcfzu6tsdj2yayhgpzvf5vw6d2rba",
        );
        store
            .remember_request_nonce(&project_id, &device_id, b"cleanup nonce")
            .expect("nonce");
        let environment_dir = dir
            .path()
            .join("projects")
            .join(project_id.as_str())
            .join("environments")
            .join(environment_id.as_str());
        fs::create_dir_all(&environment_dir).expect("environment dir");
        fs::write(environment_dir.join(".leftover.tmp"), b"temp").expect("temp");
        fs::write(environment_dir.join("publish.lock"), b"lock").expect("lock");

        let report = store
            .cleanup_storage(
                &CleanupPolicy {
                    nonce_ttl: Duration::from_secs(1),
                    temp_file_ttl: Duration::from_secs(1),
                    stale_lock_ttl: Duration::from_secs(1),
                    dry_run: false,
                },
                SystemTime::now() + Duration::from_secs(10),
            )
            .expect("cleanup");

        assert_eq!(report.nonce_files_removed, 1);
        assert_eq!(report.temp_files_removed, 1);
        assert_eq!(report.lock_files_removed, 1);
        assert!(report.bytes_removed > 0);
    }

    #[test]
    fn http_limits_reject_oversized_request_body_before_parsing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let response = handle_http_request_with_limits(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Put,
                path: "/v1/projects/not-valid/environments/not-valid/revisions/not-valid"
                    .to_string(),
                body: vec![0u8; 8],
                peer_addr: None,
            },
            &RelayHttpLimits {
                max_header_bytes: 1024,
                max_body_bytes: 4,
                max_authorization_bytes: 4,
                max_request_payload_bytes: 4,
            },
        );

        assert_eq!(response.status, 413);
    }

    #[test]
    fn http_access_record_route_round_trips_opaque_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, _, _) = ids();
        let invite_id = InviteId::new_unchecked_for_test(
            "2zhkcaqrbescvu66ekiphjeuloworxw3enrjtp3lr23on5gff5ua",
        );
        let path = format!("/v1/projects/{project_id}/access/invites/{invite_id}");

        let created = handle_http_request(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Put,
                path: path.clone(),
                body: b"signed invite bytes".to_vec(),
                peer_addr: None,
            },
        );
        assert_eq!(created.status, 201);

        let fetched = handle_http_request(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Get,
                path,
                body: Vec::new(),
                peer_addr: None,
            },
        );
        assert_eq!(fetched.status, 200);
        assert_eq!(fetched.body, b"signed invite bytes");
    }

    #[test]
    fn http_environment_cap_returns_413_over_the_wire() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::with_policy(
            dir.path(),
            StoragePolicy {
                max_environments_per_project: 1,
                ..StoragePolicy::default()
            },
        );
        let (project_id, environment_id, _) = ids();
        let other_environment_id = EnvironmentId::new_unchecked_for_test(&"z".repeat(52));

        let first = handle_http_request(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Put,
                path: format!("/v1/projects/{project_id}/access/environments/{environment_id}"),
                body: b"env genesis".to_vec(),
                peer_addr: None,
            },
        );
        assert_eq!(first.status, 201);

        let second = handle_http_request(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Put,
                path: format!(
                    "/v1/projects/{project_id}/access/environments/{other_environment_id}"
                ),
                body: b"env genesis".to_vec(),
                peer_addr: None,
            },
        );
        assert_eq!(second.status, 413);
        assert!(String::from_utf8_lossy(&second.body).contains("limit is 1"));
    }

    #[test]
    fn signed_request_payload_limit_returns_413() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, revision_id) = ids();
        let context = SignedRequestContext {
            project_id: project_id.clone(),
            signing_keypair: SigningKeyPair::generate(),
            device_id: DeviceId::new_unchecked_for_test(
                "nk4bzt42f6dmnt5lgw5pimjmcfzu6tsdj2yayhgpzvf5vw6d2rba",
            ),
        };
        let path = format!(
            "/v1/projects/{}/environments/{}/revisions/{}",
            project_id, environment_id, revision_id
        );

        let response = handle_http_request_with_limits(
            &store,
            signed_request(
                &context,
                HttpMethod::Put,
                &path,
                vec![0u8; 32],
                1_755_878_401,
                b"first request nonce",
            ),
            &RelayHttpLimits {
                max_header_bytes: 1024,
                max_body_bytes: 4096,
                max_authorization_bytes: 4096,
                max_request_payload_bytes: 4,
            },
        );

        assert_eq!(response.status, 413);
    }

    #[test]
    fn rate_limiter_rejects_requests_after_limit() {
        let mut limiter = RelayRateLimiter::new(1);
        let peer: SocketAddr = "127.0.0.1:12345".parse().expect("peer");

        assert!(limiter.allow(peer));
        assert!(!limiter.allow(peer));
    }

    #[test]
    fn observed_handler_records_metrics_and_serves_metrics_endpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let mut metrics = RelayMetrics::default();

        let health = handle_http_request_observed(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Get,
                path: "/healthz".to_string(),
                body: Vec::new(),
                peer_addr: None,
            },
            &RelayHttpLimits::default(),
            &mut metrics,
        );
        assert_eq!(health.status, 200);

        let metrics_response = handle_http_request_observed(
            &store,
            RelayHttpRequest {
                method: HttpMethod::Get,
                path: "/metrics".to_string(),
                body: Vec::new(),
                peer_addr: None,
            },
            &RelayHttpLimits::default(),
            &mut metrics,
        );
        assert_eq!(metrics_response.status, 200);
        let body = String::from_utf8(metrics_response.body).expect("metrics body");
        assert!(body.contains("keyit_relay_requests_total 1"));
        assert!(body.contains("keyit_relay_responses_total{status=\"200\"} 1"));
    }

    #[test]
    fn relay_revision_envelope_round_trips_canonical_bytes() {
        let (project_id, environment_id, revision_id) = ids();
        let envelope = RelayRevisionEnvelope {
            project_id,
            environment_id,
            revision_id,
            parent_revision_id: None,
            revision_metadata: b"metadata".to_vec(),
            encrypted_payload: b"payload".to_vec(),
        };

        let encoded = envelope.encode();
        assert!(encoded.starts_with(RelayRevisionEnvelope::MAGIC));
        assert_eq!(
            RelayRevisionEnvelope::decode(&encoded).expect("decode"),
            envelope
        );
    }

    #[test]
    fn checked_publish_rejects_stale_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, first_revision_id) = ids();
        let second_revision_id = RevisionId::new_unchecked_for_test(
            "e6g2ph2r4afg3divn6cm6s3k2oz3zz22ie4zqq6r56ljveqlx7va",
        );

        store
            .publish_revision_checked(
                &project_id,
                &environment_id,
                &first_revision_id,
                None,
                b"first",
                b"payload",
            )
            .expect("first publish");
        let err = store
            .publish_revision_checked(
                &project_id,
                &environment_id,
                &second_revision_id,
                None,
                b"second",
                b"payload",
            )
            .expect_err("stale publish should conflict");
        assert!(matches!(err, RelayStoreError::Conflict { .. }));
    }

    #[test]
    fn http_put_get_and_conflict_use_canonical_envelope() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRelayStore::new(dir.path());
        let (project_id, environment_id, _) = ids();
        let context = SignedRequestContext {
            project_id: project_id.clone(),
            signing_keypair: SigningKeyPair::generate(),
            device_id: DeviceId::new_unchecked_for_test(
                "nk4bzt42f6dmnt5lgw5pimjmcfzu6tsdj2yayhgpzvf5vw6d2rba",
            ),
        };
        let (revision_id, revision_metadata) = signed_revision_metadata(
            &project_id,
            &environment_id,
            &context.device_id,
            &context.signing_keypair,
        );
        let path = format!(
            "/v1/projects/{}/environments/{}/revisions/{}",
            project_id, environment_id, revision_id
        );
        let envelope = RelayRevisionEnvelope {
            project_id: project_id.clone(),
            environment_id: environment_id.clone(),
            revision_id: revision_id.clone(),
            parent_revision_id: None,
            revision_metadata,
            encrypted_payload: b"payload".to_vec(),
        };

        let created = handle_http_request(
            &store,
            signed_request(
                &context,
                HttpMethod::Put,
                &path,
                envelope.encode(),
                1_755_878_401,
                b"first request nonce",
            ),
        );
        assert_eq!(created.status, 201);

        let conflict = handle_http_request(
            &store,
            signed_request(
                &context,
                HttpMethod::Put,
                &path,
                envelope.encode(),
                1_755_878_402,
                b"second request nonce",
            ),
        );
        assert_eq!(conflict.status, 409);

        let fetched = handle_http_request(
            &store,
            signed_request(
                &context,
                HttpMethod::Get,
                &format!(
                    "/v1/projects/{}/environments/{}/revisions/latest",
                    project_id, environment_id
                ),
                Vec::new(),
                1_755_878_403,
                b"third request nonce",
            ),
        );
        assert_eq!(fetched.status, 200);
        assert_eq!(
            RelayRevisionEnvelope::decode(&fetched.body).expect("decode"),
            envelope
        );
    }
}
