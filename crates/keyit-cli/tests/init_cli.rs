//! Black-box smoke tests for `keyit init`, run against the actual
//! compiled `keyit` binary rather than `keyit_cli`'s library functions.
//!
//! `keyit_cli::init`'s own unit tests (see `src/init.rs`) cover the core
//! initialization logic; this file proves CLI wiring itself (argument
//! parsing, environment variable resolution, exit codes) works
//! end-to-end.
//!
//! `KEYIT_DATA_DIR` is set to an isolated temporary directory for every
//! invocation here so these tests never touch the real `$HOME`.

use std::path::Path;
use std::process::Command;

fn keyit_command(project_root: &Path, data_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_keyit"));
    command
        .current_dir(project_root)
        .env("KEYIT_DATA_DIR", data_dir);
    command
}

fn single_project_state_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir
        .join("projects")
        .read_dir()
        .expect("projects")
        .next()
        .expect("one project")
        .expect("project entry")
        .path()
        .join(".keyit")
}

fn single_environment_dir(data_dir: &Path) -> std::path::PathBuf {
    single_project_state_dir(data_dir)
        .join("environments")
        .read_dir()
        .expect("environments")
        .next()
        .expect("one environment")
        .expect("entry")
        .path()
}

#[test]
fn init_creates_keyit_dir_and_prints_the_project_id() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kvp_"),
        "expected a kvp_ project id in output: {stdout}"
    );
    assert!(project_dir.path().join("keyit.toml").exists());
    assert!(!project_dir.path().join(".keyit").exists());
    assert!(single_project_state_dir(data_dir.path())
        .join("project.toml")
        .exists());
}

#[test]
fn init_without_force_fails_on_second_run() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let first = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("first keyit init should run");
    assert!(first.status.success());

    let second = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("second keyit init should run");
    assert!(!second.status.success());
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already"),
        "expected an already-initialized error, got: {stderr}"
    );
}

#[test]
fn init_with_force_succeeds_on_second_run() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let first = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("first keyit init should run");
    assert!(first.status.success());

    let second = keyit_command(project_dir.path(), data_dir.path())
        .args(["init", "--force"])
        .output()
        .expect("second keyit init should run");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
}

#[test]
fn env_add_creates_environment_metadata_and_prints_environment_id() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let output = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kve_"),
        "expected a kve_ environment id in output: {stdout}"
    );

    let environments_dir = single_project_state_dir(data_dir.path()).join("environments");
    let environment_count = std::fs::read_dir(&environments_dir)
        .expect("environments dir")
        .count();
    assert_eq!(environment_count, 1);
}

#[test]
fn env_add_fails_before_init() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("keyit init"),
        "expected init guidance, got: {stderr}"
    );
}

#[test]
fn relay_check_rejects_non_http_url() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .args(["relay", "check", "--relay-url", "file://relay"])
        .output()
        .expect("keyit relay check should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only http:// and https:// relay URLs are supported"),
        "expected relay URL guidance, got: {stderr}"
    );
}

#[test]
fn env_add_rejects_duplicate_label() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let first = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("first keyit env add should run");
    assert!(first.status.success());

    let second = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.dev"])
        .output()
        .expect("second keyit env add should run");
    assert!(!second.status.success());
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected duplicate-label error, got: {stderr}"
    );
}

#[test]
fn status_reports_local_file_state_without_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\nLOG_LEVEL=debug\n",
    )
    .expect("write dotenv");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .arg("status")
        .output()
        .expect("keyit status should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("development"));
    assert!(stdout.contains("2 keys parsed"));
    assert!(!stdout.contains("super-secret"));
}

#[test]
fn diff_reports_key_names_without_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\nLOG_LEVEL=debug\n",
    )
    .expect("write dotenv");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .arg("diff")
        .output()
        .expect("keyit diff should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("added      API_KEY"));
    assert!(stdout.contains("added      LOG_LEVEL"));
    assert!(!stdout.contains("super-secret"));
}

#[test]
fn push_creates_local_encrypted_revision_without_printing_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .args(["init", "--relay-url", "file://local-test-relay"])
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\nLOG_LEVEL=debug\n",
    )
    .expect("write dotenv");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .args(["push", "development"])
        .output()
        .expect("keyit push should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Created local encrypted revision"));
    assert!(!stdout.contains("super-secret"));

    let payloads_dir = single_environment_dir(data_dir.path()).join("payloads");
    let payload_count = std::fs::read_dir(&payloads_dir)
        .expect("payloads dir")
        .count();
    assert_eq!(payload_count, 1);
    for entry in std::fs::read_dir(payloads_dir).expect("payloads dir") {
        let payload = std::fs::read(entry.expect("payload entry").path()).expect("read payload");
        assert!(!String::from_utf8_lossy(&payload).contains("super-secret"));
    }
}

#[test]
fn diff_after_push_reports_modified_removed_and_added_keys_without_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .args(["init", "--relay-url", "file://local-test-relay"])
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\nLOG_LEVEL=debug\n",
    )
    .expect("write dotenv");
    let push = keyit_command(project_dir.path(), data_dir.path())
        .args(["push", "development"])
        .output()
        .expect("keyit push should run");
    assert!(push.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=changed-secret\nNEW_KEY=value\n",
    )
    .expect("write dotenv");
    let diff = keyit_command(project_dir.path(), data_dir.path())
        .args(["diff", "development"])
        .output()
        .expect("keyit diff should run");
    assert!(
        diff.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&diff.stderr)
    );

    let stdout = String::from_utf8_lossy(&diff.stdout);
    assert!(stdout.contains("modified   API_KEY"));
    assert!(stdout.contains("removed    LOG_LEVEL"));
    assert!(stdout.contains("added      NEW_KEY"));
    assert!(!stdout.contains("super-secret"));
    assert!(!stdout.contains("changed-secret"));
}

#[test]
fn pull_materializes_latest_local_revision() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .args(["init", "--relay-url", "file://local-test-relay"])
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\nLOG_LEVEL=debug\n",
    )
    .expect("write dotenv");
    let push = keyit_command(project_dir.path(), data_dir.path())
        .args(["push", "development"])
        .output()
        .expect("keyit push should run");
    assert!(push.status.success());

    std::fs::remove_file(project_dir.path().join(".env.local")).expect("remove dotenv");
    let pull = keyit_command(project_dir.path(), data_dir.path())
        .args(["pull", "development"])
        .output()
        .expect("keyit pull should run");
    assert!(
        pull.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let stdout = String::from_utf8_lossy(&pull.stdout);
    assert!(stdout.contains("Materialized local revision"));
    assert!(!stdout.contains("super-secret"));

    let materialized =
        std::fs::read_to_string(project_dir.path().join(".env.local")).expect("read dotenv");
    assert!(materialized.contains("API_KEY=super-secret"));
    assert!(materialized.contains("LOG_LEVEL=debug"));
}

#[test]
fn pull_rejects_local_changes_unless_forced() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .args(["init", "--relay-url", "file://local-test-relay"])
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\n",
    )
    .expect("write dotenv");
    let push = keyit_command(project_dir.path(), data_dir.path())
        .args(["push", "development"])
        .output()
        .expect("keyit push should run");
    assert!(push.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=local-edit\n",
    )
    .expect("edit dotenv");
    let blocked = keyit_command(project_dir.path(), data_dir.path())
        .args(["pull", "development"])
        .output()
        .expect("keyit pull should run");
    assert!(!blocked.status.success());
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(stderr.contains("would overwrite local changes"));
    assert!(!stderr.contains("super-secret"));
    assert!(!stderr.contains("local-edit"));

    let forced = keyit_command(project_dir.path(), data_dir.path())
        .args(["pull", "development", "--force"])
        .output()
        .expect("keyit pull --force should run");
    assert!(
        forced.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let materialized =
        std::fs::read_to_string(project_dir.path().join(".env.local")).expect("read dotenv");
    assert!(materialized.contains("API_KEY=super-secret"));
}

#[test]
fn push_with_relay_dir_publishes_encrypted_revision_without_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");
    let relay_dir = tempfile::tempdir().expect("relay tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\nLOG_LEVEL=debug\n",
    )
    .expect("write dotenv");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .args([
            "push",
            "development",
            "--relay-dir",
            relay_dir.path().to_str().expect("relay path"),
        ])
        .output()
        .expect("keyit push should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("relay revision"));
    assert!(!stdout.contains("super-secret"));

    let payloads: Vec<_> = relay_dir
        .path()
        .join("projects")
        .read_dir()
        .expect("relay projects")
        .flat_map(|project| {
            project
                .expect("relay project")
                .path()
                .join("environments")
                .read_dir()
                .expect("relay environments")
        })
        .flat_map(|environment| {
            environment
                .expect("relay environment")
                .path()
                .join("payloads")
                .read_dir()
                .expect("relay payloads")
        })
        .map(|entry| entry.expect("relay payload").path())
        .collect();
    assert_eq!(payloads.len(), 1);
    let payload = std::fs::read(&payloads[0]).expect("read relay payload");
    assert!(!String::from_utf8_lossy(&payload).contains("super-secret"));
}

#[test]
fn pull_with_relay_dir_fetches_and_materializes_latest_revision() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");
    let relay_dir = tempfile::tempdir().expect("relay tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\nLOG_LEVEL=debug\n",
    )
    .expect("write dotenv");
    let push = keyit_command(project_dir.path(), data_dir.path())
        .args([
            "push",
            "development",
            "--relay-dir",
            relay_dir.path().to_str().expect("relay path"),
        ])
        .output()
        .expect("keyit push should run");
    assert!(push.status.success());

    let environment_dir = single_environment_dir(data_dir.path());
    std::fs::remove_file(project_dir.path().join(".env.local")).expect("remove dotenv");
    std::fs::remove_dir_all(environment_dir.join("revisions")).expect("remove local revisions");
    std::fs::remove_dir_all(environment_dir.join("payloads")).expect("remove local payloads");
    std::fs::remove_file(environment_dir.join("latest.toml")).expect("remove latest pointer");

    let pull = keyit_command(project_dir.path(), data_dir.path())
        .args([
            "pull",
            "development",
            "--relay-dir",
            relay_dir.path().to_str().expect("relay path"),
        ])
        .output()
        .expect("keyit pull should run");
    assert!(
        pull.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let stdout = String::from_utf8_lossy(&pull.stdout);
    assert!(stdout.contains("fetched latest encrypted revision"));
    assert!(!stdout.contains("super-secret"));

    let materialized =
        std::fs::read_to_string(project_dir.path().join(".env.local")).expect("read dotenv");
    assert!(materialized.contains("API_KEY=super-secret"));
    assert!(materialized.contains("LOG_LEVEL=debug"));
}

#[test]
fn whoami_reports_device_identity_without_secret_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .arg("init")
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\n",
    )
    .expect("write dotenv");

    let output = keyit_command(project_dir.path(), data_dir.path())
        .arg("whoami")
        .output()
        .expect("keyit whoami should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Project"));
    assert!(stdout.contains("Device kvd_"));
    assert!(stdout.contains("active member:          yes"));
    assert!(stdout.contains("accessible environments: 1"));
    assert!(stdout.contains("signing public key:"));
    assert!(stdout.contains("encryption public key:"));
    assert!(!stdout.contains("super-secret"));
}

#[test]
fn env_list_reports_revision_pointers_without_secret_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .args(["init", "--relay-url", "file://local-test-relay"])
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\n",
    )
    .expect("write dotenv");
    let push = keyit_command(project_dir.path(), data_dir.path())
        .args(["push", "development"])
        .output()
        .expect("keyit push should run");
    assert!(push.status.success());

    let output = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "list"])
        .output()
        .expect("keyit env list should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Environment development (kve_"));
    assert!(stdout.contains("latest:       kvr_"));
    assert!(stdout.contains("materialized: kvr_"));
    assert!(!stdout.contains("super-secret"));
}

#[test]
fn revision_list_reports_history_without_secret_values() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let data_dir = tempfile::tempdir().expect("data tempdir");

    let init = keyit_command(project_dir.path(), data_dir.path())
        .args(["init", "--relay-url", "file://local-test-relay"])
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    std::fs::write(
        project_dir.path().join(".env.local"),
        "API_KEY=super-secret\n",
    )
    .expect("write dotenv");
    let push = keyit_command(project_dir.path(), data_dir.path())
        .args(["push", "development", "--summary", "initial local demo"])
        .output()
        .expect("keyit push should run");
    assert!(push.status.success());

    let output = keyit_command(project_dir.path(), data_dir.path())
        .args(["revision", "list", "development"])
        .output()
        .expect("keyit revision list should run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Revisions for development (kve_"));
    assert!(stdout.contains("Revision kvr_"));
    assert!(stdout.contains("parent:     none"));
    assert!(stdout.contains("author:     kvd_"));
    assert!(stdout.contains("summary:    initial local demo"));
    assert!(!stdout.contains("super-secret"));
}

#[test]
fn invite_join_approve_flow_creates_signed_access_records() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let owner_data_dir = tempfile::tempdir().expect("owner data tempdir");
    let joining_data_dir = tempfile::tempdir().expect("joining data tempdir");

    let init = keyit_command(project_dir.path(), owner_data_dir.path())
        .args(["init", "--relay-url", "file://local-access-test"])
        .output()
        .expect("keyit init should run");
    assert!(init.status.success());

    let env_add = keyit_command(project_dir.path(), owner_data_dir.path())
        .args(["env", "add", "development", ".env.local"])
        .output()
        .expect("keyit env add should run");
    assert!(env_add.status.success());

    let invite = keyit_command(project_dir.path(), owner_data_dir.path())
        .args([
            "invite",
            "create",
            "--env",
            "development",
            "--expires-at",
            "9999999999",
            "--max-uses",
            "1",
        ])
        .output()
        .expect("keyit invite create should run");
    assert!(
        invite.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&invite.stderr)
    );
    let invite_stdout = String::from_utf8_lossy(&invite.stdout);
    let invite_id = invite_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Created invite "))
        .expect("invite id");
    assert!(invite_id.starts_with("kvi_"));
    let invite_bundle = invite_stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("bundle:").map(str::trim))
        .expect("invite bundle");

    let join = keyit_command(project_dir.path(), joining_data_dir.path())
        .args(["join", invite_bundle, "--device-label", "workstation"])
        .output()
        .expect("keyit join should run");
    assert!(
        join.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&join.stderr)
    );
    let join_stdout = String::from_utf8_lossy(&join.stdout);
    let joining_device_id = join_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Created join request for "))
        .expect("joining device id");
    assert!(joining_device_id.starts_with("kvd_"));
    let join_request_path = single_project_state_dir(joining_data_dir.path())
        .join("join-requests")
        .join(format!("{joining_device_id}.keyit"));
    let owner_join_request_path = single_project_state_dir(owner_data_dir.path())
        .join("join-requests")
        .join(format!("{joining_device_id}.keyit"));
    std::fs::create_dir_all(
        owner_join_request_path
            .parent()
            .expect("join request parent"),
    )
    .expect("create owner join request dir");
    std::fs::copy(&join_request_path, &owner_join_request_path).expect("copy join request");

    let approve = keyit_command(project_dir.path(), owner_data_dir.path())
        .args(["approve", joining_device_id, "--role", "member"])
        .output()
        .expect("keyit approve should run");
    assert!(
        approve.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&approve.stderr)
    );
    let approve_stdout = String::from_utf8_lossy(&approve.stdout);
    assert!(approve_stdout.contains("Approved device"));

    let owner_state_dir = single_project_state_dir(owner_data_dir.path());
    let invite_files = std::fs::read_dir(owner_state_dir.join("invites"))
        .expect("invites")
        .map(|entry| entry.expect("invite entry").path())
        .collect::<Vec<_>>();
    assert_eq!(invite_files.len(), 2);
    assert!(invite_files
        .iter()
        .any(|path| path.extension().is_some_and(|ext| ext == "keyit")));
    assert!(invite_files
        .iter()
        .any(|path| path.extension().is_some_and(|ext| ext == "bundle")));
    assert_eq!(
        std::fs::read_dir(owner_state_dir.join("join-requests"))
            .expect("join requests")
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_dir(owner_state_dir.join("approvals"))
            .expect("approvals")
            .count(),
        1
    );
}
