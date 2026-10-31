//! Test-only literal argv bridge; caller owns privilege, timer, capture and budgets.

use std::path::Path;

pub(crate) const PODMAN_ENGINE: &str = "podman";

const CONTEXT: &[&str] = &[
    "GITHUB_ACTIONS",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "GITHUB_REF",
    "GITHUB_EVENT_NAME",
    "GITHUB_REPOSITORY",
    "GITHUB_WORKFLOW_REF",
    "ImageOS",
    "ImageVersion",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "DOCKER_API_VERSION",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "CONTAINER_SSHKEY",
    "PODMAN_CONNECTIONS_CONF",
];

pub(crate) fn prefix() -> Vec<String> {
    prefix_with(|key| std::env::var(key).ok())
}

pub(crate) fn context_env() -> Vec<String> {
    context_env_with(|key| std::env::var(key).ok())
}

fn context_env_with(mut lookup: impl FnMut(&str) -> Option<String>) -> Vec<String> {
    // Always placed after the original privilege/timer owner.
    let mut argv = vec!["env".into()];
    for key in CONTEXT {
        argv.push(format!("{key}={}", lookup(key).unwrap_or_default()));
    }
    argv
}

fn prefix_with(mut lookup: impl FnMut(&str) -> Option<String>) -> Vec<String> {
    let engine = lookup("NATIVE_OUTER_ENGINE").unwrap_or_else(|| PODMAN_ENGINE.into());
    assert!(
        matches!(engine.as_str(), PODMAN_ENGINE | "docker"),
        "closed outer engine"
    );
    let directory = lookup("NATIVE_OUTER_RUN_DIRECTORY")
        .unwrap_or_else(|| panic!("explicit private outer run directory"));
    assert!(
        Path::new(&directory).is_absolute(),
        "absolute outer run directory"
    );
    // Assignments occur after the caller's sudo/timeout, never sudo -E or shell
    // serialization. Canonical policy sees the original allowlisted selectors.
    let mut argv = context_env_with(&mut lookup);
    argv.extend([
        "bash".into(),
        format!(
            "{}/scripts/native-outer-command.sh",
            env!("CARGO_MANIFEST_DIR")
        ),
        "--engine".into(),
        engine,
        "--directory".into(),
        directory,
    ]);
    argv
}

pub(crate) fn snapshot_extra_calls() -> usize {
    usize::from(std::env::var("NATIVE_OUTER_ENGINE").as_deref() == Ok("docker"))
}

#[test]
fn literal_context_and_local_default_do_not_select_an_executable_or_shell() {
    assert!(snapshot_extra_calls() <= 1);
    let argv = prefix_with(|key| match key {
        "NATIVE_OUTER_RUN_DIRECTORY" => Some("/tmp/held;not-shell".into()),
        "GITHUB_REF" => Some("refs/heads/main".into()),
        "DOCKER_HOST" => Some("must-reach-policy".into()),
        _ => None,
    });
    assert_eq!(argv[0], "env");
    assert!(argv.contains(&"GITHUB_REF=refs/heads/main".into()));
    assert!(argv.contains(&"DOCKER_HOST=must-reach-policy".into()));
    assert_eq!(
        &argv[argv.len() - 4..],
        ["--engine", "podman", "--directory", "/tmp/held;not-shell"]
    );
    assert!(
        !argv
            .iter()
            .any(|arg| matches!(arg.as_str(), "-c" | "-E" | "podman exec"))
    );
}

#[test]
fn reusable_context_is_the_identical_literal_prefix_for_external_helpers() {
    let lookup = |key: &str| match key {
        "NATIVE_OUTER_ENGINE" => Some("docker".into()),
        "NATIVE_OUTER_RUN_DIRECTORY" => Some("/tmp/held;literal".into()),
        "DOCKER_HOST" => Some("private-selector;not-shell".into()),
        _ => None,
    };
    let context = context_env_with(lookup);
    let prefix = prefix_with(lookup);
    assert_eq!(&prefix[..context.len()], context);
    assert_eq!(context.len(), CONTEXT.len() + 1);
    assert_eq!(context[0], "env");
    assert!(context.contains(&"DOCKER_HOST=private-selector;not-shell".into()));
    assert!(!context.iter().any(|item| item == "-E" || item == "-c"));
    assert_eq!(
        &prefix[prefix.len() - 4..],
        ["--engine", "docker", "--directory", "/tmp/held;literal"]
    );
    assert_eq!(context_env().len(), CONTEXT.len() + 1);
}

#[test]
fn real_builder_crosses_scrubbed_privilege_timer_and_fixed_bridge_without_a_runtime() {
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct PrivateDirectory(std::path::PathBuf);
    impl Drop for PrivateDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove exact private mock directory");
        }
    }
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let private = PrivateDirectory(
        std::env::temp_dir().join(format!("dl-outer-argv-{}-{unique}", std::process::id())),
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&private.0)
        .unwrap();
    let tools = private.0.join("tools");
    fs::DirBuilder::new().mode(0o700).create(&tools).unwrap();
    for tool in ["env", "timeout", "bash", "python3", "dirname"] {
        std::os::unix::fs::symlink(format!("/usr/bin/{tool}"), tools.join(tool)).unwrap();
    }
    let client = private.0.join("docker-client");
    fs::DirBuilder::new().mode(0o700).create(&client).unwrap();
    for name in ["docker", "podman", "sudo"] {
        let body = if name == "sudo" {
            "#!/bin/sh\n[ \"$1\" = -n ] || exit 97\nshift\nexec env -i PATH=\"$PATH\" \"$@\"\n"
        } else {
            "#!/bin/sh\nprintf '%s\\n' \"$@\"\n"
        };
        let path = tools.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let directory = private.0.to_str().unwrap();
    let path = tools.to_str().unwrap();
    for engine in ["podman", "docker"] {
        let argv = prefix_with(|key| {
            Some(
                match key {
                    "NATIVE_OUTER_ENGINE" => engine,
                    "NATIVE_OUTER_RUN_DIRECTORY" => directory,
                    "GITHUB_ACTIONS" => "true",
                    "RUNNER_ENVIRONMENT" => "github-hosted",
                    "RUNNER_OS" => "Linux",
                    "GITHUB_REF" => "refs/heads/main",
                    "GITHUB_EVENT_NAME" => "push",
                    "GITHUB_REPOSITORY" => "Strukturpiloten/docker-lens",
                    "GITHUB_WORKFLOW_REF" => {
                        "Strukturpiloten/docker-lens/.github/workflows/check.yml@refs/heads/main"
                    }
                    "ImageOS" => "ubuntu24",
                    "ImageVersion" => "20261020.1.0",
                    _ => "",
                }
                .into(),
            )
        });
        let id = "a".repeat(64);
        let output = Command::new(tools.join("sudo"))
            .env_clear()
            .env("PATH", path)
            .args(["-n", "timeout", "--signal=TERM", "--kill-after=1s", "4s"])
            .args(&argv)
            .args(["exec", &id, "sh", "-ec", "literal;not-host-shell"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stderr.is_empty());
        let lines: Vec<_> = std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .collect();
        let expected = ["exec", &id, "sh", "-ec", "literal;not-host-shell"];
        if engine == "docker" {
            assert_eq!(
                &lines[..4],
                [
                    "--config",
                    client.to_str().unwrap(),
                    "--host",
                    "unix:///var/run/docker.sock"
                ]
            );
            assert_eq!(&lines[4..], expected);
        } else {
            assert_eq!(lines[0], "--remote=false");
            assert_eq!(&lines[1..], expected);
        }
        assert_eq!(fs::read_dir(&client).unwrap().count(), 0);
        assert!(!private.0.join("outer-runtime.json").exists());
    }
}
