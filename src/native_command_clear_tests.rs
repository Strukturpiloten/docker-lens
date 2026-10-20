//! Command/entrypoint clear source effects; never catalogue admission or execution API.

use super::*;

const CONTRACT: &str = "command-clear-v1";
const FILENAME: &str = "command-clear-v1.json";
const CASE_NAMES: [&str; 4] = [
    "image_defaults",
    "entrypoint_inherit",
    "command_clear",
    "entrypoint_clear",
];
const IMAGE_ENTRY: &str = "/dl-image-entrypoint";
const EXPLICIT_ENTRY: &str = "/dl-explicit-entrypoint";
const COMMAND: &str = "/dl-command-process";
const MARKER: &str = "/tmp/dl-command-marker";
const PROBE: &str = "#!/bin/sh\n[ \"$$\" -eq 1 ] || exit 43\nprintf '%s\\n' \"$0\" \"$@\" > /tmp/dl-command-marker\nwhile :; do sleep 1; done\n";
const SEED: usize = 8;

fn empty_variant(value: &Value) -> Option<&'static str> {
    if value.is_null() {
        Some("null")
    } else if value == &json!([]) {
        Some("empty_array")
    } else {
        None
    }
}

fn vectors(case: usize) -> (Vec<&'static str>, Vec<&'static str>) {
    match case {
        0 => (vec![IMAGE_ENTRY], vec!["image-command"]),
        1 | 2 => (vec![EXPLICIT_ENTRY], vec![]),
        3 => (vec![], vec![COMMAND, "explicit-command"]),
        _ => panic!("closed command case"),
    }
}

fn invocation(case: usize) -> Vec<&'static str> {
    let (entrypoint, command) = vectors(case);
    entrypoint.into_iter().chain(command).collect()
}

fn process_argv(case: usize) -> Vec<&'static str> {
    std::iter::once("/bin/sh").chain(invocation(case)).collect()
}

fn marker(case: usize) -> String {
    format!("{}\n", invocation(case).join("\n"))
}

fn seed_script() -> String {
    // Escape the fixed body as one shell argument; JSON quoting is not shell quoting.
    let script = PROBE.replace('\'', "'\\''");
    format!(
        "set -eu; printf '%s' '{}' > {IMAGE_ENTRY}; chmod 0755 {IMAGE_ENTRY}; cp {IMAGE_ENTRY} {EXPLICIT_ENTRY}; cp {IMAGE_ENTRY} {COMMAND}",
        script
    )
}

struct CommandRun {
    native: HealthRun,
    cleanup_attempted: bool,
    cleanup_verified: bool,
}

impl CommandRun {
    fn new() -> Self {
        let mut native = HealthRun::new_for(
            "NATIVE_COMMAND_CLEAR_CANDIDATE_SHA",
            "NATIVE_COMMAND_CLEAR_DEADLINE_EPOCH",
        );
        native.cleanup_delegated = true;
        let mut owned = Self {
            native,
            cleanup_attempted: false,
            cleanup_verified: false,
        };
        let run = &mut owned.native;
        run.names = CASE_NAMES
            .into_iter()
            .flat_map(|case| {
                ["oracle", "rendered"].map(|role| format!("dl-command-{}-{case}-{role}", run.run))
            })
            .chain(std::iter::once(format!("dl-command-{}-seed", run.run)))
            .collect();
        run.derived_tag = format!("dl-command-clear-{}:fixture", run.run.to_ascii_lowercase());
        owned
    }

    fn image_for(&self, index: usize) -> &str {
        if index == SEED {
            &self.native.base
        } else {
            self.native
                .derived_id
                .as_deref()
                .unwrap_or_else(|| panic!("bound command image"))
        }
    }

    fn owned(&self, value: &Value, index: usize, expected_id: Option<&str>) -> bool {
        value["Id"]
            .as_str()
            .is_some_and(|id| identifier(id) && expected_id.is_none_or(|expected| id == expected))
            && value["Name"] == format!("/{}", self.native.names[index])
            && value["Config"]["Image"] == self.image_for(index)
            && value["Config"]["Labels"][OWNER] == self.native.run
    }

    fn bind(&mut self, index: usize, id: &str) {
        assert!(identifier(id), "canonical command fixture ID");
        let (status, value) = self.native.inspect(&self.native.names[index], false);
        assert!(
            status == 200 && self.owned(&value, index, Some(id)),
            "command fixture binding"
        );
        assert!(
            self.native.ids.iter().flatten().all(|other| other != id),
            "unique command fixture"
        );
        self.native.ids[index] = Some(id.to_owned());
    }

    fn image_owned(&self, image: &Value, expected_id: Option<&str>) -> bool {
        image["Id"].as_str().is_some_and(|id| {
            image_identifier(id) && expected_id.is_none_or(|expected| id == expected)
        }) && image["RepoTags"] == json!([self.native.derived_tag])
            && image["Config"]["Labels"][OWNER] == self.native.run
            && image["Config"]["Entrypoint"] == json!([IMAGE_ENTRY])
            && image["Config"]["Cmd"] == json!(["image-command"])
    }

    fn derive(&mut self, base_id: &Value) {
        let run = &self.native;
        assert_eq!(
            run.api(
                "GET",
                &format!("/v{}/images/{}/json", run.api, run.derived_tag),
                None,
                false
            )
            .0,
            404
        );
        assert_eq!(run.inspect(&run.names[SEED], false).0, 404);
        self.native.attempted[SEED] = true;
        let output = self.native.docker(
            &[
                "create".into(),
                "--name".into(),
                self.native.names[SEED].clone(),
                "--label".into(),
                format!("{OWNER}={}", self.native.run),
                self.native.base.clone(),
                "sh".into(),
                "-c".into(),
                seed_script(),
            ],
            false,
        );
        let id = std::str::from_utf8(&output)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed seed ID"));
        self.bind(SEED, id);
        let id = self.native.ids[SEED].clone().unwrap();
        assert!(
            self.native
                .docker(&["start".into(), "--attach".into(), id.clone()], false)
                .is_empty(),
            "silent bounded seed"
        );
        let (status, seed) = self.native.inspect(&id, false);
        assert!(
            status == 200 && self.owned(&seed, SEED, Some(&id)),
            "seed owner before commit"
        );
        assert_eq!(seed["Image"], *base_id);
        assert_eq!(seed["Config"]["Cmd"], json!(["sh", "-c", seed_script()]));
        assert!(
            seed["State"]["Status"] == "exited"
                && seed["State"]["Running"] == false
                && seed["State"]["ExitCode"] == 0
                && seed["State"]["Error"] == "",
            "seed completed successfully"
        );
        self.native.image_attempted = true;
        let output = self.native.docker(
            &[
                "commit".into(),
                "--change".into(),
                format!("ENTRYPOINT {}", json!([IMAGE_ENTRY])),
                "--change".into(),
                "CMD [\"image-command\"]".into(),
                id,
                self.native.derived_tag.clone(),
            ],
            false,
        );
        let image_id = std::str::from_utf8(&output)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed committed ID"));
        assert!(image_identifier(image_id), "canonical derived image ID");
        let (status, image) = self.native.api(
            "GET",
            &format!(
                "/v{}/images/{}/json",
                self.native.api, self.native.derived_tag
            ),
            None,
            false,
        );
        assert!(
            status == 200 && self.image_owned(&image, Some(image_id)),
            "derived exact defaults and owner"
        );
        self.native.derived_id = Some(image_id.to_owned());
    }

    fn create(&mut self, index: usize) {
        let case = index / 2;
        let run = &self.native;
        assert_eq!(run.inspect(&run.names[index], false).0, 404);
        let image = self.image_for(index).to_owned();
        let id = if index.is_multiple_of(2) {
            let mut args = vec![
                "create".into(),
                "--name".into(),
                run.names[index].clone(),
                "--label".into(),
                format!("{OWNER}={}", run.run),
            ];
            match case {
                0 => {}
                1 | 2 => args.extend(["--entrypoint".into(), EXPLICIT_ENTRY.into()]),
                3 => args.extend(["--entrypoint".into(), String::new()]),
                _ => unreachable!(),
            }
            args.push(image);
            if case == 3 {
                args.extend([COMMAND.into(), "explicit-command".into()]);
            }
            self.native.attempted[index] = true;
            let output = self.native.docker(&args, false);
            std::str::from_utf8(&output)
                .ok()
                .and_then(|s| s.strip_suffix('\n'))
                .unwrap_or_else(|| panic!("closed oracle ID"))
                .to_owned()
        } else {
            let exec = |args: &[&str]| {
                ImageCommand::Exec(
                    args.iter()
                        .map(|value| {
                            Argument::new(value.as_bytes().to_vec())
                                .unwrap_or_else(|_| panic!("typed argument"))
                        })
                        .collect(),
                )
            };
            let container = ContainerIntent {
                reference: ResourceRef::new(1),
                identity: TargetIdentity::new(run.names[index].as_bytes().to_vec())
                    .unwrap_or_else(|_| panic!("typed name")),
                image: ImageReference::new(image.as_bytes().to_vec())
                    .unwrap_or_else(|_| panic!("typed image")),
                environment: vec![],
                ports: vec![],
                mounts: vec![],
                networks: vec![],
                entrypoint: match case {
                    0 => ImageCommand::Inherit,
                    1 | 2 => exec(&[EXPLICIT_ENTRY]),
                    3 => ImageCommand::Clear,
                    _ => unreachable!(),
                },
                command: match case {
                    0 | 1 => ImageCommand::Inherit,
                    2 => ImageCommand::Clear,
                    3 => exec(&[COMMAND, "explicit-command"]),
                    _ => unreachable!(),
                },
                healthcheck: None,
                restart: None,
                settings: ContainerSettings {
                    labels: vec![
                        ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                            .unwrap_or_else(|_| panic!("typed owner")),
                    ],
                    ..ContainerSettings::default()
                },
            };
            let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))])
                .unwrap_or_else(|_| panic!("command intent"));
            let caps = ValidatedCapabilities::new(run.facts.as_ref().unwrap())
                .unwrap_or_else(|_| panic!("scoped facts"));
            let graph = DockerPlanner
                .plan(&intent, &caps)
                .unwrap_or_else(|_| panic!("command planning"));
            let artifact = DockerApiRenderer
                .render(&graph)
                .unwrap_or_else(|_| panic!("command rendering"));
            let request: Value = serde_json::from_slice(artifact.bytes())
                .unwrap_or_else(|_| panic!("one inert request"));
            let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
            let mut body = json!({"Image":image,"Labels":{(OWNER):run.run},"HostConfig":{}});
            match case {
                0 => {}
                1 => body["Entrypoint"] = json!([EXPLICIT_ENTRY]),
                2 => {
                    body["Entrypoint"] = json!([EXPLICIT_ENTRY]);
                    body["Cmd"] = json!([]);
                }
                3 => {
                    body["Entrypoint"] = json!([]);
                    body["Cmd"] = json!([COMMAND, "explicit-command"]);
                }
                _ => unreachable!(),
            }
            assert_eq!(request, json!({"method":"POST","path":path,"body":body}));
            self.native.attempted[index] = true;
            let (status, created) = self
                .native
                .api("POST", &path, Some(&request["body"]), false);
            assert_eq!(status, 201);
            created["Id"]
                .as_str()
                .unwrap_or_else(|| panic!("closed rendered ID"))
                .to_owned()
        };
        self.bind(index, &id);
    }

    fn configured(&self, index: usize) -> (Value, &'static str, &'static str) {
        let id = self.native.ids[index].as_deref().unwrap();
        let (status, value) = self.native.inspect(id, false);
        assert!(
            status == 200 && self.owned(&value, index, Some(id)),
            "exact command ownership"
        );
        assert_eq!(value["Image"], json!(self.native.derived_id));
        let (entrypoint, command) = vectors(index / 2);
        let variant = |actual: &Value, expected: Vec<&str>| {
            if expected.is_empty() {
                empty_variant(actual).unwrap_or_else(|| panic!("empty effective setting"))
            } else {
                assert_eq!(*actual, json!(expected));
                "exec"
            }
        };
        let entry_variant = variant(
            value["Config"]
                .get("Entrypoint")
                .unwrap_or_else(|| panic!("present native entrypoint")),
            entrypoint,
        );
        let command_variant = variant(
            value["Config"]
                .get("Cmd")
                .unwrap_or_else(|| panic!("present native command")),
            command,
        );
        let argv = invocation(index / 2);
        assert_eq!(value["Path"], argv[0]);
        assert_eq!(value["Args"], json!(&argv[1..]));
        assert_eq!(value["RestartCount"], 0);
        (value, entry_variant, command_variant)
    }

    fn observe(&mut self, index: usize) -> Value {
        let case = index / 2;
        let role = if index.is_multiple_of(2) {
            "oracle"
        } else {
            "rendered"
        };
        eprintln!(
            "DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case={} role={role} stage=create",
            CASE_NAMES[case]
        );
        self.create(index);
        let (before, _, _) = self.configured(index);
        assert_eq!(before["State"]["Status"], "created");
        let id = self.native.ids[index].as_deref().unwrap();
        assert_eq!(
            self.native
                .api(
                    "POST",
                    &format!("/v{}/containers/{id}/start", self.native.api),
                    None,
                    false
                )
                .0,
            204
        );
        eprintln!(
            "DOCKERLENS_NATIVE_COMMAND_CLEAR_STAGE: case={} role={role} stage=effect",
            CASE_NAMES[case]
        );
        let output = self.native.docker(&["exec".into(), id.into(), "sh".into(), "-c".into(),
            format!("for n in 1 2 3 4 5 6 7 8 9 10; do if [ -f {MARKER} ]; then cat {MARKER}; exit 0; fi; sleep 0.2; done; exit 1")], false);
        assert_eq!(output, marker(case).as_bytes());
        let output = self.native.docker(
            &[
                "exec".into(),
                id.into(),
                "cat".into(),
                "/proc/1/cmdline".into(),
            ],
            false,
        );
        let expected = process_argv(case)
            .iter()
            .flat_map(|arg| arg.as_bytes().iter().copied().chain(std::iter::once(0)))
            .collect::<Vec<_>>();
        assert_eq!(output, expected);
        let (after, entry_variant, command_variant) = self.configured(index);
        assert!(
            after["State"]["Status"] == "running"
                && after["State"]["Running"] == true
                && after["State"]["Pid"].as_u64().is_some_and(|pid| pid > 0)
                && after["State"]["Restarting"] == false
                && after["State"]["Paused"] == false
                && after["State"]["Dead"] == false
                && after["State"]["OOMKilled"] == false
                && after["State"]["Error"] == "",
            "actual uninterrupted process effect"
        );
        json!({"role":role,"id":id,"name":self.native.names[index],"owner":self.native.run,
            "image":self.native.derived_id,"wire":"passed","entrypoint":after["Config"]["Entrypoint"],
            "command":after["Config"]["Cmd"],"entrypoint_variant":entry_variant,"command_variant":command_variant,
            "path":after["Path"],"args":after["Args"],"process_argv":process_argv(case),"marker":marker(case),
            "state":"running","running":true,"restart_count":0,"cleanup":"absent"})
    }

    fn remove_container(&mut self, index: usize) -> bool {
        let run = &self.native;
        let (status, value) = run.inspect(&run.names[index], true);
        if status == 404 {
            return run.ids[index].is_some();
        }
        if status != 200 || !self.owned(&value, index, run.ids[index].as_deref()) {
            return false;
        }
        let id = value["Id"].as_str().unwrap().to_owned();
        if run
            .ids
            .iter()
            .enumerate()
            .any(|(other, known)| other != index && known.as_deref() == Some(&id))
        {
            return false;
        }
        self.native.ids[index] = Some(id.clone());
        let (status, value) = self.native.inspect(&id, true);
        if status != 200 || !self.owned(&value, index, Some(&id)) {
            return false;
        }
        self.native
            .api(
                "DELETE",
                &format!("/v{}/containers/{id}?force=1", self.native.api),
                None,
                true,
            )
            .0
            == 204
            && self.native.inspect(&id, true).0 == 404
            && self.native.inspect(&self.native.names[index], true).0 == 404
    }

    fn cleanup_inner(&mut self) -> bool {
        let mut verified = true;
        for index in 0..self.native.names.len() {
            if self.native.attempted[index] {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.remove_container(index)
                }))
                .unwrap_or(false);
            }
        }
        if verified && self.native.image_attempted {
            let run = &self.native;
            let (status, image) = run.api(
                "GET",
                &format!("/v{}/images/{}/json", run.api, run.derived_tag),
                None,
                true,
            );
            verified &= if status == 404 {
                run.derived_id.is_some()
            } else if status == 200 && self.image_owned(&image, run.derived_id.as_deref()) {
                let id = image["Id"].as_str().unwrap().to_owned();
                self.native.derived_id = Some(id.clone());
                let run = &self.native;
                let (status, check) = run.api(
                    "GET",
                    &format!("/v{}/images/{id}/json", run.api),
                    None,
                    true,
                );
                status == 200
                    && self.image_owned(&check, Some(&id))
                    && run
                        .api(
                            "DELETE",
                            &format!("/v{}/images/{id}?force=0", run.api),
                            None,
                            true,
                        )
                        .0
                        == 200
            } else {
                false
            };
        }
        for _ in 0..2 {
            for index in 0..self.native.names.len() {
                if self.native.attempted[index] {
                    verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.native.ids[index]
                            .as_ref()
                            .is_some_and(|id| self.native.inspect(id, true).0 == 404)
                            && self.native.inspect(&self.native.names[index], true).0 == 404
                    }))
                    .unwrap_or(false);
                }
            }
            if self.native.image_attempted {
                verified &= std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.native.derived_id.as_ref().is_some_and(|id| {
                        self.native
                            .api(
                                "GET",
                                &format!("/v{}/images/{id}/json", self.native.api),
                                None,
                                true,
                            )
                            .0
                            == 404
                    }) && self
                        .native
                        .api(
                            "GET",
                            &format!(
                                "/v{}/images/{}/json",
                                self.native.api, self.native.derived_tag
                            ),
                            None,
                            true,
                        )
                        .0
                        == 404
                }))
                .unwrap_or(false);
            }
        }
        verified
    }

    fn cleanup(&mut self) {
        if self.cleanup_attempted {
            return;
        }
        self.cleanup_attempted = true;
        self.cleanup_verified =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup_inner()))
                .unwrap_or(false);
        if !self.cleanup_verified {
            eprintln!("DOCKERLENS_NATIVE_CHECK: command_clear_cleanup_unverified");
        }
    }
}

impl Drop for CommandRun {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn base_snapshot(run: &HealthRun) -> Value {
    let (status, image) = run.api(
        "GET",
        &format!("/v{}/images/{}/json", run.api, run.base),
        None,
        false,
    );
    assert_eq!(status, 200);
    let digest = run.base.rsplit_once('@').unwrap().1;
    assert!(
        image["Id"].as_str().is_some_and(image_identifier)
            && image["RepoDigests"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item
                    .as_str()
                    .is_some_and(|text| text
                        .rsplit_once('@')
                        .is_some_and(|(_, actual)| actual == digest)))),
        "borrowed pinned image"
    );
    json!({"id":image["Id"],"digests":image["RepoDigests"],"config":image["Config"]})
}

fn outer_snapshot(run: &HealthRun) -> Value {
    let id = required("NATIVE_OUTER_CONTAINER_ID");
    assert!(identifier(&id), "canonical outer ID");
    let image = required("NATIVE_OUTER_IMAGE");
    let digest = image
        .rsplit_once('@')
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("pinned outer image"));
    assert!(image_identifier(digest), "outer digest");
    let elevated = match required("NATIVE_PODMAN_USE_SUDO").as_str() {
        "0" => false,
        "1" => true,
        _ => panic!("closed privilege selector"),
    };
    let mut command = run.timer(false, elevated);
    command.args(["podman", "inspect", "--format", "{{json .}}", &id]);
    let value: Value = serde_json::from_slice(&run.capture(&mut command, None, false))
        .unwrap_or_else(|_| panic!("private outer snapshot"));
    let directory = PathBuf::from(required("NATIVE_CAPTURE_DIR"));
    let mounts = value["Mounts"]
        .as_array()
        .unwrap_or_else(|| panic!("outer mounts"));
    let volumes: Vec<_> = mounts.iter().filter(|m| m["Type"] == "volume").collect();
    let binds: Vec<_> = mounts.iter().filter(|m| m["Type"] == "bind").collect();
    let networks = value["NetworkSettings"]["Networks"]
        .as_object()
        .unwrap_or_else(|| panic!("outer networks"));
    assert!(
        value["Id"] == id
            && value["Name"] == run.outer
            && value["Config"]["Labels"][OWNER] == run.run
            && value["ImageDigest"] == digest
            && value["State"]["Running"] == true
            && value["HostConfig"]["Privileged"] == true
            && value["HostConfig"]["Memory"] == 4294967296_u64
            && value["HostConfig"]["CpuQuota"] == 200000
            && value["HostConfig"]["CpuPeriod"] == 100000
            && value["HostConfig"]["PidsLimit"] == 512
            && mounts.len() == 2
            && volumes.len() == 1
            && binds.len() == 1
            && volumes[0]["Name"] == format!("dl-native-data-{}", run.run)
            && volumes[0]["Destination"]
                == if run.mode == DaemonMode::Rootless {
                    "/home/docker/.local/share/docker"
                } else {
                    "/var/lib/docker"
                }
            && volumes[0]["RW"] == true
            && binds[0]["Source"] == directory.join("socket").to_str().unwrap()
            && binds[0]["Destination"] == "/dockerlens-native"
            && binds[0]["RW"] == true
            && networks.len() == 1
            && networks.contains_key(&format!("dl-native-net-{}", run.run)),
        "bound isolated outer owner"
    );
    json!({"id":id,"name":run.outer,"owner":run.run,"image":image,
        "data_volume":format!("dl-native-data-{}",run.run),"socket_source":directory.join("socket"),
        "privileged":true,"memory_bytes":4294967296_u64,"cpu_quota":200000,"cpu_period":100000,"pids_limit":512})
}

#[test]
#[ignore = "requires isolated exact-profile Docker Engine and authenticated harness"]
fn live_command_clear_matches_engine() {
    let target = ProofTarget::new_for("NATIVE_COMMAND_CLEAR_PROOF_PATH", FILENAME);
    let mut owned = CommandRun::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eprintln!("DOCKERLENS_NATIVE_CHECK: command_clear_context");
        let outer = outer_snapshot(&owned.native);
        let uid = owned.native.context();
        let base = base_snapshot(&owned.native);
        let facts = owned.native.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::CommandClear,
            Capability::Entrypoint,
            Capability::EntrypointClear,
            Capability::ContainerLabels,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: scope.clone(),
        })
        .collect();
        eprintln!("DOCKERLENS_NATIVE_CHECK: command_clear_derive");
        owned.derive(&base["id"]);
        let mut cases = Vec::new();
        for (case, name) in CASE_NAMES.into_iter().enumerate() {
            cases.push(
                json!({"case":name,"containers":[owned.observe(2*case),owned.observe(2*case+1)]}),
            );
        }
        (outer, uid, base, cases)
    }));
    eprintln!("DOCKERLENS_NATIVE_CHECK: command_clear_cleanup");
    owned.cleanup();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    assert!(owned.cleanup_verified, "verified command cleanup required");
    let (outer, uid, base, cases) = result.unwrap_or_else(|_| unreachable!());
    let run = &owned.native;
    assert_eq!(base_snapshot(run), base);
    assert_eq!(outer_snapshot(run), outer);
    let proof = json!({"schema_version":1,"contract":CONTRACT,"context":{
        "candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,
        "rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},
        "mode":if run.mode == DaemonMode::Rootless {"rootless"} else {"rootful"},
        "docker_package":if run.lane.starts_with("debian11-") {"20.10.5+dfsg1-1+deb11u2"} else {""},
        "fixture_image":run.base,"daemon_uid":uid,"outer":outer},"shapes":["ClearCommand","ClearEntrypoint"],
        "borrowed_image":{"id":base["id"],"identity":"unchanged","removal":"not_owned"},
        "derived_image":{"id":run.derived_id,"tag":run.derived_tag,"owner":run.run,"entrypoint":[IMAGE_ENTRY],"command":["image-command"],"cleanup":"absent"},
        "seed":{"id":run.ids[SEED],"name":run.names[SEED],"owner":run.run,"image":run.base,"exit_code":0,"cleanup":"absent"},
        "cases":cases,"cleanup":{"containers":"absent","images":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    eprintln!("DOCKERLENS_NATIVE_CHECK: command_clear_evidence");
    target.publish(&proof);
}

#[test]
fn command_clear_empty_readback_is_closed_and_controls_keep_distinct_defaults() {
    assert_eq!(empty_variant(&Value::Null), Some("null"));
    assert_eq!(empty_variant(&json!([])), Some("empty_array"));
    for bad in [
        json!([""]),
        json!(["image-command"]),
        json!(false),
        json!({}),
        json!(""),
    ] {
        assert!(empty_variant(&bad).is_none());
    }
    assert!(marker(0).contains("image-command"));
    assert_eq!(marker(1), marker(2));
    assert!(!marker(2).contains("image-command"));
    assert!(!marker(3).contains(IMAGE_ENTRY));
    assert!(PROBE.contains("\"$$\" -eq 1") && PROBE.contains("\"$0\" \"$@\""));
}
