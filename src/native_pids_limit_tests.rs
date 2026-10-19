//! Private pids-limit-v2 coordinate evidence, registered as native source invocation 27.
//! Fresh native qualification remains pending; this wiring does not claim native support.
//! Coordinate agreement does not authenticate the still-unproved outer controller boundary.
//! Only disposable owned fixtures mutate.
//! No report, synthetic oracle, or test-local capability fact admits a catalogue group.
//! The private anonymous-stdin context reserves existing producer resources;
//! source records are independently validated by Python, never treated as an
//! authority merely because Rust parsed them. Every actual observer rechecks
//! the original PID1 and controller root before using native membership rows.

use super::*;
use crate::acquisition::ReadRequest;
use crate::observation::{Availability, Origin};
use crate::target::PidsLimit;

const PIDS_CONTRACT: &str = "pids-limit-v2";
const PIDS_FILENAME: &str = "pids-limit-v2.json";
const PIDS_SCOPE: &str = "finite16_finite64_unlimited_32_child_attempts_only";
const PIDS_CASES: [(&str, i64); 3] = [("finite16", 16), ("finite64", 64), ("unlimited", -1)];
const PIDS_CAPTURE_CALLS: usize = 16;
const PIDS_CAPTURE_BYTES: usize = 512 * 1024;
const PIDS_PROOF_BYTES: usize = 16 * 1024;
// The existing 1 KiB reserve contains only the closed original-boundary tuple.
const PIDS_OUTER_BINDING_RESERVE: usize = 1024;
const PIDS_CONTEXT_BYTES: usize = 131072;

fn pids_keys(value: &Value, keys: &[&str]) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("private context object"));
    assert!(
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        "closed private context keys"
    );
}

// serde_json's Value accepts repeated object keys. Scan the already valid JSON
// recursively and reject duplicates at every depth, including opaque sources.
fn pids_unique_json(bytes: &[u8]) -> Value {
    fn space(bytes: &[u8], at: &mut usize) {
        while bytes.get(*at).is_some_and(u8::is_ascii_whitespace) {
            *at += 1;
        }
    }
    fn string(bytes: &[u8], at: &mut usize) -> String {
        let start = *at;
        *at += 1;
        loop {
            match bytes[*at] {
                b'\\' => *at += 2,
                b'"' => {
                    *at += 1;
                    break;
                }
                _ => *at += 1,
            }
        }
        serde_json::from_slice(&bytes[start..*at]).unwrap_or_else(|_| panic!("private JSON string"))
    }
    fn item(bytes: &[u8], at: &mut usize) {
        space(bytes, at);
        match bytes[*at] {
            b'{' => {
                *at += 1;
                let mut keys = BTreeSet::new();
                loop {
                    space(bytes, at);
                    if bytes[*at] == b'}' {
                        *at += 1;
                        break;
                    }
                    assert!(
                        keys.insert(string(bytes, at)),
                        "unique private context keys"
                    );
                    space(bytes, at);
                    *at += 1; // colon, validated by serde_json
                    item(bytes, at);
                    space(bytes, at);
                    if bytes[*at] == b',' {
                        *at += 1;
                    }
                }
            }
            b'[' => {
                *at += 1;
                loop {
                    space(bytes, at);
                    if bytes[*at] == b']' {
                        *at += 1;
                        break;
                    }
                    item(bytes, at);
                    space(bytes, at);
                    if bytes[*at] == b',' {
                        *at += 1;
                    }
                }
            }
            b'"' => {
                string(bytes, at);
            }
            _ => {
                while bytes
                    .get(*at)
                    .is_some_and(|byte| !byte.is_ascii_whitespace() && !b",]}".contains(byte))
                {
                    *at += 1;
                }
            }
        }
    }
    let value = serde_json::from_slice(bytes).unwrap_or_else(|_| panic!("private context JSON"));
    item(bytes, &mut 0);
    value
}

struct PidsPrivateContext {
    value: Value,
    limits: [[usize; 2]; 2],
    deadline: Instant,
    timing: PrivateCaptureTiming,
    input_bytes: usize,
}

impl PidsPrivateContext {
    fn stdin() -> Self {
        use std::os::unix::fs::FileTypeExt;
        let link =
            fs::read_link("/proc/self/fd/0").unwrap_or_else(|_| panic!("private context pipe"));
        assert!(
            link.to_str()
                .is_some_and(|link| link.starts_with("pipe:[") && link.ends_with(']'))
                && fs::metadata("/proc/self/fd/0")
                    .is_ok_and(|metadata| metadata.file_type().is_fifo()),
            "anonymous private context stdin"
        );
        struct Input {
            cutoff: Instant,
            source: File,
        }
        impl Read for Input {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                loop {
                    if Instant::now() >= self.cutoff {
                        return Err(std::io::ErrorKind::TimedOut.into());
                    }
                    match self.source.read(buffer) {
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        result => return result,
                    }
                }
            }
        }
        let epoch = required("NATIVE_PIDS_LIMIT_DEADLINE_EPOCH")
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("private context cutoff"));
        let remaining = (UNIX_EPOCH + Duration::from_secs(epoch))
            .duration_since(SystemTime::now())
            .ok()
            .and_then(|remaining| remaining.checked_sub(Duration::from_secs(46)))
            .unwrap_or_else(|| panic!("private context reserve"));
        let cutoff = Instant::now() + remaining.min(Duration::from_secs(134));
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/proc/self/fd/0")
            .unwrap_or_else(|_| panic!("private nonblocking context pipe"));
        Self::read(Input { cutoff, source })
    }

    fn read(source: impl Read) -> Self {
        let mut bytes = Vec::new();
        source
            .take((PIDS_CONTEXT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .unwrap_or_else(|_| panic!("private context read"));
        assert!(
            !bytes.is_empty() && bytes.len() <= PIDS_CONTEXT_BYTES,
            "bounded private context"
        );
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Self {
        // Anchor before sampling CLOCK_MONOTONIC: conversion and parsing time
        // can only shorten the original deadline, never renew its remainder.
        let anchor = Instant::now();
        let now_ns = private_monotonic_ns();
        let context = Self::parse_at(bytes, anchor, now_ns);
        context.require_active(false);
        context
    }

    fn parse_at(bytes: &[u8], anchor: Instant, now_ns: u64) -> Self {
        assert!(
            !bytes.is_empty() && bytes.len() <= PIDS_CONTEXT_BYTES,
            "bounded private context"
        );
        let value = pids_unique_json(bytes);
        pids_keys(
            &value,
            &[
                "schema_version",
                "contract",
                "binding",
                "source",
                "boundary",
                "pids",
            ],
        );
        assert!(
            value["schema_version"].as_u64() == Some(1)
                && value["contract"] == "outer-private-context-v1",
            "private context version"
        );
        let binding = &value["binding"];
        pids_keys(
            binding,
            &[
                "session",
                "execution_origin",
                "candidate_sha",
                "ci_run_id",
                "ci_run_attempt",
                "owner",
                "lane",
                "outer_id",
                "intent_digest",
                "expectation_digest",
            ],
        );
        for key in ["session", "outer_id", "intent_digest", "expectation_digest"] {
            assert!(
                binding[key].as_str().is_some_and(identifier),
                "private context digest"
            );
        }
        assert!(
            binding["candidate_sha"]
                .as_str()
                .is_some_and(|text| text.len() == 40
                    && text
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())),
            "private context candidate"
        );
        match binding["execution_origin"].as_str() {
            Some("github_actions") => {
                for key in ["ci_run_id", "ci_run_attempt"] {
                    assert!(
                        binding[key]
                            .as_str()
                            .is_some_and(|text| (1..=20).contains(&text.len())
                                && !text.starts_with('0')
                                && text.bytes().all(|byte| byte.is_ascii_digit())),
                        "private CI identity"
                    );
                }
            }
            Some("local_process") => assert!(
                binding["ci_run_id"].is_null() && binding["ci_run_attempt"].is_null(),
                "private local identity"
            ),
            _ => panic!("closed private execution origin"),
        }
        assert!(
            binding["owner"].as_str().is_some_and(
                |text| text.len() == 8 && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
            ),
            "private context owner"
        );
        assert!(
            matches!(
                binding["lane"].as_str(),
                Some(
                    "debian11-rootful"
                        | "debian11-rootless"
                        | "upstream-rootful"
                        | "upstream-rootless"
                )
            ),
            "private context lane"
        );
        pids_keys(
            &value["source"],
            &["intent", "preflight", "database", "oci", "log"],
        );
        assert!(
            value["source"]
                .as_object()
                .unwrap()
                .values()
                .all(Value::is_object),
            "private opaque source records"
        );
        let pids = &value["pids"];
        pids_keys(
            pids,
            &[
                "start_ns",
                "deadline_ns",
                "deadline_epoch",
                "producer_reservation",
                "external_reservation",
            ],
        );
        let start = pids["start_ns"]
            .as_u64()
            .filter(|number| *number > 0)
            .unwrap_or_else(|| panic!("private start"));
        let end = pids["deadline_ns"]
            .as_u64()
            .unwrap_or_else(|| panic!("private deadline"));
        let timing = PrivateCaptureTiming {
            start_ns: start,
            deadline_ns: end,
        };
        assert!(
            timing.remaining(now_ns, false).is_some(),
            "original private admission deadline"
        );
        pids["deadline_epoch"]
            .as_u64()
            .filter(|number| *number > 0)
            .unwrap_or_else(|| panic!("private epoch"));
        let remaining = timing
            .remaining(now_ns, true)
            .unwrap_or_else(|| panic!("original private deadline"));
        let allocation = |name: &str| {
            let record = &pids[name];
            pids_keys(
                record,
                &[
                    "ordinary_calls",
                    "ordinary_bytes",
                    "cleanup_calls",
                    "cleanup_bytes",
                ],
            );
            let number = |key: &str| {
                usize::try_from(
                    record[key]
                        .as_u64()
                        .unwrap_or_else(|| panic!("private allocation integer")),
                )
                .unwrap_or_else(|_| panic!("private allocation size"))
            };
            [
                [number("ordinary_calls"), number("ordinary_bytes")],
                [number("cleanup_calls"), number("cleanup_bytes")],
            ]
        };
        let limits = allocation("producer_reservation");
        let external = allocation("external_reservation");
        for (phase, maxima) in [
            [180, MAX_BYTES - CLEANUP_BYTES],
            [CLEANUP_CALLS, CLEANUP_BYTES],
        ]
        .iter()
        .enumerate()
        {
            for (kind, maximum) in maxima.iter().enumerate() {
                assert!(
                    limits[phase][kind]
                        .checked_add(external[phase][kind])
                        .is_some_and(|sum| sum <= *maximum),
                    "private aggregate allocation"
                );
            }
        }
        Self::boundary(&value);
        Self {
            value,
            limits,
            deadline: anchor
                .checked_add(remaining)
                .unwrap_or_else(|| panic!("private deadline range")),
            timing,
            input_bytes: bytes.len(),
        }
    }

    fn boundary(value: &Value) {
        let boundary = value["boundary"]
            .as_array()
            .filter(|items| items.len() == 10)
            .unwrap_or_else(|| panic!("private boundary tuple"));
        assert!(boundary[0].as_u64() == Some(1), "private boundary version");
        for (position, length) in [(1, 3), (2, 3), (3, 3), (4, 2)] {
            assert!(
                boundary[position]
                    .as_array()
                    .is_some_and(|items| items.len() == length
                        && items.iter().all(|item| item.as_u64().is_some())),
                "private boundary numbers"
            );
        }
        let number = |position: usize, field: usize| boundary[position][field].as_u64().unwrap();
        assert!(
            (1..=4194304).contains(&number(1, 0))
                && number(1, 1) > 0
                && number(1, 2) <= u64::from(u32::MAX),
            "private original PID1"
        );
        assert!(
            (0..3).all(|field| number(2, field) > 0)
                && number(3, 0) > 0
                && number(3, 1) > 0
                && number(3, 2) <= u64::from(u32::MAX)
                && (0..2).all(|field| number(4, field) > 0),
            "private original root"
        );
        assert!(
            (5..=8).all(|position| boundary[position].as_str().is_some_and(identifier))
                && boundary[7] == value["binding"]["intent_digest"]
                && boundary[8] == value["binding"]["expectation_digest"],
            "private boundary binding"
        );
        assert!(
            boundary[9].as_array().is_some_and(|image| image.len() == 3
                && image[0].as_str().is_some_and(identifier)
                && image[1].as_str().is_some_and(image_identifier)
                && matches!(image[2].as_u64(), Some(0 | 1))),
            "private image identity"
        );
        assert!(
            serde_json::to_vec(&json!({"boundary": boundary}))
                .unwrap()
                .len()
                < PIDS_OUTER_BINDING_RESERVE,
            "private boundary size"
        );
    }

    fn bind(&self, run: &HealthRun) {
        self.bind_expected(
            &run.candidate,
            &run.run,
            &run.lane,
            &required("NATIVE_OUTER_CONTAINER_ID"),
            required("NATIVE_PIDS_LIMIT_DEADLINE_EPOCH")
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("private invocation deadline")),
        );
        assert!(
            run.outer == format!("dl-native-{}", run.run),
            "private native run binding"
        );
    }

    fn bind_expected(&self, candidate: &str, owner: &str, lane: &str, outer_id: &str, epoch: u64) {
        let binding = &self.value["binding"];
        assert!(
            binding["candidate_sha"] == candidate
                && binding["owner"] == owner
                && binding["lane"] == lane
                && binding["outer_id"] == outer_id
                && self.value["pids"]["deadline_epoch"].as_u64() == Some(epoch),
            "private context invocation binding"
        );
    }

    fn budget(&self) -> Arc<PrivateCaptureBudget> {
        let budget = Arc::new(PrivateCaptureBudget {
            limits: self.limits,
            state: Mutex::new(PrivateCaptureState::default()),
            changed: Condvar::new(),
            deadline: self.deadline,
            timing: Some(self.timing),
        });
        assert!(
            budget.debit(false, 0, self.input_bytes),
            "private context source debit"
        );
        budget
    }

    fn require_active(&self, cleanup: bool) {
        assert!(
            Instant::now() < self.deadline
                && self
                    .timing
                    .remaining(private_monotonic_ns(), cleanup)
                    .is_some(),
            "original private absolute deadline"
        );
    }
}

// Read by the observing shell itself, without command substitution or a child.
// Do not change positional arguments supplied to the three observer programs.
const PIDS_COORDINATE_PREFIX: &str = r#"set -eu; LC_ALL=C; export LC_ALL
coords_pid=; coords_chain=; coords_pid_seen=0; coords_chain_seen=0; coords_lines=0
while read -r coords_key coords_a coords_b coords_c coords_d coords_e coords_f coords_g coords_h coords_extra; do
  coords_lines=$((coords_lines+1)); [ "$coords_lines" -le 128 ]
  case "$coords_key" in
    Pid:) [ "$coords_pid_seen" -eq 0 ]; coords_pid_seen=1
      [ -z "$coords_b$coords_c$coords_d$coords_e$coords_f$coords_g$coords_h$coords_extra" ]; coords_pid=$coords_a;;
    NSpid:) [ "$coords_chain_seen" -eq 0 ]; coords_chain_seen=1; [ -z "$coords_extra" ]
      coords_chain="$coords_a $coords_b $coords_c $coords_d $coords_e $coords_f $coords_g $coords_h";;
  esac
done </proc/self/status
[ "$coords_pid_seen" -eq 1 ]; [ "$coords_chain_seen" -eq 1 ]
coords_count=0; coords_first=
for coords_value in "$$" "$coords_pid" $coords_chain; do
  case "$coords_value" in ''|0|0[0-9]*|*[!0-9]*) exit 79;; esac
done
for coords_value in $coords_chain; do
  coords_count=$((coords_count+1)); [ "$coords_count" -le 8 ]; coords_first=$coords_value
done
[ "$$" -le 4194304 ]; [ "$coords_count" -eq 1 ]
[ "$coords_pid" = "$$" ]; [ "$coords_first" = "$$" ]
printf 'SELF %s %s %s\n' "$$" "$coords_pid" "$coords_chain"
printf 'PIDNS '; readlink "/proc/$coords_pid/ns/pid"
printf 'MNTNS '; readlink "/proc/$coords_pid/ns/mnt"
printf 'CGNS '; readlink "/proc/$coords_pid/ns/cgroup"
auth_start=; auth_fields=0
read -r auth_line </proc/1/stat; auth_rest=${auth_line##*) }
for auth_item in $auth_rest; do
  auth_fields=$((auth_fields+1)); [ "$auth_fields" != 20 ] || auth_start=$auth_item
done
[ -n "$auth_start" ]; printf 'AUTHSTART %s\n' "$auth_start"
auth_uid_seen=0; auth_lines=0
while read -r auth_key auth_a auth_b auth_c auth_d auth_extra; do
  auth_lines=$((auth_lines+1)); [ "$auth_lines" -le 128 ]
  if [ "$auth_key" = Uid: ]; then
    [ "$auth_uid_seen" -eq 0 ]; auth_uid_seen=1; [ -z "$auth_extra" ]
    printf 'AUTHUID %s %s %s %s\n' "$auth_a" "$auth_b" "$auth_c" "$auth_d"
  fi
done </proc/1/status
[ "$auth_uid_seen" -eq 1 ]
printf 'AUTHPIDNS '; readlink /proc/1/ns/pid
printf 'AUTHMNTNS '; readlink /proc/1/ns/mnt
printf 'AUTHCGNS '; readlink /proc/1/ns/cgroup
auth_lines=0
while IFS= read -r auth_line; do
  auth_lines=$((auth_lines+1)); [ "$auth_lines" -le 1 ]
  printf 'AUTHMEMBER %s\n' "$auth_line"
done </proc/1/cgroup
[ "$auth_lines" -eq 1 ]; test -d /sys/fs/cgroup; test ! -L /sys/fs/cgroup
printf 'AUTHROOT '; stat -Lc '%d %i' /sys/fs/cgroup
IFS= read -r auth_pids </sys/fs/cgroup/pids.max
IFS= read -r auth_memory </sys/fs/cgroup/memory.max
printf 'AUTHMAX %s %s\n' "$auth_pids" "$auth_memory"
"#;

// Source-local stopping points, not proof outcomes or native values.
#[derive(Clone, Copy)]
enum PidsOperation {
    Context,
    Image,
    OuterObserver,
    DaemonIdentity,
    OuterPidsResolve,
    OuterMemoryResolve,
    Preflight,
    Create,
    Start,
    Inspect,
    PrivateIdentity,
    BaselineScan,
    LeafPidsResolve,
    LeafMemoryResolve,
    BaselineController,
    WorkStart,
    HeldScan,
    HeldController,
    Release,
    RestoredScan,
    RestoredController,
    FinalInspect,
    Acquisition,
    FinalSnapshots,
    Proof,
}

impl PidsOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::Image => "image",
            Self::OuterObserver => "outer_observer",
            Self::DaemonIdentity => "daemon_identity",
            Self::OuterPidsResolve => "outer_pids_resolve",
            Self::OuterMemoryResolve => "outer_memory_resolve",
            Self::Preflight => "preflight",
            Self::Create => "create",
            Self::Start => "start",
            Self::Inspect => "inspect",
            Self::PrivateIdentity => "private_identity",
            Self::BaselineScan => "baseline_scan",
            Self::LeafPidsResolve => "leaf_pids_resolve",
            Self::LeafMemoryResolve => "leaf_memory_resolve",
            Self::BaselineController => "baseline_controller",
            Self::WorkStart => "work_start",
            Self::HeldScan => "held_scan",
            Self::HeldController => "held_controller",
            Self::Release => "release",
            Self::RestoredScan => "restored_scan",
            Self::RestoredController => "restored_controller",
            Self::FinalInspect => "final_inspect",
            Self::Acquisition => "acquisition",
            Self::FinalSnapshots => "final_snapshots",
            Self::Proof => "proof",
        }
    }
}

fn pids_stage(index: Option<usize>, operation: PidsOperation) {
    let (case, role) = if let Some(index) = index {
        assert!(index < 6, "closed PID diagnostic case");
        (
            PIDS_CASES[index / 2].0,
            if index.is_multiple_of(2) {
                "oracle"
            } else {
                "rendered"
            },
        )
    } else {
        ("context", "observer")
    };
    eprintln!(
        "DOCKERLENS_NATIVE_PIDS_STAGE: case={case} role={role} stage={}",
        operation.label()
    );
}

#[derive(Debug, PartialEq, Eq)]
enum PidsResolutionFailure {
    NoControllerMount,
    RootCoordinateMismatch,
    OutsideOwnedDescendant,
    MultipleEligibleMounts,
}

impl PidsResolutionFailure {
    const fn label(&self) -> &'static str {
        match self {
            Self::NoControllerMount => "no_controller_mount",
            Self::RootCoordinateMismatch => "root_coordinate_mismatch",
            Self::OutsideOwnedDescendant => "outside_owned_descendant",
            Self::MultipleEligibleMounts => "multiple_eligible_mounts",
        }
    }
}

fn pids_resolution_failure(
    eligible_mount: bool,
    rooted_mount: bool,
    candidates: usize,
) -> Option<PidsResolutionFailure> {
    match candidates {
        1 => None,
        2.. => Some(PidsResolutionFailure::MultipleEligibleMounts),
        _ if !eligible_mount => Some(PidsResolutionFailure::NoControllerMount),
        _ if !rooted_mount => Some(PidsResolutionFailure::RootCoordinateMismatch),
        _ => Some(PidsResolutionFailure::OutsideOwnedDescendant),
    }
}

fn pids_owned_relation(equal_owner: bool, outside_owner: bool) -> &'static str {
    match (equal_owner, outside_owner) {
        (true, false) => " relation=equal_owner",
        (false, true) => " relation=outside_owner",
        (true, true) => " relation=mixed",
        (false, false) => "",
    }
}

fn pids_controller_failure(
    members_match: bool,
    lines: &[String],
    expected_current: usize,
) -> Option<&'static str> {
    // Diagnose only an already captured, unique canonical CURRENT. Never add a
    // parsing panic before the original short-circuit membership assertion.
    let mut currents = lines
        .iter()
        .filter_map(|line| line.strip_prefix("CURRENT "));
    let current = currents.next()?;
    if currents.next().is_some()
        || current.is_empty()
        || !current.bytes().all(|byte| byte.is_ascii_digit())
        || (current != "0" && current.starts_with('0'))
    {
        return None;
    }
    let current_matches = current.parse::<u64>().ok()? == expected_current as u64;
    match (members_match, current_matches) {
        (false, true) => Some("member_ids_mismatch"),
        (true, false) => Some("current_count_mismatch"),
        (false, false) => Some("members_and_current_mismatch"),
        (true, true) => None,
    }
}

// Authored from the finite protocol, not copied from an oracle implementation.
// A one-line worker gives its only fork site a fixed diagnostic line number.
const PIDS_WORKER: &str = "set -u; LC_ALL=C; export LC_ALL; n=0; trap 'code=$?; printf \"EXIT %s %s %s\\n\" \"$$\" \"$code\" \"$n\"; IFS= read -r release; [ \"$release\" = RELEASE ] || exit 73' EXIT; printf 'READY %s\\n' \"$$\"; IFS= read -r start; [ \"$start\" = START ] || exit 74; while [ \"$n\" -lt 32 ]; do n=$((n+1)); printf 'TRY %s\\n' \"$n\"; (trap - EXIT; IFS= read -r held <&5) & printf 'CHILD %s\\n' \"$!\"; done; exit 0";

const PIDS_PARENT: &str = r#"set -eu; LC_ALL=C; export LC_ALL; umask 077
[ "$$" = 1 ]; test ! -e /tmp/dl-pids; mkdir /tmp/dl-pids
mkfifo /tmp/dl-pids/parent /tmp/dl-pids/worker /tmp/dl-pids/children
exec 3<>/tmp/dl-pids/parent 4<>/tmp/dl-pids/worker 5<>/tmp/dl-pids/children
(/bin/busybox ash -c "$1" dl-pids-worker <&4 >/tmp/dl-pids/out 2>/tmp/dl-pids/err) &
worker=$!; printf 'WORKER %s\n' "$worker" >/tmp/dl-pids/state
while IFS= read -r command <&3; do
  case "$command" in
    START) printf 'START\n' >&4;;
    RELEASE) printf 'RELEASE\n' >&4; status=0; wait "$worker" || status=$?
      n=0; while [ "$n" -lt 32 ]; do printf 'release\n' >&5; n=$((n+1)); done
      jobs >/dev/null; printf 'IDLE %s\n' "$status" >>/tmp/dl-pids/state;;
    CHECK) jobs >/dev/null;;
    *) exit 75;;
  esac
done"#;

// This runs before START, while the leaf has room. State.Pid is NOT used as an
// outer /proc key. The privately observed namespace/start tuple is the anchor.
const PIDS_PRIVATE_IDENTITY: &str = r#"set -eu; LC_ALL=C; export LC_ALL
test /proc/1/exe -ef /bin/busybox
read -r line </proc/1/stat; rest=${line##*) }; set -- $rest; n=1; start=
for item do [ "$n" != 20 ] || start=$item; n=$((n+1)); done
uid=; while read -r key a b c d; do [ "$key" != Uid: ] || uid=$a; done </proc/1/status
printf '%s %s ' "$start" "$uid"; readlink /proc/1/ns/pid"#;

// Owned-outer observer only. No host proc mount or namespace entry is permitted.
// Mountinfo is collected once; later reads bind the same namespace identities.
const PIDS_OUTER_CONTEXT: &str = r#"set -eu; LC_ALL=C; export LC_ALL
n=0; while IFS= read -r line; do n=$((n+1)); [ "$n" -le 256 ]; printf 'M %s\n' "$line"; done </proc/self/mountinfo
while IFS= read -r line; do printf 'S %s\n' "$line"; done </proc/self/cgroup
count=0; visited=0
for directory in /proc/[0-9]*; do
  visited=$((visited+1)); [ "$visited" -le 512 ]; [ -r "$directory/comm" ] || continue
  read -r command <"$directory/comm" || continue; [ "$command" = dockerd ] || continue
  count=$((count+1)); uid=; chain=
  while read -r key a b c d e f g h; do
    case "$key" in Uid:) uid=$a;; NSpid:) chain="$a $b $c $d $e $f $g $h";; esac
  done <"$directory/status"
  printf 'D %s %s %s ' "${directory##*/}" "$uid" "$chain"; readlink "$directory/ns/pid"
done
[ "$count" -eq 1 ]; printf 'END\n'"#;

const PIDS_SCAN: &str = r#"set -eu; LC_ALL=C; export LC_ALL
namespace=$1; depth=$2; expected_start=$3; phase=$4; init=
visited=0
# Resolve only the original PID1 before the idle/reaping barrier. Other members
# may be exiting normally here; complete member checks follow the barrier.
for directory in /proc/[0-9]*; do
  visited=$((visited+1)); [ "$visited" -le 512 ]; [ -r "$directory/status" ] || continue
  chain=; uid=; parent=
  while read -r key a b c d e f g h; do
    case "$key" in Uid:) uid=$a;; PPid:) parent=$a;; NSpid:) chain="$a $b $c $d $e $f $g $h";; esac
  done <"$directory/status" || continue
  set -- $chain; [ "$#" -gt "$depth" ] || continue
  private=; for part do private=$part; done
  [ "$private" = 1 ] || continue
  actual=$(readlink "$directory/ns/pid") || continue; [ "$actual" = "pid:[$namespace]" ] || continue
  test "$directory/exe" -ef "$directory/root/bin/busybox"
  read -r line <"$directory/stat"; rest=${line##*) }; set -- $rest; n=1; started=
  for part do [ "$n" != 20 ] || started=$part; n=$((n+1)); done
  [ "$started" = "$expected_start" ]; [ -z "$init" ]; init=${directory##*/}
done
[ -n "$init" ]; root=/proc/$init/root/tmp/dl-pids; test -d "$root"; test ! -L "$root"
check_init() {
  [ "$(readlink /proc/$init/ns/pid)" = "pid:[$namespace]" ]
  test /proc/$init/exe -ef /proc/$init/root/bin/busybox
  read -r line </proc/$init/stat; rest=${line##*) }; set -- $rest; n=1; actual_start=
  for part do [ "$n" != 20 ] || actual_start=$part; n=$((n+1)); done
  [ "$actual_start" = "$expected_start" ]
}
check_init
ready=0; rounds=0
while [ "$rounds" -lt 40 ]; do
  found=0
  case "$phase" in
    ready) while IFS= read -r line; do case "$line" in 'READY '*) found=1;; esac; done <"$root/out";;
    exit_barrier) while IFS= read -r line; do case "$line" in 'EXIT '*) found=1;; esac; done <"$root/out";;
    idle) while IFS= read -r line; do case "$line" in 'IDLE '*) found=1;; esac; done <"$root/state"
      children=; read -r children <"/proc/$init/task/$init/children" || :
      if [ -n "$children" ]; then
        found=0; check_init; test -p "$root/parent"; test ! -L "$root/parent"
        exec 9<>"$root/parent"; test /proc/self/fd/9 -ef "$root/parent"; check_init
        printf 'CHECK\n' >&9; exec 9>&-
      fi;;
    *) exit 76;;
  esac
  if [ "$found" -eq 1 ]; then ready=1; break; fi
  rounds=$((rounds+1)); sleep 0.05
done
[ "$ready" -eq 1 ]
check_init
printf 'INIT %s\n' "$init"
while IFS= read -r line; do printf 'U %s\n' "$line"; done <"/proc/$init/uid_map"
while IFS= read -r line; do printf 'G %s\n' "$line"; done <"/proc/$init/cgroup"
while IFS= read -r line; do printf 'L %s\n' "$line"; done <"/proc/$init/limits"
for file in state out err; do
  n=0; while IFS= read -r line; do n=$((n+1)); [ "$n" -le 96 ]; [ "${#line}" -le 160 ]; printf 'F %s %s\n' "$file" "$line"; done <"$root/$file"
done
visited=0
for directory in /proc/[0-9]*; do
  visited=$((visited+1)); [ "$visited" -le 512 ]; [ -r "$directory/status" ] || continue
  chain=; uid=; parent=
  while read -r key a b c d e f g h; do
    case "$key" in Uid:) uid=$a;; PPid:) parent=$a;; NSpid:) chain="$a $b $c $d $e $f $g $h";; esac
  done <"$directory/status" || continue
  set -- $chain; [ "$#" -gt "$depth" ] || continue
  actual=$(readlink "$directory/ns/pid") || continue; [ "$actual" = "pid:[$namespace]" ] || continue
  test "$directory/exe" -ef "$directory/root/bin/busybox"
  private=; for part do private=$part; done
  read -r line <"$directory/stat"; rest=${line##*) }; set -- $rest; n=1; started=
  for part do [ "$n" != 20 ] || started=$part; n=$((n+1)); done
  [ "$private" != 1 ] || { [ "${directory##*/}" = "$init" ]; [ "$started" = "$expected_start" ]; }
  printf 'R %s %s %s %s %s %s\n' "${directory##*/}" "$private" "$parent" "$started" "$uid" "$chain"
  while IFS= read -r line; do printf 'T %s %s\n' "${directory##*/}" "$line"; done <"$directory/limits"
done
check_init
printf 'END\n'"#;

const PIDS_CONTROL: &str = r#"set -eu; LC_ALL=C; export LC_ALL
init=$1; namespace=$2; expected_start=$3; expected_uid=$4; command=$5
case "$command" in START|RELEASE) :;; *) exit 78;; esac
root=/proc/$init/root/tmp/dl-pids
check_init() {
  [ "$(readlink /proc/$init/ns/pid)" = "pid:[$namespace]" ]
  test /proc/$init/exe -ef /proc/$init/root/bin/busybox
  read -r line </proc/$init/stat; rest=${line##*) }; set -- $rest; n=1; actual_start=
  for part do [ "$n" != 20 ] || actual_start=$part; n=$((n+1)); done
  [ "$actual_start" = "$expected_start" ]
  uid=; while read -r key a b c d; do [ "$key" != Uid: ] || uid=$a; done </proc/$init/status
  [ "$uid" = "$expected_uid" ]
}
check_init; test -d "$root"; test ! -L "$root"; test -p "$root/parent"; test ! -L "$root/parent"
exec 9<>"$root/parent"; test /proc/self/fd/9 -ef "$root/parent"; check_init
printf '%s\n' "$command" >&9"#;

const PIDS_PREFLIGHT: &str = r#"set -eu
printf 'PIDS '; cat "$1/pids.current"; printf 'PIDMAX '; cat "$1/pids.max"
printf 'MEMORY '
if [ "$3" = v2 ]; then cat "$2/memory.current"; printf 'MEMMAX '; cat "$2/memory.max"
else cat "$2/memory.usage_in_bytes"; printf 'MEMMAX '; cat "$2/memory.limit_in_bytes"; fi
printf 'END\n'"#;

// Only selected, lexically resolved controller paths are accepted. The two
// controller mounts may differ in v1. No leaf policy is ever written.
const PIDS_CONTROLLER_READ: &str = r#"set -eu; LC_ALL=C; export LC_ALL
leaf=$1; outer=$2; memory=$3; outer_memory=$4; kind=$5
seen=' '
for item in "$leaf" "$outer" "$memory" "$outer_memory"; do
  case "$seen" in *" $item "*) continue;; esac; seen="$seen$item "
  test -d "$item"; test ! -L "$item"; printf 'STAT %s ' "$item"; stat -Lc '%d %i' "$item"
done
count=0; for child in "$leaf"/*; do [ ! -d "$child" ] || count=$((count+1)); done; [ "$count" -eq 0 ]
printf 'MAX '; cat "$leaf/pids.max"
printf 'CURRENT '; cat "$leaf/pids.current"
if [ -f "$leaf/pids.events.local" ]; then events=pids.events.local; else events=pids.events; fi
printf 'SOURCE %s\n' "$events"
while read -r key value; do [ "$key" != max ] || printf 'DENIALS %s\n' "$value"; done <"$leaf/$events"
while read -r member; do printf 'MEMBER %s\n' "$member"; done <"$leaf/cgroup.procs"
printf 'OUTERPIDS '; cat "$outer/pids.current"
printf 'OUTERMAX '; cat "$outer/pids.max"
if [ "$kind" = v2 ]; then
  printf 'OUTERMEMORY '; cat "$outer_memory/memory.current"
  printf 'OUTERMEMMAX '; cat "$outer_memory/memory.max"
  if [ -f "$memory/memory.events.local" ]; then file=memory.events.local; else file=memory.events; fi
  while read -r key value; do [ "$key" != oom_kill ] || printf 'OOM %s\n' "$value"; done <"$memory/$file"
else
  printf 'OUTERMEMORY '; cat "$outer_memory/memory.usage_in_bytes"
  printf 'OUTERMEMMAX '; cat "$outer_memory/memory.limit_in_bytes"
  while read -r key value; do [ "$key" != oom_kill ] || printf 'OOM %s\n' "$value"; done <"$memory/memory.oom_control"
fi
point=${leaf%/*}; depth=0
while :; do
  depth=$((depth+1)); [ "$depth" -le 32 ]; printf 'ANCESTOR '; cat "$point/pids.current"; printf 'CEILING '; cat "$point/pids.max"
  [ "$point" != "$outer" ] || break
  case "$point" in "$outer"/*) point=${point%/*};; *) exit 77;; esac
done
printf 'END\n'"#;

fn pids_u64(text: &str) -> u64 {
    assert!(
        !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()),
        "closed PID decimal"
    );
    assert!(
        text == "0" || !text.starts_with('0'),
        "canonical PID decimal"
    );
    text.parse()
        .unwrap_or_else(|_| panic!("bounded PID decimal"))
}

fn pids_namespace(text: &str, kind: &str) -> u64 {
    pids_u64(
        text.strip_prefix(&format!("{kind}:["))
            .and_then(|tail| tail.strip_suffix(']'))
            .unwrap_or_else(|| panic!("closed namespace")),
    )
}

fn pids_lines(bytes: Vec<u8>, allowed: &[&str]) -> Vec<String> {
    assert!(bytes.len() <= 65536, "bounded private PID frame");
    let text = String::from_utf8(bytes).unwrap_or_else(|_| panic!("private PID frame encoding"));
    assert!(text.ends_with("END\n"), "complete PID frame");
    let lines: Vec<_> = text.lines().map(str::to_owned).collect();
    assert!(
        lines.iter().filter(|line| line.as_str() == "END").count() == 1
            && lines.iter().take(lines.len() - 1).all(|line| line
                .split_once(' ')
                .is_some_and(|(key, _)| allowed.contains(&key) || PIDS_AUTH_KEYS.contains(&key))),
        "closed complete PID frame keys"
    );
    lines
}

fn pids_field<'a>(lines: &'a [String], key: &str) -> &'a str {
    let prefix = format!("{key} ");
    let mut found = lines.iter().filter_map(|line| line.strip_prefix(&prefix));
    let value = found
        .next()
        .unwrap_or_else(|| panic!("required PID frame field"));
    assert!(found.next().is_none(), "unique PID frame field");
    value
}

fn pids_shell(run: &HealthRun, script: &str, args: &[String]) -> Vec<u8> {
    let script = if [PIDS_OUTER_CONTEXT, PIDS_SCAN, PIDS_CONTROLLER_READ].contains(&script) {
        format!("{PIDS_COORDINATE_PREFIX}\n{script}")
    } else {
        script.to_owned()
    };
    let mut command = vec!["sh".into(), "-c".into(), script, "dl-pids-observer".into()];
    command.extend_from_slice(args);
    run.outer(&command, false)
}

struct PidsCoordinates {
    namespaces: [u64; 3],
    witnesses: Vec<Value>,
    boundary: Option<Value>,
}

const PIDS_AUTH_KEYS: [&str; 8] = [
    "AUTHSTART",
    "AUTHUID",
    "AUTHPIDNS",
    "AUTHMNTNS",
    "AUTHCGNS",
    "AUTHMEMBER",
    "AUTHROOT",
    "AUTHMAX",
];

impl PidsCoordinates {
    fn new(context: &[String]) -> Self {
        let namespaces = Self::namespaces(context);
        let mut coordinates = Self {
            namespaces,
            witnesses: Vec::with_capacity(37),
            boundary: None,
        };
        coordinates.observe(context);
        coordinates
    }

    fn authenticated(context: &[String], boundary: &Value) -> Self {
        let mut coordinates = Self {
            namespaces: Self::namespaces(context),
            witnesses: Vec::with_capacity(37),
            boundary: Some(boundary.clone()),
        };
        coordinates.observe(context);
        let mappings: Vec<_> = context
            .iter()
            .filter_map(|line| line.strip_prefix("M "))
            .filter_map(|line| {
                let (left, right) = line.split_once(" - ")?;
                let fields: Vec<_> = left.split_whitespace().collect();
                (right.split_whitespace().next() == Some("cgroup2")
                    && fields.len() >= 6
                    && fields[4] == "/sys/fs/cgroup")
                    .then_some(fields)
            })
            .collect();
        assert!(mappings.len() == 1, "one authenticated controller mount");
        let mount = &mappings[0];
        assert!(
            mount[3] == "/"
                && pids_u64(mount[0]) == boundary[3][0].as_u64().unwrap()
                && pids_u64(mount[1]) == boundary[3][1].as_u64().unwrap()
                && mount[2] == format!("0:{}", boundary[3][2].as_u64().unwrap()),
            "original authenticated controller mount"
        );
        coordinates
    }

    fn authenticate(&self, lines: &[String]) {
        let Some(boundary) = &self.boundary else {
            return;
        };
        assert!(
            pids_u64(pids_field(lines, "AUTHSTART")) == boundary[1][1].as_u64().unwrap(),
            "same original PID1 start"
        );
        let uid: Vec<_> = pids_field(lines, "AUTHUID")
            .split_whitespace()
            .map(pids_u64)
            .collect();
        assert!(
            uid.len() == 4 && uid.iter().all(|uid| Some(*uid) == boundary[1][2].as_u64()),
            "same original PID1 credentials"
        );
        for (index, key, kind) in [
            (0, "AUTHPIDNS", "pid"),
            (1, "AUTHMNTNS", "mnt"),
            (2, "AUTHCGNS", "cgroup"),
        ] {
            assert!(
                Some(pids_namespace(pids_field(lines, key), kind)) == boundary[2][index].as_u64()
                    && Some(self.namespaces[index]) == boundary[2][index].as_u64(),
                "same original PID1 and observer namespaces"
            );
        }
        assert!(
            matches!(pids_field(lines, "AUTHMEMBER"), "0::/" | "0::/init.scope"),
            "bounded original PID1 relocation"
        );
        let root: Vec<_> = pids_field(lines, "AUTHROOT")
            .split_whitespace()
            .map(pids_u64)
            .collect();
        assert!(
            root.len() == 2
                && Some(root[0]) == boundary[4][0].as_u64()
                && Some(root[1]) == boundary[4][1].as_u64(),
            "same original controller root object"
        );
        assert!(
            pids_field(lines, "AUTHMAX") == "512 4294967296",
            "unchanged original root ceilings"
        );
    }

    fn namespaces(lines: &[String]) -> [u64; 3] {
        [
            pids_namespace(pids_field(lines, "PIDNS"), "pid"),
            pids_namespace(pids_field(lines, "MNTNS"), "mnt"),
            pids_namespace(pids_field(lines, "CGNS"), "cgroup"),
        ]
    }

    fn observe(&mut self, lines: &[String]) {
        self.authenticate(lines);
        let fields: Vec<_> = pids_field(lines, "SELF").split_whitespace().collect();
        assert!(
            (3..=10).contains(&fields.len()),
            "bounded complete observer coordinate row"
        );
        let fields: Vec<_> = fields.into_iter().map(pids_u64).collect();
        let shell = fields[0];
        let proc_pid = fields[1];
        let chain = &fields[2..];
        assert!(
            (1..=4194304).contains(&shell)
                && chain.len() == 1
                && proc_pid == shell
                && chain[0] == shell,
            "procfs and observing shell share one PID coordinate"
        );
        let namespaces = Self::namespaces(lines);
        assert!(
            namespaces.iter().all(|value| *value > 0) && namespaces == self.namespaces,
            "same initial observer namespaces before controller comparison"
        );
        let chain: Vec<_> = chain
            .iter()
            .map(|pid| i128::from(*pid) - i128::from(shell))
            .collect();
        let deltas: Vec<_> = namespaces
            .iter()
            .zip(self.namespaces)
            .map(|(actual, initial)| i128::from(*actual) - i128::from(initial))
            .collect();
        assert!(
            self.witnesses.len() < 37,
            "finite ordered observer coordinate witnesses"
        );
        self.witnesses.push(json!([
            shell,
            i128::from(proc_pid) - i128::from(shell),
            chain,
            deltas[0],
            deltas[1],
            deltas[2]
        ]));
    }

    fn finish(self) -> Vec<Value> {
        assert!(
            self.witnesses.len() == 37,
            "complete ordered observer coordinate witnesses"
        );
        self.witnesses
    }
}

const PIDS_PHASE_FIELDS: [&str; 10] = [
    "rows",
    "members",
    "pids_current",
    "pids_max",
    "denials",
    "oom_kills",
    "outer_pids",
    "outer_memory",
    "ancestor_headroom",
    "phase",
];

fn pids_compact_phase(phase: &mut Value) {
    let mut fields = phase.take().as_object().unwrap().clone();
    assert!(
        fields.len() == PIDS_PHASE_FIELDS.len()
            && PIDS_PHASE_FIELDS
                .iter()
                .all(|key| fields.contains_key(*key)),
        "all original private phase fields retained"
    );
    *phase = Value::Array(
        PIDS_PHASE_FIELDS
            .iter()
            .map(|key| fields.remove(*key).unwrap())
            .collect(),
    );
}

fn pids_private_v2(proof: &mut Value, coordinates: Vec<Value>) {
    assert!(
        coordinates.len() == 37,
        "all coordinate observations before private serialization"
    );
    assert!(
        proof["schema_version"] == 2 && proof["contract"] == PIDS_CONTRACT,
        "private coordinate successor only"
    );
    proof["coordinates"] = json!(coordinates);
    let cases = proof["cases"].as_array_mut().unwrap();
    assert!(cases.len() == 6, "six unchanged private cases");
    for case in cases {
        for phase in ["baseline", "held", "restored"] {
            pids_compact_phase(&mut case[phase]);
        }
    }
}

fn pids_proof_budget(proof: &Value) {
    let size = serde_json::to_vec(proof).unwrap().len();
    assert!(
        size <= PIDS_PROOF_BYTES,
        "bounded private PID proof before publication"
    );
    let mut main = proof.clone();
    if let Some(object) = main.as_object_mut() {
        object.remove("boundary");
    }
    let main_size = serde_json::to_vec(&main).unwrap().len();
    assert!(
        main_size <= PIDS_PROOF_BYTES - PIDS_OUTER_BINDING_RESERVE
            && size.saturating_sub(main_size) <= PIDS_OUTER_BINDING_RESERVE,
        "private main and original boundary proof allowances"
    );
}

fn pids_safe_path(path: &str) -> PathBuf {
    assert!(
        path.starts_with('/') && path.len() <= 512 && !path.chars().any(char::is_whitespace),
        "bounded controller path"
    );
    let value = PathBuf::from(path);
    assert!(
        path == "/"
            || path[1..]
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "normalized controller path"
    );
    assert!(
        value.components().all(|part| matches!(
            part,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )),
        "literal controller components"
    );
    assert!(value.to_str() == Some(path), "canonical controller path");
    value
}

fn pids_resolve(
    lines: &[String],
    memberships: &[String],
    controller: &str,
    outer: &[String],
    descendant: bool,
) -> Value {
    let member = |records: &[String]| -> (&str, String) {
        let mut legacy = Vec::new();
        let mut unified = Vec::new();
        for line in records {
            let fields: Vec<_> = line.splitn(3, ':').collect();
            assert!(fields.len() == 3, "closed cgroup membership");
            if fields[1].split(',').any(|item| item == controller) {
                legacy.push(fields[2].to_owned());
            }
            if fields[0] == "0" && fields[1].is_empty() {
                unified.push(fields[2].to_owned());
            }
        }
        assert!(
            legacy.len() <= 1 && unified.len() <= 1,
            "unambiguous controller membership"
        );
        if let Some(path) = legacy.pop() {
            ("v1", path)
        } else {
            (
                "v2",
                unified
                    .pop()
                    .unwrap_or_else(|| panic!("required controller membership")),
            )
        }
    };
    let (kind, selected) = member(memberships);
    let (outer_kind, owner) = member(outer);
    assert!(kind == outer_kind, "same actual controller generation");
    let mut candidates = Vec::new();
    let mut eligible_mount = false;
    let mut rooted_mount = false;
    let mut equal_owner = false;
    let mut outside_owner = false;
    for line in lines.iter().filter_map(|line| line.strip_prefix("M ")) {
        let (left, right) = line
            .split_once(" - ")
            .unwrap_or_else(|| panic!("mountinfo delimiter"));
        let fields: Vec<_> = left.split_whitespace().collect();
        let tail: Vec<_> = right.split_whitespace().collect();
        assert!(
            fields.len() >= 6 && tail.len() == 3,
            "bounded mountinfo fields"
        );
        if !(kind == "v2" && tail[0] == "cgroup2")
            && !(kind == "v1"
                && tail[0] == "cgroup"
                && tail[2].split(',').any(|item| item == controller))
        {
            continue;
        }
        eligible_mount = true;
        let root = pids_safe_path(fields[3]);
        let mount = pids_safe_path(fields[4]);
        let selected_path = pids_safe_path(&selected);
        let owner_path = pids_safe_path(&owner);
        if let (Ok(leaf), Ok(parent)) = (
            selected_path.strip_prefix(&root),
            owner_path.strip_prefix(&root),
        ) {
            rooted_mount = true;
            // Joining an empty suffix retains a separator; the private reader requires
            // canonical path strings even when the owner is the mount root.
            let path: PathBuf = mount.join(leaf).components().collect();
            let outer_path: PathBuf = mount.join(parent).components().collect();
            equal_owner |= descendant && path == outer_path;
            outside_owner |= !path.starts_with(&outer_path);
            if (!descendant || path != outer_path) && path.starts_with(&outer_path) {
                candidates.push(json!({"kind":if tail[0] == "cgroup2" {"v2"} else {"v1"},"mount_id":pids_u64(fields[0]),"root":fields[3],"mountpoint":fields[4],"membership":selected,"path":path,"outer_membership":owner,"outer_path":outer_path,"inode":0,"device":0}));
            }
        }
    }
    if let Some(reason) = pids_resolution_failure(eligible_mount, rooted_mount, candidates.len()) {
        let relation = if reason == PidsResolutionFailure::OutsideOwnedDescendant {
            pids_owned_relation(equal_owner, outside_owner)
        } else {
            ""
        };
        eprintln!(
            "DOCKERLENS_NATIVE_PIDS_RESOLVE: reason={}{}",
            reason.label(),
            relation
        );
    }
    assert!(
        candidates.len() == 1,
        "unique controller mount-root resolution"
    );
    candidates.remove(0)
}

fn pids_cleanup_with(
    attempted: &[bool],
    ids: &[Option<String>],
    inner: impl FnOnce() -> CleanupDisposition,
) -> CleanupDisposition {
    let complete = attempted.len() == 6
        && ids.len() == 6
        && attempted
            .iter()
            .zip(ids)
            .all(|(tried, id)| !tried || id.as_deref().is_some_and(identifier));
    if complete {
        inner()
    } else {
        CleanupDisposition::OuterTeardownRequired
    }
}

fn pids_create(run: &mut HealthRun, index: usize) {
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "fresh PID fixture name"
    );
    let limit = PIDS_CASES[index / 2].1;
    let argv = [
        "/bin/busybox",
        "ash",
        "-c",
        PIDS_PARENT,
        "dl-pids-parent",
        PIDS_WORKER,
    ];
    if index.is_multiple_of(2) {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            run.names[index].clone(),
            "--label".into(),
            format!("{OWNER}={}", run.run),
            "--pids-limit".into(),
            limit.to_string(),
            run.base.clone(),
        ];
        args.extend(argv.map(str::to_owned));
        run.attempted[index] = true;
        let reply = docker(run, &args);
        let id = std::str::from_utf8(&reply)
            .ok()
            .and_then(|text| text.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("canonical PID CLI ID"));
        bind(run, index, id);
        return;
    }
    let container = ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(run.names[index].as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(run.base.as_bytes().to_vec()).unwrap(),
        environment: vec![],
        ports: vec![],
        mounts: vec![],
        networks: vec![],
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(
            argv.map(|text| Argument::new(text.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            pids_limit: Some(if limit == -1 {
                PidsLimit::Unlimited
            } else {
                PidsLimit::Count(NonZeroU64::new(limit as u64).unwrap())
            }),
            ..ContainerSettings::default()
        },
    };
    let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(container))]).unwrap();
    let graph = DockerPlanner
        .plan(
            &intent,
            &ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    let request: Value =
        serde_json::from_slice(DockerApiRenderer.render(&graph).unwrap().bytes()).unwrap();
    let path = format!("/v{}/containers/create?name={}", run.api, run.names[index]);
    let literal = json!({"method":"POST","path":path,"body":{"Image":run.base,"Cmd":argv,"Labels":{(OWNER):run.run},"HostConfig":{"PidsLimit":limit}}});
    assert!(
        request == literal && serde_json::to_vec(&request["body"]).unwrap().len() <= 4096,
        "independent complete PID literal"
    );
    run.attempted[index] = true;
    let (status, reply) = run.api("POST", &path, Some(&request["body"]), false);
    assert!(
        status == 201 && (reply["Warnings"].is_null() || reply["Warnings"] == json!([])),
        "accepted PID create without warning"
    );
    bind(
        run,
        index,
        reply["Id"]
            .as_str()
            .unwrap_or_else(|| panic!("canonical PID create ID")),
    );
}

fn pids_configured(run: &HealthRun, index: usize, image: &Value) -> Value {
    let id = run.ids[index].as_deref().unwrap();
    let (status, inspected) = run.inspect(id, false);
    assert!(
        status == 200
            && owned(run, &inspected, index, Some(id))
            && running(&inspected)
            && inspected["Image"] == image["id"]
            && inspected["State"]["OOMKilled"] == false
            && inspected["RestartCount"] == 0
            && inspected["HostConfig"]["PidsLimit"] == PIDS_CASES[index / 2].1,
        "owned unchanged running PID fixture"
    );
    assert!(
        inspected["Config"]["Cmd"]
            == json!([
                "/bin/busybox",
                "ash",
                "-c",
                PIDS_PARENT,
                "dl-pids-parent",
                PIDS_WORKER
            ])
            && (inspected["Config"]["Entrypoint"].is_null()
                || inspected["Config"]["Entrypoint"] == json!([]))
            && inspected["Path"] == "/bin/busybox"
            && inspected["Args"]
                == json!(["ash", "-c", PIDS_PARENT, "dl-pids-parent", PIDS_WORKER])
            && inspected["Mounts"].as_array().is_some_and(Vec::is_empty),
        "actual authored supervisor argv, borrowed entrypoint and no mounts"
    );
    inspected
}

fn pids_rows(lines: &[String]) -> Vec<Value> {
    let mut rows: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("R "))
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert!(
                fields.len() >= 6 && fields.len() <= 13,
                "complete PID namespace row"
            );
            assert!(
                fields[0] == fields[5] && fields[1] == *fields.last().unwrap(),
                "complete actual NSpid row binding"
            );
            json!([
                pids_u64(fields[0]),
                pids_u64(fields[1]),
                pids_u64(fields[2]),
                pids_u64(fields[3]),
                pids_u64(fields[4])
            ])
        })
        .collect();
    rows.sort_by_key(|row| row[1].as_u64().unwrap());
    assert!(
        !rows.is_empty() && rows.len() <= 34,
        "finite owned namespace inventory"
    );
    assert!(
        rows[0][1] == 1 && rows[0][0] == pids_u64(pids_field(lines, "INIT")),
        "same scan-bound original PID1"
    );
    rows
}

fn pids_log(lines: &[String], stream: &str) -> Vec<String> {
    let prefix = format!("F {stream} ");
    assert!(
        lines
            .iter()
            .filter(|line| line.starts_with("F "))
            .all(|line| ["F state ", "F out ", "F err "]
                .iter()
                .any(|prefix| line.starts_with(prefix))),
        "closed private worker streams"
    );
    lines
        .iter()
        .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .collect()
}

fn pids_scan(
    run: &HealthRun,
    context: &[String],
    namespace: u64,
    depth: u64,
    started: u64,
    phase: &str,
    coordinates: &mut PidsCoordinates,
) -> Vec<String> {
    let lines = pids_lines(
        pids_shell(
            run,
            PIDS_SCAN,
            &[
                namespace.to_string(),
                depth.to_string(),
                started.to_string(),
                phase.into(),
            ],
        ),
        &[
            "SELF", "PIDNS", "MNTNS", "CGNS", "INIT", "U", "G", "L", "F", "R", "T",
        ],
    );
    for key in ["PIDNS", "MNTNS", "CGNS"] {
        assert!(
            pids_field(&lines, key) == pids_field(context, key),
            "stable owned observer namespaces at every phase"
        );
    }
    coordinates.observe(&lines);
    lines
}

fn pids_nproc(lines: &[String], rows: &[Value]) -> Value {
    let mut limits = None;
    for row in rows.iter().take(2) {
        let prefix = format!("T {} Max processes", row[0].as_u64().unwrap());
        let values: Vec<_> = pids_field(lines, &prefix).split_whitespace().collect();
        assert!(
            values.len() == 3 && values[2] == "processes",
            "native process rlimit units"
        );
        let numbers: Vec<_> = values[..2]
            .iter()
            .map(|text| {
                if *text == "unlimited" {
                    json!("unlimited")
                } else {
                    let number = pids_u64(text);
                    assert!(number >= 35, "process rlimit headroom");
                    json!(number)
                }
            })
            .collect();
        assert!(
            numbers[1] == "unlimited"
                || numbers[0]
                    .as_u64()
                    .zip(numbers[1].as_u64())
                    .is_some_and(|(soft, hard)| soft <= hard),
            "actual Linux soft process limit does not exceed hard limit"
        );
        if let Some(previous) = &limits {
            assert!(*previous == numbers, "inherited actual process limits");
        }
        limits = Some(numbers);
    }
    json!(limits.unwrap())
}

fn pids_controller(
    run: &HealthRun,
    rows: &[Value],
    phase: &str,
    pids: &mut Value,
    memory: &mut Value,
    coordinates: &mut PidsCoordinates,
) -> (Value, String) {
    assert!(
        pids["kind"] == memory["kind"],
        "same known cgroup generation"
    );
    let bytes = pids_shell(
        run,
        PIDS_CONTROLLER_READ,
        &[
            pids["path"].as_str().unwrap().into(),
            pids["outer_path"].as_str().unwrap().into(),
            memory["path"].as_str().unwrap().into(),
            memory["outer_path"].as_str().unwrap().into(),
            pids["kind"].as_str().unwrap().into(),
        ],
    );
    pids_controller_frame(bytes, rows, phase, pids, memory, coordinates)
}

// Keep raw membership comparison and subsequent proof packing on the live path.
// Pure fixtures exercise the same parser without launching an observer command.
fn pids_controller_frame(
    bytes: Vec<u8>,
    rows: &[Value],
    phase: &str,
    pids: &mut Value,
    memory: &mut Value,
    coordinates: &mut PidsCoordinates,
) -> (Value, String) {
    let lines = pids_lines(
        bytes,
        &[
            "SELF",
            "PIDNS",
            "MNTNS",
            "CGNS",
            "STAT",
            "MAX",
            "CURRENT",
            "SOURCE",
            "DENIALS",
            "MEMBER",
            "OUTERPIDS",
            "OUTERMAX",
            "OUTERMEMORY",
            "OUTERMEMMAX",
            "OOM",
            "ANCESTOR",
            "CEILING",
        ],
    );
    coordinates.observe(&lines);
    for mapping in [pids, memory] {
        let key = format!("STAT {}", mapping["path"].as_str().unwrap());
        let fields: Vec<_> = pids_field(&lines, &key).split_whitespace().collect();
        assert!(fields.len() == 2, "controller device/inode identity");
        let (device, inode) = (pids_u64(fields[0]), pids_u64(fields[1]));
        if mapping["inode"] != 0 {
            assert!(
                mapping["inode"] == inode && mapping["device"] == device,
                "same live controller identity"
            );
        }
        mapping["inode"] = json!(inode);
        mapping["device"] = json!(device);
    }
    let maximum = pids_field(&lines, "MAX");
    let maximum = if maximum == "max" {
        json!("max")
    } else {
        json!(pids_u64(maximum))
    };
    let mut members: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("MEMBER "))
        .map(pids_u64)
        .collect();
    members.sort_unstable();
    let mut expected: Vec<_> = rows.iter().map(|row| row[0].as_u64().unwrap()).collect();
    expected.sort_unstable();
    if let Some(reason) = pids_controller_failure(members == expected, &lines, rows.len()) {
        eprintln!("DOCKERLENS_NATIVE_PIDS_CONTROLLER: reason={reason}");
    }
    assert!(
        members == expected && pids_u64(pids_field(&lines, "CURRENT")) == rows.len() as u64,
        "exclusive single-threaded leaf membership"
    );
    assert!(
        pids_field(&lines, "OUTERMAX") == "512"
            && pids_field(&lines, "OUTERMEMMAX") == "4294967296",
        "actual unchanged outer controller ceilings"
    );
    let currents: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("ANCESTOR "))
        .map(pids_u64)
        .collect();
    let ceilings: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("CEILING "))
        .collect();
    assert!(
        !currents.is_empty() && currents.len() == ceilings.len(),
        "complete constraining ancestry"
    );
    let headroom = currents
        .iter()
        .zip(ceilings)
        .map(|(current, ceiling)| {
            if ceiling == "max" {
                u64::MAX - current
            } else {
                pids_u64(ceiling).checked_sub(*current).unwrap()
            }
        })
        .min()
        .unwrap();
    let outer_pids = pids_u64(pids_field(&lines, "OUTERPIDS"));
    let outer_memory = pids_u64(pids_field(&lines, "OUTERMEMORY"));
    assert!(
        headroom >= 128 && outer_pids <= 384 && outer_memory <= 3221225472,
        "real inner/outer task and memory headroom"
    );
    let source = pids_field(&lines, "SOURCE");
    assert!(
        matches!(source, "pids.events.local" | "pids.events"),
        "known local/exclusive event source"
    );
    let packed: Vec<_> = rows
        .iter()
        .map(|row| {
            json!([
                row[0].as_i64().unwrap() - rows[0][0].as_i64().unwrap(),
                row[1],
                row[2].as_i64().unwrap() - rows[0][0].as_i64().unwrap(),
                row[3].as_i64().unwrap() - rows[0][3].as_i64().unwrap(),
                row[4].as_i64().unwrap() - rows[0][4].as_i64().unwrap()
            ])
        })
        .collect();
    let packed_members: Vec<_> = members
        .iter()
        .map(|pid| i64::try_from(*pid).unwrap() - rows[0][0].as_i64().unwrap())
        .collect();
    (
        json!({"rows":packed,"members":packed_members,"pids_current":rows.len(),"pids_max":maximum,"denials":pids_u64(pids_field(&lines,"DENIALS")),"oom_kills":pids_u64(pids_field(&lines,"OOM")),"outer_pids":outer_pids,"outer_memory":outer_memory,"ancestor_headroom":headroom,"phase":phase}),
        if source == "pids.events.local" {
            source.into()
        } else {
            "pids.events_exclusive_leaf".into()
        },
    )
}

fn pids_control(
    run: &HealthRun,
    outer_init: u64,
    namespace: u64,
    started: u64,
    uid: u64,
    command: &str,
) {
    assert!(
        matches!(command, "START" | "RELEASE"),
        "closed fixture control command"
    );
    pids_shell(
        run,
        PIDS_CONTROL,
        &[
            outer_init.to_string(),
            namespace.to_string(),
            started.to_string(),
            uid.to_string(),
            command.into(),
        ],
    );
}

fn pids_acquisition(run: &HealthRun) -> Value {
    assert!(
        run.calls.get() + PIDS_CAPTURE_CALLS + 2 <= 180
            && run.bytes.get() + PIDS_CAPTURE_BYTES + 2 * 73742 <= MAX_BYTES - CLEANUP_BYTES,
        "charged PID acquisition and final snapshot reserve"
    );
    private_capture_debit(false, PIDS_CAPTURE_CALLS, PIDS_CAPTURE_BYTES);
    run.calls.set(run.calls.get() + PIDS_CAPTURE_CALLS);
    run.bytes.set(run.bytes.get() + PIDS_CAPTURE_BYTES);
    let maximum = run
        .remaining()
        .checked_sub(Duration::from_secs(46))
        .unwrap()
        .min(Duration::from_secs(10));
    let capture = acquire(
        &Endpoint::unix_socket(PathBuf::from(&run.socket)),
        Selector::ContainerIds(
            run.ids
                .iter()
                .map(|id| NativeId::new(id.as_ref().unwrap().clone()).unwrap())
                .collect(),
        ),
        Limits {
            max_requests: 16,
            max_selected_resources: 6,
            max_expansions: 8,
            max_response_bytes: 128 * 1024,
            max_total_bytes: PIDS_CAPTURE_BYTES,
            max_elapsed: maximum,
        },
        &AtomicBool::new(false),
    )
    .unwrap_or_else(|_| panic!("complete actual six-ID PID acquisition"));
    assert!(
        capture.route() == CaptureRoute::ExplicitUnixSocket
            && capture.selected_roots().len() == 6
            && capture
                .exchanges()
                .iter()
                .all(|exchange| exchange.status().code() == 200),
        "actual successful selected PID capture"
    );
    let decoded = decode_capture(&capture).unwrap_or_else(|_| panic!("typed selected PID decoder"));
    assert!(decoded.containers.len() == 6, "six decoded PID roots");
    let mut found = BTreeSet::new();
    for container in &decoded.containers {
        let id = container.id.value().unwrap().as_bytes();
        let position = run
            .ids
            .iter()
            .position(|item| item.as_ref().unwrap().as_bytes() == id)
            .unwrap_or_else(|| panic!("only selected PID identities"));
        assert!(found.insert(position), "unique selected PID identity");
        let limit = &container.runtime.pids_limit;
        assert!(
            container.id.availability == Availability::Present
                && container.id.origin == Origin::RuntimeAssigned
                && limit.availability == Availability::Present
                && limit.origin == Origin::Effective
                && limit
                    .value()
                    .is_some_and(|actual| *actual == PIDS_CASES[position / 2].1),
            "typed exact effective PID limit"
        );
    }
    let requested = ApiVersion::new(
        NonZeroU16::new(1).unwrap(),
        if run.lane.starts_with("debian11-") {
            41
        } else {
            49
        },
    );
    assert!(
        decoded.version.requested_api_versions == vec![requested]
            && decoded.version.daemon.observation_id == capture.observation_id()
            && decoded
                .version
                .daemon
                .release
                .as_ref()
                .is_some_and(|release| release.as_str() == run.engine),
        "exact request-bound decoded PID context"
    );
    assert!(
        capture.exchanges().iter().all(|exchange| matches!(
            exchange.request(),
            ReadRequest::DaemonVersion
        ) || exchange.api_version() == Some(requested)),
        "actual versioned PID request URLs"
    );
    assert!(
        matches!(
            (run.mode, decoded.version.daemon.mode),
            (DaemonMode::Rootless, DaemonMode::Rootless)
                | (
                    DaemonMode::Rootful,
                    DaemonMode::Rootful | DaemonMode::Unknown
                )
        ),
        "nonconflicting acquired PID daemon mode"
    );
    let bytes: usize = capture
        .exchanges()
        .iter()
        .map(|exchange| exchange.body().as_bytes().len())
        .sum();
    json!({"route":"explicit_unix_socket","selected_ids":6,"requested_api":if run.lane.starts_with("debian11-") {"1.41"} else {"1.49"},"reserved_calls":16,"reserved_bytes":PIDS_CAPTURE_BYTES,"actual_requests":capture.exchanges().len(),"actual_response_bytes":bytes,"decoded":"present_effective_exact_pids_limits","max_elapsed_ns":maximum.as_nanos() as u64})
}

#[test]
#[ignore = "explicit isolated native Engine and cleanup-owner context required"]
fn live_pids_limit_effects_match_engine() {
    let started = Instant::now();
    let private = PidsPrivateContext::stdin();
    // Declared before HealthRun: ordinary panic unwinding keeps the original
    // separate cleanup reservation installed through HealthRun::drop.
    let _private_scope = PrivateCaptureScope::enter(private.budget());
    let target = ProofTarget::new_for("NATIVE_PIDS_LIMIT_PROOF_PATH", PIDS_FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_PIDS_LIMIT_CANDIDATE_SHA",
        "NATIVE_PIDS_LIMIT_DEADLINE_EPOCH",
    );
    private.bind(&run);
    run.deadline = run.deadline.min(private.deadline);
    run.names = PIDS_CASES
        .into_iter()
        .flat_map(|(name, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-pids-{}-{name}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 6];
    run.attempted = vec![false; 6];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pids_stage(None, PidsOperation::Context);
        let daemon_uid = run.context();
        pids_stage(None, PidsOperation::Image);
        let image = image_snapshot(&run);
        assert!(
            image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}),
            "no automatic borrowed volumes"
        );
        pids_stage(None, PidsOperation::OuterObserver);
        let context = pids_lines(
            pids_shell(&run, PIDS_OUTER_CONTEXT, &[]),
            &["SELF", "PIDNS", "MNTNS", "CGNS", "M", "S", "D"],
        );
        let mut coordinates = PidsCoordinates::authenticated(&context, &private.value["boundary"]);
        pids_stage(None, PidsOperation::DaemonIdentity);
        let daemon: Vec<_> = pids_field(&context, "D").split_whitespace().collect();
        assert!(daemon.len() >= 4, "observed daemon namespace chain");
        assert!(
            pids_u64(daemon[1]) == u64::from(daemon_uid),
            "independent daemon UID agreement"
        );
        let depth = daemon.len() as u64 - 3;
        let daemon_ns = pids_namespace(daemon.last().unwrap(), "pid");
        // Original namespace root is authenticated by the held bootstrap/OCI
        // context and rechecked live. A later observer/init.scope membership
        // cannot select a descendant merely because its limits look equal.
        let outer_members = vec!["0::/".to_owned()];
        pids_stage(None, PidsOperation::OuterPidsResolve);
        let outer_pids = pids_resolve(&context, &outer_members, "pids", &outer_members, false);
        pids_stage(None, PidsOperation::OuterMemoryResolve);
        let outer_memory = pids_resolve(&context, &outer_members, "memory", &outer_members, false);
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = [
            Capability::StandaloneContainer,
            Capability::Command,
            Capability::ContainerLabels,
            Capability::PidsLimit,
        ]
        .into_iter()
        .map(|capability| CapabilityFact {
            capability,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: scope.clone(),
        })
        .collect();
        let mut cases = Vec::new();
        let mut namespaces = BTreeSet::new();
        let mut observer_kind = None;
        for index in 0..6 {
            let case_started = Instant::now();
            pids_stage(Some(index), PidsOperation::Preflight);
            let preflight_lines = pids_lines(
                pids_shell(
                    &run,
                    PIDS_PREFLIGHT,
                    &[
                        outer_pids["path"].as_str().unwrap().into(),
                        outer_memory["path"].as_str().unwrap().into(),
                        outer_memory["kind"].as_str().unwrap().into(),
                    ],
                ),
                &["PIDS", "PIDMAX", "MEMORY", "MEMMAX"],
            );
            let preflight = json!({"outer_pids":pids_u64(pids_field(&preflight_lines,"PIDS")),"outer_memory":pids_u64(pids_field(&preflight_lines,"MEMORY"))});
            assert!(
                pids_field(&preflight_lines, "PIDMAX") == "512"
                    && pids_field(&preflight_lines, "MEMMAX") == "4294967296"
                    && preflight["outer_pids"].as_u64().unwrap() <= 384
                    && preflight["outer_memory"].as_u64().unwrap() <= 3221225472,
                "actual headroom before each create"
            );
            pids_stage(Some(index), PidsOperation::Create);
            pids_create(&mut run, index);
            pids_stage(Some(index), PidsOperation::Start);
            start(&run, index);
            pids_stage(Some(index), PidsOperation::Inspect);
            let inspected = pids_configured(&run, index, &image);
            let id = run.ids[index].as_ref().unwrap().clone();
            pids_stage(Some(index), PidsOperation::PrivateIdentity);
            let private = docker(
                &run,
                &[
                    "exec".into(),
                    id,
                    "/bin/busybox".into(),
                    "ash".into(),
                    "-c".into(),
                    PIDS_PRIVATE_IDENTITY.into(),
                ],
            );
            let text = std::str::from_utf8(&private).unwrap();
            let fields: Vec<_> = text.split_whitespace().collect();
            assert!(
                fields.len() == 3 && pids_u64(fields[1]) == 0,
                "actual private PID1 identity"
            );
            let init_start = pids_u64(fields[0]);
            let namespace = pids_namespace(fields[2], "pid");
            assert!(
                namespace != daemon_ns
                    && namespace != pids_namespace(pids_field(&context, "PIDNS"), "pid")
                    && namespaces.insert(namespace),
                "six distinct independently bound private PID namespaces, separate from daemon and observer"
            );
            pids_stage(Some(index), PidsOperation::BaselineScan);
            let baseline_lines = pids_scan(
                &run,
                &context,
                namespace,
                depth,
                init_start,
                "ready",
                &mut coordinates,
            );
            let baseline_rows = pids_rows(&baseline_lines);
            assert!(
                baseline_rows.len() == 2,
                "only supervisor and held worker before pressure"
            );
            assert!(
                baseline_rows[1][3].as_u64().unwrap() >= init_start,
                "actual worker cannot predate original PID1"
            );
            assert!(
                pids_field(&baseline_lines, "F out READY")
                    == baseline_rows[1][1].as_u64().unwrap().to_string()
                    && pids_field(&baseline_lines, "F state WORKER")
                        == baseline_rows[1][1].as_u64().unwrap().to_string(),
                "live original worker barrier, not stale output"
            );
            let worker_pid = baseline_rows[1][1].as_u64().unwrap();
            let ready_log = vec![format!("READY {worker_pid}")];
            let worker_log = vec![format!("WORKER {worker_pid}")];
            assert!(
                pids_log(&baseline_lines, "out") == ready_log
                    && pids_log(&baseline_lines, "state") == worker_log
                    && pids_log(&baseline_lines, "err").is_empty(),
                "fresh closed original-worker readiness logs"
            );
            let outer_init = baseline_rows[0][0].as_u64().unwrap();
            let raw_init = baseline_lines
                .iter()
                .filter_map(|line| line.strip_prefix("R "))
                .find(|line| line.split_whitespace().nth(1) == Some("1"))
                .unwrap();
            let chain: Vec<_> = raw_init.split_whitespace().skip(5).map(pids_u64).collect();
            assert!(
                chain.len() > depth as usize
                    && chain[0] == outer_init
                    && chain.last() == Some(&1)
                    && inspected["State"]["Pid"] == chain[depth as usize - 1],
                "State.Pid bound at observed daemon namespace depth, never guessed outer PID"
            );
            let memberships: Vec<_> = baseline_lines
                .iter()
                .filter_map(|line| line.strip_prefix("G ").map(str::to_owned))
                .collect();
            pids_stage(Some(index), PidsOperation::LeafPidsResolve);
            let mut pids = pids_resolve(&context, &memberships, "pids", &outer_members, true);
            pids_stage(Some(index), PidsOperation::LeafMemoryResolve);
            let mut memory = pids_resolve(&context, &memberships, "memory", &outer_members, true);
            if let Some(kind) = &observer_kind {
                assert!(
                    *kind == pids["kind"],
                    "one independently observed controller generation"
                );
            } else {
                observer_kind = Some(pids["kind"].clone());
            }
            let uid = baseline_rows[0][4].as_u64().unwrap();
            assert!(
                baseline_rows.iter().all(|row| row[4] == uid),
                "same mapped workload UID"
            );
            let maps: Vec<_> = baseline_lines
                .iter()
                .filter_map(|line| line.strip_prefix("U "))
                .map(|line| line.split_whitespace().map(pids_u64).collect::<Vec<_>>())
                .filter(|parts| {
                    parts.len() == 3 && parts[0] == 0 && parts[2] > 0 && parts[1] == uid
                })
                .collect();
            assert!(
                maps.len() == 1,
                "private root UID translated through actual map"
            );
            let nproc = pids_nproc(&baseline_lines, &baseline_rows);
            pids_stage(Some(index), PidsOperation::BaselineController);
            let (baseline, event_source) = pids_controller(
                &run,
                &baseline_rows,
                "ready",
                &mut pids,
                &mut memory,
                &mut coordinates,
            );
            pids_stage(Some(index), PidsOperation::WorkStart);
            pids_control(&run, outer_init, namespace, init_start, uid, "START");
            pids_stage(Some(index), PidsOperation::HeldScan);
            let held_lines = pids_scan(
                &run,
                &context,
                namespace,
                depth,
                init_start,
                "exit_barrier",
                &mut coordinates,
            );
            let held_rows = pids_rows(&held_lines);
            let finite = index < 2;
            let successes = if finite { 14 } else { 32 };
            let attempts = if finite { 15 } else { 32 };
            assert!(
                held_rows.len() == successes + 2 && held_rows[..2] == baseline_rows,
                "same original worker held at actual leaf saturation"
            );
            assert!(
                pids_nproc(&held_lines, &held_rows) == nproc,
                "unchanged actual inherited RLIMIT_NPROC"
            );
            let children: Vec<_> = held_lines
                .iter()
                .filter_map(|line| line.strip_prefix("F out CHILD "))
                .map(pids_u64)
                .collect();
            assert!(
                children.len() == successes
                    && held_rows[2..]
                        .iter()
                        .zip(&children)
                        .all(|(row, pid)| row[1] == *pid
                            && row[2] == baseline_rows[1][0]
                            && row[4] == uid),
                "unchanged successful fork membership and real parentage"
            );
            let tries: Vec<_> = held_lines
                .iter()
                .filter_map(|line| line.strip_prefix("F out TRY "))
                .map(pids_u64)
                .collect();
            assert!(
                tries == (1..=attempts as u64).collect::<Vec<_>>(),
                "bounded once-only fork attempts"
            );
            let exit = pids_field(&held_lines, "F out EXIT");
            assert!(
                exit == format!(
                    "{} {} {}",
                    baseline_rows[1][1].as_u64().unwrap(),
                    if finite { 2 } else { 0 },
                    attempts
                ),
                "actual original-worker EXIT barrier status"
            );
            let mut expected_log = ready_log;
            for attempt in 1..=attempts {
                expected_log.push(format!("TRY {attempt}"));
                if let Some(pid) = children.get(attempt - 1) {
                    expected_log.push(format!("CHILD {pid}"));
                }
            }
            expected_log.push(format!("EXIT {exit}"));
            assert!(
                pids_log(&held_lines, "out") == expected_log
                    && pids_log(&held_lines, "state") == worker_log,
                "exact once-only original-worker event order"
            );
            let errors: Vec<_> = held_lines
                .iter()
                .filter_map(|line| line.strip_prefix("F err "))
                .collect();
            assert!(
                if finite {
                    errors.len() == 1
                        && matches!(
                            errors[0],
                            "dl-pids-worker: can't fork: Resource temporarily unavailable"
                                | "dl-pids-worker: line 1: can't fork: Resource temporarily unavailable"
                        )
                } else {
                    errors.is_empty()
                },
                "specific C-locale native EAGAIN envelope, never generic fork text"
            );
            pids_stage(Some(index), PidsOperation::HeldController);
            let (held, held_source) = pids_controller(
                &run,
                &held_rows,
                "exit_barrier",
                &mut pids,
                &mut memory,
                &mut coordinates,
            );
            assert!(
                held_source == event_source
                    && held["denials"].as_u64().unwrap()
                        == baseline["denials"].as_u64().unwrap() + u64::from(finite)
                    && held["oom_kills"] == baseline["oom_kills"],
                "attributable exclusive-leaf denial interval with no OOM"
            );
            pids_stage(Some(index), PidsOperation::Release);
            pids_control(&run, outer_init, namespace, init_start, uid, "RELEASE");
            pids_stage(Some(index), PidsOperation::RestoredScan);
            let restored_lines = pids_scan(
                &run,
                &context,
                namespace,
                depth,
                init_start,
                "idle",
                &mut coordinates,
            );
            let restored_rows = pids_rows(&restored_lines);
            assert!(
                restored_rows == vec![baseline_rows[0].clone()],
                "all worker/child processes gone before next workload"
            );
            let mut restored_log = worker_log;
            restored_log.push(format!("IDLE {}", if finite { 2 } else { 0 }));
            assert!(
                pids_log(&restored_lines, "state") == restored_log
                    && pids_log(&restored_lines, "out") == expected_log
                    && pids_log(&restored_lines, "err") == pids_log(&held_lines, "err"),
                "original worker status preserved through release with no new output"
            );
            pids_stage(Some(index), PidsOperation::RestoredController);
            let (restored, restored_source) = pids_controller(
                &run,
                &restored_rows,
                "idle",
                &mut pids,
                &mut memory,
                &mut coordinates,
            );
            assert!(
                restored_source == event_source
                    && restored["denials"] == held["denials"]
                    && restored["oom_kills"] == baseline["oom_kills"],
                "no additional hidden fork or OOM after release"
            );
            pids_stage(Some(index), PidsOperation::FinalInspect);
            assert!(
                pids_configured(&run, index, &image)["State"]["StartedAt"]
                    == inspected["State"]["StartedAt"],
                "same live PID1 start throughout effect"
            );
            assert!(
                case_started.elapsed() <= Duration::from_secs(15),
                "bounded PID case, never reset original deadline"
            );
            cases.push(json!({"case":PIDS_CASES[index/2].0,"role":if index.is_multiple_of(2){"oracle"}else{"rendered"},"id":run.ids[index],"name":run.names[index],"wire":if index.is_multiple_of(2){"independent_cli"}else{"literal_rendered"},"image_id":image["id"],"configured_limit":PIDS_CASES[index/2].1,"identity":{"private_pid":1,"private_uid":0,"start":init_start,"pid_namespace":namespace,"state_pid":inspected["State"]["Pid"],"nspid":chain,"uid_map":maps[0],"outer_uid":uid,"worker_private":baseline_rows[1][1],"worker_start":baseline_rows[1][3]},"pids_mapping":pids,"memory_mapping":memory,"event_source":event_source,"nproc":nproc,"preflight":preflight,"baseline":baseline,"held":held,"restored":restored,"work":{"attempts":attempts,"successes":successes,"exit_status":if finite{2}else{0},"diagnostic":if finite{"native_c_eagain_fork"}else{"none"},"held_barrier":true,"release":"all_children_gone"},"elapsed_ns":case_started.elapsed().as_nanos() as u64,"cleanup":"absent"}));
        }
        pids_stage(None, PidsOperation::Acquisition);
        let acquisition = pids_acquisition(&run);
        let observer = json!({"pid_namespace":pids_namespace(pids_field(&context,"PIDNS"),"pid"),"mount_namespace":pids_namespace(pids_field(&context,"MNTNS"),"mnt"),"cgroup_namespace":pids_namespace(pids_field(&context,"CGNS"),"cgroup"),"daemon_pid_namespace":daemon_ns,"daemon_depth":depth,"daemon_uid":daemon_uid,"cgroup_kind":observer_kind.unwrap(),"outer_process_ceiling":512});
        (
            daemon_uid,
            image,
            cases,
            acquisition,
            observer,
            coordinates.finish(),
        )
    }));
    let calls = run.calls.get();
    let bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    let disposition = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let attempted = run.attempted.clone();
        let ids = run.ids.clone();
        pids_cleanup_with(&attempted, &ids, || cleanup(&mut run))
    }))
    .unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - calls;
    let cleanup_bytes = run.bytes.get() - bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    let (daemon_uid, image, cases, acquisition, observer, coordinates) =
        require_verified_result(result, disposition);
    pids_stage(None, PidsOperation::FinalSnapshots);
    assert!(
        !run.image_attempted
            && run.derived_id.is_none()
            && image_snapshot(&run) == image
            && outer_context(&run) == owner.snapshot,
        "unchanged borrowed image and owned outer after verified cleanup"
    );
    let ordinary = started.elapsed().saturating_sub(cleanup_elapsed);
    assert!(
        run.calls.get() - cleanup_calls
            == if run.lane.starts_with("debian11-") {
                124
            } else {
                123
            },
        "exact charged PID call ledger"
    );
    assert!(
        run.calls.get() - cleanup_calls <= 180
            && cleanup_calls == 54
            && run.bytes.get() - cleanup_bytes <= MAX_BYTES - CLEANUP_BYTES
            && cleanup_bytes <= CLEANUP_BYTES
            && ordinary <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "actual bounded PID accounting"
    );
    let mut proof = json!({"schema_version":2,"contract":PIDS_CONTRACT,"capability_admission":[],"catalogue_admission":false,"scope":PIDS_SCOPE,"context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-"){"1.41"}else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},"docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":daemon_uid,"outer":owner.snapshot},"borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"observer":observer,"cases":cases,"acquisition":acquisition,"accounting":{"ordinary_calls":run.calls.get()-cleanup_calls,"ordinary_bytes":run.bytes.get()-cleanup_bytes,"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"ordinary_elapsed_ns":ordinary.as_nanos() as u64,"cleanup_elapsed_ns":cleanup_elapsed.as_nanos() as u64,"elapsed_ns":started.elapsed().as_nanos() as u64,"deadline_seconds":180,"cleanup_reserve_seconds":46},"cleanup":{"containers":"absent","rounds":2,"outstanding":0,"uncertain":false}});
    pids_private_v2(&mut proof, coordinates);
    proof["boundary"] = private.value["boundary"].clone();
    pids_proof_budget(&proof);
    pids_stage(None, PidsOperation::Proof);
    private.require_active(true);
    target.publish(&proof);
    private.require_active(true);
}

#[test]
fn pids_resolution_handles_v1_comount_and_v2_nonroot_mount_roots() {
    let legacy =
        vec!["M 31 22 0:20 /owned /sys/fs/cgroup rw - cgroup cgroup rw,pids,memory".into()];
    for controller in ["pids", "memory"] {
        let resolved = pids_resolve(
            &legacy,
            &["7:pids,memory:/owned/leaf".into()],
            controller,
            &["7:pids,memory:/owned".into()],
            true,
        );
        assert_eq!(
            resolved,
            json!({"kind":"v1","mount_id":31,"root":"/owned","mountpoint":"/sys/fs/cgroup","membership":"/owned/leaf","path":"/sys/fs/cgroup/leaf","outer_membership":"/owned","outer_path":"/sys/fs/cgroup","inode":0,"device":0})
        );
    }
    let unified = vec!["M 32 22 0:21 /boundary /sys/fs/cgroup rw - cgroup2 cgroup rw".into()];
    let resolved = pids_resolve(
        &unified,
        &["0::/boundary/owned/leaf".into()],
        "pids",
        &["0::/boundary/owned".into()],
        true,
    );
    assert_eq!(
        resolved,
        json!({"kind":"v2","mount_id":32,"root":"/boundary","mountpoint":"/sys/fs/cgroup","membership":"/boundary/owned/leaf","path":"/sys/fs/cgroup/owned/leaf","outer_membership":"/boundary/owned","outer_path":"/sys/fs/cgroup/owned","inode":0,"device":0})
    );
    let outer = pids_resolve(
        &unified,
        &["0::/boundary/owned".into()],
        "memory",
        &["0::/boundary/owned".into()],
        false,
    );
    assert_eq!(outer["path"], "/sys/fs/cgroup/owned");
    assert_eq!(outer["path"], outer["outer_path"]);
}

#[test]
fn pids_resolution_canonicalizes_empty_suffix_for_v2_mount_root() {
    let mounts = vec!["M 32 22 0:21 /boundary /sys/fs/cgroup rw - cgroup2 cgroup rw".into()];
    let resolved = pids_resolve(
        &mounts,
        &["0::/boundary/leaf".into()],
        "pids",
        &["0::/boundary".into()],
        true,
    );
    assert_eq!(
        resolved,
        json!({"kind":"v2","mount_id":32,"root":"/boundary","mountpoint":"/sys/fs/cgroup","membership":"/boundary/leaf","path":"/sys/fs/cgroup/leaf","outer_membership":"/boundary","outer_path":"/sys/fs/cgroup","inode":0,"device":0})
    );
    let outer = pids_resolve(
        &mounts,
        &["0::/boundary".into()],
        "memory",
        &["0::/boundary".into()],
        false,
    );
    assert_eq!(outer["path"], "/sys/fs/cgroup");
    assert_eq!(outer["path"], outer["outer_path"]);
}

#[test]
fn pids_resolution_keeps_untranslated_sibling_duplicate_and_strict_descendant_refusals() {
    let root_mount = "M 31 22 0:20 / /sys/fs/cgroup rw - cgroup2 cgroup rw";
    for (mounts, selected, owner, descendant) in [
        (
            vec!["M 31 22 0:20 / /tmp rw - tmpfs tmpfs rw"],
            "/owned/leaf",
            "/owned",
            true,
        ),
        (
            vec!["M 31 22 0:20 /owned /sys/fs/cgroup rw - cgroup2 cgroup rw"],
            "/",
            "/",
            false,
        ),
        (vec![root_mount], "/owned-sibling/leaf", "/owned", true),
        (vec![root_mount], "/owned", "/owned", true),
        (
            vec![root_mount, "M 32 22 0:20 / /other rw - cgroup2 cgroup rw"],
            "/owned/leaf",
            "/owned",
            true,
        ),
    ] {
        let mounts: Vec<_> = mounts.into_iter().map(str::to_owned).collect();
        let result = std::panic::catch_unwind(|| {
            pids_resolve(
                &mounts,
                &[format!("0::{selected}")],
                "pids",
                &[format!("0::{owner}")],
                descendant,
            )
        });
        assert!(
            result.is_err(),
            "ambiguous or unowned controller mapping must refuse"
        );
    }
    // More than one generation-eligible mount is not itself ambiguous: only
    // candidates surviving the unchanged root/ownership predicates count.
    let resolved = pids_resolve(
        &[
            root_mount.into(),
            "M 32 22 0:20 /elsewhere /other rw - cgroup2 cgroup rw".into(),
        ],
        &["0::/owned/leaf".into()],
        "pids",
        &["0::/owned".into()],
        true,
    );
    assert_eq!(resolved["path"], "/sys/fs/cgroup/owned/leaf");
}

#[test]
fn pids_resolution_diagnostic_classification_uses_only_existing_predicate_observations() {
    for (eligible, rooted, candidates, expected, label) in [
        (
            false,
            false,
            0,
            PidsResolutionFailure::NoControllerMount,
            "no_controller_mount",
        ),
        (
            true,
            false,
            0,
            PidsResolutionFailure::RootCoordinateMismatch,
            "root_coordinate_mismatch",
        ),
        (
            true,
            true,
            0,
            PidsResolutionFailure::OutsideOwnedDescendant,
            "outside_owned_descendant",
        ),
        (
            true,
            true,
            2,
            PidsResolutionFailure::MultipleEligibleMounts,
            "multiple_eligible_mounts",
        ),
    ] {
        let reason = pids_resolution_failure(eligible, rooted, candidates).unwrap();
        assert_eq!(reason, expected);
        assert_eq!(reason.label(), label);
    }
    assert_eq!(pids_resolution_failure(true, true, 1), None);
}

#[test]
fn pids_resolution_ownership_diagnostics_distinguish_equal_and_outside_boundaries() {
    for (selected, owner, descendant, expected) in [
        ("/owned", "/owned", true, " relation=equal_owner"),
        (
            "/owned-sibling/leaf",
            "/owned",
            true,
            " relation=outside_owner",
        ),
        (
            "/elsewhere/leaf",
            "/owned",
            false,
            " relation=outside_owner",
        ),
        ("/owned/leaf", "/owned", true, ""),
        ("/owned", "/owned", false, ""),
    ] {
        let path = pids_safe_path(selected);
        let outer_path = pids_safe_path(owner);
        assert_eq!(
            pids_owned_relation(
                descendant && path == outer_path,
                !path.starts_with(&outer_path)
            ),
            expected
        );
    }
    assert_eq!(pids_owned_relation(true, true), " relation=mixed");
}

#[test]
fn pids_controller_diagnostics_use_only_canonical_existing_current_observations() {
    for (members_match, current, expected) in [
        (true, "2", None),
        (false, "2", Some("member_ids_mismatch")),
        (true, "3", Some("current_count_mismatch")),
        (false, "3", Some("members_and_current_mismatch")),
        (true, "0", Some("current_count_mismatch")),
    ] {
        assert_eq!(
            pids_controller_failure(members_match, &[format!("CURRENT {current}")], 2),
            expected
        );
    }
    for invalid in [
        "",
        "02",
        "+2",
        "-2",
        " 2",
        "2 ",
        "2\n",
        "２",
        "18446744073709551616",
    ] {
        for members_match in [false, true] {
            assert_eq!(
                pids_controller_failure(members_match, &[format!("CURRENT {invalid}")], 2),
                None
            );
        }
    }
    for lines in [
        vec![],
        vec!["MAX 2".into()],
        vec!["CURRENT 2".into(), "CURRENT 2".into()],
    ] {
        for members_match in [false, true] {
            assert_eq!(pids_controller_failure(members_match, &lines, 2), None);
        }
    }
}

// Independently authored complete shell frames, not packed proof-reader rows.
// Private PID order is deliberately the reverse of noncontiguous outer PID order.
fn pids_raw_frame_fixture() -> (&'static str, &'static str) {
    (
        "SELF 88 88 88\nPIDNS pid:[700]\nMNTNS mnt:[701]\nCGNS cgroup:[702]\nINIT 4317\n\
U 0 1000 1\nG 0::/owned/leaf\nL Max processes 4096 4096 processes\n\
F state WORKER 2\nF out READY 2\n\
R 2579 2 4317 50003 1000 2579 72 2\nT 2579 Max processes 4096 4096 processes\n\
R 4317 1 77 50000 1000 4317 71 1\nT 4317 Max processes 4096 4096 processes\n\
R 903 9 2579 50008 1000 903 79 9\nT 903 Max processes 4096 4096 processes\nEND\n",
        "SELF 99 99 99\nPIDNS pid:[700]\nMNTNS mnt:[701]\nCGNS cgroup:[702]\n\
STAT /sys/fs/cgroup/owned/leaf 41 1701\nSTAT /sys/fs/cgroup/owned 41 1700\n\
MAX 16\nCURRENT 3\nSOURCE pids.events.local\nDENIALS 0\n\
MEMBER 2579\nMEMBER 4317\nMEMBER 903\n\
OUTERPIDS 11\nOUTERMAX 512\nOUTERMEMORY 1048576\nOUTERMEMMAX 4294967296\n\
OOM 0\nANCESTOR 11\nCEILING 512\nEND\n",
    )
}

fn pids_raw_scan_rows(frame: &str) -> Vec<Value> {
    let lines = pids_lines(
        frame.as_bytes().to_vec(),
        &[
            "SELF", "PIDNS", "MNTNS", "CGNS", "INIT", "U", "G", "L", "F", "R", "T",
        ],
    );
    let mut coordinates = pids_raw_coordinates();
    coordinates.observe(&lines);
    pids_rows(&lines)
}

fn pids_raw_coordinates() -> PidsCoordinates {
    PidsCoordinates::new(&pids_lines(
        b"SELF 77 77 77\nPIDNS pid:[700]\nMNTNS mnt:[701]\nCGNS cgroup:[702]\nEND\n".to_vec(),
        &["SELF", "PIDNS", "MNTNS", "CGNS"],
    ))
}

fn pids_raw_controller(frame: &str, rows: &[Value]) -> (Value, String) {
    let mapping = json!({"kind":"v2","path":"/sys/fs/cgroup/owned/leaf","outer_path":"/sys/fs/cgroup/owned","inode":0,"device":0});
    pids_controller_frame(
        frame.as_bytes().to_vec(),
        rows,
        "baseline",
        &mut mapping.clone(),
        &mut mapping.clone(),
        &mut pids_raw_coordinates(),
    )
}

#[test]
fn pids_raw_frames_compare_outer_members_before_delta_encoding() {
    let (scan, controller) = pids_raw_frame_fixture();
    let rows = pids_raw_scan_rows(scan);
    assert_eq!(
        rows,
        vec![
            json!([4317, 1, 77, 50000, 1000]),
            json!([2579, 2, 4317, 50003, 1000]),
            json!([903, 9, 2579, 50008, 1000]),
        ]
    );
    let (proof, source) = pids_raw_controller(controller, &rows);
    assert_eq!(source, "pids.events.local");
    assert_eq!(
        proof,
        json!({"rows":[[0,1,-4240,0,0],[-1738,2,0,3,0],[-3414,9,-1738,8,0]],"members":[-3414,-1738,0],"pids_current":3,"pids_max":16,"denials":0,"oom_kills":0,"outer_pids":11,"outer_memory":1048576,"ancestor_headroom":501,"phase":"baseline"})
    );
    // Encoding is output-only: raw MEMBER lines above contain neither these
    // deltas nor private PIDs. Reconstruct the independently expected outer IDs.
    let reconstructed: Vec<_> = proof["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pid| pid.as_i64().unwrap() + 4317)
        .collect();
    assert_eq!(reconstructed, vec![903, 2579, 4317]);
}

#[test]
fn pids_coordinate_witnesses_retain_all_37_actual_observations_in_order() {
    let mut coordinates = pids_raw_coordinates();
    let mut expected = vec![json!([77, 0, [0], 0, 0, 0])];
    for pid in (101..136).chain([4194304]) {
        let lines = vec![
            format!("SELF {pid} {pid} {pid}"),
            "PIDNS pid:[700]".into(),
            "MNTNS mnt:[701]".into(),
            "CGNS cgroup:[702]".into(),
        ];
        coordinates.observe(&lines);
        expected.push(json!([pid, 0, [0], 0, 0, 0]));
    }
    assert_eq!(coordinates.finish(), expected);
    assert!(std::panic::catch_unwind(|| pids_raw_coordinates().finish()).is_err());
}

#[test]
fn pids_coordinate_witnesses_refuse_legacy_malformed_nested_or_changed_views() {
    let (_, controller) = pids_raw_frame_fixture();
    let rows = pids_raw_scan_rows(pids_raw_frame_fixture().0);
    for frame in [
        controller.replace("SELF 99 99 99\n", ""),
        controller.replace("SELF 99 99 99", "SELF 99 99"),
        controller.replace("SELF 99 99 99", "SELF 99 99 99 1"),
        controller.replace("SELF 99 99 99", "SELF 99 99 99 99"),
        controller.replace("SELF 99 99 99", "SELF 99 98 99"),
        controller.replace("SELF 99 99 99", "SELF 99 99 98"),
        controller.replace("SELF 99 99 99", "SELF 0 0 0"),
        controller.replace("SELF 99 99 99", "SELF 099 99 99"),
        controller.replace("SELF 99 99 99", "SELF +99 99 99"),
        controller.replace("SELF 99 99 99", "SELF 4194305 4194305 4194305"),
        controller.replace("SELF 99 99 99", "SELF 18446744073709551616 99 99"),
        controller.replace("SELF 99 99 99", "SELF 99 99 1 2 3 4 5 6 7 8 9"),
        controller.replace("SELF 99 99 99\n", "SELF 99 99 99\nSELF 99 99 99\n"),
        controller.replace("PIDNS pid:[700]", "PIDNS pid:[703]"),
        controller.replace("MNTNS mnt:[701]", "MNTNS mnt:[703]"),
        controller.replace("CGNS cgroup:[702]", "CGNS cgroup:[703]"),
        controller.replace("PIDNS pid:[700]\n", "PIDNS pid:[700]\nPIDNS pid:[700]\n"),
    ] {
        assert!(std::panic::catch_unwind(|| pids_raw_controller(&frame, &rows)).is_err());
    }
}

#[test]
fn pids_private_v2_phase_tuples_preserve_every_original_value() {
    let (scan, controller) = pids_raw_frame_fixture();
    let snapshot = pids_raw_controller(controller, &pids_raw_scan_rows(scan)).0;
    let mut proof = json!({"schema_version":2,"contract":PIDS_CONTRACT,"unchanged":[true,"canary"],"cases":(0..6).map(|index| json!({"case":index,"baseline":snapshot,"held":snapshot,"restored":snapshot,"unchanged":[index,"case-canary"]})).collect::<Vec<_>>()});
    let original = proof.clone();
    let mut coordinates = pids_raw_coordinates();
    for pid in 100..136 {
        coordinates.observe(&[
            format!("SELF {pid} {pid} {pid}"),
            "PIDNS pid:[700]".into(),
            "MNTNS mnt:[701]".into(),
            "CGNS cgroup:[702]".into(),
        ]);
    }
    pids_private_v2(&mut proof, coordinates.finish());
    pids_proof_budget(&proof);
    assert_eq!(proof["coordinates"].as_array().unwrap().len(), 37);
    for case in proof["cases"].as_array_mut().unwrap() {
        for phase in ["baseline", "held", "restored"] {
            let tuple = case[phase].as_array().unwrap();
            assert_eq!(tuple.len(), 10);
            // Independently specified slots, not the producer's field table.
            case[phase] = json!({"rows":tuple[0],"members":tuple[1],"pids_current":tuple[2],"pids_max":tuple[3],"denials":tuple[4],"oom_kills":tuple[5],"outer_pids":tuple[6],"outer_memory":tuple[7],"ancestor_headroom":tuple[8],"phase":tuple[9]});
        }
    }
    proof.as_object_mut().unwrap().remove("coordinates");
    assert_eq!(proof, original);
    let mut extra_field = snapshot.clone();
    extra_field["new-undisposed-field"] = json!(1);
    assert!(std::panic::catch_unwind(move || pids_compact_phase(&mut extra_field)).is_err());
    let mut legacy = original;
    legacy["schema_version"] = json!(1);
    legacy["contract"] = json!("pids-limit-v1");
    assert!(
        std::panic::catch_unwind(move || pids_private_v2(&mut legacy, vec![Value::Null; 37]))
            .is_err()
    );
}

#[test]
fn pids_private_v2_custody_keeps_exact_outer_binding_reserve() {
    pids_proof_budget(&json!("x".repeat(15358)));
    for size in [15359, 16382, 16383] {
        assert!(std::panic::catch_unwind(|| pids_proof_budget(&json!("x".repeat(size)))).is_err());
    }
}

#[test]
fn pids_raw_controller_frames_keep_membership_and_parser_refusals() {
    let (scan, controller) = pids_raw_frame_fixture();
    let rows = pids_raw_scan_rows(scan);
    for (frame, expected_panic) in [
        (
            controller
                .replace("PIDNS pid:[700]", "PIDNS pid:[703]")
                .replace("CURRENT 3\n", "CURRENT 03\n")
                .replace("MEMBER 903\n", "MEMBER 9\n"),
            "same initial observer namespaces before controller comparison",
        ),
        (
            controller.replace(
                "MEMBER 2579\nMEMBER 4317\nMEMBER 903",
                "MEMBER 2\nMEMBER 1\nMEMBER 9",
            ),
            "exclusive single-threaded leaf membership",
        ),
        (
            controller.replace("MEMBER 903\n", "MEMBER 903\nMEMBER 903\n"),
            "exclusive single-threaded leaf membership",
        ),
        (
            controller.replace("CURRENT 3\n", "CURRENT 3\nCURRENT 3\n"),
            "unique PID frame field",
        ),
        (
            controller.replace("MEMBER 903\n", "MEMBER 0903\n"),
            "canonical PID decimal",
        ),
        (
            controller.replace("CURRENT 3\n", "CURRENT 03\n"),
            "canonical PID decimal",
        ),
        (
            controller.replace("CURRENT 3\n", "CURRENT 2\n"),
            "exclusive single-threaded leaf membership",
        ),
        (
            controller.replace("END\n", "END\nEND\n"),
            "closed complete PID frame keys",
        ),
        (controller.replace("END\n", "END"), "complete PID frame"),
        (
            controller.replace("END\n", "UNKNOWN 1\nEND\n"),
            "closed complete PID frame keys",
        ),
        // A mismatched member set must still short-circuit CURRENT parsing.
        (
            controller
                .replace("MEMBER 903\n", "MEMBER 9\n")
                .replace("CURRENT 3\n", "CURRENT 03\n"),
            "exclusive single-threaded leaf membership",
        ),
    ] {
        let panic = std::panic::catch_unwind(|| pids_raw_controller(&frame, &rows)).unwrap_err();
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some(expected_panic));
    }
}

#[test]
fn pids_raw_scan_frames_keep_namespace_binding_and_duplicate_refusals() {
    let (scan, controller) = pids_raw_frame_fixture();
    for frame in [
        scan.replace("INIT 4317\n", "INIT 4317\nINIT 4317\n"),
        scan.replace("1000 903 79 9", "1000 904 79 9"),
        scan.replace("1000 903 79 9", "1000 903 79 8"),
        scan.replace(
            "R 903 9 2579 50008 1000 903 79 9",
            "R 903 9 2579 50008 1000",
        ),
        scan.replace("R 903 9", "R 0903 9")
            .replace("1000 903 79 9", "1000 0903 79 9"),
        scan.replace("END\n", "END\nEND\n"),
        scan.replace("END\n", "END"),
        // Repeated R lines remain visible to the unchanged membership equality.
        scan.replace("END\n", "R 903 9 2579 50008 1000 903 79 9\nEND\n"),
    ] {
        assert!(
            std::panic::catch_unwind(|| {
                pids_raw_controller(controller, &pids_raw_scan_rows(&frame))
            })
            .is_err()
        );
    }
}

#[test]
fn pids_unknown_create_never_enters_inner_cleanup() {
    let attempted = vec![true; 6];
    for invalid in [None, Some("bad".to_owned()), Some("A".repeat(64))] {
        let mut ids: Vec<_> = (1..=6)
            .map(|number| Some(format!("{number:064x}")))
            .collect();
        ids[2] = invalid;
        let called = Cell::new(false);
        assert!(
            pids_cleanup_with(&attempted, &ids, || {
                called.set(true);
                CleanupDisposition::VerifiedAbsent
            }) == CleanupDisposition::OuterTeardownRequired
                && !called.get(),
            "unbound create requires outer teardown before any recovery"
        );
    }
}

fn pids_private_context_fixture() -> Value {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 180;
    let start = private_monotonic_ns();
    json!({
        "schema_version":1,"contract":"outer-private-context-v1",
        "binding":{"session":"1".repeat(64),"execution_origin":"github_actions","candidate_sha":"a".repeat(40),"ci_run_id":"1","ci_run_attempt":"1","owner":"A1B2C3D4","lane":"debian11-rootful","outer_id":"2".repeat(64),"intent_digest":"3".repeat(64),"expectation_digest":"4".repeat(64)},
        "source":{"intent":{},"preflight":{},"database":{},"oci":{},"log":{}},
        "boundary":[1,[23,55,0],[700,701,702],[11,10,9],[41,1700],"5".repeat(64),"6".repeat(64),"3".repeat(64),"4".repeat(64),["7".repeat(64),format!("sha256:{}","8".repeat(64)),0]],
        "pids":{"start_ns":start,"deadline_ns":start + 180 * SECOND,"deadline_epoch":epoch,"producer_reservation":{"ordinary_calls":124,"ordinary_bytes":1572864,"cleanup_calls":54,"cleanup_bytes":1048576},"external_reservation":{"ordinary_calls":56,"ordinary_bytes":524288,"cleanup_calls":46,"cleanup_bytes":1048576}}
    })
}

#[test]
fn pids_private_context_is_closed_bounded_and_reserves_input_once() {
    let value = pids_private_context_fixture();
    let bytes = serde_json::to_vec(&value).unwrap();
    let context = PidsPrivateContext::read(bytes.as_slice());
    assert_eq!(context.value, value);
    let budget = context.budget();
    assert_eq!(budget.state.lock().unwrap().spent[0], [0, bytes.len()]);
    assert!(budget.debit(false, 16, PIDS_CAPTURE_BYTES));
    assert_eq!(
        budget.state.lock().unwrap().spent[0],
        [16, bytes.len() + PIDS_CAPTURE_BYTES]
    );
    for pointer in [
        "/unexpected",
        "/binding/unexpected",
        "/source/unexpected",
        "/pids/unexpected",
        "/pids/producer_reservation/unexpected",
        "/pids/external_reservation/unexpected",
    ] {
        let mut invalid = value.clone();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        invalid
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), json!(0));
        assert!(
            std::panic::catch_unwind(|| PidsPrivateContext::parse(
                &serde_json::to_vec(&invalid).unwrap()
            ))
            .is_err()
        );
    }
    for (pointer, replacement) in [
        ("/schema_version", json!(true)),
        ("/contract", json!("outer-private-context-v2")),
        ("/binding/session", json!("a".repeat(63))),
        ("/binding/ci_run_id", json!("01")),
        ("/binding/owner", json!("../owner")),
        ("/binding/lane", json!("other")),
        ("/source/oci", json!([])),
        ("/pids/start_ns", json!(true)),
        ("/pids/deadline_ns", json!(46 * SECOND + 1)),
        ("/pids/deadline_ns", json!(180 * SECOND + 2)),
        ("/pids/deadline_epoch", json!(0)),
        ("/pids/producer_reservation/ordinary_calls", json!(125)),
        ("/pids/producer_reservation/cleanup_calls", json!(55)),
        ("/pids/producer_reservation/ordinary_bytes", json!(1572865)),
        ("/pids/producer_reservation/cleanup_bytes", json!(1048577)),
        ("/pids/producer_reservation/ordinary_calls", json!(u64::MAX)),
        ("/boundary/0", json!(true)),
        ("/boundary/1/0", json!(0)),
        ("/boundary/1/1", json!(0)),
        ("/boundary/1/2", json!(u64::from(u32::MAX) + 1)),
        ("/boundary/2/1", json!(0)),
        ("/boundary/3/0", json!(0)),
        ("/boundary/4/1", json!(false)),
        ("/boundary/7", json!("9".repeat(64))),
        ("/boundary/9/2", json!(2)),
    ] {
        let mut invalid = value.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            std::panic::catch_unwind(|| PidsPrivateContext::parse(
                &serde_json::to_vec(&invalid).unwrap()
            ))
            .is_err()
        );
    }
}

#[test]
fn pids_private_context_rejects_recursive_escaped_duplicates_and_overflow() {
    for bytes in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#.as_slice(),
        br#"{"source":{"opaque":[{"a":1,"a":2}]}}"#.as_slice(),
    ] {
        assert!(std::panic::catch_unwind(|| pids_unique_json(bytes)).is_err());
    }
    assert_eq!(
        pids_unique_json(br#"{"a":{"escaped\"key":[true,null,"x"]}}"#),
        json!({"a":{"escaped\"key":[true,null,"x"]}})
    );
    let consumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    struct Endless(Arc<std::sync::atomic::AtomicUsize>);
    impl Read for Endless {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            bytes.fill(b'x');
            self.0.fetch_add(bytes.len(), Ordering::Relaxed);
            Ok(bytes.len())
        }
    }
    let held = Arc::clone(&consumed);
    assert!(std::panic::catch_unwind(|| PidsPrivateContext::read(Endless(held))).is_err());
    assert_eq!(consumed.load(Ordering::Relaxed), PIDS_CONTEXT_BYTES + 1);
    assert!(std::panic::catch_unwind(|| PidsPrivateContext::read(std::io::empty())).is_err());
}

fn pids_authenticated_frame() -> Vec<String> {
    [
        "SELF 77 77 77",
        "PIDNS pid:[700]",
        "MNTNS mnt:[701]",
        "CGNS cgroup:[702]",
        "AUTHSTART 55",
        "AUTHUID 0 0 0 0",
        "AUTHPIDNS pid:[700]",
        "AUTHMNTNS mnt:[701]",
        "AUTHCGNS cgroup:[702]",
        "AUTHMEMBER 0::/",
        "AUTHROOT 41 1700",
        "AUTHMAX 512 4294967296",
        "M 11 10 0:9 / /sys/fs/cgroup rw - cgroup2 cgroup rw",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn pids_authenticated_root_is_rechecked_on_all_37_observers() {
    let boundary = pids_private_context_fixture()["boundary"].clone();
    let lines = pids_authenticated_frame();
    let mut coordinates = PidsCoordinates::authenticated(&lines, &boundary);
    for index in 1..37 {
        let mut next = lines.clone();
        if index % 2 == 1 {
            next[9] = "AUTHMEMBER 0::/init.scope".into();
        }
        coordinates.observe(&next);
    }
    assert_eq!(coordinates.finish().len(), 37);
    for (key, bad) in [
        ("AUTHSTART", "56"),
        ("AUTHUID", "0 0 1 0"),
        ("AUTHUID", "0 0 0"),
        ("AUTHPIDNS", "pid:[703]"),
        ("AUTHMNTNS", "mnt:[703]"),
        ("AUTHCGNS", "cgroup:[703]"),
        ("AUTHMEMBER", "0::/same-limits-child"),
        ("AUTHROOT", "41 1701"),
        ("AUTHROOT", "42 1700"),
        ("AUTHMAX", "511 4294967296"),
        ("AUTHMAX", "512 4294967295"),
        ("M", "12 10 0:9 / /sys/fs/cgroup rw - cgroup2 cgroup rw"),
        ("M", "11 12 0:9 / /sys/fs/cgroup rw - cgroup2 cgroup rw"),
        ("M", "11 10 0:8 / /sys/fs/cgroup rw - cgroup2 cgroup rw"),
        (
            "M",
            "11 10 0:9 /descendant /sys/fs/cgroup rw - cgroup2 cgroup rw",
        ),
    ] {
        let mut changed = lines.clone();
        *changed
            .iter_mut()
            .find(|line| line.starts_with(&format!("{key} ")))
            .unwrap() = format!("{key} {bad}");
        assert!(
            std::panic::catch_unwind(|| PidsCoordinates::authenticated(&changed, &boundary))
                .is_err()
        );
    }
    for key in PIDS_AUTH_KEYS {
        let prefix = format!("{key} ");
        let mut missing = lines.clone();
        missing.retain(|line| !line.starts_with(&prefix));
        assert!(
            std::panic::catch_unwind(|| PidsCoordinates::authenticated(&missing, &boundary))
                .is_err()
        );
        let mut duplicate = lines.clone();
        duplicate.push(
            lines
                .iter()
                .find(|line| line.starts_with(&prefix))
                .unwrap()
                .clone(),
        );
        assert!(
            std::panic::catch_unwind(|| PidsCoordinates::authenticated(&duplicate, &boundary))
                .is_err()
        );
    }
}

#[test]
fn pids_private_boundary_uses_only_the_existing_reserved_proof_space() {
    let mut proof = json!({"payload":"x".repeat(15340)});
    let main_size = serde_json::to_vec(&proof).unwrap().len();
    assert!(main_size <= 15360);
    proof["boundary"] = pids_private_context_fixture()["boundary"].clone();
    assert!(serde_json::to_vec(&proof).unwrap().len() > 15360);
    pids_proof_budget(&proof);
    proof["boundary"] = json!("x".repeat(1024));
    assert!(std::panic::catch_unwind(|| pids_proof_budget(&proof)).is_err());
}

#[test]
fn pids_private_context_binds_independent_invocation_values_without_printing_sources() {
    let value = pids_private_context_fixture();
    let context = PidsPrivateContext::parse(&serde_json::to_vec(&value).unwrap());
    let candidate = "a".repeat(40);
    let outer_id = "2".repeat(64);
    let epoch = value["pids"]["deadline_epoch"].as_u64().unwrap();
    context.bind_expected(&candidate, "A1B2C3D4", "debian11-rootful", &outer_id, epoch);
    for (candidate, owner, lane, outer_id, epoch) in [
        (
            "wrong",
            "A1B2C3D4",
            "debian11-rootful",
            outer_id.as_str(),
            epoch,
        ),
        (
            candidate.as_str(),
            "wrong",
            "debian11-rootful",
            outer_id.as_str(),
            epoch,
        ),
        (
            candidate.as_str(),
            "A1B2C3D4",
            "upstream-rootful",
            outer_id.as_str(),
            epoch,
        ),
        (
            candidate.as_str(),
            "A1B2C3D4",
            "debian11-rootful",
            "wrong",
            epoch,
        ),
        (
            candidate.as_str(),
            "A1B2C3D4",
            "debian11-rootful",
            outer_id.as_str(),
            epoch + 1,
        ),
    ] {
        assert!(
            std::panic::catch_unwind(
                || context.bind_expected(candidate, owner, lane, outer_id, epoch)
            )
            .is_err()
        );
    }
    let canary = "PRIVATE_CONTEXT_CANARY_9d7e3a";
    let mut source = value.clone();
    source["source"]["oci"] = json!({"protected":canary});
    source["binding"]["candidate_sha"] = json!(canary);
    let raw = serde_json::to_vec(&source).unwrap();
    for raw in [
        raw,
        format!("{{\"source\":\"{canary}\",\"source\":null}}").into_bytes(),
        format!("{{\"{canary}\"").into_bytes(),
    ] {
        let panic = std::panic::catch_unwind(|| PidsPrivateContext::parse(&raw))
            .err()
            .unwrap();
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("");
        assert!(
            !message.contains(canary),
            "private context panic is value-free"
        );
    }
}

#[test]
fn pids_private_context_rejects_expired_future_or_delayed_original_monotonic_time() {
    let mut value = pids_private_context_fixture();
    let start = 1000 * SECOND;
    let end = start + 180 * SECOND;
    value["pids"]["start_ns"] = json!(start);
    value["pids"]["deadline_ns"] = json!(end);
    let bytes = serde_json::to_vec(&value).unwrap();
    let anchor = Instant::now();
    let early = PidsPrivateContext::parse_at(&bytes, anchor, start + 5 * SECOND);
    assert_eq!(early.deadline, anchor + Duration::from_secs(175));
    let late = PidsPrivateContext::parse_at(
        &bytes,
        anchor + Duration::from_secs(115),
        start + 120 * SECOND,
    );
    assert_eq!(late.deadline, early.deadline);
    for now in [
        start - 1,
        end - 46 * SECOND,
        end - 1,
        end,
        end + 1,
        u64::MAX,
    ] {
        assert!(
            std::panic::catch_unwind(|| PidsPrivateContext::parse_at(&bytes, anchor, now)).is_err()
        );
    }
    // Repeated parsing and arbitrary wall-clock labels cannot renew D. Epoch
    // is only a separately bound custody label after anonymous-pipe admission.
    for epoch in [1, u64::MAX] {
        value["pids"]["deadline_epoch"] = json!(epoch);
        let context = PidsPrivateContext::parse_at(
            &serde_json::to_vec(&value).unwrap(),
            anchor,
            start + 5 * SECOND,
        );
        assert_eq!(context.deadline, early.deadline);
        assert!(context.timing.remaining(end, true).is_none());
    }
    for (start, end, now) in [
        (1, 180 * SECOND + 1, 180 * SECOND + 2),
        (u64::MAX - 10, u64::MAX, u64::MAX - 5),
        (100, 99, 100),
    ] {
        value["pids"]["start_ns"] = json!(start);
        value["pids"]["deadline_ns"] = json!(end);
        assert!(
            std::panic::catch_unwind(|| PidsPrivateContext::parse_at(
                &serde_json::to_vec(&value).unwrap(),
                anchor,
                now
            ))
            .is_err()
        );
    }
}

#[test]
fn pids_private_context_execution_origin_has_no_partial_or_implicit_fallback() {
    let github = pids_private_context_fixture();
    PidsPrivateContext::parse(&serde_json::to_vec(&github).unwrap());
    let mut local = github.clone();
    local["binding"]["execution_origin"] = json!("local_process");
    local["binding"]["ci_run_id"] = Value::Null;
    local["binding"]["ci_run_attempt"] = Value::Null;
    PidsPrivateContext::parse(&serde_json::to_vec(&local).unwrap());
    for (origin, ci_run, ci_attempt) in [
        (Value::Null, Value::Null, Value::Null),
        (json!("local"), Value::Null, Value::Null),
        (json!("local_process"), json!("1"), Value::Null),
        (json!("local_process"), Value::Null, json!("1")),
        (json!("local_process"), json!("1"), json!("1")),
        (json!("github_actions"), Value::Null, Value::Null),
        (json!("github_actions"), json!("1"), Value::Null),
        (json!("github_actions"), Value::Null, json!("1")),
        (json!("github_actions"), json!("01"), json!("1")),
    ] {
        let mut invalid = github.clone();
        invalid["binding"]["execution_origin"] = origin;
        invalid["binding"]["ci_run_id"] = ci_run;
        invalid["binding"]["ci_run_attempt"] = ci_attempt;
        assert!(
            std::panic::catch_unwind(|| PidsPrivateContext::parse(
                &serde_json::to_vec(&invalid).unwrap()
            ))
            .is_err()
        );
    }
    for key in ["execution_origin", "ci_run_id", "ci_run_attempt"] {
        let mut invalid = local.clone();
        invalid["binding"].as_object_mut().unwrap().remove(key);
        assert!(
            std::panic::catch_unwind(|| PidsPrivateContext::parse(
                &serde_json::to_vec(&invalid).unwrap()
            ))
            .is_err()
        );
    }
}
