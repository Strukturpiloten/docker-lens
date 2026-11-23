//! Prepared nofile-v1 private source for eventual invocation 28; never admission.
//! Not in the canonical harness: unresolved strict PIDs invocation 27 cannot be bypassed.
//! Fresh native qualification remains pending; source wiring does not claim native support.
//! Native programs below must run only in the independently owned native lanes.

use super::*;
use crate::acquisition::{
    AcquisitionError, AcquisitionShape, LimitError, acquire_with_shape_detail,
};
use crate::observation::{Availability, Origin};
use crate::target::{
    ContainerToken, EnvironmentAssignment, NetworkAttachmentIntent, NetworkDriver, NetworkIntent,
    NetworkRole, NetworkSource, Ulimit, UlimitValue,
};
use std::collections::BTreeMap;

const CONTRACT: &str = "nofile-v1";
const FILENAME: &str = "nofile-v1.json";
const NOFILE_PROOF_MAX_BYTES: usize = 512 * 1024;
const METADATA_MAX_BYTES: usize = 64 * 1024;
const CASES: [(&str, i64, i64); 4] = [
    ("soft64_hard128", 64, 128),
    ("soft128_hard128", 128, 128),
    ("soft64_hard_unlimited", 64, -1),
    ("both_unlimited", -1, -1),
];
const NOFILE_CAPABILITIES: [Capability; 8] = [
    Capability::StandaloneContainer,
    Capability::Command,
    Capability::ContainerLabels,
    Capability::EnvironmentAssignment,
    Capability::Ulimits,
    Capability::UlimitNofile,
    Capability::BridgeNetwork,
    Capability::NetworkExternalReference,
];
const REQUESTS: usize = 20;
const BODIES: usize = 512 * 1024;
const ORDINARY_CAPTURE_ENVELOPE: usize = 65_550 + 8192;
const REFUSAL: &str = "error setting rlimit type 7: operation not permitted";
const PARENT_ENV: &str = "DOCKERLENS_NOFILE_PARENT";
const WORKER_ENV: &str = "DOCKERLENS_NOFILE_WORKER";
const BOOTSTRAP: &str =
    r#"exec /bin/sh -c "${DOCKERLENS_NOFILE_PARENT:?}" "$0" "${DOCKERLENS_NOFILE_WORKER:?}""#;

fn case_network_name(run: &HealthRun, index: usize) -> String {
    if index < 4 {
        "bridge".into()
    } else {
        format!("dl-nf-{}-net-{}", run.run, CASES[index / 2].0)
    }
}

// Constructed only by the private ledger after checking its immutable scope
// and the closed operation's state. Native bytes never enter Debug output.
pub(in crate::native_health_metadata_tests) struct NetworkRequest {
    scope: [String; 6],
    method: &'static str,
    path: String,
    body: Option<Value>,
    cleanup: bool,
}

impl NetworkRequest {
    pub(in crate::native_health_metadata_tests) fn matches(
        &self,
        run: &HealthRun,
        cleanup: bool,
    ) -> bool {
        self.scope == network_scope(run) && self.cleanup == cleanup
    }

    pub(in crate::native_health_metadata_tests) fn parts(&self) -> (&str, &str, Option<&Value>) {
        (self.method, &self.path, self.body.as_ref())
    }
}

fn network_scope(run: &HealthRun) -> [String; 6] {
    [
        run.run.clone(),
        run.lane.clone(),
        run.candidate.clone(),
        run.api.clone(),
        run.socket.clone(),
        run.outer.clone(),
    ]
}

struct NofileNetwork {
    name: String,
    id: Option<String>,
    attempted: bool,
    authenticated: bool,
    deleted: bool,
    setup_calls: usize,
    setup_bytes: usize,
    cleanup_calls: usize,
    cleanup_bytes: usize,
}

struct NofileNetworks {
    scope: [String; 6],
    outer_id: String,
    owned: [NofileNetwork; 2],
    cleanup_attempted: bool,
}

#[derive(Clone, Copy)]
enum NetworkAction {
    FreshName,
    Create,
    InspectId,
    Delete,
    AbsentId,
    AbsentName,
}

impl NofileNetworks {
    fn new(run: &HealthRun, owner: &BoundOuterCleanupOwner) -> Self {
        assert!(
            run.run.len() == 8 && run.run.bytes().all(|b| b.is_ascii_alphanumeric()),
            "closed nofile network owner token"
        );
        let outer_id = owner.snapshot["id"]
            .as_str()
            .filter(|id| identifier(id))
            .unwrap_or_else(|| {
                panic!("authenticated canonical outer ID for nofile network custody")
            });
        assert!(
            owner.snapshot["name"] == run.outer && owner.snapshot["owner"] == run.run,
            "authenticated outer snapshot matches nofile network scope"
        );
        Self {
            scope: network_scope(run),
            outer_id: outer_id.into(),
            cleanup_attempted: false,
            owned: std::array::from_fn(|index| NofileNetwork {
                name: case_network_name(run, 4 + 2 * index),
                id: None,
                attempted: false,
                authenticated: false,
                deleted: false,
                setup_calls: 0,
                setup_bytes: 0,
                cleanup_calls: 0,
                cleanup_bytes: 0,
            }),
        }
    }

    fn scope_matches(&self, run: &HealthRun) -> bool {
        self.scope == network_scope(run)
            && self
                .owned
                .iter()
                .enumerate()
                .all(|(i, n)| n.name == case_network_name(run, 4 + 2 * i))
    }

    fn bound(&self, run: &HealthRun) -> bool {
        self.scope_matches(run)
            && self.owned.iter().enumerate().all(|(i, n)| {
                if !n.attempted {
                    return n.id.is_none() && !n.authenticated && !n.deleted;
                }
                n.authenticated
                    && n.id.as_deref().is_some_and(|id| {
                        identifier(id)
                            && id != self.outer_id
                            && !run.ids.iter().flatten().any(|other| other == id)
                            && !self
                                .owned
                                .iter()
                                .enumerate()
                                .any(|(j, other)| j != i && other.id.as_deref() == Some(id))
                    })
            })
    }

    fn request(
        &self,
        run: &HealthRun,
        index: usize,
        action: NetworkAction,
        cleanup: bool,
    ) -> NetworkRequest {
        assert!(
            self.scope_matches(run),
            "original nofile network custody scope"
        );
        let n = &self.owned[index];
        let prefix = format!("/v{}/networks", run.api);
        let id = || {
            n.id.as_deref()
                .filter(|id| identifier(id))
                .unwrap_or_else(|| panic!("bound canonical nofile network ID"))
        };
        let (method, path, body) = match action {
            NetworkAction::FreshName => {
                assert!(
                    !cleanup && !n.attempted && n.id.is_none(),
                    "fresh network ledger"
                );
                ("GET", format!("{prefix}/{}", n.name), None)
            }
            NetworkAction::Create => {
                assert!(
                    !cleanup && n.attempted && n.id.is_none() && !n.authenticated,
                    "one network create"
                );
                (
                    "POST",
                    format!("{prefix}/create"),
                    Some(json!({"Name":n.name,"Driver":"bridge","Labels":{OWNER:run.run}})),
                )
            }
            NetworkAction::InspectId => {
                assert!(n.attempted && !n.deleted, "live network ledger");
                ("GET", format!("{prefix}/{}", id()), None)
            }
            NetworkAction::Delete => {
                assert!(
                    cleanup && n.authenticated && !n.deleted,
                    "owned network deletion only"
                );
                ("DELETE", format!("{prefix}/{}", id()), None)
            }
            NetworkAction::AbsentId | NetworkAction::AbsentName => {
                assert!(
                    cleanup && n.authenticated && n.deleted,
                    "deleted owned network absence"
                );
                let key = if matches!(action, NetworkAction::AbsentId) {
                    id()
                } else {
                    &n.name
                };
                ("GET", format!("{prefix}/{key}"), None)
            }
        };
        NetworkRequest {
            scope: self.scope.clone(),
            method,
            path,
            body,
            cleanup,
        }
    }

    fn authenticate(&self, run: &HealthRun, index: usize, body: &Value) -> bool {
        self.scope_matches(run)
            && self.owned[index].id.as_deref().is_some_and(|id| {
                identifier(id)
                    && body["Id"] == id
                    && body["Name"] == self.owned[index].name
                    && body["Driver"] == "bridge"
                    && body["Labels"][OWNER] == run.run
            })
    }

    fn create(&mut self, run: &HealthRun, index: usize) {
        let calls = run.calls.get();
        let bytes = run.bytes.get();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let fresh = self.request(run, index, NetworkAction::FreshName, false);
            assert!(
                run.nofile_network_api(&fresh, false).0 == 404,
                "fresh owned nofile bridge name"
            );
            self.owned[index].attempted = true; // before any possibly uncertain mutation
            let create = self.request(run, index, NetworkAction::Create, false);
            let (status, value) = run.nofile_network_api(&create, false);
            assert!(status == 201, "owned bridge create response");
            let id = value["Id"]
                .as_str()
                .filter(|id| identifier(id))
                .unwrap_or_else(|| panic!("canonical nofile bridge create ID"));
            assert!(
                id != self.outer_id
                    && !self.owned.iter().any(|n| n.id.as_deref() == Some(id))
                    && !run.ids.iter().flatten().any(|other| other == id),
                "distinct owned bridge ID"
            );
            self.owned[index].id = Some(id.into());
            let inspect = self.request(run, index, NetworkAction::InspectId, false);
            let (status, value) = run.nofile_network_api(&inspect, false);
            assert!(
                status == 200 && self.authenticate(run, index, &value),
                "bound bridge identity and owner before fixtures"
            );
            self.owned[index].authenticated = true;
        }));
        self.owned[index].setup_calls = run.calls.get() - calls;
        self.owned[index].setup_bytes = run.bytes.get() - bytes;
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
        assert!(
            self.owned[index].setup_calls == 3,
            "actual nofile bridge setup calls"
        );
    }

    fn cleanup(&mut self, run: &HealthRun, containers_absent: bool) -> bool {
        if !containers_absent || !self.bound(run) || self.cleanup_attempted {
            return false;
        }
        self.cleanup_attempted = true;
        let mut verified = true;
        for index in 0..2 {
            if !self.owned[index].attempted {
                continue;
            }
            let calls = run.calls.get();
            let bytes = run.bytes.get();
            let removed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let request = self.request(run, index, NetworkAction::InspectId, true);
                let (status, body) = run.nofile_network_api(&request, true);
                assert!(
                    status == 200 && self.authenticate(run, index, &body),
                    "owned network cleanup identity"
                );
                let request = self.request(run, index, NetworkAction::Delete, true);
                assert!(
                    run.nofile_network_api(&request, true).0 == 204,
                    "exact owned network deletion"
                );
                self.owned[index].deleted = true;
            }))
            .is_ok();
            self.owned[index].cleanup_calls += run.calls.get() - calls;
            self.owned[index].cleanup_bytes += run.bytes.get() - bytes;
            verified &= removed;
        }
        for _ in 0..2 {
            for index in 0..2 {
                if !self.owned[index].attempted {
                    continue;
                }
                let calls = run.calls.get();
                let bytes = run.bytes.get();
                let absent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    for action in [NetworkAction::AbsentId, NetworkAction::AbsentName] {
                        let request = self.request(run, index, action, true);
                        assert!(
                            run.nofile_network_api(&request, true).0 == 404,
                            "owned network absence round"
                        );
                    }
                }))
                .is_ok();
                self.owned[index].cleanup_calls += run.calls.get() - calls;
                self.owned[index].cleanup_bytes += run.bytes.get() - bytes;
                verified &= absent;
            }
        }
        verified
    }

    fn topology(&self, run: &HealthRun, acquired: &Value) -> Value {
        assert!(
            self.bound(run) && self.owned.iter().all(|n| n.attempted && n.deleted),
            "complete nofile network custody"
        );
        let default_id = acquired["networks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"] == "bridge")
            .map(|n| n["id"].clone())
            .unwrap_or(Value::Null);
        json!({"default":{"id":default_id,"name":"bridge","driver":"bridge","ownership":"not_owned","container_indices":[0,1,2,3]},
            "owned":self.owned.iter().enumerate().map(|(i,n)| json!({"case":CASES[i+2].0,"id":n.id,"name":n.name,"owner":run.run,"driver":"bridge","container_indices":[4+2*i,5+2*i],"setup_calls":n.setup_calls,"setup_bytes":n.setup_bytes,"cleanup_calls":n.cleanup_calls,"cleanup_bytes":n.cleanup_bytes,"cleanup":"absent","absence_rounds":2})).collect::<Vec<_>>()})
    }
}

// Independently authored POSIX-awk program. No oracle implementation is copied.
// ERRNO is captured immediately: even close() may subsequently overwrite it.
const WORKER: &str = r#"function sample(tag, a,n,s,h,p,q,l){
while((getline l < "/proc/self/limits")>0){n=split(l,a);if(a[1]=="Max"&&a[2]=="open"&&a[3]=="files"){s=a[4];h=a[5]}}close("/proc/self/limits");
while((getline l < "/proc/self/status")>0){split(l,a);if(a[1]=="Pid:")p=a[2];if(a[1]=="PPid:")q=a[2]}close("/proc/self/status");
print tag,s,h,p,q;return s}
function gate(tag,g){print "phase",tag;fflush();if((getline g)!=1||g!=token " " tag)exit 81}
BEGIN{
s=sample("self_pre");gate("base");n=0;r=1;e=0;
for(i=1;i<=192;i++){f="/tmp/dl-nf/f" i;ERRNO=0;r=(getline v < f);e=ERRNO;if(r!=1)break;if(v!=token " " i)exit 82;n++}
if(r!=1&&(r!=-1||e!=24))exit 83;
if(r==1&&s!="unlimited"&&s<=192)exit 84;
print "held",n,r,e;gate("held");
for(i=1;i<=n;i++)if(close("/tmp/dl-nf/f" i)!=0)exit 85;
for(i=1;i<=256;i++){f="/tmp/dl-nf/f" i;if((getline v < f)!=1||v!=token " " i||close(f)!=0)exit 86}
print "reuse",256;sample("self_post");gate("done");exit 87
}"#;

// BusyBox awk tokenizes inline source in argv in place. Bind an immutable
// argument vector and compare the file-backed program independently.
const PARENT: &str = r#"test "$$" = 1 || exit 71
set -eu;LC_ALL=C;export LC_ALL;umask 077;d=/tmp/dl-nf
test ! -e "$d";test ! -L "$d";mkdir "$d";mkfifo "$d/gate";: >"$d/report";: >"$d/error"
for i in $(seq 1 256);do printf '%s %s\n' "$0-child" "$i" >"$d/f$i";done
printf '%s' "$1" >"$d/worker.awk";chmod 0400 "$d/worker.awk"
exec 3<>"$d/gate"
s(){ printf '%s ' "$1";awk '/^Max open files /{printf "%s %s ",$4,$5}' /proc/"$2"/limits;awk '/^Pid:/{printf "%s ",$2}/^PPid:/{print $2}' /proc/"$2"/status;}
f(){ for p in /proc/$c/fd/*;do printf 'fd %s %s %s ' "$1" "${p##*/}" "$(readlink "$p")";stat -L -c '%d %i' "$p";done;}
w(){ for i in $(seq 1 80);do if grep -qx "phase $1" "$d/report";then return;fi;sleep 0.025;done;exit 72;}
b(){
test "/proc/$c/exe" -ef /bin/awk
test -f "$d/worker.awk";test ! -L "$d/worker.awk"
printf '%s' "$1" | cmp "$d/worker.awk" -
printf '%s\000' /bin/awk -v "token=$0-child" -f "$d/worker.awk" | cmp "/proc/$c/cmdline" -
}
{
printf 'nr_open ';cat /proc/sys/fs/nr_open
stat -c 'own %n %d %i' "$d"/f* "$d/gate" "$d/report" "$d/error"
s parent_pre 1
(exec /bin/awk -v "token=$0-child" -f "$d/worker.awk" 3>&- <"$d/gate" >"$d/report" 2>"$d/error") &
c=$!;w base;b "$1";s bound_pre "$c";f base;f base_repeat
printf '%s base\n' "$0-child" >&3;w held;f saturated;f saturated_repeat
printf '%s held\n' "$0-child" >&3;w done;f restored;s bound_post "$c";s parent_post 1;b "$1"
test ! -s "$d/error"
} >"$d/parent.tmp"
mv "$d/parent.tmp" "$d/parent";wait "$c""#;

const OBSERVE: &str = r#"set -eu;LC_ALL=C;export LC_ALL;site=rootuid
trap 'status=$?;trap - 0;if [ "$status" -ne 0 ];then printf "DOCKERLENS_NATIVE_NOFILE_OBSERVER: site=%s\n" "$site" >&2 || :;fi;exit "$status"' 0
test "$(id -u)" = 0;site=rootgid;test "$(id -g)" = 0;d=/tmp/dl-nf;site=reportwait
for i in $(seq 1 100);do if [ -f "$d/parent" ];then break;fi;sleep 0.05;done
site=reportfile;test -f "$d/parent";site=reportlink;test ! -L "$d/parent";site=workererror;test ! -s "$d/error"
site=workerpid;c=$(awk '$1=="bound_pre"{print $4}' "$d/parent");test -n "$c"
site=workerexe;test "/proc/$c/exe" -ef /bin/awk;site=workerargv
test -f "$d/worker.awk";test ! -L "$d/worker.awk"
printf '%s' "$1" | cmp "$d/worker.awk" -
printf '%s\000' /bin/awk -v "token=$0-child" -f "$d/worker.awk" | cmp "/proc/$c/cmdline" -
site=transcript;cat "$d/parent" "$d/report"
s(){ printf '%s ' "$1";awk '/^Max open files /{printf "%s %s ",$4,$5}' /proc/"$2"/limits;awk '/^Pid:/{printf "%s ",$2}/^PPid:/{print $2}' /proc/"$2"/status;}
site=parentlimits;s root_parent 1;site=workerlimits;s root_worker "$c""#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NofileOperation {
    Context,
    FreshName,
    Create,
    Bind,
    ConfiguredBefore,
    Start,
    ConfiguredStarted,
    Observe,
    Witness,
    ConfiguredAfter,
    RefusalStable,
    SlotAccounting,
    PairComparison,
    CapacityComparison,
    KernelComparison,
    DaemonHealth,
    Acquisition,
}
impl NofileOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::FreshName => "fresh_name",
            Self::Create => "create",
            Self::Bind => "bind",
            Self::ConfiguredBefore => "configured_before",
            Self::Start => "start",
            Self::ConfiguredStarted => "configured_started",
            Self::Observe => "observe",
            Self::Witness => "witness",
            Self::ConfiguredAfter => "configured_after",
            Self::RefusalStable => "refusal_stable",
            Self::SlotAccounting => "slot_accounting",
            Self::PairComparison => "pair_comparison",
            Self::CapacityComparison => "capacity_comparison",
            Self::KernelComparison => "kernel_comparison",
            Self::DaemonHealth => "daemon_health",
            Self::Acquisition => "acquisition",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NofileCaller {
    case: usize,
    role: NofileRole,
    operation: NofileOperation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NofileRole {
    Oracle,
    Rendered,
    Pair,
    None,
}
impl NofileCaller {
    fn fields(self) -> Option<(&'static str, &'static str, &'static str)> {
        let case = match self.case {
            0 => "soft64_hard128",
            1 => "soft128_hard128",
            2 => "soft64_hard_unlimited",
            3 => "both_unlimited",
            4 => "all",
            _ => return None,
        };
        let role = match self.role {
            NofileRole::Oracle => "oracle",
            NofileRole::Rendered => "rendered",
            NofileRole::Pair => "pair",
            NofileRole::None => "none",
        };
        Some((case, role, self.operation.name()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NofileTermination {
    Exit(u8),
    Signal(u8),
    Unknown,
}
impl NofileTermination {
    fn observed(status: Option<std::process::ExitStatus>) -> Self {
        let Some(status) = status else {
            return Self::Unknown;
        };
        if let Some(code) = status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .filter(|code| *code > 0)
        {
            return Self::Exit(code);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status
                .signal()
                .and_then(|signal| u8::try_from(signal).ok())
                .filter(|signal| (1..=64).contains(signal))
            {
                return Self::Signal(signal);
            }
        }
        Self::Unknown
    }
    fn fields(self) -> (&'static str, String) {
        match self {
            Self::Exit(code) => ("exit", code.to_string()),
            Self::Signal(code) => ("signal", code.to_string()),
            Self::Unknown => ("unknown", "none".into()),
        }
    }
}

#[derive(Default)]
struct NofileDiagnostics {
    caller: Cell<Option<NofileCaller>>,
    acquisition_error: Cell<Option<&'static str>>,
    acquisition_shape: Cell<Option<&'static str>>,
}
impl NofileDiagnostics {
    fn select(&self, run: &HealthRun, case: usize, role: NofileRole, operation: NofileOperation) {
        self.caller.set(Some(NofileCaller {
            case,
            role,
            operation,
        }));
        self.acquisition_error.set(None);
        self.acquisition_shape.set(None);
        if let Some(observation) = &run.nofile_command_observation {
            observation.reset();
        }
    }
    fn slot(&self, run: &HealthRun, index: usize, operation: NofileOperation) {
        self.select(
            run,
            index / 2,
            if index.is_multiple_of(2) {
                NofileRole::Oracle
            } else {
                NofileRole::Rendered
            },
            operation,
        );
    }
    fn all(&self, run: &HealthRun, operation: NofileOperation) {
        self.select(run, 4, NofileRole::None, operation);
    }
    fn failure(&self, run: &HealthRun) -> Option<String> {
        let caller = self.caller.get()?;
        let (case, role, operation) = caller.fields()?;
        let status = run
            .nofile_command_observation
            .as_ref()
            .and_then(|observation| observation.current_failure.get());
        let (termination, code) = NofileTermination::observed(status).fields();
        let capture = if caller.operation == NofileOperation::Observe && termination != "unknown" {
            run.nofile_command_observation
                .as_ref()
                .and_then(|observation| observation.observer_capture.get())
        } else {
            None
        };
        let suffix = match capture {
            Some(NofileObserverCapture::Matched(site)) => format!(" observer_site={}", site.name()),
            Some(NofileObserverCapture::Unavailable(reason)) => {
                format!(" observer_capture={}", reason.name())
            }
            None if caller.operation == NofileOperation::Acquisition => self
                .acquisition_error
                .get()
                .map_or_else(String::new, |error| match self.acquisition_shape.get() {
                    Some(shape) => format!(" acquisition_error={error} acquisition_shape={shape}"),
                    None => format!(" acquisition_error={error}"),
                }),
            None => String::new(),
        };
        let entry = if caller.operation == NofileOperation::Observe {
            " observer_entry=unknown"
        } else {
            ""
        };
        Some(format!(
            "DOCKERLENS_NATIVE_NOFILE_FAILURE: caller_case={case} caller_role={role} caller_operation={operation} observed_termination={termination} code={code}{suffix}{entry}"
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NofileCleanupRefusal {
    OwnershipGuard,
    InnerUnverified(Option<CleanupPhase>),
    Panic,
}
impl NofileCleanupRefusal {
    fn diagnostic(self, status: Option<std::process::ExitStatus>) -> String {
        let (reason, phase) = match self {
            Self::OwnershipGuard => ("ownership_guard", None),
            Self::InnerUnverified(phase) => ("inner_unverified", phase),
            Self::Panic => ("panic", None),
        };
        let phase = phase.map_or("unknown", CleanupPhase::name);
        // A rejected guard never entered command capture and cannot inherit work status.
        let (termination, code) = NofileTermination::observed(if self == Self::OwnershipGuard {
            None
        } else {
            status
        })
        .fields();
        format!(
            "DOCKERLENS_NATIVE_NOFILE_CLEANUP_REFUSAL: reason={reason} first_observed_termination={termination} code={code} first_unverified_phase={phase}"
        )
    }
}

fn number(text: &str) -> u64 {
    assert!(
        !text.is_empty()
            && (text == "0" || !text.starts_with('0'))
            && text.bytes().all(|b| b.is_ascii_digit()),
        "canonical private nofile integer"
    );
    text.parse()
        .unwrap_or_else(|_| panic!("bounded private nofile integer"))
}

fn limit(text: &str) -> Value {
    if text == "unlimited" {
        json!("unlimited")
    } else {
        json!(number(text))
    }
}

fn entry(fd: u64, target: &str, device: u64, inode: u64) -> Value {
    json!({"fd":fd,"target":target,"device":device,"inode":inode})
}

fn witness(bytes: &[u8], expected: (i64, i64)) -> Value {
    let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("private nofile UTF8"));
    assert!(text.ends_with('\n'), "complete private nofile report");
    let mut samples = BTreeMap::new();
    let mut owners = BTreeMap::new();
    let mut descriptors: BTreeMap<String, BTreeMap<u64, Value>> = BTreeMap::new();
    let mut phases = Vec::new();
    let (mut nr_open, mut held, mut reuse) = (None, None, None);
    for line in text.lines() {
        let a: Vec<_> = line.split(' ').collect();
        match a.as_slice() {
            ["nr_open", value] => {
                assert!(
                    nr_open.replace(number(value)).is_none(),
                    "one owned kernel ceiling"
                );
            }
            ["own", path, device, inode] => {
                assert!(
                    owners
                        .insert(
                            (*path).to_owned(),
                            json!({"device":number(device),"inode":number(inode)})
                        )
                        .is_none(),
                    "unique owned stream manifest"
                );
            }
            ["fd", phase, fd, target, device, inode] => {
                let fd = number(fd);
                assert!(fd <= i32::MAX as u64, "Linux descriptor number range");
                assert!(
                    descriptors
                        .entry((*phase).to_owned())
                        .or_default()
                        .insert(fd, entry(fd, target, number(device), number(inode)))
                        .is_none(),
                    "unique live descriptor number"
                );
            }
            ["phase", name] => phases.push(*name),
            ["held", count, result, error] => {
                assert!(
                    held.replace((number(count), *result, number(error)))
                        .is_none(),
                    "one live held-open result"
                );
            }
            ["reuse", count] => {
                assert!(
                    reuse.replace(number(count)).is_none(),
                    "one close reuse result"
                );
            }
            [name, soft, hard, pid, ppid]
                if [
                    "parent_pre",
                    "parent_post",
                    "bound_pre",
                    "bound_post",
                    "self_pre",
                    "self_post",
                    "root_parent",
                    "root_worker",
                ]
                .contains(name) =>
            {
                assert!(samples.insert((*name).to_owned(),json!({"soft":limit(soft),"hard":limit(hard),"pid":number(pid),"ppid":number(ppid)})).is_none(), "one independently read process sample");
            }
            _ => panic!("closed private nofile report grammar"),
        }
    }
    assert!(
        samples.len() == 8 && phases == ["base", "held", "done"] && reuse == Some(256),
        "complete inherited worker phases"
    );
    let kernel = json!({"soft":samples["self_pre"]["soft"],"hard":samples["self_pre"]["hard"]});
    let child = samples["self_pre"]["pid"].as_u64().unwrap();
    assert!(
        (2..=i32::MAX as u64).contains(&child)
            && nr_open.is_some_and(|n| (128..=i32::MAX as u64).contains(&n)),
        "actual worker and readable kernel ceiling"
    );
    for (name, sample) in &samples {
        assert!(
            sample["soft"] == kernel["soft"]
                && sample["hard"] == kernel["hard"]
                && if name.starts_with("parent") || name == "root_parent" {
                    sample["pid"] == 1 && sample["ppid"] == 0
                } else {
                    sample["pid"] == child && sample["ppid"] == 1
                },
            "PID1 and inherited worker actual limits agree"
        );
    }
    for (name, wanted) in [("soft", expected.0), ("hard", expected.1)] {
        if wanted >= 0 {
            assert!(kernel[name] == json!(wanted), "finite authored limit exact");
        } else {
            assert!(
                kernel[name] == "unlimited"
                    || kernel[name]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= nr_open.unwrap()),
                "truthful observed unlimited normalization"
            );
        }
    }
    if let (Some(soft), Some(hard)) = (kernel["soft"].as_u64(), kernel["hard"].as_u64()) {
        assert!(soft <= hard, "ordered actual limits");
    }
    assert!(
        kernel["soft"] != "unlimited" || kernel["hard"] == "unlimited",
        "unlimited soft requires unlimited hard"
    );
    assert!(
        owners.len() == 259 && descriptors.len() == 5,
        "complete owned file and live descriptor manifests"
    );
    let mut nodes = BTreeSet::new();
    for node in owners.values() {
        assert!(
            node["inode"].as_u64().is_some_and(|n| n > 0)
                && nodes.insert((
                    node["device"].as_u64().unwrap(),
                    node["inode"].as_u64().unwrap()
                )),
            "distinct owned regular/control stream inodes"
        );
    }
    for i in 1..=256 {
        assert!(
            owners.contains_key(&format!("/tmp/dl-nf/f{i}")),
            "complete numbered owned stream manifest"
        );
    }
    let base = &descriptors["base"];
    assert!(
        (3..=16).contains(&base.len())
            && base == &descriptors["base_repeat"]
            && base == &descriptors["restored"],
        "stable measured baseline restored after reuse"
    );
    for (fd, path) in [
        (0, "/tmp/dl-nf/gate"),
        (1, "/tmp/dl-nf/report"),
        (2, "/tmp/dl-nf/error"),
    ] {
        assert!(
            base[&fd]["target"] == path,
            "preopened standard descriptors"
        );
    }
    for value in base.values() {
        let path = value["target"].as_str().unwrap();
        assert!(
            ["/tmp/dl-nf/gate", "/tmp/dl-nf/report", "/tmp/dl-nf/error"].contains(&path)
                && value["device"] == owners[path]["device"]
                && value["inode"] == owners[path]["inode"],
            "unambiguous actually measured baseline"
        );
    }
    let (count, result, error) = held.unwrap();
    let sat = &descriptors["saturated"];
    assert!(
        sat == &descriptors["saturated_repeat"]
            && count <= 192
            && sat.len() == base.len() + count as usize,
        "stable actual live retained streams"
    );
    let mut actual = BTreeSet::new();
    for (fd, value) in sat {
        if let Some(original) = base.get(fd) {
            assert!(original == value, "baseline retained at saturation");
            continue;
        }
        let path = value["target"].as_str().unwrap();
        let i = number(
            path.strip_prefix("/tmp/dl-nf/f")
                .unwrap_or_else(|| panic!("owned retained stream target")),
        );
        assert!(
            (1..=count).contains(&i)
                && actual.insert(i)
                && value["device"] == owners[path]["device"]
                && value["inode"] == owners[path]["inode"],
            "distinct actual owned file streams not recycled"
        );
    }
    let finite = kernel["soft"].as_u64().is_some_and(|soft| soft <= 192);
    let failure = if finite {
        let soft = kernel["soft"].as_u64().unwrap();
        assert!(
            result == "-1"
                && error == 24
                && sat.len() as u64 == soft
                && sat.keys().copied().eq(0..soft),
            "actual EMFILE and live occupied descriptor range, not assumed minus three"
        );
        json!({"getline_return":-1,"errno":24,"attempt":count+1})
    } else {
        assert!(
            result == "1" && error == 0 && count == 192,
            "bounded successful opens beyond finite controls, never saturation/unlimited inference"
        );
        Value::Null
    };
    let outcome = if expected.1 >= 0 {
        "exact_finite_emfile"
    } else if kernel["hard"] != "unlimited" || (expected.0 < 0 && kernel["soft"] != "unlimited") {
        "finite_kernel_normalization"
    } else if expected.0 >= 0 {
        "exact_hard_unlimited_finite_soft_emfile"
    } else {
        "exact_both_unlimited_bounded_success"
    };
    json!({"outcome":outcome,"kernel":kernel,"samples":samples,"nr_open":nr_open.unwrap(),"owned_files":owners,
        "descriptors":descriptors.into_iter().map(|(name,items)|(name,items.into_values().collect::<Vec<_>>())).collect::<BTreeMap<_,_>>(),
        "retained_count":count,"failure":failure,"reuse_count":256,"phases":["base","held","done"],
        "exec_binding":"retained_background_pid_exact_nul_argv_exe_inode_and_proc"})
}

fn environment_bindings(value: &Value) -> Option<BTreeMap<&str, &str>> {
    let mut bindings = BTreeMap::new();
    for entry in value.as_array()? {
        let (key, value) = entry.as_str()?.split_once('=')?;
        if key.is_empty() || bindings.insert(key, value).is_some() {
            return None;
        }
    }
    Some(bindings)
}

fn fixture_environment(image_env: &Value) -> Option<BTreeMap<&str, &str>> {
    let mut expected = if image_env.is_null() {
        BTreeMap::new()
    } else {
        environment_bindings(image_env)?
    };
    if expected.insert(PARENT_ENV, PARENT).is_some()
        || expected.insert(WORKER_ENV, WORKER).is_some()
    {
        return None;
    }
    Some(expected)
}

#[test]
fn nofile_fixture_environment_preserves_values_and_refuses_shadowing() {
    let base = json!(["PATH=/bin:/usr/bin", "EMPTY=", "VALUE=left=right"]);
    let expected = fixture_environment(&base).unwrap();
    assert_eq!(expected.len(), 5);
    let configured = json!([
        format!("{WORKER_ENV}={WORKER}"),
        "EMPTY=",
        "VALUE=left=right",
        format!("{PARENT_ENV}={PARENT}"),
        "PATH=/bin:/usr/bin",
    ]);
    assert_eq!(environment_bindings(&configured).as_ref(), Some(&expected));
    for key in [PARENT_ENV, WORKER_ENV] {
        assert!(fixture_environment(&json!([format!("{key}=overshadow")])).is_none());
    }
    assert!(fixture_environment(&json!(["PATH=a", "PATH=b"])).is_none());
    assert!(
        environment_bindings(&json!([
            format!("{PARENT_ENV}={PARENT}"),
            format!("{PARENT_ENV}={PARENT}")
        ]))
        .is_none()
    );
    assert!(environment_bindings(&json!([PARENT_ENV])).is_none());
    assert!(
        environment_bindings(&json!([
            format!("{PARENT_ENV}=wrong"),
            format!("{WORKER_ENV}={WORKER}"),
            "PATH=/bin:/usr/bin",
            "EMPTY=",
            "VALUE=left=right"
        ]))
        .as_ref()
            != Some(&expected)
    );
}

fn offline_run(socket: String) -> HealthRun {
    HealthRun {
        nofile_command_observation: Some(NofileCommandObservation::default()),
        run: String::new(),
        lane: String::new(),
        candidate: String::new(),
        api: "1.41".into(),
        engine: String::new(),
        mode: DaemonMode::Rootful,
        socket,
        outer: String::new(),
        base: String::new(),
        derived_tag: String::new(),
        derived_id: None,
        image_attempted: false,
        names: vec!["inert-held-name".into()],
        ids: vec![Some("a".repeat(64))],
        attempted: vec![true],
        absence_lookup: HealthAbsenceLookup::Disabled,
        deadline: Instant::now() + Duration::from_secs(30),
        calls: Cell::new(0),
        bytes: Cell::new(0),
        facts: None,
        cleaned: true,
        cleanup_delegated: false,
    }
}

#[test]
fn nofile_cleanup_lookup_observes_actual_capture_and_http_parser() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixListener;

    let private = std::env::temp_dir().join(format!("dl-nf-{}-{}", std::process::id(), utc_ns()));
    fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
    let socket = private.join("lookup.sock");
    let mut run = offline_run(socket.to_str().unwrap().into());
    let run_controls = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for (code, body, failure) in [
            (
                200,
                format!("{{\"padding\":\"{}\"}}\n", "x".repeat(8173)),
                None,
            ),
            (
                200,
                format!("{{\"padding\":\"{}\"}}\n", "x".repeat(8174)),
                Some(NofileLookupFailure::StdoutLimit),
            ),
            (500, "{}\n".into(), Some(NofileLookupFailure::HttpStatus)),
            (200, "!\n".into(), Some(NofileLookupFailure::Json)),
            (404, "{}\n".into(), None),
        ] {
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => panic!("private inert lookup accept"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut line = String::new();
                let mut reader = BufReader::new(&stream);
                reader.read_line(&mut line).unwrap();
                assert_eq!(
                    line,
                    "GET /v1.41/containers/inert-held-name/json HTTP/1.1\r\n"
                );
                for _ in 0..16 {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        write!(stream, "HTTP/1.1 {code} Inert\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                        return;
                    }
                }
                panic!("bounded inert lookup request");
            });
            let phase = Cell::new(CleanupPhase::Delete);
            let before_bytes = run.bytes.get();
            let lookup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                remove_container_with_phase(&mut run, 0, &phase)
            }));
            server.join().unwrap();
            fs::remove_file(&socket).unwrap();
            let observed = run
                .nofile_command_observation
                .as_ref()
                .unwrap()
                .active_lookup
                .take();
            assert_eq!(observed, failure);
            if matches!(code, 200)
                && matches!(failure, None | Some(NofileLookupFailure::StdoutLimit))
            {
                assert_eq!(run.bytes.get() - before_bytes, 8192);
            }
            if code == 404 {
                assert!(lookup.unwrap());
            } else if matches!(
                failure,
                Some(NofileLookupFailure::StdoutLimit | NofileLookupFailure::Json)
            ) {
                assert!(lookup.is_err());
            } else {
                assert!(!lookup.unwrap());
            }
            let expected_phase = if code == 200 && failure.is_none() {
                CleanupPhase::NameOwnership // Parsed synthetic body has no ownership fields.
            } else {
                CleanupPhase::LookupName
            };
            assert_eq!(phase.get(), expected_phase);
        }
        let phase = Cell::new(CleanupPhase::Delete);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                remove_container_with_phase(&mut run, 0, &phase)
            }))
            .is_err()
        );
        let observation = run.nofile_command_observation.as_ref().unwrap();
        assert_eq!(
            observation.active_lookup.get(),
            Some(NofileLookupFailure::Process)
        );
        assert_eq!(run.calls.get(), 6);
    }));
    fs::remove_dir_all(private).unwrap();
    run_controls.unwrap();
}

fn authored(run: &HealthRun, index: usize) -> Value {
    let (_, soft, hard) = CASES[index / 2];
    let value = |n: i64| {
        if n < 0 {
            UlimitValue::Unlimited
        } else {
            UlimitValue::Value(n as u64)
        }
    };
    let container = ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(run.names[index].as_bytes().to_vec()).unwrap(),
        image: ImageReference::new(run.base.as_bytes().to_vec()).unwrap(),
        environment: vec![
            EnvironmentAssignment::new(PARENT_ENV.as_bytes().to_vec(), PARENT.as_bytes().to_vec())
                .unwrap(),
            EnvironmentAssignment::new(WORKER_ENV.as_bytes().to_vec(), WORKER.as_bytes().to_vec())
                .unwrap(),
        ],
        ports: vec![],
        mounts: vec![],
        networks: if index < 4 {
            vec![]
        } else {
            vec![NetworkAttachmentIntent {
                network: ResourceRef::new(2),
                aliases: vec![],
                ipv4_address: None,
                ipv6_address: None,
            }]
        },
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Exec(
            ["sh", "-c", BOOTSTRAP, run.names[index].as_str()]
                .map(|t| Argument::new(t.as_bytes().to_vec()).unwrap())
                .into(),
        ),
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            labels: vec![
                ContainerLabel::new(OWNER.as_bytes().to_vec(), run.run.as_bytes().to_vec())
                    .unwrap(),
            ],
            ulimits: vec![Ulimit {
                name: ContainerToken::new(b"nofile".to_vec()).unwrap(),
                soft: value(soft),
                hard: value(hard),
            }],
            ..ContainerSettings::default()
        },
    };
    let mut resources = Vec::new();
    if index >= 4 {
        resources.push(TargetResource::Network(NetworkIntent {
            reference: ResourceRef::new(2),
            identity: TargetIdentity::new(case_network_name(run, index).into_bytes()).unwrap(),
            role: NetworkRole::Declared,
            source: NetworkSource::External {
                expected_driver: NetworkDriver::Bridge,
                expected_internal: None,
            },
        }));
    }
    resources.push(TargetResource::Container(Box::new(container)));
    let intent = TargetIntent::new(resources).unwrap();
    let graph = DockerPlanner
        .plan(
            &intent,
            &ValidatedCapabilities::new(run.facts.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    let artifact = DockerApiRenderer.render(&graph).unwrap();
    let prerequisites = artifact.network_prerequisites();
    assert!(
        if index < 4 {
            prerequisites.is_empty()
        } else {
            prerequisites.len() == 1
                && prerequisites[0].reference == ResourceRef::new(2)
                && prerequisites[0].identity() == case_network_name(run, index).as_bytes()
                && prerequisites[0].expected_driver == NetworkDriver::Bridge
                && prerequisites[0].expected_internal.is_none()
        },
        "exact owned-bridge prerequisite, no invented default requirement"
    );
    let request: Value = serde_json::from_slice(artifact.bytes()).unwrap();
    let mut body = json!({"Image":run.base,"Cmd":["sh","-c",BOOTSTRAP,run.names[index]],"Labels":{(OWNER):run.run},
        "Env":[format!("{PARENT_ENV}={PARENT}"),format!("{WORKER_ENV}={WORKER}")],
        "HostConfig":{"Ulimits":[{"Name":"nofile","Soft":soft,"Hard":hard}]}});
    if index >= 4 {
        let name = case_network_name(run, index);
        body["HostConfig"]["NetworkMode"] = json!(name);
        body["NetworkingConfig"] = json!({"EndpointsConfig":{(name):{}}});
    }
    assert!(
        request
            == json!({"method":"POST","path":format!("/v{}/containers/create?name={}",run.api,run.names[index]),"body":body}),
        "complete independent literal nofile rendered request"
    );
    request
}

fn oracle_create_arguments(run: &HealthRun, index: usize) -> Vec<String> {
    let (_, soft, hard) = CASES[index / 2];
    let mut args = vec![
        "create".into(),
        "--name".into(),
        run.names[index].clone(),
        "--label".into(),
        format!("{OWNER}={}", run.run),
        "--ulimit".into(),
        format!("nofile={soft}:{hard}"),
        "--env".into(),
        format!("{PARENT_ENV}={PARENT}"),
        "--env".into(),
        format!("{WORKER_ENV}={WORKER}"),
        run.base.clone(),
        "sh".into(),
        "-c".into(),
        BOOTSTRAP.into(),
        run.names[index].clone(),
    ];
    if index >= 4 {
        args.splice(11..11, ["--network".into(), case_network_name(run, index)]);
    }
    args
}

#[test]
fn nofile_fixture_create_modes_match_exact_argv_and_rendered_wires() {
    use crate::version::{EngineRelease, ObservationId};

    let mut run = offline_run(String::new());
    run.base = include_str!("../scripts/native-conformance.sh")
        .lines()
        .find_map(|line| line.strip_prefix("FIXTURE_IMAGE='")?.strip_suffix('\''))
        .expect("pinned borrowed fixture image")
        .to_owned();
    run.run = "Ab12Cd34".to_owned();
    let bootstrap =
        r#"exec /bin/sh -c "${DOCKERLENS_NOFILE_PARENT:?}" "$0" "${DOCKERLENS_NOFILE_WORKER:?}""#;
    let parent_env = format!("DOCKERLENS_NOFILE_PARENT={PARENT}");
    let worker_env = format!("DOCKERLENS_NOFILE_WORKER={WORKER}");
    let cases = [
        ("soft64_hard128", 64, 128),
        ("soft128_hard128", 128, 128),
        ("soft64_hard_unlimited", 64, -1),
        ("both_unlimited", -1, -1),
    ];
    run.names = cases
        .iter()
        .flat_map(|(name, _, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-nf-Ab12Cd34-{name}-{role}"))
        })
        .collect();
    for (minor, release, mode) in [
        (41, "20.10.5+dfsg1", DaemonMode::Rootful),
        (41, "20.10.5+dfsg1", DaemonMode::Rootless),
        (56, "29.8.1", DaemonMode::Rootful),
        (56, "29.8.1", DaemonMode::Rootless),
    ] {
        run.api = format!("1.{minor}");
        run.mode = mode;
        let observation_id = ObservationId::fresh().unwrap();
        let release = EngineRelease::new(release.into()).unwrap();
        let api_version = ApiVersion::new(NonZeroU16::new(1).unwrap(), minor);
        let scope = CapabilityScope {
            observation_id,
            release: release.clone(),
            api_version,
            mode,
        };
        run.facts = Some(DaemonFacts {
            observation_id,
            release: Some(release),
            api_version: Some(api_version),
            minimum_api_version: None,
            mode,
            capabilities: NOFILE_CAPABILITIES
                .map(|capability| CapabilityFact {
                    capability,
                    state: CapabilityState::Available,
                    provenance: FactProvenance::NativeConformance,
                    scope: Some(scope.clone()),
                })
                .into(),
        });
        for (case, (case_name, soft, hard)) in cases.into_iter().enumerate() {
            let oracle_name = format!("dl-nf-Ab12Cd34-{case_name}-oracle");
            let rendered_name = format!("dl-nf-Ab12Cd34-{case_name}-rendered");
            let mut expected_argv = [
                "create",
                "--name",
                &oracle_name,
                "--label",
                "io.dockerlens.native-run=Ab12Cd34",
                "--ulimit",
                &format!("nofile={soft}:{hard}"),
                "--env",
                &parent_env,
                "--env",
                &worker_env,
                &run.base,
                "sh",
                "-c",
                bootstrap,
                &oracle_name,
            ]
            .map(str::to_owned)
            .to_vec();
            if case >= 2 {
                expected_argv.splice(
                    11..11,
                    [
                        "--network".into(),
                        format!("dl-nf-Ab12Cd34-net-{case_name}"),
                    ],
                );
            }
            assert_eq!(oracle_create_arguments(&run, 2 * case), expected_argv);
            let mut expected = json!({
                "method": "POST",
                "path": format!("/v1.{minor}/containers/create?name={rendered_name}"),
                "body": {
                    "Image": run.base,
                    "Env": [&parent_env, &worker_env],
                    "Cmd": ["sh", "-c", bootstrap, &rendered_name],
                    "Labels": {"io.dockerlens.native-run": "Ab12Cd34"},
                    "HostConfig": {"Ulimits": [{"Name": "nofile", "Soft": soft, "Hard": hard}]},
                },
            });
            if case >= 2 {
                let name = format!("dl-nf-Ab12Cd34-net-{case_name}");
                expected["body"]["HostConfig"]["NetworkMode"] = json!(name);
                expected["body"]["NetworkingConfig"] = json!({"EndpointsConfig":{(name):{}}});
            }
            let request = authored(&run, 2 * case + 1);
            assert_eq!(
                serde_json::to_vec(&request).unwrap(),
                serde_json::to_vec(&expected).unwrap()
            );
            assert!(serde_json::to_vec(&request["body"]).unwrap().len() <= 4096);
        }
    }
}

fn create_nofile(
    run: &mut HealthRun,
    index: usize,
    diagnostics: &NofileDiagnostics,
    networks: &NofileNetworks,
) {
    assert!(
        networks.bound(run) && networks.owned.iter().all(|n| n.attempted),
        "both case bridges authenticated before any container action"
    );
    diagnostics.slot(run, index, NofileOperation::FreshName);
    assert!(
        run.inspect(&run.names[index], false).0 == 404,
        "fresh nofile name"
    );
    run.attempted[index] = true;
    diagnostics.slot(run, index, NofileOperation::Create);
    if index.is_multiple_of(2) {
        let bytes = docker(run, &oracle_create_arguments(run, index));
        let id = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("closed nofile CLI create ID"));
        diagnostics.slot(run, index, NofileOperation::Bind);
        bind(run, index, id);
    } else {
        let request = authored(run, index);
        let (status, value) = run.api(
            "POST",
            request["path"].as_str().unwrap(),
            Some(&request["body"]),
            false,
        );
        // Any create refusal without a canonical ID remains an unknown-owned
        // mutation: the nofile guard must require outer teardown before cleanup.
        assert!(
            status == 201 && (value["Warnings"].is_null() || value["Warnings"] == json!([])),
            "nofile create must yield known canonical ID"
        );
        diagnostics.slot(run, index, NofileOperation::Bind);
        bind(
            run,
            index,
            value["Id"]
                .as_str()
                .unwrap_or_else(|| panic!("closed nofile API create ID")),
        );
    }
}

fn configured(
    run: &HealthRun,
    index: usize,
    image: &Value,
    running: bool,
    diagnostics: &NofileDiagnostics,
    operation: NofileOperation,
) -> Value {
    diagnostics.slot(run, index, operation);
    let id = run.ids[index].as_ref().unwrap();
    let (status, value) = run.inspect(id, false);
    let (_, soft, hard) = CASES[index / 2];
    let expected_env = fixture_environment(&image["config"]["Env"])
        .unwrap_or_else(|| panic!("closed unshadowed borrowed nofile environment"));
    assert!(
        status == 200
            && owned(run, &value, index, Some(id))
            && value["Image"] == image["id"]
            && value["Config"]["Cmd"] == json!(["sh", "-c", BOOTSTRAP, run.names[index]])
            && value["Path"] == "sh"
            && value["Args"] == json!(["-c", BOOTSTRAP, run.names[index]])
            && environment_bindings(&value["Config"]["Env"]).as_ref() == Some(&expected_env)
            && (value["Config"]["Entrypoint"].is_null()
                || value["Config"]["Entrypoint"] == json!([]))
            && value["HostConfig"]["Ulimits"] == json!([{"Name":"nofile","Soft":soft,"Hard":hard}]),
        "owned exact configured nofile values and process"
    );
    assert!(
        value["HostConfig"]["Privileged"] == false
            && (value["HostConfig"]["CapAdd"].is_null()
                || value["HostConfig"]["CapAdd"] == json!([]))
            && (value["HostConfig"]["CapDrop"].is_null()
                || value["HostConfig"]["CapDrop"] == json!([]))
            && value["RestartCount"] == 0
            && value["State"]["OOMKilled"] == false
            && value["State"]["Running"] == running
            && value["State"]["Restarting"] == false
            && value["State"]["Paused"] == false
            && value["State"]["Dead"] == false
            && value["Mounts"].as_array().is_some_and(Vec::is_empty),
        "no caps, host mounts, restarts or unstable fixture"
    );
    if index >= 4 {
        assert!(
            value["HostConfig"]["NetworkMode"] == case_network_name(run, index),
            "configured owned case bridge route"
        );
    }
    value
}

// Only the existing independently implemented HTTP helper parses transport.
// This local frame retains non-2xx JSON which HealthRun::api intentionally drops.
fn start_http(run: &HealthRun, index: usize) -> (u16, Value) {
    let path = format!(
        "/v{}/containers/{}/start",
        run.api,
        run.ids[index].as_ref().unwrap()
    );
    assert!(
        run.request_allowed("POST", &path),
        "same exact nofile HTTP allowlist"
    );
    let mut command = run.timer(false, false);
    command.args([
        "python3",
        concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/native-unix-http.py"),
        "--timeout",
        "7",
        "--max-response-bytes",
        "65536",
        "--socket",
        &run.socket,
        "--method",
        "POST",
        "--max-request-bytes",
        "8388608",
        "--json-content-type",
        "--path",
        &path,
    ]);
    let bytes = run.capture(&mut command, None, false);
    let at = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .unwrap_or_else(|| panic!("closed nofile HTTP frame"));
    let status = std::str::from_utf8(&bytes[at + 1..])
        .ok()
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("closed nofile HTTP status"));
    if status == 204 {
        assert!(at == 0, "empty successful nofile start body");
        (status, Value::Null)
    } else {
        let raw = std::str::from_utf8(&bytes[..at])
            .unwrap_or_else(|_| panic!("private nofile error UTF8"))
            .trim();
        let literal = raw
            .strip_prefix("{\"message\":")
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or_else(|| panic!("closed nofile HTTP message object"));
        // A single JSON string parser rejects trailing members and duplicate
        // message keys instead of collapsing a native object to its last key.
        let message: String = serde_json::from_str(literal)
            .unwrap_or_else(|_| panic!("single nofile HTTP error string"));
        (status, json!({"message":message}))
    }
}

fn start_cli(run: &HealthRun, index: usize) -> (u16, String) {
    let bytes=run.outer(&["sh".into(),"-c".into(),"output=$(\"$@\" 2>&1); status=$?; printf '%s\\nDOCKERLENS_NOFILE_EXIT:%s\\n' \"$output\" \"$status\"".into(),"dl-nofile-status".into(),
        "env".into(),"LC_ALL=C".into(),format!("DOCKER_API_VERSION={}",run.api),"docker".into(),"-H".into(),"unix:///dockerlens-native/docker.sock".into(),"start".into(),run.ids[index].as_ref().unwrap().clone()],false);
    let text = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("complete nofile CLI status frame"));
    let (output, status) = text
        .rsplit_once("\nDOCKERLENS_NOFILE_EXIT:")
        .unwrap_or_else(|| panic!("closed nofile CLI status delimiter"));
    let status = number(status);
    assert!(status <= 255, "bounded nofile CLI exit");
    (status as u16, output.to_owned())
}

fn refusal(error: &str) -> bool {
    error.len() <= 8192
        && error.bytes().all(|b| (32..=126).contains(&b))
        && (error == REFUSAL
            || error == format!("{REFUSAL}: unknown")
            || error.ends_with(&format!(": {REFUSAL}"))
            || error.ends_with(&format!(": {REFUSAL}: unknown")))
}

fn cli_start_refusal_matches(api: &str, id: &str, error: &str, output: &str) -> bool {
    let (daemon, summary) = output
        .split_once('\n')
        .map_or((output, None), |(daemon, summary)| (daemon, Some(summary)));
    daemon == format!("Error response from daemon: {error}")
        && summary.is_none_or(|summary| {
            summary == format!("Error: failed to start containers: {id}")
                // The pinned Docker 29 CLI omits the legacy Error: prefix.
                || (api == "1.56" && summary == format!("failed to start containers: {id}"))
        })
}

#[test]
fn nofile_start_refusal_requires_exact_inspected_message_and_full_id() {
    let id = "a".repeat(64);
    let other_id = "b".repeat(64);
    let error =
        format!("failed to create shim task: OCI runtime create failed: {REFUSAL}: unknown");
    let daemon = format!("Error response from daemon: {error}");
    let wrong = format!("Error response from daemon: other runtime context: {REFUSAL}: unknown");
    let modern = format!("{daemon}\nfailed to start containers: {id}");
    let legacy = format!("{daemon}\nError: failed to start containers: {id}");
    assert!(refusal(&error));

    for api in ["1.41", "1.56"] {
        assert!(cli_start_refusal_matches(api, &id, &error, &daemon));
        assert!(cli_start_refusal_matches(api, &id, &error, &legacy));
        assert_eq!(
            cli_start_refusal_matches(api, &id, &error, &modern),
            api == "1.56"
        );
        for output in [
            wrong.clone(),
            format!("{wrong}\nError: failed to start containers: {id}"),
            format!("{wrong}\nfailed to start containers: {id}"),
            format!("{daemon}\nfailed to start containers: {other_id}"),
            format!("{daemon}\nError: failed to start containers: {other_id}"),
            format!("{daemon}\nfailed to start containers: {}", &id[..12]),
            format!("{daemon}\nfailed to start containers: {id}, {other_id}"),
            format!("{daemon}\nError: failed to start container: {id}"),
            format!("{daemon}\r\nfailed to start containers: {id}"),
            format!("{modern}\n"),
            format!("{modern}\nother diagnostic"),
            format!("warning\n{modern}"),
            id.clone(), // Successful START stdout even when using the same full ID.
            serde_json::to_string(&json!({"message":error})).unwrap(), // Direct API body.
        ] {
            assert!(!cli_start_refusal_matches(api, &id, &error, &output));
        }
    }
    assert!(!cli_start_refusal_matches("1.55", &id, &error, &modern));
}

fn exercise(
    run: &HealthRun,
    index: usize,
    image: &Value,
    diagnostics: &NofileDiagnostics,
) -> Value {
    let before = configured(
        run,
        index,
        image,
        false,
        diagnostics,
        NofileOperation::ConfiguredBefore,
    );
    assert!(
        before["State"]["Status"] == "created"
            && before["State"]["Pid"] == 0
            && before["State"]["StartedAt"] == "0001-01-01T00:00:00Z"
            && before["State"]["FinishedAt"] == "0001-01-01T00:00:00Z"
            && before["State"]["Error"] == ""
            && before["State"]["ExitCode"] == 0,
        "never-started exact create state"
    );
    diagnostics.slot(run, index, NofileOperation::Start);
    let (status, reported) = if index.is_multiple_of(2) {
        let (s, t) = start_cli(run, index);
        (s, json!(t))
    } else {
        let (s, v) = start_http(run, index);
        (s, v)
    };
    let success = status == if index.is_multiple_of(2) { 0 } else { 204 };
    let current = configured(
        run,
        index,
        image,
        success,
        diagnostics,
        NofileOperation::ConfiguredStarted,
    );
    let (_, soft, hard) = CASES[index / 2];
    if success {
        if index.is_multiple_of(2) {
            assert!(
                reported == run.ids[index].as_ref().unwrap().as_str(),
                "exact nofile CLI started ID"
            );
        }
        assert!(
            current["State"]["Status"] == "running"
                && current["State"]["Pid"].as_u64().is_some_and(|n| n > 0),
            "actual live nofile PID1"
        );
        diagnostics.slot(run, index, NofileOperation::Observe);
        let bytes = docker(
            run,
            &[
                "exec".into(),
                "--user".into(),
                "0:0".into(),
                run.ids[index].as_ref().unwrap().clone(),
                "sh".into(),
                "-c".into(),
                OBSERVE.into(),
                run.names[index].clone(),
                WORKER.into(),
            ],
        );
        diagnostics.slot(run, index, NofileOperation::Witness);
        let value = witness(&bytes, (soft, hard));
        configured(
            run,
            index,
            image,
            true,
            diagnostics,
            NofileOperation::ConfiguredAfter,
        );
        json!({"stage":"running","cli_exit":if index.is_multiple_of(2){json!(0)}else{Value::Null},"http_status":if index.is_multiple_of(2){Value::Null}else{json!(204)},"diagnostic":Value::Null,"witness":value})
    } else {
        assert!(
            hard == -1 && status == if index.is_multiple_of(2) { 1 } else { 500 },
            "only specific unlimited START refusal eligible"
        );
        let error = current["State"]["Error"]
            .as_str()
            .unwrap_or_else(|| panic!("actual nofile start error"));
        assert!(
            refusal(error)
                && current["State"]["Status"] == "created"
                && current["State"]["Pid"] == 0
                && current["State"]["StartedAt"] == before["State"]["StartedAt"]
                && current["State"]["FinishedAt"] == before["State"]["FinishedAt"],
            "specific applying RLIMIT_NOFILE refusal and never-started facts"
        );
        if index.is_multiple_of(2) {
            let output = reported.as_str().unwrap();
            assert!(
                cli_start_refusal_matches(
                    &run.api,
                    run.ids[index].as_ref().unwrap(),
                    error,
                    output
                ),
                "exact private CLI refusal corroborates inspected error"
            );
        } else {
            assert!(
                reported["message"] == error,
                "actual API error corroborates inspected error"
            );
        }
        let after = configured(
            run,
            index,
            image,
            false,
            diagnostics,
            NofileOperation::RefusalStable,
        );
        assert!(
            after["State"] == current["State"],
            "stable never-started terminal failure"
        );
        json!({"stage":"start_refused","cli_exit":if index.is_multiple_of(2){json!(1)}else{Value::Null},"http_status":if index.is_multiple_of(2){Value::Null}else{json!(500)},"diagnostic":error,
            "witness":{"outcome":"specific_nofile_start_refusal","status":"created","pid":0,"never_started":true,"terminal_unchanged":true,"error":"setting_rlimit_nofile_eperm"}})
    }
}

fn acquisition_error_name(error: AcquisitionError) -> &'static str {
    match error {
        AcquisitionError::Endpoint => "endpoint",
        AcquisitionError::Cancelled => "cancelled",
        AcquisitionError::Deadline => "deadline",
        AcquisitionError::Io => "io",
        AcquisitionError::Protocol => "protocol",
        AcquisitionError::Status => "status",
        AcquisitionError::Version => "version",
        AcquisitionError::Shape => "shape",
        AcquisitionError::Selection => "selection",
        AcquisitionError::Budget(limit) => match limit {
            LimitError::Invalid => "budget_invalid",
            LimitError::Requests => "budget_requests",
            LimitError::PendingResponse => "budget_pending_response",
            LimitError::ResponseWithoutRequest => "budget_response_without_request",
            LimitError::Exhausted => "budget_exhausted",
            LimitError::SelectedResources => "budget_selected_resources",
            LimitError::Expansions => "budget_expansions",
            LimitError::Bytes => "budget_bytes",
            LimitError::Elapsed => "budget_elapsed",
            LimitError::Input => "budget_input",
            LimitError::InvalidResourceRef => "budget_invalid_resource_ref",
            LimitError::Incomplete => "budget_incomplete",
            LimitError::ObservationIdExhausted => "budget_observation_id_exhausted",
            LimitError::CaptureAccounting => "budget_capture_accounting",
            LimitError::MissingApiVersion => "budget_missing_api_version",
            LimitError::ResourceConflict => "budget_resource_conflict",
        },
    }
}

fn acquisition_shape_name(detail: AcquisitionShape) -> &'static str {
    match detail {
        AcquisitionShape::ContainerIdentity => "container_identity",
        AcquisitionShape::ContainerRelated => "container_related",
        AcquisitionShape::NetworkRequest => "network_request",
        AcquisitionShape::NetworkIdentity => "network_identity",
        AcquisitionShape::NetworkId => "network_id",
        AcquisitionShape::DuplicateNetworkId => "duplicate_network_id",
        AcquisitionShape::DuplicateNoncanonicalNetworkId => "duplicate_noncanonical_network_id",
        AcquisitionShape::VolumeRequest => "volume_request",
        AcquisitionShape::VolumeIdentity => "volume_identity",
    }
}

fn availability_name(availability: Availability) -> &'static str {
    match availability {
        Availability::Missing => "missing",
        Availability::Null => "null",
        Availability::Empty => "empty",
        Availability::Present => "present",
        Availability::Redacted => "redacted",
    }
}

fn captured_topology(
    run: &HealthRun,
    networks: &NofileNetworks,
    capture: &crate::evidence::Capture,
    decoded: &crate::decoder::DecodedInventory,
) -> (Vec<Value>, Vec<Value>) {
    use crate::acquisition::ReadRequest;
    assert!(
        networks.bound(run)
            && networks.owned.iter().all(|n| n.attempted)
            && decoded.networks.len() <= 3
            && decoded.volumes.is_empty(),
        "at most three distinct captured case networks, no volume expansion"
    );
    let mut summaries = Vec::new();
    let mut bindings = vec![Value::Null; 8];
    for (index, binding) in bindings.iter_mut().enumerate() {
        let container_id = run.ids[index].as_deref().unwrap();
        let container = decoded
            .containers
            .iter()
            .find(|c| {
                c.id.value()
                    .is_some_and(|v| v.as_bytes() == container_id.as_bytes())
            })
            .unwrap_or_else(|| panic!("captured network audience root"));
        let name = case_network_name(run, index);
        if let Some(mode) = container.network_mode.value() {
            assert!(
                if index < 4 {
                    matches!(
                        mode.kind,
                        crate::decoder::NetworkModeKind::Default
                            | crate::decoder::NetworkModeKind::Bridge
                    )
                } else {
                    mode.native_value.as_bytes() == name.as_bytes()
                },
                "nonconflicting captured configured network route"
            );
        }
        let availability = container.networks.availability;
        let attachments = container.networks.value();
        *binding = json!({"container_id":container_id,"endpoint_map_availability":availability_name(availability),
            "name":Value::Null,"network_id":Value::Null,"network_id_availability":Value::Null,"lookup":Value::Null});
        let Some(attachment) = attachments.and_then(|a| a.first()) else {
            assert!(
                matches!(
                    availability,
                    Availability::Missing
                        | Availability::Null
                        | Availability::Empty
                        | Availability::Redacted
                ),
                "only observed unavailable or empty maps omit endpoint evidence"
            );
            continue;
        };
        assert!(
            availability == Availability::Present
                && attachments.unwrap().len() == 1
                && attachment.name.as_bytes() == name.as_bytes(),
            "one positively observed intended case network attachment"
        );
        let endpoint = &attachment.network_id;
        let value = endpoint
            .value()
            .map(|v| std::str::from_utf8(v.as_bytes()).unwrap());
        let lookup = if endpoint.availability == Availability::Present {
            "id"
        } else {
            assert!(
                matches!(
                    (endpoint.availability, value),
                    (
                        Availability::Missing | Availability::Null | Availability::Redacted,
                        None
                    ) | (Availability::Empty, Some(""))
                ),
                "actual unavailable endpoint network identity"
            );
            "name"
        };
        binding["name"] = json!(name);
        binding["network_id"] = json!(value);
        binding["network_id_availability"] = json!(availability_name(endpoint.availability));
        binding["lookup"] = json!(lookup);
    }
    for group in 0..3 {
        let indices: Vec<usize> = match group {
            0 => (0..4).collect(),
            1 => vec![4, 5],
            _ => vec![6, 7],
        };
        let name = case_network_name(run, indices[0]);
        let observed = decoded.networks.iter().find(|n| {
            n.name
                .value()
                .is_some_and(|v| v.as_bytes() == name.as_bytes())
        });
        let supported = indices
            .iter()
            .any(|&index| !bindings[index]["lookup"].is_null());
        if !supported {
            assert!(
                observed.is_none(),
                "no fabricated exchange for an unreferenced case network"
            );
            continue;
        }
        let observed = observed.unwrap_or_else(|| panic!("captured referenced case network name"));
        let id = observed
            .id
            .value()
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .filter(|id| identifier(id))
            .unwrap_or_else(|| panic!("captured canonical network ID"));
        assert!(
            observed
                .driver
                .value()
                .is_some_and(|v| v.as_bytes() == b"bridge"),
            "captured bridge driver"
        );
        let exchange = capture
            .exchanges()
            .iter()
            .find(|e| e.resource() == Some(observed.reference))
            .unwrap_or_else(|| panic!("captured network exchange reference"));
        let ReadRequest::InspectNetwork(requested) = exchange.request() else {
            panic!("network inspect request")
        };
        let by_name = capture
            .network_name_fallbacks()
            .contains(&observed.reference);
        assert!(
            requested.as_str() == if by_name { &name } else { id },
            "actual network request identity binding"
        );
        let raw: Value = serde_json::from_slice(exchange.body().as_bytes()).unwrap();
        if group > 0 {
            assert!(
                networks.owned[group - 1].id.as_deref() == Some(id)
                    && networks.authenticate(run, group - 1, &raw),
                "captured owned bridge identity and custody"
            );
        } else {
            assert!(
                id != networks.outer_id
                    && !run.ids.iter().flatten().any(|other| other == id)
                    && !networks.owned.iter().any(|n| n.id.as_deref() == Some(id)),
                "default bridge is never owned"
            );
        }
        let lookup = if by_name { "name" } else { "id" };
        for &index in &indices {
            let binding = &bindings[index];
            if binding["lookup"].is_null() {
                continue;
            }
            assert!(
                binding["lookup"] == lookup && (by_name || binding["network_id"] == id),
                "each observed endpoint binds its own actual ID/name exchange"
            );
        }
        let mut selected = BTreeSet::new();
        let unselected = observed.active_endpoints.value().map(|members| {
            let mut unselected = 0;
            for member in members {
                let member_id = member.container_id.value().unwrap().as_bytes();
                if let Some(index) = run.ids.iter().position(|other| {
                    other
                        .as_deref()
                        .is_some_and(|id| id.as_bytes() == member_id)
                }) {
                    assert!(
                        indices.contains(&index),
                        "captured selected membership belongs to case network"
                    );
                    selected.insert(index);
                } else {
                    unselected += 1;
                }
            }
            assert!(
                group == 0 || unselected == 0,
                "owned bridge refuses observed foreign membership"
            );
            unselected
        });
        summaries.push(json!({"id":id,"name":name,"driver":"bridge","ownership":if group==0{"not_owned"}else{"owned"},
            "owner":if group==0{Value::Null}else{json!(run.run)},"container_indices":indices,"lookup":lookup,
            "active_membership_availability":availability_name(observed.active_endpoints.availability),
            "active_selected_ids":selected.into_iter().map(|i|run.ids[i].clone().unwrap()).collect::<Vec<_>>(),
            "active_unselected_count":unselected}));
    }
    assert!(
        summaries.len() == decoded.networks.len(),
        "no unsupported or fabricated captured network"
    );
    (summaries, bindings)
}

fn acquisition(
    run: &HealthRun,
    outer_backend: SourceOuterBackend,
    diagnostics: &NofileDiagnostics,
    networks: Option<&NofileNetworks>,
) -> Value {
    let calls = run.calls.get().checked_add(REQUESTS).unwrap();
    let bytes = run.bytes.get().checked_add(BODIES).unwrap();
    assert!(
        calls
            .checked_add(2 + outer_backend.snapshot_extra_calls())
            .is_some_and(|pending| pending <= MAX_CALLS - CLEANUP_CALLS)
            && bytes
                .checked_add(2 * ORDINARY_CAPTURE_ENVELOPE + outer_backend.snapshot_extra_bytes())
                .is_some_and(|pending| pending <= MAX_BYTES - CLEANUP_BYTES),
        "reserve one aggregate nofile acquisition"
    );
    let elapsed = run
        .remaining()
        .checked_sub(Duration::from_secs(46))
        .filter(|d| !d.is_zero())
        .unwrap_or_else(|| panic!("nofile acquisition cleanup reserve"));
    run.calls.set(calls);
    run.bytes.set(bytes);
    let selected = run
        .ids
        .iter()
        .map(|id| NativeId::new(id.as_ref().unwrap().clone()).unwrap())
        .collect();
    let acquisition_started = Instant::now();
    let capture = acquire_with_shape_detail(
        &Endpoint::unix_socket(PathBuf::from(&run.socket)),
        Selector::ContainerIds(selected),
        Limits {
            max_requests: REQUESTS,
            max_selected_resources: 8,
            max_expansions: 11,
            max_response_bytes: 131072,
            max_total_bytes: BODIES,
            max_elapsed: elapsed.min(Duration::from_secs(10)),
        },
        &AtomicBool::new(false),
    )
    .unwrap_or_else(|(error, detail)| {
        diagnostics
            .acquisition_error
            .set(Some(acquisition_error_name(error)));
        diagnostics
            .acquisition_shape
            .set(detail.map(acquisition_shape_name));
        panic!("one actual eight-ID nofile acquisition")
    });
    let actual_elapsed = acquisition_started.elapsed();
    let api = ApiVersion::new(
        NonZeroU16::new(1).unwrap(),
        if run.lane.starts_with("debian11-") {
            41
        } else {
            49
        },
    );
    assert!(
        capture.route() == CaptureRoute::ExplicitUnixSocket
            && capture.selected_roots().len() == 8
            && capture
                .exchanges()
                .iter()
                .all(|e| e.status().code() == 200 && e.api_version().is_none_or(|a| a == api)),
        "complete nofile acquisition and actual request API"
    );
    let decoded = decode_capture(&capture).unwrap_or_else(|_| panic!("actual nofile decode"));
    assert!(
        decoded.containers.len() == 8
            && decoded.version.requested_api_versions == vec![api]
            && decoded.version.daemon.observation_id == capture.observation_id()
            && decoded
                .version
                .daemon
                .release
                .as_ref()
                .is_some_and(|r| r.as_str() == run.engine),
        "actual bound nofile decoder context"
    );
    let mode = match (run.mode, decoded.version.daemon.mode) {
        (DaemonMode::Rootless, DaemonMode::Rootless) => "rootless_observed",
        (DaemonMode::Rootful, DaemonMode::Rootful) => "rootful_observed",
        (DaemonMode::Rootful, DaemonMode::Unknown) => "unknown_with_independent_rootful_context",
        _ => panic!("nonconflicting actual nofile mode"),
    };
    let (network_records, container_networks) = networks
        .map(|networks| {
            let topology = captured_topology(run, networks, &capture, &decoded);
            let n = topology.0.len();
            assert!(
                n <= 3
                    && capture.bounds().expansions == 8 + n
                    && capture.bounds().request_count == 10 + n,
                "actual case bridge acquisition counts derive only from observed references"
            );
            topology
        })
        .unwrap_or_default();
    let mut seen = BTreeSet::new();
    for container in &decoded.containers {
        let id = container.id.value().unwrap().as_bytes();
        let index = run
            .ids
            .iter()
            .position(|other| other.as_ref().unwrap().as_bytes() == id)
            .unwrap_or_else(|| panic!("selected nofile decoded ID"));
        let values = container
            .runtime
            .ulimits
            .value()
            .unwrap_or_else(|| panic!("decoded nofile list present"));
        let (_, soft, hard) = CASES[index / 2];
        assert!(
            seen.insert(index)
                && container.id.availability == Availability::Present
                && container.id.origin == Origin::RuntimeAssigned
                && container.runtime.ulimits.availability == Availability::Present
                && container.runtime.ulimits.origin == Origin::Effective
                && values.len() == 1
                && values[0].name.availability == Availability::Present
                && values[0].name.origin == Origin::Effective
                && values[0]
                    .name
                    .value()
                    .is_some_and(|v| v.as_bytes() == b"nofile")
                && values[0].soft.availability == Availability::Present
                && values[0].soft.origin == Origin::Effective
                && values[0].hard.availability == Availability::Present
                && values[0].hard.origin == Origin::Effective
                && values[0].soft.value() == Some(&soft)
                && values[0].hard.value() == Some(&hard),
            "actual decoded configured nofile values, not inferred kernel support"
        );
    }
    let bodies: usize = capture
        .exchanges()
        .iter()
        .map(|e| e.body().as_bytes().len())
        .sum();
    assert!(
        capture.exchanges().len() <= REQUESTS
            && bodies <= BODIES
            && capture.bounds().bytes_read == bodies
            && actual_elapsed <= Duration::from_secs(10),
        "bounded nofile response bodies"
    );
    json!({"route":"explicit_unix_socket","selected_ids":8,"requested_api":format!("{}.{}",api.major,api.minor),"reserved_calls":REQUESTS,"reserved_bytes":BODIES,"actual_requests":capture.exchanges().len(),"actual_response_bytes":bodies,"actual_expansions":capture.bounds().expansions,"actual_elapsed_ns":actual_elapsed.as_nanos(),"networks":network_records,"container_networks":container_networks,"decoded":"present_effective_exact_nofile_values","daemon_mode_evidence":mode,
        "byte_scope":"decoded_response_bodies_only","separate_transport_bounds":{"response_header_bytes":16384,"chunk_line_bytes":64,"chunk_payload_crlf_bytes":2,"final_trailer_line_bytes":16384,"actual_wire_bytes":"not_measured"},
        "limits":{"max_requests":20,"max_selected_resources":8,"max_expansions":11,"max_response_bytes":131072,"max_total_bytes":BODIES,"max_elapsed_seconds":10}})
}

#[test]
fn nofile_acquisition_reports_real_exchange_errors_and_keeps_exact_eight_id_proof() {
    use std::io::{BufRead, BufReader, ErrorKind};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixListener;

    let private =
        std::env::temp_dir().join(format!("dl-nf-acq-{}-{}", std::process::id(), utc_ns()));
    fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
    let controls = std::panic::catch_unwind(|| {
        for (control, error, requests) in [
            ("id", None, 11),
            ("name", None, 11),
            ("missing_endpoint", None, 11),
            ("distinct_networks", None, 12),
            (
                "same_bridge_twice",
                Some("shape acquisition_shape=duplicate_network_id"),
                12,
            ),
            (
                "same_noncanonical_id",
                Some("shape acquisition_shape=duplicate_noncanonical_network_id"),
                12,
            ),
            (
                "container_identity",
                Some("shape acquisition_shape=container_identity"),
                3,
            ),
            (
                "container_related",
                Some("shape acquisition_shape=container_related"),
                3,
            ),
            (
                "network_request",
                Some("shape acquisition_shape=network_request"),
                10,
            ),
            (
                "network_identity",
                Some("shape acquisition_shape=network_identity"),
                12,
            ),
            ("network_id", Some("shape acquisition_shape=network_id"), 12),
            (
                "volume_request",
                Some("shape acquisition_shape=volume_request"),
                10,
            ),
            (
                "volume_identity",
                Some("shape acquisition_shape=volume_identity"),
                11,
            ),
            ("version", Some("version"), 1),
            ("frame", Some("protocol"), 11),
            ("status", Some("status"), 11),
            ("response_bytes", Some("budget_bytes"), 11),
        ] {
            let socket = private.join(control);
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut run = offline_run(socket.to_str().unwrap().into());
            run.deadline = Instant::now() + Duration::from_secs(180);
            run.api = "1.56".into();
            run.engine = "29.8.1".into();
            run.lane = "upstream-rootful".into();
            run.ids = (1..=8).map(|id| Some(format!("{id:064x}"))).collect();
            let network_id = "a".repeat(64);
            let mut bytes = 0;
            let mut exchanges = Vec::new();
            let mut reply = |path: String, body: Value| {
                let body = body.to_string() + "\n";
                bytes += body.len();
                exchanges.push((
                    path,
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    ),
                ));
            };
            reply(
                "/version".into(),
                json!({"Version":"29.8.1","ApiVersion":"1.56",
                      "MinAPIVersion":if control == "version" { "1.50" } else { "1.44" }}),
            );
            if control != "version" {
                reply("/v1.49/info".into(), json!({"ServerVersion":"29.8.1"}));
                for (index, (soft, hard)) in [
                    (64, 128),
                    (64, 128),
                    (128, 128),
                    (128, 128),
                    (64, -1),
                    (64, -1),
                    (-1, -1),
                    (-1, -1),
                ]
                .into_iter()
                .enumerate()
                {
                    let running = index < 4
                        || matches!(control, "id" | "frame" | "status" | "response_bytes");
                    let networks = match (control, running) {
                        ("container_related", _) => json!([]),
                        ("network_request", _) => json!({"bridge":{"NetworkID":"x".repeat(1025)}}),
                        ("volume_request" | "volume_identity", _) => json!({}),
                        ("same_noncanonical_id", _) if index < 4 => {
                            json!({"a-net":{"NetworkID":""}})
                        }
                        ("same_noncanonical_id", _) => json!({"b-net":{"NetworkID":""}}),
                        ("distinct_networks", true) => json!({"other":{"NetworkID":network_id}}),
                        ("missing_endpoint", false) => json!({}),
                        (
                            "name" | "same_bridge_twice" | "distinct_networks" | "network_identity"
                            | "network_id",
                            false,
                        )
                        | ("name", true) => {
                            json!({"bridge":{"NetworkID":"","EndpointID":""}})
                        }
                        _ => json!({"bridge":{"NetworkID":network_id,"EndpointID":"endpoint"}}),
                    };
                    let id = run.ids[index].as_deref().unwrap();
                    let mounts = match control {
                        "volume_request" => json!([{"Type":"volume","Name":"x".repeat(1025)}]),
                        "volume_identity" => json!([{"Type":"volume","Name":"expected"}]),
                        _ => json!([]),
                    };
                    reply(
                        format!("/v1.49/containers/{id}/json"),
                        json!({"Id":if control=="container_identity" { "wrong" } else { id },
                            "State":{"Status":if running {"running"} else {"created"},
                            "Running":running,"Pid":if running {100+index}else{0}},"Mounts":mounts,
                            "HostConfig":{"Ulimits":[{"Name":"nofile","Soft":soft,"Hard":hard}]},
                            "NetworkSettings":{"Networks":networks}}),
                    );
                    if matches!(control, "container_identity" | "container_related") {
                        break;
                    }
                }
                let bridge = json!({"Id":network_id,"Name":"bridge","Driver":"bridge"});
                match control {
                    "container_identity" | "container_related" | "network_request"
                    | "volume_request" => {}
                    "volume_identity" => {
                        reply("/v1.49/volumes/expected".into(), json!({"Name":"wrong"}));
                    }
                    "same_noncanonical_id" => {
                        for name in ["a-net", "b-net"] {
                            reply(
                                format!("/v1.49/networks/{name}"),
                                json!({"Id":"not-a-full-id","Name":name,"Driver":"bridge"}),
                            );
                        }
                    }
                    "name" => reply("/v1.49/networks/bridge".into(), bridge),
                    _ => {
                        let mut direct = bridge.clone();
                        if control == "distinct_networks" {
                            direct["Name"] = json!("other");
                        }
                        reply(format!("/v1.49/networks/{network_id}"), direct);
                        let by_name = match control {
                            "same_bridge_twice" => Some(bridge),
                            "distinct_networks" => {
                                Some(json!({"Id":"b".repeat(64),"Name":"bridge","Driver":"bridge"}))
                            }
                            "network_identity" => Some(json!({"Id":network_id,"Name":"wrong"})),
                            "network_id" => Some(json!({"Name":"bridge"})),
                            _ => None,
                        };
                        if let Some(body) = by_name {
                            reply("/v1.49/networks/bridge".into(), body);
                        }
                    }
                }
                if let Some(raw) = match control {
                    "frame" => Some("HTTP/1.1 200 OK\r\n\r\n"),
                    "status" => Some("HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}"),
                    "response_bytes" => Some("HTTP/1.1 200 OK\r\nContent-Length: 131073\r\n\r\n"),
                    _ => None,
                } {
                    exchanges.last_mut().unwrap().1 = raw.into();
                }
            }
            assert_eq!(exchanges.len(), requests);
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(3);
                for (path, reply) in exchanges {
                    let (mut stream, _) = loop {
                        match listener.accept() {
                            Ok(accepted) => break accepted,
                            Err(e)
                                if e.kind() == ErrorKind::WouldBlock
                                    && Instant::now() < deadline =>
                            {
                                std::thread::sleep(Duration::from_millis(1))
                            }
                            Err(_) => panic!("inert acquisition accept"),
                        }
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut reader = BufReader::new(&stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    assert_eq!(line, format!("GET {path} HTTP/1.1\r\n"));
                    for _ in 0..4 {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                    }
                    assert_eq!(line, "\r\n");
                    stream.write_all(reply.as_bytes()).unwrap();
                }
            });
            let diagnostics = NofileDiagnostics::default();
            diagnostics.all(&run, NofileOperation::Acquisition);
            let acquired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                acquisition(&run, SourceOuterBackend::Docker, &diagnostics, None)
            }));
            assert!(server.join().is_ok(), "inert acquisition trace: {control}");
            assert_eq!(run.calls.get(), 20);
            assert_eq!(run.bytes.get(), 524288);
            let observed = diagnostics.failure(&run).unwrap();
            let base = "DOCKERLENS_NATIVE_NOFILE_FAILURE: caller_case=all caller_role=none caller_operation=acquisition observed_termination=unknown code=none";
            if let Some(error) = error {
                assert!(acquired.is_err(), "inert control must fail: {control}");
                assert_eq!(observed, format!("{base} acquisition_error={error}"));
                diagnostics.all(&run, NofileOperation::Acquisition);
                assert_eq!(diagnostics.failure(&run).as_deref(), Some(base));
            } else {
                assert_eq!(observed, base);
                let proof = acquired.unwrap();
                assert_eq!(proof["selected_ids"], 8);
                assert_eq!(proof["requested_api"], "1.49");
                assert_eq!(proof["actual_requests"], requests);
                assert_eq!(proof["actual_response_bytes"], bytes);
                assert_eq!(proof["decoded"], "present_effective_exact_nofile_values");
            }
        }
    });
    fs::remove_dir_all(private).unwrap();
    controls.unwrap();
}

fn nofile_cleanup_with(
    attempted: &[bool],
    ids: &[Option<String>],
    inner: impl FnOnce() -> CleanupDisposition,
) -> CleanupDisposition {
    // Shared lifecycle cleanup can recover an unknown ID through its name.
    // Nofile does not authorize that recovery after an uncertain create.
    // Refuse the entire inner attempt before any read/name recovery/mutation.
    if attempted.len() != 8
        || ids.len() != 8
        || attempted.iter().zip(ids).any(|(attempted, id)| {
            if *attempted {
                !id.as_deref().is_some_and(identifier)
            } else {
                id.is_some()
            }
        })
        || ids.iter().flatten().collect::<BTreeSet<_>>().len() != ids.iter().flatten().count()
    {
        return CleanupDisposition::OuterTeardownRequired;
    }
    inner()
}

#[test]
fn nofile_unknown_create_id_never_invokes_inner_cleanup() {
    let attempted = vec![true; 8];
    let valid: Vec<_> = (1..=8).map(|n| Some(format!("{n:064x}"))).collect();
    for invalid in [
        None,
        Some("malformed".to_owned()),
        Some("a".repeat(63)),
        Some("A".repeat(64)),
    ] {
        let mut ids = valid.clone();
        ids[3] = invalid;
        let invoked = Cell::new(false);
        let disposition = nofile_cleanup_with(&attempted, &ids, || {
            invoked.set(true);
            CleanupDisposition::VerifiedAbsent
        });
        assert!(
            disposition == CleanupDisposition::OuterTeardownRequired && !invoked.get(),
            "unknown create ID must not permit name recovery or inner cleanup"
        );
    }
    let invoked = Cell::new(false);
    assert!(
        nofile_cleanup_with(&attempted, &valid, || {
            invoked.set(true);
            CleanupDisposition::VerifiedAbsent
        }) == CleanupDisposition::VerifiedAbsent
            && invoked.get(),
        "all bound canonical IDs permit normal cleanup"
    );
    assert!(
        nofile_cleanup_with(&attempted, &valid, || {
            CleanupDisposition::OuterTeardownRequired
        }) == CleanupDisposition::OuterTeardownRequired,
        "inner cleanup uncertainty remains unverified"
    );
    let invoked = Cell::new(false);
    assert!(
        nofile_cleanup_with(&attempted[..7], &valid, || {
            invoked.set(true);
            CleanupDisposition::VerifiedAbsent
        }) == CleanupDisposition::OuterTeardownRequired
            && !invoked.get(),
        "partial ownership ledger refuses cleanup"
    );
}

#[test]
#[ignore = "prepared source; requires exact isolated native lane and bound outer owner"]
fn live_nofile_limits_and_effects_match_engine() {
    let outer_backend = source_outer_backend();
    let started = Instant::now();
    let target = ProofTarget::new_for("NATIVE_NOFILE_PROOF_PATH", FILENAME);
    let mut run = HealthRun::new_for(
        "NATIVE_NOFILE_CANDIDATE_SHA",
        "NATIVE_NOFILE_DEADLINE_EPOCH",
    );
    run.nofile_command_observation = Some(NofileCommandObservation::default());
    let diagnostics = NofileDiagnostics::default();
    run.names = CASES
        .into_iter()
        .flat_map(|(name, _, _)| {
            ["oracle", "rendered"].map(|role| format!("dl-nf-{}-{name}-{role}", run.run))
        })
        .collect();
    run.ids = vec![None; 8];
    run.attempted = vec![false; 8];
    let owner = BoundOuterCleanupOwner::bind(&run);
    let mut networks = NofileNetworks::new(&run, &owner);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        diagnostics.all(&run, NofileOperation::Context);
        // Single-thread libtest can leave its test-name prefix unterminated.
        let _ = writeln!(
            std::io::stderr(),
            "\nDOCKERLENS_NATIVE_CHECK: nofile_context"
        );
        let uid = run.context();
        let image = image_snapshot(&run);
        assert!(
            image["config"]["Volumes"].is_null() || image["config"]["Volumes"] == json!({}),
            "no borrowed automatic volumes"
        );
        assert!(
            fixture_environment(&image["config"]["Env"]).is_some(),
            "closed unshadowed borrowed nofile environment before create"
        );
        let facts = run.facts.as_mut().unwrap();
        let scope = facts.capabilities[0].scope.clone();
        facts.capabilities = NOFILE_CAPABILITIES
            .into_iter()
            .map(|capability| CapabilityFact {
                capability,
                state: CapabilityState::Available,
                provenance: FactProvenance::NativeConformance,
                scope: scope.clone(),
            })
            .collect();
        let context_calls = run.calls.get();
        assert!(
            context_calls
                == (if run.lane.starts_with("debian11-") {
                    9
                } else {
                    8
                }) + outer_backend.snapshot_extra_calls(),
            "closed original context capture count"
        );
        for index in 0..2 {
            networks.create(&run, index);
        }
        let mut records = Vec::new();
        let mut slot_calls = Vec::new();
        let _ = writeln!(std::io::stderr(), "DOCKERLENS_NATIVE_CHECK: nofile_effects");
        for index in 0..8 {
            let before = run.calls.get();
            create_nofile(&mut run, index, &diagnostics, &networks);
            let effect = exercise(&run, index, &image, &diagnostics);
            diagnostics.slot(&run, index, NofileOperation::SlotAccounting);
            let expected = if effect["stage"] == "running" { 8 } else { 7 };
            assert!(
                run.calls.get() - before == expected,
                "closed outcome-derived nofile slot accounting"
            );
            slot_calls.push(expected);
            records.push(json!({"role":if index.is_multiple_of(2){"oracle"}else{"rendered"},"id":run.ids[index],"name":run.names[index],"owner":run.run,"image_id":image["id"],"wire":if index.is_multiple_of(2){"independent_cli"}else{"literal_rendered"},"configured":{"soft":CASES[index/2].1,"hard":CASES[index/2].2},"effect":effect,"cleanup":"absent"}));
        }
        let mut cases = Vec::new();
        for (i, (name, _, _)) in CASES.into_iter().enumerate() {
            diagnostics.select(&run, i, NofileRole::Pair, NofileOperation::PairComparison);
            let a = &records[2 * i]["effect"];
            let b = &records[2 * i + 1]["effect"];
            assert!(
                a["stage"] == b["stage"]
                    && a["witness"]["outcome"] == b["witness"]["outcome"]
                    && a["witness"]["kernel"] == b["witness"]["kernel"]
                    && a["witness"]["retained_count"] == b["witness"]["retained_count"],
                "independent matching CLI/API observed disposition"
            );
            cases.push(json!({"case":name,"containers":[records[2*i],records[2*i+1]]}));
        }
        for role in 0..2 {
            diagnostics.select(
                &run,
                4,
                if role == 0 {
                    NofileRole::Oracle
                } else {
                    NofileRole::Rendered
                },
                NofileOperation::CapacityComparison,
            );
            assert!(
                records[2 + role]["effect"]["witness"]["retained_count"]
                    .as_u64()
                    .unwrap()
                    > records[role]["effect"]["witness"]["retained_count"]
                        .as_u64()
                        .unwrap(),
                "greater live retained capacity at finite soft128 than64"
            );
        }
        diagnostics.all(&run, NofileOperation::KernelComparison);
        let nr = records[0]["effect"]["witness"]["nr_open"].clone();
        for record in &records {
            if record["effect"]["stage"] == "running" {
                assert!(
                    record["effect"]["witness"]["nr_open"] == nr,
                    "same read-only kernel ceiling in owned contexts"
                );
            }
        }
        diagnostics.all(&run, NofileOperation::DaemonHealth);
        let (health_status, health) = run.api("GET", "/version", None, false);
        assert!(
            health_status == 200 && health["Version"] == run.engine,
            "post-case daemon health corroborated by finite controls"
        );
        let _ = writeln!(std::io::stderr(), "DOCKERLENS_NATIVE_CHECK: nofile_capture");
        diagnostics.all(&run, NofileOperation::Acquisition);
        let acquired = acquisition(&run, outer_backend, &diagnostics, Some(&networks));
        (uid, image, cases, acquired, context_calls, slot_calls)
    }));
    // Freeze the original work context before any cleanup call can change it.
    let work_failure = result
        .as_ref()
        .err()
        .and_then(|_| diagnostics.failure(&run));
    if let Some(observation) = &run.nofile_command_observation {
        observation.reset();
    }
    let work_elapsed = started.elapsed();
    let before_calls = run.calls.get();
    let before_bytes = run.bytes.get();
    let cleanup_started = Instant::now();
    let _ = writeln!(std::io::stderr(), "DOCKERLENS_NATIVE_CHECK: nofile_cleanup");
    // Bounded immutable ledger snapshots avoid borrowing the mutable runner in
    // the guard. Only the guarded callback can enter shared lifecycle cleanup.
    let attempted = run.attempted.clone();
    let ids = run.ids.clone();
    let entered = Cell::new(false);
    let first_unverified = Cell::new(None);
    let container_cleanup_calls = Cell::new(0);
    let container_cleanup_bytes = Cell::new(0);
    let cleanup_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !networks.bound(&run) {
            return CleanupDisposition::OuterTeardownRequired;
        }
        nofile_cleanup_with(&attempted, &ids, || {
            entered.set(true);
            let (disposition, phase) = cleanup_with_phase(&mut run);
            container_cleanup_calls.set(run.calls.get() - before_calls);
            container_cleanup_bytes.set(run.bytes.get() - before_bytes);
            first_unverified.set(phase);
            if networks.cleanup(&run, disposition == CleanupDisposition::VerifiedAbsent) {
                disposition
            } else {
                CleanupDisposition::OuterTeardownRequired
            }
        })
    }));
    let cleanup_refusal = match &cleanup_result {
        Err(_) => Some(NofileCleanupRefusal::Panic),
        Ok(CleanupDisposition::OuterTeardownRequired) if !entered.get() => {
            Some(NofileCleanupRefusal::OwnershipGuard)
        }
        Ok(CleanupDisposition::OuterTeardownRequired) => Some(
            NofileCleanupRefusal::InnerUnverified(first_unverified.get()),
        ),
        Ok(CleanupDisposition::VerifiedAbsent) => None,
    };
    let disposition = cleanup_result.unwrap_or(CleanupDisposition::OuterTeardownRequired);
    let cleanup_elapsed = cleanup_started.elapsed();
    let cleanup_calls = run.calls.get() - before_calls;
    let cleanup_bytes = run.bytes.get() - before_bytes;
    terminal_cleanup(&mut run, &owner, disposition);
    if let Some(line) = work_failure {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
    if let Some(refusal) = cleanup_refusal {
        let observation = run.nofile_command_observation.as_ref();
        let status = observation.and_then(|observation| observation.first_failure.get());
        let mut line = refusal.diagnostic(status);
        if refusal == NofileCleanupRefusal::InnerUnverified(Some(CleanupPhase::LookupName))
            && let Some(failure) =
                observation.and_then(|observation| observation.first_lookup_failure.get())
        {
            line.push_str(" lookup_failure=");
            line.push_str(failure.name());
        }
        let _ = writeln!(std::io::stderr(), "{line}");
    }
    let (uid, image, cases, acquired, context_calls, slot_calls) =
        require_verified_result(result, disposition);
    assert!(
        !run.image_attempted && run.derived_id.is_none() && image_snapshot(&run) == image,
        "borrowed image unchanged, never owned"
    );
    let outer = outer_context(&run);
    assert!(outer == owner.snapshot, "unchanged authenticated outer");
    let ordinary_calls = run.calls.get() - cleanup_calls;
    let ordinary_bytes = run.bytes.get() - cleanup_bytes;
    let ordinary_elapsed = started.elapsed().saturating_sub(cleanup_elapsed);
    let final_readback_calls = 2 + outer_backend.snapshot_extra_calls();
    let network_setup_calls: usize = networks.owned.iter().map(|n| n.setup_calls).sum();
    let network_setup_bytes: usize = networks.owned.iter().map(|n| n.setup_bytes).sum();
    let network_cleanup_calls: usize = networks.owned.iter().map(|n| n.cleanup_calls).sum();
    let network_cleanup_bytes: usize = networks.owned.iter().map(|n| n.cleanup_bytes).sum();
    assert!(
        ordinary_calls
            == context_calls
                + network_setup_calls
                + slot_calls.iter().sum::<usize>()
                + 1
                + REQUESTS
                + final_readback_calls
            && ordinary_bytes > BODIES + 2 * outer_backend.snapshot_extra_bytes()
            && ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES
            && network_setup_calls == 6
            && network_setup_bytes > 0
            && ordinary_calls <= MAX_CALLS - CLEANUP_CALLS
            && container_cleanup_calls.get() == 8 * 9
            && network_cleanup_calls == 12
            && cleanup_calls == container_cleanup_calls.get() + network_cleanup_calls
            && cleanup_calls <= CLEANUP_CALLS
            && cleanup_bytes == container_cleanup_bytes.get() + network_cleanup_bytes
            && cleanup_bytes <= CLEANUP_BYTES,
        "derived closed nofile total accounting"
    );
    assert!(
        work_elapsed <= Duration::from_secs(134)
            && ordinary_elapsed <= Duration::from_secs(134)
            && cleanup_elapsed <= Duration::from_secs(46)
            && started.elapsed() <= Duration::from_secs(180),
        "original nofile absolute deadline and cleanup reserve"
    );
    let topology = networks.topology(&run, &acquired);
    let proof = json!({"schema_version":2,"contract":CONTRACT,"capability_admission":[],"catalogue_admission":false,"scope":"four_diagonal_nofile_cases_source_only","context":{"candidate_sha":run.candidate,"run_id":run.run,"lane":run.lane,"engine_release":run.engine,"rendering_api":run.api,"acquisition_api":if run.lane.starts_with("debian11-"){ "1.41" }else{"1.49"},"mode":if run.mode==DaemonMode::Rootless{"rootless"}else{"rootful"},"docker_package":if run.lane.starts_with("debian11-"){"20.10.5+dfsg1-1+deb11u2"}else{""},"fixture_image":run.base,"daemon_uid":uid,"outer":outer},
        "borrowed_image":{"id":image["id"],"identity":"unchanged","removal":"not_owned"},"cases":cases,"network_topology":topology,"acquisition":acquired,"daemon_health":"version_matches_after_all_cases","accounting":{"network_setup_calls":network_setup_calls,"network_setup_bytes":network_setup_bytes,"container_cleanup_calls":container_cleanup_calls.get(),"container_cleanup_bytes":container_cleanup_bytes.get(),"network_cleanup_calls":network_cleanup_calls,"network_cleanup_bytes":network_cleanup_bytes,"context_calls":context_calls,"slot_calls":slot_calls,"daemon_health_calls":1,"acquisition_reserved_calls":REQUESTS,"final_readback_calls":final_readback_calls,"ordinary_calls":ordinary_calls,"ordinary_bytes":ordinary_bytes,"cleanup_calls":cleanup_calls,"cleanup_bytes":cleanup_bytes,"deadline_seconds":180,"cleanup_reserve_seconds":46,"ordinary_elapsed_ns":ordinary_elapsed.as_nanos(),"cleanup_elapsed_ns":cleanup_elapsed.as_nanos(),"elapsed_ns":started.elapsed().as_nanos(),"initial_context_acquisition":{"max_requests":16,"max_total_bytes":2097152,"max_elapsed_seconds":15,"accounting":"separate_existing_bound"}},"cleanup":{"containers":"absent","networks":"absent","owned_networks":2,"rounds":2,"outstanding":0,"uncertain":false}});
    let mut metadata = proof.clone();
    for case in metadata["cases"].as_array_mut().unwrap() {
        for item in case["containers"].as_array_mut().unwrap() {
            if item["effect"]["stage"] == "running" {
                let witness = item["effect"]["witness"].as_object_mut().unwrap();
                witness.remove("owned_files");
                witness.remove("descriptors");
            }
        }
    }
    assert!(
        serde_json::to_vec(&metadata).unwrap().len() <= METADATA_MAX_BYTES,
        "bounded nofile metadata independent of inventories"
    );
    eprintln!("DOCKERLENS_NATIVE_CHECK: nofile_proof");
    target.publish_bounded(&proof, NOFILE_PROOF_MAX_BYTES);
}

#[cfg(unix)]
#[test]
fn nofile_observed_termination_clears_current_and_retains_first_cleanup_failure() {
    use std::os::unix::process::ExitStatusExt;
    let observation = NofileCommandObservation::default();
    let failed = std::process::ExitStatus::from_raw(125 << 8);
    observation.observe(failed);
    let frozen_work = NofileTermination::observed(observation.current_failure.get());
    assert_eq!(frozen_work, NofileTermination::Exit(125));
    observation.begin_capture(); // spawn, reserve or overflow may fail before a new status is eligible
    assert_eq!(
        NofileTermination::observed(observation.current_failure.get()),
        NofileTermination::Unknown
    );
    observation.reset(); // independent cleanup scope; a rejected ownership guard enters no capture
    assert!(observation.first_failure.get().is_none());
    let guard = NofileCleanupRefusal::OwnershipGuard.diagnostic(Some(failed));
    assert!(
        guard.ends_with(
            "first_observed_termination=unknown code=none first_unverified_phase=unknown"
        )
    );
    observation.observe(std::process::ExitStatus::from_raw(7 << 8));
    observation.begin_capture();
    observation.observe(std::process::ExitStatus::from_raw(0));
    observation.begin_capture();
    observation.observe(std::process::ExitStatus::from_raw(9));
    assert_eq!(
        NofileTermination::observed(observation.first_failure.get()),
        NofileTermination::Exit(7)
    );
    assert_eq!(
        NofileTermination::observed(observation.current_failure.get()),
        NofileTermination::Signal(9)
    );
    assert_eq!(frozen_work, NofileTermination::Exit(125));
    observation.reset();
    observation.observe(std::process::ExitStatus::from_raw(0));
    assert_eq!(
        NofileTermination::observed(observation.current_failure.get()),
        NofileTermination::Unknown
    );
    assert!(observation.first_failure.get().is_none());
}

// Inert, real Unix HTTP transport: these controls execute the production curl
// path/ledger and public acquisition, never a daemon or a runtime substitute.
struct NofileSocketControl {
    private: PathBuf,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct NofileReply {
    method: &'static str,
    path: String,
    request: Option<Value>,
    status: u16,
    body: String,
}

impl NofileSocketControl {
    fn start(replies: Vec<NofileReply>) -> (Self, HealthRun) {
        use std::io::{BufRead, BufReader};
        use std::os::unix::{fs::DirBuilderExt, net::UnixListener};
        let private =
            std::env::temp_dir().join(format!("dl-nfb-{}-{}", std::process::id(), utc_ns()));
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        let socket = private.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            for reply in replies {
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(value) => break value,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        Err(_) => panic!("inert bridge control did not receive expected request"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(
                    line == format!("{} {} HTTP/1.1\r\n", reply.method, reply.path),
                    "exact inert bridge request path"
                );
                let mut length = 0;
                for _ in 0..32 {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(raw) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = raw.trim().parse::<usize>().unwrap();
                    }
                }
                assert!(
                    line == "\r\n" && length <= 4096,
                    "bounded inert bridge request headers"
                );
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                match reply.request {
                    Some(expected) => assert!(
                        serde_json::from_slice::<Value>(&body).ok().as_ref() == Some(&expected),
                        "independent complete bridge create body"
                    ),
                    None => assert!(body.is_empty(), "read/delete has no request body"),
                }
                let response = format!(
                    "HTTP/1.1 {} Control\r\nContent-Length: {}\r\n\r\n{}",
                    reply.status,
                    reply.body.len(),
                    reply.body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let mut run = offline_run(socket.to_str().unwrap().into());
        run.run = "Ab12Cd34".into();
        run.lane = "upstream-rootful".into();
        run.engine = "29.8.1".into();
        run.api = "1.56".into();
        run.candidate = "d".repeat(40);
        run.outer = "dl-native-Ab12Cd34".into();
        run.deadline = Instant::now() + Duration::from_secs(180);
        run.names = (0..8).map(|i| format!("inert-slot-{i}")).collect();
        run.ids = (1..=8).map(|i| Some(format!("{i:064x}"))).collect();
        run.attempted = vec![true; 8];
        (
            Self {
                private,
                thread: Some(thread),
            },
            run,
        )
    }

    fn finish(mut self) {
        let result = self.thread.take().unwrap().join();
        fs::remove_dir_all(&self.private).unwrap();
        assert!(result.is_ok(), "inert nofile socket script completed");
    }
}

fn bridge_control_reply(
    method: &'static str,
    key: &str,
    request: Option<Value>,
    status: u16,
    body: Value,
) -> NofileReply {
    NofileReply {
        method,
        path: format!("/v1.56/networks/{key}"),
        request,
        status,
        body: if status == 204 {
            String::new()
        } else {
            body.to_string()
        },
    }
}

fn bridge_control_identity(index: usize) -> Value {
    json!({"Id":if index==0 {"b".repeat(64)}else{"c".repeat(64)},
        "Name":format!("dl-nf-Ab12Cd34-net-{}",CASES[index+2].0),"Driver":"bridge", "Labels":{OWNER:"Ab12Cd34"}})
}

fn control_networks(run: &HealthRun) -> NofileNetworks {
    let owner = BoundOuterCleanupOwner {
        snapshot: json!({"id":"d".repeat(64),"name":run.outer,"owner":run.run}),
    };
    NofileNetworks::new(run, &owner)
}

fn bridge_control_setup() -> Vec<NofileReply> {
    let mut replies = Vec::new();
    for index in 0..2 {
        let identity = bridge_control_identity(index);
        replies.push(bridge_control_reply(
            "GET",
            identity["Name"].as_str().unwrap(),
            None,
            404,
            json!({}),
        ));
        replies.push(bridge_control_reply(
            "POST",
            "create",
            Some(json!({"Name":identity["Name"],"Driver":"bridge","Labels":{OWNER:"Ab12Cd34"}})),
            201,
            json!({"Id":identity["Id"],"Warning":""}),
        ));
        replies.push(bridge_control_reply(
            "GET",
            identity["Id"].as_str().unwrap(),
            None,
            200,
            identity.clone(),
        ));
    }
    replies
}

fn bridge_control_cleanup(fault: Option<&str>) -> Vec<NofileReply> {
    let mut replies = Vec::new();
    for index in 0..2 {
        let mut identity = bridge_control_identity(index);
        if index == 0 && fault == Some("owner") {
            identity["Labels"][OWNER] = json!("foreign-private-canary");
        }
        replies.push(bridge_control_reply(
            "GET",
            identity["Id"].as_str().unwrap(),
            None,
            200,
            identity.clone(),
        ));
        if index == 0 && fault == Some("owner") {
            continue;
        }
        replies.push(bridge_control_reply(
            "DELETE",
            identity["Id"].as_str().unwrap(),
            None,
            if index == 0 && fault == Some("delete") {
                500
            } else {
                204
            },
            json!({}),
        ));
    }
    for _ in 0..2 {
        for index in 0..2 {
            if index == 0 && fault.is_some() {
                continue;
            }
            let identity = bridge_control_identity(index);
            for key in ["Id", "Name"] {
                replies.push(bridge_control_reply(
                    "GET",
                    identity[key].as_str().unwrap(),
                    None,
                    404,
                    json!({}),
                ));
            }
        }
    }
    replies
}

#[test]
fn nofile_owned_bridges_use_real_bounded_transport_and_measured_cleanup() {
    for fault in [None, Some("owner"), Some("delete")] {
        let mut replies = bridge_control_setup();
        replies.extend(bridge_control_cleanup(fault));
        let expected_bytes: usize = replies.iter().map(|reply| reply.body.len() + 4).sum();
        let expected_calls = replies.len();
        let (server, run) = NofileSocketControl::start(replies);
        let mut networks = control_networks(&run);
        for i in 0..2 {
            networks.create(&run, i);
        }
        assert!(
            networks.bound(&run) && run.calls.get() == 6,
            "both bridges really bound in six calls"
        );
        let before = run.calls.get();
        assert!(
            !networks.cleanup(&run, false) && run.calls.get() == before,
            "no network cleanup before verified container absence"
        );
        let primary = std::panic::catch_unwind(|| panic!("original nofile work failure"));
        let verified = networks.cleanup(&run, true);
        assert!(
            verified == fault.is_none()
                && run.calls.get() == expected_calls
                && run.bytes.get() == expected_bytes,
            "actual transport status/call/byte cleanup receipts"
        );
        assert!(
            !networks.cleanup(&run, true) && run.calls.get() == expected_calls,
            "one network cleanup attempt, no mutation retry"
        );
        let retained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            require_verified_result::<()>(primary, cleanup_disposition(verified));
        }))
        .unwrap_err();
        assert!(
            retained.downcast_ref::<&str>() == Some(&"original nofile work failure"),
            "cleanup does not replace primary failure"
        );
        if verified {
            assert!(
                networks
                    .owned
                    .iter()
                    .all(|n| n.setup_calls == 3 && n.cleanup_calls == 6 && n.deleted),
                "two complete real ID/name absence rounds"
            );
        } else {
            assert!(
                !networks.owned[0].deleted && networks.owned[1].deleted,
                "foreign/uncertain deletion is not adopted"
            );
        }
        println!(
            "nofile bridge transport fault={} calls={} bytes={} cleanup_calls={} verified={verified}",
            fault.unwrap_or("none"),
            run.calls.get(),
            run.bytes.get(),
            run.calls.get() - 6
        );
        server.finish();
    }
}

#[test]
fn nofile_bridge_uncertain_create_and_crossed_scope_never_adopt_or_remove() {
    for fault in ["create", "id", "outer", "owner", "partial"] {
        let mut replies = bridge_control_setup();
        let index = if fault == "partial" { 4 } else { 1 };
        match fault {
            "create" | "partial" => {
                replies[index].status = 500;
                replies[index].body = "{}".into();
                replies.truncate(index + 1);
            }
            "id" => {
                replies[index].body = json!({"Id":"malformed-private-id"}).to_string();
                replies.truncate(index + 1);
            }
            "outer" => {
                replies[index].body = json!({"Id":"d".repeat(64)}).to_string();
                replies.truncate(index + 1);
            }
            _ => {
                replies[2].body=json!({"Id":"b".repeat(64),"Name":"private-crossed-name","Driver":"bridge","Labels":{OWNER:"foreign"}}).to_string();
                replies.truncate(3);
            }
        }
        let expected_calls = replies.len();
        let (server, run) = NofileSocketControl::start(replies);
        let mut networks = control_networks(&run);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            networks.create(&run, 0);
            networks.create(&run, 1);
        }));
        assert!(
            result.is_err() && !networks.bound(&run),
            "uncertain or foreign network create remains unbound"
        );
        assert!(
            !networks.cleanup(&run, true) && run.calls.get() == expected_calls,
            "unknown network ID forbids every cleanup request"
        );
        println!(
            "nofile bridge create fault={fault} calls={} cleanup_calls=0",
            run.calls.get()
        );
        server.finish();
    }
    let (server, mut run) = NofileSocketControl::start(bridge_control_setup());
    let mut networks = control_networks(&run);
    for i in 0..2 {
        networks.create(&run, i);
    }
    let original_id = run.ids[0].clone();
    run.ids[0] = Some("b".repeat(64));
    assert!(
        !networks.bound(&run) && !networks.cleanup(&run, true) && run.calls.get() == 6,
        "late selected container/network collision refuses cleanup without requests"
    );
    run.ids[0] = original_id;
    let admission = networks.request(&run, 0, NetworkAction::InspectId, false);
    assert!(
        !admission.matches(&run, true),
        "work token cannot become cleanup admission"
    );
    run.socket.push_str("-crossed");
    assert!(
        !admission.matches(&run, false)
            && !networks.bound(&run)
            && !networks.cleanup(&run, true)
            && run.calls.get() == 6,
        "crossed custody scope performs no I/O"
    );
    server.finish();
}

fn case_capture_control(
    endpoint_state: &str,
    membership_state: &str,
    fault: Option<&str>,
) -> Vec<NofileReply> {
    case_capture_control_with_maps(endpoint_state, membership_state, fault, None)
}

fn case_capture_control_with_maps(
    endpoint_state: &str,
    membership_state: &str,
    fault: Option<&str>,
    maps: Option<(&str, &[usize])>,
) -> Vec<NofileReply> {
    let mut replies = Vec::new();
    let mut reply = |path: String, body: Value| {
        replies.push(NofileReply {
            method: "GET",
            path,
            request: None,
            status: 200,
            body: body.to_string(),
        })
    };
    reply(
        "/version".into(),
        json!({"Version":"29.8.1","ApiVersion":"1.56","MinAPIVersion":"1.44"}),
    );
    reply("/v1.49/info".into(), json!({"ServerVersion":"29.8.1"}));
    let id = |group: usize| {
        if group == 0 && fault == Some("default_outer") {
            "d".repeat(64)
        } else if group == 0 && fault == Some("default_root") {
            format!("{:064x}", 1)
        } else {
            ["a", "b", "c"][group].repeat(64)
        }
    };
    let name = |group: usize| {
        if group == 0 {
            "bridge".to_owned()
        } else {
            format!("dl-nf-Ab12Cd34-net-{}", CASES[group + 1].0)
        }
    };
    let mut referenced = [false; 3];
    for index in 0..8 {
        let group = if index < 4 { 0 } else { index / 2 - 1 };
        let mut endpoint = json!({"NetworkID":id(group)});
        if group > 0 {
            match endpoint_state {
                "missing" => {
                    endpoint.as_object_mut().unwrap().remove("NetworkID");
                }
                "null" => endpoint["NetworkID"] = Value::Null,
                "empty" => endpoint["NetworkID"] = json!(""),
                "redacted" => endpoint["NetworkID"] = json!({"__docker_lens_redacted__":true}),
                "malformed" => endpoint["NetworkID"] = json!(17),
                _ => {}
            }
        }
        let network_name = if index == 4 && fault == Some("route") {
            name(2)
        } else {
            name(group)
        };
        let (_, soft, hard) = CASES[index / 2];
        let mut body = json!({"Id":format!("{:064x}",index+1),"HostConfig":{"NetworkMode":if group==0{"default".into()}else{name(group)},"Ulimits":[{"Name":"nofile","Soft":soft,"Hard":hard}]},
                "NetworkSettings":{"Networks":{(network_name):endpoint}},"Mounts":[]});
        let running = index < 4 || endpoint_state == "present";
        body["State"] = json!({"Status":if running{"running"}else{"created"},"Running":running,
            "Pid":if running{100+index}else{0},"StartedAt":if running{"2026-11-23T00:00:00Z"}else{"0001-01-01T00:00:00Z"}});
        if index == 4 && fault == Some("mode") {
            body["HostConfig"]["NetworkMode"] = json!("none");
        }
        if let Some((state, _)) = maps.filter(|(_, slots)| slots.contains(&index)) {
            match state {
                "missing" => {
                    body["NetworkSettings"]
                        .as_object_mut()
                        .unwrap()
                        .remove("Networks");
                }
                "null" => body["NetworkSettings"]["Networks"] = Value::Null,
                "empty" => body["NetworkSettings"]["Networks"] = json!({}),
                _ => panic!("closed map availability control"),
            }
        } else {
            referenced[group] = true;
        }
        reply(format!("/v1.49/containers/{:064x}/json", index + 1), body);
    }
    let mut network_replies = Vec::new();
    for (group, &has_reference) in referenced.iter().enumerate() {
        if !has_reference {
            continue;
        }
        let mut body = json!({"Id":id(group),"Name":name(group),"Driver":"bridge"});
        if group > 0 {
            body["Labels"] = json!({OWNER:"Ab12Cd34"});
        }
        match membership_state {
            "missing" => {}
            "null" => body["Containers"] = Value::Null,
            "redacted" => body["Containers"] = json!({"__docker_lens_redacted__":true}),
            "empty" => body["Containers"] = json!({}),
            _ => {
                let indices: Vec<usize> = match group {
                    0 => (0..4).collect(),
                    1 => vec![4, 5],
                    _ => vec![6, 7],
                };
                let mut members = serde_json::Map::new();
                for i in indices {
                    members.insert(
                        format!("{:064x}", i + 1),
                        json!({"Name":format!("inert-slot-{i}")}),
                    );
                }
                if group == 0 || fault == Some("foreign") {
                    members.insert("f".repeat(64), json!({"Name":"private-unselected-canary"}));
                }
                if group == 0 && fault == Some("audience") {
                    members.insert(format!("{:064x}", 5), json!({"Name":"private-wrong-case"}));
                }
                body["Containers"] = Value::Object(members);
            }
        }
        if group == 1 && fault == Some("owner") {
            body["Labels"][OWNER] = json!("foreign-private-canary");
        }
        if group == 1 && fault == Some("identity") {
            body["Id"] = json!("e".repeat(64));
        }
        let key = if group == 0 || endpoint_state == "present" {
            id(group)
        } else {
            name(group)
        };
        network_replies.push((key, body));
    }
    network_replies.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, body) in network_replies {
        reply(format!("/v1.49/networks/{key}"), body);
    }
    replies
}

fn bound_case_control_networks(run: &HealthRun) -> NofileNetworks {
    let mut networks = control_networks(run);
    for index in 0..2 {
        networks.owned[index].attempted = true;
        networks.owned[index].authenticated = true;
        networks.owned[index].id = Some(if index == 0 {
            "b".repeat(64)
        } else {
            "c".repeat(64)
        });
    }
    networks
}

#[test]
fn nofile_case_capture_keeps_actual_identity_availability_audience_and_limits() {
    for endpoint in ["present", "missing", "null", "empty", "redacted"] {
        for membership in ["missing", "null", "empty", "present", "redacted"] {
            let replies = case_capture_control(endpoint, membership, None);
            let bodies: usize = replies.iter().map(|reply| reply.body.len()).sum();
            let (server, run) = NofileSocketControl::start(replies);
            let networks = bound_case_control_networks(&run);
            let diagnostics = NofileDiagnostics::default();
            let proof = acquisition(
                &run,
                SourceOuterBackend::Podman,
                &diagnostics,
                Some(&networks),
            );
            assert!(
                proof["actual_expansions"] == 11
                    && proof["actual_requests"] == 13
                    && proof["actual_response_bytes"] == bodies
                    && proof["actual_elapsed_ns"]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= 10_000_000_000),
                "real eleven-expansion thirteen-GET measured capture"
            );
            assert!(
                run.calls.get() == 20 && run.bytes.get() == 524288,
                "unchanged conservative acquisition reservation"
            );
            for index in 4..8 {
                assert!(
                    proof["container_networks"][index]["network_id_availability"] == endpoint,
                    "actual endpoint availability retained"
                );
            }
            for group in 0..3 {
                let network = &proof["networks"][group];
                assert!(
                    network["active_membership_availability"] == membership,
                    "optional membership availability retained"
                );
                if matches!(membership, "missing" | "null" | "redacted") {
                    assert!(
                        network["active_unselected_count"].is_null()
                            && network["active_selected_ids"] == json!([]),
                        "unavailable membership is not empty"
                    );
                } else {
                    let expected = usize::from(group == 0 && membership == "present");
                    assert!(
                        network["active_unselected_count"] == expected,
                        "observed unselected count without identities"
                    );
                }
            }
            println!(
                "nofile case capture endpoint={endpoint} membership={membership} requests=13 expansions=11 response_bytes={bodies}"
            );
            server.finish();
        }
    }
}

#[test]
fn nofile_case_capture_refuses_crossed_identity_route_and_observed_foreign_members() {
    for fault in [
        "identity",
        "owner",
        "route",
        "mode",
        "default_outer",
        "default_root",
        "audience",
        "foreign",
        "malformed",
    ] {
        let endpoint = if fault == "malformed" {
            "malformed"
        } else {
            "empty"
        };
        let replies = case_capture_control(endpoint, "present", Some(fault));
        let (server, run) = NofileSocketControl::start(replies);
        let networks = bound_case_control_networks(&run);
        let diagnostics = NofileDiagnostics::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            acquisition(
                &run,
                SourceOuterBackend::Docker,
                &diagnostics,
                Some(&networks),
            )
        }));
        assert!(
            result.is_err() && run.calls.get() == 20 && run.bytes.get() == 524288,
            "contradictory captured evidence cannot produce successful nofile proof"
        );
        println!("nofile case capture fault={fault} refused=true");
        server.finish();
    }
}

#[test]
fn nofile_case_capture_never_invents_a_peer_endpoint_or_unrequested_network() {
    for state in ["missing", "null", "empty"] {
        for slots in [
            &[5][..],
            &[4, 5][..],
            &[0, 1, 2, 3][..],
            &[0, 1, 2, 3, 4, 5, 6, 7][..],
        ] {
            let captured =
                case_capture_control_with_maps("empty", "present", None, Some((state, slots)));
            let requests = captured.len();
            let bytes: usize = captured.iter().map(|r| r.body.len()).sum();
            let mut replies = bridge_control_setup();
            replies.extend(captured);
            replies.extend(bridge_control_cleanup(None));
            let (server, run) = NofileSocketControl::start(replies);
            let mut networks = control_networks(&run);
            for i in 0..2 {
                networks.create(&run, i);
            }
            let proof = acquisition(
                &run,
                SourceOuterBackend::Podman,
                &NofileDiagnostics::default(),
                Some(&networks),
            );
            let n = proof["networks"].as_array().unwrap().len();
            assert!(
                proof["actual_requests"] == requests
                    && requests == 10 + n
                    && proof["actual_expansions"] == 8 + n
                    && proof["actual_response_bytes"] == bytes,
                "actual counts derive only from supporting observed endpoint references"
            );
            for &i in slots {
                let row = &proof["container_networks"][i];
                assert!(
                    row["endpoint_map_availability"] == state
                        && row["name"].is_null()
                        && row["network_id"].is_null()
                        && row["network_id_availability"].is_null()
                        && row["lookup"].is_null(),
                    "whole-map absence never borrows a peer exchange"
                );
            }
            assert!(
                networks.cleanup(&run, true),
                "real owned bridge cleanup after capture controls"
            );
            let topology = networks.topology(&run, &proof);
            assert!(
                topology["default"]["id"]
                    == if slots.contains(&0) {
                        Value::Null
                    } else {
                        json!("a".repeat(64))
                    },
                "unobserved configured default never inherits an owned network identity"
            );
            println!(
                "nofile absent map state={state} absent_slots={} actual_requests={requests} expansions={} response_bytes={bytes}",
                slots.len(),
                8 + n
            );
            server.finish();
        }
    }
}

#[test]
fn nofile_bridge_transport_refuses_exhausted_original_calls_bytes_and_clock_before_io() {
    for control in [
        "work_calls",
        "work_bytes",
        "work_clock",
        "cleanup_calls",
        "cleanup_bytes",
        "cleanup_clock",
    ] {
        let (server, mut run) = NofileSocketControl::start(vec![]);
        let cleanup = control.starts_with("cleanup");
        let mut networks = if cleanup {
            bound_case_control_networks(&run)
        } else {
            control_networks(&run)
        };
        match control {
            "work_calls" => run.calls.set(300),
            "work_bytes" => run.bytes.set(2 * 1024 * 1024),
            "work_clock" => run.deadline = Instant::now() + Duration::from_secs(46),
            "cleanup_calls" => run.calls.set(400),
            "cleanup_bytes" => run.bytes.set(4 * 1024 * 1024),
            _ => run.deadline = Instant::now() + Duration::from_secs(1),
        }
        let before = (run.calls.get(), run.bytes.get());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if cleanup {
                assert!(
                    !networks.cleanup(&run, true),
                    "exhausted cleanup cannot verify absence"
                );
            } else {
                networks.create(&run, 0);
            }
        }));
        assert!(
            (cleanup || result.is_err()) && before == (run.calls.get(), run.bytes.get()),
            "original bounds refuse before network I/O"
        );
        server.finish();
    }
}

#[test]
fn nofile_case_bridges_keep_debian_acquisition_and_rendering_api_boundaries() {
    let mut captured =
        case_capture_control_with_maps("empty", "null", None, Some(("empty", &[4, 5])));
    let requests = captured.len();
    for reply in &mut captured {
        reply.path = reply.path.replace("/v1.49/", "/v1.41/");
        if reply.path == "/version" {
            reply.body =
                json!({"Version":"20.10.5+dfsg1","ApiVersion":"1.41","MinAPIVersion":"1.12"})
                    .to_string();
        } else if reply.path == "/v1.41/info" {
            reply.body = json!({"ServerVersion":"20.10.5+dfsg1"}).to_string();
        }
    }
    let bytes: usize = captured.iter().map(|r| r.body.len()).sum();
    let mut replies = bridge_control_setup();
    replies.extend(captured);
    replies.extend(bridge_control_cleanup(None));
    for reply in &mut replies {
        reply.path = reply.path.replace("/v1.56/", "/v1.41/");
    }
    let (server, mut run) = NofileSocketControl::start(replies);
    run.api = "1.41".into();
    run.engine = "20.10.5+dfsg1".into();
    run.lane = "debian11-rootful".into();
    let mut networks = control_networks(&run);
    for i in 0..2 {
        networks.create(&run, i);
    }
    let acquired = acquisition(
        &run,
        SourceOuterBackend::Docker,
        &NofileDiagnostics::default(),
        Some(&networks),
    );
    assert!(
        acquired["requested_api"] == "1.41"
            && acquired["actual_requests"] == requests
            && acquired["actual_response_bytes"] == bytes
            && acquired["actual_expansions"] == 10,
        "real 1.41 capture with an unreferenced configured case bridge"
    );
    assert!(
        networks.cleanup(&run, true) && run.calls.get() == 38,
        "same measured network setup/reservation/cleanup costs"
    );
    println!(
        "nofile Debian API1.41 requests={requests} expansions=10 response_bytes={bytes} setup_calls=6 network_cleanup_calls=12"
    );
    server.finish();
}
