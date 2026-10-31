"""Independent synthetic PIDs expectations, never native acceptance."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_pids_proof as reader

NONCE = "0123456789abcdef0123456789abcdef"


def case_fixture(slot):
    leaf_inode = {"cli16": 6001, "cli64": 6002, "cli_unlimited": 6003,
                  "rendered16": 6004, "rendered64": 6005, "rendered_unlimited": 6006}[slot]
    finite = slot.endswith("16")
    maximum = 16 if finite else (64 if slot.endswith("64") else "max")
    count = 15 if finite else 32
    events = [{"schema": "dockerlens-pids-worker-v1", "case": slot, "nonce": NONCE, "phase": "identity", "pid": 1,
               "threads": 1, "rlimit_nproc_soft": 32768, "rlimit_nproc_hard": 32768, "kernel_sysname": "Linux",
               "kernel_release": "6.17.0-independent", "kernel_version": "#1 fixture", "kernel_machine": "x86_64"}]
    for index, phase in enumerate(("baseline", "attempt", "hold-failure" if finite else "hold-control", "release", "reuse", "finished")):
        children = list(range(2, count + 2)) if index in (1, 2) else []
        events.append({"schema": "dockerlens-pids-worker-v1", "case": slot, "nonce": NONCE, "phase": phase, "pid": 1,
                       "threads": 1, "children": children, "child_count": len(children),
                       "fork_return": -1 if index == 2 and finite else (99 if index == 4 else None),
                       "errno": 11 if index == 2 and finite else (0 if index == 4 else None), "eagain": 11})
    samples = []
    for phase in range(4):
        members = list(range(1, count + 2)) if phase in (1, 2) else [1]
        event = int(finite and phase >= 2)
        controllers = []
        for index in range(3):
            current = len(members) if index == 0 else len(members) + 100
            local = event if index == 0 else 0
            controllers.append({"identity": [28, leaf_inode if index == 0 else 5001 + index, 77], "cgroup_type": "domain",
                                "maximum": maximum if index == 0 else (512 if index == 1 else "max"),
                "current": current, "events_max": event, "events_local_max": local, "current_samples": [current, current],
                "events_samples": [event, event], "events_local_samples": [local, local]})
        samples.append({"maximum": maximum, "current": len(members), "events_max": event, "cgroup_type": "domain",
            "tasks": [[45000 + pid, 9000000 + pid] for pid in members],
            "task_namespace_ids": [[45000 + pid, [45000 + pid, 1000 + pid, pid], [45000 + pid, 1000 + pid, pid]] for pid in members],
            "attribution": {"event_semantics": "hierarchical_with_local_enforcer", "pids_localevents": False, "complete_chain": True,
                "candidate_membership": "typed_procs_local_membership_v1",
                "outer_index": 1, "reader_cgroup_namespace": [5, 4026531835],
                "hierarchy_root": {"identity": [28, 2, 77], "pids_max_present": False, "cgroup_type_present": False,
                    "cgroup_events_present": False, "available_pids": True, "mount_root_is_slash": True, "qualification": "root_exempt"},
                "controllers": controllers},
            "globals": {"threads_max": 100000, "pid_max": 4194304, "total_tasks": 700, "total_tasks_samples": [700, 700], "sched_policy": 0,
                "nproc_soft": 32768, "nproc_hard": 32768, "kernel_release": "6.17.0-independent", "kernel_version": "#1 fixture", "kernel_machine": "x86_64"}})
    return {"slot": slot, "worker_events": events, "source_samples": samples, "controlled_limit": maximum,
            "effect": "enforced_with_controls_unadmitted", "definition": {}}


def artifact_fixture(candidate):
    def tool(name, **extra):
        return {"path": "/usr/lib/" + name, "size": 16, "sha256": "a" * 64,
            "identity": {"device": 1, "inode": 100, "uid": 0, "gid": 0, "mode": 0o100755, "links": 1, "mtime_ns": 1, "ctime_ns": 1},
            "package": {"status": "unavailable", "reason": "os-bootstrap-not-queried", "unverified_path_hint": None},
            "file_kind": "elf", **extra}
    return {"schema": "dockerlens-pids-worker-build-v1", "candidate": candidate, "toolchain": "1.98.1",
        "compiler": {"release": "1.98.1", "host": "x86_64-unknown-linux-gnu", "commit_hash": "a" * 40, "commit_date": "2026-10-01", "llvm_version": "23.1.0"},
        "target": "x86_64-unknown-linux-gnu", "flags": "-C target-feature=+crt-static -C panic=abort -C strip=symbols -C linker-flavor=gcc -C linker-features=-lld",
        "profile": {"name": "release", "opt-level": "z", "lto": "fat", "codegen-units": 1}, "binary": "native-pids-worker", "size": 65537, "sha256": "b" * 64,
        "elf": {"class": 64, "endianness": "little", "machine": 62, "pt_interp": False, "dt_needed": False},
        "source_sha256": "c" * 64, "controller_source_sha256": "d" * 64, "cargo_lock_sha256": "e" * 64, "cargo_manifest_sha256": "f" * 64,
        "build_log_sha256": "1" * 64, "build_log_size": 100, "original_deadline_ns": 12345678,
        "build_tools": {"schema": "dockerlens-pids-build-tools-v1", "policy": "native-gcc-bfd-v1",
            "driver": tool("gcc", version="GCC 16", native_target="x86_64-suse-linux"), "linker": tool("ld", version="GNU ld 2.47"),
            "wrappers": {"driver_sha256": "a" * 64, "linker_sha256": "b" * 64},
            "invocation": {"count": 1, "size": 100, "sha256": "c" * 64, "output_size": 65537, "output_sha256": "b" * 64},
            "dependencies": {"size": 100, "sha256": "d" * 64},
            "crt": [tool(role, role=role, file_kind="archive" if role == "libc" else "elf") for role in ("start", "init", "fini", "begin", "end", "libc")],
            "hashed_input_bytes": 256, "scope": "installed-tools-and-consumed-crt-only-v1", "implementation_closure": "unresolved"}}


def typed_chain(case, kinds, outer_index=1):
    """Author a complete leaf-to-root chain without a production topology helper."""
    leaf_inode = case["source_samples"][0]["attribution"]["controllers"][0]["identity"][1]
    for sample in case["source_samples"]:
        attr = sample["attribution"]
        leaf, outer, ancestor = attr["controllers"][:3]
        rows = []
        for index, kind in enumerate(kinds):
            row = deepcopy(leaf if index == 0 else outer if index == outer_index else ancestor)
            row["cgroup_type"] = kind
            if index:
                row["identity"] = [28, 5002 if index == outer_index else
                                   5003 if index > outer_index else 10000 + leaf_inode + index, 77]
                row["maximum"] = 512 if index == outer_index else "max"
            rows.append(row)
        attr["controllers"] = rows
        attr["outer_index"] = outer_index
        sample["cgroup_type"] = kinds[0]


def fixture(lane="upstream-rootful", backend="podman", *, expected_context=None):
    context = {"candidate_sha": "a" * 40, "run_id": "Ab12Cd34", "lane": lane, "engine_release": "20.10.5" if lane.startswith("debian11") else "29.0.0",
        "api_version": "1.41" if lane.startswith("debian11") else "1.56", "mode": "rootless" if lane.endswith("rootless") else "rootful",
        "outer_backend": backend, "outer_id": "f" * 64, "fixture_image": "docker.io/library/busybox:fixture@sha256:" + "b" * 64}
    context["outer"] = {"id": context["outer_id"], "name": "dl-native-Ab12Cd34", "owner": "Ab12Cd34",
        "image": "ghcr.io/strukturpiloten/docker-upstream-rootful:v1.0.0@sha256:" + "a" * 64,
        "data_volume": "dl-native-data-Ab12Cd34", "socket_source": "/private/fixture/socket", "privileged": True,
        "memory_bytes": 4294967296, "cpu_quota": 200000, "cpu_period": 100000, "pids_limit": 512}
    if expected_context is not None:
        context = deepcopy(expected_context)
    run_id = context["run_id"]
    outer = {"context": deepcopy(context["outer"]), "id": context["outer_id"], "pid": 100, "start_ticks": 9000000,
        "runtime_started_at": "2026-10-25T01:00:00Z", "restart_count": 0, "cgroup_namespace_mode": "private"}
    uid = 1000 if context["mode"] == "rootless" else 0
    copied = {"path": f"/tmp/dockerlens-pids-worker-{run_id}/native-pids-worker", "size": 65537, "sha256": "b" * 64,
        "source": {"device": 1, "inode": 100, "uid": 1001, "gid": 1001, "mode": 448, "links": 1},
        "copy": {"device": 2, "inode": 200, "uid": uid, "gid": uid, "mode": 448, "links": 1}, "directory_uid": uid, "directory_mode": 448,
        "io": {"schema": "dockerlens-pids-copy-io-v1", "chunk_bytes": 65536, "reserved_bytes": 196613, "reserved_operations": 8,
               "read_bytes": 131074, "write_bytes": 65537, "read_operations": 6, "write_operations": 2, "eof_probes": 2}}
    cases, decoded = [], {}
    for index, slot in enumerate(reader.SLOTS):
        case = case_fixture(slot)
        maximum = 16 if slot.endswith("16") else (64 if slot.endswith("64") else -1)
        cid, name = f"{index + 1:064x}", f"dl-pids-{run_id}-" + slot
        decoded[cid] = maximum
        document = {"oracle": "independently_authored_cli", "pids_limit": maximum, "entrypoint": "/dl-pids-worker", "fixed_mounts": 2}
        if slot.startswith("rendered"):
            prerequisites = []
            if context["mode"] == "rootless" and maximum > 0:
                prerequisites = [{"kind": "rootless_pids", "reference": "1", "identity": name, "pids_limit": str(maximum),
                    "required_cgroup_driver": "systemd", "required_cgroup_version": "2", "required_pids_report": True, "delegation": "unverified", "enforcement": "unverified"}]
            document = {"schema_version": 4 if prerequisites else 1, "context": {"kind": "observed", "provenance": "process_local_only",
                "engine_release": context["engine_release"], "api_version": context["api_version"], "daemon_mode": context["mode"]}, "prerequisites": prerequisites,
                "requests": [{"method": "POST", "path": f"/v{context['api_version']}/containers/create?name={name}", "body": {
                    "Image": context["fixture_image"], "Entrypoint": ["/dl-pids-worker"], "Cmd": [slot, NONCE, "123456789"],
                    "Labels": {"io.dockerlens.native-run": context["run_id"], "io.dockerlens.native-pids": context["run_id"], "io.dockerlens.native-pids-slot": slot},
                    "HostConfig": {"Init": False, "PidsLimit": maximum, "Mounts": [
                        {"Type": "bind", "Source": copied["path"], "Target": "/dl-pids-worker", "ReadOnly": True},
                        {"Type": "bind", "Source": "/dockerlens-native/pids-control/" + slot, "Target": "/dl-pids-control", "ReadOnly": False}]}}}]}
        case["definition"] = {"slot": slot, "id": cid, "name": name, "pids_limit": maximum, "definition": document}
        cases.append(case)
    external = {"bytes": 200000, "reads": 100}
    return {"schema_version": 2, "contract": "pids-v2", "scope": "controlled_live_leaf_enforcement_only", "capability_admission": [],
        "catalogue_admission": False, "context": context, "nonce": NONCE,
        "outer_before": outer, "outer_after_confirmation": deepcopy(outer), "outer_final": deepcopy(outer), "artifact": artifact_fixture(context["candidate_sha"]),
        "measured": {"daemon": {"release": context["engine_release"], "advertised_api": context["api_version"], "mode": context["mode"],
            "reported_pids": True, "cgroup_driver": "systemd", "cgroup_version": "2", "kernel_identity_source": "held_peer_and_live_worker"},
            "artifact_copy": copied, "decoded": {"route": "explicit_unix_socket", "selected_ids": 6, "reserved_calls": 16, "reserved_body_bytes": 262144,
                "reserved_transport_bytes": 278528, "actual_requests": 8, "actual_body_bytes": 20000,
                "limits": {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8, "max_response_bytes": 32768, "max_total_bytes": 262144, "max_elapsed_seconds": 10},
                "decoded_limits": decoded, "origin": "effective", "scope": "actual_readonly_product_acquisition"}},
        "cases": cases, "root": {"api": {"inspect_calls_reserved": 18, "inspect_body_bytes_reserved": 589824,
                "runtime_probe_calls_reserved": 1, "runtime_probe_body_bytes_reserved": 4096},
            "source": {"external_reserved": external, "root_reserved": {"bytes": 100000, "reads": 10000}, "total_reserved": {"bytes": 300000, "reads": 10100},
                "limits": {"bytes": 33554432, "reads": 65536, "output_bytes": 65536, "live_fd_reservations": 256, "fd_opens": 32768},
                "fds": {"peak_reservations": 200, "open_reservations": 20000, "fixed_overhead_reservations": 16, "source_owned_remaining": 0},
                "output_reserved_before_final": 59000}, "captured_output_bytes": 60000},
        "cleanup": {"containers": "absent", "absence_rounds": 2, "worker_exits": "finished_then_owner_term_zero", "controller": "closed_and_reaped",
            "guest_copy": "removed", "source_handles": "closed_before_final_ack", "outer": "retained_for_lane_finalizer", "outer_teardown_owner": "native_conformance_outer_v1"},
        "budgets": {"parent_calls": 250, "parent_captured_and_reserved_bytes": 1500000, "max_calls": 400, "max_bytes": 4194304,
            "cleanup_calls_reserved": 100, "cleanup_bytes_reserved": 2097152, "terminal_monotonic_ns": 123456789,
            "external_source_reserved": external, "root_output_bytes": 60000, "root_input_bytes": 6000,
            "native_effect_admission": "requires_complete_lane_exit_and_fresh_aggregate"}}


def materialize_artifact(capture, candidate):
    """Write inert synthetic ELF and receipts; never compile or execute them."""
    artifact = capture / "socket/pids-worker"
    artifact.mkdir(parents=True, mode=0o700)
    manifest = artifact_fixture(candidate)
    binary = bytearray(65537)
    struct.pack_into("<16sHHIQQQIHHHHHH", binary, 0, b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                     2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", binary, 64, 1, 5, 0, 0, 0, len(binary), len(binary), 4096)
    files = {"native-pids-worker": bytes(binary), "native-pids-worker-build.log": b"fixture build log\n",
             "native-pids-worker-driver.py": b"# inert driver wrapper\n", "native-pids-worker-ld.py": b"# inert linker wrapper\n",
             "native-pids-worker-link.json": b'{"fixture":"raw receipt"}', "native-pids-worker-link.d": b"fixture.o: fixture.c\n"}
    manifest["sha256"] = hashlib.sha256(files["native-pids-worker"]).hexdigest()
    manifest["build_log_sha256"] = hashlib.sha256(files["native-pids-worker-build.log"]).hexdigest()
    manifest["build_log_size"] = len(files["native-pids-worker-build.log"])
    tools = manifest["build_tools"]
    tools["invocation"].update(size=len(files["native-pids-worker-link.json"]),
        sha256=hashlib.sha256(files["native-pids-worker-link.json"]).hexdigest(), output_sha256=manifest["sha256"])
    tools["dependencies"].update(size=len(files["native-pids-worker-link.d"]), sha256=hashlib.sha256(files["native-pids-worker-link.d"]).hexdigest())
    tools["wrappers"].update(driver_sha256=hashlib.sha256(files["native-pids-worker-driver.py"]).hexdigest(),
                             linker_sha256=hashlib.sha256(files["native-pids-worker-ld.py"]).hexdigest())
    for relative, field in (("examples/native-pids-worker.rs", "source_sha256"),
            ("examples/native-pids-controller/mod.rs", "controller_source_sha256"),
            ("Cargo.toml", "cargo_manifest_sha256"), ("Cargo.lock", "cargo_lock_sha256")):
        manifest[field] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    files["native-pids-worker.json"] = json.dumps(manifest).encode()
    for name, data in files.items():
        path = artifact / name
        path.write_bytes(data)
        path.chmod(0o700 if name == "native-pids-worker" else 0o600)
    return manifest, files


def materialize_pids_proof(capture, expected_context):
    """Bind a full private proof to independently supplied emitter inputs."""
    manifest, _ = materialize_artifact(capture, expected_context["candidate_sha"])
    proof = fixture(expected_context=expected_context)
    proof["artifact"] = manifest
    proof["measured"]["artifact_copy"]["sha256"] = manifest["sha256"]
    path = capture / reader.FILENAME
    path.write_text(json.dumps(proof), encoding="utf-8")
    path.chmod(0o600)
    return proof


class PidsProofTests(unittest.TestCase):
    def reject(self, proof):
        with self.assertRaisesRegex(ValueError, "^invalid private pids proof$"):
            reader.validate_pids_proof(proof, fixture(proof["context"]["lane"], proof["context"]["outer_backend"])["context"])

    def test_all_lanes_backends_require_six_controls_and_remain_unadmitted(self):
        for lane in reader.LANES:
            for backend in ("podman", "docker"):
                proof = fixture(lane, backend)
                self.assertEqual(reader.validate_pids_proof(proof, proof["context"]),
                                 {"contract": "pids-v2", "capability_admission": [], "catalogue_admission": False})

    def test_literal_domain_thread_root_and_threaded_leaves_with_different_depths(self):
        proof = fixture()
        typed_chain(proof["cases"][1], ("domain threaded", "domain", "domain"))
        typed_chain(proof["cases"][2], ("threaded", "domain threaded", "domain", "domain"), 2)
        typed_chain(proof["cases"][3], ("threaded", "threaded", "domain threaded", "domain", "domain"), 3)
        self.assertEqual(reader.validate_pids_proof(proof, proof["context"]),
                         {"contract": "pids-v2", "capability_admission": [], "catalogue_admission": False})

    def test_authenticated_root_may_directly_parent_domain_or_thread_root(self):
        for kinds in (("domain", "domain"), ("threaded", "domain threaded")):
            proof = fixture()
            for case in proof["cases"]:
                typed_chain(case, kinds)
            reader.validate_pids_proof(proof, proof["context"])
            for field, replacement in (("qualification", "namespace_visible_root"),
                                       ("mount_root_is_slash", False), ("cgroup_type_present", True),
                                       ("pids_max_present", True), ("cgroup_events_present", True)):
                bad = deepcopy(proof)
                for case in bad["cases"]:
                    for sample in case["source_samples"]:
                        sample["attribution"]["hierarchy_root"][field] = replacement
                self.reject(bad)

    def test_every_prohibited_nonroot_edge_and_configured_threaded_outer_refuses(self):
        # Each pair is (child, parent); configured outer stays a separate D row.
        for child, parent in (("threaded", "domain"), ("domain", "domain threaded"),
                              ("domain threaded", "domain threaded"), ("domain", "threaded"),
                              ("domain threaded", "threaded")):
            case = case_fixture("cli16")
            typed_chain(case, (child, parent, "domain"), 2)
            with self.subTest(child=child, parent=parent), self.assertRaises(ValueError):
                reader.validate_case(case, "cli16", NONCE)
        case = case_fixture("cli16")
        typed_chain(case, ("threaded", "threaded", "domain threaded"))
        with self.assertRaises(ValueError):
            reader.validate_case(case, "cli16", NONCE)

    def test_versions_algorithm_types_and_leaf_row_equality_are_exact(self):
        mutations = [(('schema_version',), 1), (('schema_version',), True), (('contract',), 'pids-v1')]
        sample = ('cases', 0, 'source_samples', 0)
        for value in (None, True, 1, [], {}, "domain\n", "domain invalid", "thread-root", "DOMAIN"):
            mutations.extend(((sample + ('cgroup_type',), value),
                              (sample + ('attribution', 'controllers', 0, 'cgroup_type'), value)))
        mutations.extend(((sample + ('cgroup_type',), 'domain threaded'),
                          (sample + ('attribution', 'candidate_membership'), 'local_procs_v1'),
                          (sample + ('attribution', 'candidate_membership'), True),
                          (sample + ('attribution', 'candidate_membership'), None)))
        for path, value in mutations:
            proof = fixture()
            target = proof
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path, value=value):
                self.reject(proof)

    def test_kind_and_parent_stability_bind_all_cases_not_just_each_case(self):
        # These replacements preserve valid local edges and four-phase stability.
        for fault in ("leaf_kind_drift", "shared_kind", "shared_parent", "root", "reader", "outer", "duplicate_leaf"):
            proof = fixture()
            case = proof["cases"][-1]
            if fault == "leaf_kind_drift":
                case["source_samples"][2]["cgroup_type"] = "domain threaded"
                case["source_samples"][2]["attribution"]["controllers"][0]["cgroup_type"] = "domain threaded"
            elif fault == "shared_kind":
                for other in proof["cases"][:-1]:
                    typed_chain(other, ("threaded", "domain threaded", "domain"))
                typed_chain(case, ("domain", "domain", "domain"))
            else:
                for sample in case["source_samples"]:
                    attr = sample["attribution"]
                    if fault == "shared_parent":
                        attr["controllers"][2]["identity"][1] = 9999
                    elif fault == "root":
                        attr["hierarchy_root"]["identity"][1] = 9999
                    elif fault == "reader":
                        attr["reader_cgroup_namespace"][1] += 1
                    elif fault == "outer":
                        attr["controllers"][1]["identity"][1] = 9999
                    else:
                        attr["controllers"][0]["identity"][1] = 6001
            with self.subTest(fault=fault):
                self.reject(proof)

    def test_typed_leaves_retain_independent_effect_membership_and_cleanup_controls(self):
        for kinds, outer in ((("domain threaded", "domain", "domain"), 1),
                             (("threaded", "domain threaded", "domain", "domain"), 2)):
            for fault in ("extra_thread", "membership", "enforcer", "headroom", "nproc", "cleanup"):
                proof = fixture()
                for case in proof["cases"]:
                    typed_chain(case, kinds, outer)
                sample = proof["cases"][0]["source_samples"][2]
                if fault == "extra_thread":
                    proof["cases"][0]["worker_events"][3]["threads"] = 2
                elif fault == "membership":
                    sample["task_namespace_ids"][0][2] = [999, 1001, 1]
                elif fault == "enforcer":
                    sample["attribution"]["controllers"][0]["events_local_max"] = 0
                    sample["attribution"]["controllers"][0]["events_local_samples"] = [0, 0]
                elif fault == "headroom":
                    sample["globals"]["threads_max"] = sample["globals"]["total_tasks"]
                elif fault == "nproc":
                    sample["globals"]["nproc_soft"] = 1
                else:
                    proof["cleanup"]["source_handles"] = "unknown"
                with self.subTest(kinds=kinds, fault=fault):
                    self.reject(proof)

    def test_a_distinct_worker_leaf_cannot_also_parent_another_case(self):
        proof = fixture()
        case = proof["cases"][1]
        typed_chain(case, ("domain", "domain", "domain", "domain"), 2)
        for sample in case["source_samples"]:
            sample["attribution"]["controllers"][1]["identity"][1] = 6001
        # Both local chains and the shared parent relation are otherwise valid;
        # the first worker's required childless role is the violated predicate.
        for case, slot in zip(proof["cases"], ("cli16", "cli64", "cli_unlimited",
                                              "rendered16", "rendered64", "rendered_unlimited")):
            reader.validate_case(case, slot, NONCE)
        self.reject(proof)

    def test_raw_debian_engine_release_suffix_is_exact_and_never_normalized(self):
        for lane in reader.LANES:
            for release in ("20.10.5", "20.10.5+dfsg1", "20.10.5+dfsg2", "20.10.5+dfsg1-1+deb11u2",
                            "29.8.1", "29.8.1+dfsg1", "29.8.1+other", "20.10.5\n"):
                with self.subTest(lane=lane, release=release):
                    context = fixture(lane)["context"]
                    context["engine_release"] = release
                    proof = fixture(expected_context=context)
                    admitted_syntax = release in ("20.10.5", "29.8.1") or (
                        lane.startswith("debian11-") and release in ("20.10.5+dfsg1", "29.8.1+dfsg1"))
                    if admitted_syntax:
                        self.assertEqual(reader.validate_pids_proof(proof, context),
                                         {"contract": "pids-v2", "capability_admission": [], "catalogue_admission": False})
                        replayed = deepcopy(context)
                        replayed["engine_release"] = release.replace("+dfsg1", "") + ".0"
                        with self.assertRaisesRegex(ValueError, "^invalid private pids proof$"):
                            reader.validate_pids_proof(proof, replayed)
                    else:
                        with self.assertRaisesRegex(ValueError, "^invalid private pids proof$"):
                            reader.validate_pids_proof(proof, context)

    def test_local_enforcement_errno_reuse_namespace_and_higher_controls_are_independent(self):
        mutations = [
            (("cases", 0, "worker_events", 3, "errno"), 12),
            (("cases", 0, "worker_events", 5, "errno"), 11),
            (("cases", 1, "worker_events", 3, "fork_return"), -1),
            (("cases", 0, "source_samples", 2, "attribution", "controllers", 0, "events_local_max"), 0),
            (("cases", 0, "source_samples", 0, "attribution", "controllers", 1, "current"), 512),
            (("cases", 0, "source_samples", 1, "task_namespace_ids", 1, 1, 2), 99),
            (("cases", 0, "source_samples", 2, "globals", "kernel_machine"), "other"),
            (("cases", 0, "source_samples", 2, "attribution", "hierarchy_root", "qualification"), "guessed"),
            (("measured", "artifact_copy", "io", "read_operations"), 5),
            (("root", "source", "total_reserved", "reads"), 10099),
            (("cleanup", "outer"), "absent"),
            (("outer_after_confirmation", "start_ticks"), 1),
            (("artifact", "build_tools", "driver", "native_target"), "aarch64-linux-gnu"),
        ]
        for path, replacement in mutations:
            proof = fixture()
            target = proof
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = replacement
            self.reject(proof)

    def test_gnu_vendor_aliases_never_select_an_architecture_or_abi_fallback(self):
        for cpu in ("x86_64", "aarch64"):
            for suffix in ("linux-gnu", "unknown-linux-gnu", "vendor_1.2+3-linux-gnu", "suse-linux", "redhat-linux"):
                self.assertTrue(reader.native_gnu_target(cpu + "-" + suffix, cpu))
            for suffix in ("linux", "unknown-linux", "linux-gnux32", "linux-gnueabi", "musl-linux-gnu", "android-linux-gnu", "uclibc-linux-gnu",
                           "custom_musl-linux-gnu", "custom_MUSL-linux-gnu", "custom_uClibc-linux-gnu", "custom_Android-linux-gnu", "preandroidpost-linux-gnu", "véndor-linux-gnu"):
                self.assertFalse(reader.native_gnu_target(cpu + "-" + suffix, cpu))
            boundary = cpu + "-" + "v" * (128 - len(cpu) - len("--linux-gnu")) + "-linux-gnu"
            self.assertEqual(len(boundary), 128)
            self.assertTrue(reader.native_gnu_target(boundary, cpu))
            self.assertFalse(reader.native_gnu_target(boundary.replace("-v", "-vv", 1), cpu))

    def test_every_object_is_closed_and_every_declared_field_is_required(self):
        original = fixture()
        expected = deepcopy(original["context"])

        def paths(value, prefix=()):
            if type(value) is dict:
                yield prefix
                for key, child in value.items():
                    yield from paths(child, (*prefix, key))
            elif type(value) is list:
                for index, child in enumerate(value):
                    yield from paths(child, (*prefix, index))

        for path in paths(original):
            proof = deepcopy(original)
            target = proof
            for component in path:
                target = target[component]
            target["PRIVATE_PIDS_CANARY"] = True
            with self.assertRaises(ValueError, msg=str(path)):
                reader.validate_pids_proof(proof, expected)
            for key in target:
                if key == "PRIVATE_PIDS_CANARY":
                    continue
                proof = deepcopy(original)
                target = proof
                for component in path:
                    target = target[component]
                del target[key]
                with self.assertRaises(ValueError, msg=str((*path, key))):
                    reader.validate_pids_proof(proof, expected)

    def test_dynamic_ancestor_and_global_pairs_are_preserved_without_global_freeze(self):
        proof = fixture()
        for case in proof["cases"]:
            for index, sample in enumerate(case["source_samples"]):
                globals_ = sample["globals"]
                globals_["total_tasks_samples"] = [700 + index, 699 + index]
                globals_["total_tasks"] = 700 + index
                ancestor = sample["attribution"]["controllers"][2]
                ancestor["current_samples"] = [200, 199 + index]
                ancestor["current"] = max(ancestor["current_samples"])
                ancestor["events_samples"] = [sample["events_max"] + index, sample["events_max"] + index + 1]
                ancestor["events_max"] = ancestor["events_samples"][1]
        reader.validate_pids_proof(proof, proof["context"])

    def test_private_reader_rejects_duplicate_symlink_hardlink_and_overbound_proofs(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture"
            capture.mkdir(mode=0o700)
            proof = fixture()
            path = capture / reader.FILENAME
            raw = json.dumps(proof, separators=(",", ":")).encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            self.assertLess(len(raw), reader.LIMIT)
            # This test isolates proof custody; independent artifact binding
            # is covered below with real private files and exact digests.
            with patch.object(reader, "verify_artifact_files") as verify:
                reader.read_pids_proof(path, capture, proof["context"])
                verify.assert_called_once()
            path.write_bytes(b'{"schema_version":1,' + raw[1:])
            with self.assertRaises(ValueError):
                reader.read_pids_proof(path, capture, proof["context"])

            path.write_bytes(raw)
            os.link(path, capture / "hardlink")
            with self.assertRaises(ValueError):
                reader.read_pids_proof(path, capture, proof["context"])
            (capture / "hardlink").unlink()
            path.write_bytes(b"x" * (reader.LIMIT + 1))
            with self.assertRaises(ValueError):
                reader.read_pids_proof(path, capture, proof["context"])
            path.unlink()
            other = capture / "other"
            other.write_bytes(raw)
            other.chmod(0o600)
            path.symlink_to(other)
            with self.assertRaises(ValueError):
                reader.read_pids_proof(path, capture, proof["context"])


    def test_artifact_binding_reads_actual_source_binary_and_raw_tool_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)
            artifact = capture / "socket/pids-worker"
            manifest, files = materialize_artifact(capture, "a" * 40)
            reader.verify_artifact_files(manifest, capture)
            for name, data in files.items():
                path = artifact / name
                path.write_bytes(data + b"PRIVATE_PIDS_CANARY")
                with self.assertRaisesRegex(ValueError, "^invalid private pids proof$"):
                    reader.verify_artifact_files(manifest, capture)
                path.write_bytes(data)

    def test_cli_refusal_does_not_echo_private_inputs(self):
        canary = "PRIVATE_PIDS_CANARY"
        result = subprocess.run([sys.executable, str(ROOT / "scripts/native_pids_proof.py"), canary],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"invalid private pids proof\n")


if __name__ == "__main__":
    unittest.main()
