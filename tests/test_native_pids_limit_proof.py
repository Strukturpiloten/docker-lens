"""Finite synthetic proof cases; no shell worker, daemon, or host-resource probe."""

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_pids_limit_proof as reader
from test_native_external_network_proof import fixture as base_fixture

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_PIDS_CANARY"


def fixture(lane="upstream-rootful", kind="v2", nested=False):
    context = deepcopy(base_fixture(lane)["context"])
    image = "sha256:" + "b" * 64
    observer = {"pid_namespace": 100, "mount_namespace": 101, "cgroup_namespace": 102,
                "daemon_pid_namespace": 110 if nested else 100, "daemon_depth": 2 if nested else 1,
                "daemon_uid": context["daemon_uid"], "cgroup_kind": kind, "outer_process_ceiling": 512}
    cases = []
    for index in range(6):
        case, limit = reader.CASES[index // 2]
        role = ("oracle", "rendered")[index % 2]
        init = 1000 + index * 100
        uid = 1000 if lane.endswith("rootless") else 0
        start = 100000 + index * 100
        root = f"/outer/fixture{index}"
        mapping = {"kind": kind, "mount_id": 31, "root": "/outer", "mountpoint": "/sys/fs/cgroup",
                   "membership": root, "path": f"/sys/fs/cgroup/fixture{index}", "outer_membership": "/outer",
                   "outer_path": "/sys/fs/cgroup", "inode": 200 + index, "device": 20}
        memory_mapping = deepcopy(mapping)
        if kind == "v1":
            for controller, selected in (("pids", mapping), ("memory", memory_mapping)):
                selected["mountpoint"] += "/" + controller
                selected["path"] = selected["mountpoint"] + f"/fixture{index}"
                selected["outer_path"] = selected["mountpoint"]
            memory_mapping.update(mount_id=32, device=21, inode=300 + index)
        rows = [[init, 1, 50, start, uid], [init + 1, 2, init, start + 1, uid]]
        count = 16 if limit == 16 else 34
        held_rows = rows + [[init + number, number + 1, init + 1, start + number, uid]
                            for number in range(2, count)]
        snapshots = {}
        for phase, records, denials in (("baseline", rows, 0), ("held", held_rows, int(limit == 16)),
                                        ("restored", rows[:1], int(limit == 16))):
            packed = [[row[0] - init, row[1], row[2] - init, row[3] - start, row[4] - uid]
                      for row in records]
            snapshots[phase] = {"rows": packed, "members": sorted(row[0] - init for row in records),
                                "pids_current": len(records), "pids_max": "max" if limit == -1 else limit,
                                "denials": denials, "oom_kills": 0, "outer_pids": 80,
                                "outer_memory": 268435456, "ancestor_headroom": 400,
                                "phase": {"baseline": "ready", "held": "exit_barrier", "restored": "idle"}[phase]}
        chain = [init, 20 + index, 1] if nested else [init, 1]
        cases.append({"case": case, "role": role, "id": f"{index + 1:064x}",
                      "name": f"dl-pids-{context['run_id']}-{case}-{role}",
                      "wire": "independent_cli" if role == "oracle" else "literal_rendered", "image_id": image,
                      "configured_limit": limit, "identity": {"private_pid": 1, "private_uid": 0,
                          "start": start, "pid_namespace": 300 + index, "state_pid": chain[observer["daemon_depth"] - 1],
                          "nspid": chain, "uid_map": [0, uid, 1], "outer_uid": uid,
                          "worker_private": 2, "worker_start": start + 1},
                      "pids_mapping": mapping, "memory_mapping": memory_mapping,
                      "event_source": "pids.events.local", "nproc": [1024, 1024],
                      "preflight": {"outer_pids": 60, "outer_memory": 268435456},
                      **snapshots, "work": {"attempts": 15 if limit == 16 else 32,
                          "successes": 14 if limit == 16 else 32, "exit_status": 2 if limit == 16 else 0,
                          "diagnostic": "native_c_eagain_fork" if limit == 16 else "none", "held_barrier": True,
                          "release": "all_children_gone"}, "elapsed_ns": 1000000000, "cleanup": "absent"})
    return {"schema_version": 1, "contract": reader.CONTRACT, "context": context, "capability_admission": [],
            "catalogue_admission": False, "scope": reader.SCOPE,
            "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"},
            "observer": observer, "cases": cases,
            "acquisition": {"route": "explicit_unix_socket", "selected_ids": 6,
                "requested_api": context["acquisition_api"], "reserved_calls": 16,
                "reserved_bytes": 524288, "actual_requests": 9, "actual_response_bytes": 12000,
                "decoded": "present_effective_exact_pids_limits", "max_elapsed_ns": 10000000000},
            "accounting": {"ordinary_calls": 124 if lane.startswith("debian11-") else 123,
                "ordinary_bytes": 600000, "cleanup_calls": 54,
                "cleanup_bytes": 6000, "ordinary_elapsed_ns": 10000000000,
                "cleanup_elapsed_ns": 3000000000, "elapsed_ns": 14000000000,
                "deadline_seconds": 180, "cleanup_reserve_seconds": 46},
            "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


class PidsLimitProofTests(unittest.TestCase):
    def reject(self, value, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private pids limit proof$") as result:
            reader.validate_pids_limit_proof(value, context or fixture()["context"])
        self.assertNotIn(SECRET, str(result.exception))

    def test_all_exact_lanes_generations_and_nested_pid_mappings(self):
        for lane in LANES:
            for kind in ("v1", "v2"):
                for nested in (False, True):
                    with self.subTest(lane=lane, kind=kind, nested=nested):
                        proof = fixture(lane, kind, nested)
                        outcome = reader.validate_pids_limit_proof(proof, deepcopy(proof["context"]))
                        self.assertEqual(outcome, {"contract": reader.CONTRACT, "capability_admission": [],
                                                   "catalogue_admission": False, "scope": reader.SCOPE})
                        self.assertLessEqual(len(json.dumps(proof, separators=(",", ":")).encode()), reader.PROOF_BYTES)

    def test_exclusive_leaf_events_are_valid_without_new_local_interface(self):
        proof = fixture()
        for item in proof["cases"]:
            item["event_source"] = "pids.events_exclusive_leaf"
        reader.validate_pids_limit_proof(proof, proof["context"])

    def test_pid1_relative_encoding_preserves_independent_membership(self):
        proof = fixture()
        item = proof["cases"][0]
        restored = reader.rows(item["held"]["rows"], 16, item["identity"])
        self.assertEqual(restored[0], [1000, 1, 50, 100000, 0])
        self.assertEqual(restored[-1], [1015, 16, 1001, 100015, 0])
        item["held"]["members"][2] += 1
        self.reject(proof)
        for position in range(5):
            proof = fixture()
            proof["cases"][0]["held"]["rows"][2][position] = True
            self.reject(proof)

    def test_unified_memory_controller_and_observer_depth_must_agree(self):
        proof = fixture()
        proof["cases"][0]["memory_mapping"]["inode"] += 1
        self.reject(proof)
        proof = fixture()
        proof["observer"]["daemon_pid_namespace"] += 1
        self.reject(proof)

    def test_faithful_long_controller_paths_still_fail_closed_at_custody_bound(self):
        proof = fixture()
        for item in proof["cases"]:
            for controller in ("pids_mapping", "memory_mapping"):
                mapping = item[controller]
                mapping["membership"] = "/outer/" + "a" * 160 + "/" + item["id"]
                mapping["path"] = mapping["mountpoint"] + mapping["membership"][len("/outer"):]
        reader.validate_pids_limit_proof(proof, proof["context"])
        payload = json.dumps(proof, separators=(",", ":"))
        self.assertGreater(len(payload.encode()), reader.PROOF_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            target = parent / reader.FILENAME
            target.write_text(payload)
            target.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "^invalid private pids limit proof$"):
                reader.read_pids_limit_proof(target, parent, proof["context"])

    def test_namespace_inode_start_uid_map_and_daemon_pid_are_independent(self):
        changes = (("state_pid", 1000), ("private_pid", 2), ("private_uid", 1),
                   ("pid_namespace", 110), ("start", 1), ("worker_start", 1),
                   ("nspid", [1000, 1]), ("uid_map", [1, 0, 1]), ("outer_uid", 3))
        for key, value in changes:
            proof = fixture(nested=True)
            proof["cases"][0]["identity"][key] = value
            with self.subTest(key=key):
                self.reject(proof, proof["context"])

    def test_coherent_worker_start_cannot_predate_its_pid1_parent(self):
        proof = fixture()
        item = proof["cases"][0]
        item["identity"]["worker_start"] = 1
        for phase in ("baseline", "held"):
            item[phase]["rows"][1][3] = 1 - item["identity"]["start"]
        # All copies of the worker agree; rejecting only stale copies misses
        # the impossible chronology between that worker and its original PID1.
        self.assertEqual(reader.rows(item["baseline"]["rows"], 2, item["identity"])[1][3], 1)
        self.reject(proof)

    def test_nested_private_namespace_cannot_be_the_outer_observer_namespace(self):
        proof = fixture(nested=True)
        item = proof["cases"][0]
        self.assertNotEqual(proof["observer"]["pid_namespace"], proof["observer"]["daemon_pid_namespace"])
        item["identity"]["pid_namespace"] = proof["observer"]["pid_namespace"]
        self.reject(proof, proof["context"])

    def test_linux_nproc_soft_hard_order_and_unlimited_semantics(self):
        for limits in ([1024, 35], ["unlimited", 35]):
            proof = fixture()
            proof["cases"][0]["nproc"] = limits
            with self.subTest(invalid=limits):
                self.reject(proof)
        for limits in ([35, 1024], [35, "unlimited"], ["unlimited", "unlimited"]):
            proof = fixture()
            proof["cases"][0]["nproc"] = limits
            with self.subTest(valid=limits):
                reader.validate_pids_limit_proof(proof, proof["context"])

    def test_all_live_cases_need_distinct_actual_controller_leaves(self):
        for kind in ("v1", "v2"):
            for mutation in ("copied_mapping", "reused_inode", "reused_path"):
                proof = fixture(kind=kind)
                for item in proof["cases"][1:]:
                    for controller in ("pids_mapping", "memory_mapping"):
                        original = proof["cases"][0][controller]
                        if mutation == "copied_mapping":
                            item[controller] = deepcopy(original)
                        elif mutation == "reused_inode":
                            item[controller]["inode"] = original["inode"]
                        else:
                            for key in ("membership", "path"):
                                item[controller][key] = original[key]
                # Each mapping remains internally coherent; cross-case evidence
                # must establish six leaves for six simultaneously live PID1s.
                item = proof["cases"][1]
                reader.case(item, reader.CASES[0], "rendered", proof["context"],
                            proof["borrowed_image"]["id"], proof["observer"])
                with self.subTest(kind=kind, mutation=mutation):
                    self.reject(proof)

    def test_all_cases_bind_the_same_owned_outer_controllers(self):
        for kind in ("v1", "v2"):
            for mutation in ("mountpoint", "mount_id", "device", "root"):
                proof = fixture(kind=kind)
                item = proof["cases"][1]
                for controller in ("pids_mapping", "memory_mapping"):
                    mapping = item[controller]
                    if mutation == "mountpoint":
                        mapping["mountpoint"] += "/other"
                        mapping["path"] = mapping["mountpoint"] + "/fixture1"
                        mapping["outer_path"] = mapping["mountpoint"]
                    elif mutation == "root":
                        mapping["root"] = "/"
                        mapping["path"] = mapping["mountpoint"] + "/outer/fixture1"
                        mapping["outer_path"] = mapping["mountpoint"] + "/outer"
                    else:
                        mapping[mutation] += 1
                reader.case(item, reader.CASES[0], "rendered", proof["context"],
                            proof["borrowed_image"]["id"], proof["observer"])
                with self.subTest(kind=kind, mutation=mutation):
                    self.reject(proof)

    def test_real_saturation_and_exact_denial_interval_are_mandatory(self):
        for phase, field, value in (("held", "pids_current", 15), ("held", "denials", 0),
                                    ("held", "denials", 2), ("restored", "denials", 2),
                                    ("held", "oom_kills", 1), ("held", "outer_pids", 385),
                                    ("baseline", "outer_memory", 3221225473),
                                    ("held", "ancestor_headroom", 127), ("held", "phase", "ready"),
                                    ("held", "rows", []), ("held", "members", []), ("held", "pids_max", "max")):
            proof = fixture()
            proof["cases"][0][phase][field] = value
            with self.subTest(phase=phase, field=field, value=value):
                self.reject(proof)

    def test_wrong_parent_duplicate_rows_extra_task_and_stale_worker_fail(self):
        for mutation in range(5):
            proof = fixture()
            rows = proof["cases"][0]["held"]["rows"]
            if mutation == 0:
                rows[2][2] = rows[0][0]
            elif mutation == 1:
                rows[2][0] = rows[1][0]
            elif mutation == 2:
                rows[1][3] += 1
            elif mutation == 3:
                rows.append(deepcopy(rows[-1]))
            else:
                rows[2][4] = 5
            self.reject(proof)

    def test_generic_error_unknown_event_source_and_incomplete_work_fail(self):
        for key, value in (("attempts", 32), ("successes", 15), ("exit_status", 1),
                           ("diagnostic", "generic_fork_failure"), ("held_barrier", False),
                           ("release", "uncertain")):
            proof = fixture()
            proof["cases"][0]["work"][key] = value
            self.reject(proof)
        proof = fixture()
        proof["cases"][0]["event_source"] = "unknown"
        self.reject(proof)

    def test_mount_root_resolution_must_not_guess_a_docker_path(self):
        for key, value in (("root", "/other"), ("path", "/sys/fs/cgroup/guessed"),
                           ("membership", "/outer/../fixture0"), ("outer_path", "/sys/fs"),
                           ("kind", "unknown"), ("mount_id", False), ("inode", 0)):
            proof = fixture()
            proof["cases"][0]["pids_mapping"][key] = value
            self.reject(proof)

    def test_omitted_or_repeated_context_identity_and_cases_fail(self):
        for mutation in range(7):
            proof = fixture()
            if mutation == 0:
                proof["cases"].pop()
            elif mutation == 1:
                proof["cases"].reverse()
            elif mutation == 2:
                proof["cases"][1]["id"] = proof["cases"][0]["id"]
            elif mutation == 3:
                proof["cases"][1]["identity"]["pid_namespace"] = proof["cases"][0]["identity"]["pid_namespace"]
            elif mutation == 4:
                proof["context"]["candidate_sha"] = "f" * 40
            elif mutation == 5:
                proof["catalogue_admission"] = True
            else:
                proof[SECRET] = SECRET
            self.reject(proof)

    def test_budget_and_precreate_headroom_are_not_waived(self):
        for key, value in (("ordinary_calls", 181), ("ordinary_calls", 122), ("ordinary_bytes", 2097153),
                           ("cleanup_calls", 53), ("cleanup_reserve_seconds", 45),
                           ("ordinary_elapsed_ns", 134000000001), ("elapsed_ns", 180000000001)):
            proof = fixture()
            proof["accounting"][key] = value
            self.reject(proof)
        proof = fixture()
        proof["cases"][0]["preflight"]["outer_pids"] = 385
        self.reject(proof)
        for value in ([34, 1024], [True, 1024], ["unknown", 1024]):
            proof = fixture()
            proof["cases"][0]["nproc"] = value
            self.reject(proof)

    def test_private_custody_modes_links_duplicates_and_bound(self):
        proof = fixture()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            target = parent / reader.FILENAME
            payload = json.dumps(proof, separators=(",", ":"))
            target.write_text(payload)
            target.chmod(0o600)
            reader.read_pids_limit_proof(target, parent, proof["context"])
            for mode in (0o644, 0o400):
                target.chmod(mode)
                with self.assertRaises(ValueError):
                    reader.read_pids_limit_proof(target, parent, proof["context"])
            target.chmod(0o600)
            target.write_text(payload[:-1] + ',"schema_version":1}')
            with self.assertRaises(ValueError):
                reader.read_pids_limit_proof(target, parent, proof["context"])
            target.write_text(" " * (reader.PROOF_BYTES + 1))
            with self.assertRaises(ValueError):
                reader.read_pids_limit_proof(target, parent, proof["context"])
            target.write_text(payload)
            linked = parent / "link"
            os.link(target, linked)
            with self.assertRaises(ValueError):
                reader.read_pids_limit_proof(target, parent, proof["context"])
            linked.unlink()
            target.unlink()
            target.symlink_to(parent / "absent")
            with self.assertRaises(ValueError):
                reader.read_pids_limit_proof(target, parent, proof["context"])


if __name__ == "__main__":
    unittest.main()
