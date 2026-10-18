"""Independent synthetic protocol controls, not genuine native evidence."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_supplementary_groups_proof as reader
import native_network_attachment_proof as custody
from test_native_external_network_proof import fixture as context_fixture

SECRET = "PRIVATE_SUPPLEMENTARY_GROUP_CANARY"


def fixture(lane="upstream-rootful", primary_in_list=True):
    context = deepcopy(context_fixture(lane)["context"])
    context["fixture_image"] = "docker.io/library/busybox:fixture@sha256:" + "b" * 64
    image = "sha256:" + "d" * 64
    cases = []
    for case_index, (name, groups) in enumerate((("omitted", []), ("one", [23456]), ("pair", [23456, 34567]))):
        containers = []
        for role_index, role in enumerate(("oracle", "rendered")):
            number = case_index * 2 + role_index + 1
            files = []
            for gid in (23456, 34567):
                granted = gid in groups
                files.append({"owner_uid": 0, "group_gid": gid, "mode": 432, "write_exit": 0 if granted else 2,
                              "outcome": "worker_written" if granted else "native_permission_denied",
                              "readback": "worker_canary" if granted else "baseline_unchanged"})
            containers.append({
                "role": role, "id": f"{number:064x}", "name": f"dl-sg-{context['run_id']}-{name}-{role}",
                "owner": context["run_id"], "image_id": image, "wire": "independent_cli" if role == "oracle" else "literal_rendered",
                "configured_availability": "present" if groups else "null",
                "effect": {"pid": 1, "uid": 12345, "primary_gid": 3456,
                           "kernel_groups": ([3456] if primary_in_list else []) + groups,
                           "primary_gid_in_groups": primary_in_list, "effective_capabilities": "0000000000000000",
                           "kernel_pre_post_root_agree": True, "writer": "nonroot_pid1", "root_exec_scope": "setup_and_readback_only", "files": files},
                "running_after": True, "restart_count": 0, "oom_killed": False, "cleanup": "absent",
            })
        cases.append({"case": name, "authored_groups": groups, "containers": containers})
    return {
        "schema_version": 1, "contract": "supplementary-groups-v1", "scope": "numeric_nonroot_omitted_one_pair_dac_only",
        "capability_admission": [], "catalogue_admission": False, "context": context,
        "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"}, "cases": cases,
        "acquisition": {"selected_ids": 6, "route": "explicit_unix_socket", "api": context["acquisition_api"],
                        "daemon_mode_evidence": "rootless_observed" if lane.endswith("rootless") else "unknown_with_independent_rootful_context",
                        "reserved_calls": 16, "reserved_body_bytes": 524288, "actual_requests": 9, "actual_body_bytes": 32768,
                        "decoded": "effective_user_and_groupadd_agree", "byte_scope": "decoded_response_bodies_only",
                        "limits": {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8, "max_response_bytes": 131072,
                                   "max_total_body_bytes": 524288, "max_elapsed_seconds": 10},
                        "separate_transport_bounds": {"response_header_bytes": 16384, "chunk_line_bytes": 64, "chunk_payload_crlf_bytes": 2,
                                                      "final_trailer_line_bytes": 16384, "actual_wire_bytes": "not_measured"}},
        "accounting": {"ordinary_calls": 75 if lane.startswith("debian11-") else 74, "ordinary_bytes": 600000,
                       "cleanup_calls": 54, "cleanup_bytes": 4000, "ordinary_elapsed_ns": 4_000_000_000,
                       "cleanup_elapsed_ns": 2_000_000_000, "elapsed_ns": 7_000_000_000, "deadline_seconds": 180, "cleanup_reserve_seconds": 46,
                       "initial_context_acquisition": {"max_requests": 16, "max_body_bytes": 2097152, "max_elapsed_seconds": 15,
                                                       "accounting": "separate_existing_bound"}},
        "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False},
    }


class SupplementaryGroupsProofTests(unittest.TestCase):
    def reject(self, proof, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private supplementary groups proof$") as caught:
            reader.validate_supplementary_groups_proof(proof, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_four_lanes_retain_primary_representation_and_no_admission(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for primary in (False, True):
                value = fixture(lane, primary)
                self.assertEqual(reader.validate_supplementary_groups_proof(value, value["context"]),
                                 {"contract": "supplementary-groups-v1", "capability_admission": [], "catalogue_admission": False})
                for availability in ("missing", "null", "empty"):
                    for item in value["cases"][0]["containers"]:
                        item["configured_availability"] = availability
                    reader.validate_supplementary_groups_proof(value, value["context"])

    def test_every_nested_field_is_required_closed_and_typed(self):
        original = fixture()

        def paths(value, prefix=()):
            if isinstance(value, dict):
                yield prefix
                for key, child in value.items():
                    yield from paths(child, prefix + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from paths(child, prefix + (index,))

        for path in paths(original):
            target = original
            for part in path:
                target = target[part]
            for key in (*target, SECRET):
                bad = deepcopy(original)
                current = bad
                for part in path:
                    current = current[part]
                if key == SECRET:
                    current[key] = SECRET
                else:
                    del current[key]
                with self.subTest(path=path, key=key):
                    self.reject(bad)

    def test_exact_kernel_membership_nonroot_writer_and_capabilities_are_all_required(self):
        changes = {"pid": (0, True, 2), "uid": (0, True, 12346), "primary_gid": (0, True, 23456),
                   "kernel_groups": ([3456, 0], [3456, 23456, 23456], [23456, 3456], [True], [1.0], [4294967296], [3456]),
                   "primary_gid_in_groups": (False, 1, "true"), "effective_capabilities": ("1", "0000000000000001", 0, None),
                   "kernel_pre_post_root_agree": (False, 1), "writer": ("root_exec", "exec_nonroot", "configured_only"),
                   "root_exec_scope": ("permission_oracle", "all_operations")}
        for field, values in changes.items():
            for value in values:
                bad = fixture()
                bad["cases"][1]["containers"][0]["effect"][field] = value
                with self.subTest(field=field, value=value):
                    self.reject(bad)
        # CapEff=0 alone is never evidence of nonroot DAC or the actual writer.
        bad = fixture()
        bad["cases"][0]["containers"][0]["effect"]["uid"] = 0
        self.reject(bad)
        for case in range(3):
            bad = fixture()
            bad["cases"][case]["containers"][0]["configured_availability"] = "present" if case == 0 else "empty"
            self.reject(bad)

    def test_permission_matrix_requires_worker_writes_and_denied_files_unchanged(self):
        for case in range(3):
            for file_index in range(2):
                for field, values in {"owner_uid": (12345, True), "group_gid": (3456, True), "mode": (438, 511, True),
                                      "write_exit": (False, -1, 256, 0 if case == 0 or (case == 1 and file_index == 1) else 1),
                                      "outcome": ("inspect_only", "timeout", "eacces_assumed", "unknown"),
                                      "readback": ("wrong_canary", "not_read", "unknown")}.items():
                    for value in values:
                        bad = fixture()
                        bad["cases"][case]["containers"][1]["effect"]["files"][file_index][field] = value
                        self.reject(bad)
        for case, file_index in ((0, 0), (0, 1), (1, 1)):
            bad = fixture()
            file = bad["cases"][case]["containers"][0]["effect"]["files"][file_index]
            file.update(write_exit=0, outcome="worker_written", readback="worker_canary")
            self.reject(bad)
        bad = fixture()
        bad["cases"][2]["containers"][0]["effect"]["files"].reverse()
        self.reject(bad)

    def test_partial_reordered_duplicate_outer_alias_context_cleanup_and_admission_refuse(self):
        for change in range(9):
            bad = fixture()
            if change == 0:
                bad["cases"].pop()
            elif change == 1:
                bad["cases"].reverse()
            elif change == 2:
                bad["cases"][0]["containers"].reverse()
            elif change == 3:
                bad["cases"][1]["containers"].pop()
            elif change == 4:
                bad["cases"][1]["containers"][0]["id"] = bad["cases"][0]["containers"][0]["id"]
            elif change == 5:
                bad["cases"][0]["containers"][0]["id"] = bad["context"]["outer"]["id"]
            elif change == 6:
                bad["cases"][0]["authored_groups"] = [3456]
            elif change == 7:
                bad["cases"][2]["authored_groups"] = ["23456", "34567"]
            else:
                bad["cases"][2]["authored_groups"] = [34567, 23456]
            self.reject(bad)
        for section in ("context", "borrowed_image", "cleanup", "acquisition", "accounting"):
            for field in fixture()[section]:
                bad = fixture()
                bad[section][field] = SECRET
                self.reject(bad)
        for field, value in (("schema_version", True), ("scope", "all_users_groups"),
                             ("capability_admission", ["SupplementaryGroups"]), ("catalogue_admission", 0)):
            bad = fixture()
            bad[field] = value
            self.reject(bad)

    def test_capture_budgets_clock_reserve_and_boolean_numeric_confusion_refuse(self):
        for section, changes in (
            ("acquisition", {"selected_ids": (5, True), "actual_requests": (7, 17, True), "actual_body_bytes": (0, 524289, True),
                             "reserved_calls": (15, 17), "reserved_body_bytes": (524287, 524289), "api": ("1.41", "1.56")}),
            ("accounting", {"ordinary_calls": (73, 75, True), "ordinary_bytes": (524288, 2097153, True),
                            "cleanup_calls": (53, 55, True), "cleanup_bytes": (0, 552961, True),
                            "ordinary_elapsed_ns": (0, 134000000001, True), "cleanup_elapsed_ns": (0, 46000000001, True),
                            "elapsed_ns": (0, 5999999999, 180000000001, True)})):
            for field, values in changes.items():
                for value in values:
                    bad = fixture()
                    bad[section][field] = value
                    self.reject(bad)

    def test_private_custody_refuses_links_nonregular_permissions_and_json_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "supplementary-groups-v1.json"
            value = fixture()
            text = json.dumps(value)

            def save(payload=text):
                path.write_text(payload)
                path.chmod(0o600)

            def read():
                return reader.read_supplementary_groups_proof(path, root, value["context"])

            save()
            self.assertFalse(read()["catalogue_admission"])
            for payload in ("", "{", "[]", text + SECRET, "x" * 16385,
                            text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                            text.replace('"uid": 12345', '"uid": NaN'), text.replace('"uid": 12345', '"uid": Infinity')):
                save(payload)
                with self.assertRaises(ValueError):
                    read()
            save()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read()
            path.chmod(0o600)
            root.chmod(0o755)
            with self.assertRaises(ValueError):
                read()
            root.chmod(0o700)
            other = root / "other"
            os.link(path, other)
            with self.assertRaises(ValueError):
                read()
            other.unlink()
            path.rename(other)
            path.symlink_to(other)
            with self.assertRaises(ValueError):
                read()
            path.unlink()
            other.unlink()
            os.mkfifo(path, 0o600)
            with self.assertRaises(ValueError):
                read()
            path.unlink()
            with self.assertRaises(ValueError):
                read()

    def test_stable_read_and_independent_twelve_argument_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "supplementary-groups-v1.json"
            value = fixture()
            context = value["context"]
            context["outer"]["socket_source"] = str(root / "socket")
            text = json.dumps(value)
            path.write_text(text)
            path.chmod(0o600)
            original_read = os.read

            def mutate(descriptor, count):
                data = original_read(descriptor, count)
                path.write_text(text + " ")
                return data

            with patch.object(custody.os, "read", side_effect=mutate), self.assertRaises(ValueError):
                reader.read_supplementary_groups_proof(path, root, context)
            path.write_text(text)
            arguments = [str(root), context["candidate_sha"], context["run_id"], context["lane"], context["engine_release"],
                         context["rendering_api"], context["mode"], context["docker_package"], context["fixture_image"],
                         context["outer"]["image"], context["outer"]["id"], str(context["daemon_uid"])]
            result = subprocess.run([sys.executable, str(ROOT / "scripts/native_supplementary_groups_proof.py"), *arguments],
                                    capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
            arguments[1] = SECRET
            result = subprocess.run([sys.executable, str(ROOT / "scripts/native_supplementary_groups_proof.py"), *arguments],
                                    capture_output=True, text=True, timeout=5, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "invalid private supplementary groups proof")


if __name__ == "__main__":
    unittest.main()
