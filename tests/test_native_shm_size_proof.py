"""Synthetic private-reader controls, never native ShmSize qualification."""

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
import native_shm_size_proof as reader
import native_network_attachment_proof as custody
from test_native_external_network_proof import fixture as context_fixture

SECRET = "PRIVATE_SHM_SIZE_CANARY"
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")


def fixture(lane="upstream-rootful"):
    context = deepcopy(context_fixture(lane)["context"])
    context["fixture_image"] = "docker.io/library/busybox:fixture@sha256:" + "b" * 64
    image = "sha256:" + "d" * 64
    cases = []
    for case_index, (name, authored) in enumerate((("omitted", None), ("one_mib", 1048576), ("two_mib", 2097152))):
        capacity = 8 * 1024 * 1024 if authored is None else authored
        containers = []
        for role_index, role in enumerate(("oracle", "rendered")):
            number = 2 * case_index + role_index + 1
            containers.append({
                "role": role, "id": f"{number:064x}", "name": f"dl-shm-{context['run_id']}-{name}-{role}",
                "owner": context["run_id"], "image_id": image,
                "wire": "independent_cli" if role == "oracle" else "literal_rendered",
                "configured_size_bytes": capacity, "filesystem": "tmpfs", "mount_access": "rw",
                "ipc_mode": "private", "ipc_namespace": 4000 + number,
                "statfs_unit": 4096, "statfs_blocks": capacity // 4096, "capacity_bytes": capacity,
                "canary": "own_value_retained_after_all_six_seeds",
                "payload_bytes": 3145728 if authored is None else authored,
                "write_outcome": "three_mib_written_readback" if authored is None else "exact_saturation_native_enospc",
                "running_after": True, "restart_count": 0, "oom_killed": False, "cleanup": "absent",
            })
        cases.append({"case": name, "authored_size_bytes": authored, "containers": containers})
    return {
        "schema_version": 1, "contract": "shm-size-v1", "capability_admission": [], "catalogue_admission": False,
        "scope": "explicit_1MiB_2MiB_with_observed_omission_only", "context": context,
        "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"}, "cases": cases,
        "acquisition": {"route": "explicit_unix_socket", "selected_ids": 6, "requested_api": context["acquisition_api"],
                        "daemon_mode_evidence": "rootless_observed" if lane.endswith("rootless") else "unknown_with_independent_rootful_context",
                        "reserved_calls": 16, "reserved_bytes": 524288, "actual_requests": 9,
                        "byte_scope": "decoded_response_bodies_only",
                        "separate_transport_bounds": {"response_header_bytes": 16384, "chunk_line_bytes": 64,
                                                      "chunk_payload_crlf_bytes": 2, "final_trailer_line_bytes": 16384,
                                                      "actual_wire_bytes": "not_measured"},
                        "actual_response_bytes": 32768, "decoded": "present_effective_exact_sizes",
                        "limits": {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8,
                                   "max_response_bytes": 131072, "max_total_bytes": 524288, "max_elapsed_seconds": 10}},
        "accounting": {"ordinary_calls": 75 if lane.startswith("debian11-") else 74, "ordinary_bytes": 600000,
                       "cleanup_calls": 54, "cleanup_bytes": 4000, "deadline_seconds": 180,
                       "cleanup_reserve_seconds": 46, "ordinary_elapsed_ns": 4_000_000_000,
                       "cleanup_elapsed_ns": 2_000_000_000, "elapsed_ns": 7_000_000_000,
                       "initial_context_acquisition": {"max_requests": 16, "max_total_bytes": 2097152,
                                                       "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"}},
        "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False},
    }


class ShmSizeProofTests(unittest.TestCase):
    def reject(self, value, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private shm size proof$") as caught:
            reader.validate_shm_size_proof(value, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_all_exact_contexts_accept_complete_finite_controls_without_admission(self):
        for lane in LANES:
            value = fixture(lane)
            with self.subTest(lane=lane):
                self.assertEqual(reader.validate_shm_size_proof(value, value["context"]),
                                 {"contract": "shm-size-v1", "capability_admission": [], "catalogue_admission": False})
                # An observed default is comparative, never a universal 64 MiB.
                for item in value["cases"][0]["containers"]:
                    item["capacity_bytes"] = item["configured_size_bytes"] = 4 * 1024 * 1024
                    item["statfs_blocks"] = 1024
                reader.validate_shm_size_proof(value, value["context"])

    def test_every_nested_field_is_required_closed_and_type_checked(self):
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
            value = original
            for part in path:
                value = value[part]
            for key in value:
                bad = deepcopy(original)
                parent = bad
                for part in path:
                    parent = parent[part]
                del parent[key]
                with self.subTest(path=path, missing=key):
                    self.reject(bad)
            bad = deepcopy(original)
            parent = bad
            for part in path:
                parent = parent[part]
            parent[SECRET] = SECRET
            with self.subTest(path=path, extra=True):
                self.reject(bad)

    def test_no_partial_reordered_duplicate_or_outer_alias_fixture_is_proof(self):
        for change in range(8):
            bad = fixture()
            if change == 0:
                bad["cases"].pop()
            elif change == 1:
                bad["cases"].reverse()
            elif change == 2:
                bad["cases"][0]["containers"].pop()
            elif change == 3:
                bad["cases"][1]["containers"].reverse()
            elif change == 4:
                bad["cases"][1]["containers"][0]["id"] = bad["cases"][0]["containers"][0]["id"]
            elif change == 5:
                bad["cases"][0]["containers"][0]["id"] = bad["context"]["outer"]["id"]
            elif change == 6:
                bad["cases"][2]["containers"][1]["ipc_namespace"] = bad["cases"][0]["containers"][0]["ipc_namespace"]
            else:
                bad["cases"].append(deepcopy(bad["cases"][0]))
            with self.subTest(change=change):
                self.reject(bad)

    def test_inspect_only_wrong_filesystem_saturation_or_default_effect_refuses(self):
        changes = {
            "filesystem": ("overlayfs", "unknown", None), "mount_access": ("ro", None),
            "ipc_mode": ("host", "shareable", "", None), "ipc_namespace": (0, -1, True, 1.0, 2**64),
            "configured_size_bytes": (0, True, -1, 2**63, 3145728),
            "capacity_bytes": (0, -1, True, 1.0, 2**63, 7),
            "statfs_unit": (0, True, 4095, 8191, 131072), "statfs_blocks": (0, True, 1.0, 1),
            "canary": ("configured", "written_before_other_seeds", "wrong_value", None),
            "payload_bytes": (0, True, 1.0, 3),
            "write_outcome": ("inspect_only", "written", "permission_denied", "oom", "timeout", "enospc_unmeasured"),
            "running_after": (False, 1), "restart_count": (1, False), "oom_killed": (True, 0),
            "cleanup": ("unknown", None),
        }
        for case in range(3):
            for field, values in changes.items():
                for replacement in values:
                    bad = fixture()
                    bad["cases"][case]["containers"][1][field] = replacement
                    with self.subTest(case=case, field=field, value=replacement):
                        self.reject(bad)
        bad = fixture()
        bad["cases"][0]["containers"][1]["capacity_bytes"] = 4 * 1024 * 1024
        bad["cases"][0]["containers"][1]["configured_size_bytes"] = 4 * 1024 * 1024
        bad["cases"][0]["containers"][1]["statfs_blocks"] = 1024
        self.reject(bad)
        for case in range(3):
            for replacement in (0, True, 1.0, -1, "1048576"):
                bad = fixture()
                bad["cases"][case]["authored_size_bytes"] = replacement
                self.reject(bad)

    def test_context_budgets_cleanup_and_empty_admission_cannot_drift(self):
        for field in fixture()["context"]:
            bad = fixture()
            bad["context"][field] = SECRET
            self.reject(bad)
        for section in ("acquisition", "accounting", "cleanup", "borrowed_image"):
            for field in fixture()[section]:
                bad = fixture()
                bad[section][field] = SECRET
                self.reject(bad)
        for field, value in (("schema_version", True), ("catalogue_admission", 0),
                             ("capability_admission", ["ShmSize"]), ("scope", "all_sizes_and_ipc_modes")):
            bad = fixture()
            bad[field] = value
            self.reject(bad)
        for field, values in {"ordinary_calls": (73, 75, True, 301),
                              "ordinary_bytes": (0, 524288, 2097153, True),
                              "cleanup_calls": (53, 55, 101, True),
                              "cleanup_bytes": (0, 552961, 2097153, True),
                              "ordinary_elapsed_ns": (0, 134000000001, True),
                              "cleanup_elapsed_ns": (0, 46000000001, True),
                              "elapsed_ns": (0, 180000000001, True, 5999999999)}.items():
            for value in values:
                bad = fixture()
                bad["accounting"][field] = value
                self.reject(bad)
        for field, values in {"actual_requests": (0, 7, 17, True),
                              "actual_response_bytes": (0, 524289, True),
                              "reserved_calls": (0, 15, 17), "reserved_bytes": (0, 524287, 524289),
                              "selected_ids": (5, 7, True), "requested_api": ("1.41", "1.56")}.items():
            for value in values:
                bad = fixture()
                bad["acquisition"][field] = value
                self.reject(bad)

    def test_private_custody_rejects_links_permissions_nonregular_and_malformed_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "shm-size-v1.json"
            value = fixture()
            text = json.dumps(value)

            def save(payload=text):
                path.write_text(payload)
                path.chmod(0o600)

            def read():
                return reader.read_shm_size_proof(path, root, value["context"])

            save()
            self.assertFalse(read()["catalogue_admission"])
            for payload in (text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                            text.replace('"ipc_namespace": 4001', '"ipc_namespace": NaN'),
                            text.replace('"ipc_namespace": 4001', '"ipc_namespace": Infinity'),
                            text + SECRET, "x" * 16385, "[]", "null", "{"):
                save(payload)
                with self.subTest(payload=payload[:80]), self.assertRaises(ValueError):
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
            alternate = root / "alternate"
            os.link(path, alternate)
            with self.assertRaises(ValueError):
                read()
            alternate.unlink()
            path.rename(alternate)
            path.symlink_to(alternate)
            with self.assertRaises(ValueError):
                read()
            path.unlink()
            alternate.unlink()
            os.mkfifo(path, 0o600)
            with self.assertRaises(ValueError):
                read()
            path.unlink()
            with self.assertRaises(ValueError):
                read()

    def test_held_read_detects_replacement_and_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "shm-size-v1.json"
            value = fixture()
            text = json.dumps(value)
            original_read = os.read
            for replacement in (False, True):
                path.write_text(text)
                path.chmod(0o600)

                def raced_read(descriptor, count):
                    payload = original_read(descriptor, count)
                    if replacement:
                        other = root / "other"
                        other.write_text(text)
                        other.chmod(0o600)
                        other.replace(path)
                    else:
                        path.write_text(text + " ")
                    return payload

                with patch.object(custody.os, "read", side_effect=raced_read), self.assertRaises(ValueError):
                    reader.read_shm_size_proof(path, root, value["context"])

    def test_cli_uses_independent_arguments_and_emits_no_success_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture()
            context = value["context"]
            context["outer"]["socket_source"] = str(root / "socket")
            path = root / "shm-size-v1.json"
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            arguments = [str(root), context["candidate_sha"], context["run_id"], context["lane"], context["engine_release"],
                         context["rendering_api"], context["mode"], context["docker_package"], context["fixture_image"],
                         context["outer"]["image"], context["outer"]["id"], str(context["daemon_uid"])]
            result = subprocess.run([sys.executable, str(ROOT / "scripts/native_shm_size_proof.py"), *arguments],
                                    capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
            arguments[1] = SECRET
            result = subprocess.run([sys.executable, str(ROOT / "scripts/native_shm_size_proof.py"), *arguments],
                                    capture_output=True, text=True, timeout=5, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "invalid private shm size proof")


if __name__ == "__main__":
    unittest.main()
