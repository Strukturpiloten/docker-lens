"""Synthetic protocol controls, never real kernel or platform qualification."""

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
import native_kernel_settings_proof as reader
import native_network_attachment_proof as custody
from test_native_external_network_proof import fixture as context_fixture

SECRET = "PRIVATE_KERNEL_SETTINGS_CANARY"


def fixture(lane="upstream-rootful"):
    context = deepcopy(context_fixture(lane)["context"])
    context["fixture_image"] = "docker.io/library/busybox:fixture@sha256:" + "b" * 64
    image = "sha256:" + "d" * 64
    cases = []
    for case_index, (name, flag) in enumerate((("omitted", None), ("false_zero", False), ("true_one", True))):
        containers = []
        for offset, role in enumerate(("oracle", "rendered")):
            number = case_index * 2 + offset + 1
            containers.append({
                "role": role, "id": f"{number:064x}", "name": f"dl-ks-{context['run_id']}-{name}-{role}",
                "owner": context["run_id"], "image_id": image, "wire": "independent_cli" if role == "oracle" else "literal_rendered",
                "security_availability": "null" if flag is None else "present", "sysctls_availability": "empty" if flag is None else "present",
                "effect": {"parent_pid": 1, "parent_ppid": 0, "child_pid": 2, "child_ppid": 1,
                           "parent_nnp": 1 if flag is None else int(flag), "child_nnp": 1 if flag is None else int(flag),
                           "forwarding": 0 if flag is None else int(flag), "net_namespace": 1000 + number, "pid_namespace": 2000 + number,
                           "parent_pre_post_agree": True, "exec_binding": "background_pid_argv_exe_inode_and_proc",
                           "root_corroboration": "same_live_pids_and_namespaces"},
                "running_after": True, "restart_count": 0, "oom_killed": False, "cleanup": "absent",
            })
        cases.append({"case": name, "authored_nnp": flag, "authored_forwarding": None if flag is None else int(flag), "containers": containers})
    return {
        "schema_version": 1, "contract": "kernel-settings-v1", "scope": "diagonal_omitted_false0_true1_only",
        "capability_admission": [], "catalogue_admission": False, "context": context,
        "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"},
        "outer_namespaces": {"net": 1000, "pid": 2000, "unchanged": True}, "cases": cases,
        "acquisition": {"selected_ids": 6, "route": "explicit_unix_socket", "api": context["acquisition_api"],
                        "daemon_mode_evidence": "rootless_observed" if lane.endswith("rootless") else "unknown_with_independent_rootful_context",
                        "reserved_calls": 16, "reserved_body_bytes": 524288, "actual_requests": 9, "actual_body_bytes": 32768,
                        "decoded": "effective_security_and_sysctls_agree", "byte_scope": "decoded_response_bodies_only",
                        "limits": {"max_requests": 16, "max_selected_resources": 6, "max_expansions": 8, "max_response_bytes": 131072,
                                   "max_total_body_bytes": 524288, "max_elapsed_seconds": 10},
                        "separate_transport_bounds": {"response_header_bytes": 16384, "chunk_line_bytes": 64, "chunk_payload_crlf_bytes": 2,
                                                      "final_trailer_line_bytes": 16384, "actual_wire_bytes": "not_measured"}},
        "accounting": {"ordinary_calls": 71 if lane.startswith("debian11-") else 70, "ordinary_bytes": 600000, "cleanup_calls": 54,
                       "cleanup_bytes": 4000, "ordinary_elapsed_ns": 4_000_000_000, "cleanup_elapsed_ns": 2_000_000_000,
                       "elapsed_ns": 7_000_000_000, "deadline_seconds": 180, "cleanup_reserve_seconds": 46,
                       "initial_context_acquisition": {"max_requests": 16, "max_body_bytes": 2097152, "max_elapsed_seconds": 15,
                                                       "accounting": "separate_existing_bound"}},
        "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False},
    }


class KernelSettingsProofTests(unittest.TestCase):
    def reject(self, proof, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private kernel settings proof$") as caught:
            reader.validate_kernel_settings_proof(proof, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_four_lanes_complete_diagonal_controls_and_truthful_omitted_observations(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            value = fixture(lane)
            self.assertEqual(reader.validate_kernel_settings_proof(value, value["context"]),
                             {"contract": "kernel-settings-v1", "capability_admission": [], "catalogue_admission": False})
            # Observations of omitted settings are not a universal default claim.
            for nnp, forwarding in ((0, 0), (1, 1), (0, 1), (1, 0)):
                for item in value["cases"][0]["containers"]:
                    item["effect"].update(parent_nnp=nnp, child_nnp=nnp, forwarding=forwarding)
                for availability in ("missing", "null", "empty"):
                    value["cases"][0]["containers"][0]["security_availability"] = availability
                    value["cases"][0]["containers"][1]["sysctls_availability"] = availability
                    reader.validate_kernel_settings_proof(value, value["context"])

    def test_every_object_is_closed_and_every_field_required(self):
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
                changed = bad
                for part in path:
                    changed = changed[part]
                if key == SECRET:
                    changed[key] = SECRET
                else:
                    del changed[key]
                self.reject(bad)

    def test_explicit_false_cannot_accept_inherited_one_or_unsupported_disposition(self):
        for role in range(2):
            bad = fixture()
            effect = bad["cases"][1]["containers"][role]["effect"]
            effect.update(parent_nnp=1, child_nnp=1)
            self.reject(bad)
            effect["outcome"] = "unsupported_inherited_nnp"
            self.reject(bad)
        for case, value in ((1, 1), (2, 0)):
            for field in ("parent_nnp", "child_nnp", "forwarding"):
                bad = fixture()
                bad["cases"][case]["containers"][0]["effect"][field] = value
                self.reject(bad)
        bad = fixture()
        bad["cases"][2]["authored_forwarding"] = 0
        self.reject(bad)

    def test_genuine_child_exec_and_correlated_state_cannot_be_inspect_only_or_optimized(self):
        changes = {"parent_pid": (0, True, 2), "parent_ppid": (1, True), "child_pid": (0, 1, True, 4194305),
                   "child_ppid": (0, 2, True), "parent_nnp": (-1, 2, True, "1"), "child_nnp": (0, True, 1.0),
                   "forwarding": (-1, 2, True, "0"), "parent_pre_post_agree": (False, 1),
                   "exec_binding": ("tail_exec", "shell_child_unknown", "inspect_only", None),
                   "root_corroboration": ("root_exec_only", "different_pid", "namespace_unverified")}
        for field, values in changes.items():
            for value in values:
                bad = fixture()
                bad["cases"][2]["containers"][1]["effect"][field] = value
                self.reject(bad)

    def test_private_namespace_and_outer_context_ownership_refuse_aliases(self):
        for field, outer in (("net_namespace", "net"), ("pid_namespace", "pid")):
            for alias in ("outer", "other", "zero", "bool", "overflow"):
                bad = fixture()
                value = {"outer": bad["outer_namespaces"][outer], "other": bad["cases"][0]["containers"][0]["effect"][field],
                         "zero": 0, "bool": True, "overflow": 2**64}[alias]
                bad["cases"][1]["containers"][0]["effect"][field] = value
                self.reject(bad)
        # Namespace kinds are separate identities, not one global integer set.
        value = fixture()
        value["cases"][0]["containers"][0]["effect"]["net_namespace"] = value["outer_namespaces"]["pid"]
        reader.validate_kernel_settings_proof(value, value["context"])
        for value in (False, 1, "true"):
            bad = fixture()
            bad["outer_namespaces"]["unchanged"] = value
            self.reject(bad)

    def test_partial_reordered_duplicate_wrong_context_and_admission_refuse(self):
        for change in range(7):
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
            else:
                bad["cases"][2]["authored_nnp"] = 1
            self.reject(bad)
        for section in ("context", "borrowed_image", "cleanup", "accounting", "acquisition"):
            for field in fixture()[section]:
                bad = fixture()
                bad[section][field] = SECRET
                self.reject(bad)
        for field, value in (("schema_version", True), ("scope", "cartesian_and_general_security_effects"),
                             ("capability_admission", ["SecurityOptions"]), ("catalogue_admission", 0)):
            bad = fixture()
            bad[field] = value
            self.reject(bad)

    def test_numeric_budgets_times_and_decoder_claims_fail_closed(self):
        for section, changes in (
            ("acquisition", {"selected_ids": (5, True), "api": ("1.41", "1.56"), "actual_requests": (7, 17, True),
                             "actual_body_bytes": (0, 524289, True), "reserved_calls": (15, 17), "reserved_body_bytes": (524287, 524289),
                             "decoded": ("configured_only", "missing_security", "missing_sysctls")}),
            ("accounting", {"ordinary_calls": (69, 71, True), "ordinary_bytes": (524288, 2097153, True), "cleanup_calls": (53, 55, True),
                            "cleanup_bytes": (0, 552961, True), "ordinary_elapsed_ns": (0, 134000000001, True),
                            "cleanup_elapsed_ns": (0, 46000000001, True), "elapsed_ns": (0, 5999999999, 180000000001, True)})):
            for field, values in changes.items():
                for value in values:
                    bad = fixture()
                    bad[section][field] = value
                    self.reject(bad)

    def test_private_custody_rejects_unsafe_files_and_corrupted_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "kernel-settings-v1.json"
            value = fixture()
            text = json.dumps(value)

            def save(payload=text):
                path.write_text(payload)
                path.chmod(0o600)

            def read():
                return reader.read_kernel_settings_proof(path, root, value["context"])

            save()
            self.assertFalse(read()["catalogue_admission"])
            for payload in ("", "{", "[]", "x" * 16385, text + SECRET,
                            text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                            text.replace('"parent_nnp": 1', '"parent_nnp": NaN'), text.replace('"parent_nnp": 1', '"parent_nnp": Infinity')):
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

    def test_held_mutation_and_independent_twelve_fact_cli_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture()
            context = value["context"]
            context["outer"]["socket_source"] = str(root / "socket")
            text = json.dumps(value)
            path = root / "kernel-settings-v1.json"
            path.write_text(text)
            path.chmod(0o600)
            original_read = os.read

            def mutate(descriptor, count):
                payload = original_read(descriptor, count)
                path.write_text(text + " ")
                return payload

            with patch.object(custody.os, "read", side_effect=mutate), self.assertRaises(ValueError):
                reader.read_kernel_settings_proof(path, root, context)
            path.write_text(text)
            arguments = [str(root), context["candidate_sha"], context["run_id"], context["lane"], context["engine_release"],
                         context["rendering_api"], context["mode"], context["docker_package"], context["fixture_image"],
                         context["outer"]["image"], context["outer"]["id"], str(context["daemon_uid"])]
            result = subprocess.run([sys.executable, str(ROOT / "scripts/native_kernel_settings_proof.py"), *arguments],
                                    text=True, capture_output=True, timeout=5, check=False)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
            arguments[1] = SECRET
            result = subprocess.run([sys.executable, str(ROOT / "scripts/native_kernel_settings_proof.py"), *arguments],
                                    text=True, capture_output=True, timeout=5, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "invalid private kernel settings proof")


if __name__ == "__main__":
    unittest.main()
