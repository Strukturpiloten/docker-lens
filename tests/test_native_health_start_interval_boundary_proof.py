"""Independently authored inert boundary controls, never native qualification."""

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from test_native_external_network_proof import fixture as context_fixture
import native_health_start_interval_boundary_proof as reader
import native_network_attachment_proof as private_reader

SECRET = "PRIVATE_HEALTH_BOUNDARY_CANARY"
FILENAME = "health-start-interval-boundary-v1.json"
CONTRACT = "health-start-interval-boundary-v1"
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
HEALTH = {"Test": ["CMD-SHELL", "exit 1"], "Interval": 8_000_000_000,
          "Timeout": 1_000_000_000, "Retries": 3, "StartPeriod": 30_000_000_000}
STATE = {"Status": "created", "Running": False, "Pid": 0,
         "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z",
         "OOMKilled": False, "Restarting": False, "Paused": False,
         "Dead": False, "ExitCode": 0, "Error": ""}


def fixture(lane="upstream-rootful"):
    """Authored expected observations; no producer constants or emitted records."""
    context = context_fixture(lane)["context"]
    image_id = "sha256:" + "d" * 64
    cases = []
    for case_index, case in enumerate(("omitted", "zero")):
        records = []
        for role_index, role in enumerate(("oracle", "rendered")):
            cli = role == "oracle"
            refused = lane.startswith("debian11-") and case == "zero" and cli
            records.append({
                "role": role, "name": f"dl-hsi-{context['run_id']}-{case}-{role}",
                "owner": context["run_id"], "image": context["fixture_image"],
                "wire": "independent_cli" if cli else "literal_rendered",
                "request_intent": "omitted" if case == "omitted" else "explicit_zero",
                "request_member": "not_observed" if cli else "absent" if case == "omitted" else "integer_zero",
                "result": "client_unknown_flag" if refused else "accepted",
                "client_exit": 125 if refused else 0 if cli else None,
                "server_status": None if cli else 201,
                "id": None if refused else str(1 + 2 * case_index + role_index) * 64,
                "image_id": None if refused else image_id,
                "configured": None if refused else {"Config": {"Healthcheck": copy.deepcopy(HEALTH)}},
                "readback_state": None if refused else "absent",
                "state": None if refused else copy.deepcopy(STATE),
                "restart_count": None if refused else 0,
                "cleanup": "absent",
            })
        cases.append({"case": case, "records": records})
    return {"schema_version": 1, "contract": CONTRACT, "context": context,
            "admission": "unadmitted", "scope": "created_configuration_only",
            "apis": {"fixture_cli": context["rendering_api"], "renderer": context["rendering_api"],
                     "request": context["rendering_api"], "health_probe": "test_local_unadmitted"},
            "borrowed_image": {"id": image_id, "identity": "unchanged", "removal": "not_owned"},
            "budget": {"limit_seconds": 180, "cleanup_reserve_seconds": 46, "elapsed_ns": 5_000_000_000},
            "cases": cases,
            "cleanup": {"containers": "absent", "rounds": 2, "ledger_slots": 4,
                        "outstanding": 0, "uncertain": False}}


class HealthBoundaryProofTests(unittest.TestCase):
    def reject(self, proof, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private health start interval boundary proof$") as caught:
            reader.validate_health_start_interval_boundary_proof(
                proof, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_four_exact_lanes_have_fixed_distinct_client_outcomes(self):
        for lane in LANES:
            proof = fixture(lane)
            self.assertEqual(reader.validate_health_start_interval_boundary_proof(proof, proof["context"]),
                {"contract": CONTRACT, "admission": "unadmitted",
                 "outcomes": ["omission_configured_absent", "literal_zero_configured_absent",
                              "cli_zero_client_unknown_flag" if lane.startswith("debian11-")
                              else "cli_zero_configured_absent"]})

    def test_raw_absent_null_zero_positive_and_wrong_type_are_not_equivalent(self):
        self.assertEqual(reader.classify_start_interval({"Config": {"Healthcheck": {}}}), "absent")
        for value, wanted in ((None, "null"), (0, "present_zero"), (1, "present_positive"),
                              (2 ** 64 - 1, "present_positive"), (True, "wrong_type"),
                              (False, "wrong_type"), (-1, "wrong_type"), (0.0, "wrong_type"),
                              (2 ** 64, "wrong_type"), (SECRET, "wrong_type"),
                              ([], "wrong_type"), ({}, "wrong_type")):
            with self.subTest(value=value):
                self.assertEqual(reader.classify_start_interval(
                    {"Config": {"Healthcheck": {"StartInterval": value}}}), wanted)

    def test_missing_null_and_malformed_parents_refuse_separately(self):
        for value in (None, [], {}, {"Config": None}, {"Config": False},
                      {"Config": []}, {"Config": SECRET}, {"Config": {}},
                      {"Config": {"Healthcheck": None}}, {"Config": {"Healthcheck": []}},
                      {"Config": {"Healthcheck": False}}, {"Config": {"Healthcheck": SECRET}}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "^invalid private health start interval boundary proof$"):
                    reader.classify_start_interval(value)
                proof = fixture()
                proof["cases"][0]["records"][0]["configured"] = value
                self.reject(proof)

    def test_present_interval_never_passes_the_fixed_absence_observation(self):
        for value, state in ((None, "null"), (0, "present_zero"), (1, "present_positive"),
                              (True, "wrong_type"), (SECRET, "wrong_type")):
            for case in range(2):
                for role in range(2):
                    proof = fixture()
                    record = proof["cases"][case]["records"][role]
                    record["configured"]["Config"]["Healthcheck"]["StartInterval"] = value
                    record["readback_state"] = state
                    self.reject(proof)

    def test_type_sensitive_nested_health_and_created_state_controls(self):
        for field, replacements in {
            "Test": [["CMD", "exit 1"], ["CMD-SHELL", SECRET], "exit 1"],
            "Interval": [None, True, 0, 8_000_000_000.0],
            "Timeout": [0, False, 1_000_000_000.0],
            "Retries": [3.0, True, 0], "StartPeriod": [None, 0, 30_000_000_000.0],
        }.items():
            for replacement in replacements:
                proof = fixture()
                proof["cases"][0]["records"][0]["configured"]["Config"]["Healthcheck"][field] = replacement
                self.reject(proof)
        for field, replacements in {
            "Status": ["running", "exited", SECRET], "Running": [True, 0], "Pid": [False, 1],
            "StartedAt": ["2026-10-11T00:00:00Z", None], "FinishedAt": [None, ""],
            "OOMKilled": [True, 0], "Restarting": [True, 0], "Paused": [True, 0],
            "Dead": [True, 0], "ExitCode": [False, 1], "Error": [SECRET, None],
        }.items():
            for replacement in replacements:
                proof = fixture()
                proof["cases"][0]["records"][0]["state"][field] = replacement
                self.reject(proof)

    def test_case_order_roles_intent_and_wire_are_independent_and_closed(self):
        for field, replacements in {
            "role": ["rendered", SECRET], "wire": ["literal_rendered", SECRET],
            "request_intent": ["explicit_zero", 0, None],
            "request_member": ["absent", "integer_zero", SECRET],
            "readback_state": ["present_zero", 0, None], "restart_count": [False, 1],
        }.items():
            for replacement in replacements:
                proof = fixture()
                proof["cases"][0]["records"][0][field] = replacement
                self.reject(proof)
        for action in (lambda p: p["cases"].reverse(), lambda p: p["cases"].pop(),
                       lambda p: p["cases"].append(copy.deepcopy(p["cases"][0])),
                       lambda p: p["cases"][0]["records"].reverse(),
                       lambda p: p["cases"][0]["records"].pop()):
            proof = fixture()
            action(proof)
            self.reject(proof)
        proof = fixture()
        proof["cases"][1]["records"][1]["request_member"] = "absent"
        self.reject(proof)

    def test_client_refusal_cannot_be_server_rejection_or_arbitrary_failure(self):
        for lane in ("debian11-rootful", "debian11-rootless"):
            for field, replacements in {
                "result": ["accepted", "server_rejected", "unavailable", SECRET],
                "client_exit": [0, 1, 124, True, None], "server_status": [400, 500, 201],
                "id": ["a" * 64], "image_id": ["sha256:" + "d" * 64],
                "configured": [{"Config": {"Healthcheck": HEALTH}}],
                "readback_state": ["absent"], "state": [STATE], "restart_count": [0],
            }.items():
                for replacement in replacements:
                    proof = fixture(lane)
                    proof["cases"][1]["records"][0][field] = replacement
                    self.reject(proof, proof["context"])
        for case in range(2):
            for role in range(2):
                for field, replacement in (("result", "client_unknown_flag"),
                                            ("server_status", 400), ("client_exit", 125)):
                    proof = fixture()
                    proof["cases"][case]["records"][role][field] = replacement
                    self.reject(proof)

    def test_exact_identity_original_image_and_outer_collision_controls(self):
        for field, replacements in {
            "id": [None, "A" * 64, "a" * 63, "f" * 64],
            "name": [SECRET, "dl-hsi-Ab12Cd34-zero-oracle"],
            "owner": [SECRET], "image": [SECRET],
            "image_id": [None, "sha256:" + "e" * 64], "cleanup": ["unknown", None],
        }.items():
            for replacement in replacements:
                proof = fixture()
                proof["cases"][0]["records"][0][field] = replacement
                self.reject(proof)
        proof = fixture()
        proof["cases"][1]["records"][1]["id"] = proof["cases"][0]["records"][0]["id"]
        self.reject(proof)
        for field, replacement in (("id", "invalid"), ("identity", "changed"), ("removal", "owned")):
            proof = fixture()
            proof["borrowed_image"][field] = replacement
            self.reject(proof)

    def test_independent_context_and_exact_version_boundaries(self):
        for field, replacement in (("candidate_sha", "b" * 40), ("run_id", "Cd34Ab12"),
                                  ("lane", "upstream-rootless"), ("daemon_uid", 1000),
                                  ("rendering_api", "1.49"), ("engine_release", "29.8.0")):
            proof = fixture()
            proof["context"][field] = replacement
            self.reject(proof)
            if field != "candidate_sha":
                self.reject(proof, proof["context"])
            else:
                # The independently supplied caller context is the binding;
                # the reader must not hardcode one historical candidate SHA.
                self.assertEqual(reader.validate_health_start_interval_boundary_proof(
                    proof, proof["context"])["admission"], "unadmitted")
        for lane in LANES:
            for field, replacement in (("acquisition_api", "1.50"), ("rendering_api", "1.44"),
                                      ("docker_package", "20.10.5+dfsg1-1+deb11u1")):
                proof = fixture(lane)
                proof["context"][field] = replacement
                self.reject(proof, proof["context"])
        for field in ("fixture_cli", "renderer", "request", "health_probe"):
            proof = fixture()
            proof["apis"][field] = SECRET
            self.reject(proof)

    def test_deadlines_cleanup_and_admission_cannot_be_relaxed(self):
        for field, replacements in {
            "limit_seconds": [181, 0, True], "cleanup_reserve_seconds": [45, 47, True],
            "elapsed_ns": [0, -1, True, 180_000_000_001, 5_000_000_000.0],
        }.items():
            for replacement in replacements:
                proof = fixture()
                proof["budget"][field] = replacement
                self.reject(proof)
        for field, replacements in {
            "containers": ["unknown", "outer_teardown_requested"], "rounds": [1, True],
            "ledger_slots": [6, True], "outstanding": [1, False], "uncertain": [True, 0],
        }.items():
            for replacement in replacements:
                proof = fixture()
                proof["cleanup"][field] = replacement
                self.reject(proof)
        for field, replacement in (("schema_version", True), ("contract", "lifecycle-v1"),
                                  ("admission", "admitted"), ("scope", "health_scheduler_effect")):
            proof = fixture()
            proof[field] = replacement
            self.reject(proof)

    def test_every_schema_key_is_required_and_extra_keys_refuse(self):
        paths = [(), ("apis",), ("borrowed_image",), ("budget",), ("cleanup",),
                 ("cases", 0), ("cases", 0, "records", 0),
                 ("cases", 0, "records", 0, "configured"),
                 ("cases", 0, "records", 0, "configured", "Config"),
                 ("cases", 0, "records", 0, "configured", "Config", "Healthcheck"),
                 ("cases", 0, "records", 0, "state")]
        for path in paths:
            baseline = fixture()
            node = baseline
            for part in path:
                node = node[part]
            for key in tuple(node):
                proof = fixture()
                node = proof
                for part in path:
                    node = node[part]
                del node[key]
                self.reject(proof)
            proof = fixture()
            node = proof
            for part in path:
                node = node[part]
            node[SECRET] = SECRET
            self.reject(proof)

    def test_private_reader_requires_exact_owner_private_stable_file(self):
        proof = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            path = directory / FILENAME
            path.write_text(json.dumps(proof))
            os.chmod(path, 0o600)
            expected = reader.validate_health_start_interval_boundary_proof(proof, proof["context"])
            self.assertEqual(reader.read_health_start_interval_boundary_proof(path, directory, proof["context"]), expected)
            for mode in (0o644, 0o400, 0o000):
                os.chmod(path, mode)
                self.assert_read_rejected(path, directory, proof)
            os.chmod(path, 0o600)
            alias = directory / "alias.json"
            os.link(path, alias)
            self.assert_read_rejected(path, directory, proof)
            alias.unlink()
            self.assert_read_rejected(alias, directory, proof)
            alias.symlink_to(path)
            self.assert_read_rejected(alias, directory, proof)
            alias.unlink()
            for mode in (0o755, 0o600):
                os.chmod(directory, mode)
                self.assert_read_rejected(path, directory, proof)
            os.chmod(directory, 0o700)
            path.unlink()
            path.symlink_to(directory / "missing")
            self.assert_read_rejected(path, directory, proof)

    def assert_read_rejected(self, path, directory, proof):
        with self.assertRaisesRegex(ValueError, "^invalid private health start interval boundary proof$") as caught:
            reader.read_health_start_interval_boundary_proof(path, directory, proof["context"])
        self.assertNotIn(SECRET, str(caught.exception))

    def test_private_reader_rejects_duplicate_stale_overbound_and_racing_payloads(self):
        proof = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / FILENAME
            for payload in ("", "{" + f'"schema_version":1,"schema_version":1,"{SECRET}":0' + "}",
                            SECRET * 2000, json.dumps(fixture("debian11-rootful")), "null"):
                path.write_text(payload)
                os.chmod(path, 0o600)
                self.assert_read_rejected(path, directory, proof)
            path.write_text(json.dumps(proof))
            os.chmod(path, 0o600)
            with patch.object(private_reader.os, "read", return_value=b"{}"):  # short/truncated read
                self.assert_read_rejected(path, directory, proof)
            with patch.object(private_reader, "fingerprint", side_effect=range(100)):
                self.assert_read_rejected(path, directory, proof)

    def test_private_cli_envelope_preserves_status_stdout_and_trailing_stderr(self):
        # Exercise only the actual shell framing with inert local printf stubs.
        # No Docker/Podman command is executed and no daemon is contacted.
        rust = (ROOT / "src/native_health_start_interval_boundary_tests.rs").read_text()
        match = re.search(r'"(export LC_ALL=C; printf (?:\\.|[^"\\])*)"\s*\.into\(\)', rust)
        self.assertIsNotNone(match)
        envelope = json.loads('"' + match[1] + '"')

        def run(command):
            completed = subprocess.run(["sh", "-c", envelope, "inert-boundary-envelope", "sh", "-c", command],
                                       capture_output=True, timeout=3, check=False)
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, b"")
            return completed.stdout

        native_id = "a" * 64
        self.assertEqual(run(f"printf '%s\\n' '{native_id}'; exit 0"),
                         f"stdout\n{native_id}\n\x01stderr\n\x01status=0\n".encode())
        signature = b"stdout\n\x01stderr\nunknown flag: --health-start-interval\nSee 'docker create --help'.\n\x01status=125\n"
        rejection = "printf '%s\\n' 'unknown flag: --health-start-interval' \"See 'docker create --help'.\" >&2; exit 125"
        self.assertEqual(run(rejection), signature)
        for changed in (rejection.replace("125", "1"), rejection.replace("125", "124"),
                        rejection.replace(" >&2", ""), rejection.replace("; exit 125", "; printf '\\n' >&2; exit 125"),
                        "printf 'server rejected\\n' >&2; exit 125"):
            self.assertNotEqual(run(changed), signature)


if __name__ == "__main__":
    unittest.main()
