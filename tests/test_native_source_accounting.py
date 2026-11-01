"""Literal selected-backend totals and floors; synthetic, not native evidence."""

from copy import deepcopy
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from native_source_accounting import outer_snapshot_cost
import native_shm_size_proof as shm
import native_supplementary_groups_proof as groups
import native_kernel_settings_proof as kernel
from test_native_shm_size_proof import fixture as shm_fixture
from test_native_supplementary_groups_proof import fixture as groups_fixture
from test_native_kernel_settings_proof import fixture as kernel_fixture

FAMILIES = ((shm, shm_fixture, "shm_size", (75, 74, 77, 76)),
            (groups, groups_fixture, "supplementary_groups", (75, 74, 77, 76)),
            (kernel, kernel_fixture, "kernel_settings", (71, 70, 73, 72)))


class SourceAccountingTests(unittest.TestCase):
    def test_live_producers_use_checked_pending_reserve_without_duplicate_charges(self):
        lifecycle = (ROOT / "src/native_lifecycle_tests.rs").read_text()
        reserve = lifecycle.split("fn final_snapshot_room(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("matches!(ordinary_calls, 2 | 3)", reserve)
        self.assertIn("checked_add(ordinary_calls + self.snapshot_extra_calls())", reserve)
        self.assertIn("checked_add(ordinary_calls * (65_550 + 8192) + self.snapshot_extra_bytes())", reserve)
        self.assertNotIn(".set(", reserve)
        self.assertIn("fn source_pending_final_snapshot_reserves_one_backend_extra_with_checked_boundaries()", lifecycle)
        for family, normal in (("shm_size", 2), ("supplementary_groups", 2), ("kernel_settings", 3)):
            source = (ROOT / "src" / ("native_" + family + "_tests.rs")).read_text()
            self.assertLess(source.index("let outer_backend = source_outer_backend()"), source.index("BoundOuterCleanupOwner::bind(&run)"))
            self.assertIn(f"outer_backend.final_snapshot_room(calls, bytes, {normal})", source)
            self.assertIn("+ 2 * outer_backend.snapshot_extra_calls()", source)
            self.assertIn("+ 1 + 2 * outer_backend.snapshot_extra_bytes()", source)
            self.assertLess(source.index(".final_snapshot_room(calls, bytes,"), source.index("run.calls.set(calls)"))
            for forbidden in ("charge_outer_snapshot(", "run.calls.set(0)", "run.bytes.set(0)", "run.deadline ="):
                self.assertNotIn(forbidden, source)

    def test_selector_has_no_absent_unknown_or_type_coercing_fallback(self):
        self.assertEqual(outer_snapshot_cost("podman"), (0, 0))
        self.assertEqual(outer_snapshot_cost("docker"), (1, 65536))
        for backend in (None, "", "Docker", "docker\n", " podman", "rootless", "unknown", True, 1, [], {}):
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                outer_snapshot_cost(backend)

    def test_independent_literal_final_totals_and_two_snapshot_byte_floors(self):
        for module, fixture, family, totals in FAMILIES:
            validate = getattr(module, "validate_" + family + "_proof")
            for backend, offset, floor in (("podman", 0, 524289), ("docker", 2, 655361)):
                for lane, lane_offset in (("debian11-rootful", 0), ("debian11-rootless", 0),
                                          ("upstream-rootful", 1), ("upstream-rootless", 1)):
                    with self.subTest(family=family, backend=backend, lane=lane):
                        proof = fixture(lane)
                        expected_calls = totals[offset + lane_offset]
                        proof["accounting"]["ordinary_calls"] = expected_calls
                        proof["accounting"]["ordinary_bytes"] = floor
                        self.assertFalse(validate(proof, proof["context"], outer_backend=backend)["catalogue_admission"])
                        for count in (expected_calls - 1, expected_calls + 1, True):
                            bad = deepcopy(proof)
                            bad["accounting"]["ordinary_calls"] = count
                            with self.assertRaises(ValueError):
                                validate(bad, proof["context"], outer_backend=backend)
                        for size in (floor - 1, 2097153, True):
                            bad = deepcopy(proof)
                            bad["accounting"]["ordinary_bytes"] = size
                            with self.assertRaises(ValueError):
                                validate(bad, proof["context"], outer_backend=backend)
                        proof["accounting"]["ordinary_bytes"] = 2097152
                        validate(proof, proof["context"], outer_backend=backend)
                        for backend_bad in (None, "", "Docker", "unknown", True):
                            with self.assertRaises(ValueError):
                                validate(proof, proof["context"], outer_backend=backend_bad)
                        for field, value in (("lane", "unknown-rootful"), ("mode", "unknown")):
                            bad = deepcopy(proof)
                            bad["context"][field] = value
                            with self.assertRaises(ValueError):
                                validate(bad, bad["context"], outer_backend=backend)

    def test_cli_preserves_twelve_arguments_but_requires_separate_backend(self):
        import json
        for module, fixture, family, totals in FAMILIES:
            for backend in ("podman", "docker", None, "", "Docker", "unknown"):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    proof = fixture()
                    context = proof["context"]
                    context["outer"]["socket_source"] = str(root / "socket")
                    if backend == "docker":
                        proof["accounting"]["ordinary_calls"] = totals[3]
                        proof["accounting"]["ordinary_bytes"] = 655361
                    path = root / module.FILENAME
                    path.write_text(json.dumps(proof))
                    path.chmod(0o600)
                    arguments = [str(root), context["candidate_sha"], context["run_id"], context["lane"],
                                 context["engine_release"], context["rendering_api"], context["mode"],
                                 context["docker_package"], context["fixture_image"], context["outer"]["image"],
                                 context["outer"]["id"], str(context["daemon_uid"])]
                    environment = dict(os.environ)
                    environment.pop("NATIVE_OUTER_ENGINE", None)
                    if backend is not None:
                        environment["NATIVE_OUTER_ENGINE"] = backend
                    result = subprocess.run([sys.executable, str(ROOT / "scripts" / ("native_" + family + "_proof.py")), *arguments],
                                            env=environment, capture_output=True, text=True, timeout=5, check=False)
                    self.assertEqual(result.stdout, "")
                    if backend in ("podman", "docker"):
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stderr.strip(), "invalid private " + family.replace("_", " ") + " proof")


if __name__ == "__main__":
    unittest.main()
