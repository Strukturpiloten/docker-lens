"""Mandatory nofile re-reading gates emission without changing public evidence."""
from copy import deepcopy
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import test_native_evidence as legacy
import test_native_external_network_evidence as canonical
from test_native_command_clear_projection import expected_shapes
from test_native_nofile_proof import refuse_case

ROOT = Path(__file__).resolve().parents[1]
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_NOFILE_EMITTER_CANARY"
EMPTY_ADMISSION = {"contract": "nofile-v1", "capability_admission": [], "catalogue_admission": False}


def emitter_module():
    spec = importlib.util.spec_from_file_location("nofile_evidence_control", ROOT / "scripts/native-evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NofileEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit
    emit = canonical.ExternalNetworkEvidenceTests.emit

    def environment(self, lane, backend):
        return {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE, "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("-rootless") else "0",
                "NATIVE_OUTER_ENGINE": backend}

    def rerun(self, result, path, backend):
        return subprocess.run(result.args, env={**os.environ, **self.environment(path.stem, backend)},
                              capture_output=True, text=True, timeout=10, check=False)

    def test_four_lanes_and_both_backends_require_nofile_without_adding_public_projection(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                with self.subTest(lane=lane, backend=backend):
                    result, path = self.emit(lane, outer_backend=backend)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(result.args) - 2, 19)
                    record = json.loads(path.read_text())
                    shapes = expected_shapes(lane)
                    self.assertEqual(record["admitted_shapes"], shapes)
                    self.assertEqual(record["capability_outcome"], dict.fromkeys(shapes, "available"))
                    self.assertEqual(record["pids_contract"], "pids-v2")
                    for withheld in ("Ulimits", "UlimitNofile", "PidsLimit"):
                        self.assertNotIn(withheld, record["capability_outcome"])
                        self.assertNotIn(withheld, record["admitted_shapes"])
                    self.assertNotIn("nofile_contract", record)
                    self.assertNotIn("nofile_outcomes", record)
                    for private in ("owned_files", "descriptors", "retained_count", "dl-nf-", "ordinary_calls", "daemon_uid"):
                        self.assertNotIn(private, path.read_text())
                    result, path = self.emit(lane, outer_backend=backend, nofile_missing=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(path.exists())
                    self.assertFalse(path.parent.exists())
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "native evidence rejected\n")

    def test_truthful_unlimited_dispositions_leave_entire_public_emission_byte_identical(self):
        for backend in ("podman", "docker"):
            result, path = self.emit(outer_backend=backend)
            self.assertEqual(result.returncode, 0, result.stderr)
            original = path.read_bytes()
            source = path.parent.parent / "nofile-v1.json"
            exact = json.loads(source.read_text())
            normalized = deepcopy(exact)
            for index in (2, 3):
                for item in normalized["cases"][index]["containers"]:
                    witness = item["effect"]["witness"]
                    witness["outcome"] = "finite_kernel_normalization"
                    witness["kernel"]["hard"] = 1048576
                    if index == 3:
                        witness["kernel"]["soft"] = 1048576
                    for sample in witness["samples"].values():
                        sample.update(witness["kernel"])
            refused = deepcopy(exact)
            refuse_case(refused, 2)
            refuse_case(refused, 3)
            for disposition, value in (("exact", exact), ("normalized", normalized), ("specific-start-refusal", refused)):
                with self.subTest(backend=backend, disposition=disposition):
                    path.unlink()
                    source.write_text(json.dumps(value))
                    rerun = self.rerun(result, path, backend)
                    self.assertEqual(rerun.returncode, 0, rerun.stderr)
                    self.assertEqual(path.read_bytes(), original)

    def test_context_effect_accounting_and_partial_or_private_packets_refuse_all_output(self):
        changes = {
            "partial": lambda value: value["cases"].pop(),
            "candidate": lambda value: value["context"].update(candidate_sha="f" * 40),
            "run": lambda value: value["context"].update(run_id="Wrong145"),
            "lane": lambda value: value["context"].update(lane="debian11-rootful"),
            "uid": lambda value: value["context"].update(daemon_uid=1),
            "outer": lambda value: value["context"]["outer"].update(id="a" * 64),
            "backend-self-selection": lambda value: value["context"].update(outer_backend="docker"),
            "boolean-accounting": lambda value: value["accounting"].update(ordinary_calls=True),
            "cleanup": lambda value: value["cleanup"].update(uncertain=True),
            "errno": lambda value: value["cases"][0]["containers"][0]["effect"]["witness"]["failure"].update(errno=23),
            "unknown-start": lambda value: value["cases"][2]["containers"][0]["effect"].update(stage="create_refused"),
            "admission": lambda value: value.update(capability_admission=["UlimitNofile"]),
            "private-extra": lambda value: value.update({SECRET: SECRET}),
        }
        for label, change in changes.items():
            with self.subTest(label=label):
                result, path = self.emit(outer_backend="docker")
                self.assertEqual(result.returncode, 0, result.stderr)
                source = path.parent.parent / "nofile-v1.json"
                value = json.loads(source.read_text())
                change(value)
                source.write_text(json.dumps(value))
                path.unlink()
                path.parent.rmdir()
                rerun = self.rerun(result, path, "docker")
                self.assertNotEqual(rerun.returncode, 0)
                self.assertFalse(path.exists())
                self.assertFalse(path.parent.exists())
                self.assertEqual(rerun.stdout, "")
                self.assertEqual(rerun.stderr, "native evidence rejected\n")
                self.assertNotIn(SECRET, rerun.stdout + rerun.stderr)

    def test_custody_size_and_duplicate_keys_are_mandatory_at_emitter_seam(self):
        for fault in ("symlink", "hardlink", "mode", "duplicate", "oversize"):
            with self.subTest(fault=fault):
                result, path = self.emit()
                self.assertEqual(result.returncode, 0, result.stderr)
                source = path.parent.parent / "nofile-v1.json"
                path.unlink()
                path.parent.rmdir()
                if fault == "mode":
                    source.chmod(0o644)
                elif fault == "symlink":
                    original = source.with_name("held-nofile-original")
                    source.rename(original)
                    source.symlink_to(original)
                elif fault == "hardlink":
                    os.link(source, source.with_name("linked-nofile-original"))
                elif fault == "duplicate":
                    source.write_text(source.read_text()[:-1] + ',"schema_version":1}')
                else:
                    source.write_bytes(b"x" * (524288 + 1))
                rerun = self.rerun(result, path, "podman")
                self.assertNotEqual(rerun.returncode, 0)
                self.assertFalse(path.parent.exists())
                self.assertEqual(rerun.stdout, "")
                self.assertEqual(rerun.stderr, "native evidence rejected\n")

    def test_exact_typed_reader_return_and_independent_context_backend_precede_publication(self):
        module = emitter_module()
        self.assertEqual(len(inspect.signature(module.emit).parameters), 19)
        for backend in ("podman", "docker"):
            result, path = self.emit("upstream-rootless", outer_backend=backend)
            self.assertEqual(result.returncode, 0, result.stderr)
            path.unlink()
            path.parent.rmdir()
            arguments = [Path(value) for value in result.args[2:15]] + result.args[15:]
            expected_context = json.loads((path.parent.parent / "nofile-v1.json").read_text())["context"]
            invalid_results = [None, [], {}, {**EMPTY_ADMISSION, "extra": SECRET},
                {**EMPTY_ADMISSION, "contract": "wrong"}, {**EMPTY_ADMISSION, "contract": 1},
                {**EMPTY_ADMISSION, "capability_admission": ()}, {**EMPTY_ADMISSION, "capability_admission": ["Ulimits"]},
                {**EMPTY_ADMISSION, "catalogue_admission": True}, {**EMPTY_ADMISSION, "catalogue_admission": 0}]
            for invalid in invalid_results:
                with (self.subTest(backend=backend, result=invalid),
                      patch.dict(os.environ, self.environment(path.stem, backend), clear=True),
                      patch.object(module, "read_nofile_proof", return_value=invalid) as reader,
                      self.assertRaises(ValueError)):
                    module.emit(*arguments)
                self.assertFalse(path.parent.exists())
                reader.assert_called_once_with(path.parent.parent / "nofile-v1.json", path.parent.parent,
                                               expected_context, outer_backend=backend)
            with (patch.dict(os.environ, self.environment(path.stem, backend), clear=True),
                  patch.object(module, "read_nofile_proof", wraps=module.read_nofile_proof) as reader):
                module.emit(*arguments)
            self.assertTrue(path.exists())
            reader.assert_called_once_with(path.parent.parent / "nofile-v1.json", path.parent.parent,
                                           expected_context, outer_backend=backend)


if __name__ == "__main__":
    unittest.main()
