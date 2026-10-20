"""Literal raw projection controls; unit fixtures are not native evidence."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_native_evidence as legacy
import test_native_external_network_evidence as canonical
from native_harness_syntax import assert_positive_emitter_rerun, authored_emitter_authority, emitter_cli, run_emitter

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_SHM_SIZE_CANARY"


class ShmSizeEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def test_literal_closed_raw_singleton_on_all_profiles_without_catalogue_admission(self):
        from test_reviewed_catalog import required_shapes

        expected = {"shm_size_contract": "shm-size-v1", "shm_size_outcomes": {
            "admission": "raw_source_only", "catalogue_admission": "unadmitted",
            "scope": "explicit_1MiB_2MiB_with_observed_omission_only",
            "outcome": "tmpfs_effect_and_ipc_isolation_verified",
        }}
        schema = json.loads((legacy.ROOT / "docs/native-evidence.schema.json").read_text())
        definition = schema["$defs"]["shm_size_source_projection"]
        self.assertEqual(definition["type"], "object")
        self.assertFalse(definition["additionalProperties"])
        self.assertEqual(set(definition["required"]), set(expected))
        self.assertEqual(set(definition["properties"]), set(expected))
        self.assertEqual(definition["properties"]["shm_size_contract"], {"const": "shm-size-v1"})
        outcome = definition["properties"]["shm_size_outcomes"]
        self.assertEqual(outcome["type"], "object")
        self.assertFalse(outcome["additionalProperties"])
        self.assertEqual(set(outcome["required"]), set(expected["shm_size_outcomes"]))
        self.assertEqual(outcome["properties"], {key: {"const": value} for key, value in expected["shm_size_outcomes"].items()})
        self.assertNotIn("#/$defs/shm_size_source_projection", json.dumps(schema))
        self.assertEqual(required_shapes()["ShmSize"], ("ShmSize",))
        catalogue = (legacy.ROOT / "src/reviewed_catalog.rs").read_text()
        for prefix in ("REVIEWED", "UPSTREAM"):
            caps = catalogue.split(f"const {prefix}_CAPABILITIES:", 1)[1].split("];", 1)[0]
            shapes = catalogue.split(f"const {prefix}_SHAPES:", 1)[1].split("];", 1)[0]
            self.assertNotIn("Capability::ShmSize,", caps)
            self.assertNotIn("NativeCapabilityShape::ShmSize,", shapes)
        for lane in LANES:
            with self.subTest(lane=lane):
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                raw = destination.read_text()
                record = json.loads(raw)
                self.assertEqual({key: record[key] for key in expected}, expected)
                self.assertEqual(record["admitted_shapes"]["ShmSize"], ["ShmSize"])
                self.assertEqual(record["capability_outcome"]["ShmSize"], "available")
                self.assertEqual(len(record["capability_outcome"]), 43 if lane.startswith("debian11-") else 45)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 66 if lane.startswith("debian11-") else 70)
                self.assertEqual(record["admitted_shapes"]["HealthDisabled"], ["DisabledHealthcheck"])
                for private in ("ipc_namespace", "capacity_bytes", "configured_size_bytes", "statfs_blocks",
                                "statfs_unit", "payload_bytes", "ordinary_elapsed_ns", "acquisition", "borrowed_image",
                                "dl-shm-", legacy.RUN_ID, SECRET):
                    if private == "acquisition":
                        self.assertNotIn('"acquisition":', raw)
                    else:
                        self.assertNotIn(private, raw)

    def test_missing_partial_wrong_context_effect_and_cleanup_refuse_whole_output(self):
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane, shm_size_missing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(destination.exists())
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            assert_positive_emitter_rerun(self, result, destination)
            destination.unlink()
            path = destination.parent.parent / "shm-size-v1.json"
            original = json.loads(path.read_text())
            for mutation in ("partial", "context", "configuration", "effect", "isolation", "default", "cleanup", "extra", "typed"):
                with self.subTest(lane=lane, mutation=mutation):
                    proof = copy.deepcopy(original)
                    if mutation == "partial":
                        proof["cases"].pop()
                    elif mutation == "context":
                        proof["context"]["candidate_sha"] = "e" * 40
                    elif mutation == "configuration":
                        proof["cases"][1]["containers"][1]["configured_size_bytes"] = 2097152
                    elif mutation == "effect":
                        proof["cases"][2]["containers"][1]["write_outcome"] = SECRET
                    elif mutation == "isolation":
                        proof["cases"][2]["containers"][1]["ipc_namespace"] = proof["cases"][0]["containers"][0]["ipc_namespace"]
                    elif mutation == "default":
                        proof["cases"][0]["containers"][1]["capacity_bytes"] = 4194304
                    elif mutation == "cleanup":
                        proof["cleanup"]["uncertain"] = True
                    elif mutation == "typed":
                        proof["catalogue_admission"] = 0
                    else:
                        proof[SECRET] = SECRET
                    path.write_text(json.dumps(proof))
                    rejected = run_emitter(result)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse(destination.exists())
                    self.assertEqual(rejected.stdout, "")
                    self.assertEqual(rejected.stderr.strip(), "native evidence rejected")
            path.write_text(json.dumps(original))

    def test_reader_return_must_match_exact_closed_types_even_after_real_validation(self):
        spec = importlib.util.spec_from_file_location("shm_emitter_return_controls", legacy.SCRIPT)
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)
        valid = {"contract": "shm-size-v1", "capability_admission": [], "catalogue_admission": False}
        invalid = [None, [], False, {}, {**valid, "contract": SECRET}, {**valid, "capability_admission": ()},
                   {**valid, "catalogue_admission": 0}, {**valid, "capability_admission": ["ShmSize"]},
                   {**valid, SECRET: SECRET}]
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            destination.unlink()
            cli = emitter_cli(result)
            paths = [Path(value) for value in cli[:13]]
            arguments = cli[13:]
            real_reader = emitter.read_shm_size_proof
            environment = {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                           "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                           "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("rootless") else "0"}
            with authored_emitter_authority(cli) as outer_context, patch.dict(os.environ, environment):
                emitter.emit(*paths, *arguments, outer_context=outer_context)
            self.assertTrue(destination.exists())
            destination.unlink()
            for value in invalid:
                with self.subTest(lane=lane, value=value):
                    def validated_bad_return(*args):
                        self.assertEqual(real_reader(*args), valid)
                        return copy.deepcopy(value)

                    with authored_emitter_authority(cli) as outer_context, patch.dict(os.environ, environment), \
                            patch.object(emitter, "read_shm_size_proof", side_effect=validated_bad_return) as call:
                        with self.assertRaisesRegex(ValueError, "^incomplete shm-size source group$"):
                            emitter.emit(*paths, *arguments, outer_context=outer_context)
                        self.assertEqual(call.call_count, 1)
                    self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
