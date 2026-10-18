"""Literal two-family projections and whole-output refusal; not native evidence."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_native_evidence as legacy
import test_native_external_network_evidence as canonical

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_RUNTIME_SETTINGS_CANARY"
EXPECTED = {
    "supplementary_groups": {
        "contract": "supplementary-groups-v1",
        "outcomes": {"admission": "raw_source_only", "catalogue_admission": "unadmitted",
                     "scope": "numeric_nonroot_omitted_one_two_groups_only",
                     "outcome": "pid1_membership_and_dac_effects_verified"},
        "shapes": {"SupplementaryGroups": ["SupplementaryGroups"]},
    },
    "kernel_settings": {
        "contract": "kernel-settings-v1",
        "outcomes": {"admission": "raw_source_only", "catalogue_admission": "unadmitted",
                     "scope": "diagonal_omitted_false0_true1_only",
                     "outcome": "pid1_exec_inheritance_and_private_namespaces_verified"},
        "shapes": {"SecurityOptions": ["NoNewPrivilegesEnabled", "NoNewPrivilegesDisabled"],
                   "Sysctls": ["Sysctls"], "SysctlIpv4Forward": ["SysctlIpv4Forward"]},
    },
}


class RuntimeSettingsEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def test_literal_complete_groups_closed_schema_privacy_and_unchanged_catalogue(self):
        from test_reviewed_catalog import required_shapes

        schema = json.loads((legacy.ROOT / "docs/native-evidence.schema.json").read_text())
        catalogue = (legacy.ROOT / "src/reviewed_catalog.rs").read_text()
        for family, expected in EXPECTED.items():
            definition = schema["$defs"][family + "_source_projection"]
            self.assertEqual(definition["type"], "object")
            self.assertFalse(definition["additionalProperties"])
            self.assertEqual(set(definition["required"]), {family + "_contract", family + "_outcomes"})
            self.assertEqual(set(definition["properties"]), set(definition["required"]))
            self.assertEqual(definition["properties"][family + "_contract"], {"const": expected["contract"]})
            outcomes = definition["properties"][family + "_outcomes"]
            self.assertEqual(outcomes["type"], "object")
            self.assertFalse(outcomes["additionalProperties"])
            self.assertEqual(set(outcomes["required"]), set(expected["outcomes"]))
            self.assertEqual(outcomes["properties"], {key: {"const": value} for key, value in expected["outcomes"].items()})
            self.assertNotIn("#/$defs/" + family + "_source_projection", json.dumps(schema))
            for capability, shapes in expected["shapes"].items():
                self.assertEqual(required_shapes()[capability], tuple(shapes))
                for prefix in ("REVIEWED", "UPSTREAM"):
                    caps = catalogue.split(f"const {prefix}_CAPABILITIES:", 1)[1].split("];", 1)[0]
                    self.assertNotIn("Capability::" + capability + ",", caps)
                    selected = catalogue.split(f"const {prefix}_SHAPES:", 1)[1].split("];", 1)[0]
                    for shape in shapes:
                        self.assertNotIn("NativeCapabilityShape::" + shape + ",", selected)
        for lane in LANES:
            with self.subTest(lane=lane):
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                raw = destination.read_text()
                record = json.loads(raw)
                for family, expected in EXPECTED.items():
                    self.assertEqual(record[family + "_contract"], expected["contract"])
                    self.assertEqual(record[family + "_outcomes"], expected["outcomes"])
                    for capability, shapes in expected["shapes"].items():
                        self.assertEqual(record["capability_outcome"][capability], "available")
                        self.assertEqual(record["admitted_shapes"][capability], shapes)
                self.assertEqual(len(record["capability_outcome"]), 43 if lane.startswith("debian11-") else 45)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 66 if lane.startswith("debian11-") else 70)
                for private in (SECRET, "dl-sg-", "dl-ks-", legacy.RUN_ID, "parent_nnp", "child_nnp",
                                "net_namespace", "pid_namespace", "effective_capabilities", "kernel_groups",
                                "root_corroboration", "ordinary_elapsed_ns", '"acquisition":'):
                    self.assertNotIn(private, raw)
                for excluded in ("Ulimits", "UlimitNofile", "LinuxCapabilities", "MemoryLimit", "DeviceMappings", "PidsLimit"):
                    self.assertNotIn(excluded, record["capability_outcome"])
                self.assertNotIn("pids_limit_contract", record)
                self.assertNotIn("pids_limit_outcomes", record)

    def test_missing_partial_wrong_context_effect_and_cleanup_refuse_entire_output(self):
        for lane in LANES:
            for family, expected in EXPECTED.items():
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane, **{family + "_missing": True})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                path = destination.parent.parent / (expected["contract"] + ".json")
                original = json.loads(path.read_text())
                destination.unlink()
                for mutation in ("partial", "context", "configuration", "effect", "cleanup", "acquisition", "budget", "extra", "typed"):
                    with self.subTest(lane=lane, family=family, mutation=mutation):
                        proof = copy.deepcopy(original)
                        if mutation == "partial":
                            proof["cases"].pop()
                        elif mutation == "context":
                            proof["context"]["candidate_sha"] = "e" * 40
                        elif mutation == "configuration":
                            proof["cases"][1]["authored_groups" if family == "supplementary_groups" else "authored_forwarding"] = SECRET
                        elif mutation == "effect":
                            effect = proof["cases"][1]["containers"][0]["effect"]
                            if family == "supplementary_groups":
                                effect["files"][0]["outcome"] = SECRET
                            else:
                                effect["parent_nnp"] = 1  # Explicit false cannot accept inherited one.
                        elif mutation == "cleanup":
                            proof["cleanup"]["uncertain"] = True
                        elif mutation == "acquisition":
                            proof["acquisition"]["selected_ids"] = 5
                        elif mutation == "budget":
                            proof["accounting"]["ordinary_calls"] = 0
                        elif mutation == "typed":
                            proof["catalogue_admission"] = 0
                        else:
                            proof[SECRET] = SECRET
                        path.write_text(json.dumps(proof))
                        canonical.ExternalNetworkEvidenceTests.rerun(self, result, destination)
                path.write_text(json.dumps(original))

    def test_exact_closed_reader_returns_required_after_real_validation(self):
        spec = importlib.util.spec_from_file_location("runtime_settings_emitter", legacy.SCRIPT)
        emitter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(emitter)
        for lane in LANES:
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            destination.unlink()
            paths, arguments = [Path(value) for value in result.args[2:15]], result.args[15:]
            for family, expected in EXPECTED.items():
                valid = {"contract": expected["contract"], "capability_admission": [], "catalogue_admission": False}
                invalid = [None, [], False, {}, {**valid, "contract": SECRET}, {**valid, "capability_admission": ()},
                           {**valid, "catalogue_admission": 0}, {**valid, "capability_admission": ["Sysctls"]},
                           {**valid, SECRET: SECRET}]
                real = getattr(emitter, "read_" + family + "_proof")
                for value in invalid:
                    with self.subTest(lane=lane, family=family, value=value):
                        def wrong_return(*args):
                            self.assertEqual(real(*args), valid)
                            return copy.deepcopy(value)

                        with patch.dict(os.environ, {"NATIVE_FIXTURE_IMAGE": legacy.HEALTH_FIXTURE_IMAGE,
                                                     "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                                     "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("rootless") else "0"}), \
                                patch.object(emitter, "read_" + family + "_proof", side_effect=wrong_return) as call:
                            with self.assertRaisesRegex(ValueError, "^incomplete " + family.replace("_", "-") + " source group$"):
                                emitter.emit(*paths, *arguments)
                            self.assertEqual(call.call_count, 1)
                        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
