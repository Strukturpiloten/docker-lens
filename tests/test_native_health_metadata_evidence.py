"""Emitter admission requires the entire independent health protocol."""

import copy
import json
import unittest

import test_native_evidence as legacy
from native_harness_syntax import assert_positive_emitter_rerun, run_emitter
from test_native_health_metadata_proof import P, context, proof


class HealthMetadataEvidenceTests(unittest.TestCase):
    run_emit = legacy.NativeEvidenceTests.run_emit

    def version(self, lane):
        return {"Version": "20.10.5+dfsg1" if lane.startswith("debian") else "29.8.1",
                "ApiVersion": "1.41" if lane.startswith("debian") else "1.56",
                "MinAPIVersion": "1.12" if lane.startswith("debian") else "1.44"}

    def emit(self, lane="upstream-rootful", health=None):
        mode = lane.rsplit("-", 1)[1]
        image = (f"ghcr.io/strukturpiloten/docker-debian-11-{mode}:v1.0.0" if lane.startswith("debian") else
                 f"ghcr.io/strukturpiloten/docker-29-{mode}:v29.8.1") + "@sha256:" + "b" * 64
        return self.run_emit(self.version(lane), lane=lane, mode=lane.rsplit("-", 1)[1],
                             image=image,
                             package="20.10.5+dfsg1-1+deb11u2" if lane.startswith("debian") else "",
                             health_metadata=health)

    def test_complete_groups_and_only_closed_projection_for_all_lanes(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                result, destination = self.emit(lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(destination.read_text())
                self.assertEqual(record["candidate_sha"], legacy.SHA)
                self.assertEqual(record["health_metadata_contract"], "health-metadata-v1")
                self.assertEqual(record["health_metadata_probes"], ["ContainerCreateLabels", "ShellHealthcheck",
                                                                   "HealthStartPeriodPositive", "HealthStartPeriodZero"])
                for capability, shapes in (("ContainerLabels", ["ContainerCreateLabels"]),
                                            ("HealthShell", ["ShellHealthcheck"]),
                                            ("HealthStartPeriod", ["HealthStartPeriodZero", "HealthStartPeriodPositive"])):
                    self.assertEqual(record["admitted_shapes"][capability], shapes)
                    self.assertEqual(record["capability_outcome"][capability], "available")
                self.assertEqual(record["admitted_shapes"]["HealthDisabled"], ["DisabledHealthcheck"])
                self.assertEqual(record["capability_outcome"]["HealthDisabled"], "available")
                self.assertEqual("HealthStartInterval" in record["admitted_shapes"], not lane.startswith("debian11-"))
                for private in ("StartedAt", "started_at", "regression_observed_at", "dl-health-",
                                "inherited_failure", "disabled_gap_ns", "initial_attempts", "Ab12Cd34"):
                    self.assertNotIn(private, destination.read_text())

    def test_disabled_singleton_is_closed_raw_only_on_all_four_exact_profiles(self):
        import test_native_external_network_evidence as canonical
        from test_reviewed_catalog import required_shapes

        expected = {
            "health_disabled_contract": "health-metadata-v1",
            "health_disabled_outcomes": {
                "admission": "raw_source_only", "catalogue_admission": "unadmitted",
                "outcome": "disabled_health_suppression_verified",
            },
        }
        schema = json.loads((legacy.ROOT / "docs/native-evidence.schema.json").read_text())
        definition = schema["$defs"]["health_disabled_source_projection"]
        self.assertEqual(definition["type"], "object")
        self.assertFalse(definition["additionalProperties"])
        self.assertEqual(set(definition["required"]), set(expected))
        self.assertEqual(set(definition["properties"]), set(expected))
        self.assertEqual(definition["properties"]["health_disabled_contract"], {"const": "health-metadata-v1"})
        outcome = definition["properties"]["health_disabled_outcomes"]
        self.assertEqual(outcome["type"], "object")
        self.assertFalse(outcome["additionalProperties"])
        self.assertEqual(set(outcome["required"]), set(expected["health_disabled_outcomes"]))
        self.assertEqual(outcome["properties"], {
            key: {"const": value} for key, value in expected["health_disabled_outcomes"].items()})
        self.assertNotIn("#/$defs/health_disabled_source_projection", json.dumps(schema))
        self.assertEqual(required_shapes()["HealthDisabled"], ("DisabledHealthcheck",))
        catalogue = (legacy.ROOT / "src/reviewed_catalog.rs").read_text()
        for prefix in ("REVIEWED", "UPSTREAM"):
            capabilities = catalogue.split(f"const {prefix}_CAPABILITIES:", 1)[1].split("];", 1)[0]
            shapes = catalogue.split(f"const {prefix}_SHAPES:", 1)[1].split("];", 1)[0]
            self.assertNotIn("Capability::HealthDisabled,", capabilities)
            self.assertNotIn("NativeCapabilityShape::DisabledHealthcheck,", shapes)
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                # Explicit unit fixtures only, not authenticated native evidence.
                self.assertEqual(P.validate_health_metadata_proof(proof(lane), *context(lane)), [
                    "ContainerCreateLabels", "ShellHealthcheck", "HealthStartPeriodPositive", "HealthStartPeriodZero"])
                result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(destination.read_text())
                self.assertEqual({key: record[key] for key in expected}, expected)
                self.assertEqual(record["admitted_shapes"]["HealthDisabled"], ["DisabledHealthcheck"])
                self.assertEqual(record["capability_outcome"]["HealthDisabled"], "available")
                self.assertEqual(len(record["capability_outcome"]), 43 if lane.startswith("debian11-") else 45)
                self.assertEqual(sum(map(len, record["admitted_shapes"].values())), 66 if lane.startswith("debian11-") else 70)
                self.assertEqual(record["health_metadata_probes"], ["ContainerCreateLabels", "ShellHealthcheck",
                                                                   "HealthStartPeriodPositive", "HealthStartPeriodZero"])

    def test_every_disabled_and_inherited_control_is_mandatory_before_any_output(self):
        import test_native_external_network_evidence as canonical

        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane, health_metadata_missing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(destination.exists())
            result, destination = canonical.ExternalNetworkEvidenceTests.emit(self, lane)
            self.assertEqual(result.returncode, 0, result.stderr)
            assert_positive_emitter_rerun(self, result, destination)
            destination.unlink()
            path = destination.parent.parent / "health-metadata.json"
            original = json.loads(path.read_text())
            mutations = []
            for field, value in (("candidate_sha", "e" * 40), ("cleanup", "uncertain"),
                                 ("PRIVATE_HEALTH_CANARY", "PRIVATE_HEALTH_CANARY")):
                changed = copy.deepcopy(original)
                changed[field] = value
                mutations.append((field, changed))
            for index in (2, 3):
                changed = copy.deepcopy(original)
                changed["cases"].pop(index)
                mutations.append((f"case{index}-missing", changed))
                changed = copy.deepcopy(original)
                changed["cases"][index]["wire"] = "failed"
                mutations.append((f"case{index}-wire", changed))
                for role in (0, 1):
                    changed = copy.deepcopy(original)
                    changed["cases"][index]["containers"].pop(role)
                    mutations.append((f"case{index}-role{role}-missing", changed))
                    effects = {"initial_state": "starting", "health_config": "failed", "running": "failed",
                               "cleanup": "uncertain", "PRIVATE_HEALTH_CANARY": "PRIVATE_HEALTH_CANARY"}
                    if index == 2:
                        effects.update({"health_sentinel": "absent", "initial_attempts": [], "initial_streak": 0})
                    else:
                        effects.update({"health_sentinel": "present", "disabled_gap_ns": 1_999_999_999,
                                        "initial_streak": 1, "initial_attempts": original["cases"][2]["containers"][0]["initial_attempts"]})
                    for field, value in effects.items():
                        changed = copy.deepcopy(original)
                        changed["cases"][index]["containers"][role][field] = value
                        mutations.append((f"case{index}-role{role}-{field}", changed))
            for field in ("derived_image", "seed_container"):
                changed = copy.deepcopy(original)
                changed[field]["cleanup"] = "uncertain"
                mutations.append((field + "-cleanup", changed))
            for mutation, value in mutations:
                with self.subTest(lane=lane, mutation=mutation):
                    path.write_text(json.dumps(value))
                    rejected = run_emitter(result)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse(destination.exists())
                    self.assertEqual(rejected.stdout, "")
                    self.assertEqual(rejected.stderr.strip(), "native evidence rejected")
            path.write_text(json.dumps(original))

    def test_partial_foreign_or_late_only_health_proof_refuses_entire_manifest(self):
        original = proof()
        invalid = [{}, {**original, "private-canary": "PRIVATE_HEALTH_CANARY"}]
        foreign = copy.deepcopy(original)
        foreign["candidate_sha"] = "c" * 40
        invalid.append(foreign)
        partial = copy.deepcopy(original)
        partial["shapes"].pop()
        invalid.append(partial)
        late = copy.deepcopy(original)
        late["cases"][0]["containers"][0]["regression_observed_at"] = "2026-10-07T00:00:21.000000000Z"
        invalid.append(late)
        for value in invalid:
            with self.subTest():
                result, destination = self.emit(health=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())
                self.assertNotIn("PRIVATE_HEALTH_CANARY", result.stderr + result.stdout)
                self.assertIn("native evidence rejected", result.stderr)

    def test_omitted_mandatory_file_refuses_whole_manifest(self):
        result, destination = self.run_emit(self.version("upstream-rootful"), health_metadata_missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())

    def test_other_api_profile_cannot_borrow_health_qualification(self):
        version = self.version("upstream-rootful")
        version["ApiVersion"] = "1.52"
        result, destination = self.run_emit(version)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(destination.exists())
