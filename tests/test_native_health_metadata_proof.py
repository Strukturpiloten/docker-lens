"""Independent timestamp, effect, ownership and private-file proof controls."""

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("health_metadata", ROOT / "scripts/native_health_metadata_proof.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
SHAPES = ["ContainerCreateLabels", "ShellHealthcheck", "HealthStartPeriodPositive", "HealthStartPeriodZero"]
CASES = ["grace_positive", "period_zero", "inherited_failure", "disabled"]
RUN = "Ab12Cd34"
SHA = "a" * 40
IMAGE = "docker.io/library/busybox:test@sha256:" + "b" * 64
DERIVED = "sha256:" + "d" * 64
CANARY = "PRIVATE_HEALTH_CANARY"


def stamp(seconds, fraction=0):
    return f"2026-10-07T00:00:{seconds:02}.{fraction:09}Z"


def failed(first, second):
    return [{"start": stamp(value), "end": stamp(value, 200_000_000), "exit_code": 1}
            for value in (first, second)]


def context(lane):
    debian = lane.startswith("debian11-")
    return (lane, "20.10.5+dfsg1" if debian else "29.8.1", "1.41" if debian else "1.56",
            lane.rsplit("-", 1)[1], SHA, RUN, IMAGE)


def proof(lane="upstream-rootful"):
    cases = []
    for index, case in enumerate(CASES):
        records = []
        for role_index, role in enumerate(("oracle", "rendered")):
            disabled = case == "disabled"
            transition = index < 2
            records.append({
                "role": role, "id": f"{index * 2 + role_index + 1:064x}",
                "name": f"dl-health-{RUN}-{case}-{role}", "owner": RUN,
                "image": IMAGE if transition else DERIVED,
                "labels": "passed", "health_config": "passed", "running": "passed",
                "started_at": stamp(0),
                "initial_state": "disabled" if disabled else "starting" if index == 0 else "unhealthy",
                "initial_streak": 0 if disabled or index == 0 else 2,
                "initial_attempts": [] if disabled else failed(1, 6),
                "recovery_attempt": {"start": stamp(8), "end": stamp(8, 200_000_000), "exit_code": 0}
                                    if transition else None,
                "recovery": "healthy" if transition else "not_applicable",
                "regression": "unhealthy" if transition else "not_applicable",
                "regression_attempts": failed(9, 10) if transition else [],
                "regression_streak": 2 if transition else 0,
                "regression_observed_at": stamp(11) if transition else None,
                "health_sentinel": "absent" if disabled else "present",
                "disabled_gap_ns": 3_000_000_000 if disabled else None, "cleanup": "absent",
            })
        cases.append({"case": case, "wire": "passed", "containers": records})
    lane, engine, api, mode, candidate, run, image = context(lane)
    return {"schema_version": 1, "kind": "dockerlens-native-health-metadata-proof",
            "contract": "health-metadata-v1", "candidate_sha": candidate, "lane": lane,
            "engine_release": engine, "rendering_api": api,
            "acquisition_api": "1.41" if lane.startswith("debian11-") else "1.49",
            "daemon_mode": mode, "base_image": image, "base_health_start_period_ns": 0,
            "debian_package": "20.10.5+dfsg1-1+deb11u2" if lane.startswith("debian11-") else None,
            "run_id": run, "cleanup": "absent", "shapes": SHAPES, "cases": cases,
            "derived_image": {"id": DERIVED, "tag": f"dl-health-{RUN.lower()}:inherited", "owner": RUN,
                              "configured": "passed", "cleanup": "absent"},
            "seed_container": {"id": "f" * 64, "name": f"dl-health-{RUN}-seed", "owner": RUN,
                               "image": IMAGE, "cleanup": "absent"}}


class HealthMetadataProofTests(unittest.TestCase):
    def rejected(self, value, lane="upstream-rootful"):
        with self.assertRaises((ValueError, TypeError)):
            P.validate_health_metadata_proof(value, *context(lane))

    def test_exact_four_shapes_and_all_four_observed_contexts(self):
        for lane in P.LANES:
            self.assertEqual(P.validate_health_metadata_proof(proof(lane), *context(lane)), SHAPES)
        output = json.dumps(P.validate_health_metadata_proof(proof(), *context("upstream-rootful")))
        for private in (RUN, SHA, IMAGE, DERIVED, "started_at", "2026-10", CANARY):
            self.assertNotIn(private, output)
        self.assertNotIn("HealthDisabled", output)
        self.assertNotIn("StartInterval", output)

    def test_every_root_case_role_and_cleanup_binding_is_required(self):
        for lane in P.LANES:
            good = proof(lane)
            for key in good:
                for remove in (True, False):
                    value = copy.deepcopy(good)
                    if remove:
                        del value[key]
                    else:
                        value[key] = CANARY
                    self.rejected(value, lane)
            for object_key in ("derived_image", "seed_container"):
                for field in good[object_key]:
                    value = copy.deepcopy(good)
                    value[object_key][field] = CANARY
                    self.rejected(value, lane)
            for case_index, case in enumerate(good["cases"]):
                for role_index, record in enumerate(case["containers"]):
                    for field in record:
                        value = copy.deepcopy(good)
                        value["cases"][case_index]["containers"][role_index][field] = CANARY
                        self.rejected(value, lane)

    def test_each_case_and_role_must_be_complete_unique_ordered(self):
        for field in ("cases", "shapes"):
            for alter in (lambda rows: rows[:-1], lambda rows: rows[::-1], lambda rows: rows + rows[:1]):
                value = proof()
                value[field] = alter(value[field])
                self.rejected(value)
        for index in range(4):
            value = proof()
            value["cases"][index]["containers"].reverse()
            self.rejected(value)
            value = proof()
            value["cases"][index]["containers"][1]["id"] = value["cases"][0]["containers"][0]["id"]
            self.rejected(value)
        value = proof()
        value["cases"][0]["wire"] = "failed"
        self.rejected(value)

    def test_grace_requires_two_actual_completed_distinct_failures_inside_authored_window(self):
        changes = ([], failed(1, 6)[:1], [failed(1, 6)[0]] * 2, failed(6, 1), failed(1, 20))
        for attempts in changes:
            value = proof()
            value["cases"][0]["containers"][0]["initial_attempts"] = attempts
            self.rejected(value)
        for field, changed in (("initial_streak", 1), ("initial_state", "healthy"),
                               ("started_at", "0001-01-01T00:00:00Z"),
                               ("started_at", stamp(7)), ("initial_streak", False)):
            value = proof()
            value["cases"][0]["containers"][0][field] = changed
            self.rejected(value)

    def test_zero_oracle_must_start_fail_without_suppression_and_recover_then_regress(self):
        for inherited in (True, 20_000_000_000, None):
            value = proof()
            value["base_health_start_period_ns"] = inherited
            self.rejected(value)
        for role in (0, 1):
            for field, changed in (("started_at", "0001-01-01T00:00:00Z"),
                                   ("initial_state", "starting"), ("initial_streak", 0),
                                   ("initial_attempts", []), ("recovery_attempt", None),
                                   ("recovery", "not_applicable"), ("regression_attempts", []),
                                   ("regression_streak", 0), ("health_sentinel", "absent")):
                value = proof()
                value["cases"][1]["containers"][role][field] = changed
                self.rejected(value)

    def test_attempts_are_bound_to_one_start_and_real_ordered_health_transitions(self):
        for case_index in (0, 1, 2):
            for role in (0, 1):
                for field, changed in (("exit_code", 0), ("exit_code", True), ("start", stamp(0)),
                                       ("end", stamp(0)), ("end", "bad"), ("output", CANARY)):
                    value = proof()
                    attempts = value["cases"][case_index]["containers"][role]["initial_attempts"]
                    attempts[0][field] = changed
                    # start == StartedAt is legal; make its completion precede it for this counterfactual.
                    if field == "start" and changed == stamp(0):
                        attempts[0]["end"] = stamp(0)
                    self.rejected(value)
        for field in ("recovery_attempt", "regression_attempts"):
            value = proof()
            record = value["cases"][0]["containers"][0]
            record[field] = ({"start": stamp(2), "end": stamp(3), "exit_code": 0}
                             if field == "recovery_attempt" else failed(7, 8))
            self.rejected(value)
        value = proof()
        value["cases"][0]["containers"][0]["recovery_attempt"] = {
            "start": stamp(20), "end": stamp(20, 200_000_000), "exit_code": 0}
        self.rejected(value)

    def test_inherited_failure_and_disabled_sentinel_are_independent_required_controls(self):
        for field, changed in (("initial_attempts", []), ("initial_state", "healthy"),
                               ("initial_streak", 0), ("health_sentinel", "absent")):
            value = proof()
            value["cases"][2]["containers"][0][field] = changed
            self.rejected(value)
        for field, changed in (("disabled_gap_ns", 1_999_999_999), ("disabled_gap_ns", True),
                               ("initial_state", "healthy"), ("health_sentinel", "present"),
                               ("initial_attempts", failed(1, 2))):
            value = proof()
            value["cases"][3]["containers"][1][field] = changed
            self.rejected(value)

    def test_first_success_must_end_grace_before_both_counted_failures_and_observation(self):
        for role in (0, 1):
            value = proof()
            record = value["cases"][0]["containers"][role]
            record["initial_attempts"] = failed(1, 2)
            record["recovery_attempt"] = {"start": stamp(6), "end": stamp(6, 200_000_000), "exit_code": 0}
            record["regression_attempts"] = failed(21, 22)
            record["regression_observed_at"] = stamp(23)
            self.rejected(value)
            # The same later counted failures are valid for explicit zero,
            # so this counterfactual fails only the positive-grace contract.
            zero = proof()
            zero["cases"][1]["containers"][role].update({
                key: copy.deepcopy(record[key]) for key in
                ("initial_attempts", "recovery_attempt", "regression_attempts", "regression_observed_at")})
            self.assertEqual(P.validate_health_metadata_proof(zero, *context("upstream-rootful")), SHAPES)
            value = proof()
            value["cases"][0]["containers"][role]["regression_observed_at"] = stamp(20)
            self.rejected(value)

    def test_extra_private_fields_boolean_numbers_and_noncanonical_timestamps_reject(self):
        for path in ((), ("cases", 0), ("cases", 0, "containers", 0), ("derived_image",)):
            value = proof()
            node = value
            for part in path:
                node = node[part]
            node[CANARY] = CANARY
            self.rejected(value)
        for stamp_value in ("2026-02-30T00:00:00Z", "2026-10-07T00:00:00+00:00",
                            "2026-10-07T00:00:60Z", "2026-10-07T00:00:00.1234567890Z"):
            value = proof()
            value["cases"][0]["containers"][0]["started_at"] = stamp_value
            self.rejected(value)

    def test_private_file_is_bounded_owned_regular_stable_and_duplicate_free(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            directory.chmod(0o700)
            path = directory / "health-metadata.json"
            payload = json.dumps(proof())
            path.write_text(payload, encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(P.read_health_metadata_proof(path, directory, *context("upstream-rootful")), SHAPES)
            for invalid in ("", "x" * (P.LIMIT + 1), "{", "NaN",
                            payload.replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1')):
                path.write_text(invalid, encoding="utf-8")
                with self.assertRaises(ValueError):
                    P.read_health_metadata_proof(path, directory, *context("upstream-rootful"))
            path.write_text(payload, encoding="utf-8")
            for mode in (0o640, 0o644):
                path.chmod(mode)
                with self.assertRaises(ValueError):
                    P.read_health_metadata_proof(path, directory, *context("upstream-rootful"))
            path.chmod(0o600)
            with patch.object(P, "fingerprint", side_effect=lambda _info: object()):
                with self.assertRaises(ValueError):
                    P.read_health_metadata_proof(path, directory, *context("upstream-rootful"))
            link = directory / "second-link"
            os.link(path, link)
            with self.assertRaises(ValueError):
                P.read_health_metadata_proof(path, directory, *context("upstream-rootful"))
            link.unlink()
            path.unlink()
            path.symlink_to(directory / "missing")
            with self.assertRaises(OSError):
                P.read_health_metadata_proof(path, directory, *context("upstream-rootful"))


if __name__ == "__main__":
    unittest.main()
