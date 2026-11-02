"""Independent authored refusal controls, not actual Engine qualification."""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from test_native_external_network_proof import fixture as context_fixture
import native_lifecycle_default_effect_proof as reader

SECOND = 1_000_000_000
EPOCH = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()) * SECOND
SECRET = "PRIVATE_DEFAULT_EFFECT_CANARY"
OUTCOMES = ("stop_timeout_omitted_graceful_zero_forced", "health_start_interval_default_equivalent")


def timestamp(offset):
    seconds, fraction = divmod(EPOCH + offset, SECOND)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"


def clock(offset):
    return [EPOCH + offset - 10_000_000, EPOCH + offset + 10_000_000, 20_000_000]


def attempt(start, age):
    return {"start": timestamp(start + age * SECOND), "end": timestamp(start + age * SECOND + 50_000_000),
            "exit_code": 1, "marker": "lifecycle-health-failure"}


def snapshot(start, early, ages, raw):
    before, after = (6_300_000_000, 6_400_000_000) if early else (11_600_000_000, 11_700_000_000)
    return {"before": timestamp(start + before), "after": timestamp(start + after),
            "before_clock": clock(start + before), "after_clock": clock(start + after),
            "raw_start_interval": raw, "status": "starting", "failing_streak": 0,
            "running": True, "restart_count": 0, "attempts": [attempt(start, age) for age in ages]}


def fixture(lane="upstream-rootful"):
    context = context_fixture(lane)["context"]
    debian = lane.startswith("debian11-")
    image = "sha256:" + "d" * 64

    def identity(index, suffix):
        role = "oracle" if index % 2 == 0 else "rendered"
        return {"role": role, "id": str(index + 1) * 64, "name": f"dl-def-{context['run_id']}-{suffix}",
                "owner": context["run_id"], "image": context["fixture_image"], "image_id": image,
                "wire": "independent_cli" if role == "oracle" else "literal_rendered", "cleanup": "absent"}

    stops = []
    for index in range(4):
        omitted = index < 2
        start = (index * 8 + 1) * SECOND
        ready, requested = start + SECOND, start + 1_100_000_000
        duration = 3_050_000_000 if omitted else 100_000_000
        finished, observed = requested + duration, requested + duration + 100_000_000
        role = "oracle" if index % 2 == 0 else "rendered"
        record = identity(index, f"timeout-{'omitted' if omitted else 'zero'}-{role}")
        record.update({"timeout_request": "omitted" if omitted else 0,
                       "raw_timeout": "absent" if omitted else "present_zero", "readiness": "pid1-term-ready",
                       "term_log": "single_term" if omitted else "empty", "running_before_stop": True,
                       "started_at": timestamp(start), "ready_observed_at": timestamp(ready),
                       "stop_requested_at": timestamp(requested), "finished_at": timestamp(finished),
                       "stopped_observed_at": timestamp(observed), "ready_clock": clock(ready),
                       "request_clock": clock(requested), "observed_clock": clock(observed),
                       "timeout_override": False, "signal_override": False, "stop_elapsed_ns": duration,
                       "exit_code": 41 if omitted else 137, "state": "exited", "running": False,
                       "pid": 0, "oom_killed": False, "restarting": False, "restart_count": 0,
                       "paused": False, "dead": False, "state_error_empty": True})
        stops.append(record)
    health = []
    for index, suffix in ((4, "health-control"), (5, "health-candidate")):
        start = (40 + 16 * (index - 4)) * SECOND
        raw = "absent" if debian or index == 4 else "present_zero"
        record = identity(index, suffix)
        record.update({"start_interval_request": "omitted" if index == 4 else 0,
                       "raw_start_interval": raw, "request_accepted": True, "started_at": timestamp(start),
                       "early": snapshot(start, True, [] if debian else [5], raw),
                       "late": snapshot(start, False, [8] if debian else [5, 10], raw)})
        health.append(record)
    return {"schema_version": 1, "contract": "lifecycle-default-effects-v1", "context": context,
            "apis": {"fixture_cli": context["rendering_api"], "stop_renderer": context["rendering_api"],
                     "health_renderer": context["rendering_api"], "request": context["rendering_api"],
                     "health_probe": "test_local_unadmitted"},
            "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"},
            "legacy_zero_cli": {"name": f"dl-def-{context['run_id']}-zero-cli-refusal",
                                "outcome": "unknown_flag" if debian else "not_applicable",
                                "exit_code": 125 if debian else None, "stdout_empty": True,
                                "stderr_signature": "unknown_health_start_interval" if debian else "not_applicable",
                                "absence_reads": 2 if debian else 0, "started": False},
            "stop_timeout": stops,
            "health_start_interval": {"outcome": "unsupported_legacy_field" if debian else "default_equivalent",
                                      "source_scope": "accepted_unknown_member_legacy_schedule_only" if debian
                                      else "supported_field_zero_default_schedule", "interval_ns": 8 * SECOND,
                                      "start_period_ns": 30 * SECOND, "start_interval_request": 0,
                                      "timeout_ns": SECOND, "retries": 3, "containers": health},
            "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False},
            "accounting": {"ordinary_calls": 100, "cleanup_calls": 56 if debian else 54,
                           "ordinary_bytes": 50000, "cleanup_bytes": 5000, "deadline_seconds": 180, "renewed": False}}


class DefaultEffectProofTests(unittest.TestCase):
    def reject(self, proof, context=None):
        with self.assertRaises(ValueError) as raised:
            reader.validate_lifecycle_default_effect_proof(proof, context or fixture(proof["context"]["lane"])["context"])
        self.assertEqual(str(raised.exception), "invalid private lifecycle default effect proof")
        self.assertNotIn(SECRET, str(raised.exception))

    def mutate(self, path, value, lane="upstream-rootful"):
        proof = fixture(lane)
        target = proof
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        self.reject(proof)

    def test_four_independent_lane_expectations(self):
        for lane in ("upstream-rootful", "upstream-rootless", "debian11-rootful", "debian11-rootless"):
            with self.subTest(lane=lane):
                proof = fixture(lane)
                expected = ("stop_timeout_omitted_graceful_zero_forced", "health_start_interval_unsupported_legacy_field") if lane.startswith("debian11-") else OUTCOMES
                self.assertEqual(reader.validate_lifecycle_default_effect_proof(proof, proof["context"]), expected)

    def test_legacy_unknown_member_acceptance_is_not_zero_semantics(self):
        for lane in ("debian11-rootful", "debian11-rootless"):
            self.mutate(("health_start_interval", "outcome"), "default_equivalent", lane)
            self.mutate(("health_start_interval", "source_scope"), "supported_field_zero_default_schedule", lane)
            self.mutate(("health_start_interval", "containers", 1, "raw_start_interval"), "present_zero", lane)
        for lane in ("upstream-rootful", "upstream-rootless"):
            self.mutate(("health_start_interval", "outcome"), "unsupported_legacy_field", lane)
            self.mutate(("health_start_interval", "source_scope"), "accepted_unknown_member_legacy_schedule_only", lane)

    def test_zero_marker_race_is_closed_not_graceful(self):
        proof = fixture()
        for index in (2, 3):
            proof["stop_timeout"][index]["term_log"] = "single_term"
        self.assertEqual(reader.validate_lifecycle_default_effect_proof(proof, proof["context"]), OUTCOMES)
        for log in (None, False, [], "lifecycle-term\n", "single_term\nsingle_term", SECRET):
            self.mutate(("stop_timeout", 2, "term_log"), log)
        self.mutate(("stop_timeout", 0, "term_log"), "empty")
        self.mutate(("stop_timeout", 2, "exit_code"), 41)

    def test_stop_states_overrides_and_raw_defaults(self):
        bad = {"timeout_request": False, "raw_timeout": "null", "readiness": SECRET, "running_before_stop": False,
               "timeout_override": True, "signal_override": True, "exit_code": 0, "state": "running",
               "running": True, "pid": 1, "oom_killed": True, "restarting": True, "restart_count": 1,
               "paused": True, "dead": True, "state_error_empty": False}
        for field, value in bad.items():
            for index in range(4):
                with self.subTest(field=field, index=index):
                    self.mutate(("stop_timeout", index, field), value)
        self.mutate(("stop_timeout", 0, "raw_timeout"), "present_zero")
        self.mutate(("stop_timeout", 2, "raw_timeout"), "absent")
        self.mutate(("stop_timeout", 2, "timeout_request"), "omitted")

    def test_stop_disjoint_native_and_monotonic_boundaries(self):
        for index, values in ((0, (2_799_999_999, 5_500_000_000, True, -1)),
                              (2, (800_000_000, 2_800_000_000, True, -1))):
            for value in values:
                self.mutate(("stop_timeout", index, "stop_elapsed_ns"), value)
        proof = fixture()
        record = proof["stop_timeout"][2]
        record["finished_at"] = record["ready_observed_at"]
        self.reject(proof)
        self.mutate(("stop_timeout", 0, "finished_at"), timestamp(12 * SECOND))
        self.mutate(("stop_timeout", 0, "request_clock"), [EPOCH, EPOCH + SECOND, SECOND])
        self.mutate(("stop_timeout", 0, "request_clock"), [EPOCH + 2_100_000_000] * 3)
        self.mutate(("stop_timeout", 0, "request_clock"), [True, 1, 0])

    def test_health_defaults_preserve_raw_availability(self):
        proof = fixture()
        for record in proof["health_start_interval"]["containers"]:
            record["raw_start_interval"] = "absent"
            for sample in (record["early"], record["late"]):
                sample["raw_start_interval"] = "absent"
        self.assertEqual(reader.validate_lifecycle_default_effect_proof(proof, proof["context"]), OUTCOMES)
        for value in (None, 0, False, "null", "positive", SECRET):
            self.mutate(("health_start_interval", "containers", 1, "raw_start_interval"), value)
        self.mutate(("health_start_interval", "containers", 1, "start_interval_request"), "omitted")
        self.mutate(("health_start_interval", "containers", 0, "start_interval_request"), 0)
        self.mutate(("health_start_interval", "containers", 1, "request_accepted"), False)
        self.mutate(("health_start_interval", "containers", 1, "early", "raw_start_interval"), "absent")

    def test_health_real_scheduler_expectations_not_api_inference(self):
        for lane in ("upstream-rootful", "debian11-rootful"):
            for index in (0, 1):
                root = ("health_start_interval", "containers", index)
                start = (40 + 16 * index) * SECOND
                self.mutate((*root, "late", "attempts"), [], lane)
                self.mutate((*root, "early", "attempts"), [attempt(start, 1)], lane)
                self.mutate((*root, "late", "attempts"), [attempt(start, 8)] if lane.startswith("upstream") else [attempt(start, 5), attempt(start, 10)], lane)
                self.mutate((*root, "started_at"), timestamp(start + SECOND), lane)
                for key, value in (("status", "healthy"), ("failing_streak", 1), ("running", False), ("restart_count", 1)):
                    self.mutate((*root, "early", key), value, lane)
        root = ("health_start_interval", "containers", 0, "late", "attempts", 1)
        for key, value in (("marker", SECRET), ("exit_code", 0), ("end", timestamp(50 * SECOND)),
                           ("start", timestamp(49 * SECOND)), ("unknown", True)):
            self.mutate((*root, key), value)
        self.mutate(("health_start_interval", "containers", 0, "early", "after"), timestamp(47_200_000_000))
        self.mutate(("health_start_interval", "containers", 0, "late", "before"), timestamp(51_199_999_999))
        self.mutate(("health_start_interval", "containers", 0, "early", "before_clock"), [EPOCH, EPOCH, 0])

    def test_context_identity_ownership_and_cleanup(self):
        for path, value in ((("contract",), "lifecycle-v1"), (("schema_version",), True),
                            (("apis", "request"), "1.49"), (("apis", "health_probe"), "admitted"),
                            (("borrowed_image", "identity"), "changed"), (("borrowed_image", "removal"), "removed"),
                            (("cleanup", "rounds"), 1), (("cleanup", "outstanding"), 1), (("cleanup", "uncertain"), True),
                            (("accounting", "ordinary_calls"), 301), (("accounting", "cleanup_calls"), 100),
                            (("accounting", "ordinary_bytes"), 2097153), (("accounting", "deadline_seconds"), 360),
                            (("accounting", "renewed"), True), (("context", "candidate_sha"), "b" * 40)):
            self.mutate(path, value)
        proof = fixture()
        proof["health_start_interval"]["containers"][1]["id"] = proof["stop_timeout"][0]["id"]
        self.reject(proof)
        for field, value in (("id", "f" * 64), ("id", "A" * 64), ("name", SECRET), ("owner", SECRET),
                             ("image", SECRET), ("image_id", "sha256:" + "e" * 64), ("wire", "retry"), ("cleanup", "uncertain")):
            self.mutate(("stop_timeout", 0, field), value)

    def test_distinct_parser_refusal_requires_exact_absence(self):
        for field, value in (("name", fixture("debian11-rootful")["health_start_interval"]["containers"][1]["name"]),
                             ("outcome", "accepted"), ("exit_code", 1), ("stdout_empty", False),
                             ("stderr_signature", SECRET), ("absence_reads", 1), ("started", True)):
            self.mutate(("legacy_zero_cli", field), value, "debian11-rootful")
        self.mutate(("legacy_zero_cli", "outcome"), "unknown_flag")

    def test_closed_missing_null_and_unknown_parent_shapes(self):
        for path in (("health_start_interval",), ("stop_timeout",), ("legacy_zero_cli",), ("accounting",),
                     ("health_start_interval", "containers", 0, "early"),
                     ("health_start_interval", "containers", 0, "late", "attempts")):
            for value in (None, False, SECRET, {}):
                self.mutate(path, value)
        proof = fixture()
        del proof["health_start_interval"]["containers"][0]["early"]["attempts"]
        self.reject(proof)
        proof = fixture()
        proof["unexpected"] = SECRET
        self.reject(proof)

    def test_private_reader_and_closed_filesystem_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)
            capture.chmod(0o700)
            path = capture / "lifecycle-default-effects-v1.json"
            proof = fixture()

            def write(content):
                path.write_text(content)
                path.chmod(0o600)

            def rejected(candidate=path, parent=capture):
                with self.assertRaises(ValueError) as raised:
                    reader.read_lifecycle_default_effect_proof(candidate, parent, proof["context"])
                self.assertEqual(str(raised.exception), "invalid private lifecycle default effect proof")
                self.assertNotIn(SECRET, str(raised.exception))

            write(json.dumps(proof))
            self.assertEqual(reader.read_lifecycle_default_effect_proof(path, capture, proof["context"]), OUTCOMES)
            path.chmod(0o644)
            rejected()
            path.chmod(0o600)
            capture.chmod(0o755)
            rejected()
            capture.chmod(0o700)
            wrong = capture / "wrong.json"
            wrong.write_text(json.dumps(proof))
            wrong.chmod(0o600)
            rejected(wrong)
            link = capture / "link.json"
            os.link(path, link)
            rejected()
            link.unlink()
            path.unlink()
            path.symlink_to(wrong)
            rejected()
            path.unlink()
            write('{"contract":"' + SECRET + '","contract":"duplicate"}')
            rejected()
            write(SECRET * 2048)
            rejected()
            write('{"canary":"' + SECRET + '"')
            rejected()

    def test_source_registration_live_effects_and_single_deadline(self):
        source = (ROOT / "src/native_lifecycle_default_effect_tests.rs").read_text()
        parent = (ROOT / "src/native_lifecycle_tests.rs").read_text()
        self.assertIn('#[path = "native_lifecycle_default_effect_tests.rs"]\nmod default_effect;', parent)
        self.assertIn('fn live_lifecycle_default_effects_match_engine()', source)
        self.assertIn('#[ignore = "requires isolated exact-profile Docker Engine and authenticated harness"]', source)
        self.assertEqual(source.count("HealthRun::new_for("), 1)
        for key in ("NATIVE_LIFECYCLE_DEFAULT_EFFECT_PROOF_PATH", "NATIVE_LIFECYCLE_DEFAULT_EFFECT_CANDIDATE_SHA",
                    "NATIVE_LIFECYCLE_DEFAULT_EFFECT_DEADLINE_EPOCH"):
            self.assertIn(key, source)
        self.assertEqual(source.count("start(run, index);"), 2)
        self.assertIn('docker(run, &["stop".into(), id.clone()])', source)
        self.assertIn('logs.as_slice() == b"lifecycle-term\\n"', source)
        self.assertIn('logs.is_empty()', source)
        self.assertIn('run.remaining() > wait + Duration::from_secs(46)', source)
        self.assertNotIn("run.deadline =", source)
        self.assertNotIn("docker commit", source)
        self.assertNotIn("image_attempted = true", source)
        self.assertNotIn("derived_id = Some", source)
        self.assertIn('run.inspect(&name, false).0, 404', source)
        self.assertIn('assert_eq!(output.as_slice(), LEGACY_REJECTION)', source)


if __name__ == "__main__":
    unittest.main()
