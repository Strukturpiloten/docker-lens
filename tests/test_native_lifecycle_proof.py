"""Authored pure lifecycle refusal controls; not native qualification."""

import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from test_native_external_network_proof import fixture as context_fixture
import native_lifecycle_proof as reader
import native_network_attachment_proof as private_reader

SECOND = 1_000_000_000
EPOCH = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()) * SECOND
SECRET = "PRIVATE_LIFECYCLE_CANARY"


def timestamp(offset):
    seconds, fraction = divmod(EPOCH + offset, SECOND)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"


def clock(offset):
    return [EPOCH + offset - 10_000_000, EPOCH + offset + 10_000_000, 20_000_000]


def attempt(start, age):
    return {"start": timestamp(start + age * SECOND), "end": timestamp(start + age * SECOND + 50_000_000),
            "exit_code": 1, "marker": "lifecycle-health-failure"}


def snapshot(start, early, ages):
    before, after = (3_400_000_000, 3_500_000_000) if early else (9_500_000_000, 9_600_000_000)
    return {"before": timestamp(start + before), "after": timestamp(start + after),
            "before_clock": clock(start + before), "after_clock": clock(start + after),
            "status": "starting", "failing_streak": 0, "running": True, "restart_count": 0,
            "attempts": [attempt(start, age) for age in ages]}


def fixture(lane="upstream-rootful", negative=False, control_age=5):
    context = context_fixture(lane)["context"]
    image = "sha256:" + "d" * 64

    def identity(index, role, suffix):
        return {"role": role, "id": str(index + 1) * 64, "name": f"dl-life-{context['run_id']}-{suffix}",
                "owner": context["run_id"], "image": context["fixture_image"], "image_id": image,
                "wire": "independent_cli" if role == "oracle" else "literal_rendered", "cleanup": "absent"}

    stops = []
    for case, (seconds, exit_code, duration) in enumerate(((1, 137, SECOND), (5, 41, 3 * SECOND))):
        records = []
        for offset, role in enumerate(("oracle", "rendered")):
            start = (case * 10 + offset * 5) * SECOND
            record = identity(case * 2 + offset, role, f"timeout-{seconds}-{role}")
            record.update({"configured_seconds": seconds, "readiness": "pid1-term-ready", "term_marker": True,
                "running_before_stop": True, "started_at": timestamp(start), "ready_observed_at": timestamp(start + SECOND),
                "stop_requested_at": timestamp(start + 2 * SECOND), "finished_at": timestamp(start + 2 * SECOND + duration),
                "stopped_observed_at": timestamp(start + 2 * SECOND + duration + 100_000_000),
                "ready_clock": clock(start + SECOND), "request_clock": clock(start + 2 * SECOND),
                "observed_clock": clock(start + 2 * SECOND + duration + 100_000_000),
                "timeout_override": False, "signal_override": False, "stop_elapsed_ns": duration + 100_000_000,
                "exit_code": exit_code, "state": "exited", "running": False, "pid": 0, "oom_killed": False,
                "restarting": False, "restart_count": 0, "paused": False, "dead": False, "state_error_empty": True})
            records.append(record)
        stops.append({"configured_seconds": seconds, "expected_exit_code": exit_code, "containers": records})
    health = []
    for index, role, suffix, start in ((4, "oracle", "health-control", 30 * SECOND),
                                        (5, "rendered", "health-candidate", 60 * SECOND)):
        effective = index == 5 and not negative
        record = identity(index, role, suffix)
        record.update({"start_interval_request": SECOND if index == 5 else "omitted",
                       "start_interval_readback_ns": SECOND if effective else 0, "request_accepted": True,
                       "started_at": timestamp(start), "early": snapshot(start, True, [1, 2, 3] if effective else []),
                       "late": snapshot(start, False, [5, 6, 7, 8, 9] if effective else [control_age])})
        health.append(record)
    return {"schema_version": 1, "contract": "lifecycle-v1", "context": context,
            "apis": {"fixture_cli": context["rendering_api"], "stop_renderer": context["rendering_api"],
                     "health_renderer": context["rendering_api"], "request": context["rendering_api"],
                     "health_probe": "test_local_unadmitted"},
            "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"}, "stop_timeout": stops,
            "health_start_interval": {"outcome": "not_effective_on_selected_api" if negative else "effective",
                "interval_ns": 8 * SECOND, "start_period_ns": 30 * SECOND, "start_interval_ns": SECOND,
                "timeout_ns": SECOND, "retries": 3, "containers": health},
            "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


class LifecycleProofTests(unittest.TestCase):
    def reject(self, proof, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private lifecycle proof$") as caught:
            reader.validate_lifecycle_proof(proof, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_effect_is_not_inferred_from_version_and_control_can_use_five_or_eight_seconds(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for age in (5, 8):
                proof = fixture(lane, control_age=age)
                self.assertEqual(reader.validate_lifecycle_proof(proof, proof["context"]),
                                 ("stop_timeout_effective", "health_start_interval_effective"))
        for lane in ("debian11-rootful", "debian11-rootless"):
            proof = fixture(lane, negative=True, control_age=8)
            self.assertEqual(reader.validate_lifecycle_proof(proof, proof["context"]),
                             ("stop_timeout_effective", "health_start_interval_not_effective_on_selected_api"))
        proof = fixture(negative=True)
        self.reject(proof)

    def test_stop_requires_exact_term_path_configured_timeout_and_distinct_exit(self):
        changes = {"configured_seconds": (0, 5, True), "term_marker": (False, 1), "readiness": ("configured",),
            "timeout_override": (True, 0), "signal_override": (True, 0), "running_before_stop": (False, 1),
            "exit_code": (0, 41, 143, True, 137.0), "state": ("running",), "running": (True, 0),
            "pid": (1, False), "oom_killed": (True, 0), "restarting": (True, 0), "restart_count": (1, False),
            "paused": (True, 0), "dead": (True, 0), "state_error_empty": (False, 1), "cleanup": ("uncertain",)}
        for key, values in changes.items():
            for value in values:
                proof = fixture()
                proof["stop_timeout"][0]["containers"][0][key] = value
                self.reject(proof)
        for exit_code in (0, 137, 143):
            proof = fixture()
            proof["stop_timeout"][1]["containers"][1]["exit_code"] = exit_code
            self.reject(proof)

    def test_both_stop_clocks_require_disjoint_windows_and_agreement(self):
        for case, durations in ((0, (0, 799_999_999, 2_500_000_000, 3 * SECOND, True)),
                                (1, (SECOND, 2_500_000_000, 2_799_999_999, 5_500_000_000, True))):
            for duration in durations:
                proof = fixture()
                proof["stop_timeout"][case]["containers"][0]["stop_elapsed_ns"] = duration
                self.reject(proof)
        for duration in (100_000_000, 799_999_999, 2_500_000_000, 3 * SECOND):
            proof = fixture()
            proof["stop_timeout"][0]["containers"][0]["finished_at"] = timestamp(2 * SECOND + duration)
            self.reject(proof)
        proof = fixture()
        proof["stop_timeout"][0]["containers"][0]["stop_elapsed_ns"] = 2 * SECOND
        self.reject(proof)  # Same broad window, inconsistent independent clocks.
        proof = fixture()
        proof["stop_timeout"][0]["containers"][0]["started_at"] = timestamp(-181 * SECOND)
        self.reject(proof)

    def test_clock_drift_slow_reads_and_caller_clock_jumps_refuse(self):
        for field in ("ready_clock", "request_clock", "observed_clock"):
            for values in ([True, 2, 1], [0, 1, 1], [EPOCH, EPOCH - 1, 1],
                           [EPOCH, EPOCH + SECOND, SECOND], [EPOCH, EPOCH + 100_000_000, 0]):
                proof = fixture()
                proof["stop_timeout"][0]["containers"][0][field] = values
                self.reject(proof)
        for role in (0, 1):
            for phase in ("early", "late"):
                for field in ("before_clock", "after_clock"):
                    proof = fixture()
                    proof["health_start_interval"]["containers"][role][phase][field][0] -= SECOND
                    self.reject(proof)

    def test_health_requires_own_start_timely_early_and_real_late_attempts(self):
        proof = fixture()
        health = proof["health_start_interval"]["containers"]
        self.assertNotEqual(health[0]["started_at"], health[1]["started_at"])
        self.assertEqual(reader.validate_lifecycle_proof(proof, proof["context"])[1], "health_start_interval_effective")
        for role in (0, 1):
            for phase in ("early", "late"):
                for key, value in (("status", "unhealthy"), ("failing_streak", 1), ("running", False), ("restart_count", 1)):
                    proof = fixture()
                    proof["health_start_interval"]["containers"][role][phase][key] = value
                    self.reject(proof)
            proof = fixture()
            proof["health_start_interval"]["containers"][role]["late"]["attempts"] = []
            self.reject(proof)
            proof = fixture()
            proof["health_start_interval"]["containers"][role]["started_at"] = timestamp(0)
            self.reject(proof)
        for count in (0, 1, 2):
            proof = fixture()
            proof["health_start_interval"]["containers"][1]["early"]["attempts"] = proof["health_start_interval"]["containers"][1]["early"]["attempts"][:count]
            self.reject(proof)
        proof = fixture()
        proof["health_start_interval"]["containers"][0]["early"]["attempts"] = [attempt(30 * SECOND, 3)]
        self.reject(proof)
        for phase, offset in (("early", 3_200_000_000), ("early", 4 * SECOND), ("late", 8 * SECOND), ("late", 12 * SECOND)):
            proof = fixture()
            sample = proof["health_start_interval"]["containers"][1][phase]
            for field in ("before", "after"):
                sample[field] = timestamp(60 * SECOND + offset)
                sample[field + "_clock"] = clock(60 * SECOND + offset)
            self.reject(proof)

    def test_health_marker_exit_chronology_and_completed_attempts_are_not_metadata(self):
        for phase in ("early", "late"):
            for key, values in {"exit_code": (0, -1, 137, True), "marker": (SECRET, "", False),
                                "start": (timestamp(0), timestamp(100 * SECOND)),
                                "end": (timestamp(60 * SECOND), timestamp(100 * SECOND))}.items():
                for value in values:
                    proof = fixture()
                    proof["health_start_interval"]["containers"][1][phase]["attempts"][0][key] = value
                    self.reject(proof)
        proof = fixture()
        attempts = proof["health_start_interval"]["containers"][1]["early"]["attempts"]
        attempts[1] = copy.deepcopy(attempts[0])
        self.reject(proof)
        proof = fixture()
        proof["health_start_interval"]["containers"][1]["late"]["attempts"] = [attempt(60 * SECOND, 3)]
        self.reject(proof)

    def test_debian_negative_requires_accepted_literal_request_and_both_later_effects(self):
        lane = "debian11-rootless"
        for role in (0, 1):
            for key, value in (("request_accepted", False), ("start_interval_request", 0), ("wire", "version_only")):
                proof = fixture(lane, negative=True, control_age=8)
                proof["health_start_interval"]["containers"][role][key] = value
                self.reject(proof, fixture(lane)["context"])
            for count in (1, 2):
                proof = fixture(lane, negative=True, control_age=8)
                start = (30 if role == 0 else 60) * SECOND
                proof["health_start_interval"]["containers"][role]["early"]["attempts"] = [attempt(start, age) for age in range(1, count + 1)]
                self.reject(proof, fixture(lane)["context"])
            proof = fixture(lane, negative=True, control_age=8)
            proof["health_start_interval"]["containers"][role]["late"]["attempts"] = []
            self.reject(proof, fixture(lane)["context"])
        proof = fixture(lane, negative=True, control_age=8)
        proof["health_start_interval"]["containers"][1]["start_interval_readback_ns"] = SECOND
        self.reject(proof, fixture(lane)["context"])

    def test_every_nested_key_is_required_closed_and_private_errors_are_fixed(self):
        def mappings(value, path=()):
            if isinstance(value, dict):
                yield path, value
                for key, child in value.items():
                    yield from mappings(child, (*path, key))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from mappings(child, (*path, index))
        source = fixture()
        for path, value in mappings(source):
            for key in (*value, "unexpected"):
                proof = copy.deepcopy(source)
                node = proof
                for step in path:
                    node = node[step]
                if key == "unexpected":
                    node[key] = SECRET
                else:
                    del node[key]
                self.reject(proof)

    def test_context_api_identity_ownership_and_cleanup_must_match(self):
        for key in fixture()["context"]:
            proof = fixture()
            proof["context"][key] = SECRET
            self.reject(proof)
        for key in fixture()["apis"]:
            proof = fixture()
            proof["apis"][key] = "1.49"
            self.reject(proof)
        for field, values in {"rounds": (1, True, 2.0), "outstanding": (1, False),
                              "uncertain": (True, 0), "containers": ("present",)}.items():
            for value in values:
                proof = fixture()
                proof["cleanup"][field] = value
                self.reject(proof)
        for key, value in (("identity", "changed"), ("removal", "deleted"), ("id", "sha256:" + "e" * 64)):
            proof = fixture()
            proof["borrowed_image"][key] = value
            self.reject(proof)
        for duplicate in (fixture()["context"]["outer"]["id"], "1" * 64):
            proof = fixture()
            proof["health_start_interval"]["containers"][1]["id"] = duplicate
            self.reject(proof)
        for key in ("id", "name", "owner", "image", "image_id", "role", "wire"):
            proof = fixture()
            proof["health_start_interval"]["containers"][0][key] = SECRET
            self.reject(proof)
        for path in (("stop_timeout",), ("stop_timeout", 0, "containers"), ("health_start_interval", "containers")):
            proof = fixture()
            node = proof
            for key in path:
                node = node[key]
            node.pop()
            self.reject(proof)
        proof = fixture()
        proof["schema_version"] = True
        self.reject(proof)

    def test_private_file_boundary_and_only_closed_public_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / reader.FILENAME
            proof = fixture()
            payload = json.dumps(proof, separators=(",", ":"))
            self.assertLess(len(payload), 16 * 1024)

            def write(text=payload):
                path.write_text(text)
                path.chmod(0o600)

            def read():
                return reader.read_lifecycle_proof(path, directory, proof["context"])

            def reject():
                with self.assertRaisesRegex(ValueError, "^invalid private lifecycle proof$") as caught:
                    read()
                self.assertNotIn(SECRET, str(caught.exception))

            write()
            result = read()
            self.assertEqual(result, ("stop_timeout_effective", "health_start_interval_effective"))
            self.assertNotIn(proof["context"]["run_id"], str(result))
            for text in ("", "{", payload.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
                         payload.replace('"schema_version":1', '"schema_version":NaN'), " " * 16385):
                write(text)
                reject()
            write()
            path.chmod(0o644)
            reject()
            path.chmod(0o600)
            directory.chmod(0o755)
            reject()
            directory.chmod(0o700)
            extra = directory / "extra"
            os.link(path, extra)
            reject()
            extra.unlink()
            path.rename(extra)
            path.symlink_to(extra)
            reject()
            path.unlink()
            extra.rename(path)
            original = private_reader.os.read

            def drift(descriptor, limit):
                data = original(descriptor, limit)
                path.write_bytes(data + b" ")
                return data

            with patch.object(private_reader.os, "read", drift):
                reject()

    def test_terminal_outer_handoff_never_counts_as_verified_absence(self):
        for value in ("outer_teardown_required", "handed_off", "requested", "unverified"):
            proof = fixture()
            proof["cleanup"]["containers"] = value
            self.reject(proof)
        proof = fixture()
        proof["cleanup"]["owner"] = "native_conformance_outer_v1"
        self.reject(proof)
        proof = fixture()
        proof["cleanup"]["uncertain"] = True
        self.reject(proof)


if __name__ == "__main__":
    unittest.main()
