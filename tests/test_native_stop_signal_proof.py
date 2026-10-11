"""Authored negative controls; no Docker execution or native evidence."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_native_external_network_proof import fixture as context_fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_stop_signal_proof as proof_reader
import native_network_attachment_proof as private_reader

SECRET = "PRIVATE_STOP_SIGNAL_CANARY"
FILENAME = "stop-signal-v1.json"


def fixture(lane="upstream-rootful"):
    context = context_fixture(lane)["context"]
    image_id = "sha256:" + "e" * 64
    cases = []
    for index, (signal, name, code) in enumerate((("SIGTERM", "term", 41), ("SIGINT", "int", 42))):
        containers = []
        for offset, role in enumerate(("oracle", "rendered")):
            containers.append({
                "role": role, "id": str(1 + index * 2 + offset) * 64,
                "name": f"dl-stop-{context['run_id']}-{name}-{role}", "owner": context["run_id"],
                "image": context["fixture_image"], "image_id": image_id, "configured_signal": signal,
                "wire": "passed", "readiness": "pid1-traps-ready", "running_before_stop": True,
                "started_at": "2026-10-01T00:00:00Z", "ready_observed_at": "2026-10-01T00:00:01Z",
                "stop_requested_at": "2026-10-01T00:00:02Z", "finished_at": "2026-10-01T00:00:02.1Z",
                "stopped_observed_at": "2026-10-01T00:00:02.2Z", "stop_timeout_seconds": 3,
                "signal_override": False, "stop_elapsed_ns": 200_000_000,
                "exit_code": code, "state": "exited", "running": False, "pid": 0, "oom_killed": False,
                "restarting": False, "restart_count": 0, "cleanup": "absent",
            })
        cases.append({"signal": signal, "expected_exit_code": code, "containers": containers})
    return {"schema_version": 1, "contract": "stop-signal-v1", "context": context, "shapes": ["StopSignal"],
            "borrowed_image": {"id": image_id, "identity": "unchanged", "removal": "not_owned"},
            "cases": cases, "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


class StopSignalProofTests(unittest.TestCase):
    def reject(self, proof, expected=None):
        with self.assertRaisesRegex(ValueError, "^invalid private stop signal proof$") as caught:
            proof_reader.validate_stop_signal_proof(proof, fixture()["context"] if expected is None else expected)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_all_four_profiles_require_both_spellings_and_roles(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            proof = fixture(lane)
            self.assertEqual(proof_reader.validate_stop_signal_proof(proof, proof["context"]), ("StopSignal",))
        for key in ("cases", "shapes"):
            proof = fixture()
            proof[key] = proof[key][:-1]
            self.reject(proof)
        for index in range(2):
            proof = fixture()
            proof["cases"][index]["containers"].pop()
            self.reject(proof)
        proof = fixture()
        proof["cases"].reverse()
        self.reject(proof)

    def test_every_container_field_is_required_and_closed(self):
        for case in range(2):
            for role in range(2):
                for field in fixture()["cases"][case]["containers"][role]:
                    with self.subTest(case=case, role=role, field=field):
                        proof = fixture()
                        del proof["cases"][case]["containers"][role][field]
                        self.reject(proof)
                        proof = fixture()
                        proof["cases"][case]["containers"][role][field] = SECRET
                        self.reject(proof)
                proof = fixture()
                proof["cases"][case]["containers"][role]["unexpected"] = SECRET
                self.reject(proof)

    def test_forced_kill_natural_exit_wrong_trap_and_stale_lifecycle_refused(self):
        changes = {"exit_code": (0, 42, 137, 143, True, 41.0), "running": (True, 0),
                   "pid": (1, False), "oom_killed": (True, 0), "signal_override": (True, 0),
                   "stop_timeout_seconds": (-1, 10, True), "stop_elapsed_ns": (0, -1, 5_000_000_000, True),
                   "readiness": ("unavailable", "configured"), "running_before_stop": (False, 1),
                   "configured_signal": ("TERM", "15", "SIGINT"), "state": ("running", "dead"),
                   "finished_at": ("2026-10-01T00:00:01Z", "2026-10-01T00:00:10Z"),
                   "started_at": ("2026-10-01T00:00:02Z", "2026-09-30T23:00:00Z"),
                   "ready_observed_at": ("2026-10-01T00:00:03Z",), "cleanup": ("unknown",)}
        for field, values in changes.items():
            for value in values:
                proof = fixture()
                proof["cases"][0]["containers"][0][field] = value
                self.reject(proof)
        proof = fixture()
        proof["cases"][1]["containers"][1]["id"] = proof["cases"][0]["containers"][0]["id"]
        self.reject(proof)

    def test_context_cleanup_and_borrowed_image_are_not_self_attested(self):
        for field in fixture()["context"]:
            proof = fixture()
            proof["context"][field] = SECRET
            self.reject(proof)
        for field, values in {"rounds": (1, True, 2.0), "outstanding": (1, False),
                              "uncertain": (True, 0), "containers": ("present",)}.items():
            for value in values:
                proof = fixture()
                proof["cleanup"][field] = value
                self.reject(proof)
        for field, value in (("identity", "changed"), ("removal", "deleted"), ("id", "sha256:" + "c" * 64)):
            proof = fixture()
            proof["borrowed_image"][field] = value
            self.reject(proof)
        proof = fixture()
        proof["schema_version"] = True
        self.reject(proof)

    def test_private_reader_rejects_links_modes_duplicates_partial_and_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / FILENAME
            value = fixture()
            payload = json.dumps(value)
            def write(text=payload):
                path.write_text(text)
                path.chmod(0o600)
            def read():
                return proof_reader.read_stop_signal_proof(path, root, value["context"])
            write()
            self.assertEqual(read(), ("StopSignal",))
            for text in ("", "{", payload.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'), " " * 16385):
                write(text)
                with self.assertRaises(ValueError): read()
            write()
            path.chmod(0o644)
            with self.assertRaises(ValueError): read()
            path.chmod(0o600)
            extra = root / "extra"
            os.link(path, extra)
            with self.assertRaises(ValueError): read()
            extra.unlink()
            path.rename(extra)
            path.symlink_to(extra)
            with self.assertRaises(ValueError): read()
            path.unlink()
            extra.rename(path)
            original = private_reader.os.read
            def changed(fd, maximum):
                raw = original(fd, maximum)
                path.write_bytes(raw + b" ")
                return raw
            with patch.object(private_reader.os, "read", changed), self.assertRaises(ValueError): read()


if __name__ == "__main__":
    unittest.main()
