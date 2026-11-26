"""Independent logging private-proof semantics/custody; no native logging run."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_logging_proof as reader
from test_native_external_network_proof import fixture as context_fixture

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
PROGRAM = 'test "$$" = 1 || exit 61; printf "%s\\n" "$1"'
NONE_ERROR = "Error response from daemon: configured logging driver does not support reading\n"


def fixture(lane="upstream-rootful", *, outer_backend="podman"):
    context = deepcopy(context_fixture(lane)["context"])
    context["fixture_image"] = "docker.io/library/busybox:1.37.0@sha256:" + "b" * 64
    image = "sha256:" + "d" * 64
    records = []
    for i, (driver, role) in enumerate((d, r) for d in ("json-file", "local", "none") for r in ("oracle", "rendered")):
        ident = f"{i + 1:064x}"
        token = f"dockerlens-log-v1:{context['run_id']}:{driver}:{role}"
        config = {"Type": driver, "Config": {"max-size": "1m"} if driver == "json-file" else {}}
        before = {"log_config": deepcopy(config), "cmd": ["sh", "-c", PROGRAM, "dl-log", token], "tty": False,
                  "entrypoint": "empty_inherited", "init": "not_inserted", "status": "created", "pid": 0, "running": False,
                  "exit": 0, "oom": False, "restarts": 0, "error_empty": True,
                  "started_at": "0001-01-01T00:00:00Z", "finished_at": "0001-01-01T00:00:00Z"}
        after = deepcopy(before)
        after.update(status="exited", started_at="2026-09-01T10:00:01.000000001Z", finished_at="2026-09-01T10:00:01.100000001Z")
        raw = NONE_ERROR if driver == "none" else token + "\n"
        status = 1 if driver == "none" else 0
        frame = raw + f"\nDOCKERLENS_LOG_EXIT:{status}\n"
        read = {"target": ident, "argv": ["logs", "--tail", "1", "--timestamps=false", ident], "status": status,
                "raw": raw, "raw_sha256": sha256(raw.encode()).hexdigest(), "frame": frame, "frame_sha256": sha256(frame.encode()).hexdigest()}
        records.append({"driver": driver, "role": role, "id": ident, "name": f"dl-log-{context['run_id']}-{driver}-{role}",
                        "owner": context["run_id"], "image_id": image, "wire": "independent_cli" if role == "oracle" else "literal_rendered",
                        "requested": config, "before": before, "after": after, "wait_exit": 0, "read": read, "cleanup": "absent"})
    extra = {"podman": 0, "docker": 65536}[outer_backend]
    delta = 1 if outer_backend == "docker" else 0
    calls = (9 if lane.startswith("debian11-") else 8) + delta
    context_bytes = 80000 + extra
    slot_bytes = [6000, 10000] * 3
    health_bytes = 5000
    before_bytes = context_bytes + sum(slot_bytes) + health_bytes
    final_bytes = 5000 + extra
    return {"schema_version": 1, "contract": "logging-v1", "capability_admission": [], "catalogue_admission": False,
            "scope": "explicit_drivers_configured_one_line_read_only", "context": context, "outer_backend": outer_backend,
            "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"}, "containers": records,
            "daemon_health": "version_matches_after_controls",
            "accounting": {"context_calls": calls, "context_bytes": context_bytes, "slot_calls": [7] * 6, "slot_bytes": slot_bytes,
                           "daemon_health_calls": 1, "daemon_health_bytes": health_bytes, "before_cleanup_calls": calls + 43,
                           "before_cleanup_bytes": before_bytes, "ordinary_calls": calls + 45 + delta, "ordinary_bytes": before_bytes + final_bytes,
                           "cleanup_calls": 54, "cleanup_bytes": 120000, "final_readback_calls": 2 + delta, "final_readback_bytes": final_bytes,
                           "reservation": {"pending_ordinary_bytes": 1769766 + extra, "slot_byte_limits": [193564, 322616] * 3,
                                           "cleanup_calls": 54, "cleanup_bytes": 552960, "final_calls": 2 + delta, "final_bytes": 147484 + extra,
                                           "byte_scope": "captured_stdout_stderr_not_wire"},
                           "deadline_seconds": 180, "cleanup_reserve_seconds": 46, "ordinary_elapsed_ns": 5_000_000_000,
                           "cleanup_elapsed_ns": 2_000_000_000, "elapsed_ns": 8_000_000_000,
                           "initial_context_acquisition": {"max_requests": 16, "max_total_bytes": 2097152, "max_elapsed_seconds": 15,
                                                           "accounting": "separate_existing_bound"}},
            "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


def bind_context(proof, context):
    proof = deepcopy(proof)
    proof["context"] = deepcopy(context)
    for item in proof["containers"]:
        token = f"dockerlens-log-v1:{context['run_id']}:{item['driver']}:{item['role']}"
        item["owner"] = context["run_id"]
        item["name"] = f"dl-log-{context['run_id']}-{item['driver']}-{item['role']}"
        for stage in ("before", "after"):
            item[stage]["cmd"][-1] = token
        value = item["read"]
        value["raw"] = NONE_ERROR if item["driver"] == "none" else token + "\n"
        value["frame"] = value["raw"] + f"\nDOCKERLENS_LOG_EXIT:{value['status']}\n"
    rebind(proof)
    return proof


def rebind(proof):
    for record in proof["containers"]:
        read = record["read"]
        read["raw_sha256"] = sha256(read["raw"].encode()).hexdigest()
        read["frame_sha256"] = sha256(read["frame"].encode()).hexdigest()


def read_mutation(proof, index, raw, status):
    value = proof["containers"][index]["read"]
    value.update(raw=raw, status=status, frame=raw + f"\nDOCKERLENS_LOG_EXIT:{status}\n")


def mutations():
    return {
        "missing": lambda p: p["containers"].pop(),
        "duplicate": lambda p: p["containers"].__setitem__(1, deepcopy(p["containers"][0])),
        "role-swap": lambda p: p["containers"].__setitem__(slice(0, 2), list(reversed(p["containers"][:2]))),
        "driver": lambda p: p["containers"][0].update(driver="syslog"),
        "missing-driver": lambda p: p["containers"][0]["requested"].pop("Type"),
        "max-size": lambda p: p["containers"][0]["requested"]["Config"].update({"max-size": "10m"}),
        "unit": lambda p: p["containers"][0]["before"]["log_config"]["Config"].update({"max-size": "1M"}),
        "effective-options": lambda p: p["containers"][0]["after"]["log_config"]["Config"].update({"max-file": "3"}),
        "local-options": lambda p: p["containers"][2]["requested"]["Config"].update({"max-size": "1m"}),
        "none-options": lambda p: p["containers"][4]["after"]["log_config"]["Config"].update({"compress": "false"}),
        "nil-config": lambda p: p["containers"][2]["before"]["log_config"].update(Config=None),
        "wrong-image": lambda p: p["containers"][0].update(image_id="sha256:" + "e" * 64),
        "wrong-owner": lambda p: p["containers"][0].update(owner="Other001"),
        "outer-cid": lambda p: p["containers"][0].update(id=p["context"]["outer"]["id"]),
        "read-other-cid": lambda p: p["containers"][0]["read"].update(target=p["containers"][1]["id"]),
        "read-argv": lambda p: p["containers"][0]["read"]["argv"].__setitem__(2, "2"),
        "program": lambda p: p["containers"][0]["before"]["cmd"].__setitem__(2, "printf wrong"),
        "tty": lambda p: p["containers"][0]["after"].update(tty=True),
        "wait": lambda p: p["containers"][0].update(wait_exit=1),
        "wait-bool": lambda p: p["containers"][0].update(wait_exit=False),
        "never-started": lambda p: p["containers"][0]["after"].update(started_at="0001-01-01T00:00:00Z"),
        "oom": lambda p: p["containers"][0]["after"].update(oom=True),
        "restart": lambda p: p["containers"][0]["after"].update(restarts=1),
        "live-pid0": lambda p: p["containers"][0]["after"].update(running=True, status="running"),
        "none-empty-success": lambda p: read_mutation(p, 4, "", 0),
        "none-empty-failure": lambda p: read_mutation(p, 4, "", 1),
        "none-canary": lambda p: read_mutation(p, 4, "dockerlens-log-v1:RunA1234:none:oracle\n", 0),
        "none-permission": lambda p: read_mutation(p, 4, "permission denied\n", 1),
        "none404": lambda p: read_mutation(p, 4, "Error response from daemon: No such container\n", 1),
        "none-timeout": lambda p: read_mutation(p, 4, NONE_ERROR, 124),
        "none-cancel": lambda p: read_mutation(p, 4, NONE_ERROR, 130),
        "none-extra": lambda p: read_mutation(p, 4, NONE_ERROR + "private suffix\n", 1),
        "canary-rebound": lambda p: read_mutation(p, 0, "wrong-canary\n", 0),
        "empty-success": lambda p: read_mutation(p, 2, "", 0),
        "readable-refusal": lambda p: read_mutation(p, 2, NONE_ERROR, 1),
        "truncated-lf": lambda p: read_mutation(p, 0, p["containers"][0]["read"]["raw"].rstrip("\n"), 0),
        "extra-lf": lambda p: read_mutation(p, 0, p["containers"][0]["read"]["raw"] + "\n", 0),
        "injected-delimiter": lambda p: read_mutation(p, 0, p["containers"][0]["read"]["raw"] + "\nDOCKERLENS_LOG_EXIT:0\n", 0),
        "trailing-frame": lambda p: p["containers"][0]["read"].update(frame=p["containers"][0]["read"]["frame"] + "trailing"),
        "candidate": lambda p: p["context"].update(candidate_sha="e" * 40),
        "api": lambda p: p["context"].update(acquisition_api="1.56"),
        "mode": lambda p: p["context"].update(mode="rootless"),
        "uid": lambda p: p["context"].update(daemon_uid=1),
        "backend": lambda p: p.update(outer_backend="docker"),
        "calls": lambda p: p["accounting"].update(ordinary_calls=0),
        "slot-calls": lambda p: p["accounting"].update(slot_calls=[6] * 6),
        "ctx-bytes": lambda p: p["accounting"].update(context_bytes=400000),
        "slot-bytes": lambda p: p["accounting"]["slot_bytes"].__setitem__(0, 193565),
        "wire-claim": lambda p: p["accounting"]["reservation"].update(byte_scope="total_wire_bytes"),
        "reserve": lambda p: p["accounting"]["reservation"].update(final_bytes=0),
        "counter-bool": lambda p: p["accounting"].update(cleanup_calls=True),
        "work-cutoff": lambda p: p["accounting"].update(ordinary_elapsed_ns=134000000001),
        "cleanup-time": lambda p: p["accounting"].update(cleanup_elapsed_ns=46000000001),
        "cleanup-uncertain": lambda p: p["cleanup"].update(uncertain=True),
        "borrowed-delete": lambda p: p["borrowed_image"].update(removal="deleted"),
        "admission": lambda p: p.update(capability_admission=["LogConfig"]),
        "unknown-key": lambda p: p.update(PRIVATE_LOGGING_CANARY="PRIVATE_LOGGING_CANARY"),
    }


class LoggingProofTests(unittest.TestCase):
    def test_all_profiles_backends_and_debian_release_variants_with_exact_six_controls(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                proof = fixture(lane, outer_backend=backend)
                with self.subTest(lane=lane, backend=backend):
                    self.assertEqual(reader.validate_logging_proof(proof, deepcopy(proof["context"]), outer_backend=backend),
                                     {"contract": "logging-v1", "capability_admission": [], "catalogue_admission": False})
                    self.assertLess(len(json.dumps(proof, separators=(",", ":")).encode()), 16384)
                    if lane.startswith("debian11-"):
                        proof["context"]["engine_release"] = "20.10.5"
                        reader.validate_logging_proof(proof, deepcopy(proof["context"]), outer_backend=backend)

    def test_rebound_hashes_never_legitimize_false_semantics(self):
        original = fixture()
        for name, mutate in mutations().items():
            with self.subTest(name=name):
                proof = deepcopy(original); mutate(proof); rebind(proof)
                with self.assertRaisesRegex(ValueError, "invalid private logging proof"):
                    reader.validate_logging_proof(proof, original["context"], outer_backend="podman")

    def test_independent_budget_arithmetic_and_cumulative_cleanup_final_guard(self):
        self.assertEqual(21 * 73742 + 24 * 9216, 1769766)
        self.assertEqual(1769766 + 65536, 1835302)
        self.assertEqual(54 * 10240, 552960)
        self.assertEqual([8 + 45, 9 + 45, 9 + 45 + 1, 10 + 45 + 1], [53, 54, 55, 56])
        self.assertEqual([53 + 54, 54 + 54, 55 + 54, 56 + 54], [107, 108, 109, 110])
        self.assertEqual(2097152 - 552960 - 147484, 1396708)
        self.assertEqual(2097152 - 552960 - 147484 - 65536, 1331172)
        proof = fixture()
        a = proof["accounting"]
        # Keep all arithmetic internally consistent while exceeding only the
        # shared cumulative cleanup+final capacity. A hash cannot fix this.
        a["slot_bytes"] = [193564, 250000] * 3
        a["before_cleanup_bytes"] = a["context_bytes"] + sum(a["slot_bytes"]) + a["daemon_health_bytes"]
        a["ordinary_bytes"] = a["before_cleanup_bytes"] + a["final_readback_bytes"]
        self.assertGreater(a["before_cleanup_bytes"], 1396708)
        with self.assertRaises(ValueError): reader.validate_logging_proof(proof, proof["context"], outer_backend="podman")

    def test_private_held_reader_rejects_malformed_oversized_and_custody_substitutions(self):
        for fault in ("valid", "duplicate", "malformed", "oversize", "mode", "directory-mode", "symlink", "hardlink", "fifo"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); root.chmod(0o700); proof = fixture()
                path = root / "logging-v1.json"; path.write_text(json.dumps(proof, separators=(",", ":"))); path.chmod(0o600)
                if fault == "duplicate": path.write_text('{"schema_version":1,"schema_version":1}')
                elif fault == "malformed": path.write_text("{")
                elif fault == "oversize": path.write_text("x" * 16385)
                elif fault == "mode": path.chmod(0o644)
                elif fault == "directory-mode": root.chmod(0o755)
                elif fault == "symlink": path.rename(root / "original"); path.symlink_to(root / "original")
                elif fault == "hardlink": os.link(path, root / "alias")
                elif fault == "fifo": path.unlink(); os.mkfifo(path, 0o600)
                if fault == "valid":
                    self.assertEqual(reader.read_logging_proof(path, root, proof["context"], outer_backend="podman"), {"contract": "logging-v1", "capability_admission": [], "catalogue_admission": False})
                else:
                    with self.assertRaisesRegex(ValueError, "invalid private logging proof"):
                        reader.read_logging_proof(path, root, proof["context"], outer_backend="podman")
        for swap_directory in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "capture"; root.mkdir(mode=0o700); proof = fixture()
                path = root / "logging-v1.json"; path.write_text(json.dumps(proof)); path.chmod(0o600)
                real = os.read
                def swap(fd, limit):
                    data = real(fd, limit)
                    if swap_directory: root.rename(root.with_name("old")); root.mkdir(mode=0o700)
                    else: path.unlink()
                    path.write_text(json.dumps(proof)); path.chmod(0o600)
                    return data
                with patch("native_network_attachment_proof.os.read", side_effect=swap), self.assertRaises(ValueError):
                    reader.read_logging_proof(path, root, proof["context"], outer_backend="podman")


if __name__ == "__main__": unittest.main()
