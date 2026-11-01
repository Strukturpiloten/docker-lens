"""Independent semantic/custody negatives for device source; no native calls."""
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
import native_device_mapping_proof as reader
from test_native_external_network_proof import fixture as context_fixture

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")


def fixture(lane="upstream-rootful", *, outer_backend="podman"):
    context = deepcopy(context_fixture(lane)["context"])
    context["fixture_image"] = "docker.io/library/busybox:1.37.0@sha256:" + "b" * 64
    image = "sha256:" + "d" * 64
    records = []
    for index, role in enumerate(("oracle", "rendered")):
        report = f"source 1 3\ntarget 42 {100 + index} 1 3\nopened 42 {100 + index} 1 3\nread 0\nafter 42 {100 + index} 1 3\n"
        records.append({"role": role, "id": f"{index + 1:064x}", "name": f"dl-device-{context['run_id']}-{role}",
                        "owner": context["run_id"], "image_id": image,
                        "wire": "independent_cli" if index == 0 else "literal_rendered",
                        "configured": {"devices": [{"PathOnHost": "/dev/null", "PathInContainer": "/dev/native-null", "CgroupPermissions": "r"}],
                                       "process": "owned_pid1_loop", "running": True, "pid": 420 + index, "restarts": 0},
                        "effect": {"report": report, "report_sha256": sha256(report.encode()).hexdigest(),
                                   "nonsymlink": True, "kind": "character", "rdev": {"major": 1, "minor": 3},
                                   "read": {"exit": 0, "max_bytes": 1, "bytes": 0}, "binding": "held_fd_same_inode_before_after"},
                        "cleanup": "absent"})
    extra = {"podman": 0, "docker": 1}[outer_backend]
    calls = (9 if lane.startswith("debian11-") else 8) + extra
    return {"schema_version": 1, "contract": "device-mapping-v1", "capability_admission": [], "catalogue_admission": False,
            "scope": "configured_mapping_and_character_read_only", "outer_backend": outer_backend, "context": context,
            "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"}, "containers": records,
            "daemon_health": "version_matches_after_controls",
            "accounting": {"context_calls": calls, "slot_calls": [8, 8], "daemon_health_calls": 1, "final_readback_calls": 2 + extra,
                           "ordinary_calls": calls + 19 + extra, "ordinary_bytes": 500000 + 131072 * extra,
                           "cleanup_calls": 18, "cleanup_bytes": 40000, "deadline_seconds": 180, "cleanup_reserve_seconds": 46,
                           "ordinary_elapsed_ns": 5_000_000_000, "cleanup_elapsed_ns": 2_000_000_000, "elapsed_ns": 8_000_000_000,
                           "initial_context_acquisition": {"max_requests": 16, "max_total_bytes": 2097152,
                                                           "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"}},
            "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


def mutations():
    return {
        "missing-role": lambda p: p["containers"].pop(),
        "duplicate-role": lambda p: p["containers"].__setitem__(1, deepcopy(p["containers"][0])),
        "swapped-roles": lambda p: p["containers"].reverse(),
        "outer-id": lambda p: p["containers"][0].update(id=p["context"]["outer"]["id"]),
        "role-wire": lambda p: p["containers"][0].update(wire="literal_rendered"),
        "name": lambda p: p["containers"][0].update(name="other"),
        "owner": lambda p: p["containers"][0].update(owner="different"),
        "image": lambda p: p["containers"][0].update(image_id="sha256:" + "e" * 64),
        "host-path": lambda p: p["containers"][0]["configured"]["devices"][0].update(PathOnHost="/dev/zero"),
        "target-path": lambda p: p["containers"][0]["configured"]["devices"][0].update(PathInContainer="/dev/null"),
        "permission": lambda p: p["containers"][0]["configured"]["devices"][0].update(CgroupPermissions="rw"),
        "extra-device": lambda p: p["containers"][0]["configured"]["devices"].append({}),
        "running": lambda p: p["containers"][0]["configured"].update(running=False),
        "pid": lambda p: p["containers"][0]["configured"].update(pid=0),
        "process": lambda p: p["containers"][0]["configured"].update(process="unknown"),
        "restart": lambda p: p["containers"][0]["configured"].update(restarts=1),
        "symlink": lambda p: p["containers"][0]["effect"].update(nonsymlink=False),
        "regular": lambda p: p["containers"][0]["effect"].update(kind="regular"),
        "rdev": lambda p: p["containers"][0]["effect"]["rdev"].update(minor=5),
        "read-failed": lambda p: p["containers"][0]["effect"]["read"].update(exit=1),
        "timeout": lambda p: p["containers"][0]["effect"]["read"].update(exit=124),
        "cancelled": lambda p: p["containers"][0]["effect"]["read"].update(exit=130),
        "read-unbounded": lambda p: p["containers"][0]["effect"]["read"].update(max_bytes=2),
        "read-zero-device": lambda p: p["containers"][0]["effect"]["read"].update(bytes=1),
        "stale-node": lambda p: p["containers"][0]["effect"].update(binding="path_only"),
        "backend": lambda p: p.update(outer_backend="docker"),
        "candidate": lambda p: p["context"].update(candidate_sha="e" * 40),
        "run": lambda p: p["context"].update(run_id="Other145"),
        "lane": lambda p: p["context"].update(lane="debian11-rootful"),
        "mode": lambda p: p["context"].update(mode="rootless"),
        "fixture-image": lambda p: p["context"].update(fixture_image="docker.io/library/busybox:1.37.0@sha256:" + "f" * 64),
        "acquisition-api": lambda p: p["context"].update(acquisition_api="1.56"),
        "rendering-api": lambda p: p["context"].update(rendering_api="1.49"),
        "daemon-uid": lambda p: p["context"].update(daemon_uid=1),
        "outer": lambda p: p["context"]["outer"].update(id="e" * 64),
        "borrowed-removal": lambda p: p["borrowed_image"].update(removal="deleted"),
        "health": lambda p: p.update(daemon_health="unknown"),
        "calls": lambda p: p["accounting"].update(ordinary_calls=1),
        "calls-bool": lambda p: p["accounting"].update(cleanup_calls=True),
        "slot-calls": lambda p: p["accounting"].update(slot_calls=[7, 9]),
        "cleanup-bytes": lambda p: p["accounting"].update(cleanup_bytes=184321),
        "work-time": lambda p: p["accounting"].update(ordinary_elapsed_ns=134000000001),
        "total-time": lambda p: p["accounting"].update(elapsed_ns=1),
        "unknown-cleanup": lambda p: p["cleanup"].update(uncertain=True),
        "not-absent": lambda p: p["containers"][0].update(cleanup="unknown"),
        "admission": lambda p: p.update(capability_admission=["DeviceMappings"]),
        "private-extra": lambda p: p.update(PRIVATE_DEVICE_CANARY="PRIVATE_DEVICE_CANARY"),
    }


class DeviceMappingProofTests(unittest.TestCase):
    def test_four_lanes_and_independently_bound_backends(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                p = fixture(lane, outer_backend=backend)
                self.assertEqual(reader.validate_device_mapping_proof(p, deepcopy(p["context"]), outer_backend=backend),
                                 {"contract": "device-mapping-v1", "capability_admission": [], "catalogue_admission": False})
                with self.assertRaises(ValueError):
                    reader.validate_device_mapping_proof(p, p["context"], outer_backend="docker" if backend == "podman" else "podman")

    def test_semantics_cannot_be_replaced_by_internal_agreement_or_rebound_digest(self):
        original = fixture()
        for name, mutate in mutations().items():
            with self.subTest(name=name):
                p = deepcopy(original)
                mutate(p)
                for item in p["containers"]:
                    item["effect"]["report_sha256"] = sha256(item["effect"]["report"].encode()).hexdigest()
                with self.assertRaisesRegex(ValueError, "invalid private device mapping proof"):
                    reader.validate_device_mapping_proof(p, original["context"], outer_backend="podman")
        for old, new in (("source 1 3", "source 1 5"), ("target 42 100 1 3", "target 42 100 1 5"),
                         ("opened 42 100", "opened 42 101"), ("read 0", "read 1"),
                         ("after 42 100", "after 42 101"), ("target 42", "target 042"), ("read 0\n", "")):
            p = deepcopy(original)
            effect = p["containers"][0]["effect"]
            effect["report"] = effect["report"].replace(old, new)
            effect["report_sha256"] = sha256(effect["report"].encode()).hexdigest()
            with self.subTest(report=(old, new)), self.assertRaises(ValueError):
                reader.validate_device_mapping_proof(p, original["context"], outer_backend="podman")

    def test_private_reader_rejects_malformed_oversized_and_custody_substitutions(self):
        for mutation in ("none", "duplicate", "malformed", "oversize", "mode", "directory-mode", "symlink", "hardlink", "missing", "fifo"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o700)
                p = fixture()
                path = root / reader.FILENAME
                path.write_text(json.dumps(p))
                path.chmod(0o600)
                if mutation == "duplicate":
                    path.write_text('{"schema_version":1,"schema_version":1}')
                elif mutation == "malformed":
                    path.write_text('{')
                elif mutation == "oversize":
                    path.write_text('x' * 16385)
                elif mutation == "mode":
                    path.chmod(0o644)
                elif mutation == "directory-mode":
                    root.chmod(0o755)
                elif mutation == "symlink":
                    path.rename(root / "original")
                    path.symlink_to(root / "original")
                elif mutation == "hardlink":
                    os.link(path, root / "alias")
                elif mutation in ("missing", "fifo"):
                    path.unlink()
                    if mutation == "fifo":
                        os.mkfifo(path, 0o600)
                if mutation == "none":
                    self.assertEqual(reader.read_device_mapping_proof(path, root, p["context"], outer_backend="podman"), reader.RESULT)
                else:
                    with self.assertRaisesRegex(ValueError, "invalid private device mapping proof"):
                        reader.read_device_mapping_proof(path, root, p["context"], outer_backend="podman")

    def test_held_file_and_directory_identity_drift_is_rejected(self):
        for swap_directory in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "capture"
                root.mkdir(mode=0o700)
                p = fixture()
                path = root / reader.FILENAME
                path.write_text(json.dumps(p)); path.chmod(0o600)
                original_read = os.read
                def replaced_read(fd, size):
                    data = original_read(fd, size)
                    if swap_directory:
                        root.rename(root.with_name("old")); root.mkdir(mode=0o700)
                    else:
                        path.unlink()
                    path.write_text(json.dumps(p)); path.chmod(0o600)
                    return data
                with patch("native_network_attachment_proof.os.read", side_effect=replaced_read), self.assertRaises(ValueError):
                    reader.read_device_mapping_proof(path, root, p["context"], outer_backend="podman")


if __name__ == "__main__":
    unittest.main()
