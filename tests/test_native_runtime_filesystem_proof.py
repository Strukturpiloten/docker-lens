"""Independently authored synthetic controls; no Engine or catalogue evidence."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from test_native_external_network_proof import fixture as context_fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_runtime_filesystem_proof as reader

SECRET = "PRIVATE_RUNTIME_FILESYSTEM_CANARY"


def fixture(lane="upstream-rootful"):
    context = context_fixture(lane)["context"]
    image = "sha256:" + "e" * 64
    cases = []
    # Deliberately independent of the validator's CASES/FIELDS constants.
    for index, (name, flag) in enumerate((("omitted", None), ("false", False), ("true", True))):
        controls = []
        for offset, role in enumerate(("oracle", "rendered")):
            controls.append({
                "role": role, "id": str(1 + index * 2 + offset) * 64,
                "name": f"dl-runtime-{context['run_id']}-{name}-{role}", "owner": context["run_id"],
                "image": context["fixture_image"], "image_id": image,
                "wire": "independent_cli" if role == "oracle" else "literal_rendered",
                "cli_api": context["rendering_api"], "init_configured": flag,
                "readonly_configured": flag is True, "worker_pid": 7 if flag is True else 1,
                "worker_ppid": 1 if flag is True else 0, "worker_state": "S", "pid1_pid": 1,
                "rootfs_probe_path": "/dockerlens-rootfs-canary", "probe_path_mount": False,
                "write_exit": 2 if flag is True else 0, "write_effect": "erofs" if flag is True else "written",
                "readback": "absent" if flag is True else "exact_canary",
                "started_at": "2026-10-01T00:00:00Z", "process_observed_at": "2026-10-01T00:00:01Z",
                "write_observed_at": "2026-10-01T00:00:02Z", "running_after_at": "2026-10-01T00:00:03Z",
                "running_after": True, "restart_count": 0, "cleanup": "absent",
            })
        cases.append({"case": name, "authored_init": flag, "authored_readonly": flag, "containers": controls})
    return {"schema_version": 1, "contract": "runtime-filesystem-v1", "context": context,
            "capability_admission": [], "catalogue_admission": False, "init_effect_scope": "pid1_indirection_only",
            "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"}, "cases": cases,
            "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


class RuntimeFilesystemProofTests(unittest.TestCase):
    def reject(self, value, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private runtime filesystem proof$") as caught:
            reader.validate_runtime_filesystem_proof(value, context or fixture()["context"])
        self.assertNotIn(SECRET, str(caught.exception))

    def test_four_exact_lanes_have_explicit_no_admission_outputs(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            value = fixture(lane)
            self.assertEqual(reader.validate_runtime_filesystem_proof(value, value["context"]),
                             {"contract": "runtime-filesystem-v1", "capability_admission": [], "catalogue_admission": False})
            value["cases"][0]["containers"][0]["init_configured"] = False
            reader.validate_runtime_filesystem_proof(value, value["context"])

    def test_all_objects_are_closed_and_every_field_required(self):
        value = fixture()
        paths = [(), ("borrowed_image",), ("cleanup",)]
        for case in range(3):
            paths.append(("cases", case))
            paths.extend(("cases", case, "containers", role) for role in range(2))
        for path in paths:
            current = value
            for part in path:
                current = current[part]
            for key in current:
                bad = fixture()
                target = bad
                for part in path:
                    target = target[part]
                del target[key]
                self.reject(bad)
            bad = fixture()
            target = bad
            for part in path:
                target = target[part]
            target[SECRET] = SECRET
            self.reject(bad)

    def test_actual_process_relationships_must_match_each_authored_control(self):
        for index in range(3):
            changes = {"worker_ppid": (True, -1, 1.0, 0 if index == 2 else 1),
                       "worker_state": ("Z", "T", "configured", None), "pid1_pid": (2, True),
                       "init_configured": (True if index < 2 else False,),
                       "worker_pid": (True, 0, -1, 1.0, 4194305, 1 if index == 2 else 7)}
            for field, replacements in changes.items():
                for replacement in replacements:
                    bad = fixture()
                    bad["cases"][index]["containers"][0][field] = replacement
                    self.reject(bad)

    def test_write_failure_is_erofs_only_not_any_nonzero_or_configured_boolean(self):
        for index in range(3):
            changes = {"write_exit": (True, -1, 256, 0.0, 0 if index == 2 else 2),
                       "write_effect": ("permission_denied", "timeout", "configured", "unknown"),
                       "readback": ("wrong_canary", "absent" if index < 2 else "exact_canary"),
                       "probe_path_mount": (True, 0), "readonly_configured": (None, 1, index != 2),
                       "running_after": (False, 1), "restart_count": (1, False)}
            for field, replacements in changes.items():
                for replacement in replacements:
                    bad = fixture()
                    bad["cases"][index]["containers"][1][field] = replacement
                    self.reject(bad)

    def test_context_order_ids_clocks_cleanup_and_admission_cannot_drift(self):
        for field in fixture()["context"]:
            bad = fixture()
            bad["context"][field] = SECRET
            self.reject(bad)

        changes = {"process_observed_at": ("invalid", "2026-09-30T23:59:59Z", "2026-10-01T00:00:04Z"),
                   "running_after_at": ("2026-10-01T00:00:01Z", "2026-10-01T00:03:01Z"),
                   "cli_api": ("1.49", "1.41"), "cleanup": ("unknown",)}
        for field, replacements in changes.items():
            for replacement in replacements:
                bad = fixture()
                bad["cases"][0]["containers"][0][field] = replacement
                self.reject(bad)
        for field, replacement in (("containers", "unknown"), ("rounds", 1), ("rounds", True),
                                   ("outstanding", 1), ("uncertain", True)):
            bad = fixture()
            bad["cleanup"][field] = replacement
            self.reject(bad)
        for field, replacement in (("capability_admission", ["ContainerInit"]), ("catalogue_admission", True),
                                   ("init_effect_scope", "zombie_reaping"), ("schema_version", True)):
            bad = fixture()
            bad[field] = replacement
            self.reject(bad)
        for mutation in range(5):
            bad = fixture()
            if mutation == 0:
                bad["cases"].pop()
            elif mutation == 1:
                bad["cases"].reverse()
            elif mutation == 2:
                bad["cases"][0]["containers"].reverse()
            elif mutation == 3:
                bad["cases"][1]["containers"][0]["id"] = bad["cases"][0]["containers"][0]["id"]
            else:
                bad["cases"][0]["authored_init"] = False
            self.reject(bad)

    def test_fixture_ids_cannot_reuse_the_bound_outer_container_id(self):
        for case in range(3):
            for role in range(2):
                bad = fixture()
                bad["cases"][case]["containers"][role]["id"] = bad["context"]["outer"]["id"]
                self.reject(bad)

    def test_private_reader_refuses_malformed_duplicate_unknown_and_unsafe_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "runtime-filesystem-v1.json"
            value = fixture()
            payload = json.dumps(value)
            def write(text=payload):
                path.write_text(text)
                path.chmod(0o600)
            def read():
                return reader.read_runtime_filesystem_proof(path, root, value["context"])
            write()
            self.assertFalse(read()["catalogue_admission"])
            for text in ("", "{", payload.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                         " " * 16385, payload.replace('"worker_pid": 1', '"worker_pid": NaN', 1)):
                write(text)
                with self.assertRaises(ValueError):
                    read()
            write()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read()
            path.chmod(0o600)
            extra = root / "extra"
            os.link(path, extra)
            with self.assertRaises(ValueError):
                read()
            extra.unlink()
            path.rename(extra)
            path.symlink_to(extra)
            with self.assertRaises(ValueError):
                read()
            path.unlink()
            extra.unlink()
            with self.assertRaises(ValueError):
                read()


if __name__ == "__main__":
    unittest.main()
