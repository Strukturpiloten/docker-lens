"""Independent finite hostname fixtures and strict private-file fault controls."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from native_hostname_proof import CONTRACT, ERROR, FILENAME, main, read_hostname_proof, validate_hostname_proof

SECRET = "PRIVATE_HOSTNAME_CANARY"


def fixture(lane="upstream-rootful"):
    debian = lane.startswith("debian11-")
    mode = lane.rsplit("-", 1)[1]
    run = "Ab12Cd34"
    context = {
        "candidate_sha": "a" * 40, "run_id": run, "lane": lane,
        "engine_release": "20.10.5+dfsg1" if debian else "29.8.1",
        "rendering_api": "1.41" if debian else "1.56", "acquisition_api": "1.41" if debian else "1.49",
        "mode": mode, "docker_package": "20.10.5+dfsg1-1+deb11u2" if debian else "",
        "fixture_image": "docker.io/library/busybox:synthetic@sha256:" + "b" * 64,
        "daemon_uid": 1000 if mode == "rootless" else 0,
        "outer": {"id": "f" * 64, "name": f"dl-native-{run}", "owner": run,
                  "image": f"synthetic-{mode}:only@sha256:" + "c" * 64,
                  "data_volume": f"dl-native-data-{run}", "socket_source": "/synthetic/socket",
                  "privileged": True, "memory_bytes": 4294967296, "cpu_quota": 200000,
                  "cpu_period": 100000, "pids_limit": 512},
    }
    proof = {"schema_version": 1, "contract": "hostname-v1", "context": context,
             "capability_admission": [], "catalogue_admission": False,
             "borrowed_image": {"id": "sha256:" + "d" * 64, "identity": "unchanged", "removal": "not_owned"},
             "cases": [], "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}
    for index, case in enumerate(("omitted", "explicit")):
        authored = None if case == "omitted" else f"dl-hostname-{run}"
        records = []
        for offset, role in enumerate(("oracle", "rendered")):
            identifier = str(2 * index + offset + 1) * 64
            observed = identifier[:12] if authored is None else authored
            records.append({"role": role, "id": identifier, "name": f"dl-host-{run}-{case}-{role}",
                            "owner": run, "image": context["fixture_image"], "image_id": proof["borrowed_image"]["id"],
                            "wire": "independent_cli" if role == "oracle" else "literal_rendered",
                            "cli_api": context["rendering_api"], "request_hostname": "omitted" if authored is None else authored,
                            "configured_hostname": observed, "process_hostname": observed,
                            "started_at": "2026-10-18T10:00:00.000000001Z", "running_before": True,
                            "running_after": True, "restart_count": 0, "cleanup": "absent"})
        proof["cases"].append({"case": case, "authored_hostname": authored, "containers": records})
    return proof


class HostnameProofTests(unittest.TestCase):
    def reject(self, proof, context):
        with self.assertRaisesRegex(ValueError, "^" + ERROR + "$"):
            validate_hostname_proof(proof, context)

    def test_four_lanes_and_omission_are_distinct_without_admission(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            proof = fixture(lane)
            self.assertEqual(validate_hostname_proof(proof, copy.deepcopy(proof["context"])),
                             {"contract": "hostname-v1", "capability_admission": [], "catalogue_admission": False})
            self.assertIsNone(proof["cases"][0]["authored_hostname"])
            self.assertNotEqual(proof["cases"][0]["containers"][0]["configured_hostname"],
                                proof["cases"][1]["authored_hostname"])

    def test_missing_partial_duplicate_and_foreign_records_are_refused(self):
        original = fixture()
        for key in original:
            changed = copy.deepcopy(original)
            del changed[key]
            self.reject(changed, original["context"])
        for index in range(2):
            changed = copy.deepcopy(original)
            changed["cases"].pop(index)
            self.reject(changed, original["context"])
            for offset in range(2):
                changed = copy.deepcopy(original)
                changed["cases"][index]["containers"].pop(offset)
                self.reject(changed, original["context"])
                for key in original["cases"][index]["containers"][offset]:
                    for missing in (False, True):
                        changed = copy.deepcopy(original)
                        if missing:
                            del changed["cases"][index]["containers"][offset][key]
                        else:
                            changed["cases"][index]["containers"][offset][key] = SECRET
                        self.reject(changed, original["context"])
        for duplicate in (original["context"]["outer"]["id"], original["cases"][0]["containers"][0]["id"]):
            changed = copy.deepcopy(original)
            changed["cases"][1]["containers"][0]["id"] = duplicate
            self.reject(changed, original["context"])

    def test_independent_context_actual_effect_defaults_cleanup_and_types_are_required(self):
        original = fixture()
        for key in original["context"]:
            changed = copy.deepcopy(original)
            changed["context"][key] = SECRET
            self.reject(changed, original["context"])
        for case in (0, 1):
            for field in ("configured_hostname", "process_hostname"):
                changed = copy.deepcopy(original)
                changed["cases"][case]["containers"][0][field] = "wrong-hostname"
                self.reject(changed, original["context"])
        changed = copy.deepcopy(original)
        changed["cases"][0]["authored_hostname"] = changed["cases"][0]["containers"][0]["configured_hostname"]
        self.reject(changed, original["context"])
        for key, bad in (("rounds", True), ("outstanding", 1), ("uncertain", True), ("containers", "unknown")):
            changed = copy.deepcopy(original)
            changed["cleanup"][key] = bad
            self.reject(changed, original["context"])
        for key, bad in (("running_before", 1), ("running_after", False), ("restart_count", True),
                         ("started_at", "0001-01-01T00:00:00Z")):
            changed = copy.deepcopy(original)
            changed["cases"][0]["containers"][0][key] = bad
            self.reject(changed, original["context"])
        for key, bad in (("schema_version", True), ("capability_admission", ["ContainerHostname"]),
                         ("catalogue_admission", True), (SECRET, SECRET)):
            changed = copy.deepcopy(original)
            changed[key] = bad
            self.reject(changed, original["context"])

    def test_private_custody_and_command_line_bind_context_without_leaking(self):
        for failure in (None, "missing", "public", "parent", "symlink", "fifo", "hardlink", "oversized", "duplicate", "nonfinite", "context"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                proof = fixture()
                proof["context"]["outer"]["socket_source"] = str(root / "socket")
                context = copy.deepcopy(proof["context"])
                path = root / FILENAME
                path.write_text(json.dumps(proof))
                path.chmod(0o600)
                if failure == "missing":
                    path.unlink()
                elif failure == "public":
                    path.chmod(0o640)
                elif failure == "parent":
                    root.chmod(0o750)
                elif failure in ("symlink", "fifo"):
                    path.unlink()
                    if failure == "symlink":
                        (root / "other").write_text(json.dumps(proof))
                        path.symlink_to(root / "other")
                    else:
                        os.mkfifo(path, 0o600)
                elif failure == "hardlink":
                    os.link(path, root / "other")
                elif failure == "oversized":
                    path.write_text(" " * 16385)
                elif failure == "duplicate":
                    path.write_text(path.read_text().replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1', 1))
                elif failure == "nonfinite":
                    path.write_text(path.read_text().replace('"restart_count": 0', '"restart_count": NaN', 1))
                elif failure == "context":
                    context["candidate_sha"] = "e" * 40
                if failure is None:
                    self.assertEqual(read_hostname_proof(path, root, context)["contract"], CONTRACT)
                else:
                    with self.assertRaisesRegex(ValueError, "^" + ERROR + "$"):
                        read_hostname_proof(path, root, context)
                args = [str(root), context["candidate_sha"], context["run_id"], context["lane"],
                        context["engine_release"], context["rendering_api"], context["mode"], context["docker_package"],
                        context["fixture_image"], context["outer"]["image"], context["outer"]["id"], str(context["daemon_uid"])]
                result = subprocess.run([sys.executable, str(ROOT / "scripts/native_hostname_proof.py"), *args],
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual(result.returncode == 0, failure is None)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "" if failure is None else "native hostname proof rejected\n")

    def test_command_line_requires_canonical_independent_uid_context_and_arity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proof = fixture()
            proof["context"]["outer"]["socket_source"] = str(root / "socket")
            context = proof["context"]
            path = root / FILENAME
            path.write_text(json.dumps(proof))
            path.chmod(0o600)
            args = [str(root), context["candidate_sha"], context["run_id"], context["lane"],
                    context["engine_release"], context["rendering_api"], context["mode"], context["docker_package"],
                    context["fixture_image"], context["outer"]["image"], context["outer"]["id"], "0"]
            main(args)
            for uid in ("00", "-0", "+0", " 0", "1", "4294967296", SECRET):
                with self.subTest(uid=uid), self.assertRaisesRegex(ValueError, "^" + ERROR + "$"):
                    main([*args[:-1], uid])
            for changed in (args[:-1], [*args, SECRET], [*args[:5], "1.49", *args[6:]]):
                with self.assertRaisesRegex(ValueError, "^" + ERROR + "$"):
                    main(changed)


if __name__ == "__main__":
    unittest.main()
