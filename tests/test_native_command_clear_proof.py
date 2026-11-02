"""Independently authored source controls; never native acceptance evidence."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_native_external_network_proof import fixture as context_fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_command_clear_proof as reader
import native_network_attachment_proof as custody

SECRET = "PRIVATE_COMMAND_CLEAR_CANARY"


def fixture(lane="upstream-rootful"):
    context = context_fixture(lane)["context"]
    run = context["run_id"]
    derived = "sha256:" + "d" * 64
    # Expected vectors are authored here, not obtained from the validator.
    examples = (("image_defaults", ["/dl-image-entrypoint"], ["image-command"]),
                ("entrypoint_inherit", ["/dl-explicit-entrypoint"], []),
                ("command_clear", ["/dl-explicit-entrypoint"], []),
                ("entrypoint_clear", [], ["/dl-command-process", "explicit-command"]))
    cases = []
    for index, (case, entrypoint, command) in enumerate(examples):
        argv = entrypoint + command
        containers = []
        for offset, role in enumerate(("oracle", "rendered")):
            containers.append({
                "role": role, "id": f"{1 + index * 2 + offset:064x}",
                "name": f"dl-command-{run}-{case}-{role}", "owner": run, "image": derived,
                "wire": "passed", "entrypoint": entrypoint, "command": command,
                "entrypoint_variant": "exec" if entrypoint else "empty_array",
                "command_variant": "exec" if command else "empty_array",
                "path": argv[0], "args": argv[1:], "process_argv": ["/bin/sh"] + argv,
                "marker": "\n".join(argv) + "\n", "state": "running", "running": True,
                "restart_count": 0, "cleanup": "absent",
            })
        cases.append({"case": case, "containers": containers})
    return {
        "schema_version": 1, "contract": "command-clear-v1", "context": context,
        "shapes": ["ClearCommand", "ClearEntrypoint"],
        "borrowed_image": {"id": "sha256:" + "e" * 64, "identity": "unchanged", "removal": "not_owned"},
        "derived_image": {"id": derived, "tag": f"dl-command-clear-{run.lower()}:fixture", "owner": run,
                          "entrypoint": ["/dl-image-entrypoint"], "command": ["image-command"], "cleanup": "absent"},
        "seed": {"id": "9" * 64, "name": f"dl-command-{run}-seed", "owner": run,
                 "image": context["fixture_image"], "exit_code": 0, "cleanup": "absent"},
        "cases": cases, "cleanup": {"containers": "absent", "images": "absent", "rounds": 2,
                                   "outstanding": 0, "uncertain": False},
    }


class CommandClearProofTests(unittest.TestCase):
    def reject(self, proof, expected=None):
        with self.assertRaisesRegex(ValueError, "^invalid private command clear proof$") as caught:
            reader.validate_command_clear_proof(proof, fixture()["context"] if expected is None else expected)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_four_profiles_and_both_native_empty_variants(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            proof = fixture(lane)
            self.assertEqual(reader.validate_command_clear_proof(proof, proof["context"]),
                             ("ClearCommand", "ClearEntrypoint"))
            for case in proof["cases"]:
                for record in case["containers"]:
                    for field in ("entrypoint", "command"):
                        if record[field] == []:
                            record[field] = None
                            record[field + "_variant"] = "null"
            self.assertEqual(reader.validate_command_clear_proof(proof, proof["context"]), reader.SHAPES)

    def test_every_effect_and_identity_field_is_closed_and_mandatory(self):
        for index in range(4):
            for role in range(2):
                for field in fixture()["cases"][index]["containers"][role]:
                    with self.subTest(case=index, role=role, field=field):
                        proof = fixture()
                        del proof["cases"][index]["containers"][role][field]
                        self.reject(proof)
                        proof = fixture()
                        proof["cases"][index]["containers"][role][field] = SECRET
                        self.reject(proof)
                proof = fixture()
                proof["cases"][index]["containers"][role]["extra"] = SECRET
                self.reject(proof)

    def test_inherited_default_or_readback_only_cannot_prove_clear_effects(self):
        changes = {"command": [None, ["image-command"], [""], False, {}],
                   "command_variant": ["null", "exec", "missing"], "process_argv": [[], ["/bin/sh", "/dl-image-entrypoint", "image-command"]],
                   "marker": ["/dl-image-entrypoint\nimage-command\n", "passed"],
                   "running": [False, 1], "restart_count": [1, False, 0.0], "wire": ["unobserved"]}
        for field, values in changes.items():
            for value in values:
                proof = fixture()
                proof["cases"][2]["containers"][1][field] = value
                self.reject(proof)
        for field, value in (("entrypoint", ["/dl-image-entrypoint"]),
                             ("process_argv", ["/bin/sh", "/dl-image-entrypoint", "/dl-command-process", "explicit-command"]),
                             ("entrypoint_variant", "null")):
            proof = fixture()
            proof["cases"][3]["containers"][1][field] = value
            self.reject(proof)
        # Both controls are required even when the two explicit-entrypoint effects agree.
        for index in range(4):
            proof = fixture()
            proof["cases"].pop(index)
            self.reject(proof)

    def test_order_unique_ids_context_types_and_cleanup_refuse(self):
        for field in fixture()["context"]:
            proof = fixture()
            proof["context"][field] = SECRET
            self.reject(proof)
        for field in ("borrowed_image", "derived_image", "seed", "cleanup"):
            for key in fixture()[field]:
                proof = fixture()
                del proof[field][key]
                self.reject(proof)
                proof = fixture()
                proof[field][key] = SECRET
                self.reject(proof)
        for field, value in (("rounds", True), ("outstanding", False), ("uncertain", 0)):
            proof = fixture()
            proof["cleanup"][field] = value
            self.reject(proof)
        proof = fixture()
        proof["cases"].reverse()
        self.reject(proof)
        proof = fixture()
        proof["cases"][0]["containers"].reverse()
        self.reject(proof)
        for duplicate in (fixture()["seed"]["id"], fixture()["context"]["outer"]["id"],
                          fixture()["cases"][0]["containers"][0]["id"]):
            proof = fixture()
            proof["cases"][3]["containers"][1]["id"] = duplicate
            self.reject(proof)
        proof = fixture()
        proof["derived_image"]["id"] = proof["borrowed_image"]["id"]
        self.reject(proof)
        proof = fixture()
        proof["schema_version"] = True
        self.reject(proof)

    def test_owner_private_reader_modes_links_duplicates_partial_and_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            path = root / reader.FILENAME
            proof = fixture()
            payload = json.dumps(proof)

            def write(text):
                path.write_text(text)
                path.chmod(0o600)

            def refused():
                with self.assertRaisesRegex(ValueError, "^invalid private command clear proof$"):
                    reader.read_command_clear_proof(path, root, proof["context"])

            write(payload)
            self.assertEqual(reader.read_command_clear_proof(path, root, proof["context"]), reader.SHAPES)
            path.chmod(0o644)
            refused()
            path.chmod(0o600)
            root.chmod(0o755)
            refused()
            root.chmod(0o700)
            alias = root / "alias"
            os.link(path, alias)
            refused()
            alias.unlink()
            path.rename(alias)
            path.symlink_to(alias)
            refused()
            path.unlink()
            alias.rename(path)
            for bad in (payload[:-1], '{"schema_version":1,' + payload[1:], payload + " " * 16384):
                write(bad)
                refused()

    def test_root_fields_and_nonempty_defaults_cannot_be_removed_or_authorized(self):
        for field in fixture():
            proof = fixture()
            del proof[field]
            self.reject(proof)
        for field in ("entrypoint", "command"):
            for wrong in (None, [], [""], False):
                proof = fixture()
                proof["derived_image"][field] = wrong
                self.reject(proof)
        for field, value in (("capability_admission", []), ("catalogue_admission", False)):
            proof = fixture()
            proof[field] = value
            self.reject(proof)

    def test_stable_file_owner_fifo_and_direct_child_custody_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / reader.FILENAME
            proof = fixture()
            path.write_text(json.dumps(proof))
            path.chmod(0o600)

            def refused(candidate=path, directory=root):
                with self.assertRaisesRegex(ValueError, "^invalid private command clear proof$"):
                    reader.read_command_clear_proof(candidate, directory, proof["context"])

            refused(root / "foreign.json")
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            refused(alias / reader.FILENAME, alias)
            with mock.patch.object(custody.os, "geteuid", return_value=os.geteuid() + 1):
                refused()
            real_read = custody.os.read

            def changed_after_read(descriptor, limit):
                payload = real_read(descriptor, limit)
                path.write_text(json.dumps(proof) + " ")
                return payload

            with mock.patch.object(custody.os, "read", side_effect=changed_after_read):
                refused()
            path.unlink()
            os.mkfifo(path, 0o600)
            refused()


if __name__ == "__main__":
    unittest.main()
