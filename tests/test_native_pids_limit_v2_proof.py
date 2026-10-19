"""Independent synthetic PIDs-v2 controls; no native capture, worker or host probe."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_native_pids_limit_proof import fixture as legacy_fixture
import native_pids_limit_proof as legacy
import native_pids_limit_v2_proof as reader

ROOT = Path(__file__).resolve().parents[1]
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_PIDS_V2_CANARY"
FAILURE = "invalid private pids limit proof"


def compact_legacy(proof):
    """Author the wire tuple order explicitly, independently of the reader table."""
    result = deepcopy(proof)
    result["schema_version"] = 2
    result["contract"] = "pids-limit-v2"
    for case in result["cases"]:
        for phase in ("baseline", "held", "restored"):
            value = case[phase]
            case[phase] = [value["rows"], value["members"], value["pids_current"], value["pids_max"],
                           value["denials"], value["oom_kills"], value["outer_pids"], value["outer_memory"],
                           value["ancestor_headroom"], value["phase"]]
    # Context; finite16 oracle/rendered; finite64 oracle/rendered; unlimited
    # oracle/rendered. Each case is baseline(scan, controller), held(scan,
    # controller), restored(scan, controller). Values are authored, not captured.
    result["coordinates"] = [
        [71, 0, [0], 0, 0, 0],
        [101, 0, [0], 0, 0, 0], [102, 0, [0], 0, 0, 0],
        [103, 0, [0], 0, 0, 0], [104, 0, [0], 0, 0, 0],
        [105, 0, [0], 0, 0, 0], [106, 0, [0], 0, 0, 0],
        [201, 0, [0], 0, 0, 0], [202, 0, [0], 0, 0, 0],
        [203, 0, [0], 0, 0, 0], [204, 0, [0], 0, 0, 0],
        [205, 0, [0], 0, 0, 0], [206, 0, [0], 0, 0, 0],
        [301, 0, [0], 0, 0, 0], [302, 0, [0], 0, 0, 0],
        [303, 0, [0], 0, 0, 0], [304, 0, [0], 0, 0, 0],
        [305, 0, [0], 0, 0, 0], [306, 0, [0], 0, 0, 0],
        [401, 0, [0], 0, 0, 0], [402, 0, [0], 0, 0, 0],
        [403, 0, [0], 0, 0, 0], [404, 0, [0], 0, 0, 0],
        [405, 0, [0], 0, 0, 0], [406, 0, [0], 0, 0, 0],
        [501, 0, [0], 0, 0, 0], [502, 0, [0], 0, 0, 0],
        [503, 0, [0], 0, 0, 0], [504, 0, [0], 0, 0, 0],
        [505, 0, [0], 0, 0, 0], [506, 0, [0], 0, 0, 0],
        [601, 0, [0], 0, 0, 0], [602, 0, [0], 0, 0, 0],
        [603, 0, [0], 0, 0, 0], [604, 0, [0], 0, 0, 0],
        [605, 0, [0], 0, 0, 0], [606, 0, [0], 0, 0, 0],
    ]
    return result


def fixture(lane="upstream-rootful", kind="v2", nested=False):
    """Current-consumer fixture with the historical helper's context structure."""
    return compact_legacy(legacy_fixture(lane, kind, nested))


def payload(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class PidsLimitV2ProofTests(unittest.TestCase):
    def reject(self, value, context=None):
        with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$") as caught:
            reader.validate_pids_limit_v2_proof(value, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def write(self, parent, proof):
        parent.chmod(0o700)
        target = parent / reader.FILENAME
        target.write_text(payload(proof), encoding="utf-8")
        target.chmod(0o600)
        return target

    def test_all_sixteen_synthetic_profiles_generations_and_depths(self):
        for lane in LANES:
            for kind in ("v1", "v2"):
                for nested in (False, True):
                    with self.subTest(lane=lane, kind=kind, nested=nested):
                        proof = fixture(lane, kind, nested)
                        before = deepcopy(proof)
                        self.assertEqual(reader.validate_pids_limit_v2_proof(proof, proof["context"]),
                                         {"contract": "pids-limit-v2", "capability_admission": [],
                                          "catalogue_admission": False, "scope": legacy.SCOPE})
                        self.assertEqual(proof, before)
                        self.assertLessEqual(len(payload(proof).encode()), 15360)
                        with tempfile.TemporaryDirectory() as directory:
                            parent = Path(directory)
                            target = self.write(parent, proof)
                            self.assertEqual(reader.read_pids_limit_v2_proof(target, parent, proof["context"])["contract"],
                                             "pids-limit-v2")

    def test_independent_literal_field_order_and_witness_positions(self):
        self.assertEqual(reader.PHASE_FIELDS,
                         ("rows", "members", "pids_current", "pids_max", "denials", "oom_kills",
                          "outer_pids", "outer_memory", "ancestor_headroom", "phase"))
        proof = fixture()
        self.assertEqual(proof["cases"][0]["restored"],
                         [[[0, 1, -950, 0, 0]], [0], 1, 16, 1, 0, 80, 268435456, 400, "idle"])
        self.assertEqual([record[0] for record in proof["coordinates"]],
                         [71, 101, 102, 103, 104, 105, 106, 201, 202, 203, 204, 205, 206,
                          301, 302, 303, 304, 305, 306, 401, 402, 403, 404, 405, 406,
                          501, 502, 503, 504, 505, 506, 601, 602, 603, 604, 605, 606])
        self.assertEqual(proof["coordinates"][0], [71, 0, [0], 0, 0, 0])
        with patch.object(reader, "validate_pids_limit_proof", wraps=legacy.validate_pids_limit_proof) as validator:
            reader.validate_pids_limit_v2_proof(proof, proof["context"])
            expanded, context = validator.call_args.args
            self.assertEqual(expanded, legacy_fixture())
            self.assertIs(context, proof["context"])
            self.assertEqual(validator.call_count, 1)

    def test_every_coordinate_position_requires_same_proc_pid_single_chain_and_namespaces(self):
        for index in range(37):
            for position in (1, 3, 4, 5):
                for invalid in (1, -1, False, True, 0.0, None, SECRET):
                    with self.subTest(index=index, position=position, invalid=invalid):
                        proof = fixture()
                        proof["coordinates"][index][position] = invalid
                        self.reject(proof)
            for chain in ([], [0, 0], [1], [-1], [False], [0.0], "0", None):
                proof = fixture()
                proof["coordinates"][index][2] = chain
                self.reject(proof)

    def test_coordinate_lengths_types_anchors_and_shell_pid_bounds_are_strict(self):
        for invalid in (None, {}, False, [], fixture()["coordinates"][:-1], fixture()["coordinates"] * 2):
            proof = fixture()
            proof["coordinates"] = invalid
            self.reject(proof)
        for invalid in (None, {}, False, [], [1, 0, [0], 0, 0], [1, 0, [0], 0, 0, 0, 0]):
            proof = fixture()
            proof["coordinates"][12] = invalid
            self.reject(proof)
        for invalid in (0, -1, 4194305, True, False, 1.0, "1", None):
            proof = fixture()
            proof["coordinates"][0][0] = invalid
            self.reject(proof)
        for namespace in ("pid_namespace", "mount_namespace", "cgroup_namespace", "daemon_pid_namespace"):
            for invalid in (0, -1, True, False, 1.0, "100", 2**64):
                proof = fixture()
                proof["observer"][namespace] = invalid
                with patch.object(reader, "validate_pids_limit_proof") as validator:
                    self.reject(proof)
                    validator.assert_not_called()
        # Namespace deltas cannot be reinterpreted as absolute namespace IDs.
        proof = fixture()
        proof["coordinates"][0] = [71, 0, [0], 100, 101, 102]
        self.reject(proof)

    def test_valid_pid_reuse_and_equivalent_record_permutation_are_not_new_refusals(self):
        proof = fixture()
        proof["coordinates"].reverse()
        reader.validate_pids_limit_v2_proof(proof, proof["context"])
        proof["coordinates"] = [[4194304, 0, [0], 0, 0, 0] for _ in range(37)]
        reader.validate_pids_limit_v2_proof(proof, proof["context"])
        proof["coordinates"][0][0] = 1
        reader.validate_pids_limit_v2_proof(proof, proof["context"])

    def test_every_case_and_phase_requires_exact_ten_slot_list_not_legacy_object(self):
        for index in range(6):
            for phase in ("baseline", "held", "restored"):
                for invalid in (None, {}, True, "legacy", [], [0] * 9, [0] * 11,
                                legacy_fixture()["cases"][index][phase]):
                    proof = fixture()
                    proof["cases"][index][phase] = invalid
                    with patch.object(reader, "validate_pids_limit_proof") as validator:
                        self.reject(proof)
                        validator.assert_not_called()
                proof = fixture()
                del proof["cases"][index][phase]
                self.reject(proof)
        for left, right in (("baseline", "held"), ("held", "restored"), ("baseline", "restored")):
            proof = fixture()
            item = proof["cases"][0]
            item[left], item[right] = item[right], item[left]
            self.reject(proof)
        proof = fixture()
        packed = proof["cases"][0]["baseline"]
        packed[2], packed[3] = packed[3], packed[2]
        self.reject(proof)

    def test_no_version_or_relabelled_legacy_fallback(self):
        self.reject(legacy_fixture())
        for mutation in ("relabel", "coordinates", "mixed_phase", "schema_bool", "unknown", "missing"):
            proof = fixture()
            if mutation in ("relabel", "coordinates"):
                proof = legacy_fixture()
                proof.update(schema_version=2, contract="pids-limit-v2")
                if mutation == "coordinates":
                    proof["coordinates"] = fixture()["coordinates"]
            elif mutation == "mixed_phase":
                proof["cases"][5]["restored"] = legacy_fixture()["cases"][5]["restored"]
            elif mutation == "schema_bool":
                proof["schema_version"] = True
            elif mutation == "unknown":
                proof[SECRET] = SECRET
            else:
                del proof["coordinates"]
            self.reject(proof)
        for invalid in (None, [], False, "pids-limit-v2"):
            self.reject(invalid)

    def test_packet_counts_unknown_keys_and_phase_slot_types_are_not_laundered(self):
        for invalid in (None, {}, False, [], fixture()["cases"][:-1], fixture()["cases"] * 2):
            proof = fixture()
            proof["cases"] = invalid
            self.reject(proof)
        proof = fixture()
        proof["cases"][0] = []
        self.reject(proof)
        for namespace in ("observer", "context", "accounting", "acquisition", "cleanup", "borrowed_image"):
            proof = fixture()
            proof[namespace][SECRET] = SECRET
            self.reject(proof)
        proof = fixture()
        proof["cases"][0][SECRET] = SECRET
        self.reject(proof)
        for phase in ("baseline", "held", "restored"):
            for position in range(10):
                for invalid in (False, True, None):
                    proof = fixture()
                    proof["cases"][0][phase][position] = invalid
                    self.reject(proof)
            proof = fixture()
            proof["cases"][0][phase] = tuple(proof["cases"][0][phase])
            self.reject(proof)
        for invalid in (1, 2.0, False, "2", None):
            proof = fixture()
            proof["schema_version"] = invalid
            self.reject(proof)

    def test_original_semantic_mutations_remain_refusals_after_compaction(self):
        changes = [
            (("scope",), "unknown"), (("catalogue_admission",), True),
            (("capability_admission",), ["PidsLimit"]), (("borrowed_image", "identity"), "changed"),
            (("observer", "outer_process_ceiling"), 513), (("observer", "daemon_depth"), 2),
            (("cases", 0, "configured_limit"), 64), (("cases", 0, "cleanup"), "uncertain"),
            (("cases", 0, "identity", "private_pid"), 2), (("cases", 0, "identity", "pid_namespace"), 100),
            (("cases", 0, "identity", "state_pid"), 999), (("cases", 0, "identity", "outer_uid"), True),
            (("cases", 0, "nproc"), [1024, 35]), (("cases", 0, "preflight", "outer_pids"), 385),
            (("cases", 0, "event_source"), SECRET), (("cases", 0, "work", "diagnostic"), "generic_fork"),
            (("cases", 0, "work", "held_barrier"), 1), (("cases", 0, "elapsed_ns"), 15000000001),
            (("cases", 0, "pids_mapping", "outer_path"), "/sys/fs"),
            (("cases", 0, "memory_mapping", "inode"), 999),
            (("acquisition", "actual_requests"), 17), (("acquisition", "reserved_bytes"), 524289),
            (("accounting", "ordinary_calls"), 124), (("accounting", "cleanup_reserve_seconds"), 45),
            (("accounting", "ordinary_bytes"), 2097153), (("accounting", "cleanup_calls"), 53),
            (("accounting", "elapsed_ns"), 180000000001), (("cleanup", "uncertain"), True),
        ]
        for phase in ("baseline", "held", "restored"):
            for key, invalid in (("pids_current", True), ("pids_max", False), ("denials", -1),
                                 ("oom_kills", 1), ("outer_pids", 385), ("outer_memory", 3221225473),
                                 ("ancestor_headroom", 127), ("phase", SECRET), ("members", [1])):
                changes.append((("cases", 0, phase, key), invalid))
        for route, invalid in changes:
            proof = legacy_fixture()
            selected = proof
            for key in route[:-1]:
                selected = selected[key]
            selected[route[-1]] = invalid
            with self.subTest(route=route):
                with self.assertRaises(ValueError):
                    legacy.validate_pids_limit_proof(proof, fixture()["context"])
                self.reject(compact_legacy(proof))
        for position in range(5):
            proof = fixture()
            proof["cases"][0]["held"][0][2][position] = True
            self.reject(proof)
        proof = fixture()
        proof["cases"].reverse()
        self.reject(proof)
        proof = fixture()
        proof["cases"][1]["id"] = proof["cases"][0]["id"]
        self.reject(proof)

    def test_legacy_result_is_exact_typed_and_new_outcome_is_independent(self):
        expected = {"contract": "pids-limit-v1", "capability_admission": [],
                    "catalogue_admission": False, "scope": legacy.SCOPE}
        for key, invalid in (("contract", "pids-limit-v2"), ("capability_admission", ()),
                             ("capability_admission", ["PidsLimit"]), ("catalogue_admission", 0),
                             ("catalogue_admission", True), ("scope", []), ("scope", SECRET)):
            outcome = deepcopy(expected)
            outcome[key] = invalid
            with patch.object(reader, "validate_pids_limit_proof", return_value=outcome):
                self.reject(fixture())
        for invalid in (None, [], {**expected, SECRET: SECRET}, {key: expected[key] for key in expected if key != "scope"}):
            with patch.object(reader, "validate_pids_limit_proof", return_value=invalid):
                self.reject(fixture())
        with patch.object(reader, "validate_pids_limit_proof", return_value=expected):
            result = reader.validate_pids_limit_v2_proof(fixture(), fixture()["context"])
        self.assertEqual(result, {**expected, "contract": "pids-limit-v2"})
        self.assertIsNot(result, expected)
        self.assertIsNot(result["capability_admission"], expected["capability_admission"])

    def test_canonical_actual_envelope_reserves_1024_bytes_without_file_padding(self):
        proof = fixture()
        original = len(payload(proof).encode())
        # Grow a validated context path, not an ignored field or file padding.
        proof["context"]["outer"]["socket_source"] = "/" + "s" * 20 + "/socket"
        size = len(payload(proof).encode())
        proof["context"]["outer"]["socket_source"] = "/" + "s" * (20 + 15360 - size) + "/socket"
        self.assertLess(original, 15360)
        self.assertEqual(len(payload(proof).encode()), 15360)
        reader.validate_pids_limit_v2_proof(proof, proof["context"])
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = self.write(parent, proof)
            reader.read_pids_limit_v2_proof(target, parent, proof["context"])
            proof["context"]["outer"]["socket_source"] = "/x" + proof["context"]["outer"]["socket_source"]
            self.assertGreater(len(payload(proof).encode()), 15360)
            self.reject(proof, proof["context"])
            self.write(parent, proof)
            with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                reader.read_pids_limit_v2_proof(target, parent, proof["context"])
        self.assertEqual(reader.PROOF_BYTES - reader.SERIALIZED_BYTES, 1024)

    def test_original_bytes_duplicates_and_custody_fail_before_expansion(self):
        proof = fixture()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = self.write(parent, proof)
            for bad in (payload(proof)[:-1] + ',"schema_version":2}',
                        payload(proof).replace('"pid_namespace":100', '"pid_namespace":100,"pid_namespace":100', 1),
                        " " * 16385, payload(proof) + " " * 16384, "", "{", SECRET):
                target.write_text(bad)
                with patch.object(reader, "validate_pids_limit_v2_proof") as expansion:
                    with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                        reader.read_pids_limit_v2_proof(target, parent, proof["context"])
                    expansion.assert_not_called()
            self.write(parent, proof)
            for mode in (0o644, 0o400):
                target.chmod(mode)
                with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                    reader.read_pids_limit_v2_proof(target, parent, proof["context"])
            target.chmod(0o600)
            os.link(target, parent / "hardlink")
            with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                reader.read_pids_limit_v2_proof(target, parent, proof["context"])
            (parent / "hardlink").unlink()
            target.rename(parent / "elsewhere")
            target.symlink_to(parent / "elsewhere")
            with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                reader.read_pids_limit_v2_proof(target, parent, proof["context"])
            target.unlink()
            target = self.write(parent, proof)
            parent.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                reader.read_pids_limit_v2_proof(target, parent, proof["context"])

    def test_utf8_size_is_bytes_not_character_or_ascii_escape_count(self):
        proof = fixture()
        proof["context"]["outer"]["socket_source"] = "/socket"
        available = 15360 - len(payload(proof).encode()) - 1
        proof["context"]["outer"]["socket_source"] = "/" + "é" * (available // 2) + "s" * (available % 2) + "/socket"
        self.assertEqual(len(payload(proof).encode()), 15360)
        self.assertLess(len(payload(proof)), 15360)
        self.assertGreater(len(json.dumps(proof, separators=(",", ":")).encode()), 15360)
        reader.validate_pids_limit_v2_proof(proof, proof["context"])
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = self.write(parent, proof)
            reader.read_pids_limit_v2_proof(target, parent, proof["context"])
        proof["context"]["outer"]["socket_source"] = "/é" + proof["context"]["outer"]["socket_source"]
        self.reject(proof, proof["context"])

    def test_unstable_file_fifo_and_wrong_direct_child_refuse_before_expansion(self):
        proof = fixture()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = self.write(parent, proof)
            original_read = os.read

            def read_then_change(descriptor, count):
                data = original_read(descriptor, count)
                target.write_text(payload(proof) + " ")
                return data

            with patch("native_network_attachment_proof.os.read", side_effect=read_then_change):
                with patch.object(reader, "validate_pids_limit_v2_proof") as expansion:
                    with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                        reader.read_pids_limit_v2_proof(target, parent, proof["context"])
                    expansion.assert_not_called()
            target.unlink()
            os.mkfifo(target, 0o600)
            with patch.object(reader, "validate_pids_limit_v2_proof") as expansion:
                with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                    reader.read_pids_limit_v2_proof(target, parent, proof["context"])
                expansion.assert_not_called()
            target.unlink()
            self.write(parent, proof)
            wrong = parent / "other.json"
            wrong.write_text(payload(proof))
            wrong.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                reader.read_pids_limit_v2_proof(wrong, parent, proof["context"])
            for route, invalid in ((("candidate_sha",), "f" * 40), (("outer", "id"), "e" * 64),
                                   (("daemon_uid",), True), (("outer", "privileged"), 1)):
                bad = deepcopy(proof)
                selected = bad["context"]
                for key in route[:-1]:
                    selected = selected[key]
                selected[route[-1]] = invalid
                self.write(parent, bad)
                with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                    reader.read_pids_limit_v2_proof(target, parent, proof["context"])

    def test_context_rejection_precedes_coordinate_and_legacy_expansion(self):
        proof = fixture()
        for candidate in ("e" * 40, SECRET):
            context = deepcopy(proof["context"])
            context["candidate_sha"] = candidate
            with patch.object(reader, "validate_coordinates", side_effect=AssertionError("coordinate expansion")) as coordinates, \
                    patch.object(reader, "validate_pids_limit_proof", side_effect=AssertionError("legacy expansion")) as semantics:
                self.reject(proof, context)
                coordinates.assert_not_called()
                semantics.assert_not_called()

    def test_old_reader_never_runs_and_context_must_match(self):
        proof = fixture()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = self.write(parent, proof)
            with patch.object(legacy, "read_pids_limit_proof", side_effect=AssertionError("v1 fallback")):
                reader.read_pids_limit_v2_proof(target, parent, proof["context"])
                with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                    reader.read_pids_limit_v2_proof(parent / legacy.FILENAME, parent, proof["context"])
                (parent / legacy.FILENAME).write_text(payload(legacy_fixture()))
                target.write_text(payload(legacy_fixture()))
                with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                    reader.read_pids_limit_v2_proof(target, parent, proof["context"])
                self.write(parent, proof)
            for route in (("candidate_sha",), ("run_id",), ("outer", "owner"), ("daemon_uid",)):
                context = deepcopy(proof["context"])
                selected = context
                for key in route[:-1]:
                    selected = selected[key]
                selected[route[-1]] = SECRET
                with self.assertRaisesRegex(ValueError, "^" + FAILURE + "$"):
                    reader.read_pids_limit_v2_proof(target, parent, context)

    def test_cli_exact_twelve_arguments_current_filename_and_fixed_private_failure(self):
        from native_outer_coordinator import serialize_consumer_context
        from test_native_outer_authority import authority_fixture
        for lane in LANES:
            with tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                outer_context, context, _account, _options, _prefix, proof = authority_fixture(lane, directory)
                proof["boundary"] = outer_context["boundary"]
                proof["observer"].update(zip(("pid_namespace", "mount_namespace", "cgroup_namespace"), outer_context["boundary"][2]))
                proof["observer"]["daemon_pid_namespace"] = outer_context["boundary"][2][0]
                target = self.write(parent, proof)
                arguments = [str(parent), context["candidate_sha"], context["run_id"], lane,
                             context["engine_release"], context["rendering_api"], context["mode"],
                             context["docker_package"], context["fixture_image"], context["outer"]["image"],
                             context["outer"]["id"], str(context["daemon_uid"])]
                command = [sys.executable, str(ROOT / "scripts/native_pids_limit_v2_proof.py")]
                missing = subprocess.run(command + arguments, input="", capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual((missing.returncode, missing.stdout, missing.stderr), (1, "", FAILURE + "\n"))
                # Only source acquisition is authored/injected in this actual
                # child. Its stdin schema, budget, proof custody and all37
                # coordinate predicates are the production reader's code.
                code = '''import sys
import native_outer_coordinator as c
import native_pids_limit_v2_proof as r
from test_native_outer_authority import authority_fixture
_ctx,_expected,account,options,prefix,_proof=authority_fixture(sys.argv[4],sys.argv[1])
original=c.derive_consumer_authority
c.derive_consumer_authority=lambda value,expected,budget=None:original(value,expected,account_loader=lambda *_:account,socket_options=lambda _:options,log_reader=lambda _i,_l,p:p==prefix)
try:r.main(sys.argv[1:])
except (OSError,ValueError):raise SystemExit("invalid private pids limit proof") from None
'''
                fake_command = [sys.executable, "-c", code]
                environment = {**os.environ, "PYTHONPATH": str(ROOT / "scripts") + ":" + str(ROOT / "tests"),
                               "NATIVE_PIDS_LIMIT_DEADLINE_EPOCH": str(outer_context["pids"]["deadline_epoch"])}
                encoded = serialize_consumer_context(outer_context).decode("ascii")
                success = subprocess.run(fake_command + arguments, input=encoded, env=environment,
                                         capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual((success.returncode, success.stdout, success.stderr), (0, "", ""))
                for invalid in (arguments[:-1], arguments + [SECRET], arguments[:-1] + [SECRET]):
                    result = subprocess.run(fake_command + invalid, input=encoded, env=environment,
                                            capture_output=True, text=True, timeout=5, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual((result.stdout, result.stderr), ("", FAILURE + "\n"))
                target.rename(parent / legacy.FILENAME)
                result = subprocess.run(fake_command + arguments, input=encoded, env=environment,
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, FAILURE + "\n")


if __name__ == "__main__":
    unittest.main()
