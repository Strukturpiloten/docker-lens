"""Synthetic nofile protocol controls; these never establish native support."""

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_nofile_proof as reader
from test_native_external_network_proof import fixture as context_fixture

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
SECRET = "PRIVATE_NOFILE_CANARY"


def witness(soft, hard, baseline=3, maximal=False):
    kernel = {"soft": "unlimited" if soft == -1 else soft, "hard": "unlimited" if hard == -1 else hard}
    owners = {}
    paths = ["/tmp/dl-nf/" + name for name in ("gate", "report", "error")]
    paths += [f"/tmp/dl-nf/f{i}" for i in range(1, 257)]
    for index, path in enumerate(paths):
        owners[path] = {"device": reader.U64 if maximal else 100,
                        "inode": reader.U64 - index if maximal else 1000 + index}

    def descriptor(fd, path):
        return {"fd": fd, "target": path, **owners[path]}

    base = [descriptor(i, paths[i % 3]) for i in range(baseline)]
    count = 192 if soft == -1 else soft - baseline
    held = deepcopy(base)
    for i in range(1, count + 1):
        fd = 2**31 - 1 - i if maximal and soft == -1 else baseline + i - 1
        held.append(descriptor(fd, f"/tmp/dl-nf/f{i}"))
    held.sort(key=lambda item: item["fd"])
    samples = {}
    for name in reader.SAMPLES:
        parent = name.startswith("parent") or name == "root_parent"
        samples[name] = {**kernel, "pid": 1 if parent else (2**31 - 1 if maximal else 7), "ppid": 0 if parent else 1}
    outcome = "exact_finite_emfile" if hard != -1 else (
        "exact_hard_unlimited_finite_soft_emfile" if soft != -1 else "exact_both_unlimited_bounded_success")
    return {"outcome": outcome, "kernel": kernel, "samples": samples, "nr_open": 2**31 - 1 if maximal else 1048576,
            "owned_files": owners, "descriptors": {"base": deepcopy(base), "base_repeat": deepcopy(base),
                                                   "saturated": deepcopy(held), "saturated_repeat": deepcopy(held),
                                                   "restored": deepcopy(base)},
            "retained_count": count, "failure": None if soft == -1 else {"getline_return": -1, "errno": 24, "attempt": count + 1},
            "reuse_count": 256, "phases": ["base", "held", "done"],
            "exec_binding": "retained_background_pid_exact_nul_argv_exe_inode_and_proc"}


def fixture(lane="upstream-rootful", baseline=3, maximal=False):
    context = deepcopy(context_fixture(lane)["context"])
    context["fixture_image"] = "docker.io/library/busybox:1.37.0@sha256:" + "b" * 64
    image = "sha256:" + "d" * 64
    cases = []
    for case_index, (name, soft, hard) in enumerate(reader.CASES):
        items = []
        for role_index, role in enumerate(("oracle", "rendered")):
            items.append({"role": role, "id": f"{2 * case_index + role_index + 1:064x}",
                          "name": f"dl-nf-{context['run_id']}-{name}-{role}", "owner": context["run_id"],
                          "image_id": image, "wire": "independent_cli" if role == "oracle" else "literal_rendered",
                          "configured": {"soft": soft, "hard": hard}, "cleanup": "absent",
                          "effect": {"stage": "running", "cli_exit": 0 if role == "oracle" else None,
                                     "http_status": None if role == "oracle" else 204, "diagnostic": None,
                                     "witness": witness(soft, hard, baseline, maximal)}})
        cases.append({"case": name, "containers": items})
    context_calls = 9 if lane.startswith("debian11-") else 8
    return {"schema_version": 1, "contract": "nofile-v1", "capability_admission": [], "catalogue_admission": False,
            "scope": "four_diagonal_nofile_cases_source_only", "context": context,
            "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"},
            "cases": cases, "daemon_health": "version_matches_after_all_cases",
            "acquisition": {"route": "explicit_unix_socket", "selected_ids": 8, "requested_api": context["acquisition_api"],
                            "reserved_calls": 20, "reserved_bytes": 524288, "actual_requests": 11, "actual_response_bytes": 65536,
                            "decoded": "present_effective_exact_nofile_values",
                            "daemon_mode_evidence": "rootless_observed" if lane.endswith("rootless") else "unknown_with_independent_rootful_context",
                            "byte_scope": "decoded_response_bodies_only",
                            "separate_transport_bounds": {"response_header_bytes": 16384, "chunk_line_bytes": 64,
                                                          "chunk_payload_crlf_bytes": 2, "final_trailer_line_bytes": 16384,
                                                          "actual_wire_bytes": "not_measured"},
                            "limits": {"max_requests": 20, "max_selected_resources": 8, "max_expansions": 10,
                                       "max_response_bytes": 131072, "max_total_bytes": 524288, "max_elapsed_seconds": 10}},
            "accounting": {"context_calls": context_calls, "slot_calls": [8] * 8, "daemon_health_calls": 1,
                           "acquisition_reserved_calls": 20, "final_readback_calls": 2, "ordinary_calls": context_calls + 87,
                           "ordinary_bytes": 1048576, "cleanup_calls": 72, "cleanup_bytes": 8192, "deadline_seconds": 180,
                           "cleanup_reserve_seconds": 46, "ordinary_elapsed_ns": 5_000_000_000,
                           "cleanup_elapsed_ns": 2_000_000_000, "elapsed_ns": 8_000_000_000,
                           "initial_context_acquisition": {"max_requests": 16, "max_total_bytes": 2097152,
                                                           "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"}},
            "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


def refuse_case(proof, case_index):
    for role_index, item in enumerate(proof["cases"][case_index]["containers"]):
        item["effect"] = {"stage": "start_refused", "cli_exit": 1 if role_index == 0 else None,
                          "http_status": 500 if role_index == 1 else None,
                          "diagnostic": "OCI runtime create failed: error setting rlimit type 7: operation not permitted: unknown",
                          "witness": {"outcome": "specific_nofile_start_refusal", "status": "created", "pid": 0,
                                      "never_started": True, "terminal_unchanged": True, "error": "setting_rlimit_nofile_eperm"}}
        proof["accounting"]["slot_calls"][2 * case_index + role_index] = 7
        proof["accounting"]["ordinary_calls"] -= 1


def report_bytes(value):
    """Independent upper-width rendering of the complete actual text protocol."""
    lines = [f"nr_open {value['nr_open']}"]
    for path, node in value["owned_files"].items():
        lines.append(f"own {path} {node['device']} {node['inode']}")
    for phase, items in value["descriptors"].items():
        for item in items:
            lines.append(f"fd {phase} {item['fd']} {item['target']} {item['device']} {item['inode']}")
    for name, item in value["samples"].items():
        lines.append(f"{name} {item['soft']} {item['hard']} {item['pid']} {item['ppid']}")
    failure = value["failure"]
    lines.append(f"held {value['retained_count']} {-1 if failure else 1} {24 if failure else 0}")
    lines += ["reuse 256", "phase base", "phase held", "phase done"]
    return len(("\n".join(lines) + "\n").encode())


class NofileProofTests(unittest.TestCase):
    def reject(self, value, context=None):
        with self.assertRaisesRegex(ValueError, "^invalid private nofile proof$") as caught:
            reader.validate_nofile_proof(value, fixture()["context"] if context is None else context)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_all_four_contexts_and_independently_measured_non_three_baselines(self):
        for lane in LANES:
            for baseline in (3, 4, 16):
                value = fixture(lane, baseline)
                self.assertEqual(reader.validate_nofile_proof(value, value["context"]),
                                 {"contract": "nofile-v1", "capability_admission": [], "catalogue_admission": False})

    def test_precise_start_refusal_is_distinct_from_normalization_and_exact_unlimited(self):
        value = fixture()
        for case_index in (2, 3):
            refuse_case(value, case_index)
        reader.validate_nofile_proof(value, value["context"])
        normalized = fixture()
        for case_index in (2, 3):
            for item in normalized["cases"][case_index]["containers"]:
                observed = item["effect"]["witness"]
                observed["outcome"] = "finite_kernel_normalization"
                observed["kernel"]["hard"] = 1048576
                if case_index == 3:
                    observed["kernel"]["soft"] = 1048576
                for sample in observed["samples"].values():
                    sample.update(observed["kernel"])
        reader.validate_nofile_proof(normalized, normalized["context"])
        for diagnostic in ("operation not permitted", "error setting rlimit type 6: operation not permitted",
                           "error setting rlimit type 7: no space left on device", "PRIVATE_" + SECRET):
            wrong = deepcopy(value)
            wrong["cases"][2]["containers"][0]["effect"]["diagnostic"] = diagnostic
            self.reject(wrong)
        wrong = deepcopy(value)
        wrong["cases"][2]["containers"][0]["effect"]["stage"] = "create_refused"
        self.reject(wrong)

    def test_maximal_complete_serialization_and_command_output_fit_without_budget_growth(self):
        value = fixture("debian11-rootless", baseline=16, maximal=True)
        before = reader.metadata_size(value)
        value["context"]["outer"]["socket_source"] = "/" + "x" * (65536 - before + len(value["context"]["outer"]["socket_source"]) - 8) + "/socket"
        self.assertEqual(reader.metadata_size(value), 65536)
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertGreater(len(payload), 16384)
        self.assertLessEqual(len(payload), 512 * 1024)
        inventory = len(payload) - reader.metadata_size(value)
        self.assertLessEqual(inventory, 427672)
        reader.validate_nofile_proof(value, value["context"])
        records = [item["effect"]["witness"] for case in value["cases"] for item in case["containers"]]
        self.assertEqual(sum(len(w["owned_files"]) for w in records), 2072)
        self.assertEqual(sum(len(items) for w in records for items in w["descriptors"].values()), 2240)
        for observed in records:
            self.assertLessEqual(report_bytes(observed), 65550)
        value["context"]["outer"]["socket_source"] += "x"
        self.reject(value, value["context"])

    def test_fd_holes_recycling_target_inode_alias_and_live_process_drift_refuse(self):
        mutations = (
            lambda w: w["descriptors"]["saturated"][3].update(fd=999),
            lambda w: w["descriptors"]["saturated"][3].update(target="/tmp/dl-nf/f2"),
            lambda w: w["descriptors"]["saturated"][3].update(inode=99999),
            lambda w: w["descriptors"]["restored"].append(deepcopy(w["descriptors"]["saturated"][3])),
            lambda w: w["samples"]["bound_post"].update(pid=8),
            lambda w: w["samples"]["parent_pre"].update(soft=128),
            lambda w: w["samples"]["self_post"].update(hard=64),
            lambda w: w["owned_files"]["/tmp/dl-nf/f2"].update(w["owned_files"]["/tmp/dl-nf/f1"]),
        )
        for mutate in mutations:
            value = fixture()
            mutate(value["cases"][0]["containers"][0]["effect"]["witness"])
            self.reject(value)

    def test_wrong_errno_ceiling_control_and_bool_numeric_witnesses_refuse(self):
        for errno in (True, 1, 23, 28, "24", 110):
            value = fixture()
            value["cases"][0]["containers"][0]["effect"]["witness"]["failure"]["errno"] = errno
            self.reject(value)
        for mutate in (
            lambda w: w.update(retained_count=192),
            lambda w: w.update(reuse_count=128),
            lambda w: w.update(failure=None),
            lambda w: w.update(nr_open=64),
            lambda w: w["descriptors"]["base"][0].update(fd=False),
        ):
            value = fixture()
            mutate(value["cases"][0]["containers"][0]["effect"]["witness"])
            self.reject(value)

    def test_pair_disagreement_ids_context_cleanup_budgets_and_admission_refuse(self):
        for field, wrong in (("ordinary_calls", 1), ("cleanup_calls", 71), ("ordinary_bytes", 2097153),
                             ("cleanup_reserve_seconds", 45), ("deadline_seconds", 181), ("ordinary_elapsed_ns", 135 * 10**9)):
            value = fixture()
            value["accounting"][field] = wrong
            self.reject(value)
        for mutate in (
            lambda p: p.update(capability_admission=["Ulimits"]),
            lambda p: p.update(catalogue_admission=True),
            lambda p: p["cleanup"].update(uncertain=True),
            lambda p: p["cases"][1]["containers"][0].update(id=None),
            lambda p: p["cases"][1]["containers"][0].update(id=p["context"]["outer"]["id"]),
            lambda p: p["cases"][2]["containers"][0]["effect"]["witness"].update(outcome="finite_kernel_normalization"),
            lambda p: p["acquisition"].update(selected_ids=4),
            lambda p: p["acquisition"].update(daemon_mode_evidence="rootless_observed"),
            lambda p: p["context"].update(candidate_sha="e" * 40),
        ):
            value = fixture()
            mutate(value)
            self.reject(value)

    def test_closed_nested_objects_and_required_fields(self):
        paths = ((), ("borrowed_image",), ("accounting",), ("acquisition",), ("cleanup",),
                 ("cases", 0), ("cases", 0, "containers", 0), ("cases", 0, "containers", 0, "effect"),
                 ("cases", 0, "containers", 0, "effect", "witness"),
                 ("cases", 0, "containers", 0, "effect", "witness", "kernel"))
        for path in paths:
            value = fixture()
            obj = value
            for part in path:
                obj = obj[part]
            obj[SECRET] = SECRET
            self.reject(value)
            del obj[SECRET]
            del obj[next(iter(obj))]
            self.reject(value)

    def test_shared_custody_forwarding_uses_fixed_filename_and_only_new_bound(self):
        # Shared keyword/method implementation and custody boundary tests belong
        # to main integration, not this source-only five-file worktree.
        value = fixture()
        with patch.object(reader, "read_private_proof", return_value="sentinel") as shared:
            self.assertEqual(reader.read_nofile_proof(Path("/private/capture/nofile-v1.json"),
                                                    "/private/capture", value["context"]), "sentinel")
            shared.assert_called_once_with(Path("/private/capture/nofile-v1.json"), "/private/capture",
                                           "nofile-v1.json", value["context"], reader.validate_nofile_proof,
                                           max_bytes=524288)
        with patch.object(reader, "read_private_proof", side_effect=ValueError(SECRET)):
            with self.assertRaisesRegex(ValueError, "^invalid private nofile proof$"):
                reader.read_nofile_proof(Path("/private/capture/nofile-v1.json"), "/private/capture", value["context"])

    def test_twelve_fact_cli_is_independent_silent_and_default_private(self):
        value = fixture()
        context = value["context"]
        args = ["/private/capture", context["candidate_sha"], context["run_id"], context["lane"],
                context["engine_release"], context["rendering_api"], context["mode"], context["docker_package"],
                context["fixture_image"], context["outer"]["image"], context["outer"]["id"], str(context["daemon_uid"])]
        with patch.object(reader, "read_nofile_proof") as read, contextlib.redirect_stdout(io.StringIO()) as output:
            reader.main(args)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(read.call_args.args[2], context)
        for bad in (args[:-1], args + [SECRET], args[:-1] + ["00"]):
            with self.assertRaisesRegex(ValueError, "^invalid private nofile proof$"):
                reader.main(bad)


if __name__ == '__main__':
    unittest.main()
