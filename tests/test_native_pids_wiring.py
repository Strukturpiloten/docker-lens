"""PIDs27 closed argv/caller/stream controls with inert runtime substitutes."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CID = "a" * 64
NONCE = "0123456789abcdef0123456789abcdef"
TEST = "live_pids_limits_and_effects_match_engine"
SELECTED = "native_health_metadata_tests::lifecycle::pids::" + TEST
HANDOFF = "DOCKERLENS_NATIVE_LIFECYCLE_CLEANUP: owner=native_conformance_outer_v1 scope=outer_container_and_data_volume state=required"
SETUP_REFUSAL = "DOCKERLENS_NATIVE_PIDS_SETUP_REFUSAL: code="
IO_DETAIL = "DOCKERLENS_NATIVE_PIDS_IO:"


class PidsWiringTests(unittest.TestCase):
    def bridge(self, engine, arguments):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "native-outer-command.sh"
            script.write_bytes((ROOT / "scripts/native-outer-command.sh").read_bytes())
            (root / "native-outer-runtime.sh").write_text('''native_outer_attach() {
  [[ $1 == "$EXPECTED_ENGINE" && $2 == "$EXPECTED_DIRECTORY" ]] || return 1
  native_outer_cmd=("$FAKE_RUNTIME")
}
''')
            runtime = root / "inert-runtime"
            runtime.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ["TRACE"]).write_text(json.dumps(sys.argv[1:]))
sys.stdout.buffer.write(sys.stdin.buffer.read())
''')
            runtime.chmod(0o700)
            result = subprocess.run(["bash", str(script), "--engine", engine, "--directory", directory, "pids-controller", *arguments],
                input=b"private literal stream\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env={**os.environ, "EXPECTED_ENGINE": engine, "EXPECTED_DIRECTORY": directory,
                     "FAKE_RUNTIME": str(runtime), "TRACE": str(root / "trace")}, timeout=5)
            trace = json.loads((root / "trace").read_text()) if (root / "trace").exists() else None
            return result, trace

    def test_selected_backend_keeps_fixed_argv_and_interactive_bytes_without_host_runtime(self):
        for engine in ("podman", "docker"):
            for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
                args = [CID, "Ab12Cd34", lane, NONCE, "123456789"]
                result, trace = self.bridge(engine, args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(trace, ["exec", "-i", "--user", "0", CID,
                    "/dockerlens-native/pids-worker/native-pids-worker", "serve", *args[1:]])
                self.assertEqual(result.stdout, b"private literal stream\n")
                self.assertEqual(result.stderr, b"")

    def test_bridge_rejects_widening_ids_lanes_nonce_deadline_and_extra_arguments(self):
        args = [CID, "Ab12Cd34", "upstream-rootful", NONCE, "123456789"]
        for changed in [args + ["/bin/sh"], args[:-1], ["name", *args[1:]], [CID, "../run", *args[2:]],
                        [*args[:2], "foreign-rootful", *args[3:]], [*args[:3], "x" * 32, args[4]],
                        [*args[:4], "0"], [*args[:4], "123;id"]]:
            result, trace = self.bridge("podman", changed)
            self.assertEqual(result.returncode, 2)
            self.assertIsNone(trace)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"native outer command refused\n")

    def wrapper(self, output, status=0, listing=None, *, target="native_pids", test_name=TEST,
                registry=None, registry_kind="file", capture_failure=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "src").mkdir()
            capture_parent = root / "captures"
            capture_parent.mkdir(mode=0o700)
            if capture_failure in ("create", "write"):
                mktemp = root / "mktemp"
                mktemp.write_text('''#!/usr/bin/env python3
import os, sys, tempfile
if os.environ["CAPTURE_FAILURE"] == "create":
    print("PRIVATE_CAPTURE_PATH_CANARY", file=sys.stderr)
    raise SystemExit(1)
directory = tempfile.mkdtemp()
with open(os.path.join(directory, "run.raw"), "xb") as held:
    held.write(b"private preexisting capture")
print(directory)
''')
                mktemp.chmod(0o700)
            if capture_failure == "cleanup":
                remove = root / "rm"
                remove.write_text('#!/usr/bin/env bash\nprintf "PRIVATE_CAPTURE_PATH_CANARY\\n" >&2\nexit 1\n')
                remove.chmod(0o700)
            wrapper = root / "scripts/run-exact-native-test.sh"
            wrapper.write_bytes((ROOT / "scripts/run-exact-native-test.sh").read_bytes())
            registry_path = root / "src/native_pids_setup_refusals.txt"
            registry_bytes = (ROOT / "src/native_pids_setup_refusals.txt").read_bytes() if registry is None else registry
            if registry_kind == "file":
                registry_path.write_bytes(registry_bytes)
            elif registry_kind == "symlink":
                (root / "foreign-registry").write_bytes(registry_bytes)
                registry_path.symlink_to(root / "foreign-registry")
            elif registry_kind == "fifo":
                os.mkfifo(registry_path)
            elif registry_kind != "missing":
                raise AssertionError("unknown inert registry fixture")
            (root / "output").write_bytes(output.encode() if isinstance(output, str) else output)
            selected = "native_health_metadata_tests::lifecycle::pids::" + test_name if target == "native_pids" else test_name
            listing = selected + ": test" if listing is None else listing
            (root / "listing").write_bytes(listing.encode() if isinstance(listing, str) else listing)
            cargo = root / "cargo"
            cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open(os.environ["TRACE"], "a") as stream:
    stream.write(json.dumps({"argv":sys.argv[1:], "deadline":os.environ.get("NATIVE_PIDS_DEADLINE_EPOCH"),
                            "owner":os.environ.get("NATIVE_LIFECYCLE_CLEANUP_OWNER")}) + "\\n")
if "--list" in sys.argv:
    sys.stdout.buffer.write(Path(os.environ["LISTING_PATH"]).read_bytes() + b"\\n")
else:
    sys.stdout.buffer.write(Path(os.environ["OUTPUT_PATH"]).read_bytes() + b"\\n")
    sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o700)
            result = subprocess.run(["bash", str(wrapper), target, test_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "TRACE": str(root / "trace"),
                     "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1", "LISTING_PATH": str(root / "listing"),
                     "OUTPUT_PATH": str(root / "output"), "STATUS": str(status), "TMPDIR": str(capture_parent),
                     "CAPTURE_FAILURE": capture_failure or ""})
            if capture_failure != "cleanup":
                self.assertEqual(list(capture_parent.iterdir()), [], "private raw captures must be removed")
            else:
                self.assertTrue(list(capture_parent.iterdir()), "fixture must actually refuse raw-capture cleanup")
            self.assertNotIn(b"PRIVATE_CAPTURE_PATH_CANARY", result.stdout + result.stderr)
            trace = root / "trace"
            return result, [json.loads(row) for row in trace.read_text().splitlines()] if trace.exists() else []

    def test_exact_selector_and_original_deadline_reject_zero_execution_and_cleanup_handoff(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        result, trace = self.wrapper(success)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(trace), 2)
        self.assertIn("--lib", trace[1]["argv"])
        self.assertIn(SELECTED, trace[1]["argv"])
        self.assertIn("--ignored", trace[1]["argv"])
        self.assertIn("--exact", trace[1]["argv"])
        self.assertRegex(trace[1]["deadline"], r"^[1-9][0-9]+$")
        self.assertEqual(trace[1]["owner"], "native_conformance_outer_v1")
        for output, status, listing in [(success, 0, ""), (success, 0, (SELECTED + ": test\n") * 2),
                (success.replace("1 passed", "0 passed"), 0, None), (success + "\n" + HANDOFF, 0, None),
                ("DOCKERLENS_NATIVE_CHECK: pids_context\nPRIVATE_PIDS_CANARY\n" + success, 1, None)]:
            result, _ = self.wrapper(output, status, listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"PRIVATE_PIDS_CANARY", result.stdout + result.stderr)

    def test_constructor_refusal_registry_is_packaged_and_projects_every_actual_code_on_failure(self):
        # Independent complete expectations: changing registry alone cannot
        # silently expand the reviewed constructor diagnostic vocabulary.
        expected = (
            "pids-ancillary pids-artifact pids-artifact-source pids-bootstrap pids-budget "
            "pids-build-tools pids-build-tools-raw pids-capture pids-cgroup-namespace "
            "pids-child-custody pids-clock pids-deadline pids-eof pids-frame pids-frames "
            "pids-input pids-integer pids-json pids-nonce pids-outer pids-outer-changed "
            "pids-proc pids-read pids-reservation pids-schema pids-sequence pids-shutdown "
            "pids-socket pids-source-budget pids-status pids-supervisor pids-write"
        ).split()
        self.assertEqual((ROOT / "src/native_pids_setup_refusals.txt").read_text().splitlines(), expected)
        self.assertIn('include_str!("native_pids_setup_refusals.txt")', (ROOT / "src/native_pids_tests.rs").read_text())
        self.assertIn('"src/**"', (ROOT / "Cargo.toml").read_text())
        for code in expected + ["unclassified"]:
            with self.subTest(code=code):
                line = SETUP_REFUSAL + code
                output = "DOCKERLENS_NATIVE_CHECK: pids_context\n" + line + "\nPRIVATE_PIDS_CANARY"
                result, trace = self.wrapper(output, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(trace), 2)
                self.assertIn((line + "\n").encode(), result.stderr)
                self.assertEqual(result.stderr.count(SETUP_REFUSAL.encode()), 1)
                self.assertIn(b"DOCKERLENS_NATIVE_CHECK: pids_context\n", result.stderr)
                self.assertNotIn(b"PRIVATE_PIDS_CANARY", result.stdout + result.stderr)
                self.assertLessEqual(len(line), 64)

    def test_constructor_refusal_projection_is_failure_only_and_exact_test_only(self):
        line = SETUP_REFUSAL + "pids-outer"
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        for kwargs in ({"status": 101, "target": "native_container"},
                       {"status": 101, "test_name": "other_pids_test"}):
            result, _ = self.wrapper(line + "\n" + success, **kwargs)
            self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)
            self.assertEqual(result.returncode == 0, kwargs["status"] == 0)
        result, _ = self.wrapper(success)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)

    def test_constructor_refusal_projection_rejects_private_suffixes_unknowns_and_duplicates(self):
        valid = SETUP_REFUSAL + "pids-outer"
        for output in [
            SETUP_REFUSAL + "pids-secret-PRIVATE_PIDS_CANARY",
            SETUP_REFUSAL + "/tmp/PRIVATE_PIDS_CANARY/socket",
            SETUP_REFUSAL + "token=PRIVATE_PIDS_CANARY",
            SETUP_REFUSAL + "pids-version",
            valid + " PRIVATE_PIDS_CANARY",
            valid + "\r",
            SETUP_REFUSAL + "pids-ou\0ter",
            valid + "\0",
            valid + "\0PRIVATE_PIDS_CANARY",
            valid + "\x1b[31mPRIVATE_PIDS_CANARY",
            SETUP_REFUSAL + "pids-secret-" + "x" * 70000,
            valid + "\n" + SETUP_REFUSAL + "pids-cgroup-namespace",
            valid + "\n" + SETUP_REFUSAL + "pids-secret-PRIVATE_PIDS_CANARY",
            "x" * 1048577 + "\n" + valid,
        ]:
            with self.subTest(length=len(output)):
                result, _ = self.wrapper(output, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)
                self.assertNotIn(b"PRIVATE_PIDS_CANARY", result.stdout + result.stderr)
                self.assertNotIn(b"ignored null byte", result.stdout + result.stderr)
                self.assertNotIn(b"run-exact-native-test.sh:", result.stdout + result.stderr)
                self.assertIn(b"(exit 101)", result.stderr)

    def test_constructor_refusal_deduplicates_identical_records_but_rejects_success_conflicts(self):
        line = SETUP_REFUSAL + "pids-outer"
        result, _ = self.wrapper(line + "\n" + line, status=101)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.count((line + "\n").encode()), 1)
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        evidence = "DOCKERLENS_NATIVE_CHECK: pids_evidence"
        for output, status in [(line + "\n" + evidence, 101), (evidence + "\n" + line, 101),
                               (line + "\n" + success, 101), (line + "\n" + success, 0),
                               (line, 0), (line + "\n" + evidence, 0)]:
            result, _ = self.wrapper(output, status=status)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(line.encode(), result.stdout + result.stderr)
            self.assertNotIn(evidence.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"test result: ok.", result.stdout + result.stderr)
            self.assertIn((SETUP_REFUSAL + "unclassified\n").encode(), result.stderr)
            self.assertNotIn(b"required native test passed:", result.stdout + result.stderr)
        for registry in [b"", None]:
            result, _ = self.wrapper(line + "\n" + evidence + "\n" + success, status=0, registry=registry)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(evidence.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"test result: ok.", result.stdout + result.stderr)
            self.assertIn((SETUP_REFUSAL + "unclassified\n").encode(), result.stderr)

    def test_raw_capture_refuses_invalid_listing_and_oversize_without_normalizing_bytes(self):
        for listing in [(SELECTED + ": test\0").encode(), b"x" * 1048577]:
            result, trace = self.wrapper("", listing=listing)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(trace), 1)
            self.assertNotIn(b"ignored null byte", result.stdout + result.stderr)
            self.assertNotIn(b"run-exact-native-test.sh:", result.stdout + result.stderr)
        for output in [SETUP_REFUSAL.encode() + b"pids-ou\0ter", b"x" * 1048577]:
            result, _ = self.wrapper(output, status=0)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"ignored null byte", result.stdout + result.stderr)
        output = b"\x1b[31mUTF8: \xc3\xa9\x1b[0m\nDOCKERLENS_NATIVE_CHECK: pids_context\n"
        output += (SETUP_REFUSAL + "pids-outer").encode()
        result, _ = self.wrapper(output, status=101)
        self.assertIn((SETUP_REFUSAL + "pids-outer\n").encode(), result.stderr)
        self.assertIn(b"DOCKERLENS_NATIVE_CHECK: pids_context\n", result.stderr)
        self.assertNotIn(b"UTF8", result.stdout + result.stderr)

    def test_raw_capture_creation_write_and_cleanup_failures_stay_closed(self):
        for failure in ["create", "write", "cleanup"]:
            result, _ = self.wrapper(SETUP_REFUSAL + "pids-outer", status=101, capture_failure=failure)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"PRIVATE_CAPTURE_PATH_CANARY", result.stdout + result.stderr)
            self.assertNotIn(b"run-exact-native-test.sh:", result.stdout + result.stderr)
            if failure == "cleanup":
                self.assertIn(b"private capture cleanup unavailable", result.stderr)
            if failure == "write":
                self.assertIn(b"(exit 101)", result.stderr)
                self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        result, _ = self.wrapper(success, capture_failure="cleanup")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"required native test passed:", result.stdout + result.stderr)

    def test_constructor_refusal_projection_fails_closed_for_registry_tampering(self):
        registry = (ROOT / "src/native_pids_setup_refusals.txt").read_bytes()
        for changed in [b"", registry.rstrip(b"\n"), registry.replace(b"\n", b"\r\n"),
                        registry.replace(b"pids-write", b"pids-status"),
                        registry.replace(b"pids-write", b"pids-secret-xxxxxxxxxx"),
                        registry.replace(b"pids-write", b"pids-WRITE"),
                        registry.replace(b"pids-write", b"pids--write"),
                        registry.replace(b"pids-write", b"pids-write-"),
                        registry.replace(b"pids-write", b"pids-writ\xff"),
                        registry + b"pids-z\n", b"x" * 705,
                        b"\n".join(reversed(registry.splitlines())) + b"\n"]:
            result, _ = self.wrapper(SETUP_REFUSAL + "pids-outer", status=101, registry=changed)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)
        for kind in ["missing", "symlink", "fifo"]:
            result, _ = self.wrapper(SETUP_REFUSAL + "pids-outer", status=101, registry_kind=kind)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)

    def test_constructor_io_projects_only_closed_paired_phase_and_kind_on_failure(self):
        general = SETUP_REFUSAL + "pids-read"
        for phase in ("ready", "bind", "confirm"):
            for kind in ("reset", "not_connected", "bad_descriptor", "invalid_argument",
                         "permission_denied", "resource", "other"):
                detail = IO_DETAIL + f" phase={phase} kind={kind}"
                with self.subTest(phase=phase, kind=kind):
                    self.assertLessEqual(len(detail.encode("ascii")), 64)
                    result, _ = self.wrapper(detail + "\n" + general + "\n" + detail + "\n" + general, status=101)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stderr.count((general + "\n").encode()), 1)
                    self.assertEqual(result.stderr.count((detail + "\n").encode()), 1)
                    self.assertIn(b"(exit 101)", result.stderr)

    def test_constructor_io_rejects_unpaired_conflicting_malformed_and_private_detail(self):
        general = SETUP_REFUSAL + "pids-read"
        detail = IO_DETAIL + " phase=ready kind=reset"
        bad_details = [
            IO_DETAIL,
            IO_DETAIL + " phase=bootstrap_ready kind=reset",
            IO_DETAIL + " phase=ready kind=ECONNRESET",
            IO_DETAIL + " phase=ready kind=reset errno=104",
            IO_DETAIL + " phase=ready kind=PRIVATE_PIDS_CANARY",
            detail + " PRIVATE_PIDS_CANARY",
            detail + "\r",
            " " + detail,
            detail + "\0PRIVATE_PIDS_CANARY",
            detail + "\n" + IO_DETAIL + " phase=confirm kind=reset",
            detail + "\n" + IO_DETAIL + " phase=ready kind=other",
            detail + "\n" + IO_DETAIL + " PRIVATE_PIDS_CANARY",
            IO_DETAIL + "x" * 70000,
        ]
        outputs = [detail, general, SETUP_REFUSAL + "pids-eof\n" + detail,
                   SETUP_REFUSAL + "unclassified\n" + detail,
                   general + "\n" + SETUP_REFUSAL + "pids-outer\n" + detail]
        outputs.extend(general + "\n" + bad for bad in bad_details)
        for output in outputs:
            with self.subTest(length=len(output)):
                result, _ = self.wrapper(output, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(IO_DETAIL.encode(), result.stdout + result.stderr)
                self.assertNotIn(b"PRIVATE_PIDS_CANARY", result.stdout + result.stderr)
                self.assertIn(b"(exit 101)", result.stderr)
        for target, name in [("native_pids", "other_pids_test"), ("native_nofile", "other_test")]:
            result, _ = self.wrapper(general + "\n" + detail, status=101, target=target, test_name=name)
            self.assertNotIn(IO_DETAIL.encode(), result.stdout + result.stderr)
            self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)

    def test_constructor_io_any_prefix_contradicts_success_even_without_valid_companion(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        evidence = "DOCKERLENS_NATIVE_CHECK: pids_evidence"
        detail = IO_DETAIL + " phase=bind kind=permission_denied"
        for diagnostic in (detail, IO_DETAIL, IO_DETAIL + " PRIVATE_PIDS_CANARY",
                           SETUP_REFUSAL + "pids-read\n" + detail):
            for status, positive in [(0, ""), (0, success), (0, evidence),
                                     (101, success), (101, evidence)]:
                for output in (diagnostic + "\n" + positive, positive + "\n" + diagnostic):
                    with self.subTest(diagnostic=diagnostic, status=status, positive=positive):
                        result, _ = self.wrapper(output, status=status)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn(IO_DETAIL.encode(), result.stdout + result.stderr)
                        self.assertNotIn(b"PRIVATE_PIDS_CANARY", result.stdout + result.stderr)
                        self.assertNotIn(evidence.encode(), result.stdout + result.stderr)
                        self.assertNotIn(success.encode(), result.stdout + result.stderr)
                        self.assertIn((SETUP_REFUSAL + "unclassified\n").encode(), result.stderr)

    def test_canonical27_is_after_kernel_reader_and_before_final_emission(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        calls = re.findall(r'run-exact-native-test\.sh" ([a-z_0-9]+) ([a-z_0-9]+)', source)
        self.assertEqual(calls[-2:], [("native_kernel_settings", "live_kernel_settings_match_engine"), ("native_pids", TEST)])
        self.assertEqual(len(calls), 27)
        reader = source.index('python3 "$script_dir/native_pids_proof.py"')
        child = source.index('"$(dirname "$0")/run-exact-native-test.sh" native_pids')
        prebuild = source.index('python3 "$script_dir/build-native-pids-worker.py"')
        publication = source.index('publish_native_evidence() {')
        self.assertEqual(source.count('publish_native_evidence() {'), 1)
        self.assertLess(source.index('python3 "$script_dir/native_kernel_settings_proof.py"'), child)
        self.assertLess(prebuild, child)
        self.assertLess(child, reader)
        # The maintained-profile lane publishes only during EXIT after outer
        # teardown. Native work must complete before that deferred function is
        # even defined, irrespective of optional public evidence selection.
        for required_native_step in (prebuild, child, reader):
            self.assertLess(required_native_step, publication)
        self.assertLess(reader, source.index('if [[ -n ${DOCKERLENS_NATIVE_EVIDENCE_DIR:-} ]]', reader))

    def test_required27_precedes_cleanup_and_failure_never_reaches_deferred_publication(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        # Execute the actual final coordinator segment with inert command
        # substitutes. Only publication is deferred; no runtime is contacted.
        start = source.index('# Build the fixed inert witness before invocation27')
        end = source.index('\nnative_success_summary=', start)
        segment = source[start:end]
        for profile in ("", "owned-profile"):
            for evidence in ("", "synthetic-evidence"):
                for failure in ("", "prebuild", "child", "reader"):
                    with self.subTest(profile=profile, evidence=bool(evidence), failure=failure), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / "socket").mkdir(mode=0o700)
                        (root / "python3").write_text('''#!/usr/bin/python3
import os, sys
if sys.argv[1] == "-c":
    print("123456789")
    raise SystemExit(0)
name = sys.argv[1].rsplit("/", 1)[-1]
event = {"build-native-pids-worker.py":"prebuild", "native_pids_proof.py":"reader"}[name]
with open(os.environ["TRACE"], "a") as stream:
    stream.write(event + "\\n")
raise SystemExit(int(os.environ["FAILURE"] == event))
''')
                        (root / "python3").chmod(0o700)
                        child = root / "run-exact-native-test.sh"
                        child.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ $1 == native_pids && $2 == live_pids_limits_and_effects_match_engine ]]
printf 'child\\n' >> "$TRACE"
[[ $FAILURE != child ]]
''')
                        child.chmod(0o700)
                        harness = root / "coordinator-tail.sh"
                        harness.write_text('''#!/usr/bin/env bash
set -euo pipefail
native_publication_command() {
  if [[ $1 == git ]]; then
    if [[ $* == *'rev-parse HEAD' ]]; then printf '%s\\n' "$NATIVE_PIDS_CANDIDATE_SHA"; fi
  else
    printf 'emitter\\n' >> "$TRACE"
  fi
}
cleanup() {
  local status=$?
  trap - EXIT
  printf 'teardown\\n' >> "$TRACE"
  if [[ -n $apparmor_profile && $status == 0 && ${apparmor_native_completed:-0} == 1 ]]; then
    publish_native_evidence || status=$?
  fi
  exit "$status"
}
trap cleanup EXIT
''' + segment + '\nprintf "complete\\n" >> "$TRACE"\n')
                        variables = {name: "synthetic" for name in (
                            "run_id", "lane", "server_version", "api_version", "expected_mode", "image", "installed_docker_package",
                            "NATIVE_FIXTURE_IMAGE", "NATIVE_OUTER_CONTAINER_ID", "NATIVE_OUTER_IMAGE", "NATIVE_SHAPES_PATH",
                            "NATIVE_SOURCE_PROBES_PATH", "NATIVE_NETWORK_PROBES_PATH", "NATIVE_VOLUME_PROBES_PATH",
                            "NATIVE_VOLUME_LABEL_PROBES_PATH", "NATIVE_IDENTITY_PROBES_PATH", "NATIVE_PORT_PROBES_PATH",
                            "NATIVE_HEALTH_METADATA_PROOF_PATH", "NATIVE_NETWORK_ATTACHMENT_PROOF_PATH", "NATIVE_BIND_RELABEL_PROOF_PATH")}
                        result = subprocess.run(["bash", str(harness)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5,
                            env={**os.environ, **variables, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                                 "TRACE": str(root / "trace"), "FAILURE": failure, "run_dir": directory, "script_dir": directory,
                                 "NATIVE_PIDS_CANDIDATE_SHA": "a" * 40, "DOCKERLENS_NATIVE_CANDIDATE_SHA": "a" * 40,
                                 "apparmor_profile": profile, "DOCKERLENS_NATIVE_EVIDENCE_DIR": evidence})
                        trace = (root / "trace").read_text().splitlines()
                        expected = ["prebuild", "child", "reader"]
                        if failure:
                            self.assertNotEqual(result.returncode, 0)
                            self.assertEqual(trace, expected[:expected.index(failure) + 1] + ["teardown"])
                        else:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            if evidence and not profile:
                                expected.append("emitter")
                            expected.extend(["complete", "teardown"])
                            if evidence and profile:
                                expected.append("emitter")
                            self.assertEqual(trace, expected)


if __name__ == "__main__":
    unittest.main()
