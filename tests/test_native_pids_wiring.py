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
STARTUP_REFUSAL = "DOCKERLENS_NATIVE_PIDS_START:"
BIND_OBSERVATION = "DOCKERLENS_NATIVE_PIDS_BIND:"


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
                registry=None, registry_kind="file", capture_failure=None, terminate_output=True):
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
    sys.stdout.buffer.write(Path(os.environ["OUTPUT_PATH"]).read_bytes()
                            + (b"\\n" if os.environ["TERMINATE_OUTPUT"] == "1" else b""))
    sys.exit(int(os.environ["STATUS"]))
''')
            cargo.chmod(0o700)
            result = subprocess.run(["bash", str(wrapper), target, test_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "TRACE": str(root / "trace"),
                     "NATIVE_LIFECYCLE_CLEANUP_OWNER": "native_conformance_outer_v1", "LISTING_PATH": str(root / "listing"),
                     "OUTPUT_PATH": str(root / "output"), "STATUS": str(status), "TMPDIR": str(capture_parent),
                     "CAPTURE_FAILURE": capture_failure or "", "TERMINATE_OUTPUT": "1" if terminate_output else "0"})
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

    def test_startup_catalogue_matches_finite_origins_and_every_instrumented_site(self):
        import ast
        source = (ROOT / "scripts/native-pids-supervisor.py").read_text()
        values = {}
        for node in ast.parse(source).body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in ("SUPERVISOR_SITES", "WORKER_SITES", "PEER_SITES", "STARTUP_KINDS"):
                    values[node.targets[0].id] = ast.literal_eval(node.value)
        # Literal contract checks independent of the parser's tables: exact
        # process prefixes and all taxonomic kinds, not arbitrary pids-* data.
        self.assertEqual(values["STARTUP_KINDS"], ("guard", "no_api", "import", "bad_arg", "denied", "missing",
                         "unsupported", "resource", "io", "cancelled", "other"))
        self.assertIn("parent_uid", values["WORKER_SITES"])
        self.assertIn("kid_gate_read", values["WORKER_SITES"])
        self.assertIn("mon_wait", values["SUPERVISOR_SITES"])
        self.assertNotIn("mon_wait", values["WORKER_SITES"])
        self.assertNotIn("parent_uid", values["SUPERVISOR_SITES"])
        sites = [origin + "_" + site for origin, key in (("s", "SUPERVISOR_SITES"), ("w", "WORKER_SITES"))
                 for site in values[key] + values["PEER_SITES"]]
        self.assertEqual(len(sites), len(set(sites)))
        rust = (ROOT / "src/native_pids_tests.rs").read_text()
        rust_sites = re.findall(r'"([a-z_0-9]+)"', rust.split("const STARTUP_SITES: &[&str] = &[", 1)[1].split("];", 1)[0])
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        wrapper_sites = re.search(r'startup_sites = set\(b"([a-z_0-9 ]+)"\.split\(\)\)', wrapper)[1].split()
        self.assertEqual(rust_sites, sites)
        self.assertEqual(wrapper_sites, sites)
        used = set()
        for name in ("native-pids-supervisor.py", "native_pids_boundary.py", "native_pids_locator.py"):
            for node in ast.walk(ast.parse((ROOT / "scripts" / name).read_text())):
                if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                    called = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
                    if called in ("scope", "fault", "startup_scope", "startup_fault", "startup_require"):
                        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "_BIND":
                            continue
                        used.add(node.args[0].value)
        declared = set(values["SUPERVISOR_SITES"] + values["WORKER_SITES"] + values["PEER_SITES"])
        self.assertEqual(used, declared)
        for site in sites:
            for kind in values["STARTUP_KINDS"]:
                record = f"DOCKERLENS_NATIVE_PIDS_START: s={site} k={kind}"
                self.assertTrue(record.isascii())
                self.assertLessEqual(len(record), 63)
        drop = rust.split("impl Drop for RootChannel {", 1)[1].split("struct WorkerControl", 1)[0]
        self.assertEqual(drop.count("retire_child("), 1)
        self.assertEqual(drop.count("self.startup.get().copied()"), 1)
        self.assertLess(drop.index("retire_child("), drop.index("self.startup.get().copied()"))
        for forbidden in (".join(", ".is_finished(", ".try_wait(", "sleep(", "get_or_init("):
            self.assertNotIn(forbidden, drop)

    def test_startup_projects_only_triple_paired_finite_records(self):
        general = SETUP_REFUSAL + "pids-read"
        detail = IO_DETAIL + " phase=ready kind=reset"
        for site in ("s_fd0", "w_parent_uid"):
            for kind in ("guard", "no_api", "import", "bad_arg", "denied", "missing",
                         "unsupported", "resource", "io", "cancelled", "other"):
                startup = STARTUP_REFUSAL + f" s={site} k={kind}"
                result, _ = self.wrapper(startup + "\n" + detail + "\n" + general + "\n" + startup, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.count((startup + "\n").encode()), 1)
                self.assertEqual(result.stderr.count((general + "\n").encode()), 1)
                self.assertEqual(result.stderr.count((detail + "\n").encode()), 1)
                self.assertIn(b"(exit 101)", result.stderr)
        startup = STARTUP_REFUSAL + " s=w_parent_uid k=guard"
        for prefix in ("", general, detail, SETUP_REFUSAL + "pids-eof\n" + detail,
                       general + "\n" + IO_DETAIL + " phase=bind kind=reset",
                       general + "\n" + IO_DETAIL + " phase=ready kind=other"):
            result, _ = self.wrapper(prefix + "\n" + startup, status=101)
            self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
        for target, name in (("native_pids", "other_test"), ("native_nofile", "other_test")):
            result, _ = self.wrapper(general + "\n" + detail + "\n" + startup, status=101, target=target, test_name=name)
            self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)

    def test_startup_conflicts_unknown_private_records_nul_and_overflow_never_project(self):
        companions = SETUP_REFUSAL + "pids-read\n" + IO_DETAIL + " phase=ready kind=reset\n"
        valid = STARTUP_REFUSAL + " s=w_parent_uid k=guard"
        parent = STARTUP_REFUSAL + " s=s_par_gate_send k=io"
        gate = STARTUP_REFUSAL + " s=w_kid_gate_read k=guard"
        for value in [
            STARTUP_REFUSAL, STARTUP_REFUSAL + " PRIVATE_CANARY", valid + " PRIVATE_CANARY", valid + "\r",
            valid + "\0", valid + "\0PRIVATE_CANARY", STARTUP_REFUSAL + " s=w_PRIVATE_CANARY k=guard",
            STARTUP_REFUSAL + " s=s_parent_uid k=guard", STARTUP_REFUSAL + " s=w_mon_wait k=io",
            STARTUP_REFUSAL + " s=w_parent_uid k=PRIVATE_CANARY", valid + "\n" + parent, parent + "\n" + valid,
            parent + "\n" + gate, gate + "\n" + parent,
            STARTUP_REFUSAL + " s=s_peer_live k=io\n" + STARTUP_REFUSAL + " s=w_peer_live k=io",
            valid + "\n" + STARTUP_REFUSAL + " PRIVATE_CANARY", STARTUP_REFUSAL + "x" * 70000,
            "x" * 1048577 + "\n" + valid,
        ]:
            with self.subTest(length=len(value)):
                result, _ = self.wrapper(companions + value, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
                self.assertNotIn(b"PRIVATE_CANARY", result.stdout + result.stderr)
                self.assertIn(b"(exit 101)", result.stderr)
        # A gate record is only its observed site; no retirement/root-cause field.
        result, _ = self.wrapper(companions + gate, status=101)
        self.assertIn((gate + "\n").encode(), result.stderr)
        self.assertNotIn(b"cause=", result.stdout + result.stderr)
        self.assertNotIn((STARTUP_REFUSAL + " s=unavailable").encode(), result.stdout + result.stderr)

    def test_any_startup_prefix_contradicts_success_before_companion_or_registry_validation(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        evidence = "DOCKERLENS_NATIVE_CHECK: pids_evidence"
        for startup in (STARTUP_REFUSAL, STARTUP_REFUSAL + " PRIVATE_CANARY",
                        STARTUP_REFUSAL + " s=w_parent_uid k=guard"):
            for status, positive in ((0, ""), (0, success), (0, evidence), (101, success), (101, evidence)):
                for output in (startup + "\n" + positive, positive + "\n" + startup):
                    result, _ = self.wrapper(output, status=status, registry=b"")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
                    self.assertNotIn(b"PRIVATE_CANARY", result.stdout + result.stderr)
                    self.assertNotIn(evidence.encode(), result.stdout + result.stderr)
                    self.assertNotIn(success.encode(), result.stdout + result.stderr)
                    self.assertIn((SETUP_REFUSAL + "unclassified\n").encode(), result.stderr)

    def test_constructor_eof_pairs_closed_phase_and_preserves_original_failure(self):
        general = SETUP_REFUSAL + "pids-eof"
        startup = STARTUP_REFUSAL + " s=s_fd0 k=guard"
        for phase in ("ready", "bind", "confirm"):
            detail = IO_DETAIL + f" phase={phase} kind=eof"
            result, _ = self.wrapper(startup + "\n" + detail + "\n" + general + "\n" + detail + "\n" + startup, status=101)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.count((general + "\n").encode()), 1)
            self.assertEqual(result.stderr.count((detail + "\n").encode()), 1)
            self.assertEqual(result.stderr.count((startup + "\n").encode()), int(phase == "ready"))
            self.assertIn(b"(exit 101)", result.stderr)

    def test_constructor_eof_rejects_mismatched_missing_conflicting_and_foreign_pairs(self):
        eof = SETUP_REFUSAL + "pids-eof"
        read = SETUP_REFUSAL + "pids-read"
        detail = IO_DETAIL + " phase=ready kind=eof"
        reset = IO_DETAIL + " phase=ready kind=reset"
        startup = STARTUP_REFUSAL + " s=w_parent_uid k=guard"
        for prefix in (eof, detail, read + "\n" + detail, eof + "\n" + reset,
                       SETUP_REFUSAL + "pids-outer\n" + detail,
                       eof + "\n" + IO_DETAIL + " phase=ready kind=other",
                       eof + "\n" + read + "\n" + detail,
                       eof + "\n" + detail + "\n" + reset):
            result, _ = self.wrapper(prefix + "\n" + startup, status=101)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
            self.assertNotIn(IO_DETAIL.encode(), result.stdout + result.stderr)
            self.assertIn(b"(exit 101)", result.stderr)
        for target, name in (("native_pids", "other_pids_test"), ("native_nofile", "other_test")):
            result, _ = self.wrapper(eof + "\n" + detail + "\n" + startup, status=101, target=target, test_name=name)
            self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)
            self.assertNotIn(IO_DETAIL.encode(), result.stdout + result.stderr)
            self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)

    def test_constructor_eof_unknown_private_and_nul_records_remain_unobserved(self):
        general = SETUP_REFUSAL + "pids-eof\n"
        detail = IO_DETAIL + " phase=ready kind=eof"
        startup = STARTUP_REFUSAL + " s=w_parent_uid k=guard"
        for malformed in (detail + " PRIVATE_EOF_CANARY", detail + "\r", detail + "\0PRIVATE_EOF_CANARY",
                          IO_DETAIL + " phase=ready kind=e\\x6ff",
                          IO_DETAIL + " phase=ready kind=EOF",
                          IO_DETAIL + " phase=PRIVATE_EOF_CANARY kind=eof"):
            result, _ = self.wrapper(general + malformed + "\n" + startup, status=101)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(IO_DETAIL.encode(), result.stdout + result.stderr)
            self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"PRIVATE_EOF_CANARY", result.stdout + result.stderr)
        for malformed in (startup + "\0", startup + " PRIVATE_EOF_CANARY",
                          STARTUP_REFUSAL + " s=w_PRIVATE_EOF_CANARY k=guard",
                          startup + "\n" + STARTUP_REFUSAL + " s=s_peer_live k=io",
                          STARTUP_REFUSAL + "x" * 70000):
            result, _ = self.wrapper(general + detail + "\n" + malformed, status=101)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"PRIVATE_EOF_CANARY", result.stdout + result.stderr)

    def test_constructor_eof_prefixes_and_paired_startup_contradict_all_positive_results(self):
        general = SETUP_REFUSAL + "pids-eof"
        detail = IO_DETAIL + " phase=ready kind=eof"
        startup = STARTUP_REFUSAL + " s=w_parent_uid k=guard"
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        evidence = "DOCKERLENS_NATIVE_CHECK: pids_evidence"
        for diagnostic in (detail, detail + " PRIVATE_EOF_CANARY", general + "\n" + detail + "\n" + startup):
            for status, positive in ((0, ""), (0, success), (101, success), (101, evidence)):
                for output in (diagnostic + "\n" + positive, positive + "\n" + diagnostic):
                    result, _ = self.wrapper(output, status=status)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(IO_DETAIL.encode(), result.stdout + result.stderr)
                    self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
                    self.assertNotIn(b"PRIVATE_EOF_CANARY", result.stdout + result.stderr)
                    self.assertNotIn(success.encode(), result.stdout + result.stderr)
                    self.assertNotIn(evidence.encode(), result.stdout + result.stderr)
                    self.assertIn((SETUP_REFUSAL + "unclassified\n").encode(), result.stderr)

    def host_pairs(self):
        sites = ("w_gh_read", "w_gh_mount", "w_gh_walk", "w_gh_leaf", "w_gh_verify", "w_gh_root", "w_gh_nodes", "w_gv_make", "w_gv_call", "w_gv_time", "w_gv_record", "w_gv_bind", "w_gv_ids", "w_gv_dirs", "w_gv_files", "w_gv_type", "w_gv_cache")
        tags = ("unclassified", "ENOENT", "EACCES", "EPERM", "EMFILE", "ENFILE", "ENOMEM", "ENOSPC",
            "EIO", "EINVAL", "ESPIPE", "EINTR", "other_os", "declared_unsupported_events")
        return [(site, tag) for site in sites for tag in tags
            if tag != "declared_unsupported_events" or site in ("w_gh_root", "w_gh_nodes")]

    def test_host_catalogues_are_independent_closed_literals_and_223_pairs(self):
        import ast
        sites = ("gh_read", "gh_mount", "gh_walk", "gh_leaf", "gh_verify", "gh_root", "gh_nodes", "gv_make", "gv_call", "gv_time", "gv_record", "gv_bind", "gv_ids", "gv_dirs", "gv_files", "gv_type", "gv_cache")
        tags = ("unclassified", "ENOENT", "EACCES", "EPERM", "EMFILE", "ENFILE", "ENOMEM", "ENOSPC",
            "EIO", "EINVAL", "ESPIPE", "EINTR", "other_os", "declared_unsupported_events")
        tree = ast.parse((ROOT / "scripts/native-pids-supervisor.py").read_text())
        declarations = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in ("HOST_BIND_SITES", "HOST_BIND_EXCEPTIONS")}
        self.assertEqual(declarations, {"HOST_BIND_SITES": sites, "HOST_BIND_EXCEPTIONS": tags})
        used = set()
        for path, helper in (("scripts/native_pids_boundary.py", "_group_escape"),
                             ("scripts/native_pids_locator.py", "_host_group_escape")):
            for node in ast.walk(ast.parse((ROOT / path).read_text())):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == helper:
                    used.add(node.args[1].value)
        self.assertEqual(used, set(sites))
        rust = (ROOT / "src/native_pids_tests.rs").read_text()
        rust_sites = re.findall(r'"([a-z_]+)"', rust.split("const HOST_BIND_SITES: &[&str] = &[", 1)[1].split("];", 1)[0])
        rust_tags = re.findall(r'"([A-Za-z_]+)"', rust.split("const HOST_BIND_EXCEPTIONS:", 1)[1].split("];", 1)[0])
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        wrapper_sites = re.search(r'host_bind_sites = set\(b"([a-z_ ]+)"\.split\(\)\)', wrapper)[1].split()
        wrapper_tags = re.search(r'host_bind_exceptions = set\(b"([A-Za-z_ ]+)"\.split\(\)\)', wrapper)[1].split()
        self.assertEqual(rust_sites, ["w_" + site for site in sites]); self.assertEqual(wrapper_sites, rust_sites)
        self.assertEqual(rust_tags, list(tags)); self.assertEqual(wrapper_tags, list(tags))
        pairs = self.host_pairs()
        self.assertEqual(len(set(pairs)), 223)
        self.assertEqual(max(len(BIND_OBSERVATION + f" s={site} e={tag}\n") for site, tag in pairs), 72)

    def test_every_host_pair_projects_only_with_both_exact_eligible_pairs(self):
        for code, kind in (("pids-eof", "eof"), ("pids-read", "reset")):
            general, detail = SETUP_REFUSAL + code, IO_DETAIL + f" phase=bind kind={kind}"
            for site, tag in self.host_pairs():
                bind = BIND_OBSERVATION + f" s={site} e={tag}"
                result, _ = self.wrapper(bind + "\n" + detail + "\n" + general + "\n" + bind + "\n", status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"(exit 101)", result.stderr)
                self.assertEqual(result.stderr.count((bind + "\n").encode()), 1, (site, tag, result.stderr))
                self.assertEqual(result.stderr.count((general + "\n").encode()), 1)
                self.assertEqual(result.stderr.count((detail + "\n").encode()), 1)

    def type_detail_forms(self):
        tokens = ("o_time", "o_fds", "o_opens", "o_other", "m_syscall", "m_guard", "m_other",
            "r_time", "r_reads", "r_bytes", "r_cap", "r_other", "d_domain", "d_domthr", "d_dominv",
            "d_thread", "d_other", "cleanup")
        return [BIND_OBSERVATION + " s=w_gv_type e=unclassified d=" + token for token in tokens]

    def test_type_details_are_18_closed_additions_to_223_bare_forms(self):
        records = self.type_detail_forms()
        self.assertEqual(len(set(records)) + len(self.host_pairs()), 241)
        self.assertLessEqual(max(len(record + "\n") for record in records), 72)
        for code, kind in (("pids-eof", "eof"), ("pids-read", "reset")):
            prefix = SETUP_REFUSAL + code + "\n" + IO_DETAIL + f" phase=bind kind={kind}\n"
            for record in records:
                result, _ = self.wrapper(prefix + record + "\n" + record + "\n", status=101)
                self.assertEqual(result.stderr.count((record + "\n").encode()), 1)
                self.assertNotEqual(result.returncode, 0)
        valid = records[0] + "\n"
        bad = [valid.rstrip("\n"), valid.replace(" d=", "  d="), valid.replace("d=o_time", "d=PRIVATE"),
            valid.replace("w_gv_type", "w_gv_files"), valid.replace("unclassified", "ENOENT"),
            valid.replace("unclassified", "other_os"), valid.replace(" e=unclassified", ""),
            valid.replace("d=o_time", "d=o_time d=o_time"), valid + records[1] + "\n",
            valid + BIND_OBSERVATION + " s=w_gv_type e=unclassified\n", valid + STARTUP_REFUSAL + " invalid\n"]
        prefix = SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=bind kind=eof\n"
        for record in bad:
            result, _ = self.wrapper(prefix + record, status=101, terminate_output=False)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
        for companions in (SETUP_REFUSAL + "pids-read\n" + IO_DETAIL + " phase=bind kind=eof\n",
                SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=ready kind=eof\n"):
            result, _ = self.wrapper(companions + valid, status=101)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)

    def test_host_strict_fields_partial_eof_conflicts_and_family_taint(self):
        prefix = SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=bind kind=eof\n"
        valid = BIND_OBSERVATION + " s=w_gh_read e=ENOENT\n"
        records = [
            BIND_OBSERVATION + " s=w_gh_read\n",
            BIND_OBSERVATION + " s=w_oc_host e=ENOENT\n",
            BIND_OBSERVATION + " s=w_gh_read e=declared_unsupported_events\n",
            BIND_OBSERVATION + " s=w_gh_verify e=declared_unsupported_events\n",
            BIND_OBSERVATION + " s=w_gh_read e=PRIVATE_HOST_CANARY\n",
            BIND_OBSERVATION + " s=w_unknown e=ENOENT\n",
            BIND_OBSERVATION + " e=ENOENT s=w_gh_read\n",
            BIND_OBSERVATION + " s=w_gh_read  e=ENOENT\n",
            BIND_OBSERVATION + " s=w_gh_read e=ENOENT e=ENOENT\n",
            BIND_OBSERVATION + " s=w_gh_read e=ENOENT k=guard\n",
            valid.rstrip("\n"), valid.rstrip("\n") + "\r\n", valid.rstrip("\n") + "\0\n",
            valid + BIND_OBSERVATION + " s=w_gh_read e=EACCES\n",
            valid + BIND_OBSERVATION + " s=w_oc_host\n",
            valid + STARTUP_REFUSAL + " PRIVATE_HOST_CANARY\n",
            STARTUP_REFUSAL + " PRIVATE_HOST_CANARY\n" + valid,
            BIND_OBSERVATION + "x" * 70000,
            "x" * 1048577 + "\n" + valid,
        ]
        for record in records:
            result, _ = self.wrapper(prefix + record, status=101, terminate_output=False)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
            self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"PRIVATE_HOST_CANARY", result.stdout + result.stderr)
        for companions in (SETUP_REFUSAL + "pids-read\n" + IO_DETAIL + " phase=bind kind=eof\n",
                SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=bind kind=reset\n",
                SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=ready kind=eof\n",
                SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=confirm kind=eof\n",
                SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=bind kind=other\n"):
            result, _ = self.wrapper(companions + valid, status=101)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
        for target, name in (("native_hostname", TEST), ("native_pids", TEST + "_foreign")):
            result, _ = self.wrapper(prefix + valid, status=101, target=target, test_name=name)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)

    def test_new_valid_and_malformed_host_prefixes_always_taint_positive_results(self):
        records = [BIND_OBSERVATION + f" s={site} e={tag}\n" for site, tag in self.host_pairs()]
        records.extend(record + "\n" for record in self.type_detail_forms())
        records.extend((BIND_OBSERVATION + " s=w_gh_read e=PRIVATE_HOST_CANARY\n",
                        BIND_OBSERVATION + " s=w_gh_read\n"))
        for record in records:
            for status, positive in ((0, ""), (0, "test result: ok. 1 passed; 0 failed\n"),
                    (101, "DOCKERLENS_NATIVE_CHECK: pids_evidence\n")):
                result, _ = self.wrapper(record + positive, status=status)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
                self.assertNotIn(b"PRIVATE_HOST_CANARY", result.stdout + result.stderr)
                self.assertNotIn(b"pids_evidence", result.stdout + result.stderr)
                self.assertIn((SETUP_REFUSAL + "unclassified\n").encode(), result.stderr)

    def test_bind_catalogue_is_exact_and_separate_from_startup(self):
        import ast
        expected = ("capture_adopt", "session_init", "request_read", "handler", "request_schema",
            "context_schema", "labels", "external_debit", "outer_args", "outer_process", "outer_vector",
            "outer_pidns", "outer_cgroup", "endpoint", "daemon_context", "daemon_bind", "reserve_api",
            "outer_recheck", "pending_reply",
        "oc_pre", "oc_host", "oc_guest", "oc_select", "oc_max", "oc_recheck")
        tree = ast.parse((ROOT / "scripts/native-pids-supervisor.py").read_text())
        declared = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "BIND_SITES" for target in node.targets))
        self.assertEqual(declared, expected)
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "scope":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "_BIND":
                    used.add(node.args[0].value)
        locator = ast.parse((ROOT / "scripts/native_pids_locator.py").read_text())
        for node in ast.walk(locator):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_outer_escape":
                used.add(node.args[1].value)
        self.assertEqual(used, set(expected))
        self.assertEqual(len(expected), 25)
        sites = ["w_" + name for name in expected]
        rust = (ROOT / "src/native_pids_tests.rs").read_text()
        rust_sites = re.findall(r'"([a-z_]+)"', rust.split("const BIND_SITES: &[&str] = &[", 1)[1].split("];", 1)[0])
        wrapper = (ROOT / "scripts/run-exact-native-test.sh").read_text()
        wrapper_sites = re.search(r'bind_sites = set\(b"([a-z_ ]+)"\.split\(\)\)', wrapper)[1].split()
        self.assertEqual(rust_sites, sites)
        self.assertEqual(wrapper_sites, sites)
        for site in sites:
            line = BIND_OBSERVATION + " s=" + site
            self.assertTrue(line.isascii())
            self.assertLessEqual(len(line), 63)
            self.assertNotIn(" k=", line)
        self.assertEqual(max(len(BIND_OBSERVATION + " s=" + site) for site in sites), 47)
        # Pure setup/normal stop only: bootstrap must return BEFORE activation,
        # and pending response must return BEFORE stop. No shared phase channel.
        source = (ROOT / "scripts/native-pids-supervisor.py").read_text()
        factory = source.split("def source_server(", 1)[1].split("def monitor(", 1)[0]
        self.assertLess(factory.index("capture = channel.bootstrap("), factory.index("_BIND.begin()"))
        self.assertLess(factory.index("_BIND.begin()"), factory.index('_BIND.scope("capture_adopt")'))
        server = source.split("def serve_session(", 1)[1].split("def source_server(", 1)[0]
        self.assertLess(server.index("channel.response(session.handle("), server.index("_BIND.stop()"))
        self.assertLess(server.index("_BIND.stop()"), server.index("finally:"))

    def test_bind_projects_every_site_only_with_exact_consistent_bind_pair(self):
        sites = ("capture_adopt", "session_init", "request_read", "handler", "request_schema",
            "context_schema", "labels", "external_debit", "outer_args", "outer_process", "outer_vector",
            "outer_pidns", "outer_cgroup", "endpoint", "daemon_context", "daemon_bind", "reserve_api",
            "outer_recheck", "pending_reply",
        "oc_pre", "oc_host", "oc_guest", "oc_select", "oc_max", "oc_recheck")
        for code, kind in (("pids-eof", "eof"), ("pids-read", "reset")):
            general, detail = SETUP_REFUSAL + code, IO_DETAIL + f" phase=bind kind={kind}"
            for site in sites:
                bind = BIND_OBSERVATION + " s=w_" + site
                result, _ = self.wrapper(bind + "\n" + detail + "\n" + general + "\n" + bind, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.count((bind + "\n").encode()), 1)
                self.assertEqual(result.stderr.count((general + "\n").encode()), 1)
                self.assertEqual(result.stderr.count((detail + "\n").encode()), 1)
                self.assertIn(b"(exit 101)", result.stderr)

    def test_bind_rejects_missing_wrong_phase_errno_code_and_foreign_selector(self):
        bind = BIND_OBSERVATION + " s=w_outer_cgroup"
        eof, read = SETUP_REFUSAL + "pids-eof", SETUP_REFUSAL + "pids-read"
        detail = IO_DETAIL + " phase=bind kind=eof"
        for prefix in ("", eof, detail, read + "\n" + detail,
                       eof + "\n" + IO_DETAIL + " phase=bind kind=reset",
                       read + "\n" + IO_DETAIL + " phase=bind kind=other",
                       eof + "\n" + IO_DETAIL + " phase=ready kind=eof",
                       eof + "\n" + IO_DETAIL + " phase=confirm kind=eof",
                       eof + "\n" + detail + "\n" + read,
                       eof + "\n" + detail + "\n" + IO_DETAIL + " phase=ready kind=eof"):
            result, _ = self.wrapper(prefix + "\n" + bind, status=101)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
        for target, name in (("native_pids", "other_test"), ("native_nofile", "other_test")):
            result, _ = self.wrapper(eof + "\n" + detail + "\n" + bind, status=101, target=target, test_name=name)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)

    def test_bind_and_start_conflicts_suppress_both_sites_before_phase_selection(self):
        for code, detail in (("pids-eof", "phase=bind kind=eof"), ("pids-read", "phase=bind kind=reset"),
                             ("pids-eof", "phase=ready kind=eof"), ("pids-read", "phase=ready kind=reset")):
            general, io = SETUP_REFUSAL + code, IO_DETAIL + " " + detail
            for bind in (BIND_OBSERVATION + " s=w_endpoint", BIND_OBSERVATION + " PRIVATE_BIND_CANARY"):
                for start in (STARTUP_REFUSAL + " s=w_parent_uid k=guard", STARTUP_REFUSAL + " PRIVATE_BIND_CANARY"):
                    for records in (bind + "\n" + start, start + "\n" + bind):
                        result, _ = self.wrapper(general + "\n" + io + "\n" + records, status=101)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
                        self.assertNotIn(STARTUP_REFUSAL.encode(), result.stdout + result.stderr)
                        self.assertNotIn(b"PRIVATE_BIND_CANARY", result.stdout + result.stderr)
                        self.assertIn((general + "\n").encode(), result.stderr)
                        self.assertIn((io + "\n").encode(), result.stderr)

    def test_bind_unknown_kind_suffix_private_nul_and_overflow_are_unobserved(self):
        companions = SETUP_REFUSAL + "pids-eof\n" + IO_DETAIL + " phase=bind kind=eof\n"
        valid = BIND_OBSERVATION + " s=w_endpoint"
        for record in (BIND_OBSERVATION, BIND_OBSERVATION + " PRIVATE_BIND_CANARY",
                       valid + " k=guard", valid + " PRIVATE_BIND_CANARY", valid + "\r", valid + "\0",
                       valid + "\0PRIVATE_BIND_CANARY", BIND_OBSERVATION + " s=s_endpoint",
                       BIND_OBSERVATION + " s=w_PRIVATE_BIND_CANARY", valid + "\n" + BIND_OBSERVATION + " s=w_handler",
                       BIND_OBSERVATION + "x" * 70000, "x" * 1048577 + "\n" + valid):
            result, _ = self.wrapper(companions + record, status=101)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"PRIVATE_BIND_CANARY", result.stdout + result.stderr)
            self.assertIn(b"(exit 101)", result.stderr)

    def test_any_bind_prefix_taints_positive_results_even_without_companions(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
        evidence = "DOCKERLENS_NATIVE_CHECK: pids_evidence"
        for record in (BIND_OBSERVATION, BIND_OBSERVATION + " PRIVATE_BIND_CANARY",
                       BIND_OBSERVATION + " s=w_endpoint"):
            for status, positive in ((0, ""), (0, success), (0, evidence), (101, success), (101, evidence)):
                for output in (record + "\n" + positive, positive + "\n" + record):
                    result, _ = self.wrapper(output, status=status, registry=b"")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(BIND_OBSERVATION.encode(), result.stdout + result.stderr)
                    self.assertNotIn(b"PRIVATE_BIND_CANARY", result.stdout + result.stderr)
                    self.assertNotIn(success.encode(), result.stdout + result.stderr)
                    self.assertNotIn(evidence.encode(), result.stdout + result.stderr)
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
