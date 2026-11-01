"""Independent closed measurement diagnostics through the real exact wrapper."""
from hashlib import sha256
from pathlib import Path
import unittest

import test_native_pids_wiring as legacy
from test_native_pids_wiring import HANDOFF, SELECTED, SETUP_REFUSAL

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "DOCKERLENS_NATIVE_PIDS_MEASUREMENT_REFUSAL: code="
FAMILY = "DOCKERLENS_NATIVE_PIDS_MEASUREMENT_REFUSAL"
SUCCESS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out;"
SECRET = "PRIVATE_MEASUREMENT_CANARY"
# Authored from an independent callsite/return audit of measure and its helpers,
# not loaded from the production registry or formatter. OuterFinalize is not a
# measurement operation; its pids-shutdown code deliberately remains excluded.
EXPECTED_CODES = """
pids-acquisition pids-actor pids-ancestor-custody pids-ancestors pids-ancillary
pids-artifact pids-artifact-copy pids-artifact-copy-io pids-attribution pids-budget
pids-capture pids-case pids-cases pids-cgroup-type pids-child-custody
pids-childless-leaves pids-configured-fixture pids-controller pids-controller-capture
pids-controller-deadline pids-controller-eof pids-controller-frame
pids-controller-read pids-controller-sequence pids-controller-slot
pids-controller-status pids-controller-write pids-create pids-created-id
pids-deadline pids-decode pids-distinct-leaves pids-enforcer pids-eof pids-facts
pids-fork-effect pids-frame pids-frames pids-fresh-name pids-global-custody
pids-global-headroom pids-headroom pids-hierarchy-root pids-id
pids-independent-literal pids-info pids-input pids-integer pids-intent pids-json
pids-kernel pids-kernel-identity pids-limit pids-measurement-custody pids-nproc
pids-observation pids-observation-pair pids-outer-type pids-package pids-plan
pids-prerequisite pids-read pids-render pids-reservation pids-reuse pids-schema
pids-sequence pids-slot pids-source-budget pids-start pids-status pids-task-custody
pids-tasks pids-type-edge pids-unqualified-destination pids-version pids-worker
pids-write
""".split()


class MeasurementRefusalTests(unittest.TestCase):
    wrapper = legacy.PidsWiringTests.wrapper

    def test_independent_inventory_exact_packaged_bytes_and_constructor_boundary(self):
        registry = (ROOT / "src/native_pids_measurement_refusals.txt").read_bytes()
        self.assertEqual(len(EXPECTED_CODES), 78)
        self.assertEqual(EXPECTED_CODES, sorted(set(EXPECTED_CODES)))
        self.assertEqual(registry, ("\n".join(EXPECTED_CODES) + "\n").encode())
        self.assertEqual(sha256(registry).hexdigest(), "7e69a1dd044be9883d7bc9c22c1c6e64117435ec602f3b4af7f6ec6fedd54401")
        self.assertNotIn("pids-shutdown", EXPECTED_CODES)
        self.assertNotIn("pids-bootstrap", EXPECTED_CODES)
        self.assertIn("pids-budget", EXPECTED_CODES)  # Shared reservation helper.
        self.assertIn('"src/**"', (ROOT / "Cargo.toml").read_text())
        constructor = (ROOT / "src/native_pids_setup_refusals.txt").read_text().splitlines()
        self.assertEqual(len(constructor), 32)
        self.assertIn("pids-bootstrap", constructor)
        self.assertNotIn("pids-version", constructor)

    def test_every_authored_measurement_code_projects_once_only_on_failure(self):
        for code in EXPECTED_CODES + ["unclassified"]:
            with self.subTest(code=code):
                result, trace = self.wrapper(PREFIX + code, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(trace), 2)
                self.assertEqual(result.stderr.count((PREFIX + code + "\n").encode()), 1)
                self.assertIn(b"(exit 101)", result.stderr)
                self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)

    def test_unknown_private_cross_family_and_unterminated_records_never_project(self):
        for code in ("new", "pids-unknown", "pids-bootstrap", "pids-shutdown", "memory-effect", "nofile-status",
                     "/tmp/" + SECRET, "pids-version ", "pids-version\r" + SECRET, "pids-version:" + SECRET,
                     "pids-version\n" + PREFIX + "pids-info", "pids-version\0" + SECRET,
                     "\x1b[31mpids-version", "保護", SECRET * 100):
            with self.subTest(code=code):
                result, _ = self.wrapper(PREFIX + code, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)
                self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        result, _ = self.wrapper(PREFIX + "pids-version", status=101, terminate_output=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)

    def test_duplicate_or_mixed_observation_families_do_not_select_a_phase(self):
        line = PREFIX + "pids-version"
        for other in (line, PREFIX + "pids-info", SETUP_REFUSAL + "pids-outer",
                      "DOCKERLENS_NATIVE_PIDS_IO: phase=ready kind=eof",
                      "DOCKERLENS_NATIVE_PIDS_START: s=s_imports k=import",
                      "DOCKERLENS_NATIVE_PIDS_BIND: s=w_capture_adopt"):
            for output in (line + "\n" + other, other + "\n" + line):
                result, _ = self.wrapper(output, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)
                self.assertNotIn(SETUP_REFUSAL.encode(), result.stdout + result.stderr)

    def test_any_measurement_prefix_contradicts_success_without_printing_native_values(self):
        for line in (PREFIX + "pids-version", PREFIX + SECRET, FAMILY, FAMILY + ":private=" + SECRET,
                     PREFIX + "pids-version\0" + SECRET):
            for status in (0, 101):
                for positive in (SUCCESS, "DOCKERLENS_NATIVE_CHECK: pids_evidence"):
                    result, _ = self.wrapper(line + "\n" + positive, status=status)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(b"required native test passed:", result.stdout + result.stderr)
                    self.assertNotIn(b"test result: ok.", result.stdout + result.stderr)
                    self.assertNotIn(b"pids_evidence", result.stdout + result.stderr)
                    self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
                    self.assertNotIn((PREFIX + "pids-version").encode(), result.stdout + result.stderr)

    def test_registry_missing_alias_or_same_shape_substitution_cannot_project(self):
        registry = (ROOT / "src/native_pids_measurement_refusals.txt").read_bytes()
        changed = registry.replace(b"pids-version", b"pids-verson")
        self.assertEqual(len(changed.splitlines()), 78)
        self.assertEqual(changed.splitlines(), sorted(set(changed.splitlines())))
        for kind, value in [(kind, registry) for kind in ("missing", "symlink", "fifo", "hardlink", "writable")] + [
                ("file", b""), ("file", registry[:-1]), ("file", changed), ("file", b"x" * 2263)]:
            result, _ = self.wrapper(PREFIX + "pids-version", status=101,
                                     measurement_registry=value, measurement_registry_kind=kind)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)

    def test_original_error_cleanup_handoff_timeout_and_private_panic_remain_dominant(self):
        line = PREFIX + "pids-info"
        for status in (101, 124, 130, 143):
            failure = ("DOCKERLENS_NATIVE_CHECK: pids_context\nDOCKERLENS_NATIVE_CHECK: pids_cleanup\n" + line + "\n"
                       + f"thread '{SELECTED}' panicked at src/native_pids_tests.rs:123:4:\n" + SECRET + "\n" + HANDOFF)
            result, _ = self.wrapper(failure, status=status)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"(exit {status})".encode(), result.stderr)
            self.assertIn(line.encode(), result.stderr)
            self.assertIn(HANDOFF.encode(), result.stderr)
            self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        result, _ = self.wrapper(line, status=101, capture_failure="cleanup")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"private capture cleanup unavailable", result.stderr)

    def test_foreign_selector_and_raw_capture_uncertainty_cannot_admit_measurement(self):
        for status in (0, 101):
            result, _ = self.wrapper(PREFIX + "pids-version" + "\n" + SUCCESS, status=status,
                                     test_name="different_native_pids_test")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)
            self.assertNotIn(b"required native test passed:", result.stdout + result.stderr)
        for output in ((PREFIX + "pids-version\0" + SECRET).encode(), b"x" * 1048577):
            result, _ = self.wrapper(output, status=0)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)
        for failure in ("create", "write"):
            result, _ = self.wrapper(PREFIX + "pids-version", status=101, capture_failure=failure)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)

    def test_diagnostic_occurs_after_existing_cleanup_and_no_acceptance_data_changes(self):
        source = (ROOT / "src/native_pids_tests.rs").read_text()
        live = source[source.index("fn live_pids_limits_and_effects_match_engine()"):]
        self.assertLess(live.index("terminal_cleanup("), live.index("pids_measurement_refusal_diagnostic(phase)"))
        self.assertLess(live.index("pids_measurement_refusal_diagnostic(phase)"), live.index('panic!("private native PIDs observation refused")'))
        self.assertIn("Ok(Err(phase))", live)
        self.assertIn('include_str!("native_pids_measurement_refusals.txt")', source)
        result, _ = self.wrapper(SUCCESS, status=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
