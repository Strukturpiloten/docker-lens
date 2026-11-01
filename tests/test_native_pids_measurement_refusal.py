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
        self.assertLess(live.index("terminal_cleanup("), live.index("pids_configured_fixture_diagnostic("))
        self.assertLess(live.index("pids_configured_fixture_diagnostic("), live.index('panic!("private native PIDs observation refused")'))
        self.assertIn("Ok(Err(phase))", live)
        self.assertIn('include_str!("native_pids_measurement_refusals.txt")', source)
        result, _ = self.wrapper(SUCCESS, status=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)


    @staticmethod
    def configured_line(slot="cli16", checks="11111111110111", shapes=None, lengths="11"):
        if shapes is None:
            shapes = "string,string,string,string,false,string,string,sixteen,null,array,array,zero"
        return (PREFIX + "pids-configured-fixture slot=" + slot + " checks=" + checks
                + " shapes=" + shapes + " lengths=" + lengths)

    def test_configured_witness_projects_independently_coherent_slots_checks_and_shapes(self):
        # Literal expected limit classes for all six roles, independent of the
        # wrapper mapping. The sole mismatch is Init=null versus explicit false.
        for slot, limit in (("cli16", "sixteen"), ("cli64", "sixty_four"), ("cli_unlimited", "null"),
                            ("rendered16", "sixteen"), ("rendered64", "sixty_four"), ("rendered_unlimited", "null")):
            shapes = "string,string,string,string,false,string,string," + limit + ",null,array,array,zero"
            line = self.configured_line(slot=slot, shapes=shapes)
            result, trace = self.wrapper(line, status=101)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(trace), 2)
            self.assertEqual(result.stderr.count((line + "\n").encode()), 1)

        passing_shapes = "string,string,string,string,false,string,string,sixteen,false,array,array,zero"
        # Coherent failures authored per predicate, not arbitrary bit flips on
        # a stale null-Init record. Noncanonical Id also cannot equal created Id.
        cases = (
            ("HTTP status", "01111111111111", passing_shapes, "11"),
            ("noncanonical Id", "10011111111111", passing_shapes, "11"),
            ("different canonical Id", "11011111111111", passing_shapes, "11"),
            ("different name", "11101111111111", passing_shapes, "11"),
            ("different image", "11110111111111", passing_shapes, "11"),
            ("different original owner", "11111011111111", passing_shapes, "11"),
            ("running true", "11111101111111", "string,string,string,string,true,string,string,sixteen,false,array,array,zero", "11"),
            ("different experiment owner", "11111110111111", passing_shapes, "11"),
            ("different slot label", "11111111011111", passing_shapes, "11"),
            ("different limit", "11111111101111", "string,string,string,string,false,string,string,sixty_four,false,array,array,zero", "11"),
            ("Init null", "11111111110111", "string,string,string,string,false,string,string,sixteen,null,array,array,zero", "11"),
            ("different entrypoint contents", "11111111111011", passing_shapes, "11"),
            ("different command contents", "11111111111101", passing_shapes, "11"),
            ("nonzero restarts", "11111111111110", "string,string,string,string,false,string,string,sixteen,false,array,array,integer", "11"),
            ("different entrypoint length", "11111111111011", passing_shapes, "01"),
            ("different command length", "11111111111101", passing_shapes, "10"),
            ("nonarray entrypoint and command", "11111111111001", "string,string,string,string,false,string,string,sixteen,false,null,object,zero", "00"),
        )
        for label, checks, shapes, lengths in cases:
            with self.subTest(label=label):
                line = self.configured_line(checks=checks, shapes=shapes, lengths=lengths)
                result, _ = self.wrapper(line, status=101)
                self.assertIn((line + "\n").encode(), result.stderr)

        # Every allowed shape is coherent at Id with both syntax and equality
        # false; even a string may contain a noncanonical private value.
        for shape in ("missing", "null", "false", "true", "zero", "minus_one", "sixteen", "sixty_four",
                      "integer", "number", "string", "array", "object"):
            shapes = ",".join([shape, *passing_shapes.split(",")[1:]])
            line = self.configured_line(checks="10011111111111", shapes=shapes)
            result, _ = self.wrapper(line, status=101)
            self.assertIn((line + "\n").encode(), result.stderr)
        line = self.configured_line(checks="01111011110101", lengths="10")
        result, _ = self.wrapper(line + "\n" + SECRET, status=101)
        self.assertIn((line + "\n").encode(), result.stderr)
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)

    def test_configured_witness_rejects_cross_field_contradictions(self):
        # Keep HTTP=false in every contradictory case so the all-true guard
        # cannot mask a missing cross-field rule. All other starting facts are
        # independently coherent, including explicit Init=false.
        checks = "01111111111111"
        shapes = "string,string,string,string,false,string,string,sixteen,false,array,array,zero".split(",")
        cases = []
        for label, field in (("canonical Id requires string", 0), ("name requires string", 1),
                             ("image requires string", 2), ("original owner requires string", 3),
                             ("experiment owner requires string", 5), ("slot label requires string", 6)):
            changed = shapes.copy()
            changed[field] = "null"
            cases.append((label, self.configured_line(checks=checks, shapes=",".join(changed))))
        cases.append(("equal Id implies canonical", self.configured_line(checks="00111111111111", shapes=",".join(shapes))))

        for label, bit, field in (("Running", 6, 4), ("Init", 10, 8)):
            changed_checks = checks[:bit] + "0" + checks[bit + 1:]
            cases.append((label + " false must match", self.configured_line(checks=changed_checks, shapes=",".join(shapes))))
            for wrong_shape in ("missing", "null", "true", "zero", "string"):
                changed = shapes.copy()
                changed[field] = wrong_shape
                cases.append((label + " nonfalse must not match " + wrong_shape,
                              self.configured_line(checks=checks, shapes=",".join(changed))))

        for slot, expected, wrong in (("cli16", "sixteen", "sixty_four"), ("cli64", "sixty_four", "minus_one"),
                                     ("cli_unlimited", "null", "zero"), ("rendered16", "sixteen", "minus_one"),
                                     ("rendered64", "sixty_four", "sixteen"), ("rendered_unlimited", "null", "sixteen")):
            changed = shapes.copy()
            changed[7] = expected
            cases.append((slot + " authored limit must match", self.configured_line(slot=slot, checks="01111111101111", shapes=",".join(changed))))
            changed[7] = wrong
            cases.append((slot + " wrong limit must not match", self.configured_line(slot=slot, checks=checks, shapes=",".join(changed))))
        for wrong_shape in ("missing", "null", "false", "number", "integer"):
            changed = shapes.copy()
            changed[7] = wrong_shape
            cases.append(("invalid limit shape " + wrong_shape, self.configured_line(checks=checks, shapes=",".join(changed))))

        cases.append(("zero restarts must match", self.configured_line(checks="01111111111110", shapes=",".join(shapes))))
        for wrong_shape in ("missing", "null", "false", "integer", "number"):
            changed = shapes.copy()
            changed[11] = wrong_shape
            cases.append(("nonzero restart shape " + wrong_shape, self.configured_line(checks=checks, shapes=",".join(changed))))

        for label, bit, field, lengths in (("entrypoint", 11, 9, "01"), ("command", 12, 10, "10")):
            changed = shapes.copy()
            changed[field] = "string"
            nonmatch = checks[:bit] + "0" + checks[bit + 1:]
            cases.append((label + " nonarray cannot have matching length",
                          self.configured_line(checks=nonmatch, shapes=",".join(changed))))
            cases.append((label + " nonarray cannot match contents",
                          self.configured_line(checks=checks, shapes=",".join(changed), lengths=lengths)))
            cases.append((label + " wrong array length cannot match contents",
                          self.configured_line(checks=checks, shapes=",".join(shapes), lengths=lengths)))
        for label, line in cases:
            with self.subTest(label=label):
                result, _ = self.wrapper(line, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)

    def test_configured_witness_rejects_incomplete_unknown_reordered_or_private_metadata(self):
        valid = self.configured_line()
        shapes = "string,string,string,string,false,string,string,sixteen,null,array,array,zero"
        malformed = [
            self.configured_line(slot="cli17"), self.configured_line(slot=SECRET),
            self.configured_line(checks="1" * 14), self.configured_line(checks="0" * 13),
            self.configured_line(checks="0" * 15), self.configured_line(checks="2" + "0" * 13),
            self.configured_line(shapes=shapes + ",null"), self.configured_line(shapes=",".join(shapes.split(",")[:-1])),
            self.configured_line(shapes=shapes.replace("sixteen", "sixteen:" + SECRET)),
            self.configured_line(shapes=shapes.replace("sixteen", "16")),
            self.configured_line(lengths="0"), self.configured_line(lengths="000"), self.configured_line(lengths="02"),
            valid.replace(" slot=cli16 checks=11111111110111", " checks=11111111110111 slot=cli16"),
            valid.replace(" slot=cli16", " slot=cli16 slot=cli16"),
            valid + " lengths=11", valid + " private=" + SECRET, valid + " ", valid + "\r" + SECRET,
            valid + "\0" + SECRET, valid + "x" * 400,
            valid.replace("code=pids-configured-fixture", "code=pids-info"),
            valid.replace("code=pids-configured-fixture", "code=unclassified"),
            valid.replace(" shapes=", "  shapes="),
        ]
        for line in malformed:
            with self.subTest(line=line):
                result, _ = self.wrapper(line, status=101)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)
                self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        result, _ = self.wrapper(valid, status=101, terminate_output=False)
        self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)

    def test_configured_witness_retains_duplicate_mixed_success_and_foreign_selector_refusals(self):
        line = self.configured_line()
        for other in (line, PREFIX + "pids-configured-fixture", PREFIX + "pids-info",
                      SETUP_REFUSAL + "pids-outer", "DOCKERLENS_NATIVE_PIDS_IO: phase=ready kind=eof",
                      "DOCKERLENS_NATIVE_PIDS_START: s=s_imports k=import", "DOCKERLENS_NATIVE_PIDS_BIND: s=w_capture_adopt"):
            for output in (line + "\n" + other, other + "\n" + line):
                result, _ = self.wrapper(output, status=101)
                self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)
        for status in (0, 101):
            for positive in (SUCCESS, "DOCKERLENS_NATIVE_CHECK: pids_evidence"):
                result, _ = self.wrapper(line + "\n" + positive, status=status)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(line.encode(), result.stdout + result.stderr)
                self.assertNotIn(b"required native test passed:", result.stdout + result.stderr)
                self.assertNotIn(b"test result: ok.", result.stdout + result.stderr)
            result, _ = self.wrapper(line, status=status, test_name="different_native_pids_test")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)

    def test_configured_witness_keeps_original_panic_timeout_and_cleanup_dominance(self):
        line = self.configured_line()
        for status in (101, 124, 130, 143):
            output = ("DOCKERLENS_NATIVE_CHECK: pids_context\nDOCKERLENS_NATIVE_CHECK: pids_cleanup\n" + line
                      + f"\nthread '{SELECTED}' panicked at src/native_pids_tests.rs:123:4:\n" + SECRET + "\n" + HANDOFF)
            result, _ = self.wrapper(output, status=status)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"(exit {status})".encode(), result.stderr)
            self.assertIn((line + "\n").encode(), result.stderr)
            self.assertIn(HANDOFF.encode(), result.stderr)
            self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        result, _ = self.wrapper(line, status=101, capture_failure="cleanup")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"private capture cleanup unavailable", result.stderr)
        for failure in ("create", "write"):
            result, _ = self.wrapper(line, status=101, capture_failure=failure)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PREFIX.encode(), result.stdout + result.stderr)

    def test_bare_configured_phase_remains_available_when_no_witness_is_constructed(self):
        line = PREFIX + "pids-configured-fixture"
        result, _ = self.wrapper(line, status=101)
        self.assertIn((line + "\n").encode(), result.stderr)
        self.assertNotIn(b" slot=", result.stdout + result.stderr)


    def test_eof_caller_context_projects_only_for_eof_after_cleanup_and_closed_slot_phase(self):
        valid = [("locate_batch", "none", "none"), ("seal_measurements", "none", "none")]
        for slot in ("cli16", "cli64", "cli_unlimited", "rendered16", "rendered64", "rendered_unlimited"):
            valid.extend(("sample", slot, phase) for phase in ("before", "at_limit", "after_release",
                          "after_failure" if slot.endswith("16") else "control"))
        for caller, slot, phase in valid:
            line = PREFIX + f"pids-eof caller={caller} slot={slot} phase={phase}"
            result, trace = self.wrapper("DOCKERLENS_NATIVE_CHECK: pids_cleanup\n" + line, status=101)
            self.assertEqual(len(trace), 2)
            self.assertEqual(result.stderr.count((line + "\n").encode()), 1)
            self.assertNotEqual(result.returncode, 0)

    def test_eof_caller_context_refuses_stale_unknown_mixed_and_success_records(self):
        line = PREFIX + "pids-eof caller=sample slot=cli16 phase=after_failure"
        invalid = [line.replace("pids-eof", "pids-read"), line.replace("cli16", "cli64"),
                   line.replace("after_failure", "control"), line.replace("cli16", SECRET),
                   line.replace("sample", "locate_batch"), line + " " + SECRET,
                   line + "\r", line + "\0" + SECRET, line + "\n" + line,
                   line + "\n" + SETUP_REFUSAL + "pids-eof",
                   line + "\nDOCKERLENS_NATIVE_NOFILE_FAILURE: " + SECRET]
        for record in invalid:
            result, _ = self.wrapper("DOCKERLENS_NATIVE_CHECK: pids_cleanup\n" + record, status=101)
            self.assertNotIn(b" caller=", result.stdout + result.stderr)
            self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        for output, status in [(line, 101), ("DOCKERLENS_NATIVE_CHECK: pids_cleanup\n" + line + "\n" + SUCCESS, 0),
                               ("DOCKERLENS_NATIVE_CHECK: pids_cleanup\n" + line + "\n" + SUCCESS, 101)]:
            result, _ = self.wrapper(output, status=status)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b" caller=", result.stdout + result.stderr)
        result, _ = self.wrapper("DOCKERLENS_NATIVE_CHECK: pids_cleanup\n" + line, status=101, terminate_output=False)
        self.assertNotIn(b" caller=", result.stdout + result.stderr)

    def test_unlimited_passing_limit_bit_requires_null_without_minus_one_fallback(self):
        for slot in ("cli_unlimited", "rendered_unlimited"):
            for shape, projects in (("null", True), ("minus_one", False), ("missing", False)):
                shapes = "string,string,string,string,false,string,string," + shape + ",null,array,array,zero"
                line = self.configured_line(slot=slot, shapes=shapes)
                result, _ = self.wrapper(line, status=101)
                self.assertEqual((line + "\n").encode() in result.stderr, projects)


if __name__ == "__main__":
    unittest.main()
