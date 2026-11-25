"""Pure mocked-transport cleanup controls; never an Engine or host experiment."""

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_kernel_cleanup as helper

IDENTIFIER = "a" * 64
NAME = "dl-ks-Ab12Cd34-false_zero-oracle"
IMAGE = "docker.io/library/busybox:fixture@sha256:" + "b" * 64
OWNER = "Ab12Cd34"
SECRET = "PRIVATE_KERNEL_CLEANUP_CANARY"
PATH = f"/v1.56/containers/{NAME}/json"


def native():
    return {"Id": IDENTIFIER, "Name": "/" + NAME,
            "Config": {"Image": IMAGE, "Labels": {helper.OWNER: OWNER, "private": SECRET},
                       "Cmd": ["sh", "-c", "line1\nline2\n" + "x" * 20000], "ArgsEscaped": False},
            "Args": [SECRET, "y" * 8000], "Other": {"nested": [None, True, 1, 1.25]}}


def encoded(value):
    return json.dumps(value).encode()


def expected_owned(value):
    """Independent four-field expected ownership, paired with Rust source controls.

    This composes the REAL projection with independently expected ownership.
    It is not a claim that Python executes the Rust owned() implementation.
    """
    return (type(value) is dict and value.get("Id") == IDENTIFIER and value.get("Name") == "/" + NAME
            and value.get("Config", {}).get("Image") == IMAGE
            and value.get("Config", {}).get("Labels", {}).get(helper.OWNER) == OWNER)


class Output:
    def __init__(self):
        self.buffer = io.BytesIO()


class KernelCleanupTests(unittest.TestCase):
    def reject(self, status, body):
        with self.assertRaises(helper.ProjectionError) as caught:
            helper.project(status, body)
        self.assertEqual(str(caught.exception), helper.DIAGNOSTIC)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_large_complete_inspect_projects_only_four_actual_fields_and_full_body_count(self):
        body = encoded(native())
        self.assertGreater(len(body), 8192)
        self.assertLessEqual(len(body), 65536)
        projection = helper.project(200, body)
        self.assertEqual(projection, {"status": 200, "body_bytes": len(body), "object": {
            "Id": IDENTIFIER, "Name": "/" + NAME,
            "Config": {"Image": IMAGE, "Labels": {helper.OWNER: OWNER}}}})
        wire = helper.encode(projection)
        self.assertLess(len(wire), 8192)
        self.assertNotIn(SECRET.encode(), wire)
        self.assertNotIn(b'"Cmd"', wire)
        self.assertNotIn(b'"Args"', wire)
        # Full consumed body and actual captured projection are both charged,
        # even when the body bytes never appeared on child stdout.
        preexisting = 1234
        reserved_and_output = preexisting + 65536 + len(wire)
        reconciled = reserved_and_output - (65536 - projection["body_bytes"])
        self.assertEqual(reconciled, preexisting + len(body) + len(wire))

    def test_full_body_boundary_65536_is_consumed_and_65537_is_refused(self):
        body = encoded(native())
        complete = body + b" " * (65536 - len(body))
        self.assertEqual(len(complete), 65536)
        self.assertEqual(helper.project(200, complete)["body_bytes"], 65536)
        self.reject(200, complete + b" ")

    def test_missing_malformed_and_illtyped_required_fields_fail_closed(self):
        for field in ("Id", "Name", "Config"):
            value = native()
            del value[field]
            self.reject(200, encoded(value))
        for field in ("Image", "Labels"):
            value = native()
            del value["Config"][field]
            self.reject(200, encoded(value))
        value = native()
        del value["Config"]["Labels"][helper.OWNER]
        self.reject(200, encoded(value))
        for field, wrong in (("Id", None), ("Id", "A" * 64), ("Id", "short"), ("Name", False),
                             ("Name", "missing-slash"), ("Name", "/"), ("Config", [])):
            value = native()
            value[field] = wrong
            self.reject(200, encoded(value))
        for field, wrong in (("Image", 1), ("Image", ""), ("Labels", []), ("Labels", None)):
            value = native()
            value["Config"][field] = wrong
            self.reject(200, encoded(value))
        for wrong in (None, False, [], {}, "bad", "Ab12Cd3\n"):
            value = native()
            value["Config"]["Labels"][helper.OWNER] = wrong
            self.reject(200, encoded(value))

    def test_composed_wrong_ownership_at_either_name_or_id_read_never_deletes(self):
        mutations = (
            lambda value: value.update(Id="c" * 64),
            lambda value: value.update(Name="/dl-ks-Ab12Cd34-true_one-oracle"),
            lambda value: value["Config"].update(Image=IMAGE + "-other"),
            lambda value: value["Config"]["Labels"].update({helper.OWNER: "Other123"}),
        )
        for mutate in mutations:
            for wrong_slot in (0, 1):
                bodies = [native(), native()]
                mutate(bodies[wrong_slot])
                deletion = []
                # Both structurally valid actual projections must independently
                # pass expected exact ownership before the deletion callback.
                projected = [helper.project(200, encoded(body))["object"] for body in bodies]
                if all(expected_owned(value) for value in projected):
                    deletion.append(IDENTIFIER)
                self.assertEqual(deletion, [])
        good = helper.project(200, encoded(native()))["object"]
        self.assertTrue(expected_owned(good))

    def test_full_json_duplicates_nonfinite_malformed_unicode_and_projection_overflow_refuse(self):
        small = encoded(native())
        for body in (b"", b"null", b"[]", b'"not an inspect"', small[:-1], small + b"{}",
                     small.replace(b'"Id":', b'"Id":"' + b"c" * 64 + b'","Id":', 1),
                     small.replace(b'"nested":', b'"nested":0,"nested":', 1),
                     small.replace(b'1.25', b'NaN'), small.replace(b'1.25', b'Infinity'),
                     small.replace(b'1.25', b'-Infinity'), small.replace(b'1.25', b'1e9999'),
                     small.replace(SECRET.encode(), b"\\ud800", 1), b"\xff", b"\xef\xbb\xbf" + small):
            self.reject(200, body)
        value = native()
        value["Config"]["Image"] = "x" * 9000
        self.reject(200, encoded(value))

    def test_status404_is_only_an_actual_negative_projection_not_ownership(self):
        body = encoded({"message": SECRET})
        projection = helper.project(404, body)
        self.assertEqual(projection, {"status": 404, "body_bytes": len(body), "object": None})
        self.assertFalse(expected_owned(projection["object"]))
        self.assertNotIn(SECRET.encode(), helper.encode(projection))
        for body in (b"", b"{}", b'{"message":false}', b'{"message":"a","message":"b"}',
                     b'{"message":"a","extra":1}', encoded(native())):
            self.reject(404, body)
        for status in (True, "200", 201, 204, 301, 400, 403, 500, 503):
            self.reject(status, encoded({"message": SECRET}))

    def test_request_uses_original_actual_status_bytes_contract_and_fixed_bounded_get(self):
        body = encoded(native())
        with patch.object(helper.HTTP, "request", return_value=(200, body)) as request:
            projection = helper.request_projection("/private/engine.sock", PATH)
        request.assert_called_once_with("/private/engine.sock", "GET", PATH, timeout=7,
                                        max_response_bytes=65536, max_request_bytes=8388608,
                                        content_type="application/json")
        self.assertEqual(projection["body_bytes"], len(body))
        for path in (PATH.replace("1.56", "1.49"), PATH + "?force=1", PATH.replace("/json", "/start"),
                     "/version", "/v1.56/containers/arbitrary/json", PATH + "\r\nGET /version", "//" + PATH,
                     PATH.replace(NAME, "%2e%2e"), PATH.replace(NAME, NAME + "/..")):
            with patch.object(helper.HTTP, "request") as request:
                with self.assertRaises(helper.ProjectionError):
                    helper.request_projection("/private/engine.sock", path)
                request.assert_not_called()
        for version in ("1.41", "1.56"):
            for key in (NAME, IDENTIFIER):
                with patch.object(helper.HTTP, "request", return_value=(404, b'{"message":"absent"}')):
                    self.assertEqual(helper.request_projection("/private/engine.sock", f"/v{version}/containers/{key}/json")["status"], 404)

    def test_malformed_return_frame_transport_errors_and_bad_cli_have_constant_private_refusal(self):
        cases = [(200,), [200, encoded(native())], (200, encoded(native()), 0),
                 (200, "not bytes"), (200, bytearray(b"{}")), (500, encoded({"message": SECRET}))]
        for frame in cases:
            output = Output()
            with patch.object(helper.HTTP, "request", return_value=frame), patch.object(helper.sys, "stdout", output), contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(helper.main(["--socket", "/private/engine.sock", "--path", PATH]), 1)
            self.assertEqual(output.buffer.getvalue(), b"")
            self.assertEqual(error.getvalue(), helper.DIAGNOSTIC + "\n")
        for code in (2, 3, 4, 5, 6, 7):
            output = Output()
            with patch.object(helper.HTTP, "request", side_effect=helper.HTTP.TransportError(code)), patch.object(helper.sys, "stdout", output), contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(helper.main(["--socket", "/private/engine.sock", "--path", PATH]), 1)
            self.assertEqual(output.buffer.getvalue(), b"")
            self.assertEqual(error.getvalue(), helper.DIAGNOSTIC + "\n")
        for arguments in ([], ["--method", "DELETE"], ["--socket", "/private/engine.sock", "--path", PATH, "--timeout", "8"]):
            with patch.object(helper.HTTP, "request") as request, contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(helper.main(arguments), 1)
                request.assert_not_called()
            self.assertEqual(error.getvalue(), helper.DIAGNOSTIC + "\n")

    def test_successful_main_emits_one_closed_private_frame_without_native_extras(self):
        body = encoded(native())
        output = Output()
        with patch.object(helper.HTTP, "request", return_value=(200, body)), patch.object(helper.sys, "stdout", output), contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(helper.main(["--socket", "/private/engine.sock", "--path", PATH]), 0)
        wire = output.buffer.getvalue()
        self.assertEqual(json.loads(wire), helper.project(200, body))
        self.assertEqual(wire.count(b"\n"), 1)
        self.assertEqual(error.getvalue(), "")
        self.assertNotIn(SECRET.encode(), wire)

    def test_unknown_created_ids_never_authorize_expected_inner_callback(self):
        # Independent expected guard control, pinned to the production Rust
        # predicate/call ordering by test_native_kernel_settings_source.
        def expected_guard(attempted, identifiers, callback):
            if (len(attempted) != 6 or len(identifiers) != 6
                    or any(tried and (type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None)
                           for tried, value in zip(attempted, identifiers))):
                return "outer_teardown_required"
            return callback()
        valid = [f"{i:064x}" for i in range(1, 7)]
        for wrong in (None, "lost", "A" * 64, "a" * 63):
            identifiers = valid.copy()
            identifiers[2] = wrong
            calls = []
            self.assertEqual(expected_guard([True] * 6, identifiers, lambda: calls.append("inner")), "outer_teardown_required")
            self.assertEqual(calls, [])
        calls = []
        self.assertEqual(expected_guard([True] * 6, valid, lambda: calls.append("inner") or "verified_absent"), "verified_absent")
        self.assertEqual(calls, ["inner"])

    def test_individual_body_success_cannot_bypass_unchanged_whole_proof_cleanup_cap(self):
        import native_kernel_settings_proof as reader
        from test_native_kernel_settings_proof import fixture
        value = fixture()
        raw = encoded(native())
        full = raw + b" " * (65536 - len(raw))
        projected = helper.encode(helper.project(200, full))
        value["accounting"]["cleanup_bytes"] = 12 * (len(full) + len(projected))
        self.assertGreater(value["accounting"]["cleanup_bytes"], 552960)
        with self.assertRaisesRegex(ValueError, "^invalid private kernel settings proof$"):
            reader.validate_kernel_settings_proof(value, value["context"], outer_backend="podman")

    def test_actual_capture_output_charge_is_not_reused_after_failure_or_full_body(self):
        maximum, calls_max, envelope, body_max = 4 * 1024 * 1024, 400, 8192 + 2048, 65536
        def room(calls, total):
            return calls < calls_max and total + body_max + envelope <= maximum
        self.assertTrue(room(399, maximum - body_max - envelope))
        self.assertFalse(room(400, 0))
        self.assertFalse(room(399, maximum - body_max - envelope + 1))
        original, captured = 4096, 800
        reserved = original + body_max
        for failure in ("timeout", "oversize", "illtyped", "malformed_frame", "unknown"):
            with self.subTest(failure=failure):
                # No valid frame: no accounting reconciliation is authorized.
                charged = reserved + captured
                self.assertEqual(charged, original + body_max + captured)
        for actual in (1, 8193, 65536):
            reconciled = reserved + captured - (body_max - actual)
            self.assertEqual(reconciled, original + actual + captured)


if __name__ == "__main__":
    unittest.main()
