"""Logging core ordering and actual frame/helper controls, without Cargo."""
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from test_native_logging_proof import fixture, read_mutation, rebind
import native_logging_proof as reader

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/native_logging_tests.rs"


class LoggingCoreWiringTests(unittest.TestCase):
    def test_actual_status_frame_preserves_all_output_lfs_and_inner_exit(self):
        source = SOURCE.read_text()
        literal = re.search(r'const STATUS_FRAME: &str =\s*("(?:[^"\\]|\\.)*");', source).group(1)
        frame_program = json.loads(literal)
        for raw, status in (("canary\n", 0), ("canary\n\n", 0), ("canary", 0), ("", 0),
                            (reader.REFUSAL, 1), ("permission denied\n", 1), (reader.REFUSAL, 124), (reader.REFUSAL, 130), (reader.REFUSAL, 143)):
            with self.subTest(raw=raw, status=status):
                result = subprocess.run(["sh", "-c", frame_program, "dl-log-status", sys.executable, "-c",
                                         "import sys; sys.stderr.write(sys.argv[1]); sys.exit(int(sys.argv[2]))", raw, str(status)],
                                        capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout, (raw + f"\nDOCKERLENS_LOG_EXIT:{status}\n").encode())
                if status in (0, 1):
                    self.assertEqual(reader.parse_frame(result.stdout.decode()), (status, raw))
                else:
                    with self.assertRaises(ValueError):
                        reader.parse_frame(result.stdout.decode())
                proof = fixture()
                read_mutation(proof, 4, raw, status)
                proof["containers"][4]["read"]["frame"] = result.stdout.decode()
                rebind(proof)
                if (raw, status) == (reader.REFUSAL, 1):
                    reader.validate_logging_proof(proof, proof["context"], outer_backend="podman")
                else:
                    with self.assertRaises(ValueError):
                        reader.validate_logging_proof(proof, proof["context"], outer_backend="podman")

    def test_actual_binary_stdout_and_stderr_frames_preserve_nul_and_reject_rebound_hashes(self):
        source = SOURCE.read_text()
        literal = re.search(r'const STATUS_FRAME: &str =\s*("(?:[^"\\]|\\.)*");', source).group(1)
        frame_program = json.loads(literal)
        for slot in (0, 4):
            original = fixture()
            valid = original["containers"][slot]["read"]
            for raw in (valid["raw"].encode() + b"\0", b"\0" + valid["raw"].encode(), valid["raw"].encode().replace(b"\n", b"\0\n")):
                for channel in (1, 2):
                    with self.subTest(slot=slot, raw=raw, channel=channel):
                        result = subprocess.run(["sh", "-c", frame_program, "dl-log-status", sys.executable, "-c",
                                                 "import os,sys;os.write(int(sys.argv[2]),bytes.fromhex(sys.argv[1]));sys.exit(int(sys.argv[3]))",
                                                 raw.hex(), str(channel), str(valid["status"])], capture_output=True, timeout=5, check=False)
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(result.stderr, b"")
                        self.assertEqual(result.stdout, raw + f"\nDOCKERLENS_LOG_EXIT:{valid['status']}\n".encode())
                        self.assertIn(b"\0", result.stdout)
                        with self.assertRaises(ValueError):
                            reader.parse_frame(result.stdout.decode())
                        proof = fixture()
                        read_mutation(proof, slot, raw.decode(), valid["status"])
                        proof["containers"][slot]["read"]["frame"] = result.stdout.decode()
                        rebind(proof)
                        with self.assertRaises(ValueError):
                            reader.validate_logging_proof(proof, proof["context"], outer_backend="podman")

    def http_helper(self, body, status=404):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "socket")
            requests = []
            errors = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path)
                server.listen(1)
                server.settimeout(5)

                def serve():
                    try:
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(5)
                            request = b""
                            while b"\r\n\r\n" not in request:
                                request += connection.recv(4096)
                            requests.append(request)
                            connection.sendall(f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                    except OSError as error:
                        errors.append(type(error).__name__)

                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    result = subprocess.run([sys.executable, str(ROOT / "scripts/native-unix-http.py"),
                                             "--socket", path, "--method", "GET", "--path",
                                             "/v1.41/containers/dl-log-RunA1234-none-oracle/json",
                                             "--timeout", "1", "--max-response-bytes", "1000"],
                                            capture_output=True, timeout=5, check=False)
                finally:
                    thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
            self.assertEqual(len(requests), 1)
            head, payload = requests[0].split(b"\r\n\r\n", 1)
            self.assertEqual(head.split(b"\r\n")[0], b"GET /v1.41/containers/dl-log-RunA1234-none-oracle/json HTTP/1.1")
            self.assertEqual(payload, b"")
            return result

    def test_real_existing_unix_helper_exact_name_get_and_response_bound(self):
        body = b'{"message":"No such container: dl-log-RunA1234-none-oracle"}\n'
        result = self.http_helper(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, body + b"\n404")
        self.assertLessEqual(len(result.stdout), 1024)
        oversized = self.http_helper(b"PRIVATE_LOGGING_CANARY" + b"x" * 1000)
        self.assertEqual(oversized.returncode, 6)
        self.assertEqual(oversized.stdout, b"")
        self.assertEqual(oversized.stderr, b"native-unix-http-v1:size-bound\n")

    def test_core_has_one_original_deadline_and_pre_mutation_liability(self):
        source = SOURCE.read_text()
        create = source[source.index("fn create("):source.index("fn parse_read(")]
        self.assertLess(create.index("absence(run, index)"), create.index("run.attempted[index] = true"))
        self.assertLess(create.index("run.attempted[index] = true"), create.index("let id ="))
        self.assertLess(create.index("let before = configured"), create.index("run.ids[index] = Some(id)"))
        live = source[source.index("fn live_logging_matches_engine()"):source.index("fn unit_facts(")]
        self.assertEqual(live.count("HealthRun::new_for("), 1)
        self.assertEqual(live.count("BoundOuterCleanupOwner::bind"), 1)
        self.assertLess(live.index("context_bytes\n"), live.index("for index in 0..6"))
        self.assertLess(live.index("checked_add(pending)"), live.index("create(&mut run"))
        self.assertLess(live.index('small_docker(&run, &["wait"'), live.index("let read = read(&run"))
        self.assertLess(live.index("let read = read(&run"), live.index("let after = configured"))
        self.assertLess(live.index("final_room(backend"), live.index("cleanup_with(&attempted"))
        self.assertLess(live.index("terminal_cleanup("), live.index("require_verified_result("))
        self.assertLess(live.index("require_verified_result("), live.index("target.publish(&proof)"))
        for forbidden in ("run.calls.set(", "run.bytes.set(", "run.cleanup()", "LogPath", "--follow", "max-file", "--privileged"):
            # Unsupported max-file appears only in offline refusal tests below unit_facts.
            self.assertNotIn(forbidden, live)
        for token in ("Duration::from_secs(134)", "Duration::from_secs(46)", "Duration::from_secs(180)",
                      "cleanup_calls == 54", "run.calls.get() - before_calls == 7", "!run.image_attempted"):
            self.assertIn(token, live)

    def test_local_absence_and_unknown_id_guard_keep_shared_authorization_closed(self):
        source = SOURCE.read_text()
        absence = source[source.index("fn absence("):source.index("fn small_docker(")]
        for token in ('run.request_allowed("GET", &path)', '.checked_sub(Duration::from_secs(46))', '.min(7)',
                      '"/scripts/native-unix-http.py"', '"--max-response-bytes",\n        "1000"', 'run.capture(&mut command, None, false)'):
            self.assertIn(token, absence)
        self.assertNotIn("--body-stdin", absence)
        guard = source[source.index("fn cleanup_with("):source.index("#[test]", source.index("fn cleanup_with("))]
        self.assertIn("*a && !id.as_deref().is_some_and(identifier)", guard)
        self.assertLess(guard.index("CleanupDisposition::OuterTeardownRequired"), guard.index("inner()"))
        self.assertIn("checked_add(54)", guard)
        self.assertIn("checked_add(54 * CLEANUP_ENVELOPE)", guard)
        self.assertIn("backend.final_snapshot_room(calls, bytes, 2)", guard)
        for prepared in ("logging_frames_require_real_inner_exit_exact_bytes_and_no_injected_records",
                         "logging_absence_is_exact_bounded_and_rejects_duplicate_or_unknown_json",
                         "logging_pending_cleanup_and_final_reads_use_checked_original_capacity",
                         "logging_omitted_empty_and_explicit_requests_have_independent_literals",
                         "logging_driver_and_max_size_capabilities_remain_independent",
                         "logging_options_refuse_unknown_driver_keys_and_malformed_sizes"):
            self.assertIn("fn " + prepared + "()", source)


if __name__ == "__main__":
    unittest.main()
