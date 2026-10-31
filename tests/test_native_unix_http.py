"""Independent wire controls for the test-only Unix-HTTP client; no Engine required."""

import contextlib
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-unix-http.py"
SPEC = importlib.util.spec_from_file_location("native_unix_http", SCRIPT)
HTTP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HTTP)


@contextlib.contextmanager
def peer(reply, *, delay=0):
    """One independently parsed request and an authored raw reply, with finite cleanup."""
    with tempfile.TemporaryDirectory(prefix="dl-http-") as directory:
        path = str(Path(directory) / "engine.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        listener.settimeout(2)
        observed = []
        stopped = threading.Event()

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    wire = bytearray()
                    while b"\r\n\r\n" not in wire:
                        part = connection.recv(4096)
                        if not part:
                            return
                        wire.extend(part)
                    head, body = bytes(wire).split(b"\r\n\r\n", 1)
                    length = 0
                    for line in head.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":", 1)[1])
                    while len(body) < length:
                        part = connection.recv(length - len(body))
                        if not part:
                            return
                        body += part
                    observed.append((head, body))
                    pieces = reply if isinstance(reply, list) else [reply]
                    for piece in pieces:
                        if stopped.wait(delay):
                            return
                        connection.sendall(piece)
            except (OSError, ValueError):
                pass  # Client deadline/cancellation intentionally closes the peer.

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield path, observed
        finally:
            stopped.set()
            listener.close()
            thread.join(3)
            if thread.is_alive():
                raise AssertionError("fake server leaked")


class NativeUnixHttpTests(unittest.TestCase):
    def request(self, path, **kwargs):
        return HTTP.request(path, kwargs.pop("method", "GET"),
                            kwargs.pop("target", "/version"),
                            timeout=kwargs.pop("timeout", 1),
                            max_response_bytes=kwargs.pop("max_response_bytes", 1024),
                            **kwargs)

    def cli(self, path, *args, input=None, timeout="1"):
        return subprocess.run([sys.executable, str(SCRIPT), "--socket", path,
                               "--method", "GET", "--path", "/version",
                               "--timeout", timeout, "--max-response-bytes", "1024", *args],
                              input=input, capture_output=True, timeout=3, check=False)



    def test_exact_method_origin_path_binary_body_and_explicit_json_header(self):
        body = b'{"protected":"\x00\xff"}'
        with peer(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}") as (path, seen):
            self.assertEqual(self.request(path, method="POST", target="/v1.41/create?name=x%2By",
                                          body=body, max_request_bytes=len(body),
                                          content_type="application/json"), (201, b"{}"))
        self.assertEqual(seen, [(b"POST /v1.41/create?name=x%2By HTTP/1.1\r\nHost: localhost\r\n"
                                 b"Connection: close\r\nContent-Type: application/json\r\n"
                                 + f"Content-Length: {len(body)}".encode(), body)])

    def test_absent_and_empty_post_both_send_zero_length(self):
        for body in (None, b""):
            with self.subTest(body=body), peer(b"HTTP/1.1 204 No Content\r\n\r\n") as (path, seen):
                self.assertEqual(self.request(path, method="POST", body=body), (204, b""))
            self.assertIn(b"Content-Length: 0", seen[0][0])
            self.assertNotIn(b"Content-Type:", seen[0][0])
            self.assertEqual(seen[0][1], b"")

    def test_get_has_no_invented_content_headers(self):
        with peer(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx") as (path, seen):
            self.assertEqual(self.request(path), (200, b"x"))
        self.assertNotIn(b"Content-Length", seen[0][0])
        self.assertNotIn(b"Content-Type", seen[0][0])

    def test_status_is_real_including_failure_statuses(self):
        for status in (200, 201, 400, 404, 500):
            reply = f"HTTP/1.1 {status} Authored\r\nContent-Length: 0\r\n\r\n".encode()
            with self.subTest(status=status), peer(reply) as (path, _):
                result = self.cli(path)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, f"\n{status}".encode(), b""))

    def test_chunked_and_incremental_complete_responses(self):
        with peer([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                   b"2\r\nab\r\n", b"1\r\nc\r\n0\r\n\r\n"], delay=0.01) as (path, _):
            self.assertEqual(self.request(path, max_response_bytes=3), (200, b"abc"))

    def test_closed_protocol_and_size_errors_never_publish_stdout(self):
        cases = [
            (b"not HTTP\r\n\r\n", 5),
            (b"HTTP/1.1 101 Switching\r\n\r\n", 5),
            (b"HTTP/1.1 200 OK\r\n\r\n", 5),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx", 5),
            (b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", 5),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", 5),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n", 5),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", 5),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Encoding: gzip\r\n\r\n", 5),
            (b"HTTP/1.1 204 Empty\r\nContent-Length: 1\r\n\r\nx", 5),
            (b"HTTP/1.1 200 OK\r\n folded: invalid\r\n\r\n", 5),
            (b"HTTP/1.1 200 OK\r\nX: private", 5),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n", 6),
            (b"HTTP/1.1 200 OK\r\nX: " + b"x" * 16384, 6),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n401\r\n", 6),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n", 5),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx", 5),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\n\r\n", 5),
        ]
        for index, (reply, code) in enumerate(cases):
            with self.subTest(index=index), peer(reply) as (path, _):
                result = self.cli(path)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr,
                                 f"native-unix-http-v1:{HTTP.MARKERS[code]}\n".encode())
                self.assertNotIn(path.encode(), result.stderr)

    def test_slow_incremental_headers_and_body_share_absolute_deadline(self):
        responses = [
            [b"H", b"T", b"T", b"P", b"/", b"1"],
            [b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n", b"x", b"y", b"z"],
        ]
        for response in responses:
            with self.subTest(response=response), peer(response, delay=0.06) as (path, _):
                started = time.monotonic()
                with self.assertRaises(HTTP.TransportError) as caught:
                    self.request(path, timeout=0.17)
                self.assertEqual(caught.exception.category, HTTP.Category.DEADLINE)
                self.assertLess(time.monotonic() - started, 0.5)

    def test_validation_is_closed_and_cannot_select_other_transports(self):
        cases = [dict(target="http://private/"), dict(target="//private/"),
                 dict(target="/x\r\nSecret: value"), dict(method="GET\nX"),
                 dict(timeout=float("nan")), dict(timeout=float("inf")),
                 dict(timeout=0), dict(timeout=3601), dict(max_response_bytes=0),
                 dict(max_request_bytes=-1), dict(content_type="private"), dict(body="private")]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(HTTP.TransportError) as caught:
                self.request("/does-not-exist", **kwargs)
            self.assertEqual((caught.exception.code, str(caught.exception)), (2, "validation"))
        with self.assertRaises(HTTP.TransportError) as caught:
            self.request("relative.sock")
        self.assertEqual(caught.exception.code, 2)
        with self.assertRaises(HTTP.TransportError) as caught:
            self.request("/does-not-exist", body=b"xx", max_request_bytes=1)
        self.assertEqual(caught.exception.code, 6)

    def test_missing_socket_is_io_not_http_000_and_no_ambient_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "missing.sock")
            result = self.cli(path)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (4, b"", b"native-unix-http-v1:connection-io\n"))

    def test_cli_stdin_is_bounded_and_part_of_absolute_deadline(self):
        result = self.cli("/not-contacted", "--body-stdin", input=b"protected")
        self.assertEqual(result.returncode, 2)
        result = self.cli("/not-contacted", "--body-stdin", "--max-request-bytes", "1", input=b"xx")
        self.assertEqual((result.returncode, result.stdout), (6, b""))
        with subprocess.Popen([sys.executable, str(SCRIPT), "--socket", "/not-contacted",
                               "--method", "POST", "--path", "/x", "--timeout", "0.1",
                               "--max-response-bytes", "10", "--body-stdin", "--max-request-bytes", "10"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            child.wait(timeout=1)
            out, err = child.communicate()
        self.assertEqual((child.returncode, out, err), (3, b"", b"native-unix-http-v1:deadline\n"))

    def test_cli_exact_stdin_and_discard_framing(self):
        with peer(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}") as (path, seen):
            result = self.cli(path, "--body-stdin", "--max-request-bytes", "3",
                              "--json-content-type", "--discard-body", input=b"x\x00y")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"201\n", b""))
        self.assertEqual(seen[0][1], b"x\x00y")
        self.assertIn(b"Content-Type: application/json", seen[0][0])

    def test_cancellation_exceptions_propagate_through_importable_api(self):
        for exception in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=exception), mock.patch.object(HTTP, "_exchange", side_effect=exception):
                with self.assertRaises(exception):
                    self.request("/private.sock")

    def test_private_output_is_complete_fresh_exclusive_and_mode_0600(self):
        reply = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nprotected"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "body.json"
            with peer(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nprotected") as (path, _):
                result = self.cli(path, "--response-body-file", str(target))
            self.assertEqual((result.returncode, result.stdout), (0, b"200\n"))
            self.assertEqual(target.read_bytes(), b"protected")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with peer(reply) as (path, _):
                result = self.cli(path, "--response-body-file", str(target))
            self.assertEqual((result.returncode, result.stdout), (7, b""))
            self.assertEqual(target.read_bytes(), b"protected")
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_private_output_rejects_existing_symlinks_and_nonprivate_directories(self):
        reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "body"
            target.symlink_to(root / "missing")
            for mode in (0o700, 0o755):
                root.chmod(mode)
                with peer(reply) as (path, _):
                    result = self.cli(path, "--response-body-file", str(target))
                self.assertEqual((result.returncode, result.stdout), (7, b""))
            root.chmod(0o700)
            target.unlink()
            link = root / "linked"
            link.symlink_to(root, target_is_directory=True)
            with peer(reply) as (path, _):
                result = self.cli(path, "--response-body-file", str(link / "fresh"))
            self.assertEqual(result.returncode, 7)
            self.assertFalse((root / "fresh").exists())

    def test_output_cleanup_failure_has_closed_category(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "fresh")
            unlink = os.unlink
            try:
                with mock.patch.object(HTTP.os, "unlink", side_effect=OSError("protected cleanup")):
                    with self.assertRaises(HTTP.TransportError) as caught:
                        HTTP._publish(target, b"private", time.monotonic() + 1)
                self.assertEqual((caught.exception.category, str(caught.exception)),
                                 (HTTP.Category.OUTPUT, "output"))
            finally:
                for path in Path(directory).iterdir():
                    unlink(path)

    def test_staging_collision_preserves_preexisting_foreign_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory) / ".unix-http-fixed"
            staging.write_bytes(b"preexisting protected bytes")
            target = Path(directory) / "fresh"
            with mock.patch.object(HTTP.secrets, "token_hex", return_value="fixed"):
                with self.assertRaises(HTTP.TransportError) as caught:
                    HTTP._publish(str(target), b"new bytes", time.monotonic() + 1)
            self.assertEqual(caught.exception.code, 7)
            self.assertEqual(staging.read_bytes(), b"preexisting protected bytes")
            self.assertFalse(target.exists())

    def test_publication_cancellation_and_first_failure_survive_cleanup_error(self):
        for exception in (KeyboardInterrupt(), SystemExit(), HTTP.TransportError(3)):
            with self.subTest(exception=type(exception)), tempfile.TemporaryDirectory() as directory:
                target = str(Path(directory) / "fresh")
                close = os.close
                with mock.patch.object(HTTP, "_remaining", side_effect=exception), \
                        mock.patch.object(HTTP.os, "unlink", side_effect=OSError("protected cleanup")), \
                        mock.patch.object(HTTP.os, "close", wraps=close) as closed:
                    with self.assertRaises(type(exception)) as caught:
                        HTTP._publish(target, b"private", time.monotonic() + 1)
                self.assertIs(caught.exception, exception)
                self.assertTrue(closed.called)
                directory_fd = closed.call_args.args[0]
                with self.assertRaises(OSError):
                    os.fstat(directory_fd)
                self.assertFalse(Path(target).exists())

    def test_failed_response_cannot_publish_partial_cleanup_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absence"
            with peer(b"HTTP/1.1 404 Missing\r\nContent-Length: 9\r\n\r\nprivate") as (path, _):
                result = self.cli(path, "--response-body-file", str(target))
            self.assertEqual((result.returncode, result.stdout), (5, b""))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cancellation_closes_inflight_request_without_output(self):
        with peer([b"H"] * 40, delay=0.03) as (path, _):
            child = subprocess.Popen([sys.executable, str(SCRIPT), "--socket", path,
                                      "--method", "DELETE", "--path", "/owned", "--timeout", "2",
                                      "--max-response-bytes", "100"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.08)
            child.terminate()
            out, err = child.communicate(timeout=1)
            self.assertEqual((child.returncode, out, err), (-signal.SIGTERM, b"", b""))

    def test_closed_downstream_pipe_uses_fixed_output_failure_without_shutdown_traceback(self):
        with peer(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nprotected") as (path, _):
            child = subprocess.Popen([sys.executable, str(SCRIPT), "--socket", path,
                                      "--method", "GET", "--path", "/private", "--timeout", "1",
                                      "--max-response-bytes", "100"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child.stdout.close()
            error = child.stderr.read()
            child.stderr.close()
            child.wait(timeout=2)
        self.assertEqual((child.returncode, error), (7, b"native-unix-http-v1:private-output\n"))

    def test_canonical_gate_discovers_independent_standalone_transport_controls(self):
        gate = (ROOT / "scripts/check-all.sh").read_text()
        self.assertIn("python3 -m unittest discover -s tests -v", gate)
        source = SCRIPT.read_text()
        self.assertNotIn("subprocess", source)
        import ast
        imports = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imports.extend(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                imports.append(node.module.partition(".")[0])
        self.assertTrue(imports)
        self.assertTrue(set(imports) <= sys.stdlib_module_names)
        documentation = (ROOT / "docs/native-unix-http.md").read_text()
        self.assertIn("not migrated", documentation)
        self.assertIn("BoxFerry", documentation)


class NativePeerLeaseTests(unittest.TestCase):
    """Real wire bytes through one socketpair, no Engine or listener needed."""

    def exchange(self, reply, lease, *, timeout=1):
        client, server = socket.socketpair()
        received = []
        def respond():
            try:
                wire = bytearray()
                while b"\r\n\r\n" not in wire:
                    part = server.recv(4096)
                    if not part:
                        return
                    wire.extend(part)
                received.append(bytes(wire))
                server.sendall(reply)
            except OSError:
                pass
            finally:
                server.close()
        thread = threading.Thread(target=respond)
        thread.start()
        # Preserve real socket's I/O/closure while replacing only connect; the
        # pair is already connected, and exactly this stream reaches the lease.
        proxy = mock.Mock(wraps=client)
        proxy.__enter__ = mock.Mock(return_value=proxy)
        proxy.__exit__ = mock.Mock(side_effect=lambda *_: client.close())
        proxy.connect = mock.Mock()
        factory = mock.Mock(side_effect=lambda stream: lease if stream is proxy else self.fail("wrong stream"))
        try:
            with mock.patch.object(HTTP.socket, "socket", return_value=proxy):
                result = HTTP.request("/explicit-held-endpoint", "GET", "/v1.41/containers/" + "a" * 64 + "/json",
                                      timeout=timeout, max_response_bytes=128, peer_lease=factory)
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(proxy.connect.call_count, 1)
            return result, received
        finally:
            client.close()
            thread.join(2)
            self.assertFalse(thread.is_alive())

    def test_lease_is_same_stream_checked_before_after_body_and_closed(self):
        lease = mock.Mock()
        result, requests = self.exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", lease)
        self.assertEqual(result, (200, b"{}"))
        self.assertEqual(lease.check.call_count, 3)
        self.assertEqual(lease.close.call_count, 1)
        self.assertEqual(len(requests), 1)
        self.assertTrue(requests[0].startswith(b"GET /v1.41/containers/" + b"a" * 64 + b"/json HTTP/1.1\r\n"))

    def test_malformed_body_and_each_peer_check_failure_close_without_payload(self):
        for fail_at in (0, 1, 2, 3):
            with self.subTest(fail_at=fail_at):
                lease = mock.Mock()
                if fail_at:
                    lease.check.side_effect = [None] * (fail_at - 1) + [RuntimeError("private PID/path/body")]
                reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" if fail_at else b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxBAD"
                with self.assertRaises(HTTP.TransportError) as error:
                    self.exchange(reply, lease)
                self.assertNotIn("private", str(error.exception))
                self.assertEqual(lease.close.call_count, 1)

    def test_slow_lease_uses_original_http_deadline_and_cancellation_closes(self):
        lease = mock.Mock()
        lease.check.side_effect = lambda: time.sleep(0.02)
        with self.assertRaises(HTTP.TransportError) as error:
            self.exchange(b"", lease, timeout=0.005)
        self.assertEqual(error.exception.code, 3)
        self.assertEqual(lease.close.call_count, 1)
        lease = mock.Mock()
        lease.check.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.exchange(b"", lease)
        self.assertEqual(lease.close.call_count, 1)

    def test_cleanup_failure_preserves_primary_protocol_deadline_and_cancellation(self):
        for primary in ("protocol", "deadline", "cancellation", "none"):
            with self.subTest(primary=primary):
                lease = mock.Mock()
                lease.close.side_effect = RuntimeError("private cleanup PID/path/body")
                reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                if primary == "protocol":
                    reply = b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n"
                elif primary == "deadline":
                    lease.check.side_effect = lambda: time.sleep(0.02)
                elif primary == "cancellation":
                    lease.check.side_effect = KeyboardInterrupt()
                if primary == "cancellation":
                    with self.assertRaises(KeyboardInterrupt):
                        self.exchange(reply, lease)
                else:
                    with self.assertRaises(HTTP.TransportError) as failure:
                        self.exchange(reply, lease, timeout=0.005 if primary == "deadline" else 1)
                    self.assertEqual(failure.exception.code, {"protocol": 5, "deadline": 3, "none": 4}[primary])
                    self.assertNotIn("private", str(failure.exception))
                self.assertEqual(lease.close.call_count, 1)

    def test_close_only_failure_inside_callers_except_block_still_refuses_payload(self):
        lease = mock.Mock()
        lease.close.side_effect = RuntimeError("private cleanup failure")
        try:
            raise ValueError("caller's unrelated handled exception")
        except ValueError:
            with self.assertRaises(HTTP.TransportError) as failure:
                self.exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nusable", lease)
        self.assertEqual(failure.exception.code, 4)
        self.assertEqual(lease.close.call_count, 1)

    def test_slow_successful_lease_close_cannot_return_after_original_deadline(self):
        lease = mock.Mock()
        lease.close.side_effect = lambda: time.sleep(0.03)
        with self.assertRaises(HTTP.TransportError) as failure:
            self.exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", lease, timeout=0.01)
        self.assertEqual(failure.exception.code, 3)
        self.assertEqual(lease.close.call_count, 1)
if __name__ == "__main__":
    unittest.main()
