#!/usr/bin/env python3
"""Test-only explicit AF_UNIX HTTP transport, independent of product acquisition.

See docs/native-unix-http.md for the versioned API and closed exit categories.
"""

import argparse
from enum import Enum
import math
import os
import re
import select
import socket
import stat
import sys
import secrets
import time

HEADER_LIMIT = 16 * 1024
BYTE_LIMIT = 64 * 1024 * 1024
MARKERS = {
    2: "invalid-argument", 3: "deadline", 4: "connection-io",
    5: "http-protocol", 6: "size-bound", 7: "private-output",
}


class Category(str, Enum):
    VALIDATION = "validation"
    DEADLINE = "deadline"
    IO = "io"
    PROTOCOL = "protocol"
    SIZE = "size"
    OUTPUT = "output"


CATEGORIES = dict(zip(range(2, 8), Category))


class TransportError(Exception):
    """A closed category; never stores native exception text or payloads."""

    def __init__(self, code):
        self.code = code
        self.category = CATEGORIES[code]
        super().__init__(self.category.value)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportError(3)
    return remaining


def _validate(socket_path, method, path, timeout, response_cap, request_cap, body,
              content_type):
    if (not isinstance(socket_path, str) or not os.path.isabs(socket_path)
            or any(ord(c) < 32 or ord(c) == 127 for c in socket_path)
            or not isinstance(method, str)
            or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method) is None
            or not isinstance(path, str) or not path.startswith("/")
            or path.startswith("//") or "#" in path
            or any(ord(c) <= 32 or ord(c) >= 127 for c in path)
            or not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
            or not 0 < timeout <= 3600 or not math.isfinite(timeout)
            or any(type(cap) is not int or not 0 < cap <= BYTE_LIMIT
                   for cap in (response_cap, request_cap))
            or body is not None and not isinstance(body, bytes)
            or content_type not in (None, "application/json")):
        raise TransportError(2)
    if body is not None and len(body) > request_cap:
        raise TransportError(6)


class _Reader:
    def __init__(self, stream, deadline):
        self.stream, self.deadline, self.buffer = stream, deadline, bytearray()

    def receive(self, cap):
        self.stream.settimeout(_remaining(self.deadline))
        chunk = self.stream.recv(min(cap, 8192))
        _remaining(self.deadline)
        if not chunk:
            raise TransportError(5)
        self.buffer.extend(chunk)

    def line(self, cap):
        while True:
            at = self.buffer.find(b"\r\n")
            if at >= 0:
                if at + 2 > cap:
                    raise TransportError(6)
                result = bytes(self.buffer[:at])
                del self.buffer[:at + 2]
                return result, at + 2
            if len(self.buffer) >= cap:
                raise TransportError(6)
            self.receive(cap - len(self.buffer))

    def exact(self, size):
        while len(self.buffer) < size:
            self.receive(size - len(self.buffer))
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result


def _exchange(socket_path, method, path, body, deadline, response_cap, content_type):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(_remaining(deadline))
        stream.connect(socket_path)
        # Fixed Host is inert HTTP syntax. No hostname is ever resolved.
        head = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
                "Connection: close\r\n")
        if content_type is not None:
            head += "Content-Type: application/json\r\n"
        if body is not None or method == "POST":
            head += f"Content-Length: {len(body) if body is not None else 0}\r\n"
        stream.settimeout(_remaining(deadline))
        stream.sendall(head.encode("ascii") + b"\r\n" + (body or b""))
        reader = _Reader(stream, deadline)
        status_line, used = reader.line(HEADER_LIMIT)
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*", status_line)
        if match is None or int(match[1]) < 200:
            raise TransportError(5)
        status_code = int(match[1])
        headers = {}
        while True:
            line, size = reader.line(HEADER_LIMIT - used)
            used += size
            if not line:
                break
            match = re.fullmatch(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([\x20-\x7e\t]*)", line)
            if match is None:
                raise TransportError(5)
            key, value = match[1].lower(), match[2].strip()
            if key in headers and key in (b"content-length", b"transfer-encoding", b"content-encoding"):
                raise TransportError(5)
            headers[key] = value
        length, transfer = headers.get(b"content-length"), headers.get(b"transfer-encoding")
        if (length is not None and transfer is not None
                or headers.get(b"content-encoding", b"identity").lower() != b"identity"
                or transfer is not None and transfer.lower() != b"chunked"
                or length is not None and re.fullmatch(rb"[0-9]+", length) is None):
            raise TransportError(5)
        if method == "HEAD" or status_code in (204, 304):
            if transfer is not None or status_code == 204 and length not in (None, b"0"):
                raise TransportError(5)
            result = b""
        elif length is not None:
            # Avoid converting arbitrarily long decimal strings.
            if len(length) > 12 or int(length) > response_cap:
                raise TransportError(6)
            result = reader.exact(int(length))
        elif transfer is not None:
            result = bytearray()
            metadata = 0
            while True:
                line, size = reader.line(HEADER_LIMIT - metadata)
                metadata += size
                if re.fullmatch(rb"[0-9a-fA-F]+", line) is None:
                    raise TransportError(5)
                if len(line) > 12 or int(line, 16) > response_cap - len(result):
                    raise TransportError(6)
                size = int(line, 16)
                if not size:
                    # Trailers are deliberately unsupported rather than silently ignored.
                    if reader.exact(2) != b"\r\n":
                        raise TransportError(5)
                    break
                result.extend(reader.exact(size))
                if reader.exact(2) != b"\r\n":
                    raise TransportError(5)
            result = bytes(result)
        else:
            raise TransportError(5)
        if reader.buffer:
            raise TransportError(5)
        _remaining(deadline)
        return status_code, result


def request(socket_path, method, path, body=None, *, timeout,
            max_response_bytes, max_request_bytes=BYTE_LIMIT, content_type=None):
    """Return (actual HTTP status, complete bytes), or raise TransportError."""
    _validate(socket_path, method, path, timeout, max_response_bytes, max_request_bytes,
              body, content_type)
    return _request_until(socket_path, method, path, body,
                          time.monotonic() + timeout, max_response_bytes, content_type)


def _request_until(socket_path, method, path, body, deadline, response_cap, content_type):
    try:
        return _exchange(socket_path, method, path, body, deadline, response_cap, content_type)
    except (TimeoutError, socket.timeout):
        raise TransportError(3) from None
    except (OSError, ValueError, OverflowError):
        raise TransportError(4) from None


def _stdin(deadline, cap):
    result = bytearray()
    while True:
        ready, _, _ = select.select([sys.stdin.buffer], [], [], _remaining(deadline))
        if not ready:
            raise TransportError(3)
        chunk = os.read(sys.stdin.fileno(), min(8192, cap + 1 - len(result)))
        _remaining(deadline)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > cap:
            raise TransportError(6)


def _publish(path, body, deadline):
    temporary = None
    directory = None
    try:
        if not os.path.isabs(path) or not os.path.basename(path):
            raise TransportError(7)
        parent = os.path.dirname(path)
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for component in parent.split("/")[1:]:
            if component in ("", ".", ".."):
                raise TransportError(7)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise TransportError(7)
        staging_name = ".unix-http-" + secrets.token_hex(16)
        descriptor = os.open(staging_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as output:
            staging_info = os.fstat(output.fileno())
            temporary = staging_name
            output.write(body)
        _remaining(deadline)
        # A hard link publishes a complete fresh file exclusively; never replace old bytes.
        os.link(temporary, os.path.basename(path), src_dir_fd=directory,
                dst_dir_fd=directory, follow_symlinks=False)
    except OSError:
        raise TransportError(7) from None
    finally:
        active_failure = sys.exc_info()[0] is not None
        cleanup_failed = False
        try:
            if temporary is not None:
                current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (staging_info.st_dev, staging_info.st_ino):
                    raise TransportError(7)
                os.unlink(temporary, dir_fd=directory)
        except (OSError, TransportError):
            cleanup_failed = True
        finally:
            if directory is not None:
                try:
                    os.close(directory)
                except OSError:
                    cleanup_failed = True
        if cleanup_failed and not active_failure:
            raise TransportError(7)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise TransportError(2)


def _stdout(data):
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except OSError:
        # Prevent interpreter-exit flushing from printing a raw BrokenPipe traceback.
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        raise TransportError(7) from None


def main():
    parser = _Parser(description=__doc__)
    for name in ("socket", "method", "path"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--timeout", required=True, type=float)
    parser.add_argument("--max-response-bytes", required=True, type=int)
    parser.add_argument("--max-request-bytes", type=int)
    parser.add_argument("--body-stdin", action="store_true")
    parser.add_argument("--json-content-type", action="store_true")
    destinations = parser.add_mutually_exclusive_group()
    destinations.add_argument("--response-body-file")
    destinations.add_argument("--discard-body", action="store_true")
    try:
        args = parser.parse_args()
        if args.body_stdin and args.max_request_bytes is None:
            raise TransportError(2)
        cap = args.max_request_bytes if args.max_request_bytes is not None else BYTE_LIMIT
        content_type = "application/json" if args.json_content_type else None
        _validate(args.socket, args.method, args.path, args.timeout, args.max_response_bytes,
                  cap, None, content_type)
        deadline = time.monotonic() + args.timeout
        body = _stdin(deadline, cap) if args.body_stdin else None
        code, result = _request_until(args.socket, args.method, args.path, body, deadline,
                                      args.max_response_bytes, content_type)
        if args.response_body_file:
            _publish(args.response_body_file, result, deadline)
        _remaining(deadline)
        if args.response_body_file or args.discard_body:
            _stdout(f"{code:03d}\n".encode("ascii"))
        else:
            _stdout(result + f"\n{code:03d}".encode("ascii"))
        return 0
    except TransportError as error:
        code = error.code
    except (OSError, ValueError, OverflowError):
        code = 4
    sys.stderr.write(f"native-unix-http-v1:{MARKERS[code]}\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
