"""Private kernel-only cleanup ownership projection, never a transport or oracle."""

import argparse
import importlib.util
import json
import math
from pathlib import Path
import re
import sys

OWNER = "io.dockerlens.native-run"
BODY_LIMIT = 65536
OUTPUT_LIMIT = 8192
TIMEOUT = 7
REQUEST_LIMIT = 8388608
DIAGNOSTIC = "invalid native kernel cleanup"
INSPECT_PATH = re.compile(r"/v(?:1\.41|1\.56)/containers/(?:[0-9a-f]{64}|dl-ks-[A-Za-z0-9]{8}-(?:omitted|false_zero|true_one)-(?:oracle|rendered))/json")
SPEC = importlib.util.spec_from_file_location("kernel_cleanup_http", Path(__file__).with_name("native-unix-http.py"))
HTTP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HTTP)


class ProjectionError(Exception):
    """Closed refusal; no native values or exception text are retained."""


def fail():
    raise ProjectionError(DIAGNOSTIC) from None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def finite_number(value):
    result = float(value)
    if not math.isfinite(result):
        fail()
    return result


def reject_constant(_value):
    fail()


def text(value):
    if (type(value) is not str or not value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        fail()
    return value


def validate_strings(native):
    pending = [native]
    while pending:
        value = pending.pop()
        if type(value) is str:
            value.encode("utf-8")  # Reject escaped unpaired surrogates anywhere.
        elif type(value) is dict:
            pending.extend(value)
            pending.extend(value.values())
        elif type(value) is list:
            pending.extend(value)


def project(status, body):
    """Validate the FULL native JSON before returning only actual ownership fields.

    Structural validation is not ownership authentication. The Rust caller must
    still compare BOTH requested names and canonical IDs using existing owned().
    """
    try:
        if type(status) is not int or status not in (200, 404) or type(body) is not bytes or not 0 < len(body) <= BODY_LIMIT:
            fail()
        native = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object,
                            parse_float=finite_number, parse_constant=reject_constant)
        validate_strings(native)
        if type(native) is not dict:
            fail()
        if status == 404:
            if set(native) != {"message"}:
                fail()
            text(native["message"])
            owned = None
        else:
            identifier = text(native["Id"])
            name = text(native["Name"])
            if re.fullmatch(r"[0-9a-f]{64}", identifier) is None or not name.startswith("/") or len(name) < 2:
                fail()
            config = native["Config"]
            if type(config) is not dict or type(config["Labels"]) is not dict:
                fail()
            image = text(config["Image"])
            owner = text(config["Labels"][OWNER])
            if re.fullmatch(r"[A-Za-z0-9]{8}", owner) is None:
                fail()
            owned = {"Id": identifier, "Name": name, "Config": {"Image": image, "Labels": {OWNER: owner}}}
        result = {"status": status, "body_bytes": len(body), "object": owned}
        # Bound output without transforming/minifying any native Cmd/Args body.
        encode(result)
        return result
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, UnicodeError):
        fail()


def encode(projection):
    payload = json.dumps(projection, allow_nan=False).encode("utf-8") + b"\n"
    if len(payload) > OUTPUT_LIMIT:
        fail()
    return payload


def request_projection(socket_path, path):
    if type(path) is not str or INSPECT_PATH.fullmatch(path) is None:
        fail()
    frame = HTTP.request(socket_path, "GET", path, timeout=TIMEOUT,
                         max_response_bytes=BODY_LIMIT, max_request_bytes=REQUEST_LIMIT,
                         content_type="application/json")
    if type(frame) is not tuple or len(frame) != 2:
        fail()
    return project(*frame)


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        fail()


def main(arguments=None):
    try:
        parser = Parser(add_help=False)
        parser.add_argument("--socket", required=True)
        parser.add_argument("--path", required=True)
        arguments = parser.parse_args(arguments)
        projection = request_projection(arguments.socket, arguments.path)
        sys.stdout.buffer.write(encode(projection))
        sys.stdout.buffer.flush()
        return 0
    except (ProjectionError, HTTP.TransportError, OSError, ValueError, TypeError, KeyError,
            OverflowError, RecursionError, UnicodeError):
        sys.stderr.write(DIAGNOSTIC + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
