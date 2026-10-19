"""Actual anonymous pipes, authored packets, fake clocks; no broker/runtime launch."""

import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import json
import os
from pathlib import Path
import struct
from threading import Event, Thread, Timer
import time
import unittest
from unittest.mock import patch

import native_outer_broker_protocol as protocol
from native_outer_broker_protocol import Binding, Empty, Endpoint, Ledger, OCIReceipt, ProtocolError, RecheckedReceipt, StartedReceipt

BINDING = Binding("a" * 64, "b" * 40, "39173069422", "1", "c" * 64, "sha256:" + "d" * 64)
ID = "e" * 64
STARTED = "2026-10-19T12:34:56.123456789Z"
CANARY = "PRIVATE_BROKER_CANARY_/host/original-oci"


def packet(verb="create", kind="request", sequence=1, container_id=None, payload=None):
    # Independent envelope schema, no use of Endpoint._packet or canonical().
    return {"v": 1, "kind": kind, "session": "a" * 64, "candidate": "b" * 40,
            "run_id": "39173069422", "run_attempt": "1", "launch_digest": "c" * 64,
            "image_digest": "sha256:" + "d" * 64, "sequence": sequence,
            "container_id": container_id, "verb": verb, "payload": {} if payload is None else payload}


def wire(value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return struct.pack(">I", len(raw)) + raw


def receipt(raw=b'{"original":"private OCI bytes"}'):
    return OCIReceipt(raw, 9, 1234, 0, 0o100640, 1, len(raw), hashlib.sha256(raw).hexdigest(), 23456)


def budget(seconds=2, max_calls=10000, max_bytes=1048576, clock=time.monotonic, cancelled=lambda: False):
    now = clock()
    return Ledger(max_calls, max_bytes, now + seconds, now + seconds + 1, now + seconds + 2,
                  now + seconds + 3, clock, cancelled)


@contextmanager
def peers(ledger=None, client_binding=BINDING, broker_binding=BINDING):
    request_r, request_w = os.pipe()
    reply_r, reply_w = os.pipe()
    ledger = budget() if ledger is None else ledger
    client = Endpoint("client", client_binding, reply_r, request_w, ledger)
    broker = Endpoint("broker", broker_binding, request_r, reply_w, ledger)
    try:
        yield client, broker, ledger
    finally:
        client.close()
        broker.close()


class BrokerProtocolTests(unittest.TestCase):
    def refused(self, operation, endpoint=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(ProtocolError) as caught:
                operation()
        self.assertEqual(str(caught.exception), "outer broker protocol refused")
        self.assertEqual(repr(caught.exception), "ProtocolError('outer broker protocol refused')")
        self.assertNotIn(CANARY, repr(caught.exception))
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        if endpoint is not None:
            self.assertTrue(endpoint.poisoned and endpoint.closed)
            for fd in (endpoint.read_fd, endpoint.write_fd):
                with self.assertRaises(OSError):
                    os.fstat(fd)
            # Failure remains permanent, without a single further read/write.
            calls, size = endpoint.ledger.calls, endpoint.ledger.bytes
            with patch.object(protocol.os, "read", side_effect=AssertionError("no IO")), \
                 patch.object(protocol.os, "write", side_effect=AssertionError("no IO")):
                with self.assertRaises(ProtocolError):
                    endpoint.receive()
            self.assertEqual((endpoint.ledger.calls, endpoint.ledger.bytes), (calls, size))

    def exchange(self, client, broker, verb, payload, container_id=None):
        client.request(verb)
        message = broker.receive()
        self.assertEqual((message.verb, type(message.payload)), (verb, Empty))
        errors = []

        def respond():
            try:
                broker.respond(payload, container_id)
            except BaseException as error:
                errors.append(error)

        thread = Thread(target=respond)
        thread.start()
        try:
            result = client.receive()
        finally:
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return result

    def ready(self, client, broker):
        self.exchange(client, broker, "create", Empty(), ID)
        value = receipt()
        self.exchange(client, broker, "initialize", value)
        self.exchange(client, broker, "start", StartedReceipt(23456, STARTED))
        return value

    def test_full_closed_transaction_and_raw_oci_once_at_maximum_size(self):
        with peers() as (client, broker, ledger):
            created = self.exchange(client, broker, "create", Empty(), ID)
            self.assertEqual((created.sequence, created.container_id), (1, ID))
            self.assertEqual((client.id, broker.id), (ID, ID))
            raw = (b"\x00\xff" + CANARY.encode()) * 2000
            raw = (raw + b"X" * 65536)[:65536]
            original = receipt(raw)
            initialized = self.exchange(client, broker, "initialize", original)
            self.assertEqual(initialized.payload.raw, raw)
            self.assertEqual(initialized.payload.sha256, hashlib.sha256(raw).hexdigest())
            self.assertNotIn(CANARY, repr(initialized))
            self.assertNotIn(CANARY, repr(initialized.payload))
            with self.assertRaises(FrozenInstanceError):
                initialized.payload.raw = b"other"
            self.exchange(client, broker, "start", StartedReceipt(23456, STARTED))
            for _ in range(2):
                checked = self.exchange(client, broker, "recheck", RecheckedReceipt(original.sha256, 23456, STARTED))
                self.assertEqual(checked.payload.init_pid, 23456)
            self.assertEqual(client.cleanup_obligation, "live_id")
            self.exchange(client, broker, "teardown", Empty())
            self.assertTrue(client.closed and broker.closed)
            self.assertFalse(client.poisoned or broker.poisoned)
            self.assertEqual(client.cleanup_obligation, "teardown_acknowledged_unverified")
            self.assertGreater(ledger.bytes, 2 * len(raw))
            self.assertGreater(ledger.calls, 24)

    def test_independent_literal_create_request_and_canonical_wire(self):
        # Literal independent canonical field order and values.
        raw = (b'{"candidate":"' + b"b" * 40 + b'","container_id":null,"image_digest":"sha256:' + b"d" * 64 +
               b'","kind":"request","launch_digest":"' + b"c" * 64 + b'","payload":{},"run_attempt":"1",'
               b'"run_id":"39173069422","sequence":1,"session":"' + b"a" * 64 + b'","v":1,"verb":"create"}')
        with peers() as (_client, broker, _ledger):
            os.write(_client.write_fd, struct.pack(">I", len(raw)) + raw)
            message = broker.receive()
            self.assertEqual((message.verb, message.container_id, message.sequence), ("create", None, 1))
            self.assertEqual(broker.cleanup_obligation, "unknown_create")
        with peers() as (client, broker, _ledger):
            client.request("create")
            header = os.read(broker.read_fd, 4)
            self.assertEqual(struct.unpack(">I", header)[0], len(raw))
            self.assertEqual(os.read(broker.read_fd, len(raw)), raw)

    def test_exact_envelope_keys_types_binding_and_no_arbitrary_verbs_or_payload(self):
        changes = {"session": "f" * 64, "candidate": "f" * 40, "launch_digest": "f" * 64,
                   "image_digest": "sha256:" + "f" * 64, "run_id": "39173069423", "run_attempt": "2",
                   "sequence": True, "v": True, "container_id": ID, "kind": "reply",
                   "verb": "OPEN", "payload": {"path": CANARY}}
        for key, value in changes.items():
            with self.subTest(key=key), peers() as (client, broker, _ledger):
                altered = packet()
                altered[key] = value
                os.write(client.write_fd, wire(altered))
                self.refused(broker.receive, broker)
        for key in packet():
            with peers() as (client, broker, _ledger):
                altered = packet()
                del altered[key]
                os.write(client.write_fd, wire(altered))
                self.refused(broker.receive, broker)
        with peers() as (client, broker, _ledger):
            altered = packet()
            altered[CANARY] = CANARY
            os.write(client.write_fd, wire(altered))
            self.refused(broker.receive, broker)
        for verb in ("OPEN", "command", "query", "inspect_url", None, True, {}, []):
            with peers() as (client, _broker, _ledger):
                self.refused(lambda: client.request(verb), client)

    def test_noncanonical_duplicate_nonfinite_nonascii_and_bad_json(self):
        normal = wire(packet())[4:]
        invalids = [normal + b" ", normal.replace(b'"v":1', b'"v":1,"v":1'),
                    normal.replace(b'"v":1', b'"v":NaN'), normal.replace(b'"v":1', b'"v":1.0'),
                    normal.replace(b'"payload":{}', b'"payload":[]'), b"\xff", b"[]", b"null", b"{", b"[" * 3000 + b"]" * 3000]
        for raw in invalids:
            with peers() as (client, broker, _ledger):
                os.write(client.write_fd, struct.pack(">I", len(raw)) + raw)
                self.refused(broker.receive, broker)

    def test_sequence_replay_id_mutation_wrong_reply_and_initialize_once(self):
        for field, replacement in (("sequence", 1), ("sequence", 3), ("container_id", "f" * 64),
                                   ("container_id", None), ("verb", "start")):
            with peers() as (client, broker, _ledger):
                self.exchange(client, broker, "create", Empty(), ID)
                altered = packet("initialize", sequence=2, container_id=ID)
                altered[field] = replacement
                os.write(client.write_fd, wire(altered))
                self.refused(broker.receive, broker)
        with peers() as (client, broker, _ledger):
            self.exchange(client, broker, "create", Empty(), ID)
            self.exchange(client, broker, "initialize", receipt())
            self.refused(lambda: client.request("initialize"), client)
        for field, replacement in (("session", "f" * 64), ("container_id", "not-an-id"), ("sequence", 2)):
            with peers() as (client, broker, _ledger):
                client.request("create")
                altered = packet(kind="reply", container_id=ID)
                altered[field] = replacement
                os.write(broker.write_fd, wire(altered))
                self.refused(client.receive, client)
                self.assertEqual(client.cleanup_obligation, "unknown_create")

    def test_oci_typed_fields_full_hash_metadata_and_base64_are_strict(self):
        good = receipt()
        changes = {"raw": b"", "device": 0, "inode": True, "uid": 1000, "mode": 0o100666,
                   "links": 2, "size": len(good.raw) + 1, "sha256": "0" * 64, "init_pid": True}
        for key, value in list(changes.items()) + [("raw", b"x" * 65537), ("mode", 0o040700), ("links", True), ("uid", False)]:
            with self.subTest(key=key), peers() as (client, broker, _ledger):
                self.exchange(client, broker, "create", Empty(), ID)
                client.request("initialize")
                broker.receive()
                self.refused(lambda: broker.respond(replace(good, **{key: value})), broker)
        valid_payload = {"raw": base64.b64encode(good.raw).decode(), "device": 9, "inode": 1234, "uid": 0,
                         "mode": 0o100640, "links": 1, "size": len(good.raw), "sha256": good.sha256, "init_pid": 23456}
        for replacement in ("!", "é", base64.b64encode(good.raw).decode() + "=", True):
            with peers() as (client, broker, _ledger):
                self.exchange(client, broker, "create", Empty(), ID)
                client.request("initialize")
                altered = dict(valid_payload, raw=replacement)
                os.write(broker.write_fd, wire(packet("initialize", "reply", 2, ID, altered)))
                self.refused(client.receive, client)

    def test_started_and_recheck_facts_pin_exact_pid_time_and_original_digest(self):
        for value in (StartedReceipt(True, STARTED), StartedReceipt(23457, STARTED),
                      StartedReceipt(23456, "0001-01-01T00:00:00Z"),
                      StartedReceipt(23456, "0001-01-01T01:00:00+01:00"), StartedReceipt(23456, CANARY)):
            with peers() as (client, broker, _ledger):
                self.exchange(client, broker, "create", Empty(), ID)
                self.exchange(client, broker, "initialize", receipt())
                client.request("start")
                broker.receive()
                self.refused(lambda: broker.respond(value), broker)
        for value in (RecheckedReceipt("0" * 64, 23456, STARTED),
                      RecheckedReceipt(receipt().sha256, 23457, STARTED),
                      RecheckedReceipt(receipt().sha256, 23456, "2026-10-19T12:34:57Z")):
            with peers() as (client, broker, _ledger):
                self.ready(client, broker)
                client.request("recheck")
                broker.receive()
                self.refused(lambda: broker.respond(value), broker)

    def test_eof_partial_frames_oversize_zero_and_never_eof_acknowledgment(self):
        for raw in (b"", b"\0\0", struct.pack(">I", 100) + b"partial", struct.pack(">I", 0), struct.pack(">I", 90001)):
            with peers() as (client, broker, _ledger):
                if raw:
                    os.write(client.write_fd, raw)
                client.close()
                self.refused(broker.receive, broker)
        with peers() as (client, broker, _ledger):
            value = self.ready(client, broker)
            self.exchange(client, broker, "recheck", RecheckedReceipt(value.sha256, 23456, STARTED))
            client.request("recheck")
            broker.receive()
            broker.close()
            self.refused(client.receive, client)
            self.assertEqual(client.cleanup_obligation, "live_id")

    def test_validated_create_id_survives_decode_cancel_and_partial_reply_failure(self):
        cancelled = Event()
        with peers(budget(cancelled=cancelled.is_set)) as (client, broker, _ledger):
            client.request("create")
            broker.receive()
            broker.respond(Empty(), ID)
            real_loads = json.loads

            def decode(*args, **kwargs):
                result = real_loads(*args, **kwargs)
                cancelled.set()
                return result

            with patch.object(protocol.json, "loads", side_effect=decode):
                self.refused(client.receive, client)
            self.assertEqual((client.id, client.cleanup_obligation), (ID, "live_id"))
        cancelled = Event()
        with peers(budget(cancelled=cancelled.is_set)) as (client, broker, _ledger):
            client.request("create")
            broker.receive()
            real_write = os.write

            def fail_after_write(*args):
                count = real_write(args[0], args[1][:17])
                self.assertEqual(count, 17)
                self.assertLess(count, len(args[1]))
                cancelled.set()
                return count

            with patch.object(protocol.os, "write", side_effect=fail_after_write):
                self.refused(lambda: broker.respond(Empty(), ID), broker)
            self.assertEqual((broker.id, broker.cleanup_obligation), (ID, "live_id"))

    def test_timeout_cancel_and_backpressure_are_bounded_and_permanent(self):
        ledger = budget(seconds=0.03)
        with peers(ledger) as (client, _broker, _ledger):
            client.request("create")
            began = time.monotonic()
            self.refused(client.receive, client)
            self.assertLess(time.monotonic() - began, 0.3)
            self.assertEqual(client.cleanup_obligation, "unknown_create")
        cancelled = Event()
        with peers(budget(cancelled=cancelled.is_set)) as (client, _broker, _ledger):
            client.request("create")
            timer = Timer(0.01, cancelled.set)
            timer.start()
            try:
                self.refused(client.receive, client)
            finally:
                timer.join(timeout=1)
        with peers(budget(seconds=0.03)) as (client, _broker, _ledger):
            while True:
                try:
                    os.write(client.write_fd, b"X" * 4096)
                except BlockingIOError:
                    break
            began = time.monotonic()
            self.refused(lambda: client.request("create"), client)
            self.assertLess(time.monotonic() - began, 0.3)

    def test_aggregate_ledger_budget_never_resets_on_request_or_new_endpoint(self):
        ledger = budget(max_bytes=700)
        with peers(ledger) as (client, broker, _ledger):
            client.request("create")
            self.refused(broker.receive, broker)  # Same conservative ledger charges both ends.
            self.assertGreater(ledger.bytes, 400)
        with peers(budget(max_calls=1)) as (client, _broker, _ledger):
            self.refused(lambda: client.request("create"), client)
        ledger = budget()
        with peers(ledger):
            pass
        request_r, request_w = os.pipe()
        reply_r, reply_w = os.pipe()
        try:
            self.refused(lambda: Endpoint("client", BINDING, reply_r, request_w, ledger))
        finally:
            os.close(request_r)
            os.close(reply_w)

    def test_shared_absolute_deadlines_teardown_after_startup_and_unknown_binding(self):
        now = [0.0]
        ledger = Ledger(10000, 1048576, 1, 2, 3, 4, lambda: now[0], lambda: False)
        with peers(ledger) as (client, broker, _ledger):
            self.exchange(client, broker, "create", Empty(), ID)
            now[0] = 1.5
            self.exchange(client, broker, "teardown", Empty())
            self.assertEqual(client.cleanup_obligation, "teardown_acknowledged_unverified")
        now[0] = 0.0
        ledger = Ledger(10000, 1048576, 1, 2, 3, 4, lambda: now[0], lambda: False)
        with peers(ledger) as (client, broker, _ledger):
            self.ready(client, broker)
            now[0] = 2.5
            self.exchange(client, broker, "teardown", Empty())
        now[0] = 0.0
        ledger = Ledger(10000, 1048576, 1, 2, 3, 4, lambda: now[0], lambda: False)
        with peers(ledger) as (client, broker, _ledger):
            self.exchange(client, broker, "create", Empty(), ID)
            now[0] = 1.5
            os.write(client.write_fd, wire(packet("initialize", sequence=2, container_id=ID)))
            self.refused(broker.receive, broker)
        for replacement in (replace(BINDING, session="f" * 64), replace(BINDING, candidate="f" * 40)):
            with peers(client_binding=BINDING, broker_binding=replacement) as (client, broker, _ledger):
                client.request("create")
                self.refused(broker.receive, broker)
        for startup, custody, cleanup, watchdog in ((121, 122, 123, 124), (1, 2, 3, 1801),
                                                  (1, 2, 3, 2), (1, float("nan"), 3, 4)):
            self.refused(lambda: Ledger(1, 1, startup, custody, cleanup, watchdog, lambda: 0, lambda: False))
        def broken_clock():
            raise RuntimeError(CANARY)
        self.refused(lambda: Ledger(1, 1, 1, 2, 3, 4, broken_clock, lambda: False))

    def test_nonzero_nanosecond_near_utc_minimum_is_not_a_zero_started_at(self):
        started = "0001-01-01T01:00:00.000000001+01:00"
        with peers() as (client, broker, _ledger):
            self.exchange(client, broker, "create", Empty(), ID)
            original = receipt()
            self.exchange(client, broker, "initialize", original)
            result = self.exchange(client, broker, "start", StartedReceipt(23456, started))
            self.assertEqual(result.payload.started_at, started)
            self.exchange(client, broker, "recheck", RecheckedReceipt(original.sha256, 23456, started))

    def test_cleanup_expiry_and_clock_regression_never_renew_an_allowance(self):
        for regression in (False, True):
            now = [0.0]
            ledger = Ledger(10000, 1048576, 1, 2, 3, 4, lambda: now[0], lambda: False)
            with self.subTest(regression=regression), peers(ledger) as (client, broker, _ledger):
                self.exchange(client, broker, "create", Empty(), ID)
                if regression:
                    now[0] = 0.5
                    ledger.check("cleanup")
                    now[0] = 0.25
                else:
                    now[0] = 3.0
                self.refused(lambda: client.request("teardown"), client)
                self.assertEqual(client.cleanup_obligation, "live_id")
                self.refused(broker.receive, broker)
                self.assertEqual(broker.cleanup_obligation, "live_id")

    def test_direct_ledger_errors_never_expose_callback_or_hash_private_values(self):
        def private_failure():
            raise RuntimeError(CANARY)

        for attribute in ("clock", "cancelled"):
            for method in ("check", "debit"):
                with self.subTest(attribute=attribute, method=method):
                    ledger = budget()
                    setattr(ledger, attribute, private_failure)
                    self.refused(lambda: getattr(ledger, method)("startup"))

        class PrivateHash:
            def __hash__(self):
                raise RuntimeError(CANARY)

        ledger = budget()
        self.refused(lambda: ledger.claim(BINDING, PrivateHash()))
        self.refused(lambda: ledger.check(PrivateHash()))
        self.refused(lambda: Ledger(1, 1, 1, 2, 3, 4, private_failure, lambda: False))

    def test_received_oci_exact_keys_and_noncanonical_base64_pad_bits(self):
        raw = b"x"
        value = {"raw": "eA==", "device": 9, "inode": 1234, "uid": 0, "mode": 0o100640,
                 "links": 1, "size": 1, "sha256": hashlib.sha256(raw).hexdigest(), "init_pid": 23456}
        variants = [dict(value, raw="eB=="), dict(value, unknown=CANARY), dict(value, uid=False)]
        for key in value:
            missing = dict(value)
            del missing[key]
            variants.append(missing)
        for payload in variants:
            with peers() as (client, broker, _ledger):
                self.exchange(client, broker, "create", Empty(), ID)
                client.request("initialize")
                os.write(broker.write_fd, wire(packet("initialize", "reply", 2, ID, payload)))
                self.refused(client.receive, client)

    def test_pipe_endpoint_validation_no_inheritance_and_no_runtime_surface(self):
        with peers() as (client, broker, _ledger):
            for fd in (client.read_fd, client.write_fd, broker.read_fd, broker.write_fd):
                self.assertFalse(os.get_inheritable(fd))
                self.assertFalse(os.get_blocking(fd))
        for change in (replace(BINDING, run_id="01"), replace(BINDING, launch_digest=CANARY),
                       replace(BINDING, candidate="b" * 64), replace(BINDING, run_attempt=True)):
            read_fd, write_fd = os.pipe()
            self.refused(lambda: Endpoint("client", change, read_fd, write_fd, budget()))
        source = (Path(__file__).resolve().parents[1] / "scripts/native_outer_broker_protocol.py").read_text()
        for forbidden in ("subprocess", "sudo", "os.open(", "socket", "if __name__", "print(", "native_outer_lifecycle", "ProtocolError(raw"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
