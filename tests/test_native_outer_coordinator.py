"""Offline coordinator accounting controls; no runtime/native commands."""

from dataclasses import FrozenInstanceError, replace
import json
import io
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import native_outer_coordinator as coordinator

from native_outer_coordinator import (Allowance, CoordinationError, PRIVATE_CONTEXT_BYTES, ReservationBook, ReservedBudget,
                                       read_consumer_context, serialize_consumer_context)


class PhysicalSourceAccountingTests(unittest.TestCase):
    def budget(self, size, *, cancelled=lambda: False):
        return coordinator.ReservedBudget(coordinator.Reservation(
            secrets.token_hex(32), 1, "source", "test", coordinator.Allowance(0, size, 100),
            time.monotonic_ns() + 10_000_000_000), time.monotonic_ns, cancelled)

    def test_remaining_zero_one_exact_and_lookahead_never_overread(self):
        for remaining in (0, 1, 8):
            with self.subTest(remaining=remaining):
                budget, physical = self.budget(remaining), []
                def read(maximum):
                    physical.append(maximum)
                    return b"x" * maximum
                with self.assertRaises(CoordinationError):
                    coordinator.bounded_source_io(budget, 9, read)
                self.assertEqual(sum(physical), remaining)
                self.assertEqual(budget.used.source_bytes, remaining)
                self.assertTrue(budget.poisoned)
                self.assertFalse(budget._source_claims)
        budget = self.budget(8)
        self.assertEqual(coordinator.bounded_source_io(budget, 8, lambda maximum: b"x" * maximum), b"x" * 8)
        with self.assertRaises(CoordinationError):
            coordinator.bounded_source_io(budget, 1, lambda _maximum: self.fail("unfunded EOF probe"))
        self.assertEqual(budget.used.source_bytes, 8)

    def test_partial_eof_and_unread_claim_release_do_not_refund_spend(self):
        budget = self.budget(8)
        self.assertEqual(coordinator.bounded_source_io(budget, 9, lambda _maximum: b"abc"), b"abc")
        self.assertEqual(budget.used.source_bytes, 3)
        self.assertEqual(coordinator.bounded_source_io(budget, 9, lambda _maximum: b""), b"")
        with budget.claim_source(5) as claim:
            self.assertEqual(claim.limit, 5)
            claim.consume(5)
        self.assertEqual(budget.used.source_bytes, 8)
        self.assertEqual(budget._source_reserved, 0)

    def test_simultaneous_claims_share_capacity_and_cannot_cross_phase(self):
        budget = self.budget(10)
        with budget.claim_source(8) as first:
            with budget.claim_source(8) as second:
                self.assertEqual((first.limit, second.limit), (8, 2))
                second.consume(1)
                first.consume(3)
        self.assertEqual(budget.used.source_bytes, 4)
        self.assertEqual(budget._source_reserved, 0)
        with budget.claim_source(6) as claim:
            scope = coordinator.ScopeBudget(budget, self.budget(10))
            with self.assertRaises(CoordinationError):
                scope.begin(object())
            self.assertIs(scope.active, budget)
            claim.consume(2)
        self.assertEqual((budget.used.native_calls, budget.used.source_bytes), (0, 6))

    def test_post_read_cancel_and_io_error_keep_completed_bytes(self):
        cancelled = [False]
        budget = self.budget(8, cancelled=lambda: cancelled[0])
        def read(_maximum):
            cancelled[0] = True
            return b"abc"
        with self.assertRaises(CoordinationError):
            coordinator.bounded_source_io(budget, 8, read)
        self.assertEqual(budget.used.source_bytes, 3)
        self.assertEqual(budget._source_reserved, 0)
        budget = self.budget(8)
        physical = io.BytesIO(b"12345678")
        def failed(maximum):
            physical.read(min(4, maximum))
            raise OSError("authored post-I/O failure")
        with self.assertRaises(OSError):
            coordinator.bounded_source_io(budget, 8, failed)
        self.assertEqual(physical.tell(), 4)
        self.assertEqual(budget.used.source_bytes, 8)
        self.assertTrue(budget.poisoned)
        with self.assertRaises(CoordinationError):
            coordinator.bounded_source_io(budget, 4, physical.read)
        self.assertEqual(physical.tell(), 4)
        self.assertEqual(budget._source_reserved, 0)

    def test_invalid_result_after_physical_io_charges_full_claim_and_poison(self):
        for invalid in ("4", True, -1, 9, None):
            with self.subTest(result=invalid):
                budget, physical = self.budget(8), io.BytesIO(b"12345678")
                def failed(maximum):
                    physical.read(min(4, maximum))
                    return invalid
                with self.assertRaises(CoordinationError):
                    coordinator.bounded_source_io(budget, 8, failed)
                self.assertEqual((physical.tell(), budget.used.source_bytes), (4, 8))
                self.assertTrue(budget.poisoned)
                self.assertFalse(budget._source_claims)
                with self.assertRaises(CoordinationError):
                    coordinator.bounded_source_io(budget, 1, physical.read)
                self.assertEqual(physical.tell(), 4)

    def test_unknown_failure_cannot_reset_phase_or_poison_independent_recovery(self):
        lane, pids = self.budget(10), self.budget(10)
        book, roles = coordinator.prepare_reservations(secrets.token_hex(32), time.monotonic_ns() + 300_000_000_000)
        recovery = ReservedBudget(book.claim_before_spawn(roles["root_recovery"]), time.monotonic_ns, lambda: False)
        scope = coordinator.ScopeBudget(lane, pids)
        physical = io.BytesIO(b"12345678")
        # The other claim is known unused; unwinding releases its reservation,
        # never the failed operation's permanently charged maximum.
        with lane.claim_source(6):
            def failed(maximum):
                physical.read(maximum)
                raise OSError("authored unknown completion")
            with self.assertRaises(OSError):
                coordinator.bounded_source_io(scope, 8, failed)
            self.assertEqual(lane._source_reserved, 6)
        self.assertEqual((physical.tell(), lane.used.source_bytes, lane._source_reserved), (4, 4, 0))
        with self.assertRaises(CoordinationError):
            scope.begin(object())
        self.assertIs(scope.active, lane)
        self.assertEqual(coordinator.bounded_source_io(recovery, 8, lambda _maximum: b"cleanup"), b"cleanup")
        self.assertEqual(recovery.used.source_bytes, 7)
        self.assertEqual((recovery.reservation.sequence, recovery.reservation.role), (8, "root_recovery"))
        with self.assertRaises(CoordinationError):
            book.claim_before_spawn(roles["root_recovery"])
        with self.assertRaises(CoordinationError):
            ReservedBudget(recovery.reservation, time.monotonic_ns, lambda: False)

    def test_concurrent_completed_claim_is_charged_even_after_other_fault_poison(self):
        budget = self.budget(10)
        with budget.claim_source(6) as existing:
            def failed(_maximum):
                raise OSError("unknown completion")
            with self.assertRaises(OSError):
                coordinator.bounded_source_io(budget, 8, failed)
            with self.assertRaises(CoordinationError):
                existing.consume(2)
        self.assertEqual((budget.used.source_bytes, budget._source_reserved), (6, 0))
        self.assertTrue(budget.poisoned)

    def test_raw_fdopen_meter_cannot_prefetch_past_aggregate(self):
        import tempfile
        with tempfile.TemporaryFile() as source:
            source.write(b"x" * 10000)
            source.seek(0)
            budget = self.budget(1)
            with coordinator.metered_source_reads(budget):
                stream = os.fdopen(os.dup(source.fileno()), "rb")
                try:
                    with self.assertRaises(CoordinationError):
                        stream.read(10000)
                finally:
                    # A poisoned budget must not prevent closing the raw FD.
                    with self.assertRaises(CoordinationError):
                        stream.close()
            self.assertEqual(source.tell(), 1)
            self.assertEqual(budget.used.source_bytes, 1)

    def test_real_candidate_loader_cannot_read_past_remaining_one(self):
        root = Path(__file__).resolve().parents[1]
        item = json.loads((root / "docs/native-image-defaults/20261019-accounts-v1.json").read_bytes())["images"][0]
        budget, physical = self.budget(1), []
        original = os.read
        def read(descriptor, maximum):
            raw = original(descriptor, maximum)
            physical.append((maximum, len(raw)))
            return raw
        with patch.object(coordinator.os, "read", read), self.assertRaises(CoordinationError):
            coordinator.candidate_account(item["lane"], item["architecture"], item["canonical_reference"], budget=budget)
        self.assertEqual(physical, [(1, 1)])
        self.assertEqual(budget.used.source_bytes, 1)

    def test_private_child_context_write_is_prebounded_before_physical_io(self):
        budget = self.budget(1)
        written, original = [], os.write
        def write(descriptor, raw):
            count = original(descriptor, raw)
            written.append((len(raw), count))
            return count
        with patch.object(coordinator.os, "write", write), self.assertRaises(CoordinationError):
            coordinator.run_private_role((sys.executable, "-c", "import sys;sys.stdin.buffer.read()"),
                                         {"PATH": "/usr/bin:/bin"}, b"private context", budget,
                                         time.monotonic_ns() + 3_000_000_000)
        self.assertEqual(written, [(1, 1)])
        self.assertEqual(budget.used.source_bytes, 1)
        self.assertFalse(budget._source_claims)


class ConsumerBootstrapAccountingTests(unittest.TestCase):
    def test_partial_raw_stdin_adopts_actual_spend_once_without_prefetch(self):
        from test_native_outer_authority import authority_fixture
        context = authority_fixture()[0]
        context["binding"]["session"] = secrets.token_hex(32)
        raw = coordinator.serialize_consumer_context(context)
        class Partial:
            def __init__(self):
                self.source = io.BytesIO(raw)
            def read(self, maximum):
                return self.source.read(min(3, maximum))
        class Buffered:
            def __init__(self):
                self.raw = Partial()
            def read(self, _maximum):
                raise AssertionError("buffered prefetch was used")
        bootstrap = coordinator.ConsumerInput("reader")
        decoded = coordinator.read_consumer_context(Buffered(), bootstrap=bootstrap)
        budget = bootstrap.adopt(decoded)
        self.assertEqual(budget.used.source_bytes, len(raw))
        self.assertEqual(budget.used.io_calls, bootstrap.calls)
        self.assertEqual((budget.reservation.role, budget.reservation.sequence), ("reader", 6))
        self.assertEqual(budget.reservation.allowance.source_bytes, 219000)
        with self.assertRaises(CoordinationError):
            bootstrap.adopt(decoded)
        self.assertEqual(budget.used.source_bytes, len(raw))

    def test_executable_role_and_fixed_original_slice_precede_any_stdin_io(self):
        source = io.BytesIO(b"private")
        with self.assertRaises(CoordinationError):
            coordinator.ConsumerInput("producer")
        with patch.object(coordinator, "ROLE_PLAN", (("reader", "pids", coordinator.Allowance(0, 1, 10)),)):
            with self.assertRaises(CoordinationError):
                coordinator.ConsumerInput("reader")
        self.assertEqual(source.tell(), 0)

    def test_missing_partial_and_oversized_stdin_never_adopt_or_overread(self):
        from test_native_outer_authority import authority_fixture
        valid_context = authority_fixture()[0]
        for raw in (b"", b'{"schema_version":', b"x" * (coordinator.PRIVATE_CONTEXT_BYTES + 4096)):
            with self.subTest(length=len(raw)):
                bootstrap = coordinator.ConsumerInput("reader")
                source = io.BytesIO(raw)
                with self.assertRaises(CoordinationError):
                    coordinator.read_consumer_context(source, bootstrap=bootstrap)
                self.assertEqual(bootstrap.spent, min(len(raw), coordinator.PRIVATE_CONTEXT_BYTES + 1))
                self.assertEqual(source.tell(), bootstrap.spent)
                self.assertFalse(bootstrap.adopted)
                self.assertTrue(bootstrap.failed)
                with self.assertRaises(CoordinationError):
                    bootstrap.read(source)
                with self.assertRaises(CoordinationError):
                    bootstrap.adopt(valid_context)

    def test_raw_unknown_failure_and_invalid_result_charge_current_claim_and_cannot_adopt(self):
        from test_native_outer_authority import authority_fixture
        valid_context = authority_fixture()[0]
        for invalid in (OSError("authored post-read failure"), "4", True, -1, 4097, None, b"x" * 4097):
            with self.subTest(result_type=type(invalid).__name__):
                physical = io.BytesIO(b"12345678")
                class Source:
                    def read(self, maximum):
                        physical.read(min(4, maximum))
                        if isinstance(invalid, BaseException):
                            raise invalid
                        return invalid
                bootstrap = coordinator.ConsumerInput("reader")
                with self.assertRaises(CoordinationError):
                    coordinator.read_consumer_context(Source(), bootstrap=bootstrap)
                self.assertEqual((physical.tell(), bootstrap.spent, bootstrap.calls), (4, 4096, 1))
                self.assertTrue(bootstrap.failed)
                self.assertFalse(bootstrap.adopted)
                with self.assertRaises(CoordinationError):
                    bootstrap.read(Source())
                with self.assertRaises(CoordinationError):
                    bootstrap.adopt(valid_context)
                self.assertEqual(physical.tell(), 4)

    def test_eof_without_strict_parse_and_changed_validated_context_cannot_adopt(self):
        from test_native_outer_authority import authority_fixture
        context = authority_fixture()[0]
        bootstrap = coordinator.ConsumerInput("reader")
        raw = coordinator.serialize_consumer_context(context)
        self.assertEqual(bootstrap.read(io.BytesIO(raw)), raw)
        with self.assertRaises(CoordinationError):
            bootstrap.adopt(context)
        bootstrap = coordinator.ConsumerInput("reader")
        decoded = coordinator.read_consumer_context(io.BytesIO(raw), bootstrap=bootstrap)
        decoded["binding"]["session"] = secrets.token_hex(32)
        with self.assertRaises(CoordinationError):
            bootstrap.adopt(decoded)

    def test_role_table_drift_cannot_refresh_bootstrap_allowance(self):
        from test_native_outer_authority import authority_fixture
        context = authority_fixture()[0]
        context["binding"]["session"] = secrets.token_hex(32)
        bootstrap = coordinator.ConsumerInput("reader")
        decoded = coordinator.read_consumer_context(io.BytesIO(coordinator.serialize_consumer_context(context)), bootstrap=bootstrap)
        changed = tuple((role, scope, coordinator.Allowance(allowance.native_calls, allowance.source_bytes + 1, allowance.io_calls))
                        if role == "reader" else (role, scope, allowance) for role, scope, allowance in coordinator.ROLE_PLAN)
        with patch.object(coordinator, "ROLE_PLAN", changed):
            with self.assertRaises(CoordinationError):
                bootstrap.adopt(decoded)
        self.assertTrue(bootstrap.adopted)


class PhaseAccountingTests(unittest.TestCase):
    def budget(self):
        book, roles = coordinator.prepare_reservations(secrets.token_hex(32), time.monotonic_ns() + 600_000_000_000)
        return coordinator.ReservedBudget(book.claim_before_spawn(roles["caller_lane"]), time.monotonic_ns, lambda: False)

    def test_partial_request_prepays_both_bounded_copies_before_decode(self):
        for raw in (b"", b"\x00\x00", b"\x00\x00\x00\x05[]", b"\x00\x00\x00\x00", b"\x00\x00\x20\x01"):
            with self.subTest(length=len(raw)):
                budget = self.budget()
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, raw)
                    os.close(write_fd)
                    write_fd = None
                    with self.assertRaises(coordinator.CoordinationError):
                        coordinator.phase_read(read_fd, budget=budget)
                    self.assertEqual(budget.used.source_bytes, 2 * (coordinator.PHASE_BYTES + 4))
                    self.assertGreaterEqual(budget.used.io_calls, 3 * coordinator.PHASE_IO_CALLS)
                finally:
                    os.close(read_fd)
                    if write_fd is not None:
                        os.close(write_fd)

    def test_actual_sources_and_five_outer_requests_exhaust_explicit_old_caller(self):
        # A lower bound, not whole-path fit: root protocol/log/context/ACK
        # traffic is deliberately excluded. Canonical performs these same
        # source reads, then receives setup/producer/emitter/final/teardown
        # under caller_lane (reader request alone is in caller_pids).
        root = Path(__file__).resolve().parents[1]
        old_bytes = {"root_lane": 400000, "caller_lane": 200000, "emitter": 448576}
        old_plan = tuple((role, scope, replace(allowance, source_bytes=old_bytes[role])) if role in old_bytes
                         else (role, scope, allowance) for role, scope, allowance in coordinator.ROLE_PLAN)
        with patch.object(coordinator, "ROLE_PLAN", old_plan):
            budget = self.budget()
        self.assertEqual(budget.reservation.allowance.source_bytes, 200000)
        shell = (root / "scripts/native-conformance.sh").read_bytes()
        budget.debit(source_bytes=len(shell), io_calls=1)
        records = json.loads((root / "docs/native-image-defaults/20261019-accounts-v1.json").read_bytes())
        item = records["images"][0]
        coordinator.candidate_account(item["lane"], item["architecture"], item["canonical_reference"], budget=budget)
        source_bytes = sum((root / "docs/native-image-defaults" / name).stat().st_size for name in
                           ("20261019-accounts-v1.json", "podman493-source-binding-v1.json", "20261019-paths-v1.json"))
        self.assertEqual(budget.used.source_bytes, len(shell) + source_bytes)
        self.assertGreater(len(shell) + source_bytes + 5 * 2 * (coordinator.PHASE_BYTES + 4),
                           budget.reservation.allowance.source_bytes)
        with self.assertRaises(coordinator.CoordinationError):
            for phase in ("setup", "producer", "emitter", "final", "teardown"):
                read_fd, write_fd = os.pipe()
                try:
                    coordinator.phase_write(write_fd, [phase])
                    coordinator.phase_read(read_fd, budget=budget)
                finally:
                    os.close(write_fd)
                    os.close(read_fd)
        self.assertTrue(budget.poisoned)


class ReservationTests(unittest.TestCase):
    def test_candidate_static_partition_preserves_exact_envelopes_and_fixed_once_admission(self):
        expected = (("root_lane", "outer", Allowance(16, 288000, 30000)),
                    ("caller_lane", "outer", Allowance(0, 290000, 20000)),
                    ("emitter", "outer", Allowance(0, 470576, 20000)),
                    ("root_pids", "pids", Allowance(3, 450000, 12000)),
                    ("caller_pids", "pids", Allowance(0, 379576, 12000)),
                    ("reader", "pids", Allowance(0, 219000, 12000)),
                    ("producer", "pids", Allowance(177, 1048576, 0)),
                    ("root_recovery", "recovery", Allowance(4, 81993, 12000)))
        self.assertEqual(coordinator.ROLE_PLAN, expected)
        session, deadline = secrets.token_hex(32), time.monotonic_ns() + 60_000_000_000
        book, roles = coordinator.prepare_reservations(session, deadline)
        self.assertEqual(dict(book.envelopes), {"outer": Allowance(16, 1048576, 70000),
                                              "pids": Allowance(180, 2097152, 36000),
                                              "recovery": Allowance(4, 81993, 12000)})
        self.assertEqual(dict(book.used), dict(book.envelopes))
        for sequence, (role, scope, allowance) in enumerate(expected, 1):
            reservation = roles[role]
            self.assertEqual(reservation, coordinator.fixed_reservation(session, role, deadline))
            self.assertEqual((reservation.sequence, reservation.scope, reservation.allowance),
                             (sequence, scope, allowance))
            with self.assertRaises(CoordinationError):
                book.claim_before_spawn(replace(reservation))
            self.assertIs(book.claim_before_spawn(reservation), reservation)
            with self.assertRaises(CoordinationError):
                book.claim_before_spawn(reservation)

    def test_each_candidate_role_overcap_cannot_spill_or_recreate_recovery(self):
        for failed_role, _scope, _allowance in coordinator.ROLE_PLAN:
            with self.subTest(role=failed_role):
                book, roles = coordinator.prepare_reservations(secrets.token_hex(32), time.monotonic_ns() + 60_000_000_000)
                budgets = {role: ReservedBudget(book.claim_before_spawn(reservation), time.monotonic_ns, lambda: False)
                           for role, reservation in roles.items()}
                budget = budgets[failed_role]
                with self.assertRaises(CoordinationError):
                    budget.debit(source_bytes=budget.reservation.allowance.source_bytes + 1)
                self.assertTrue(budget.poisoned)
                for role, sibling in budgets.items():
                    self.assertEqual(sibling.used, Allowance(0, 0, 0))
                    if role != failed_role:
                        self.assertFalse(sibling.poisoned)
                        sibling.debit(source_bytes=sibling.reservation.allowance.source_bytes)
                        self.assertEqual(sibling.used.source_bytes, roles[role].allowance.source_bytes)
                self.assertEqual((roles["root_recovery"].sequence, roles["root_recovery"].allowance),
                                 (8, Allowance(4, 81993, 12000)))
                with self.assertRaises(CoordinationError):
                    book.claim_before_spawn(roles["root_recovery"])
                with self.assertRaises(CoordinationError):
                    book.reserve("replacement_recovery", "recovery", Allowance(4, 81993, 12000))
                self.assertEqual(dict(book.used), dict(book.envelopes))

    def book(self):
        return ReservationBook(secrets.token_hex(32), {"pids": Allowance(10, 100, 40), "lane": Allowance(2, 20, 10)},
                               {"pids": 190_000_000_000, "lane": 600_000_000_000})

    def test_nonoverlapping_predebits_and_failed_spawn_never_refund(self):
        book = self.book()
        producer = book.reserve("producer", "pids", Allowance(8, 80, 30))
        reader = book.reserve("reader", "pids", Allowance(2, 20, 10))
        self.assertIs(book.claim_before_spawn(producer), producer)
        with self.assertRaises(CoordinationError):
            book.claim_before_spawn(producer)
        # A failed Popen cannot return producer's unused credit.
        with self.assertRaises(CoordinationError):
            book.reserve("retry", "pids", Allowance(1, 0, 0))
        self.assertIs(book.claim_before_spawn(reader), reader)
        self.assertEqual(book.used["pids"], Allowance(10, 100, 40))
        with self.assertRaises(TypeError):
            book.used["pids"] = Allowance(0, 0, 0)
        with self.assertRaises(TypeError):
            book.envelopes["pids"] = Allowance(20, 200, 80)
        with self.assertRaises(FrozenInstanceError):
            producer.allowance.native_calls = 20

    def test_replay_forgery_role_reuse_and_scope_cannot_create_allowance(self):
        book = self.book()
        reservation = book.reserve("producer", "pids", Allowance(1, 1, 1))
        for forged in (replace(reservation, sequence=2), replace(reservation),
                       replace(reservation, allowance=Allowance(10, 100, 40))):
            with self.assertRaises(CoordinationError):
                book.claim_before_spawn(forged)
        for role, scope in (("producer", "pids"), ("new", "new_scope")):
            with self.assertRaises(CoordinationError):
                book.reserve(role, scope, Allowance(0, 0, 0))
        # Nofile/lane allowance is separate, never imported into PIDs.
        book.reserve("nofile_boundary", "lane", Allowance(2, 20, 10))
        self.assertEqual(book.used["pids"], Allowance(1, 1, 1))

    def test_child_cannot_spend_another_roles_slice_or_reset_after_failure(self):
        book = self.book()
        reservation = book.reserve("producer", "pids", Allowance(1, 10, 3))
        child = ReservedBudget(reservation, lambda: 10, lambda: False)
        child.debit(native_calls=1, source_bytes=10, io_calls=3)
        with self.assertRaises(CoordinationError):
            child.debit(native_calls=1)
        with self.assertRaises(CoordinationError):
            child.debit()
        with self.assertRaises(CoordinationError):
            ReservedBudget(reservation, lambda: 10, lambda: False)
        self.assertEqual(book.used["pids"], Allowance(1, 10, 3))

    def test_deadline_cancellation_clock_drift_and_bool_values_refuse(self):
        for bad in (Allowance(True, 0, 0), Allowance(0, -1, 0), Allowance(0, 0, 1.0)):
            with self.assertRaises(CoordinationError):
                self.book().reserve("producer", "pids", bad)
        now = [10]
        reservation = self.book().reserve("producer", "pids", Allowance(1, 10, 3))
        child = ReservedBudget(reservation, lambda: now[0], lambda: False)
        now[0] = 9
        with self.assertRaises(CoordinationError):
            child.check()
        with self.assertRaises(CoordinationError):
            ReservedBudget(self.book().reserve("expired", "pids", Allowance(1, 10, 3)),
                           lambda: reservation.deadline_ns, lambda: False)
        with self.assertRaises(CoordinationError):
            ReservedBudget(self.book().reserve("cancelled", "pids", Allowance(1, 10, 3)), lambda: 10, lambda: True)

    def test_actual_separate_processes_get_only_their_prepaid_slices(self):
        root = Path(__file__).resolve().parents[1]
        book = self.book()
        reservations = [book.reserve("producer", "pids", Allowance(7, 70, 28)),
                        book.reserve("reader", "pids", Allowance(3, 30, 12))]
        child_code = '''import json,sys
from native_outer_coordinator import Allowance,Reservation,ReservedBudget,CoordinationError
v=json.loads(sys.stdin.buffer.read(4097)); a=Allowance(*v['limits'])
r=Reservation(v['session'],v['sequence'],v['role'],'pids',a,v['deadline'])
b=ReservedBudget(r,lambda:10,lambda:False)
b.debit(native_calls=a.native_calls,source_bytes=a.source_bytes,io_calls=a.io_calls)
try:
    b.debit(native_calls=1)
    raise AssertionError('overspend accepted')
except CoordinationError:
    pass
try:
    ReservedBudget(r,lambda:10,lambda:False)
    raise AssertionError('reservation reset accepted')
except CoordinationError:
    pass
print(json.dumps([b.used.native_calls,b.used.source_bytes,b.used.io_calls]))
'''
        observed = []
        for reservation in reservations:
            book.claim_before_spawn(reservation)
            payload = {"session": reservation.session, "sequence": reservation.sequence, "role": reservation.role,
                       "limits": [reservation.allowance.native_calls, reservation.allowance.source_bytes, reservation.allowance.io_calls],
                       "deadline": reservation.deadline_ns}
            completed = subprocess.run([sys.executable, "-c", child_code], input=json.dumps(payload).encode(),
                                       cwd=root, env={"PATH": os.environ["PATH"], "PYTHONPATH": str(root / "scripts"),
                                                      "PYTHONDONTWRITEBYTECODE": "1"},
                                       capture_output=True, close_fds=True, timeout=3, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            observed.append(json.loads(completed.stdout))
        self.assertEqual(tuple(map(sum, zip(*observed))), (10, 100, 40))
        self.assertEqual(book.used["pids"], Allowance(10, 100, 40))


class ConsumerContextTests(unittest.TestCase):
    def context(self):
        binding = {"session": "1" * 64, "candidate_sha": "2" * 40, "execution_origin": "github_actions", "ci_run_id": "39173069422", "ci_run_attempt": "1",
                   "owner": "AbCd1234", "lane": "upstream-rootful", "outer_id": "3" * 64,
                   "intent_digest": "4" * 64, "expectation_digest": "5" * 64}
        return {"schema_version": 1, "contract": "outer-private-context-v1", "binding": binding,
                "source": {"intent": {}, "preflight": {}, "database": {}, "oci": {}, "log": {}},
                "boundary": [1, [4194304, 2**64 - 1, 2**32 - 1], [2**64 - 1] * 3,
                             [2**64 - 1, 2**64 - 1, 2**32 - 1], [2**64 - 1] * 2,
                             "6" * 64, "7" * 64, "4" * 64, "5" * 64, ["8" * 64, "sha256:" + "9" * 64, 1]],
                "pids": {"start_ns": 10_000_000_000, "deadline_ns": 190_000_000_000, "deadline_epoch": 1800000000,
                         "producer_reservation": {"ordinary_calls": 177, "ordinary_bytes": 1048576,
                                                  "cleanup_calls": 90, "cleanup_bytes": 1048576},
                         "external_reservation": {"ordinary_calls": 3, "ordinary_bytes": 1007623,
                                                  "cleanup_calls": 8, "cleanup_bytes": 1048576}}}

    def test_maximum_boundary_and_real_serialization_limits_include_encoding(self):
        value = self.context()
        encoded = serialize_consumer_context(value)
        self.assertEqual(read_consumer_context(io.BytesIO(encoded)), value)
        # This tests the actual encoded transport, not a source-string count.
        value["source"]["oci"]["raw"] = "A" * 87384
        value["source"]["preflight"]["semantic"] = "\"\\\n" * 100
        initial = serialize_consumer_context(value)
        value["source"]["intent"]["padding"] = ""
        padding_base = len(serialize_consumer_context(value))
        value["source"]["intent"]["padding"] = "A" * (PRIVATE_CONTEXT_BYTES - padding_base)
        maximal = serialize_consumer_context(value)
        self.assertEqual(len(maximal), PRIVATE_CONTEXT_BYTES)
        self.assertLess(len(initial), len(maximal))
        value["source"]["intent"]["padding"] += "A"
        with self.assertRaises(CoordinationError):
            serialize_consumer_context(value)
        with self.assertRaises(CoordinationError):
            read_consumer_context(io.BytesIO(maximal + b" "))

    def test_local_origin_has_no_fabricated_ci_identity_and_no_fallback(self):
        value = self.context()
        value["binding"].update(execution_origin="local_process", ci_run_id=None, ci_run_attempt=None)
        self.assertEqual(read_consumer_context(io.BytesIO(serialize_consumer_context(value))), value)
        for origin, run, attempt in (("github_actions", None, None), ("local_process", "1", "1"),
                                     ("local_process", None, "1"), ("other", None, None)):
            value["binding"].update(execution_origin=origin, ci_run_id=run, ci_run_attempt=attempt)
            with self.assertRaises(CoordinationError):
                serialize_consumer_context(value)

    def test_duplicate_unknown_bool_reservation_and_noncanonical_input_refuse(self):
        raw = serialize_consumer_context(self.context())
        for invalid in (raw + b" ", raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
                        raw.replace(b'"ordinary_calls":177', b'"ordinary_calls":true'), b"[" * 3000 + b"]" * 3000):
            with self.assertRaises(CoordinationError):
                read_consumer_context(io.BytesIO(invalid))
        value = self.context()
        value["pids"]["external_reservation"]["ordinary_calls"] = 4
        with self.assertRaises(CoordinationError):
            serialize_consumer_context(value)
        value = self.context()
        value["boundary"][8] = "0" * 64
        with self.assertRaises(CoordinationError):
            serialize_consumer_context(value)


if __name__ == "__main__":
    unittest.main()
