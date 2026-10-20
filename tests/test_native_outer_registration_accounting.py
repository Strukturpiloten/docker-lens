"""Real diagnostic registration I/O against the original caller reservation."""

import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch

import native_outer_canonical as canonical
import native_outer_coordinator as coordinator


class RegistrationAccountingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dockerlens-registration-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.diagnostics = self.directory / "diagnostics"
        self.diagnostics.mkdir(mode=0o700)
        self.log = self.diagnostics / "daemon.log"
        self.fd = os.open(self.log, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, self.fd)
        self.registration = self.diagnostics / "port-log-registration.json"

    def budget(self, remaining=None, cancelled=lambda: False):
        book, roles = coordinator.prepare_reservations(
            secrets.token_hex(32), time.monotonic_ns() + 10_000_000_000)
        budget = coordinator.ReservedBudget(
            book.claim_before_spawn(roles["caller_lane"]), time.monotonic_ns, cancelled)
        if remaining is not None:
            budget.debit(source_bytes=budget.reservation.allowance.source_bytes - remaining)
        return budget

    def prepare(self, budget):
        canonical.diagnostic_prepare(
            str(self.directory), "AbCd1234", "upstream-rootful", self.fd, budget=budget)

    def test_actual_canonical_preparation_charges_exact_serialized_bytes(self):
        budget = self.budget()
        self.prepare(budget)
        raw = self.registration.read_bytes()
        self.assertEqual(budget.used.source_bytes, len(raw))
        self.assertGreaterEqual(budget.used.io_calls, 12)
        self.assertEqual(budget.reservation.role, "caller_lane")
        record = json.loads(raw)
        self.assertEqual(record["status"], "prepared")
        self.assertEqual(record["logPath"], str(self.log))
        self.assertEqual(record["inode"], os.fstat(self.fd).st_ino)
        self.assertEqual(os.fstat(self.fd).st_size, 0)
        self.assertEqual(self.registration.stat().st_mode & 0o777, 0o600)

    def test_partial_raw_writes_are_charged_once_without_buffered_prefetch(self):
        budget, real_write, sizes = self.budget(), os.write, []

        def partial(descriptor, raw):
            amount = real_write(descriptor, raw[:7])
            sizes.append(amount)
            return amount

        with patch.object(os, "write", partial):
            self.prepare(budget)
        self.assertGreater(len(sizes), 1)
        self.assertTrue(all(0 < size <= 7 for size in sizes))
        self.assertEqual(budget.used.source_bytes, sum(sizes))
        self.assertEqual(sum(sizes), self.registration.stat().st_size)
        self.assertEqual(json.loads(self.registration.read_bytes())["status"], "prepared")

    def test_one_remaining_byte_cannot_publish_a_truncated_registration(self):
        budget = self.budget(remaining=1)
        before = budget.used.source_bytes
        with self.assertRaises(coordinator.CoordinationError):
            self.prepare(budget)
        self.assertTrue(budget.poisoned)
        self.assertEqual(budget.used.source_bytes - before, 1)
        self.assertEqual(self.registration.stat().st_size, 1)
        with self.assertRaises(coordinator.CoordinationError):
            budget.claim_source(1)
        self.assertEqual(os.fstat(self.fd).st_size, 0)

    def test_write_then_raise_retains_full_attempt_and_original_log_descriptor(self):
        budget, real_write, attempted = self.budget(), os.write, []

        def unknown(descriptor, raw):
            attempted.append(len(raw))
            real_write(descriptor, raw[:4])
            raise OSError("authored registration write fault")

        with patch.object(os, "write", unknown), self.assertRaises(OSError):
            self.prepare(budget)
        self.assertEqual(len(attempted), 1)
        self.assertEqual(budget.used.source_bytes, attempted[0])
        self.assertEqual(self.registration.stat().st_size, 4)
        self.assertTrue(budget.poisoned)
        self.assertEqual(os.fstat(self.fd).st_size, 0)
        with self.assertRaises(coordinator.CoordinationError):
            budget.claim_source(1)

    def test_cancelled_original_authority_never_creates_registration(self):
        state = {"cancelled": False}
        budget = self.budget(cancelled=lambda: state["cancelled"])
        state["cancelled"] = True
        with self.assertRaises(coordinator.CoordinationError):
            self.prepare(budget)
        self.assertFalse(self.registration.exists())
        self.assertEqual(budget.used.source_bytes, 0)
        self.assertEqual(os.fstat(self.fd).st_size, 0)


if __name__ == "__main__":
    unittest.main()
