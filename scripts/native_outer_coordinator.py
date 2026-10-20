"""Private coordinator resource reservations.

Reservation accounting is pre-fork: a child can spend only its immutable slice,
and an unused/failed child never refunds or renews it. The canonical dispatcher
uses these accounting, private-context and direct-child transport primitives;
their source presence is not a native qualification result.
"""

from dataclasses import dataclass
from contextlib import contextmanager
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from threading import Lock
from types import MappingProxyType

_LOCAL_RESERVATIONS = set()
_LOCAL_RESERVATION_LOCK = Lock()

PRIVATE_CONTEXT_CONTRACT = "outer-private-context-v1"
PRIVATE_CONTEXT_BYTES = 131072
PRIVATE_BOUNDARY_BYTES = 1024
PRIVATE_CONTEXT_KEYS = ("schema_version", "contract", "binding", "source", "boundary", "pids")
PRIVATE_BINDING_KEYS = ("session", "candidate_sha", "execution_origin", "ci_run_id", "ci_run_attempt", "owner", "lane", "outer_id", "intent_digest", "expectation_digest")
PRIVATE_SOURCE_KEYS = ("intent", "preflight", "database", "oci", "log")
PRIVATE_PIDS_KEYS = ("start_ns", "deadline_ns", "deadline_epoch", "producer_reservation", "external_reservation")
PRIVATE_RESERVATION_KEYS = ("ordinary_calls", "ordinary_bytes", "cleanup_calls", "cleanup_bytes")
PIDS_PRODUCER_CLEANUP = (96, 2015159)
# References the SAME once-only original root_recovery reservation (seq8).
# It is not a second PIDs cleanup budget and never renews its time authority.
PIDS_EXTERNAL_CLEANUP = (4, 81993)


def _hex(value, size):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None


def validate_consumer_context(value):
    """Closed transport schema, NOT independent validation of source authority.

    Rust additionally binds the observed original root throughout all 37 reads.
    The mandatory Python consumer independently validates source facts/OCI/log
    and derives this boundary before comparing it with the produced proof.
    """
    require(type(value) is dict and set(value) == set(PRIVATE_CONTEXT_KEYS))
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["contract"] == PRIVATE_CONTEXT_CONTRACT)
    binding, source, pids, boundary = (value[key] for key in ("binding", "source", "pids", "boundary"))
    require(type(binding) is dict and set(binding) == set(PRIVATE_BINDING_KEYS))
    for key in ("session", "outer_id", "intent_digest", "expectation_digest"):
        require(_hex(binding[key], 64))
    require(_hex(binding["candidate_sha"], 40))
    require(binding["execution_origin"] in ("github_actions", "local_process"))
    if binding["execution_origin"] == "github_actions":
        require(all(type(binding[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", binding[key]) is not None
                    for key in ("ci_run_id", "ci_run_attempt")))
    else:
        require(binding["ci_run_id"] is None and binding["ci_run_attempt"] is None)
    require(type(binding["owner"]) is str and re.fullmatch(r"[A-Za-z0-9]{8}", binding["owner"]) is not None)
    require(binding["lane"] in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"))
    require(type(source) is dict and set(source) == set(PRIVATE_SOURCE_KEYS)
            and all(type(record) is dict for record in source.values()))
    require(type(pids) is dict and set(pids) == set(PRIVATE_PIDS_KEYS))
    start, deadline, epoch = (pids[key] for key in ("start_ns", "deadline_ns", "deadline_epoch"))
    require(all(uint(item) and item > 0 for item in (start, deadline, epoch))
            and 46_000_000_000 < deadline - start <= 180_000_000_000)
    for name in ("producer_reservation", "external_reservation"):
        allocation = pids[name]
        require(type(allocation) is dict and set(allocation) == set(PRIVATE_RESERVATION_KEYS)
                and all(uint(item) for item in allocation.values()))
    producer, external = pids["producer_reservation"], pids["external_reservation"]
    require(producer["ordinary_calls"] + external["ordinary_calls"] <= 180
            and producer["ordinary_bytes"] + external["ordinary_bytes"] <= 2097152
            and producer["cleanup_calls"] + external["cleanup_calls"] <= 100
            and producer["cleanup_bytes"] + external["cleanup_bytes"] <= 2097152)
    require(sum(allocation["ordinary_calls"] + allocation["cleanup_calls"] for allocation in (producer, external)) <= 400
            and sum(allocation["ordinary_bytes"] + allocation["cleanup_bytes"] for allocation in (producer, external)) <= 4194304)
    require(type(boundary) is list and len(boundary) == 10 and type(boundary[0]) is int and boundary[0] == 1)
    for position, length in ((1, 3), (2, 3), (3, 3), (4, 2)):
        require(type(boundary[position]) is list and len(boundary[position]) == length
                and all(uint(item) for item in boundary[position]))
    require(1 <= boundary[1][0] <= 4194304 and boundary[1][1] > 0 and boundary[1][2] <= 4294967295)
    require(all(item > 0 for item in boundary[2]) and boundary[3][0] > 0 and boundary[3][1] > 0
            and boundary[3][2] <= 4294967295 and all(item > 0 for item in boundary[4]))
    require(all(_hex(boundary[index], 64) for index in (5, 6, 7, 8))
            and boundary[7] == binding["intent_digest"] and boundary[8] == binding["expectation_digest"])
    image = boundary[9]
    require(type(image) is list and len(image) == 3 and _hex(image[0], 64)
            and type(image[1]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image[1]) is not None
            and type(image[2]) is int and image[2] in (0, 1))
    require(len(json.dumps({"boundary": boundary}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) + 1 <= PRIVATE_BOUNDARY_BYTES)
    return value


def serialize_consumer_context(value):
    validate_consumer_context(value)
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    require(0 < len(raw) <= PRIVATE_CONTEXT_BYTES)
    return raw


def read_consumer_context(stream, *, bootstrap=None):
    """Read one independently supplied private stdin copy, never env/sidecars."""
    try:
        raw = stream.read(PRIVATE_CONTEXT_BYTES + 1) if bootstrap is None else bootstrap.read(stream)
        require(type(raw) is bytes and 0 < len(raw) <= PRIVATE_CONTEXT_BYTES)
        def unique(pairs):
            result = {}
            for key, item in pairs:
                require(key not in result)
                result[key] = item
            return result
        def nonfinite(_item):
            raise CoordinationError()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
        validate_consumer_context(value)
        require(serialize_consumer_context(value) == raw)
        if bootstrap is not None:
            bootstrap._accept(value, raw)
        return value
    except Exception:
        if bootstrap is not None:
            bootstrap.failed = True
        raise CoordinationError() from None


class ConsumerInput:
    """Preclaimed consumer-role stdin, before its session can be decoded.

    The executable, not stdin, selects the role. Its supervising coordinator
    already claimed that fixed slice. This view authorizes only its bounded
    initial copy, then adopts the actual spend into that SAME slice once.
    No source identity or new deadline is invented before strict admission.
    """
    def __init__(self, role):
        require(role in ("reader", "emitter"))
        entries = [entry for entry in ROLE_PLAN if entry[0] == role]
        require(len(entries) == 1)
        self.role, self.allowance = role, entries[0][2]
        self.allowance.validate()
        require(PRIVATE_CONTEXT_BYTES + 1 <= self.allowance.source_bytes)
        self.spent = self.calls = 0
        self.read_attempted = self.adopted = False
        self.failed = self.eof = False
        self.validated_context = self.validated_wire = None

    def read(self, stream):
        require(not self.read_attempted and not self.adopted and not self.failed)
        self.read_attempted = True
        # Bypass BufferedReader prefetch. This is the first stdin source I/O;
        # partial reads do not establish EOF, and lookahead uses the same cap.
        raw_stream = getattr(stream, "raw", stream)
        result = bytearray()
        try:
            while True:
                maximum = min(4096, PRIVATE_CONTEXT_BYTES + 1 - self.spent)
                require(maximum > 0)
                require(self.calls < self.allowance.io_calls)
                self.calls += 1
                try:
                    part = raw_stream.read(maximum)
                except BaseException:
                    self.spent += maximum  # Unknown physical completion.
                    raise
                if type(part) is not bytes or len(part) > maximum:
                    self.spent += maximum  # Invalid result is not EOF/zero.
                    raise CoordinationError()
                self.spent += len(part)
                require(self.spent <= PRIVATE_CONTEXT_BYTES)
                if not part:
                    self.eof = True
                    return bytes(result)
                result.extend(part)
        except BaseException:
            self.failed = True
            raise

    def _accept(self, context, raw):
        require(self.read_attempted and self.eof and not self.failed and self.validated_context is None)
        self.validated_context, self.validated_wire = context, raw

    def adopt(self, context):
        require(self.read_attempted and self.eof and not self.adopted and not self.failed
                and self.validated_context is context and serialize_consumer_context(context) == self.validated_wire)
        self.adopted = True  # An unsuccessful adoption cannot be retried.
        budget = consumer_budget(context, self.role)
        require(budget.reservation.role == self.role and budget.reservation.allowance == self.allowance)
        budget.debit(source_bytes=self.spent, io_calls=self.calls)
        return budget


def read_consumer_input(stream, role):
    bootstrap = ConsumerInput(role)
    context = read_consumer_context(stream, bootstrap=bootstrap)
    return context, bootstrap.adopt(context)


def socket_mount_options(path):
    """Independent statfs-derived options for the one authored bind source."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        flags = os.fstatvfs(descriptor).f_flag
        # Linux MS_NOEXEC/MS_NOSUID/MS_NODEV, as used by the reviewed source.
        return ("rw", "rprivate", *((name for bit, name in ((8, "noexec"), (2, "nosuid"), (4, "nodev"))
                                      if flags & bit)), "rbind")
    finally:
        os.close(descriptor)


def candidate_account(lane, architecture, image_ref, *, directory=None, budget=None):
    """Load bounded candidate-owned independent source records, not context claims."""
    from native_outer_launch import reviewed_account
    directory = Path(__file__).resolve().parent.parent / "docs/native-image-defaults" if directory is None else Path(directory)
    documents = []
    for name in ("20261019-accounts-v1.json", "podman493-source-binding-v1.json", "20261019-paths-v1.json"):
        if budget is not None:
            budget.debit(io_calls=1)
        descriptor = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw = (os.read(descriptor, 32769) if budget is None else
                   bounded_source_io(budget, 32769, lambda maximum: os.read(descriptor, maximum)))
            require(0 < len(raw) <= 32768)
            documents.append(raw)
        finally:
            os.close(descriptor)
    records = json.loads(documents[0])["images"]
    selected = [item for item in records if item["lane"] == lane and item["architecture"] == architecture]
    require(len(selected) == 1)
    selected = selected[0]
    account = reviewed_account(*documents[:2], lane, architecture, image_ref,
                               selected["platform_manifest_digest"], selected["config_digest"])
    paths = json.loads(documents[2])
    require(paths["schema_version"] == 1 and paths["purpose"] == "historical_independent_image_path_expectations"
            and paths["source_receipt_sha256"] == "sha256:a80d8fc77784781e66267a3235746e8a02ddb611e71b4286c2cbca395400ca05"
            and paths["accounts_source_sha256"] == "sha256:ab61771e18c56e68ebcaf76e394a0d2466cda97edcecf14f0a44300777b35859"
            and paths["runtime_or_compatibility_qualification"] is False
            and paths["extracts_or_executes_rootfs"] is False and paths["absence_is_not_runtime_creation_proof"] is True
            and paths["columns"] == ["path", "present", "kind", "uid", "gid", "mode"])
    witnesses = [item for item in paths["images"] if item["lane"] == lane and item["architecture"] == architecture]
    require(len(witnesses) == 1)
    witness = witnesses[0]
    require(witness["canonical_reference"] == image_ref and witness["index_digest"] == account.image_digest
            and witness["platform_manifest_digest"] == account.platform_digest and witness["config_digest"] == account.config_digest
            and witness["no_link_hazards"] is True and type(witness["paths"]) is list)
    seen = set()
    for path in witness["paths"]:
        require(type(path) is list and len(path) == 6 and type(path[0]) is str and path[0].startswith("/")
                and path[0] not in seen and type(path[1]) is bool
                and ((path[1] and path[2] in ("directory", "regular")) or (not path[1] and path[2] == "absent")))
        seen.add(path[0])
    require({"/", "/proc", "/dev", "/dev/pts", "/dev/mqueue", "/sys", "/sys/fs/cgroup", "/dev/shm",
             "/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/run/.containerenv", "/dockerlens-native",
             "/home/docker/.local/share/docker" if lane.endswith("rootless") else "/var/lib/docker"} <= seen)
    return account


def derive_consumer_authority(context, expected_context=None, *, account_loader=candidate_account,
                              socket_options=socket_mount_options, log_reader=None, budget=None):
    """Independently reconstruct process/mount/resources and original boundary.

    The supplied boundary is a claim to compare, never the source of expected
    OCI values. Neither a matching image handle nor metadata alone authenticates
    a pull: the root broker's same-run preflight remains the trusted acquisition.
    """
    from native_outer_bootstrap import parse_bootstrap_log
    from native_outer_broker_protocol import DatabaseReceipt, payload_read
    from native_outer_launch import (CreateIntent, derive_launch, expectation_digest, intent_digest, source_defaults)
    from native_outer_lifecycle import RuntimeProfile, _validate_oci
    from native_outer_runtime import config_semantics, normalize_image
    try:
        validate_consumer_context(context)
        binding, source = context["binding"], context["source"]
        require(set(source["intent"]) == set(CreateIntent.__dataclass_fields__))
        intent = CreateIntent(**source["intent"])
        require(intent.lane == binding["lane"] and intent.owner == binding["owner"])
        if expected_context is not None:
            require(binding["candidate_sha"] == expected_context["candidate_sha"]
                    and binding["owner"] == expected_context["run_id"] and binding["lane"] == expected_context["lane"]
                    and binding["outer_id"] == expected_context["outer"]["id"]
                    and intent.image_ref == expected_context["outer"]["image"]
                    and intent.socket_source == expected_context["outer"]["socket_source"])
        preflight = payload_read("preflight", source["preflight"])
        require(RuntimeProfile(**preflight.runtime_profile)
                == RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2"))
        if account_loader is candidate_account:
            account = account_loader(intent.lane, preflight.architecture, intent.image_ref, budget=budget)
        else:
            account = account_loader(intent.lane, preflight.architecture, intent.image_ref)
        require(intent_digest(intent, account, binding["candidate_sha"]) == binding["intent_digest"])
        semantic = preflight.semantic
        require(config_semantics(semantic["config"], audited_raw=True) == semantic)
        native = {"Id": preflight.native_image_id, "Digest": preflight.native_image_digest,
                  "RepoDigests": list(preflight.native_repo_digests), "Architecture": preflight.architecture,
                  "Os": preflight.os, "User": semantic["config"]["User"],
                  "Config": {key: value for key, value in semantic["config"].items() if value},
                  "RootFS": {"Type": "layers", "Layers": list(preflight.ordered_diff_ids)}}
        image = normalize_image(json.dumps([native], separators=(",", ":")).encode(), account)
        database = payload_read("initialize", source["database"])
        require(type(database) is DatabaseReceipt and database.init_pid == context["boundary"][1][0]
                and (database.native_image_id, database.native_image_digest)
                == (image.native_id, image.native_digest))
        expected = derive_launch(intent, image.launch_image(), account,
                                 source_defaults(intent, account, database, socket_options(intent.socket_source)))
        complete = expectation_digest(expected, binding["outer_id"], binding["intent_digest"])
        require(complete == binding["expectation_digest"])
        oci = payload_read("bind_expectation", source["oci"])
        require(oci.init_pid == database.init_pid and hashlib.sha256(oci.raw).hexdigest() == oci.sha256)
        _validate_oci(oci.raw, expected, binding["outer_id"])
        log = source["log"]
        require(set(log) == {"object", "prefix"} and type(log["object"]) is list and len(log["object"]) == 5)
        prefix = base64.b64decode(log["prefix"], validate=True)
        require(0 < len(prefix) <= 2048)
        if log_reader is None:
            if budget is not None:
                budget.debit(io_calls=3)
            descriptor = os.open(intent.run_directory + "/diagnostics/daemon.log", os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                require([info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink] == log["object"]
                        and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                        and info.st_uid == os.geteuid() and info.st_nlink == 1)
                observed = (os.read(descriptor, len(prefix)) if budget is None else
                            bounded_source_io(budget, len(prefix), lambda maximum: os.read(descriptor, maximum)))
                require(observed == prefix)
            finally:
                os.close(descriptor)
        else:
            require(log_reader(intent, log, prefix) is True)
        frame = parse_bootstrap_log(prefix, intent.nonce)
        require(frame["uid"] == expected.uid)
        boundary = [1, [database.init_pid, frame["start"], frame["uid"]], frame["namespaces"],
                    [frame["mount"][0], frame["mount"][1], int(frame["mount"][2][2:])], frame["controller"][:2],
                    oci.sha256, hashlib.sha256(prefix).hexdigest(), binding["intent_digest"], complete,
                    [image.native_id, image.native_digest, 0 if image.native_digest_kind == "index" else 1]]
        require(boundary == context["boundary"])
        return boundary
    except Exception:
        raise CoordinationError() from None


class CoordinationError(ValueError):
    def __init__(self):
        super().__init__("outer coordinator refused")


def require(condition):
    if not condition:
        raise CoordinationError()


def uint(value):
    return type(value) is int and 0 <= value <= (1 << 64) - 1


@dataclass(frozen=True, repr=False)
class Allowance:
    native_calls: int
    source_bytes: int
    io_calls: int

    def validate(self):
        require(all(uint(value) for value in (self.native_calls, self.source_bytes, self.io_calls)))


@dataclass(frozen=True, repr=False)
class Reservation:
    session: str
    sequence: int
    role: str
    scope: str
    allowance: Allowance
    deadline_ns: int


class ReservationBook:
    """One coordinator-owned book for independently supplied existing envelopes.

    No wire operation may create a scope, request credits or alter an envelope.
    Reservations are debited before any child starts, including failed starts.
    The caller must derive these finite envelopes from the existing harness;
    this generic accounting class does not grant a native allowance itself.
    """
    def __init__(self, session, envelopes, deadlines_ns):
        require(type(session) is str and re.fullmatch(r"[0-9a-f]{64}", session) is not None)
        require(type(envelopes) is dict and type(deadlines_ns) is dict and set(envelopes) == set(deadlines_ns))
        require(1 <= len(envelopes) <= 8)
        for scope, allowance in envelopes.items():
            require(type(scope) is str and re.fullmatch(r"[a-z_]{1,32}", scope) is not None and type(allowance) is Allowance)
            allowance.validate()
            require(uint(deadlines_ns[scope]) and deadlines_ns[scope] > 0)
        self.session, self.envelopes, self.deadlines_ns = session, MappingProxyType(dict(envelopes)), MappingProxyType(dict(deadlines_ns))
        self._used = {scope: Allowance(0, 0, 0) for scope in envelopes}
        self.used = MappingProxyType(self._used)
        self._reservations, self._claimed, self._roles = {}, set(), set()
        self.reservations = MappingProxyType(self._reservations)
        self.lock = Lock()

    def reserve(self, role, scope, allowance):
        require(type(role) is str and re.fullmatch(r"[a-z_]{1,32}", role) is not None)
        require(type(allowance) is Allowance)
        allowance.validate()
        with self.lock:
            require(scope in self.envelopes and (scope, role) not in self._roles)
            used, cap = self.used[scope], self.envelopes[scope]
            total = Allowance(used.native_calls + allowance.native_calls,
                              used.source_bytes + allowance.source_bytes, used.io_calls + allowance.io_calls)
            require(total.native_calls <= cap.native_calls and total.source_bytes <= cap.source_bytes and total.io_calls <= cap.io_calls)
            reservation = Reservation(self.session, len(self.reservations) + 1, role, scope, allowance, self.deadlines_ns[scope])
            self._used[scope] = total
            self._roles.add((scope, role))
            self._reservations[reservation.sequence] = reservation
            return reservation

    def claim_before_spawn(self, reservation):
        with self.lock:
            require(type(reservation) is Reservation and reservation.session == self.session
                    and self.reservations.get(reservation.sequence) is reservation and reservation.sequence not in self._claimed)
            self._claimed.add(reservation.sequence)
            return reservation


class SourceClaim:
    """An in-flight maximum, bound to one original role, not spent credit.

    Only the unread part is released. Completed bytes remain spent even when
    the operation, cancellation check or subsequent decoding fails.
    """
    def __init__(self, owner, limit):
        self.owner, self.limit, self.closed = owner, limit, False

    def __enter__(self):
        return self

    def consume(self, size):
        self.owner._settle_source(self, size)

    def fail(self):
        self.owner._settle_source(self, self.limit, check=False, fault=True)

    def __exit__(self, *_exception):
        if not self.closed:
            self.owner._settle_source(self, 0, check=False)


def bounded_source_io(budget, maximum, operation):
    """Authorize a bounded read/write before I/O against its existing role.

    A shortened maximum is not evidence of EOF. If it is filled, refuse after
    recording the bytes, rather than expose a possibly complete-looking prefix.
    The operation receives the authorized maximum and returns bytes or a write
    count. Its unread claim capacity is never a refund of spent bytes.
    """
    with budget.claim_source(maximum) as claim:
        budget.debit(io_calls=1)
        try:
            result = operation(claim.limit)
        except BaseException:
            # A callback may have completed physical I/O before raising. Its
            # actual amount is unknown: permanently charge the full authorized
            # maximum, poison only this original role, and never retry it.
            claim.fail()
            raise
        size = len(result) if type(result) is bytes else result
        claim.consume(size)
        budget.check()
        if claim.limit < maximum and size == claim.limit:
            claim.owner.poisoned = True
            raise CoordinationError()
        return result


class ReservedBudget:
    """A child's already-debited slice; no reference to the coordinator book.

    Reads/writes/polls are I/O calls, not native-command calls. Wire transfer,
    context copies and source reads all debit source_bytes when used by the
    actual dispatch, in addition to bounded native stdout/stderr. No reset API.
    """
    def __init__(self, reservation, clock_ns, cancelled):
        require(type(reservation) is Reservation and type(reservation.allowance) is Allowance)
        reservation.allowance.validate()
        require(type(reservation.session) is str and re.fullmatch(r"[0-9a-f]{64}", reservation.session) is not None
                and uint(reservation.sequence) and reservation.sequence > 0)
        require(all(type(value) is str and re.fullmatch(r"[a-z_]{1,32}", value) is not None
                    for value in (reservation.role, reservation.scope)))
        require(uint(reservation.deadline_ns) and reservation.deadline_ns > 0)
        key = (reservation.session, reservation.sequence, reservation.role, reservation.scope)
        with _LOCAL_RESERVATION_LOCK:
            require(key not in _LOCAL_RESERVATIONS and len(_LOCAL_RESERVATIONS) < 16384)
            _LOCAL_RESERVATIONS.add(key)
        self.reservation, self.clock_ns, self.cancelled = reservation, clock_ns, cancelled
        self.used = Allowance(0, 0, 0)
        self.last = 0
        self.poisoned = False
        self.lock = Lock()
        self._source_claims = set()
        self._source_reserved = 0
        self.check()

    def check(self):
        try:
            require(not self.poisoned)
            now = self.clock_ns()
            require(uint(now) and self.last <= now < self.reservation.deadline_ns and self.cancelled() is False)
            self.last = now
            return self.reservation.deadline_ns - now
        except BaseException:
            self.poisoned = True
            raise CoordinationError() from None

    def debit(self, native_calls=0, source_bytes=0, io_calls=0):
        with self.lock:
            try:
                self.check()
                require(all(uint(value) for value in (native_calls, source_bytes, io_calls)))
                used, cap = self.used, self.reservation.allowance
                total = Allowance(used.native_calls + native_calls, used.source_bytes + source_bytes, used.io_calls + io_calls)
                require(total.native_calls <= cap.native_calls and total.source_bytes + self._source_reserved <= cap.source_bytes
                        and total.io_calls <= cap.io_calls)
                self.used = total
            except BaseException:
                self.poisoned = True
                raise CoordinationError() from None

    def claim_source(self, maximum):
        with self.lock:
            try:
                self.check()
                require(uint(maximum) and maximum > 0)
                remaining = self.reservation.allowance.source_bytes - self.used.source_bytes - self._source_reserved
                require(remaining > 0)
                claim = SourceClaim(self, min(maximum, remaining))
                self._source_reserved += claim.limit
                self._source_claims.add(claim)
                return claim
            except BaseException:
                self.poisoned = True
                raise CoordinationError() from None

    def _settle_source(self, claim, size, *, check=True, fault=False):
        with self.lock:
            try:
                require(claim in self._source_claims and claim.owner is self and not claim.closed)
                invalid = not uint(size) or size > claim.limit
                charged = claim.limit if invalid or fault else size
                self._source_claims.remove(claim)
                self._source_reserved -= claim.limit
                claim.closed = True
                # Record physical bytes before checking cancellation/time. A
                # fault after successful I/O must not erase their accounting.
                self.used = Allowance(self.used.native_calls, self.used.source_bytes + charged, self.used.io_calls)
                if invalid or fault:
                    self.poisoned = True
                    require(not invalid)
                if check:
                    self.check()
            except BaseException:
                self.poisoned = True
                raise CoordinationError() from None


class ScopeBudget:
    """Once-only PIDs switch between two already-prepaid, disjoint slices."""
    def __init__(self, lane, pids):
        self.lane, self.pids, self.active = lane, pids, lane
        self.started = self.ended = False
        self.timing = None

    def begin(self, timing):
        self.check()
        require(not self.started and not self.ended and not self.active._source_claims)
        self.started, self.timing, self.active = True, timing, self.pids
        self.check()

    def end(self):
        self.check()
        require(self.started and not self.ended and not self.active._source_claims)
        self.ended, self.active = True, self.lane

    def check(self):
        remaining = self.active.check()
        if self.started and not self.ended:
            remaining = min(remaining, self.timing.deadline_ns - self.active.clock_ns())
            require(remaining > 0)
        return remaining

    def debit(self, native_calls=0, source_bytes=0, io_calls=0):
        self.check()
        self.active.debit(native_calls=native_calls, source_bytes=source_bytes, io_calls=io_calls)

    def claim_source(self, maximum):
        self.check()
        return self.active.claim_source(maximum)


PHASE_BYTES = 8192
PHASE_IO_CALLS = 64
PHASE_MESSAGES = 8


def phase_write(descriptor, value, *, budget=None, stats=None):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    require(0 < len(raw) <= PHASE_BYTES)
    data = struct.pack(">I", len(raw)) + raw
    if budget is not None:
        # Coordinator reply plus relay forwarding: the SAME caller reservation
        # prepays both whole copies before any possibly partial write. No child
        # gets a fresh budget and failed/unused bytes are never refunded.
        budget.debit(source_bytes=2 * len(data), io_calls=3 * PHASE_IO_CALLS)
    calls = 0
    while data:
        calls += 1
        require(calls <= PHASE_IO_CALLS)
        if budget is not None:
            budget.debit(io_calls=1)
        count = os.write(descriptor, data)
        require(count > 0)
        if stats is not None:
            stats["written"] = stats.get("written", 0) + count
        data = data[count:]


def phase_read(descriptor, *, deadline_ns=None, alive=lambda: True, budget=None, stats=None):
    if budget is not None:
        # The relay has already consumed a complete proxy request before it
        # forwards it. Prepay BOTH bounded copies, even if this receiver sees
        # only a partial frame/EOF; observed-byte-only debit would undercount
        # the upstream completed copy on cancellation. No reset/refund.
        budget.debit(source_bytes=2 * (PHASE_BYTES + 4), io_calls=3 * PHASE_IO_CALLS)
    calls = 0
    def read(size):
        nonlocal calls
        data = bytearray()
        while len(data) < size:
            if deadline_ns is not None:
                require(alive() and time.monotonic_ns() < deadline_ns)
                with selectors.DefaultSelector() as selector:
                    selector.register(descriptor, selectors.EVENT_READ)
                    if budget is not None:
                        budget.debit(io_calls=1)
                    if not selector.select(min(0.5, (deadline_ns - time.monotonic_ns()) / 1e9)):
                        continue
            calls += 1
            require(calls <= PHASE_IO_CALLS)
            if budget is not None:
                budget.debit(io_calls=1)
            part = os.read(descriptor, size - len(data))
            require(bool(part))
            if stats is not None:
                stats["read"] = stats.get("read", 0) + len(part)
            data.extend(part)
        return bytes(data)
    size = struct.unpack(">I", read(4))[0]
    require(0 < size <= PHASE_BYTES)
    raw = read(size)
    value = json.loads(raw)
    require(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") == raw)
    return value


def phase_proxy(arguments):
    require(1 <= len(arguments) <= 22 and arguments[0] in ("setup", "producer", "reader", "emitter", "final", "teardown"))
    require(all(type(item) is str and "\0" not in item and len(item) <= 4096 for item in arguments))
    phase_write(1, arguments)
    require(phase_read(0) == {"ok": True})


def phase_relay(upstream_read, upstream_write):
    """Dedicated shell coprocess; only this relay retains shell-upstream FDs."""
    require(upstream_read != upstream_write and min(upstream_read, upstream_write) > 2)
    for descriptor in (upstream_read, upstream_write):
        require(stat.S_ISFIFO(os.fstat(descriptor).st_mode))
        os.set_inheritable(descriptor, False)
    try:
        for _message in range(PHASE_MESSAGES):
            request = phase_read(0)
            phase_write(upstream_write, request)
            reply = phase_read(upstream_read)
            require(reply == {"ok": True})
            phase_write(1, reply)
        require(False)
    finally:
        os.close(upstream_read)
        os.close(upstream_write)


def run_private_role(argv, environment, context_raw, budget, deadline_ns, *, spawn=subprocess.Popen):
    """Direct child with bounded anonymous stdin and no inherited control FDs."""
    require(type(argv) is tuple and type(context_raw) is bytes and len(context_raw) <= PRIVATE_CONTEXT_BYTES)
    process, streams = None, {}
    try:
        process = spawn(argv, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        close_fds=True, start_new_session=True)
        require(all(stream is not None for stream in (process.stdin, process.stdout, process.stderr)))
        streams = {process.stdin: "input", process.stdout: "output", process.stderr: "error"}
        offset, captured = 0, {"output": 0, "error": 0}
        with selectors.DefaultSelector() as selector:
            for stream, purpose in streams.items():
                os.set_blocking(stream.fileno(), False)
                if purpose != "input" or context_raw:
                    selector.register(stream, selectors.EVENT_WRITE if purpose == "input" else selectors.EVENT_READ)
                else:
                    stream.close()
            while selector.get_map():
                budget.check()
                remaining = (deadline_ns - time.monotonic_ns()) / 1e9
                require(remaining > 0)
                budget.debit(io_calls=1)
                for key, _event in selector.select(min(remaining, 0.05)):
                    purpose = streams[key.fileobj]
                    if purpose == "input":
                        count = bounded_source_io(budget, min(4096, len(context_raw) - offset),
                                                  lambda maximum: os.write(key.fd, context_raw[offset:offset + maximum]))
                        require(count > 0)
                        offset += count
                        if offset == len(context_raw):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        part = bounded_source_io(budget, min(4096, 16385 - captured[purpose]),
                                                 lambda maximum: os.read(key.fd, maximum))
                        captured[purpose] += len(part)
                        require(captured[purpose] <= 16384)
                        if not part:
                            selector.unregister(key.fileobj)
            require(offset == len(context_raw))
            require(process.wait(timeout=max(0.001, (deadline_ns - time.monotonic_ns()) / 1e9)) == 0)
    except BaseException:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise CoordinationError() from None
    finally:
        for stream in streams:
            stream.close()


# One shared original outer envelope, not one fresh pool per process. These
# provisional static reservations are not native-fit qualification. No role can
# grow its slice, borrow from a sibling, or renew its once-only admission.
ROLE_PLAN = (
    ("root_lane", "outer", Allowance(16, 288000, 30000)),
    ("caller_lane", "outer", Allowance(0, 290000, 20000)),
    ("emitter", "outer", Allowance(0, 470576, 20000)),
    ("root_pids", "pids", Allowance(3, 450000, 12000)),
    ("caller_pids", "pids", Allowance(0, 379576, 12000)),
    ("reader", "pids", Allowance(0, 219000, 12000)),
    ("producer", "pids", Allowance(177, 1048576, 0)),
    ("root_recovery", "recovery", Allowance(4, 81993, 12000)),
)


def prepare_reservations(session, lane_deadline_ns):
    book = ReservationBook(session,
                           {"outer": Allowance(16, 1048576, 70000),
                            "pids": Allowance(180, 2097152, 36000),
                            "recovery": Allowance(4, 81993, 12000)},
                           {name: lane_deadline_ns for name in ("outer", "pids", "recovery")})
    reservations = {role: book.reserve(role, scope, allowance) for role, scope, allowance in ROLE_PLAN}
    return book, reservations


def fixed_reservation(session, role, deadline_ns):
    for sequence, (name, scope, allowance) in enumerate(ROLE_PLAN, 1):
        if name == role:
            return Reservation(session, sequence, role, scope, allowance, deadline_ns)
    require(False)


def consumer_budget(context, role):
    require(role in ("reader", "emitter"))
    require(context["pids"]["start_ns"] <= time.monotonic_ns())
    # The coordinator claims this fixed disjoint slice before spawning. The
    # emitter gets only its later original-lane slice, never renewed PIDs credit.
    deadline = context["pids"]["deadline_ns"] if role == "reader" else int(os.environ["DOCKERLENS_OUTER_LANE_DEADLINE_NS"])
    return ReservedBudget(fixed_reservation(context["binding"]["session"], role, deadline), time.monotonic_ns, lambda: False)


@contextmanager
def metered_source_reads(budget):
    """Single-threaded fixed consumer scope; charge actual bounded OS reads.

    Existing proof readers retain their own no-follow/cap/custody checks. This
    does not alter native-command accounting or install a new resource pool.
    """
    names = ("open", "close", "stat", "lstat", "fstat", "readlink", "fstatvfs", "lseek", "mkdir")
    originals = {name: getattr(os, name) for name in names}
    original, original_fdopen = os.read, os.fdopen
    def read(descriptor, size):
        return bounded_source_io(budget, size, lambda maximum: original(descriptor, maximum))
    def operation(method):
        def call(*arguments, **keywords):
            budget.debit(io_calls=1)
            return method(*arguments, **keywords)
        return call
    class SourceFile:
        def __init__(self, file):
            self.file = file
        def fileno(self):
            return self.file.fileno()
        def read(self, size):
            require(type(size) is int and 0 <= size <= 524289)
            return bounded_source_io(budget, size, self.file.read)
        def seek(self, *arguments):
            budget.debit(io_calls=1)
            return self.file.seek(*arguments)
        def close(self):
            try:
                budget.debit(io_calls=1)
            finally:
                self.file.close()
        def __enter__(self):
            return self
        def __exit__(self, *_arguments):
            self.close()
    def fdopen(descriptor, mode="r", *arguments, **keywords):
        require(mode == "rb" and not arguments and not keywords)
        # Raw binary input prevents BufferedReader from silently prefetching
        # and discarding bytes beyond a returned overflow-detection cap.
        return SourceFile(original_fdopen(descriptor, mode, buffering=0))
    for name, method in originals.items():
        setattr(os, name, operation(method))
    os.read = read
    os.fdopen = fdopen
    try:
        yield
    finally:
        os.read = original
        os.fdopen = original_fdopen
        for name, method in originals.items():
            setattr(os, name, method)
