"""Typed discovery lease for the fixed runtime source; never a source-provider IPC API.

Only a fixed trusted in-process caller may supply Source and the matching
callback. The callback must be pure on supplied facts: no extra source I/O,
process acquisition, commands or descriptor retention. Counter/ownership
checkpoints detect persistent drift, not malicious change-and-return behavior.

The caller retains actual outer selection/checks and SO_PEERPIDFD/inspect role
authority. Provisional records are locators. Actual Source.process acquisition
and namespace custody remain necessary. Groups/controller acquisition must run
only AFTER this lease closes successfully. Returned witnesses have one central
owner; records must never close them separately. A failed/uncertain close is a
ROOT abort, never a successful transfer or permission to retry a closed number.

Authored transcript controls prove only their measured fitting envelopes, not native behavior.
128 graph FDs plus six selected ownership SETS (each normally 7 Process FDs and
up to 15 namespace-parent FDs), graph witnesses and the original 16 fixed slots
can exceed 256. Existing Budget must refuse before I/O; no allowance is raised.
Complete final-source review and fresh proof-v2 native qualification remain required.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import re

import importlib.util
from pathlib import Path
import sys


def _sibling(name):
    path = Path(__file__).with_name(name + ".py").resolve()
    module = sys.modules.get(name)
    if module is not None:
        if getattr(module, "__file__", None) is None or Path(module.__file__).resolve() != path:
            raise ValueError("pids-import")
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


locator = _sibling("native_pids_locator")
topology = _sibling("native_pids_topology")


boundary = locator.boundary
require = boundary.require


class Mode(Enum):
    PEER = "peer"
    WORKERS = "workers"


class Role(Enum):
    PEER = "peer"
    CLI16 = "cli16"
    CLI64 = "cli64"
    CLI_UNLIMITED = "cli_unlimited"
    RENDERED16 = "rendered16"
    RENDERED64 = "rendered64"
    RENDERED_UNLIMITED = "rendered_unlimited"


@dataclass(frozen=True)
class Provisional:
    pid: int
    start: int
    directory_identity: tuple
    membership: tuple
    local: int
    coverage: int


@dataclass(frozen=True)
class Candidate:
    process: boundary.Process
    status: tuple
    namespace_chain: tuple
    provisional: Provisional


@dataclass(frozen=True)
class Witness:
    directory: int
    identity: tuple
    membership: tuple
    borrowed: bool


@dataclass(frozen=True)
class Selection:
    role: Role
    candidate: Candidate
    local_witness: Witness
    coverage_witness: Witness


@dataclass(frozen=True)
class TypeObservation:
    identity: tuple
    parent: tuple | None
    kind: topology.CgroupType


class _Cleanup:
    def __init__(self, source, baseline):
        self.source, self.baseline, self.first = source, frozenset(baseline), None

    def close_fd(self, fd):
        try:
            self.source.close_fd(fd)
        except BaseException as error:
            self.first = self.first if self.first is not None else error
            raise self.first

    def release(self, previous):
        # release_since attempts its snapshot after OSError, then refuses.
        # Non-OSError may interrupt that loop; attempt still-owned scopes once.
        try:
            self.source.release_since(previous)
        except BaseException as error:
            self.first = self.first if self.first is not None else error
            try:
                self.source.release_since(self.baseline)
            except BaseException as later:
                raise self.first from later
            raise self.first
        if self.first is not None:
            raise self.first


class DiscoveryTransfer:
    """Sole explicit owner of selected scopes and unique non-borrowed witnesses.

    Source.owned remains the original descriptor custody ledger; this object
    has the exclusive right to retire only its captured scopes. Fixed caller
    ordering must retire it before generic Source cleanup, never both owners.
    Selected processes/time/namespace scopes must remain live through later
    Groups and measurements until the original owner's seal/cleanup. Graph
    witnesses may be released separately only after dependent Groups hold the
    required object witnesses. Later caller FDs are preserved. A close attempt retires this owner
    before I/O; any remaining uncertain ownership requires ROOT abort/Source
    teardown, not another close attempt on this object.
    """
    def __init__(self, source, selections, witnesses, process_owned, witness_owned, types):
        self.selections, self.witnesses = selections, witnesses
        self.types = types
        self._source, self._closed = source, False
        self._process_owned, self._witness_owned = frozenset(process_owned), frozenset(witness_owned)

    def release_witnesses(self):
        require(not self._closed)
        owned, self._witness_owned = self._witness_owned, frozenset()
        try:
            require(owned <= self._source.owned)
            preserve = self._source.owned - owned
            _Cleanup(self._source, preserve).release(preserve)
        except BaseException:
            self._closed = True
            raise

    def close(self):
        require(not self._closed)
        self._closed = True
        owned = self._process_owned | self._witness_owned
        self._process_owned = self._witness_owned = frozenset()
        require(owned <= self._source.owned)
        preserve = self._source.owned - owned
        _Cleanup(self._source, preserve).release(preserve)

    def handoff(self):
        """Retire closing rights into the ORIGINAL Source, without closing FDs.

        No caller FD set or new owner is accepted. The fixed locator must first
        bind actual Groups/processes and release every graph witness.
        """
        require(not self._closed and not self._witness_owned
                and self._process_owned <= self._source.owned)
        self._closed = True
        self._process_owned = frozenset()

    def abort(self):
        """Retire an untransferred scope; a failed earlier close is not retried."""
        if not self._closed:
            self.close()


@dataclass(frozen=True)
class _Node:
    directory: int
    parent: int | None
    membership: tuple
    identity: tuple
    entries: tuple
    kind: topology.CgroupType
    pids: tuple


def _state(source):
    budget = source.budget
    return (frozenset(source.owned), budget.reads, budget.bytes, budget.fds,
            budget.opens, budget.output, budget.frames)


class _Lease:
    def __init__(self, source, mode, candidates, cleanup):
        self.source, self.mode, self.candidates, self.cleanup = source, mode, candidates, cleanup
        self._active, self._chosen = None, None
        self._retired = False
        self._seen, self._selected = set(), {}
        self._expected = _state(source)

    @contextmanager
    def acquire(self, record):
        require(not self._retired and self._active is None and _state(self.source) == self._expected)
        require(any(record is candidate for candidate in self.candidates) and record.pid not in self._seen)
        self._seen.add(record.pid)
        previous = frozenset(self.source.owned)
        retained = False
        try:
            process = self.source.process(record.pid, record.start)
            require(type(process) is boundary.Process
                    and process.pid == record.pid and process.start == record.start
                    and boundary.identity(process.directory) == record.directory_identity
                    and process.identity[0] == record.directory_identity
                    and process.membership == record.membership)
            status, vector = locator.status_vectors(self.source.read(process.directory, "status", 4096), record.pid)
            require(status == process.status)
            chain = self.source.namespace_chain(process.namespaces[0], vector)
            # Capture the complete virtual Source.process + namespace_chain delta,
            # including LocatorSource.process_times and every retained parent FD.
            scope = frozenset(self.source.owned - previous)
            require(process.directory in scope)
            candidate = Candidate(process, status, chain, record)
            self._active, self._chosen = candidate, None
            before_callback = _state(self.source)
            yield candidate
            require(not self._retired and _state(self.source) == before_callback)
            if self._chosen is not None:
                self._selected[self._chosen] = (candidate, scope)
                retained = True
        finally:
            self._active, self._chosen = None, None
            if not retained and not self._retired:
                self.cleanup.release(previous)
            self._expected = _state(self.source)

    def select(self, role, candidate):
        roles = (Role.PEER,) if self.mode is Mode.PEER else tuple(role for role in Role if role is not Role.PEER)
        require(not self._retired and self._active is not None
                and type(role) is Role and role in roles and role not in self._selected
                and self._chosen is None and candidate is self._active)
        self._chosen = role

    def finish(self):
        require(not self._retired and self._active is None and _state(self.source) == self._expected)
        roles = (Role.PEER,) if self.mode is Mode.PEER else tuple(role for role in Role if role is not Role.PEER)
        require(set(self._selected) == set(roles))
        # LocateBatch must inspect every leader to reject ambiguous matches.
        # Peer binding acquires only its independently authenticated peer PID.
        if self.mode is Mode.WORKERS:
            require(self._seen == {record.pid for record in self.candidates})
        self._retired = True
        return tuple((role, *self._selected[role]) for role in roles)


def discover(source, outer, mode, consume):
    """Run one bounded lease; matching callback receives only this local lease.

    No caller path/PID/FD list, source-provider selection or serialized authority
    is accepted. Source/outer/callback are fixed trusted integration objects.
    Outer authenticity/current/limit and final ROOT acceptance remain caller
    duties. Work/cleanup failures never return a partially populated transfer.
    """
    require(type(mode) is Mode and callable(consume))
    baseline = frozenset(source.owned)
    cleanup = _Cleanup(source, baseline)
    lease = None
    root = outer.directories[-1]
    nodes, identities = [], set()

    def metadata(fd):
        require(boundary.fs_magic(fd) == boundary.CGROUP_MAGIC)
        return boundary.identity(fd), source.fd_mount_id(fd)

    def read_cgroup(fd, name, cap):
        file = source.open(name, fd)
        try:
            require(boundary.fs_magic(file) == boundary.CGROUP_MAGIC)
            return source.read_fd(file, cap)
        finally:
            cleanup.close_fd(file)

    def typed_procs(fd, parent=None, initial=False):
        kind = topology.parse_type(read_cgroup(fd, "cgroup.type", 32))
        if initial:
            topology.coverage_plan(tuple(topology.Node(index, node.parent, node.kind)
                                         for index, node in enumerate(nodes))
                                   + (topology.Node(len(nodes), parent, kind),), 0)
        pids = ()
        if kind is not topology.CgroupType.THREADED:
            body = read_cgroup(fd, "cgroup.procs", 5632)
            require(not body or re.fullmatch(rb"(?:[1-9][0-9]{0,9}\n)+", body) is not None)
            values = tuple(int(pid) for pid in body.splitlines())
            require(len(values) == len(set(values)) and all(pid < 2**31 for pid in values))
            pids = tuple(sorted(values))
            require(topology.parse_type(read_cgroup(fd, "cgroup.type", 32)) is kind)
        return kind, pids

    def entries(fd):
        result = source.entries(fd)
        require(type(result) is tuple and len(result) <= 4096)
        for name, kind in result:
            require(type(name) is str and name and name.isascii() and "/" not in name
                    and "\0" not in name and name not in (".", "..") and kind in (4, 8))
        require(len({name for name, _kind in result}) == len(result))
        return tuple(sorted(result))

    def walk(fd, parent, membership, depth):
        require(depth <= topology.MAX_DEPTH and len(nodes) < topology.MAX_NODES)
        identity, mount = metadata(fd)
        require(identity[0] == root_identity[0] and mount == root_mount and identity not in identities)
        identities.add(identity)
        listing = entries(fd)
        kind, pids = typed_procs(fd, parent, initial=True)
        index = len(nodes)
        nodes.append(_Node(fd, parent, membership, identity, listing, kind, pids))
        for name, entry_kind in listing:
            if entry_kind == 4:
                require(depth < topology.MAX_DEPTH and len(nodes) < topology.MAX_NODES)
                walk(source.open(name, fd, directory=True), index, membership + (name,), depth + 1)

    def provisional(pid, coverage):
        previous = frozenset(source.owned)
        try:
            directory = source.open(str(pid), source.proc, directory=True)
            require(boundary.fs_magic(directory) == boundary.PROC_MAGIC)
            identity = boundary.identity(directory)
            start = boundary.start_from_stat(source.read(directory, "stat", 1024), pid)
            membership = boundary.cgroup_path(source.read(directory, "cgroup", 1024))
            require(boundary.start_from_stat(source.read(directory, "stat", 1024), pid) == start)
            require(membership in by_membership)
            local = by_membership[membership]
            require(plan[local].owner == coverage)
            return Provisional(pid, start, identity, membership, local, coverage)
        finally:
            cleanup.release(previous)

    try:
        require(root in baseline and source.proc in baseline)
        require(boundary.fs_magic(source.proc) == boundary.PROC_MAGIC)
        proc_identity = boundary.identity(source.proc)
        root_identity, root_mount = metadata(root)
        walk(root, None, outer.membership, 0)
        plan = {step.node: step for step in topology.coverage_plan(
            tuple(topology.Node(index, node.parent, node.kind) for index, node in enumerate(nodes)), 0)}
        by_membership = {node.membership: index for index, node in enumerate(nodes)}
        leaders = {}
        for index, node in enumerate(nodes):
            for pid in node.pids:
                require(pid not in leaders and len(leaders) < 512)
                leaders[pid] = index
        records = tuple(provisional(pid, leaders[pid]) for pid in sorted(leaders))
        require(len({record.directory_identity for record in records}) == len(records))
        lease = _Lease(source, mode, records, cleanup)
        consume(lease)
        selected = lease.finish()
        # Pass B: complete held graph, named objects, coverage and local records.
        require(boundary.fs_magic(source.proc) == boundary.PROC_MAGIC
                and boundary.identity(source.proc) == proc_identity)
        for node in nodes:
            require(metadata(node.directory) == (node.identity, root_mount)
                    and entries(node.directory) == node.entries
                    and typed_procs(node.directory) == (node.kind, node.pids))
            if node.parent is not None:
                reopened = source.open(node.membership[-1], nodes[node.parent].directory, directory=True)
                try:
                    require(metadata(reopened) == (node.identity, root_mount))
                finally:
                    cleanup.close_fd(reopened)
        require(tuple(provisional(record.pid, record.coverage) for record in records) == records)
        for _role, candidate, _scope in selected:
            source.check_process(candidate.process)
            require(boundary.identity(candidate.process.directory) == candidate.provisional.directory_identity
                    and candidate.process.membership == candidate.provisional.membership)
        require(boundary.fs_magic(source.proc) == boundary.PROC_MAGIC
                and boundary.identity(source.proc) == proc_identity
                and metadata(root) == (root_identity, root_mount))
        witness_indices = sorted({index for _role, candidate, _scope in selected
                                 for index in (candidate.provisional.local, candidate.provisional.coverage)})
        witnesses = {index: Witness(nodes[index].directory, nodes[index].identity, nodes[index].membership,
                                    nodes[index].directory in baseline) for index in witness_indices}
        selections = tuple(Selection(role, candidate, witnesses[candidate.provisional.local],
                                     witnesses[candidate.provisional.coverage])
                           for role, candidate, _scope in selected)
        process_owned = set().union(*(scope for _role, _candidate, scope in selected))
        witness_owned = {witness.directory for witness in witnesses.values() if not witness.borrowed}
    except BaseException:
        if lease is not None:
            # A malformed trusted caller may abandon an acquisition context.
            # Retire it before ROOT cleanup so delayed generator finalization
            # cannot close later Source scopes from a stale ownership snapshot.
            lease._retired = True
        cleanup.release(baseline)
        raise
    types = tuple(TypeObservation((*node.identity, root_mount),
                                 (*nodes[node.parent].identity, root_mount) if node.parent is not None else None,
                                 node.kind) for node in nodes)
    cleanup.release(baseline | process_owned | witness_owned)
    return DiscoveryTransfer(source, selections, tuple(witnesses.values()), process_owned, witness_owned, types)
