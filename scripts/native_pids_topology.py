"""Pure preparation for typed PIDs discovery; no collector or evidence authority.

Keys are caller-local labels, never descriptors, inodes, paths or process IDs.
A connected supplied tree does not establish completeness of a kernel walk.
"""

from dataclasses import dataclass
from enum import Enum


MAX_NODES = 128
MAX_DEPTH = 12


class TopologyRefusal(ValueError):
    """Closed shape/role refusal, without caller values."""


def _require(condition):
    if not condition:
        raise TopologyRefusal("pids-topology")


class CgroupType(Enum):
    DOMAIN = "domain"
    THREAD_ROOT = "domain threaded"
    THREADED = "threaded"


def parse_type(raw):
    """Decode only exact complete kernel type bytes, including their final LF."""
    _require(type(raw) is bytes)
    for kind in CgroupType:
        if raw == kind.value.encode("ascii") + b"\n":
            return kind
    raise TopologyRefusal("pids-topology")


@dataclass(frozen=True)
class Node:
    key: int
    parent: int | None
    kind: CgroupType


class ProcsRead(Enum):
    LOCAL = "local"
    AGGREGATE = "aggregate"
    NONE = "none"


@dataclass(frozen=True)
class CoverageStep:
    node: int
    owner: int
    procs_read: ProcsRead


def _key(value):
    return type(value) is int and 0 <= value < 2**64


def coverage_plan(nodes, configured_root):
    """Return a deterministic plan for a supplied configured512 subtree shape.

    LOCAL/AGGREGATE steps request procs only at their own owner. NONE must not
    request procs and inherits exactly one enclosing thread root. This assigns
    discovery coverage, never a discovered leader's actual local membership.
    """
    _require(type(nodes) is tuple and 1 <= len(nodes) <= MAX_NODES)
    _require(_key(configured_root))
    by_key = {}
    for node in nodes:
        _require(type(node) is Node and _key(node.key))
        _require(node.parent is None or _key(node.parent))
        _require(type(node.kind) is CgroupType and node.key not in by_key)
        by_key[node.key] = node
    _require(configured_root in by_key)
    root = by_key[configured_root]
    _require(root.parent is None and root.kind in (CgroupType.DOMAIN, CgroupType.THREAD_ROOT))
    children = {key: [] for key in by_key}
    for node in nodes:
        if node.key == configured_root:
            continue
        _require(node.parent in by_key and node.parent != node.key)
        parent = by_key[node.parent]
        if parent.kind is CgroupType.DOMAIN:
            _require(node.kind in (CgroupType.DOMAIN, CgroupType.THREAD_ROOT))
        else:
            _require(node.kind is CgroupType.THREADED)
        children[node.parent].append(node.key)

    visited, result = set(), []

    def walk(key, depth, thread_owner):
        _require(depth <= MAX_DEPTH and key not in visited)
        visited.add(key)
        node = by_key[key]
        if node.kind is CgroupType.DOMAIN:
            _require(thread_owner is None)
            owner, procs_read = key, ProcsRead.LOCAL
        elif node.kind is CgroupType.THREAD_ROOT:
            _require(thread_owner is None)
            thread_owner = owner = key
            procs_read = ProcsRead.AGGREGATE
        else:
            _require(thread_owner is not None)
            owner, procs_read = thread_owner, ProcsRead.NONE
        result.append(CoverageStep(key, owner, procs_read))
        for child in sorted(children[key]):
            walk(child, depth + 1, thread_owner)

    walk(configured_root, 0, None)
    _require(len(visited) == len(nodes))
    return tuple(result)


class Phase(Enum):
    DISCOVERY_LEASE = "discovery_lease"
    BETWEEN_LEASES = "between_leases"
    MEASUREMENTS = "measurements"
    AFTER_SEAL = "after_seal"


def check_transition(previous, current, phase):
    """Check observed same-object type changes only; never rebind or reopen work.

    Allowed changes still require a new complete applicable topology check.
    Identity, observation timing and lease/seal state are caller obligations.
    """
    _require(type(previous) is CgroupType and type(current) is CgroupType and type(phase) is Phase)
    if previous is current:
        return
    _require(phase in (Phase.BETWEEN_LEASES, Phase.AFTER_SEAL))
    _require({previous, current} == {CgroupType.DOMAIN, CgroupType.THREAD_ROOT})


class TypeScope:
    """Internal source observations, never frame-supplied roles or authority.

    current contains only this acquisition epoch's actual observations. Frozen
    measurement chains cannot be seeded by last/bootstrap observations.
    """
    def __init__(self):
        self.phase = "setup"
        self.last, self.current, self.frozen = {}, {}, {}

    def begin_locate(self):
        _require(self.phase == "setup")
        self.phase, self.current = "locating", {}

    def observe(self, identity, kind, parent):
        _require(type(kind) is CgroupType)
        value = kind, parent
        old = self.last.get(identity)
        if old is not None:
            _require(old[1] == parent)
        if self.phase == "measuring" and identity in self.frozen:
            _require(self.frozen[identity] == value)
        elif self.phase == "locating" and identity in self.current:
            # Discovery itself has its own immutable two-pass lease. Between
            # that lease and final role validation, D/R may change only while
            # the source revalidates the complete applicable chain.
            check_transition(self.current[identity][0], kind, Phase.BETWEEN_LEASES)
        elif old is not None:
            check_transition(old[0], kind, Phase.AFTER_SEAL if self.phase == "sealed" else Phase.BETWEEN_LEASES)
        self.last[identity] = self.current[identity] = value
        return kind

    def freeze(self, identities):
        _require(self.phase == "locating" and identities and all(key in self.current for key in identities))
        self.frozen = {key: self.current[key] for key in identities}
        self.phase = "measuring"

    def seal(self):
        _require(self.phase == "measuring")
        self.phase, self.current, self.frozen = "sealed", {}, {}
