"""Pure, test-private explicit Docker expectations; never original authority.

Inputs are independent caller assertions, not observations extracted from OCI.
No function opens a source, authenticates provenance, or permits a native action.
"""

from dataclasses import dataclass
from enum import Enum
import json
import re

ERROR = "invalid private Docker source expectation"
SOURCE_LIMIT = 65536
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")


class Match(Enum):
    ExpectationMatchOriginalAuthorityUnverified = "expectation_match_original_authority_unverified"

    @property
    def capability_admission(self):
        return ()

    @property
    def catalogue_admission(self):
        return False


@dataclass(frozen=True, repr=False)
class DockerSourceBasis:
    kind: str
    revision: str
    record_digest: str


@dataclass(frozen=True, repr=False)
class DockerLaunchIntent:
    session: str
    candidate: str
    run: str
    lane: str
    outer_id: str
    owner: str
    network: str
    volume: str
    image_pin: str
    image_id: str
    image_platform: str
    image_config_digest: str
    hostname: str
    argv: tuple
    env: tuple
    cwd: str
    storage_destination: str
    socket_destination: str
    pids: int
    memory: int
    cpu_quota: int
    cpu_period: int
    log_driver: str
    log_max_size: str
    log_max_file: str
    basis: DockerSourceBasis


@dataclass(frozen=True, repr=False)
class DockerImageFacts:
    pin: str
    image_id: str
    platform: str
    config_digest: str
    basis: DockerSourceBasis


@dataclass(frozen=True, repr=False)
class DockerAccountFacts:
    uid: int
    gid: int
    groups: tuple
    basis: DockerSourceBasis


@dataclass(frozen=True, repr=False)
class DockerMount:
    destination: str
    kind: str
    source: str
    options: tuple


@dataclass(frozen=True, repr=False)
class DockerMountFacts:
    entries: tuple
    basis: DockerSourceBasis


@dataclass(frozen=True, repr=False)
class DockerPolicyFacts:
    layout: str
    oci_version: str
    root_path: str
    root_readonly: bool
    namespaces: tuple
    cgroups_path: str
    annotations: tuple
    apparmor_profile: str | None
    basis: DockerSourceBasis


@dataclass(frozen=True, repr=False)
class DockerLaunchProjection:
    intent: DockerLaunchIntent
    image: DockerImageFacts
    account: DockerAccountFacts
    mounts: DockerMountFacts
    policy: DockerPolicyFacts


@dataclass(frozen=True, repr=False)
class DockerSourceOwnerFacts:
    session: str
    candidate: str
    run: str
    lane: str
    outer_id: str
    image_id: str
    source_digest: str
    pid: int
    start_ticks: int
    uid: int
    namespaces: tuple
    source_file: tuple
    source_ancestors: tuple
    original_root: tuple
    pids_controller: tuple
    log_file: tuple


def fail():
    raise ValueError(ERROR) from None


def require_docker_provider(outer_backend):
    if type(outer_backend) is not str or outer_backend != "docker":
        fail()
    return Match.ExpectationMatchOriginalAuthorityUnverified


def _text(value, maximum=4096):
    if type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > maximum:
        fail()
    return value


def _integer(value, minimum=0, maximum=2**64 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        fail()
    return value


def _tuple(value, maximum=128):
    if type(value) is not tuple or len(value) > maximum:
        fail()
    return value


def _path(value):
    _text(value)
    if value != "/" and (not value.startswith("/") or any(p in ("", ".", "..") for p in value[1:].split("/"))):
        fail()
    return value


def _digest(value):
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        fail()


def _basis(value):
    if (type(value) is not DockerSourceBasis or type(value.kind) is not str
            or value.kind != "independent-explicit-docker-source-v1"):
        fail()
    _text(value.revision, 128)
    _digest(value.record_digest)


def _context(value):
    for name in ("session", "candidate", "run", "lane", "outer_id"):
        _text(getattr(value, name), 128)
    if re.fullmatch(r"[0-9a-f]{40}", value.candidate) is None or value.lane not in LANES:
        fail()
    if re.fullmatch(r"[0-9a-f]{64}", value.outer_id) is None:
        fail()


def _projection(expected):
    if type(expected) is not DockerLaunchProjection:
        fail()
    intent, image, account, mounts, policy = (expected.intent, expected.image, expected.account, expected.mounts, expected.policy)
    for value, cls in ((intent, DockerLaunchIntent), (image, DockerImageFacts), (account, DockerAccountFacts),
                       (mounts, DockerMountFacts), (policy, DockerPolicyFacts)):
        if type(value) is not cls:
            fail()
        _basis(value.basis)
    _context(intent)
    for name in ("owner", "network", "volume", "hostname", "image_id", "image_platform", "image_config_digest",
                 "log_driver", "log_max_size", "log_max_file"):
        _text(getattr(intent, name), 128)
    _text(intent.image_pin, 512)
    _text(image.pin, 512)
    if re.fullmatch(r"[^\s@]+:[^\s:@/]+@sha256:[0-9a-f]{64}", image.pin) is None:
        fail()
    _digest(image.image_id)
    _digest(image.config_digest)
    if type(image.platform) is not str or re.fullmatch(r"linux/[a-z0-9_]+(?:/[a-z0-9_]+)?", image.platform) is None:
        fail()
    if (intent.owner != intent.run or intent.image_pin != image.pin or intent.image_id != image.image_id
            or intent.image_platform != image.platform or intent.image_config_digest != image.config_digest):
        fail()
    if not _tuple(intent.argv, 64):
        fail()
    for item in intent.argv:
        _text(item)
    environment = set()
    for item in _tuple(intent.env):
        _text(item)
        key, separator, _ = item.partition("=")
        if not separator or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None or key in environment:
            fail()
        environment.add(key)
    _path(intent.cwd)
    _path(intent.storage_destination)
    _path(intent.socket_destination)
    if intent.storage_destination == intent.socket_destination:
        fail()
    for value, required in ((intent.pids, 512), (intent.memory, 4294967296),
                            (intent.cpu_quota, 200000), (intent.cpu_period, 100000)):
        if _integer(value) != required:
            fail()
    if (intent.log_driver, intent.log_max_size, intent.log_max_file) != ("json-file", "1m", "1"):
        fail()
    for value in (account.uid, account.gid):
        _integer(value, maximum=2**32 - 1)
    for value in _tuple(account.groups, 64):
        _integer(value, maximum=2**32 - 1)
    if len(set(account.groups)) != len(account.groups):
        fail()
    projected_mounts = []
    destinations = set()
    for mount in _tuple(mounts.entries, 32):
        if type(mount) is not DockerMount:
            fail()
        _path(mount.destination)
        _text(mount.kind, 32)
        _text(mount.source)
        if mount.kind == "bind":
            _path(mount.source)
        if mount.destination in destinations:
            fail()
        destinations.add(mount.destination)
        for option in _tuple(mount.options, 32):
            _text(option, 128)
            if option in ("U", ":U"):
                fail()
        if len(set(mount.options)) != len(mount.options):
            fail()
        projected_mounts.append({"destination": mount.destination, "type": mount.kind,
                                 "source": mount.source, "options": list(mount.options)})
    for destination in (intent.storage_destination, intent.socket_destination):
        if not any(m.destination == destination and m.kind == "bind" for m in mounts.entries):
            fail()
    if (_text(policy.layout, 64) != "explicit-linux-oci-projection-v1"
            or type(policy.root_readonly) is not bool):
        fail()
    _text(policy.oci_version, 32)
    _path(policy.root_path)
    _text(policy.cgroups_path)
    namespaces = []
    kinds = set()
    for namespace in _tuple(policy.namespaces, 7):
        if type(namespace) is not tuple or len(namespace) != 2:
            fail()
        kind, path = namespace
        _text(kind, 32)
        if kind not in ("pid", "mount", "cgroup", "ipc", "uts", "network", "user") or kind in kinds:
            fail()
        kinds.add(kind)
        namespaces.append({"type": kind} if path is None else {"type": kind, "path": _path(path)})
    if not {"pid", "mount", "cgroup"}.issubset(kinds):
        fail()
    annotations = {}
    for pair in _tuple(policy.annotations, 64):
        if type(pair) is not tuple or len(pair) != 2:
            fail()
        key, value = pair
        _text(key, 256)
        _text(value)
        if key in annotations:
            fail()
        annotations[key] = value
    process = {"args": list(intent.argv), "env": list(intent.env), "cwd": intent.cwd,
               "user": {"uid": account.uid, "gid": account.gid, "additionalGids": list(account.groups)}}
    if policy.apparmor_profile is not None:
        process["apparmorProfile"] = _text(policy.apparmor_profile, 256)
    projection = {"ociVersion": policy.oci_version, "hostname": intent.hostname,
                  "root": {"path": policy.root_path, "readonly": policy.root_readonly},
                  "process": process, "mounts": projected_mounts, "annotations": annotations,
                  "linux": {"namespaces": namespaces, "cgroupsPath": policy.cgroups_path,
                            "resources": {"pids": {"limit": intent.pids}, "memory": {"limit": intent.memory},
                                          "cpu": {"quota": intent.cpu_quota, "period": intent.cpu_period}}}}
    _tree(projection)
    if len(json.dumps(projection, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > SOURCE_LIMIT:
        fail()
    return projection


def prepare_docker_launch_projection(*, outer_backend, intent, image, account, mounts, policy):
    """Check explicit caller records, not Docker merge/default or source authority."""
    require_docker_provider(outer_backend)
    expected = DockerLaunchProjection(intent, image, account, mounts, policy)
    try:
        _projection(expected)
        return expected
    except (ValueError, TypeError, AttributeError, UnicodeError):
        fail()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def _tree(value, depth=0, count=None):
    if count is None:
        count = [0]
    count[0] += 1
    if depth > 16 or count[0] > 4096:
        fail()
    if type(value) is dict:
        if len(value) > 128:
            fail()
        for key, child in value.items():
            _text(key, 256)
            _tree(child, depth + 1, count)
    elif type(value) is list:
        if len(value) > 128:
            fail()
        for child in value:
            _tree(child, depth + 1, count)
    elif type(value) is str:
        _text(value) if value else None
    elif type(value) is int:
        _integer(value, -2**63, 2**64 - 1)
    elif value is not None and type(value) is not bool:
        fail()


def _exact(actual, expected):
    if type(actual) is not type(expected):
        fail()
    if type(expected) is dict:
        if actual.keys() != expected.keys():
            fail()
        for key in expected:
            _exact(actual[key], expected[key])
    elif type(expected) is list:
        if len(actual) != len(expected):
            fail()
        for left, right in zip(actual, expected):
            _exact(left, right)
    elif actual != expected:
        fail()


def validate_docker_explicit_projection(raw_oci_bytes, *, outer_backend, expected):
    """Match only the documented explicit projection; source authority stays unknown."""
    require_docker_provider(outer_backend)
    try:
        wanted = _projection(expected)
        if type(raw_oci_bytes) is not bytes or not 0 < len(raw_oci_bytes) <= SOURCE_LIMIT:
            fail()
        actual = json.loads(raw_oci_bytes.decode("utf-8"), object_pairs_hook=_pairs,
                            parse_constant=lambda _: fail(), parse_float=lambda _: fail())
        _tree(actual)
        if type(actual) is not dict or actual.keys() != wanted.keys():
            fail()
        # These named security/default members are outside this projection, not validated.
        # Hooks and unknown members are not accepted. Never call this full OCI validation.
        unchecked_process = {"terminal", "noNewPrivileges", "capabilities", "rlimits", "selinuxLabel", "oomScoreAdj"}
        unchecked_linux = {"devices", "seccomp", "maskedPaths", "readonlyPaths", "rootfsPropagation",
                           "uidMappings", "gidMappings", "mountLabel", "sysctl"}
        for section, unchecked in (("process", unchecked_process), ("linux", unchecked_linux)):
            if type(actual[section]) is not dict or set(actual[section]) - set(wanted[section]) - unchecked:
                fail()
            actual[section] = {key: value for key, value in actual[section].items() if key not in unchecked}
        _exact(actual, wanted)
        return Match.ExpectationMatchOriginalAuthorityUnverified
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        fail()


def _owner_projection(facts):
    if type(facts) is not DockerSourceOwnerFacts:
        fail()
    _context(facts)
    _digest(facts.image_id)
    _digest(facts.source_digest)
    _integer(facts.pid, 1, 2**31 - 1)
    _integer(facts.start_ticks, 1)
    _integer(facts.uid, maximum=2**32 - 1)
    for value, size in ((facts.namespaces, 3), (facts.source_file, 5), (facts.original_root, 3),
                        (facts.pids_controller, 2), (facts.log_file, 5)):
        if len(_tuple(value, size)) != size:
            fail()
        for number in value:
            _integer(number)
    if (not all(facts.namespaces) or not facts.source_file[1] or not 0 < facts.source_file[2] <= SOURCE_LIMIT
            or not facts.original_root[0] or not facts.original_root[2]
            or not facts.pids_controller[1] or not facts.log_file[1]):
        fail()
    if not _tuple(facts.source_ancestors, 8):
        fail()
    for ancestor in facts.source_ancestors:
        if len(_tuple(ancestor, 2)) != 2:
            fail()
        _integer(ancestor[0])
        _integer(ancestor[1], 1)
    return {"session": facts.session, "candidate": facts.candidate, "run": facts.run, "lane": facts.lane,
            "outer_id": facts.outer_id, "image_id": facts.image_id, "source_digest": facts.source_digest,
            "pid": facts.pid, "start_ticks": facts.start_ticks, "uid": facts.uid,
            "namespaces": list(facts.namespaces), "source_file": list(facts.source_file),
            "source_ancestors": [list(item) for item in facts.source_ancestors],
            "original_root": list(facts.original_root), "pids_controller": list(facts.pids_controller),
            "log_file": list(facts.log_file)}


def validate_source_claim_binding(claim, *, outer_backend, expected_owner_facts):
    """Check separate assertions for agreement; tuples are not retained live custody."""
    require_docker_provider(outer_backend)
    try:
        wanted = _owner_projection(expected_owner_facts)
        _tree(claim)
        _exact(claim, wanted)
        return Match.ExpectationMatchOriginalAuthorityUnverified
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError):
        fail()
