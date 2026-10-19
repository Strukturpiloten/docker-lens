"""Independent image/create normalization for the fixed outer launch.

No target OCI input is accepted by this module. Image facts come from an exact
digest/config-bound image observation and separately reviewed account records;
process policy precedes creation; owned DB mount sources are bound before start. Missing facts
refuse, never become permissive expectations copied from the inspected OCI.
"""

from dataclasses import dataclass
from functools import wraps
import hashlib
import json
import re

from native_outer_lifecycle import (LaunchExpectation, LifecycleError, MountExpectation, environment_map,
                                    integer, path_parts, require, text)

PODMAN_SOURCE = "8d2b55ddde1bc81f43d018dfc1ac027c06b26a7f"
ACCOUNT_SOURCE = "sha256:ab61771e18c56e68ebcaf76e394a0d2466cda97edcecf14f0a44300777b35859"
SOURCE_RECEIPT = "sha256:cd25532699b9155c9097cd4f17b48d2eba8f465545ae003a927c2892be121f1e"


def closed_normalization(method):
    @wraps(method)
    def call(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except Exception:
            raise LifecycleError() from None
    return call


@dataclass(frozen=True, repr=False)
class AccountRecord:
    image_digest: str
    platform_digest: str
    config_digest: str
    architecture: str
    user_text: str
    uid: int
    gid: int
    additional_gids: tuple
    home: str
    passwd_sha256: str
    group_sha256: str
    canonical_reference: str = ""
    config_semantic_sha256: str = ""
    ordered_layer_diff_ids: tuple = ()
    declared_variant: str = ""


@dataclass(frozen=True, repr=False)
class CreateIntent:
    lane: str
    owner: str
    nonce: str
    image_ref: str
    name: str
    data_volume: str
    network: str
    socket_source: str
    run_directory: str


@dataclass(frozen=True, repr=False)
class IndependentDefaults:
    """Exact source/config/owned-storage facts, not values read from target OCI."""
    source_commit: str
    architecture: str
    image_digest: str
    image_config_digest: str
    platform_digest: str
    config_sha256: str
    standard_mounts: tuple
    volume_source: str
    resource_extras: tuple
    baseline_environment: tuple
    user_mount_options: tuple


def digest(value):
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _document(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 32768)
    def nonfinite(_value):
        require(False)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=nonfinite)
    require(type(value) is dict)
    return value


@closed_normalization
def reviewed_account(account_raw, source_raw, lane, architecture, canonical_reference, platform_digest, config_digest):
    """Select immutable audited facts, refusing new pins/platform/config chains.

    The two documents are candidate-owned historical rule records. Selection
    does not authenticate a running executable, runtime state or mounted rootfs.
    No account file payload, image Env, or private receipt path is consumed.
    """
    accounts, source = _document(account_raw), _document(source_raw)
    require(set(accounts) == {"schema_version", "purpose", "source_receipt_sha256",
                              "podman_identity_rules_commit", "runtime_or_compatibility_qualification", "images"})
    require(type(accounts["schema_version"]) is int and accounts["schema_version"] == 1
            and accounts["purpose"] == "historical_independent_image_account_expectations"
            and accounts["source_receipt_sha256"] == ACCOUNT_SOURCE
            and accounts["podman_identity_rules_commit"] == PODMAN_SOURCE
            and accounts["runtime_or_compatibility_qualification"] is False)
    require(type(source.get("schema_version")) is int and source["schema_version"] == 1
            and source.get("purpose") == "historical_podman493_source_binding"
            and source.get("source_receipt_sha256") == SOURCE_RECEIPT
            and source.get("commit") == PODMAN_SOURCE and source.get("tag") == "v4.9.3"
            and source.get("annotated_tag_object") == "bd1b4a96544e6199f369feef8cb19c2e8f803b1f"
            and source.get("tree") == "917a3fb31ddef8f6835bbc939d0654e805b64acd"
            and source.get("runtime_or_compatibility_qualification") is False)
    require(type(accounts["images"]) is list and len(accounts["images"]) == 8)
    selected, seen = [], set()
    for record in accounts["images"]:
        require(type(record) is dict and set(record) == {
            "lane", "architecture", "canonical_reference", "index_digest", "platform_manifest_digest",
            "config_digest", "image_user", "uid", "gid", "additional_gids", "home", "passwd_sha256",
            "group_sha256", "ordered_layers", "os", "variant", "config_semantic_sha256"})
        require(type(record["lane"]) is str and type(record["architecture"]) is str)
        key = (record["lane"], record["architecture"])
        require(key not in seen)
        seen.add(key)
        if key == (lane, architecture):
            selected.append(record)
    require(len(selected) == 1)
    record = selected[0]
    require(record["canonical_reference"] == canonical_reference
            and record["platform_manifest_digest"] == platform_digest and record["config_digest"] == config_digest)
    require(record["os"] == "linux" and record["variant"] == ("v8" if architecture == "arm64" else ""))
    require(all(digest(record[key]) for key in ("index_digest", "platform_manifest_digest", "config_digest", "passwd_sha256", "group_sha256", "config_semantic_sha256")))
    require(type(canonical_reference) is str and canonical_reference.endswith("@" + record["index_digest"]))
    groups = record["additional_gids"]
    require(integer(record["uid"], 0, 4294967295) and integer(record["gid"], 0, 4294967295)
            and type(groups) is list and len(groups) <= 32
            and all(integer(group, 0, 4294967295) for group in groups) and len(set(groups)) == len(groups))
    require(type(record["image_user"]) is str and "\0" not in record["image_user"] and len(record["image_user"]) <= 256)
    path_parts(record["home"])
    layers = record["ordered_layers"]
    require(type(layers) is list and 1 <= len(layers) <= 64
            and all(type(layer) is dict and set(layer) == {"digest", "diff_id"}
                    and digest(layer["digest"]) and digest(layer["diff_id"]) for layer in layers))
    return AccountRecord(record["index_digest"], platform_digest, config_digest, architecture, record["image_user"],
                         record["uid"], record["gid"], tuple(groups), record["home"],
                         record["passwd_sha256"][7:], record["group_sha256"][7:], canonical_reference,
                         record["config_semantic_sha256"], tuple(layer["diff_id"] for layer in layers), record["variant"])


def original_argv(image_config, lane):
    """Image arrays, not container inspect.Config.Entrypoint's joined string."""
    require(type(image_config) is dict and type(lane) is str)
    entrypoint = image_config.get("Entrypoint")
    require(entrypoint is None or (type(entrypoint) is list and len(entrypoint) <= 16
                                  and all(text(value, 4096) for value in entrypoint)))
    explicit = ["/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock"]
    if lane == "debian11-rootless":
        explicit.append("--storage-driver=vfs")
    # The canonical harness supplies a command, so image Cmd is not inherited.
    return tuple(entrypoint or ()) + tuple(explicit)


@closed_normalization
def derive_launch(intent, image, account, defaults):
    require(type(intent) is CreateIntent and type(account) is AccountRecord and type(defaults) is IndependentDefaults)
    require(type(intent.owner) is str and re.fullmatch(r"[A-Za-z0-9]{8}", intent.owner) is not None)
    require(intent.name == "dl-native-" + intent.owner and intent.data_volume == "dl-native-data-" + intent.owner
            and intent.network == "dl-native-net-" + intent.owner)
    path_parts(intent.run_directory)
    require(intent.lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"))
    require(type(image) is dict and set(image) == {"digest", "config_digest", "platform_digest", "architecture", "config"})
    require(digest(image["digest"]) and digest(image["config_digest"]))
    require(intent.image_ref.endswith("@" + image["digest"]))
    require(account.image_digest == defaults.image_digest == image["digest"])
    require(account.config_digest == defaults.image_config_digest == image["config_digest"])
    require(account.architecture == defaults.architecture == image["architecture"] and account.architecture in ("amd64", "arm64"))
    require(defaults.source_commit == PODMAN_SOURCE and digest(account.platform_digest)
            and account.platform_digest == defaults.platform_digest == image["platform_digest"])
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in
                (account.passwd_sha256, account.group_sha256, defaults.config_sha256)))
    require(integer(account.uid, 0, 4294967295) and integer(account.gid, 0, 4294967295))
    require(type(account.additional_gids) is tuple and len(account.additional_gids) <= 32
            and all(integer(value, 0, 4294967295) for value in account.additional_gids)
            and len(set(account.additional_gids)) == len(account.additional_gids))
    config = image["config"]
    require(type(config) is dict and config.get("User", "") == account.user_text)
    image_environment = config.get("Env")
    require(image_environment is None or type(image_environment) is list)
    environment = environment_map([] if image_environment is None else image_environment)
    baseline = environment_map(defaults.baseline_environment)
    # Explicit CLI env closes ambient config/proxy sources while preserving
    # every image value. HOME follows the independently resolved image user.
    baseline.update(environment)
    if "HOME" not in baseline:
        require(text(account.home))
        baseline["HOME"] = account.home
    cwd = config.get("WorkingDir", "")
    require(type(cwd) is str)
    cwd = cwd or "/"
    if cwd != "/":
        path_parts(cwd)
    require(type(defaults.standard_mounts) is tuple and defaults.standard_mounts)
    require(all(type(mount) is MountExpectation for mount in defaults.standard_mounts))
    path_parts(defaults.volume_source)
    path_parts(intent.socket_source)
    storage = "/home/docker/.local/share/docker" if intent.lane.endswith("rootless") else "/var/lib/docker"
    require(type(defaults.user_mount_options) is tuple and len(defaults.user_mount_options) == 2)
    require(all(type(options) is tuple and all(text(option, 256) for option in options) for options in defaults.user_mount_options))
    mounts = (MountExpectation(storage, "bind", defaults.volume_source, defaults.user_mount_options[0]),
              MountExpectation("/dockerlens-native", "bind", intent.socket_source, defaults.user_mount_options[1]))
    return LaunchExpectation(intent.lane, intent.name, intent.image_ref, image["digest"], intent.owner, intent.nonce,
                             original_argv(config, intent.lane), tuple(name + "=" + value for name, value in sorted(baseline.items())),
                             account.uid, account.gid, account.additional_gids, cwd, defaults.standard_mounts, mounts,
                             "machine.slice", defaults.resource_extras)


def launch_digest(expectation):
    record = (expectation.lane, expectation.name, expectation.image_digest, expectation.owner, expectation.nonce,
              expectation.original_argv, tuple(sorted(environment_map(expectation.environment).items())),
              expectation.uid, expectation.gid, expectation.additional_gids, expectation.cwd,
              tuple((item.destination, item.kind, item.source, item.options) for item in expectation.standard_mounts + expectation.user_mounts),
              expectation.cgroup_parent, expectation.resource_extras)
    return hashlib.sha256(json.dumps(record, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@closed_normalization
def intent_digest(intent, account, candidate):
    """Static policy binding available before native preflight or create."""
    require(type(intent) is CreateIntent and type(account) is AccountRecord)
    require(type(candidate) is str and re.fullmatch(r"[0-9a-f]{40}", candidate) is not None)
    record = {"domain": "dockerlens-outer-intent-v2", "intent": vars(intent),
              "account": vars(account), "candidate": candidate, "podman_source": PODMAN_SOURCE,
              "resources": [512, 4294967296, 8589934592, 100000, 200000],
              "policy": "fixed-closed-env-hooks-mounts-host-userns-two-mounts-v1"}
    return hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                                     allow_nan=False).encode("ascii")).hexdigest()


@closed_normalization
def expectation_digest(expectation, container_id, static_digest):
    """Complete binding is distinct from intent and includes the created ID."""
    require(type(expectation) is LaunchExpectation)
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                for value in (container_id, static_digest)))
    record = ("dockerlens-outer-expectation-v2", static_digest, container_id, launch_digest(expectation))
    return hashlib.sha256(json.dumps(record, separators=(",", ":")).encode("ascii")).hexdigest()


@closed_normalization
def source_defaults(intent, account, database, socket_options):
    """Reviewed 4.9.3 host-userns privileged recipe, never target OCI input.

    Before initialization only sentinel storage paths are used, solely to
    construct the immutable process/create policy. They cannot be bound or
    started; both owners must replace them with owned database facts first.
    """
    from native_outer_broker_protocol import DatabaseReceipt
    require(type(intent) is CreateIntent and type(account) is AccountRecord)
    require(type(socket_options) is tuple and socket_options[:2] == ("rw", "rprivate")
            and socket_options[-1:] == ("rbind",)
            and all(option in ("rw", "rprivate", "rbind", "nosuid", "nodev", "noexec") for option in socket_options)
            and len(set(socket_options)) == len(socket_options))
    if database is None:
        static, run, volume = "/uninitialized/static", "/uninitialized/run", "/uninitialized/volume"
    else:
        require(type(database) is DatabaseReceipt and database.state == "initialized"
                and database.native_image_id == account.config_digest[7:]
                and database.native_image_digest in (account.image_digest, account.platform_digest))
        static, run, volume = database.static_dir, database.hostname_path.rsplit("/", 1)[0], database.owned_volume["mountpoint"]
        require(database.owned_volume == {"name": intent.data_volume, "mountpoint": volume, "owner": intent.owner}
                and database.hostname_path == run + "/hostname" and database.hosts_path == run + "/hosts"
                and database.resolv_conf_path == run + "/resolv.conf")
        for path in (static, run, volume):
            path_parts(path)
    mounts = (
        MountExpectation("/proc", "proc", "proc", ("nosuid", "noexec", "nodev")),
        MountExpectation("/dev", "tmpfs", "tmpfs", ("nosuid", "strictatime", "mode=755", "size=65536k")),
        MountExpectation("/dev/pts", "devpts", "devpts", ("nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5")),
        MountExpectation("/dev/mqueue", "mqueue", "mqueue", ("nosuid", "noexec", "nodev")),
        MountExpectation("/sys", "sysfs", "sysfs", ("rprivate", "nosuid", "noexec", "nodev", "rw")),
        MountExpectation("/sys/fs/cgroup", "cgroup", "cgroup", ("rprivate", "nosuid", "noexec", "nodev", "relatime", "rw")),
        MountExpectation("/dev/shm", "bind", static + "/shm", ("bind", "rprivate", "nosuid", "noexec", "nodev")),
        *(MountExpectation(destination, "bind", run + "/" + name, ("bind", "rprivate")) for destination, name in
          (("/etc/hostname", "hostname"), ("/etc/hosts", "hosts"), ("/etc/resolv.conf", "resolv.conf"), ("/run/.containerenv", ".containerenv"))))
    volume_options = (("suid", "dev", "rw", "rprivate", "rbind") if intent.lane == "debian11-rootless"
                      else ("rw", "rprivate", "nosuid", "nodev", "rbind"))
    return IndependentDefaults(PODMAN_SOURCE, account.architecture, account.image_digest, account.config_digest,
                               account.platform_digest, hashlib.sha256(b"").hexdigest(), mounts, volume,
                               (("memory", (("swap", 8589934592),)),),
                               ("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "container=podman"),
                               (volume_options, socket_options))
