"""Authored anonymous-context source controls; no native or image acquisition."""

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

import native_outer_coordinator as coordinator
from native_outer_broker_protocol import DatabaseReceipt, OCIReceipt, PreflightReceipt, payload_wire
from native_outer_launch import CreateIntent, derive_launch, expectation_digest, intent_digest, source_defaults
from native_outer_lifecycle import RuntimeProfile
from native_outer_runtime import config_semantic_sha256, config_semantics
from test_native_outer_launch import LaunchTests
from test_native_outer_lifecycle import NONCE, literal_frame, oci_fixture
from test_native_pids_limit_v2_proof import fixture as proof_fixture
import native_pids_limit_v2_proof as reader


def bind_proof_boundary(proof, boundary):
    proof["boundary"] = deepcopy(boundary)
    proof["observer"].update(zip(("pid_namespace", "mount_namespace", "cgroup_namespace"), boundary[2]))
    if proof["observer"]["daemon_depth"] == 1:
        proof["observer"]["daemon_pid_namespace"] = boundary[2][0]
    for case in proof["cases"]:
        for key in ("pids_mapping", "memory_mapping"):
            mapping = case[key]
            leaf = mapping["path"].rsplit("/", 1)[1]
            mapping.update(device=boundary[4][0], mount_id=boundary[3][0], root="/", mountpoint="/sys/fs/cgroup",
                           outer_membership="/", outer_path="/sys/fs/cgroup", membership="/" + leaf,
                           path="/sys/fs/cgroup/" + leaf)
    return proof


def authority_fixture(lane="upstream-rootless", directory=None, expected_context=None, *, reviewed=False, architecture="amd64"):
    proof = proof_fixture(lane)
    if expected_context is not None:
        proof["context"] = deepcopy(expected_context)
    expected_context = proof["context"]
    root = expected_context["outer"]
    if directory is not None:
        root["socket_source"] = str(directory) + "/socket"
    owner, image_ref = expected_context["run_id"], root["image"]
    _, _, account, _ = LaunchTests().inputs(lane)
    config = {"User": "docker", "Env": ["PATH=/image/bin", "VALUE=image"], "WorkingDir": "/"}
    if reviewed:
        from native_outer_public_config_facts import PUBLIC_CONFIG
        account = coordinator.candidate_account(lane, architecture, image_ref)
        config = deepcopy(PUBLIC_CONFIG[lane])
        assert config_semantic_sha256(config, audited_raw=True) == account.config_semantic_sha256
    else:
        account = replace(account, image_digest=image_ref.rsplit("@", 1)[1], canonical_reference=image_ref,
                          config_semantic_sha256=config_semantic_sha256(config), ordered_layer_diff_ids=("sha256:" + "8" * 64,))
    intent = CreateIntent(lane, owner, NONCE, image_ref, root["name"], root["data_volume"],
                          "dl-native-net-" + owner, root["socket_source"], root["socket_source"].rsplit("/", 1)[0])
    preflight = PreflightReceipt(vars(RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2")),
                                 account.config_digest[7:], account.platform_digest,
                                 (image_ref.rsplit(":", 1)[0].split("@", 1)[0] + "@" + account.image_digest,),
                                 "linux", account.architecture, account.ordered_layer_diff_ids, config_semantics(config, audited_raw=True))
    # Readable tag is stripped only before @, not the sha256 separator.
    repository = image_ref.split("@", 1)[0].rsplit(":", 1)[0]
    preflight = replace(preflight, native_repo_digests=(repository + "@" + account.image_digest,))
    database = DatabaseReceipt(2345, account.config_digest[7:], account.platform_digest, "/owned/static",
                               "/owned/run/hostname", "/owned/run/hosts", "/owned/run/resolv.conf",
                               {"name": intent.data_volume, "mountpoint": "/owned/volume/data", "owner": owner})
    options = ("rw", "rprivate", "nosuid", "nodev", "rbind")
    if reviewed and directory is not None:
        Path(intent.socket_source).mkdir(mode=0o777, exist_ok=True)
        options = coordinator.socket_mount_options(intent.socket_source)
    image = {"digest": account.image_digest, "platform_digest": account.platform_digest,
             "config_digest": account.config_digest, "architecture": account.architecture, "config": config}
    launch = derive_launch(intent, image, account, source_defaults(intent, account, database, options))
    native = oci_fixture(launch)
    native["linux"]["cgroupsPath"] = "machine.slice:libpod:" + root["id"]
    native["linux"]["resources"]["memory"]["swap"] = 8589934592
    native["process"]["user"]["additionalGids"] = list(account.additional_gids)
    raw = json.dumps(native, separators=(",", ":")).encode()
    sha256 = hashlib.sha256(raw).hexdigest()
    oci = OCIReceipt(raw, 11, 12, 0, 0o100600, 1, len(raw), sha256, 2345)
    prefix = literal_frame(account.uid)
    log_object = [20, 21, 1000, 0o100600, 1]
    if reviewed and directory is not None:
        diagnostics = Path(directory) / "diagnostics"
        diagnostics.mkdir(mode=0o700, exist_ok=True)
        target = diagnostics / "daemon.log"
        target.write_bytes(prefix)
        target.chmod(0o600)
        info = target.stat()
        log_object = [info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink]
    static = intent_digest(intent, account, expected_context["candidate_sha"])
    complete = expectation_digest(launch, root["id"], static)
    now = time.monotonic_ns()
    context = {"schema_version": 1, "contract": "outer-private-context-v1",
               "binding": {"session": "1" * 64, "candidate_sha": expected_context["candidate_sha"],
                           "execution_origin": "github_actions",
                           "ci_run_id": "123", "ci_run_attempt": "1", "owner": owner, "lane": lane,
                           "outer_id": root["id"], "intent_digest": static, "expectation_digest": complete},
               "source": {"intent": vars(intent), "preflight": payload_wire("preflight", preflight),
                          "database": payload_wire("initialize", database), "oci": payload_wire("bind_expectation", oci),
                          "log": {"object": log_object, "prefix": base64.b64encode(prefix).decode()}},
               "boundary": [1, [2345, 123456, account.uid], [4026533001, 4026533002, 4026533003], [101, 99, 28], [28, 2],
                            sha256, hashlib.sha256(prefix).hexdigest(), static, complete,
                            [account.config_digest[7:], account.platform_digest, 1]],
               "pids": {"start_ns": now, "deadline_ns": now + 180_000_000_000, "deadline_epoch": int(time.time()) + 180,
                        "producer_reservation": {"ordinary_calls": 177, "ordinary_bytes": 1048576,
                                                 "cleanup_calls": 96, "cleanup_bytes": 2015159},
                        "external_reservation": {"ordinary_calls": 3, "ordinary_bytes": 1048576,
                                                 "cleanup_calls": 4, "cleanup_bytes": 81993}}}
    bind_proof_boundary(proof, context["boundary"])
    return context, expected_context, account, options, prefix, proof


class IndependentAuthorityTests(unittest.TestCase):
    def derive(self, context, expected, account, options, prefix):
        return coordinator.derive_consumer_authority(context, expected,
                    account_loader=lambda lane, architecture, reference: account,
                    socket_options=lambda path: options,
                    log_reader=lambda intent, log, observed: observed == prefix)

    def test_full_source_reconstruction_and_original_boundary(self):
        context, expected, account, options, prefix, _proof = authority_fixture()
        self.assertEqual(self.derive(context, expected, account, options, prefix),
                         [1, [2345, 123456, 1000], [4026533001, 4026533002, 4026533003], [101, 99, 28], [28, 2],
                          *context["boundary"][5:]])
        # Explicit source-rule expectations, not an OCI-to-expectation copy.
        defaults = source_defaults(CreateIntent(**context["source"]["intent"]), account,
                                   DatabaseReceipt(**context["source"]["database"]), options)
        self.assertEqual(defaults.user_mount_options[0], ("rw", "rprivate", "nosuid", "nodev", "rbind"))
        self.assertEqual(defaults.resource_extras, (("memory", (("swap", 8589934592),)),))

    def test_supplied_boundary_and_self_consistent_target_env_are_not_authority(self):
        context, expected, account, options, prefix, _proof = authority_fixture()
        for position, changed in ((1, [2345, 123457, 1000]), (2, [4026533001, 4026533002, 4026533004]),
                                  (4, [28, 3])):
            edited = deepcopy(context)
            edited["boundary"][position] = changed
            with self.assertRaises(coordinator.CoordinationError):
                self.derive(edited, expected, account, options, prefix)
        edited = deepcopy(context)
        target = json.loads(base64.b64decode(edited["source"]["oci"]["raw"]))
        target["process"]["env"].append("INJECTED=private-canary")
        raw = json.dumps(target, separators=(",", ":")).encode()
        edited["source"]["oci"].update(raw=base64.b64encode(raw).decode(), size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        edited["boundary"][5] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(coordinator.CoordinationError):
            self.derive(edited, expected, account, options, prefix)

    def test_native_digest_kind_owned_paths_and_initial_root_are_not_aliases(self):
        context, expected, account, options, prefix, _proof = authority_fixture()
        edits = [("preflight", "native_image_digest", account.image_digest),
                 ("database", "hosts_path", "/foreign/run/hosts"),
                 ("preflight", "architecture", "arm64")]
        for record, key, changed in edits:
            edited = deepcopy(context)
            edited["source"][record][key] = changed
            with self.assertRaises(coordinator.CoordinationError):
                self.derive(edited, expected, account, options, prefix)
        edited = deepcopy(context)
        edited["source"]["log"]["prefix"] = base64.b64encode(prefix.replace(b'0::/', b'0::/init.scope')).decode()
        with self.assertRaises(coordinator.CoordinationError):
            self.derive(edited, expected, account, options, prefix)

    def test_boundary_proof_requires_all_37_observations_in_original_namespaces(self):
        context, expected, account, options, prefix, proof = authority_fixture()
        proof["boundary"] = context["boundary"]
        proof["observer"].update(zip(("pid_namespace", "mount_namespace", "cgroup_namespace"), context["boundary"][2]))
        proof["observer"]["daemon_pid_namespace"] = context["boundary"][2][0]
        original = coordinator.derive_consumer_authority
        def authority(value, expected_value, budget=None):
            return original(value, expected_value, account_loader=lambda *_args: account,
                            socket_options=lambda _path: options, log_reader=lambda *_args: True)
        with patch.object(coordinator, "derive_consumer_authority", side_effect=authority):
            self.assertEqual(reader.validate_pids_limit_v2_proof(proof, expected, context)["contract"], "pids-limit-v2")
            for index in range(37):
                edited = deepcopy(proof)
                edited["coordinates"][index][4] = 1
                with self.assertRaises(ValueError):
                    reader.validate_pids_limit_v2_proof(edited, expected, context)
            edited = deepcopy(proof)
            edited["observer"]["pid_namespace"] += 1
            with self.assertRaises(ValueError):
                reader.validate_pids_limit_v2_proof(edited, expected, context)
