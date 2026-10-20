"""Independent synthetic inputs; never actual image/default qualification."""

from dataclasses import replace
import json
from pathlib import Path
import re
import unittest

from native_outer_lifecycle import LifecycleError, MountExpectation, environment_map
from native_outer_launch import (AccountRecord, CreateIntent, IndependentDefaults, PODMAN_SOURCE,
                                 derive_launch, launch_digest, original_argv)
from native_outer_launch import reviewed_account


class LaunchTests(unittest.TestCase):
    def inputs(self, lane="upstream-rootless"):
        image = {"digest": "sha256:" + "a" * 64, "config_digest": "sha256:" + "b" * 64,
                 "platform_digest": "sha256:" + "d" * 64,
                 "architecture": "amd64", "config": {"Entrypoint": [], "User": "docker", "WorkingDir": "/",
                                                       "Env": ["PATH=/image/bin", "VALUE=image"]}}
        intent = CreateIntent(lane, "AbCd1234", "c" * 64, "example.invalid/image@" + image["digest"],
                              "dl-native-AbCd1234", "dl-native-data-AbCd1234", "dl-native-net-AbCd1234",
                              "/private/run/socket", "/private/run")
        account = AccountRecord(image["digest"], "sha256:" + "d" * 64, image["config_digest"], "amd64",
                                "docker", 1000, 1000, (1000,), "/home/docker", "e" * 64, "f" * 64)
        defaults = IndependentDefaults(PODMAN_SOURCE, "amd64", image["digest"], image["config_digest"], image["platform_digest"], "1" * 64,
                                       (MountExpectation("/proc", "proc", "proc", ("nosuid", "noexec", "nodev")),),
                                       "/owned/volume/data", (), ("PATH=/baseline", "container=podman"),
                                       (("rw", "rbind"), ("rw", "rbind")))
        return intent, image, account, defaults

    def test_explicit_command_image_entrypoint_and_actual_rootless_cwd(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            intent, image, account, defaults = self.inputs(lane)
            launch = derive_launch(intent, image, account, defaults)
            self.assertEqual(launch.cwd, "/")
            self.assertEqual(launch.additional_gids, (1000,))
            self.assertEqual(launch.original_argv[:2], ("/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock"))
            self.assertEqual("--storage-driver=vfs" in launch.original_argv, lane == "debian11-rootless")
            self.assertEqual(environment_map(launch.environment),
                             {"PATH": "/image/bin", "VALUE": "image", "HOME": "/home/docker", "container": "podman"})
        image["config"]["Entrypoint"] = ["entry", "fixed"]
        image["config"]["Cmd"] = ["ignored-image-command"]
        self.assertEqual(original_argv(image["config"], "upstream-rootful")[:2], ("entry", "fixed"))

    def test_environment_semantics_unique_map_not_go_map_order(self):
        intent, image, account, defaults = self.inputs()
        launch = derive_launch(intent, image, account, defaults)
        reordered = replace(launch, environment=tuple(reversed(launch.environment)))
        self.assertEqual(launch_digest(launch), launch_digest(reordered))
        for values in (["A=1", "A=1"], ["NO_EQUALS"], ["A=1", None], ["BAD-NAME=x"]):
            with self.assertRaises(LifecycleError):
                environment_map(values)

    def test_missing_independent_inputs_and_wrong_image_platform_source_refuse(self):
        intent, image, account, defaults = self.inputs()
        for bad_account in (None, replace(account, image_digest="sha256:" + "0" * 64),
                            replace(account, config_digest="sha256:" + "0" * 64),
                            replace(account, platform_digest="sha256:" + "0" * 64),
                            replace(account, architecture="arm64"), replace(account, passwd_sha256=""),
                            replace(account, additional_gids=(1000, 1000))):
            with self.assertRaises(LifecycleError):
                derive_launch(intent, image, bad_account, defaults)
        for bad_defaults in (None, replace(defaults, source_commit="0" * 40),
                             replace(defaults, platform_digest="sha256:" + "0" * 64),
                             replace(defaults, standard_mounts=()), replace(defaults, user_mount_options=((),))):
            with self.assertRaises(LifecycleError):
                derive_launch(intent, image, account, bad_defaults)
        image["config"]["Env"] = False
        with self.assertRaises(LifecycleError):
            derive_launch(intent, image, account, defaults)


class ReviewedAccountTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.accounts = (self.root / "docs/native-image-defaults/20261019-accounts-v1.json").read_bytes()
        self.source = (self.root / "docs/native-image-defaults/podman493-source-binding-v1.json").read_bytes()
        self.records = json.loads(self.accounts)["images"]

    def select(self, record, **changes):
        values = {key: record[key] for key in ("lane", "architecture", "canonical_reference", "config_digest")}
        values["platform_digest"] = record["platform_manifest_digest"]
        values.update(changes)
        return reviewed_account(self.accounts, self.source, **values)

    def test_current_four_canonical_pins_and_eight_digest_chains(self):
        harness = (self.root / "scripts/native-conformance.sh").read_text()
        pins = dict(re.findall(r"^([A-Z_]+_IMAGE)='([^']+)'$", harness, re.MULTILINE))
        pin_by_lane = {"upstream-rootful": pins["UPSTREAM_ROOTFUL_IMAGE"],
                       "upstream-rootless": pins["UPSTREAM_ROOTLESS_IMAGE"],
                       "debian11-rootful": pins["DEBIAN_ROOTFUL_IMAGE"],
                       "debian11-rootless": pins["DEBIAN_ROOTLESS_IMAGE"]}
        self.assertEqual(len(self.records), 8)
        for record in self.records:
            self.assertEqual(record["canonical_reference"], pin_by_lane[record["lane"]])
            account = self.select(record)
            self.assertEqual(account.additional_gids, tuple(record["additional_gids"]))
            self.assertEqual((account.uid, account.gid, account.home), (record["uid"], record["gid"], record["home"]))
            if record["lane"] == "upstream-rootful":
                self.assertEqual(account.additional_gids, (0, 1, 2, 3, 4, 6, 10, 11, 20, 26, 27))

    def test_new_pin_platform_or_config_requires_new_reviewed_record(self):
        record = self.records[0]
        for changes in ({"canonical_reference": "new.invalid/image@sha256:" + "0" * 64},
                        {"platform_digest": "sha256:" + "0" * 64}, {"config_digest": "sha256:" + "0" * 64},
                        {"architecture": "unknown"}, {"lane": "unknown"}):
            with self.assertRaises(LifecycleError):
                self.select(record, **changes)

    def test_source_binding_and_record_identity_are_not_authority_from_inputs(self):
        source = json.loads(self.source)
        source["commit"] = "0" * 40
        self.source = json.dumps(source).encode()
        with self.assertRaises(LifecycleError):
            self.select(self.records[0])
        self.setUp()
        accounts = json.loads(self.accounts)
        accounts["images"][1] = accounts["images"][0]
        self.accounts = json.dumps(accounts).encode()
        with self.assertRaises(LifecycleError):
            self.select(self.records[0])


if __name__ == "__main__":
    unittest.main()
