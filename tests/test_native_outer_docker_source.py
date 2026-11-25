"""Independent synthetic Docker expectations; these tests grant no live authority."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import io
import contextlib
import json
from pathlib import Path
import sys
from types import CodeType
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import native_outer_docker_source as source

SECRET = "PRIVATE_DOCKER_SOURCE_CANARY"

# Deliberately literal: this is not serialized from the expectation builder.
# All paths/profile/version here are synthetic assertions, not Docker defaults.
OCI = b'''{
  "ociVersion":"1.1.0",
  "hostname":"synthetic-outer",
  "root":{"path":"/synthetic/owned/rootfs","readonly":false},
  "process":{
    "args":["/synthetic/gated-bootstrap","--token","PRIVATE_DOCKER_SOURCE_CANARY"],
    "env":["EXPLICIT_ONE=first","EXPLICIT_EMPTY="],
    "cwd":"/synthetic/work",
    "user":{"uid":1200,"gid":1300,"additionalGids":[1400,1500]},
    "apparmorProfile":"synthetic-explicit-profile"
  },
  "mounts":[
    {"destination":"/synthetic/data","type":"bind","source":"/synthetic/owned/data","options":["rbind","rw","rprivate"]},
    {"destination":"/synthetic/socket","type":"bind","source":"/synthetic/owned/socket","options":["rbind","rw","rprivate"]}
  ],
  "annotations":{"test.explicit-owner":"unit-run"},
  "linux":{
    "namespaces":[{"type":"pid"},{"type":"mount"},{"type":"cgroup"}],
    "cgroupsPath":"synthetic-explicit-cgroup-not-a-runtime-path",
    "resources":{"pids":{"limit":512},"memory":{"limit":4294967296},"cpu":{"quota":200000,"period":100000}}
  }
}'''


def inputs(lane="upstream-rootless"):
    # Source-record declarations are independently authored synthetic inputs.
    basis = source.DockerSourceBasis("independent-explicit-docker-source-v1", "synthetic-docker-recipe-1",
                                     "sha256:" + "a" * 64)
    intent = source.DockerLaunchIntent(
        session="unit-session", candidate="b" * 40, run="unit-run", lane=lane, outer_id="c" * 64,
        owner="unit-run", network="unit-network", volume="unit-volume",
        image_pin="example.invalid/synthetic:unit@sha256:" + "d" * 64,
        image_id="sha256:" + "e" * 64, image_platform="linux/amd64", image_config_digest="sha256:" + "f" * 64,
        hostname="synthetic-outer", argv=("/synthetic/gated-bootstrap", "--token", SECRET),
        env=("EXPLICIT_ONE=first", "EXPLICIT_EMPTY="), cwd="/synthetic/work",
        storage_destination="/synthetic/data", socket_destination="/synthetic/socket",
        pids=512, memory=4294967296, cpu_quota=200000, cpu_period=100000,
        log_driver="json-file", log_max_size="1m", log_max_file="1", basis=basis)
    image = source.DockerImageFacts("example.invalid/synthetic:unit@sha256:" + "d" * 64,
                                    "sha256:" + "e" * 64, "linux/amd64", "sha256:" + "f" * 64, basis)
    account = source.DockerAccountFacts(1200, 1300, (1400, 1500), basis)
    mounts = source.DockerMountFacts((
        source.DockerMount("/synthetic/data", "bind", "/synthetic/owned/data", ("rbind", "rw", "rprivate")),
        source.DockerMount("/synthetic/socket", "bind", "/synthetic/owned/socket", ("rbind", "rw", "rprivate"))), basis)
    policy = source.DockerPolicyFacts("explicit-linux-oci-projection-v1", "1.1.0", "/synthetic/owned/rootfs", False,
                                      (("pid", None), ("mount", None), ("cgroup", None)),
                                      "synthetic-explicit-cgroup-not-a-runtime-path", (("test.explicit-owner", "unit-run"),),
                                      "synthetic-explicit-profile", basis)
    return {"intent": intent, "image": image, "account": account, "mounts": mounts, "policy": policy}


def owner_facts(lane="upstream-rootless"):
    return source.DockerSourceOwnerFacts(
        "unit-session", "b" * 40, "unit-run", lane, "c" * 64, "sha256:" + "e" * 64,
        "sha256:" + "1" * 64, 700, 123456, 0, (501, 502, 503),
        (21, 22, 1024, 24, 25), ((31, 32), (33, 34)), (41, 42, 43), (51, 52), (61, 62, 0, 64, 65))


def claim(lane="upstream-rootless"):
    # This separate literal intentionally does not deserialize owner_facts().
    return {"session": "unit-session", "candidate": "b" * 40, "run": "unit-run", "lane": lane,
            "outer_id": "c" * 64, "image_id": "sha256:" + "e" * 64, "source_digest": "sha256:" + "1" * 64,
            "pid": 700, "start_ticks": 123456, "uid": 0, "namespaces": [501, 502, 503],
            "source_file": [21, 22, 1024, 24, 25], "source_ancestors": [[31, 32], [33, 34]],
            "original_root": [41, 42, 43], "pids_controller": [51, 52], "log_file": [61, 62, 0, 64, 65]}


class DockerExplicitSourceTests(unittest.TestCase):
    def prepare(self, values=None, backend="docker"):
        return source.prepare_docker_launch_projection(outer_backend=backend, **(inputs() if values is None else values))

    def validate(self, raw=OCI, expected=None, backend="docker"):
        return source.validate_docker_explicit_projection(raw, outer_backend=backend,
                                                           expected=self.prepare() if expected is None else expected)

    def encode(self, value):
        return json.dumps(value, separators=(",", ":")).encode()

    def rejected(self, function):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaises(ValueError) as caught:
                function()
        self.assertEqual(str(caught.exception), source.ERROR)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(output.getvalue(), "")

    def assert_unverified(self, result):
        self.assertIs(result, source.Match.ExpectationMatchOriginalAuthorityUnverified)
        self.assertEqual(result.capability_admission, ())
        self.assertIs(result.catalogue_admission, False)
        self.assertEqual(result.value, "expectation_match_original_authority_unverified")

    def test_four_inner_lanes_do_not_select_backend_or_grant_authority(self):
        for lane in source.LANES:
            with self.subTest(lane=lane):
                self.assert_unverified(self.validate(expected=self.prepare(inputs(lane))))
                self.assert_unverified(source.validate_source_claim_binding(
                    claim(lane), outer_backend="docker", expected_owner_facts=owner_facts(lane)))

    def test_only_explicit_docker_selection_without_packet_or_lane_fallback(self):
        for backend in (None, "", "Docker", "docker\n", "podman", *source.LANES, True, 1, {}, []):
            with self.subTest(backend=backend):
                self.rejected(lambda: source.require_docker_provider(backend))
                self.rejected(lambda: self.prepare(backend=backend))
                self.rejected(lambda: self.validate(backend=backend))
                self.rejected(lambda: source.validate_source_claim_binding(
                    dict(claim(), backend="docker"), outer_backend=backend, expected_owner_facts=owner_facts()))
        with self.assertRaises(TypeError):
            source.prepare_docker_launch_projection(**inputs())

    def test_inputs_are_frozen_redacted_and_not_authority_credentials(self):
        expected = self.prepare()
        records = [expected, *inputs().values(), inputs()["intent"].basis, *inputs()["mounts"].entries, owner_facts()]
        for record in records:
            self.assertNotIn(SECRET, repr(record))
            self.assertNotIn("sha256:", repr(record))
        with self.assertRaises(FrozenInstanceError):
            expected.intent.owner = "different"
        for key in inputs():
            values = inputs()
            values[key] = None
            self.rejected(lambda: self.prepare(values))

    def test_missing_or_podman_provenance_and_unbound_image_facts_refuse(self):
        for key in inputs():
            for basis in (None, source.DockerSourceBasis("podman-source-v1", "4.9.3", "sha256:" + "a" * 64),
                          source.DockerSourceBasis("independent-explicit-docker-source-v1", "", "sha256:" + "a" * 64),
                          source.DockerSourceBasis("independent-explicit-docker-source-v1", "synthetic", SECRET)):
                values = inputs()
                values[key] = replace(values[key], basis=basis)
                self.rejected(lambda: self.prepare(values))
        for field, value in (("pin", "example.invalid/other:unit@sha256:" + "d" * 64),
                             ("image_id", "sha256:" + "0" * 64), ("platform", "linux/arm64"),
                             ("config_digest", "sha256:" + "0" * 64)):
            values = inputs()
            values["image"] = replace(values["image"], **{field: value})
            self.rejected(lambda: self.prepare(values))

    def test_current_resource_and_logging_recipe_cannot_be_changed_on_both_sides(self):
        for field, value in (("pids", 513), ("memory", 4294967295), ("cpu_quota", 100000),
                             ("cpu_period", 200000), ("pids", True), ("log_driver", "k8s-file"),
                             ("log_max_size", "2m"), ("log_max_file", "2")):
            values = inputs()
            values["intent"] = replace(values["intent"], **{field: value})
            self.rejected(lambda: self.prepare(values))

    def test_each_raw_resource_value_type_and_complete_shape_is_exact(self):
        for group, field in (("pids", "limit"), ("memory", "limit"), ("cpu", "quota"), ("cpu", "period")):
            for mutation in ("different", "boolean", "missing"):
                value = json.loads(OCI)
                resources = value["linux"]["resources"][group]
                if mutation == "missing":
                    del resources[field]
                else:
                    resources[field] = True if mutation == "boolean" else resources[field] + 1
                self.rejected(lambda: self.validate(self.encode(value)))
        value = json.loads(OCI)
        value["linux"]["resources"]["memory"]["swap"] = 4294967296
        self.rejected(lambda: self.validate(self.encode(value)))

    def test_source_and_claim_agreement_does_not_replace_independent_expectations(self):
        mutations = (
            lambda v: v["process"].update(args=["/synthetic/gated-bootstrap --token", SECRET]),
            lambda v: v["process"].update(env=["EXPLICIT_ONE=forged", "EXPLICIT_EMPTY="]),
            lambda v: v["process"].update(cwd="/forged/work"),
            lambda v: v["process"]["user"].update(uid=0),
            lambda v: v["root"].update(path="/forged/root"),
            lambda v: v["mounts"][0].update(source="/forged/data"),
            lambda v: v["linux"]["resources"]["pids"].update(limit=1024),
            lambda v: v["linux"].update(cgroupsPath="forged-boundary"),
        )
        for mutation in mutations:
            value = json.loads(OCI)
            mutation(value)
            forged_packet = {"observed_oci": value, "claimed_projection": deepcopy(value)}
            self.assertEqual(forged_packet["observed_oci"], forged_packet["claimed_projection"])
            self.rejected(lambda: self.validate(self.encode(forged_packet["observed_oci"])))

    def test_argument_env_account_mount_and_namespace_boundaries(self):
        mutations = (
            lambda v: v["process"]["args"].reverse(),
            lambda v: v["process"]["env"].append("EXPLICIT_ONE=first"),
            lambda v: v["process"]["env"].reverse(),
            lambda v: v["process"]["user"].update(uid=True),
            lambda v: v["process"]["user"].update(additionalGids=[1500, 1400]),
            lambda v: v["mounts"][0]["options"].reverse(),
            lambda v: v["mounts"][0]["options"].append("U"),
            lambda v: v["mounts"][0].update(destination="/different"),
            lambda v: v["mounts"].append(deepcopy(v["mounts"][0])),
            lambda v: v["linux"]["namespaces"][0].update(path="/forged/ns/pid"),
            lambda v: v["linux"]["namespaces"].append({"type": "pid"}),
            lambda v: v.update(hooks={"prestart": []}),
            lambda v: v["process"].update(apparmorProfile="unconfined"),
            lambda v: v["annotations"].update({"test.explicit-owner": "other"}),
            lambda v: v.update(ociVersion="different"),
        )
        for mutation in mutations:
            value = json.loads(OCI)
            mutation(value)
            self.rejected(lambda: self.validate(self.encode(value)))

    def test_missing_defaults_or_unsupported_explicit_layout_refuse(self):
        for field, value in (("layout", "podman-crun-systemd-v2"), ("layout", None), ("root_path", "rootfs"),
                             ("root_readonly", 0), ("cgroups_path", ""), ("namespaces", ()),
                             ("annotations", (("duplicate", "one"), ("duplicate", "two")))):
            values = inputs()
            values["policy"] = replace(values["policy"], **{field: value})
            self.rejected(lambda: self.prepare(values))
        for field, value in (("argv", ()), ("env", ("A=1", "A=1")), ("env", ["A=1"]),
                             ("cwd", "/a/../b"), ("owner", "foreign"), ("image_pin", "floating:latest")):
            values = inputs()
            values["intent"] = replace(values["intent"], **{field: value})
            self.rejected(lambda: self.prepare(values))
        values = inputs()
        values["mounts"] = replace(values["mounts"], entries=())
        self.rejected(lambda: self.prepare(values))
        for value in ({"Id": "c" * 64, "Config": {}, "HostConfig": {}},
                      {"backend": "docker", "audit": "passing", "peer_pid": 700}, {}):
            self.rejected(lambda: self.validate(self.encode(value)))

    def test_unchecked_security_members_are_explicitly_not_complete_validation(self):
        value = json.loads(OCI)
        value["process"]["terminal"] = True
        value["process"]["capabilities"] = {"effective": ["SYNTHETIC_UNEXAMINED"]}
        value["linux"]["seccomp"] = {"defaultAction": "SYNTHETIC_UNEXAMINED"}
        self.assert_unverified(self.validate(self.encode(value)))
        value["process"]["unknown_default"] = "not in the declared scope"
        self.rejected(lambda: self.validate(self.encode(value)))

    def test_profile_absence_and_namespace_paths_require_explicit_expectations(self):
        values = inputs()
        values["policy"] = replace(values["policy"], apparmor_profile=None)
        expected = self.prepare(values)
        self.rejected(lambda: self.validate(expected=expected))
        raw = OCI.replace(b',\n    "apparmorProfile":"synthetic-explicit-profile"', b"")
        self.assert_unverified(self.validate(raw, expected))
        values = inputs()
        values["policy"] = replace(values["policy"], namespaces=(
            ("pid", "/synthetic/owned/ns/pid"), ("mount", None), ("cgroup", None)))
        raw = OCI.replace(b'{"type":"pid"}', b'{"type":"pid","path":"/synthetic/owned/ns/pid"}')
        self.assert_unverified(self.validate(raw, self.prepare(values)))
        self.rejected(lambda: self.validate(raw))

    def test_65536_byte_limit_duplicate_nonfinite_utf8_and_wrong_json_types(self):
        self.assert_unverified(self.validate(OCI + b" " * (65536 - len(OCI))))
        for raw in (OCI + b" " * (65537 - len(OCI)), b"", bytearray(OCI), OCI.decode(),
                    OCI.replace(b'"hostname":"synthetic-outer"', b'"hostname":"synthetic-outer","hostname":"synthetic-outer"'),
                    OCI.replace(b'"limit":512', b'"limit":512,"limit":512'),
                    OCI.replace(b'"limit":512', b'"limit":NaN'),
                    OCI.replace(b'"limit":512', b'"limit":Infinity'),
                    OCI.replace(b'"limit":512', b'"limit":512.0'),
                    OCI.replace(b'"limit":512', b'"limit":true'), b"\xff", b"{", b"[]", b"null",
                    b"[" * 2000 + b"]" * 2000):
            self.rejected(lambda: self.validate(raw))

    def test_collection_depth_strings_and_expected_source_size_are_bounded(self):
        for extra in ([0] * 129, [[0] * 128] * 40, "x" * 4097, "é" * 2049,
                      "\ud800", [[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]):
            value = json.loads(OCI)
            value["linux"]["seccomp"] = extra
            self.rejected(lambda: self.validate(self.encode(value)))
        values = inputs()
        values["intent"] = replace(values["intent"], argv=("x" * 4096,) * 20)
        self.rejected(lambda: self.prepare(values))

    def test_every_claim_coordinate_binds_separate_owner_facts(self):
        original = claim()
        for field in original:
            value = deepcopy(original)
            if type(value[field]) is str:
                value[field] += SECRET
            elif type(value[field]) is int:
                value[field] += 1
            else:
                value[field] = []
            self.rejected(lambda: source.validate_source_claim_binding(
                value, outer_backend="docker", expected_owner_facts=owner_facts()))
            missing = deepcopy(original)
            del missing[field]
            self.rejected(lambda: source.validate_source_claim_binding(
                missing, outer_backend="docker", expected_owner_facts=owner_facts()))
        for field in ("pid", "start_ticks", "uid"):
            value = deepcopy(original)
            value[field] = True
            self.rejected(lambda: source.validate_source_claim_binding(
                value, outer_backend="docker", expected_owner_facts=owner_facts()))
        self.rejected(lambda: source.validate_source_claim_binding(
            dict(original, authority=True), outer_backend="docker", expected_owner_facts=owner_facts()))
        self.rejected(lambda: source.validate_source_claim_binding(original, outer_backend="docker", expected_owner_facts=original))

    def test_forged_matching_owner_assertions_still_never_authenticate_custody(self):
        facts = replace(owner_facts(), pid=999, original_root=(91, 92, 93))
        value = dict(claim(), pid=999, original_root=[91, 92, 93])
        self.assert_unverified(source.validate_source_claim_binding(value, outer_backend="docker", expected_owner_facts=facts))

    def test_owner_fact_limits_and_malformed_tuples_refuse(self):
        for field, value in (("source_file", (21, 22, 65537, 24, 25)), ("source_file", (21, 22, 0, 24, 25)),
                             ("source_ancestors", ()), ("source_ancestors", ((1, 2),) * 9),
                             ("source_ancestors", ((1,),)), ("namespaces", (True, 2, 3)),
                             ("pid", 2**31), ("uid", -1), ("source_digest", SECRET)):
            facts = replace(owner_facts(), **{field: value})
            self.rejected(lambda: source.validate_source_claim_binding(claim(), outer_backend="docker", expected_owner_facts=facts))

    def test_module_closure_has_no_io_runtime_or_obsolete_graph_imports(self):
        forbidden = {"os", "subprocess", "socket", "open", "exec", "eval", "__import__",
                     "native_outer_lifecycle", "native_outer_launch", "native_outer_coordinator",
                     "native_outer_bootstrap", "native_outer_runtime", "native_outer_broker"}
        self.assertFalse(forbidden.intersection(source.__dict__))

        def names(code):
            result = set(code.co_names)
            for constant in code.co_consts:
                if type(constant) is CodeType:
                    result.update(names(constant))
            return result

        for value in source.__dict__.values():
            if getattr(value, "__module__", None) == source.__name__ and hasattr(value, "__code__"):
                self.assertFalse(forbidden.intersection(names(value.__code__)))


if __name__ == "__main__":
    unittest.main()
