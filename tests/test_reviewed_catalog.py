"""Checked-in reviewed records must bind the exact native artifact bytes."""

import hashlib
import json
import re
import unittest
from copy import deepcopy
from pathlib import Path

from test_native_evidence import SHAPES


ROOT = Path(__file__).resolve().parents[1]
RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/36451790131/attempts/1"
CANDIDATE = "d51d7dbfda5ee6f8fefe92605afe8baea3dc504e"
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
LANE_VARIANTS = {
    "Debian11Rootful": "debian11-rootful",
    "Debian11Rootless": "debian11-rootless",
    "UpstreamRootful": "upstream-rootful",
    "UpstreamRootless": "upstream-rootless",
}
EXPECTED_MANIFESTS = {
    "debian11-rootful": "3d7f161903d03c9dd6c11105ba74897c80e4b2514358231e97ce550c73ef900b",
    "debian11-rootless": "72d404754dd367fbafddfcbb4e31688b423e448b08812bf35d7b79a15f8d78c2",
    "upstream-rootful": "896b16f875841d2a6708f4483a94a03cd4aa2832c0988d2365066b36cd07fa1e",
    "upstream-rootless": "ec31ef230d76cf91071856dfdaf5601cb59f8fd72f154d4fd4746963bb228b7e",
}
EXPECTED_REVIEWED = {
    "debian11-rootful": "f4a68bec2605814b9ff9c3942adc60cee88255775f17c101cc0b72767fe03e0f",
    "debian11-rootless": "7445b521282ded2e1d07f2478a7d7812ed51b27a488861483fe228b85b114986",
    "upstream-rootful": "063d5ea178ff754d16fc3ce1db99855907a0b6a93b924f241fcf8b14c2811362",
    "upstream-rootless": "a9620c6a3b94c31e662e11b14de7688290eec8f2532dd5a061652ef01b2639ee",
}
EXPECTED_IDENTITIES = {
    "debian11-rootful": {
        "build": {"kind": "debian-package", "distribution": "debian11", "package_name": "docker.io",
                  "package_revision": "20.10.5+dfsg1-1+deb11u2"},
        "engine_release": "20.10.5+dfsg1", "advertised_api": "1.41",
        "acquisition_api": "1.41", "rendering_api": "1.41", "mode": "rootful",
    },
    "debian11-rootless": {
        "build": {"kind": "debian-package", "distribution": "debian11", "package_name": "docker.io",
                  "package_revision": "20.10.5+dfsg1-1+deb11u2"},
        "engine_release": "20.10.5+dfsg1", "advertised_api": "1.41",
        "acquisition_api": "1.41", "rendering_api": "1.41", "mode": "rootless",
    },
    "upstream-rootful": {
        "build": {"kind": "upstream"}, "engine_release": "29.8.1",
        "advertised_api": "1.56", "acquisition_api": "1.49", "rendering_api": "1.56",
        "mode": "rootful",
    },
    "upstream-rootless": {
        "build": {"kind": "upstream"}, "engine_release": "29.8.1",
        "advertised_api": "1.56", "acquisition_api": "1.49", "rendering_api": "1.56",
        "mode": "rootless",
    },
}
ADMISSION_CANDIDATE = "702910b003daae58babd540d7ba3de4998275feb"
ADMISSION_RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/37209363801/attempts/1"
ADMISSION_SHAPES = {
    **SHAPES,
    "VolumeExternalReference": ["ExternalVolumeReference"],
    "NetworkExternalReference": ["ExternalNetworkReference"],
    "NetworkInternal": ["InternalBridgeNetworkCreate"],
}
ADMISSION_MANIFESTS = {
    "debian11-rootful": "55d93a54dca1e60b8331611d7b5aa9a6e7b4f23513cf82bdb095f1d3b1ef2ed1",
    "debian11-rootless": "c6d59cd2c40613a764eb5a6e5e31cf934a4c4deac5835aa6d7b4d8cc65da5200",
    "upstream-rootful": "cff1c7eee2883671a28009e0c97d027f01d526039c8beb2ebcadeafe48d38ce0",
    "upstream-rootless": "317b99075b795459a2b8d974f2a498448b83f260cb72b6e595d69e997970e392",
}
ADMISSION_REVIEWED = {
    "debian11-rootful": "b9f3064cadfc2302678b9a334597907fd35eeb856464d4e6c81bf4465875d0e8",
    "debian11-rootless": "365e8a70e2e5a369912da47d2a510e45acd7cca3ac6e932e3536ad75f22c64b9",
    "upstream-rootful": "27c47307f4fdd523a22448415238a729e7a6458fddc554259f23ea99fff5ff76",
    "upstream-rootless": "c0f8160bf8787e9490713595f58c1b4eeb9aeee3ff5f4739776a1010bdea6e1f",
}
LABEL_CANDIDATE = "0d8268155a5aacddaeb501adf7f8b2fe06a718ca"
LABEL_RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/37214738475/attempts/1"
LABEL_SHAPES = {**ADMISSION_SHAPES, "VolumeLabels": ["VolumeCreateLabels"]}
LABEL_MANIFESTS = {
    "debian11-rootful": "4bf511a7753a522423286288fcdbed2eaf3325bf2edff44f9dea32ce02c731d5",
    "debian11-rootless": "b6ae28b4f09b691c1e2490b7ca4c97e7ee479a038307721013c6b04343306f94",
    "upstream-rootful": "0f3f540aa428c37ec09b37f436b15d3e98231fb7151dd21639cefb22dc073198",
    "upstream-rootless": "c25e502010a660e96bda7244e7df95afab0a74fcc33c4cf1d613c46980b30ae8",
}
LABEL_REVIEWED = {
    "debian11-rootful": "2306973726b1ecaeac9b26936cfe4df127a9f4927ae5f7bd41be99b528ee37fa",
    "debian11-rootless": "f471fc1f6998bfdebb130734a11c484ff7bb7e42a406805ab269bd482347eac4",
    "upstream-rootful": "dd2dec14ce75c1dfb672f018a8ade98334783edcd964758da6b4a432d22429a0",
    "upstream-rootless": "280839c9f4d6cfd1adda9f25bbf17fdfbb3fab162e91c346a614c31e1e318c44",
}
# Every reviewed cohort must be deliberately added here with its exact run,
# candidate, four identities, four envelope digests, four raw manifest digests,
# and exact reviewed capability-to-shape admissions. A later new shape needs
# explicit independently reviewed source mapping, not a raw probe marker.
COHORTS = {
    (CANDIDATE, RUN): {
        lane: (EXPECTED_REVIEWED[lane], EXPECTED_MANIFESTS[lane],
               EXPECTED_IDENTITIES[lane], SHAPES)
        for lane in LANES
    },
    (ADMISSION_CANDIDATE, ADMISSION_RUN): {
        lane: (ADMISSION_REVIEWED[lane], ADMISSION_MANIFESTS[lane],
               EXPECTED_IDENTITIES[lane], ADMISSION_SHAPES)
        for lane in LANES
    },
    (LABEL_CANDIDATE, LABEL_RUN): {
        lane: (LABEL_REVIEWED[lane], LABEL_MANIFESTS[lane],
               EXPECTED_IDENTITIES[lane], LABEL_SHAPES)
        for lane in LANES
    },
}
RECORD_TUPLE = re.compile(
    r'\(\s*NativeEvidenceLane::(?P<variant>\w+),\s*'
    r'"(?P<digest>[0-9a-f]{64})",\s*include_str!\(\s*'
    r'"\.\./docs/evidence/reviewed/sha256/(?P<path_digest>[0-9a-f]{64})\.json"\s*\),\s*\)',
    re.DOTALL,
)


def required_shapes() -> dict[str, tuple[str, ...] | None]:
    """Read every closed required_for arm; fail if the Rust shape contract drifts."""
    source = (ROOT / "src/version.rs").read_text(encoding="utf-8")
    capabilities = source.split("pub enum Capability {", 1)[1].split("}", 1)[0]
    shape_enum = source.split("pub(crate) enum NativeCapabilityShape {", 1)[1].split("}", 1)[0]
    capability_names = set(re.findall(r"^\s*(\w+),\s*$", capabilities, re.MULTILINE))
    shape_names = set(re.findall(r"^\s*(\w+),\s*$", shape_enum, re.MULTILINE))
    function = source.split("pub(crate) fn required_for(capability: Capability)", 1)[1]
    arms_start = function.index("match capability {") + len("match capability {")
    arms = []
    start = arms_start
    stack = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for position in range(arms_start, len(function)):
        character = function[position]
        if character in "([{":
            stack.append(character)
        elif character in ")]}":
            if not stack:
                if character != "}":
                    raise ValueError("malformed required_for match")
                if function[start:position].strip():
                    raise ValueError("unterminated required_for arm")
                break
            if stack.pop() != pairs[character]:
                raise ValueError("malformed required_for delimiters")
            if character == "}" and not stack and re.match(r"\s*Capability::", function[position + 1:]):
                arms.append(function[start:position + 1].strip())
                start = position + 1
        elif character == "," and not stack:
            arms.append(function[start:position].strip())
            start = position + 1
    else:
        raise ValueError("unterminated required_for match")

    result = {}
    for arm in arms:
        left, separator, right = arm.partition("=>")
        if not separator or not re.fullmatch(r"\s*Capability::\w+(?:\s*\|\s*Capability::\w+)*\s*", left):
            raise ValueError("unrecognized required_for arm")
        right = right.strip()
        if right.startswith("{") and right.endswith("}"):
            right = right[1:-1].strip()
        if right == "None":
            shapes = None
        else:
            match = re.fullmatch(r"Some\(\s*&\[(.*)\]\s*\)", right, re.DOTALL)
            if not match or re.sub(r"Self::\w+|[\s,]", "", match[1]):
                raise ValueError(f"unrecognized required_for shapes: {right}")
            shapes = tuple(re.findall(r"Self::(\w+)", match[1]))
            if not shapes or len(shapes) != len(set(shapes)) or not set(shapes) <= shape_names:
                raise ValueError("invalid required_for shapes")
        for name in re.findall(r"Capability::(\w+)", left):
            if name in result:
                raise ValueError("duplicate required_for capability")
            result[name] = shapes
    if set(result) != capability_names or not capability_names or not shape_names:
        raise ValueError("required_for does not cover the closed capability enum")
    return result


def hashed_json(kind: str) -> list[tuple[Path, dict]]:
    directory = ROOT / "docs/evidence" / kind / "sha256"
    result = []
    for path in sorted(directory.glob("*.json")):
        content = path.read_bytes()
        if path.stem != hashlib.sha256(content).hexdigest():
            raise ValueError(f"content digest does not match filename: {path}")
        result.append((path, json.loads(content)))
    return result


def indexed_cohorts(
    records: list[tuple[Path, dict]],
    cohorts: dict[tuple[str, str], dict[str, tuple[str, str, dict, dict]]],
) -> dict[tuple[str, str], dict[str, tuple[Path, dict]]]:
    if not cohorts or any(set(lanes) != set(LANES) for lanes in cohorts.values()):
        raise ValueError("each closed cohort must specify all four exact lanes")
    if len(records) != sum(len(lanes) for lanes in cohorts.values()):
        raise ValueError("reviewed cohort record count differs from closed specification")
    grouped: dict[tuple[str, str], list[tuple[Path, dict]]] = {key: [] for key in cohorts}
    for path, record in records:
        key = (record["candidate_sha"], record["run_url"])
        if key not in cohorts:
            raise ValueError("unknown reviewed candidate or source run")
        grouped[key].append((path, record))
    result = {}
    for key, lanes in cohorts.items():
        entries = grouped[key]
        names = [record["lane"] for _, record in entries]
        if len(entries) != len(lanes) or len(set(names)) != len(names) or set(names) != set(lanes):
            raise ValueError("exactly one reviewed record is required for each cohort lane")
        for path, record in entries:
            reviewed_digest, manifest_digest, identity, _ = lanes[record["lane"]]
            if path.stem != reviewed_digest or record["native_manifest_sha256"] != manifest_digest:
                raise ValueError("reviewed or native manifest digest differs from closed specification")
            if record["identity"] != identity:
                raise ValueError("reviewed identity differs from closed specification")
        result[key] = {record["lane"]: (path, record) for path, record in entries}
    return result


def indexed_native_manifests(
    records: list[tuple[Path, dict]],
    cohorts: dict[tuple[str, str], dict[str, tuple[str, str, dict, dict]]],
) -> dict[str, tuple[Path, dict]]:
    expected = {
        manifest: (candidate, lane)
        for (candidate, _), lanes in cohorts.items()
        for lane, (_, manifest, _, _) in lanes.items()
    }
    if len(records) != len(expected) or {path.stem for path, _ in records} != set(expected):
        raise ValueError("native manifest file set differs from closed cohort specification")
    for path, manifest in records:
        candidate, lane = expected[path.stem]
        if manifest["candidate_sha"] != candidate or manifest["lane"] != lane:
            raise ValueError("native manifest identity differs from closed cohort specification")
    return {path.stem: (path, manifest) for path, manifest in records}


def bind_cohorts(
    reviewed_records: list[tuple[Path, dict]],
    native_records: list[tuple[Path, dict]],
    cohorts: dict[tuple[str, str], dict[str, tuple[str, str, dict, dict]]],
) -> dict[tuple[str, str], dict[str, tuple[Path, dict]]]:
    reviewed = indexed_cohorts(reviewed_records, cohorts)
    raw = indexed_native_manifests(native_records, cohorts)
    required = required_shapes()
    for cohort_key, lanes in reviewed.items():
        for lane, (_, record) in lanes.items():
            manifest = raw[record["native_manifest_sha256"]][1]
            identity = record["identity"]
            expected_admission = cohorts[cohort_key][lane][3]
            if record["schema_version"] != 1 or record["native_manifest_artifact_name"] != f"dockerlens-native-{lane}":
                raise ValueError("reviewed record schema or lane artifact differs")
            fields = (
                (identity["engine_release"], manifest["engine_version"]),
                (identity["advertised_api"], manifest["engine_api_max"]),
                (identity["acquisition_api"], manifest["acquisition_api"]),
                (identity["rendering_api"], manifest["rendering_api"]),
                (identity["mode"], manifest["expected_mode"]),
            )
            if any(left != right for left, right in fields):
                raise ValueError("reviewed identity differs from native manifest")
            build = identity["build"]
            if build["kind"] == "debian-package":
                if (build["package_revision"] != manifest["debian_docker_package"]
                        or build["distribution"] != "debian11" or build["package_name"] != "docker.io"):
                    raise ValueError("reviewed package differs from native manifest")
            elif build["kind"] == "upstream":
                if manifest["debian_docker_package"] is not None:
                    raise ValueError("upstream manifest unexpectedly names a Debian package")
            else:
                raise ValueError("unknown reviewed build kind")
            entries = record["capabilities"]
            names = [entry["name"] for entry in entries]
            if len(names) != len(set(names)) or set(names) != set(expected_admission):
                raise ValueError("reviewed capability names differ from closed admission")
            for entry in entries:
                name = entry["name"]
                shapes = entry["admitted_shapes"]
                rust_shapes = required.get(name)
                expected_shapes = expected_admission[name]
                if (rust_shapes is None or len(expected_shapes) != len(set(expected_shapes))
                        or set(expected_shapes) != set(rust_shapes)):
                    raise ValueError("closed admission differs from required_for shapes")
                if (entry["state"] != "available"
                        or shapes != expected_shapes
                        or len(shapes) != len(set(shapes))
                        or manifest["capability_outcome"].get(name) != "available"
                        or manifest["admitted_shapes"].get(name) != shapes):
                    raise ValueError("reviewed or raw shapes differ from closed admission")
    return reviewed


class ReviewedCatalogTests(unittest.TestCase):
    def test_rust_record_tuples_pair_exact_lane_digest_and_file(self) -> None:
        source = (ROOT / "src/reviewed_catalog.rs").read_text(encoding="utf-8")
        section = source.split("const RECORDS:", 1)[1].split("pub(crate) fn records", 1)[0]
        tuples = list(RECORD_TUPLE.finditer(section))
        self.assertEqual(len(tuples), 4)
        self.assertEqual(section.count("NativeEvidenceLane::"), 4)
        reviewed = {
            lane: path.stem
            for lane, (path, _) in indexed_cohorts(hashed_json("reviewed"), COHORTS)[LABEL_CANDIDATE, LABEL_RUN].items()
        }
        self.assertEqual({match["variant"] for match in tuples}, set(LANE_VARIANTS))
        for match in tuples:
            lane = LANE_VARIANTS[match["variant"]]
            self.assertEqual(match["digest"], reviewed[lane])
            self.assertEqual(match["path_digest"], reviewed[lane])
            self.assertEqual(match["digest"], LABEL_REVIEWED[lane])

    def test_four_records_bind_exact_manifest_bytes_and_shapes(self) -> None:
        native_records = hashed_json("native")
        raw = indexed_native_manifests(native_records, COHORTS)
        reviewed = bind_cohorts(hashed_json("reviewed"), native_records, COHORTS)[CANDIDATE, RUN]
        for lane in LANES:
            with self.subTest(lane=lane):
                reviewed_path, record = reviewed[lane]
                raw_path, manifest = raw[record["native_manifest_sha256"]]
                self.assertEqual(record["schema_version"], 1)
                self.assertEqual(record["run_url"], RUN)
                self.assertEqual(record["candidate_sha"], CANDIDATE)
                self.assertEqual(manifest["candidate_sha"], CANDIDATE)
                self.assertEqual(record["native_manifest_artifact_name"], f"dockerlens-native-{lane}")
                self.assertEqual(record["native_manifest_sha256"], raw_path.stem)
                self.assertEqual(record["native_manifest_sha256"], EXPECTED_MANIFESTS[lane])
                identity = record["identity"]
                self.assertEqual(identity["engine_release"], manifest["engine_version"])
                self.assertEqual(identity["advertised_api"], manifest["engine_api_max"])
                self.assertEqual(identity["acquisition_api"], manifest["acquisition_api"])
                self.assertEqual(identity["rendering_api"], manifest["rendering_api"])
                self.assertEqual(identity["mode"], manifest["expected_mode"])
                self.assertEqual(identity["mode"], lane.rsplit("-", 1)[1])
                self.assertEqual(identity["engine_release"],
                                 "20.10.5+dfsg1" if lane.startswith("debian11-") else "29.8.1")
                expected_api = "1.41" if lane.startswith("debian11-") else "1.56"
                self.assertEqual(identity["advertised_api"], expected_api)
                self.assertEqual(identity["rendering_api"], expected_api)
                self.assertEqual(identity["acquisition_api"],
                                 "1.41" if lane.startswith("debian11-") else "1.49")
                if lane.startswith("debian11-"):
                    self.assertEqual(identity["build"], {
                        "kind": "debian-package", "distribution": "debian11",
                        "package_name": "docker.io",
                        "package_revision": manifest["debian_docker_package"],
                    })
                else:
                    self.assertEqual(identity["build"], {"kind": "upstream"})
                    self.assertIsNone(manifest["debian_docker_package"])
                entries = record["capabilities"]
                self.assertEqual(len(entries), len(SHAPES))
                capabilities = {entry["name"]: entry for entry in entries}
                self.assertEqual(set(capabilities), set(SHAPES))
                self.assertEqual(sum(map(len, SHAPES.values())), 20)
                for name, shapes in SHAPES.items():
                    self.assertEqual(capabilities[name]["state"], "available")
                    self.assertEqual(capabilities[name]["admitted_shapes"], shapes)
                    self.assertEqual(manifest["capability_outcome"][name], "available")
                    self.assertEqual(manifest["admitted_shapes"][name], shapes)
                self.assertEqual(len(reviewed_path.stem), 64)

    def test_new_admission_cohort_is_exact_and_excludes_raw_label_evidence(self) -> None:
        native_records = hashed_json("native")
        raw = indexed_native_manifests(native_records, COHORTS)
        reviewed = bind_cohorts(hashed_json("reviewed"), native_records, COHORTS)
        self.assertEqual(set(reviewed), set(COHORTS))
        self.assertEqual(len(ADMISSION_SHAPES), 13)
        self.assertEqual(sum(map(len, ADMISSION_SHAPES.values())), 23)
        for lane, (path, record) in reviewed[ADMISSION_CANDIDATE, ADMISSION_RUN].items():
            with self.subTest(lane=lane):
                self.assertEqual(path.stem, ADMISSION_REVIEWED[lane])
                self.assertEqual(record["native_manifest_sha256"], ADMISSION_MANIFESTS[lane])
                self.assertEqual(record["identity"], EXPECTED_IDENTITIES[lane])
                claims = {entry["name"]: entry["admitted_shapes"] for entry in record["capabilities"]}
                self.assertEqual(claims, ADMISSION_SHAPES)
                manifest = raw[record["native_manifest_sha256"]][1]
                self.assertEqual(set(manifest["admitted_shapes"]) - set(claims), {"VolumeLabels"})
                self.assertEqual(manifest["admitted_shapes"]["VolumeLabels"], ["VolumeCreateLabels"])
                self.assertEqual(manifest["capability_outcome"]["VolumeLabels"], "available")
                self.assertNotIn("VolumeLabels", claims)
                self.assertEqual(len(manifest["source_probes"]), 19)
                self.assertEqual(len(manifest["network_probes"]), 22)
                self.assertEqual(len(manifest["volume_probes"]), 6)
                self.assertEqual(len(manifest["volume_label_probes"]), 4)

    def test_label_candidate_binds_four_exact_complete_raw_groups(self) -> None:
        native_records = hashed_json("native")
        raw = indexed_native_manifests(native_records, COHORTS)
        reviewed = bind_cohorts(hashed_json("reviewed"), native_records, COHORTS)
        self.assertEqual(len(LABEL_SHAPES), 14)
        self.assertEqual(sum(map(len, LABEL_SHAPES.values())), 24)
        for lane, (path, record) in reviewed[LABEL_CANDIDATE, LABEL_RUN].items():
            with self.subTest(lane=lane):
                self.assertEqual(path.stem, LABEL_REVIEWED[lane])
                self.assertEqual(record["native_manifest_sha256"], LABEL_MANIFESTS[lane])
                self.assertEqual(record["identity"], EXPECTED_IDENTITIES[lane])
                claims = {entry["name"]: entry["admitted_shapes"] for entry in record["capabilities"]}
                manifest = raw[record["native_manifest_sha256"]][1]
                self.assertEqual(claims, LABEL_SHAPES)
                self.assertEqual(manifest["admitted_shapes"], LABEL_SHAPES)
                self.assertEqual(manifest["capability_outcome"]["VolumeLabels"], "available")
                self.assertEqual(manifest["volume_label_probes"], [
                    "VolumeCreateLabels", "VolumeLabelInspect", "VolumeLabelPersistence",
                    "VolumeLabelOwnershipCleanup",
                ])
                self.assertEqual(len(manifest["source_probes"]), 19)
                self.assertEqual(len(manifest["network_probes"]), 22)
                self.assertEqual(len(manifest["volume_probes"]), 6)

    def test_compiled_candidate_has_only_fourteen_complete_capability_groups(self) -> None:
        source = (ROOT / "src/reviewed_catalog.rs").read_text(encoding="utf-8")
        self.assertIn(f'const SOURCE_CANDIDATE: &str = "{LABEL_CANDIDATE}";', source)
        self.assertIn(f'"{LABEL_RUN}";', source)
        capabilities = source.split("const REVIEWED_CAPABILITIES:", 1)[1].split("];", 1)[0]
        shapes = source.split("const REVIEWED_SHAPES:", 1)[1].split("];", 1)[0]
        capability_names = re.findall(r"Capability::(\w+)", capabilities)
        shape_names = re.findall(r"NativeCapabilityShape::(\w+)", shapes)
        self.assertEqual(len(capability_names), 14)
        self.assertEqual(set(capability_names), set(LABEL_SHAPES))
        self.assertEqual(len(shape_names), 24)
        self.assertEqual(set(shape_names), {shape for group in LABEL_SHAPES.values() for shape in group})

    def test_label_candidate_requires_positive_complete_raw_and_reviewed_label_group(self) -> None:
        reviewed_records = hashed_json("reviewed")
        native_records = hashed_json("native")
        for lane in LANES:
            for side in ("raw", "reviewed"):
                for fault in ("missing", "empty", "duplicate", "wrong_shape", "unavailable", "unknown"):
                    reviewed = deepcopy(reviewed_records)
                    native = deepcopy(native_records)
                    if side == "raw":
                        manifest = next(data for path, data in native if path.stem == LABEL_MANIFESTS[lane])
                        if fault == "missing":
                            del manifest["admitted_shapes"]["VolumeLabels"]
                        elif fault == "empty":
                            manifest["admitted_shapes"]["VolumeLabels"] = []
                        elif fault == "duplicate":
                            manifest["admitted_shapes"]["VolumeLabels"] *= 2
                        elif fault == "wrong_shape":
                            manifest["admitted_shapes"]["VolumeLabels"] = ["NamedVolumeCreate"]
                        else:
                            manifest["capability_outcome"]["VolumeLabels"] = fault
                    else:
                        record = next(data for path, data in reviewed if path.stem == LABEL_REVIEWED[lane])
                        entry = next(entry for entry in record["capabilities"] if entry["name"] == "VolumeLabels")
                        if fault == "missing":
                            record["capabilities"].remove(entry)
                        elif fault == "empty":
                            entry["admitted_shapes"] = []
                        elif fault == "duplicate":
                            entry["admitted_shapes"] *= 2
                        elif fault == "wrong_shape":
                            entry["admitted_shapes"] = ["NamedVolumeCreate"]
                        else:
                            entry["state"] = fault
                    with self.subTest(lane=lane, side=side, fault=fault):
                        with self.assertRaises(ValueError):
                            bind_cohorts(reviewed, native, COHORTS)

    def test_new_singleton_groups_require_positive_complete_linked_raw_evidence(self) -> None:
        reviewed_records = hashed_json("reviewed")
        native_records = hashed_json("native")
        for lane in LANES:
            for name in ("VolumeExternalReference", "NetworkExternalReference", "NetworkInternal"):
                for fault in ("missing", "empty", "duplicate", "wrong_shape", "unavailable", "unknown"):
                    altered = deepcopy(native_records)
                    manifest = next(record for path, record in altered if path.stem == ADMISSION_MANIFESTS[lane])
                    if fault == "missing":
                        del manifest["admitted_shapes"][name]
                    elif fault == "empty":
                        manifest["admitted_shapes"][name] = []
                    elif fault == "duplicate":
                        manifest["admitted_shapes"][name] *= 2
                    elif fault == "wrong_shape":
                        manifest["admitted_shapes"][name] = ["VolumeCreateLabels"]
                    else:
                        manifest["capability_outcome"][name] = fault
                    with self.subTest(lane=lane, group=name, fault=fault):
                        with self.assertRaisesRegex(ValueError, "reviewed or raw shapes differ from closed admission"):
                            bind_cohorts(reviewed_records, altered, COHORTS)

    def test_closed_cohorts_accept_second_known_complete_cohort_only(self) -> None:
        records = hashed_json("reviewed")
        second_candidate = "a" * 40
        second_run = "https://github.com/Strukturpiloten/docker-lens/actions/runs/999/attempts/1"
        second_spec = {
            lane: (f"{index + 1:064x}", f"{index + 5:064x}",
                   deepcopy(EXPECTED_IDENTITIES[lane]), deepcopy(SHAPES))
            for index, lane in enumerate(LANES)
        }
        known = {**COHORTS, (second_candidate, second_run): second_spec}
        # Synthetic in-memory records exercise indexing only; these are not
        # checked-in evidence, production RECORDS, or positive capability facts.
        synthetic = []
        historical = indexed_cohorts(records, COHORTS)[CANDIDATE, RUN]
        for path, record in historical.values():
            forged = deepcopy(record)
            forged["candidate_sha"] = second_candidate
            forged["run_url"] = second_run
            forged["native_manifest_sha256"] = second_spec[record["lane"]][1]
            synthetic.append((Path(second_spec[record["lane"]][0] + ".json"), forged))
        self.assertEqual(set(indexed_cohorts(records + synthetic, known)), set(known))
        unknown = deepcopy(synthetic)
        unknown[0][1]["run_url"] = "https://github.com/Strukturpiloten/docker-lens/actions/runs/1000/attempts/1"
        wrong_manifest = deepcopy(synthetic)
        wrong_manifest[0][1]["native_manifest_sha256"] = "f" * 64
        wrong_identity = deepcopy(synthetic)
        wrong_identity[0][1]["identity"]["mode"] = "rootless" if wrong_identity[0][1]["identity"]["mode"] == "rootful" else "rootful"
        wrong_envelope = [(Path("f" * 64 + ".json"), synthetic[0][1]), *synthetic[1:]]
        incomplete_spec = {**known, (second_candidate, second_run): dict(list(second_spec.items())[:-1])}
        with self.assertRaises(ValueError):
            indexed_cohorts(records + synthetic, incomplete_spec)
        for altered in (
            records[:-1] + synthetic,
            records + synthetic[:-1],
            records + synthetic[:-1] + [synthetic[0]],
            records + unknown,
            records + wrong_manifest,
            records + wrong_identity,
            records + wrong_envelope,
        ):
            with self.subTest(lanes=[data["lane"] for _, data in altered]):
                with self.assertRaises(ValueError):
                    indexed_cohorts(altered, known)

    def test_historical_substitution_is_rejected_even_with_rehashed_filename(self) -> None:
        records = hashed_json("reviewed")
        changed = deepcopy(records)
        path, record = changed[0]
        record["identity"]["mode"] = "rootless" if record["identity"]["mode"] == "rootful" else "rootful"
        replacement = json.dumps(record, sort_keys=True).encode("utf-8")
        changed[0] = (path.with_name(hashlib.sha256(replacement).hexdigest() + ".json"), record)
        with self.assertRaises(ValueError):
            indexed_cohorts(changed, COHORTS)

    def test_second_cohort_raw_and_reviewed_must_agree_even_when_rehashed(self) -> None:
        historical_reviewed = hashed_json("reviewed")
        historical_native = hashed_json("native")
        reviewed = indexed_cohorts(historical_reviewed, COHORTS)[CANDIDATE, RUN]
        native = indexed_native_manifests(historical_native, COHORTS)
        candidate = "b" * 40
        run = "https://github.com/Strukturpiloten/docker-lens/actions/runs/1001/attempts/1"
        spec = {}
        second_reviewed = []
        second_native = []
        # Test-only records with a second known cohort; no source file is added.
        for index, lane in enumerate(LANES):
            record = deepcopy(reviewed[lane][1])
            manifest = deepcopy(native[record["native_manifest_sha256"]][1])
            reviewed_digest = f"{index + 21:064x}"
            manifest_digest = f"{index + 25:064x}"
            record["candidate_sha"] = candidate
            record["run_url"] = run
            record["native_manifest_sha256"] = manifest_digest
            manifest["candidate_sha"] = candidate
            spec[lane] = (reviewed_digest, manifest_digest,
                          deepcopy(EXPECTED_IDENTITIES[lane]), deepcopy(SHAPES))
            second_reviewed.append((Path(reviewed_digest + ".json"), record))
            second_native.append((Path(manifest_digest + ".json"), manifest))
        known = {**COHORTS, (candidate, run): spec}
        self.assertEqual(set(bind_cohorts(historical_reviewed + second_reviewed,
                                          historical_native + second_native, known)), set(known))

        def repinned(data: dict) -> tuple[Path, dict]:
            digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()
            return Path(digest + ".json"), data

        bad_native = deepcopy(second_native)
        bad_native[0][1]["engine_api_max"] = "1.99"
        bad_native[0] = repinned(bad_native[0][1])
        bad_reviewed = deepcopy(second_reviewed)
        bad_reviewed[0][1]["native_manifest_sha256"] = bad_native[0][0].stem
        bad_reviewed[0] = repinned(bad_reviewed[0][1])
        repinned_spec = deepcopy(known)
        lane = LANES[0]
        _, _, identity, admission = repinned_spec[candidate, run][lane]
        repinned_spec[candidate, run][lane] = (
            bad_reviewed[0][0].stem, bad_native[0][0].stem, identity, admission,
        )
        with self.assertRaises(ValueError):
            bind_cohorts(historical_reviewed + bad_reviewed,
                         historical_native + bad_native, repinned_spec)

        bad_reviewed = deepcopy(second_reviewed)
        bad_reviewed[0][1]["capabilities"][0]["admitted_shapes"] = ["NotAdmitted"]
        bad_reviewed[0] = repinned(bad_reviewed[0][1])
        repinned_spec = deepcopy(known)
        _, manifest_digest, identity, admission = repinned_spec[candidate, run][lane]
        repinned_spec[candidate, run][lane] = (
            bad_reviewed[0][0].stem, manifest_digest, identity, admission,
        )
        with self.assertRaises(ValueError):
            bind_cohorts(historical_reviewed + bad_reviewed,
                         historical_native + second_native, repinned_spec)

        # A new capability cannot pass merely because the manual cohort and
        # reviewed envelope agree on an incomplete required_for group.
        partial = ["NetworkIpamV4", "NetworkIpamV6", "NetworkIpamGateway", "NetworkIpamRange"]
        bad_native = deepcopy(second_native)
        bad_native[0][1]["capability_outcome"]["NetworkIpam"] = "available"
        bad_native[0][1]["admitted_shapes"]["NetworkIpam"] = partial
        bad_native[0] = repinned(bad_native[0][1])
        bad_reviewed = deepcopy(second_reviewed)
        bad_reviewed[0][1]["capabilities"].append({
            "name": "NetworkIpam", "state": "available", "admitted_shapes": partial,
        })
        bad_reviewed[0][1]["native_manifest_sha256"] = bad_native[0][0].stem
        bad_reviewed[0] = repinned(bad_reviewed[0][1])
        repinned_spec = deepcopy(known)
        admission = deepcopy(SHAPES)
        admission["NetworkIpam"] = partial
        repinned_spec[candidate, run][lane] = (
            bad_reviewed[0][0].stem, bad_native[0][0].stem,
            deepcopy(EXPECTED_IDENTITIES[lane]), admission,
        )
        with self.assertRaisesRegex(ValueError, "closed admission differs from required_for shapes"):
            bind_cohorts(historical_reviewed + bad_reviewed,
                         historical_native + bad_native, repinned_spec)

        # A complete reviewed claim also requires the linked raw lane manifest
        # to contain every claimed shape, even after all digests are repinned.
        bad_native = deepcopy(second_native)
        bad_native[0][1]["admitted_shapes"]["NamedVolume"].pop()
        bad_native[0] = repinned(bad_native[0][1])
        bad_reviewed = deepcopy(second_reviewed)
        bad_reviewed[0][1]["native_manifest_sha256"] = bad_native[0][0].stem
        bad_reviewed[0] = repinned(bad_reviewed[0][1])
        repinned_spec = deepcopy(known)
        repinned_spec[candidate, run][lane] = (
            bad_reviewed[0][0].stem, bad_native[0][0].stem,
            deepcopy(EXPECTED_IDENTITIES[lane]), deepcopy(SHAPES),
        )
        with self.assertRaisesRegex(ValueError, "reviewed or raw shapes differ from closed admission"):
            bind_cohorts(historical_reviewed + bad_reviewed,
                         historical_native + bad_native, repinned_spec)

    def test_evidence_is_in_published_package_rule(self) -> None:
        manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('"docs/**"', manifest)


if __name__ == "__main__":
    unittest.main()
