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
IDENTITY_CANDIDATE = "032b1510524f391f08a795dab4da73f6fa8f7213"
IDENTITY_RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/37439627551/attempts/1"
IDENTITY_SHAPES = {
    **LABEL_SHAPES,
    "ContainerUser": ["ContainerUser"],
    "ContainerWorkdir": ["ContainerWorkdir"],
}
IDENTITY_PROBES = [
    "ContainerUser", "ContainerWorkdir", "ContainerNumericUidGid",
    "ContainerProcessWorkingDirectory", "ContainerIdentityOwnershipCleanup",
]
IDENTITY_CASES = [
    "inherit", "numeric_uid_gid", "numeric_uid", "named_user",
    "named_user_group", "named_user_numeric_group", "numeric_user_named_group",
    "missing_user", "missing_group", "nondirectory_workdir",
]
IDENTITY_MANIFESTS = {
    "debian11-rootful": "4972a2d7557e55b5aa44ab85534055239c18684928d7357f9a9d214d0f08aabc",
    "debian11-rootless": "8895f2267ddd005e8574e364048e9c4aa3220b887db66473016b51a0a2a2c31b",
    "upstream-rootful": "497c461ea3463cfbf82ff5256c0ec442132d9bfd32060913d0ef5a0e8f90c0f5",
    "upstream-rootless": "648f64f9d751dd5cf52ac7504a8af12267c397e395177772e10afe25f7f5d673",
}
IDENTITY_REVIEWED = {
    "debian11-rootful": "24313f10b84b8a3410906d5ad4721d3ef389ad2e09be5b59416929ef57e86b78",
    "debian11-rootless": "c9800d722f1b505f5b1e5a54d9c60e68502fceaa0779f690c5504623ec473333",
    "upstream-rootful": "b6cebf2f71be5992b112661650e37e69270d45f7d1b8e89843e843bded325020",
    "upstream-rootless": "81a1ee33c3a02d83fe6cd0f1683e1bb9b6c8774dc8aa192b2160c6ee44ba0943",
}
APPLICATION_CANDIDATE = "6df951eb9e112becf8124fe9f8624b1df0dfbf2e"
APPLICATION_RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/37706460127/attempts/1"
APPLICATION_SHAPES = {
    "BindMount": [
        "BindMountReadWrite",
        "BindMountReadOnly"
    ],
    "BindRelabelPrivate": [
        "BindMountPrivateRelabelReadWrite",
        "BindMountPrivateRelabelReadOnly"
    ],
    "BindRelabelShared": [
        "BindMountSharedRelabelReadWrite",
        "BindMountSharedRelabelReadOnly"
    ],
    "BridgeNetwork": [
        "BridgeNetworkCreate",
        "BridgeNetworkAttach"
    ],
    "Command": [
        "ExecCommand"
    ],
    "ContainerLabels": [
        "ContainerCreateLabels"
    ],
    "ContainerUser": [
        "ContainerUser"
    ],
    "ContainerWorkdir": [
        "ContainerWorkdir"
    ],
    "Entrypoint": [
        "ExecEntrypoint"
    ],
    "EnvironmentAssignment": [
        "EnvironmentValue",
        "EnvironmentEmptyValue"
    ],
    "HealthShell": [
        "ShellHealthcheck"
    ],
    "HealthStartPeriod": [
        "HealthStartPeriodZero",
        "HealthStartPeriodPositive"
    ],
    "Healthcheck": [
        "ExecHealthcheck"
    ],
    "NamedVolume": [
        "NamedVolumeCreate",
        "NamedVolumeMountReadWrite",
        "NamedVolumeMountReadOnly"
    ],
    "NetworkAliases": [
        "NetworkPrimaryAliases",
        "NetworkSecondaryAliases"
    ],
    "NetworkExternalReference": [
        "ExternalNetworkReference"
    ],
    "NetworkInternal": [
        "InternalBridgeNetworkCreate"
    ],
    "NetworkLabels": [
        "NetworkCreateLabels"
    ],
    "NetworkMultipleAttachment": [
        "NetworkSecondaryConnect"
    ],
    "PortEphemeral": [
        "EphemeralHostPort"
    ],
    "PortExposeOnly": [
        "ExposedOnlyPort"
    ],
    "PortHostIpv4": [
        "FixedIpv4HostPort",
        "EphemeralIpv4HostPort"
    ],
    "PortMultipleBindings": [
        "MultipleFixedPortBindings",
        "MultipleEphemeralPortBindings"
    ],
    "PortPublish": [
        "FixedTcpPort",
        "FixedUdpPort"
    ],
    "RestartPolicy": [
        "RestartNo",
        "RestartAlways",
        "RestartUnlessStopped",
        "RestartOnFailureUnlimited",
        "RestartOnFailureLimited"
    ],
    "StandaloneContainer": [
        "StandaloneCreate"
    ],
    "VolumeExternalReference": [
        "ExternalVolumeReference"
    ],
    "VolumeLabels": [
        "VolumeCreateLabels"
    ]
}
APPLICATION_UPSTREAM_SHAPES = {
    **APPLICATION_SHAPES,
    "PortHostIpv6": ["FixedIpv6HostPort", "EphemeralIpv6HostPort"],
}
APPLICATION_MANIFESTS = {
    "debian11-rootful": "5cdef1c4f537d44d6dc6e0e9040a4cc98760bdc10d6c50296c7824e572e43a67",
    "debian11-rootless": "c1838c7377d8a7aeed9606730dca813c6ec5c979b462bfd896d89bde7e53dd18",
    "upstream-rootful": "a6c4511598db1625565439549f4ef00d7684ed6af0809634b0222b1d0f50fdd2",
    "upstream-rootless": "cc4c7dd0045054cabdd43c222d9ef07470d3a702cc70e127931621359bae0268"
}
APPLICATION_REVIEWED = {
    "debian11-rootful": "edc6276b2caf91be8057430159524563f59dae1528cda8f342f37c1336d2fdc2",
    "debian11-rootless": "bf3b2374782342abda9bc13f07f273f22a262f1412afb16376efcf376dceac17",
    "upstream-rootful": "7eacfd00927374220e2bbe6340b62595803e8db2842b29034dc6145f73401cac",
    "upstream-rootless": "c2f380eaf9cbb8f4cdd8ca380afe350f6f97a39aeb98fc2211d531c3320d1d4a"
}
APPLICATION_ARCHIVES = {
    "dockerlens-native-upstream-rootful": {
        "id": 11520685056,
        "digest": "sha256:30c3867535885773789942e74e7d635169c18ed2b04829ffaf673473e3c159ef",
        "size": 1960
    },
    "dockerlens-native-debian11-rootful": {
        "id": 11520286786,
        "digest": "sha256:a44d43b34994516a8f5141f83d158b7dbea548ab8a415fefc846b9428f50c19c",
        "size": 2015
    },
    "dockerlens-native-debian11-rootless": {
        "id": 11520112925,
        "digest": "sha256:267ead5ec1e6e70dea94f6bd1c89a453d641ad0b59f71e96bc72cf9c77ef4e72",
        "size": 2014
    },
    "dockerlens-native-upstream-rootless": {
        "id": 11520012210,
        "digest": "sha256:091cb4f4318bb0e3965875632fe71c6746b9f18842d10d86f9850bbbe4b68d68",
        "size": 1963
    }
}
APPLICATION_CONTRACTS = {
    "health_metadata": ("health-metadata-v1", [
        "ContainerCreateLabels", "ShellHealthcheck", "HealthStartPeriodPositive", "HealthStartPeriodZero",
    ]),
    "network_attachment": ("network-attachments-v1", [
        "NetworkCreateLabels", "NetworkPrimaryAliases", "NetworkSecondaryAliases", "NetworkSecondaryConnect",
    ]),
    "bind_relabel": ("bind-relabel-config-v1", [
        "BindMountSharedRelabelReadWrite", "BindMountSharedRelabelReadOnly",
        "BindMountPrivateRelabelReadWrite", "BindMountPrivateRelabelReadOnly",
    ]),
}
EXTERNAL_CANDIDATE = "133f2857dac77c60aa79eab1a473c5749fd459ab"
EXTERNAL_RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/37788762974/attempts/1"
EXTERNAL_EXPECTATION_SHAPES = ["ExternalNetworkInternalFalse", "ExternalNetworkInternalTrue"]
EXTERNAL_SHAPES = {**APPLICATION_SHAPES,
                   "NetworkExternalInternalExpectation": EXTERNAL_EXPECTATION_SHAPES}
EXTERNAL_UPSTREAM_SHAPES = {**APPLICATION_UPSTREAM_SHAPES,
                            "NetworkExternalInternalExpectation": EXTERNAL_EXPECTATION_SHAPES}
EXTERNAL_MANIFESTS = {
    "debian11-rootful": "46ba7bb9f437161fba283adbd9dbdc2c31963f256d9e621f4044152a94988b6f",
    "debian11-rootless": "62d926303919c1accda2f483a21932d97a9afc8db492d105e16167c18b9b2c96",
    "upstream-rootful": "a4e0801a3c323fdbe4ffef214e8631d7130177217f1102ccc29a766e4ac15864",
    "upstream-rootless": "4c430cd369650f7f0f12ae64491585230967e8cd7983f5d6594204d7cb46aa39"
}
EXTERNAL_REVIEWED = {
    "debian11-rootful": "60d1a2a4892eb47bc95244194113a1d0fd24c52a1e057ce3469be433106b3d12",
    "debian11-rootless": "e014e47b24643055f01349e5a3296a938d4d88f34415f0f9bb4f1286709be29a",
    "upstream-rootful": "727db2b40c56df2f03d26b9134a35d31f2837db8ed00d5887371896ab336635e",
    "upstream-rootless": "f951bf1919e7dc039c8900f3c2144e4b71ad05e675ec54fa64406963b37dba35"
}
EXTERNAL_ARCHIVES = {
    "dockerlens-native-debian11-rootful": {
        "id": 11555628216,
        "digest": "sha256:bc7e59e2491a8fe16ef51e61f62d7a35c88c634e767f84df0db517fd2533cab3",
        "size": 2078
    },
    "dockerlens-native-debian11-rootless": {
        "id": 11555847235,
        "digest": "sha256:0c99036427d733a0f1ae87e5848a35093d5018fd6c04f79c626d0e9b83c4d8cb",
        "size": 2078
    },
    "dockerlens-native-upstream-rootful": {
        "id": 11556251694,
        "digest": "sha256:84cb87ffd1752ee66d1eacd29a75debbdd6da74f39168842b81467df100a419e",
        "size": 2022
    },
    "dockerlens-native-upstream-rootless": {
        "id": 11555702953,
        "digest": "sha256:dcc1d1d9c99cfc4e4005e3cd1e25cfff94008107ec6d3b4b6e4ff2a90b836868",
        "size": 2026
    }
}

STOP_SIGNAL_CANDIDATE = "ef8b40c2d392c3983a3ebdc54730812352fe6b39"
STOP_SIGNAL_RUN = "https://github.com/Strukturpiloten/docker-lens/actions/runs/38106164571/attempts/1"
STOP_SIGNAL_SHAPES = {**EXTERNAL_SHAPES, "StopSignal": ["StopSignal"]}
STOP_SIGNAL_UPSTREAM_SHAPES = {**EXTERNAL_UPSTREAM_SHAPES, "StopSignal": ["StopSignal"]}
STOP_SIGNAL_MANIFESTS = {
    "debian11-rootful": "27053783c2ad3dc4b28bdcd2a5a0411c859d9dcf51d4d9317f73bde8b3cb4898",
    "debian11-rootless": "e8c453818f346d606175d474805ea3d3757b0eb8729e7f566ef1fc27a89dbf57",
    "upstream-rootful": "7237f2381503997226970a2038ca43e569959b6175ce3aa69906245e41138d67",
    "upstream-rootless": "04173f9bf854c4e3b8a6e19f3fb58d5155dd75bf69076893397ae55e5983f216"
}
STOP_SIGNAL_REVIEWED = {
    "debian11-rootful": "ae366c50cb7213cf62f75b0cee002ec1f81c7ec56b0518053575c0c2f2c74033",
    "debian11-rootless": "3f207baae9a2fd58f1a02b4f2c0cc282f10ab36b70e1497ed36e7a5c58a954fd",
    "upstream-rootful": "1a128e59871f6a22c69618c5c01d5909bf928d3de4f1eb03957af6cd12c6464b",
    "upstream-rootless": "90d64a85ec81af3a1b69520555c6c160b70c8631b14519fec28e1b1fb742c95b"
}
STOP_SIGNAL_ARCHIVES = {
    "dockerlens-native-debian11-rootful": {
        "id": 11689868005,
        "digest": "sha256:1c2682b644c05ea8cb430d9680058faa5ba777173f3a8a726ff46c0d623ed2ca",
        "size": 2117
    },
    "dockerlens-native-debian11-rootless": {
        "id": 11689927730,
        "digest": "sha256:8c126a3fb99b7ad3295de776686cd7b26e365187f438d0a8123914b485dcbe17",
        "size": 2117
    },
    "dockerlens-native-upstream-rootful": {
        "id": 11689318158,
        "digest": "sha256:0e6eaea917364e744aa81ba92e51a9fc51d5f374c8f76915164e66557fe357cd",
        "size": 2063
    },
    "dockerlens-native-upstream-rootless": {
        "id": 11689542993,
        "digest": "sha256:61ddf6969bc8cfba8b77c598f0959e08765a69a86747adb8eda0ea6e48b2013d",
        "size": 2064
    }
}
STOP_SIGNAL_REVIEW_RECEIPT_SHA256 = "02485e90a14b0ab44c03388931a0532b904fa963e1b90c05f03113b892637cb1"

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
    (IDENTITY_CANDIDATE, IDENTITY_RUN): {
        lane: (IDENTITY_REVIEWED[lane], IDENTITY_MANIFESTS[lane],
               EXPECTED_IDENTITIES[lane], IDENTITY_SHAPES)
        for lane in LANES
    },
    (APPLICATION_CANDIDATE, APPLICATION_RUN): {
        lane: (APPLICATION_REVIEWED[lane], APPLICATION_MANIFESTS[lane],
               EXPECTED_IDENTITIES[lane], APPLICATION_SHAPES if lane.startswith("debian11-")
               else APPLICATION_UPSTREAM_SHAPES)
        for lane in LANES
    },
    (EXTERNAL_CANDIDATE, EXTERNAL_RUN): {
        lane: (EXTERNAL_REVIEWED[lane], EXTERNAL_MANIFESTS[lane],
               EXPECTED_IDENTITIES[lane], EXTERNAL_SHAPES if lane.startswith("debian11-")
               else EXTERNAL_UPSTREAM_SHAPES)
        for lane in LANES
    },
    (STOP_SIGNAL_CANDIDATE, STOP_SIGNAL_RUN): {
        lane: (STOP_SIGNAL_REVIEWED[lane], STOP_SIGNAL_MANIFESTS[lane],
               EXPECTED_IDENTITIES[lane], STOP_SIGNAL_SHAPES if lane.startswith("debian11-")
               else STOP_SIGNAL_UPSTREAM_SHAPES)
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
        result.append((path, strict_public_json(content)))
    return result


def strict_public_json(raw: bytes) -> dict:
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate public key")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("nonfinite public value")

    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    if type(result) is not dict:
        raise ValueError("public root")
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
            if {"ContainerUser", "ContainerWorkdir"} & set(expected_admission):
                if (manifest.get("identity_contract") != "container-identity-v1"
                        or manifest.get("identity_cases") != IDENTITY_CASES
                        or manifest.get("identity_probes") != IDENTITY_PROBES):
                    raise ValueError("identity admission requires complete parameterized proof markers")
            if cohort_key in ((APPLICATION_CANDIDATE, APPLICATION_RUN), (EXTERNAL_CANDIDATE, EXTERNAL_RUN),
                              (STOP_SIGNAL_CANDIDATE, STOP_SIGNAL_RUN)):
                if (manifest["admitted_shapes"] != expected_admission
                        or manifest["capability_outcome"] != dict.fromkeys(expected_admission, "available")
                        or manifest.get("bind_relabel_selinux_effect") != "unverified"):
                    raise ValueError("application admission requires exact raw groups and unverified SELinux effects")
                for prefix, (contract, probes) in APPLICATION_CONTRACTS.items():
                    if (manifest.get(f"{prefix}_contract") != contract
                            or manifest.get(f"{prefix}_probes") != probes):
                        raise ValueError("application admission requires complete source projection")
                port_shapes = [
                    "FixedIpv4HostPort", "EphemeralIpv4HostPort",
                    "FixedIpv6HostPort", "EphemeralIpv6HostPort",
                    "MultipleFixedPortBindings", "MultipleEphemeralPortBindings",
                    "ExposedOnlyPort", "EphemeralHostPort",
                ]
                ports = [{"shape": shape, "outcome": "observed"} for shape in port_shapes]
                if lane.startswith("debian11-"):
                    for entry in ports[2:4]:
                        entry.update(outcome="expected_negative",
                                     reason="nested_default_bridge_ipv6_runtime_binding_absent")
                if manifest.get("port_probes") != ports:
                    raise ValueError("application admission requires exact per-lane port outcomes")
            if cohort_key in ((EXTERNAL_CANDIDATE, EXTERNAL_RUN), (STOP_SIGNAL_CANDIDATE, STOP_SIGNAL_RUN)):
                if (manifest.get("external_network_contract") != "external-network-internal-v1"
                        or manifest.get("external_network_probes") != EXTERNAL_EXPECTATION_SHAPES):
                    raise ValueError("external admission requires complete independent source projection")
            if cohort_key == (STOP_SIGNAL_CANDIDATE, STOP_SIGNAL_RUN):
                if (manifest.get("stop_signal_contract") != "stop-signal-v1"
                        or manifest.get("stop_signal_probes") != ["StopSignal"]):
                    raise ValueError("stop signal admission requires complete independent source projection")
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
            for lane, (path, _) in indexed_cohorts(hashed_json("reviewed"), COHORTS)[STOP_SIGNAL_CANDIDATE, STOP_SIGNAL_RUN].items()
        }
        self.assertEqual({match["variant"] for match in tuples}, set(LANE_VARIANTS))
        for match in tuples:
            lane = LANE_VARIANTS[match["variant"]]
            self.assertEqual(match["digest"], reviewed[lane])
            self.assertEqual(match["path_digest"], reviewed[lane])
            self.assertEqual(match["digest"], STOP_SIGNAL_REVIEWED[lane])

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

    def test_compiled_candidate_has_exact_per_lane_complete_groups(self) -> None:
        source = (ROOT / "src/reviewed_catalog.rs").read_text(encoding="utf-8")
        self.assertIn(f'const SOURCE_CANDIDATE: &str = "{STOP_SIGNAL_CANDIDATE}";', source)
        self.assertIn(f'"{STOP_SIGNAL_RUN}";', source)
        for prefix, expected, counts in (
                ("REVIEWED", STOP_SIGNAL_SHAPES, (30, 47)),
                ("UPSTREAM", STOP_SIGNAL_UPSTREAM_SHAPES, (31, 49))):
            capabilities = source.split(f"const {prefix}_CAPABILITIES:", 1)[1].split("];", 1)[0]
            shapes = source.split(f"const {prefix}_SHAPES:", 1)[1].split("];", 1)[0]
            capability_names = re.findall(r"Capability::(\w+)", capabilities)
            shape_names = re.findall(r"NativeCapabilityShape::(\w+)", shapes)
            self.assertEqual(len(capability_names), counts[0])
            self.assertEqual(set(capability_names), set(expected))
            self.assertEqual(len(shape_names), counts[1])
            self.assertEqual(set(shape_names), {shape for group in expected.values() for shape in group})
        selection = source.split("fn expected_admission(", 1)[1].split("const RECORDS:", 1)[0]
        self.assertRegex(selection, r"Debian11Rootful\s*\|\s*NativeEvidenceLane::Debian11Rootless\s*=>\s*\{\s*\(REVIEWED_CAPABILITIES, REVIEWED_SHAPES\)")
        self.assertRegex(selection, r"UpstreamRootful\s*\|\s*NativeEvidenceLane::UpstreamRootless\s*=>\s*\{\s*\(UPSTREAM_CAPABILITIES, UPSTREAM_SHAPES\)")



    def test_application_public_provenance_binds_independently_reviewed_api_receipt(self) -> None:
        receipt = json.loads((ROOT / "docs/evidence/application-cohort-37706460127.json").read_text())
        self.assertEqual(receipt["repository"], {"id": 1387403220, "full_name": "Strukturpiloten/docker-lens"})
        self.assertEqual(receipt["candidate_sha"], APPLICATION_CANDIDATE)
        self.assertEqual(receipt["run"]["id"], 37706460127)
        self.assertEqual(receipt["run"]["attempt"], 1)
        self.assertEqual(receipt["run"]["dispatcher_sha"], "719aeedf58f81a578b27649a81a2f26065115374")
        self.assertNotEqual(receipt["candidate_sha"], receipt["run"]["dispatcher_sha"])
        self.assertEqual(receipt["run"]["event"], "workflow_dispatch")
        self.assertEqual(receipt["run"]["workflow_path"], ".github/workflows/native-validation.yml")
        self.assertEqual(receipt["run"]["workflow_ref"], "refs/heads/main")
        self.assertEqual(receipt["run"]["conclusion"], "success")
        self.assertEqual(receipt["review"]["native_tests_each_lane"], 14)
        self.assertEqual(receipt["review"]["public_artifact_controls"], 51)
        self.assertEqual(receipt["review"]["acceptance_comment"],
                         "https://github.com/Strukturpiloten/docker-lens/pull/99#issuecomment-6049645585")
        self.assertEqual(receipt["selinux_effect"], "unverified")
        artifacts = receipt["artifacts"]
        self.assertEqual(len(artifacts), 4)
        self.assertEqual({item["name"] for item in artifacts}, set(APPLICATION_ARCHIVES))
        for artifact in artifacts:
            expected = APPLICATION_ARCHIVES[artifact["name"]]
            self.assertEqual(artifact["id"], expected["id"])
            self.assertEqual(artifact["archive_api_digest"], expected["digest"])
            self.assertEqual(artifact["size"], expected["size"])
            self.assertFalse(artifact["expired"])
            lane = artifact["name"].removeprefix("dockerlens-native-")
            self.assertEqual(artifact["member_name"], f"{lane}.json")
            self.assertEqual(artifact["native_manifest_sha256"], APPLICATION_MANIFESTS[lane])
            self.assertEqual(artifact["reviewed_record_sha256"], APPLICATION_REVIEWED[lane])
        jobs = receipt["jobs"]
        self.assertEqual(len(jobs), 7)
        self.assertEqual({job["id"] for job in jobs}, {
            113081887680, 113081926043, 113083692059, 113083692072,
            113083692073, 113083692171, 113084563786,
        })
        for job in jobs:
            self.assertEqual(job["conclusion"], "success")
            self.assertRegex(job["authenticated_log_sha256"], r"^[0-9a-f]{64}$")
        forbidden = {"runtime_uid", "outer_id", "container_id", "network_id", "owner",
                     "signed_url", "token", "credential", "private_proof", "log_body"}
        def check_public(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(set(value).isdisjoint(forbidden))
                for child in value.values():
                    check_public(child)
            elif isinstance(value, list):
                for child in value:
                    check_public(child)
        check_public(receipt)

    def test_application_cohort_binds_exact_groups_and_preserves_all_history(self) -> None:
        reviewed = bind_cohorts(hashed_json("reviewed"), hashed_json("native"), COHORTS)
        self.assertEqual(len(reviewed), 7)
        for lane, (path, record) in reviewed[APPLICATION_CANDIDATE, APPLICATION_RUN].items():
            expected = APPLICATION_SHAPES if lane.startswith("debian11-") else APPLICATION_UPSTREAM_SHAPES
            self.assertEqual(path.stem, APPLICATION_REVIEWED[lane])
            self.assertEqual(record["native_manifest_sha256"], APPLICATION_MANIFESTS[lane])
            self.assertEqual({entry["name"]: entry["admitted_shapes"] for entry in record["capabilities"]},
                             expected)
            self.assertEqual(len(expected), 28 if lane.startswith("debian11-") else 29)
            self.assertEqual(sum(map(len, expected.values())), 44 if lane.startswith("debian11-") else 46)
            self.assertEqual({name: expected[name] for name in IDENTITY_SHAPES}, IDENTITY_SHAPES)
            self.assertEqual("PortHostIpv6" in expected, lane.startswith("upstream-"))
            for name in ("NetworkIpv6", "NetworkIpam", "NetworkOptions", "NetworkStaticAddress",
                         "ContainerInit", "MemoryLimit", "DeviceMappings", "HealthDisabled", "HealthStartInterval"):
                self.assertNotIn(name, expected)

    def test_application_groups_reject_partial_wrong_and_nonpositive_evidence(self) -> None:
        reviewed_records = hashed_json("reviewed")
        native_records = hashed_json("native")
        for lane in LANES:
            expected = APPLICATION_SHAPES if lane.startswith("debian11-") else APPLICATION_UPSTREAM_SHAPES
            for name in set(expected) - set(IDENTITY_SHAPES):
                for side in ("raw", "reviewed"):
                    for fault in ("missing", "partial", "duplicate", "wrong", "unavailable", "unknown"):
                        reviewed, native = deepcopy(reviewed_records), deepcopy(native_records)
                        manifest = next(data for path, data in native if path.stem == APPLICATION_MANIFESTS[lane])
                        record = next(data for path, data in reviewed if path.stem == APPLICATION_REVIEWED[lane])
                        entry = next(entry for entry in record["capabilities"] if entry["name"] == name)
                        if fault == "missing":
                            if side == "raw":
                                del manifest["admitted_shapes"][name]
                            else:
                                record["capabilities"].remove(entry)
                        elif fault in ("unavailable", "unknown"):
                            if side == "raw":
                                manifest["capability_outcome"][name] = fault
                            else:
                                entry["state"] = fault
                        else:
                            shapes = expected[name][:-1] if fault == "partial" else (
                                [*expected[name], expected[name][0]] if fault == "duplicate" else ["StandaloneCreate"])
                            if side == "raw":
                                manifest["admitted_shapes"][name] = shapes
                            else:
                                entry["admitted_shapes"] = shapes
                        with self.subTest(lane=lane, name=name, side=side, fault=fault):
                            with self.assertRaises(ValueError):
                                bind_cohorts(reviewed, native, COHORTS)

    def test_application_projection_cannot_promote_controls_or_selinux_effects(self) -> None:
        reviewed = hashed_json("reviewed")
        originals = hashed_json("native")
        for lane in LANES:
            for key, fault in [
                ("bind_relabel_selinux_effect", "verified"),
                ("port_probes", []),
                *[(f"{prefix}_{field}", "" if field == "contract" else probes[:-1])
                  for prefix, (_, probes) in APPLICATION_CONTRACTS.items()
                  for field in ("contract", "probes")],
            ]:
                native = deepcopy(originals)
                manifest = next(data for path, data in native if path.stem == APPLICATION_MANIFESTS[lane])
                manifest[key] = fault
                with self.subTest(lane=lane, key=key):
                    with self.assertRaises(ValueError):
                        bind_cohorts(reviewed, native, COHORTS)
        for lane in LANES[:2]:
            native = deepcopy(originals)
            manifest = next(data for path, data in native if path.stem == APPLICATION_MANIFESTS[lane])
            manifest["admitted_shapes"]["PortHostIpv6"] = APPLICATION_UPSTREAM_SHAPES["PortHostIpv6"]
            manifest["capability_outcome"]["PortHostIpv6"] = "available"
            with self.assertRaises(ValueError):
                bind_cohorts(reviewed, native, COHORTS)

    def test_identity_cohort_adds_only_two_singleton_groups_and_preserves_history(self) -> None:
        reviewed = bind_cohorts(hashed_json("reviewed"), hashed_json("native"), COHORTS)
        raw = indexed_native_manifests(hashed_json("native"), COHORTS)
        self.assertEqual(len(reviewed), 7)
        self.assertEqual(len(IDENTITY_SHAPES), 16)
        self.assertEqual(sum(map(len, IDENTITY_SHAPES.values())), 26)
        self.assertEqual(set(IDENTITY_SHAPES) - set(LABEL_SHAPES),
                         {"ContainerUser", "ContainerWorkdir"})
        for lane, (path, record) in reviewed[IDENTITY_CANDIDATE, IDENTITY_RUN].items():
            with self.subTest(lane=lane):
                self.assertEqual(path.stem, IDENTITY_REVIEWED[lane])
                self.assertEqual(record["native_manifest_sha256"], IDENTITY_MANIFESTS[lane])
                self.assertEqual(record["identity"], EXPECTED_IDENTITIES[lane])
                claims = {entry["name"]: entry["admitted_shapes"] for entry in record["capabilities"]}
                manifest = raw[IDENTITY_MANIFESTS[lane]][1]
                self.assertEqual(claims, IDENTITY_SHAPES)
                self.assertEqual(manifest["admitted_shapes"], IDENTITY_SHAPES)
                self.assertEqual(manifest["capability_outcome"],
                                 dict.fromkeys(IDENTITY_SHAPES, "available"))
                self.assertEqual(manifest["identity_contract"], "container-identity-v1")
                self.assertEqual(manifest["identity_cases"], IDENTITY_CASES)
                self.assertEqual(manifest["identity_probes"], IDENTITY_PROBES)
                for name, shapes in LABEL_SHAPES.items():
                    self.assertEqual(claims[name], shapes)
                for name in ("SupplementaryGroups", "UserNamespace", "PortHostIpv4"):
                    self.assertNotIn(name, claims)

    def test_identity_admission_rejects_legacy_partial_or_reordered_proof_markers(self) -> None:
        reviewed_records = hashed_json("reviewed")
        native_records = hashed_json("native")
        for lane in LANES:
            for field, expected in (
                ("identity_cases", IDENTITY_CASES),
                ("identity_probes", IDENTITY_PROBES),
            ):
                for fault in (None, [], expected[:-1], expected[::-1], [*expected, expected[0]]):
                    native = deepcopy(native_records)
                    manifest = next(data for path, data in native if path.stem == IDENTITY_MANIFESTS[lane])
                    if fault is None:
                        del manifest[field]
                    else:
                        manifest[field] = fault
                    with self.subTest(lane=lane, field=field, fault=fault):
                        with self.assertRaises(ValueError):
                            bind_cohorts(reviewed_records, native, COHORTS)
            for contract in (None, "", "container-identity-v2"):
                native = deepcopy(native_records)
                manifest = next(data for path, data in native if path.stem == IDENTITY_MANIFESTS[lane])
                if contract is None:
                    del manifest["identity_contract"]
                else:
                    manifest["identity_contract"] = contract
                with self.subTest(lane=lane, contract=contract):
                    with self.assertRaises(ValueError):
                        bind_cohorts(reviewed_records, native, COHORTS)

    def test_identity_groups_require_complete_positive_linked_raw_and_reviewed_evidence(self) -> None:
        reviewed_records = hashed_json("reviewed")
        native_records = hashed_json("native")
        for lane in LANES:
            for name in ("ContainerUser", "ContainerWorkdir"):
                for side in ("raw", "reviewed"):
                    for fault in ("missing", "empty", "duplicate", "wrong_group", "unavailable", "unknown"):
                        reviewed = deepcopy(reviewed_records)
                        native = deepcopy(native_records)
                        wrong_shape = "ContainerWorkdir" if name == "ContainerUser" else "ContainerUser"
                        if side == "raw":
                            manifest = next(data for path, data in native if path.stem == IDENTITY_MANIFESTS[lane])
                            if fault == "missing":
                                del manifest["admitted_shapes"][name]
                            elif fault == "empty":
                                manifest["admitted_shapes"][name] = []
                            elif fault == "duplicate":
                                manifest["admitted_shapes"][name] *= 2
                            elif fault == "wrong_group":
                                manifest["admitted_shapes"][name] = [wrong_shape]
                            else:
                                manifest["capability_outcome"][name] = fault
                        else:
                            record = next(data for path, data in reviewed if path.stem == IDENTITY_REVIEWED[lane])
                            entry = next(entry for entry in record["capabilities"] if entry["name"] == name)
                            if fault == "missing":
                                record["capabilities"].remove(entry)
                            elif fault == "empty":
                                entry["admitted_shapes"] = []
                            elif fault == "duplicate":
                                entry["admitted_shapes"] *= 2
                            elif fault == "wrong_group":
                                entry["admitted_shapes"] = [wrong_shape]
                            else:
                                entry["state"] = fault
                        with self.subTest(lane=lane, group=name, side=side, fault=fault):
                            with self.assertRaises(ValueError):
                                bind_cohorts(reviewed, native, COHORTS)

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


    def test_external_cohort_is_exact_append_only_and_publicly_authenticated(self) -> None:
        native = hashed_json("native")
        reviewed = bind_cohorts(hashed_json("reviewed"), native, COHORTS)
        self.assertEqual(len(reviewed), 7)
        raw = indexed_native_manifests(native, COHORTS)
        for lane, (path, record) in reviewed[EXTERNAL_CANDIDATE, EXTERNAL_RUN].items():
            expected = EXTERNAL_SHAPES if lane.startswith("debian11-") else EXTERNAL_UPSTREAM_SHAPES
            prior = APPLICATION_SHAPES if lane.startswith("debian11-") else APPLICATION_UPSTREAM_SHAPES
            self.assertEqual(path.stem, EXTERNAL_REVIEWED[lane])
            self.assertEqual(record["native_manifest_sha256"], EXTERNAL_MANIFESTS[lane])
            self.assertEqual({entry["name"]: entry["admitted_shapes"] for entry in record["capabilities"]}, expected)
            self.assertEqual({name: shapes for name, shapes in expected.items()
                              if name != "NetworkExternalInternalExpectation"}, prior)
            self.assertEqual((len(expected), sum(map(len, expected.values()))),
                             (29, 46) if lane.startswith("debian11-") else (30, 48))
            manifest = raw[EXTERNAL_MANIFESTS[lane]][1]
            self.assertEqual(manifest["external_network_contract"], "external-network-internal-v1")
            self.assertEqual(manifest["external_network_probes"], EXTERNAL_EXPECTATION_SHAPES)
            self.assertEqual(manifest["admitted_shapes"]["NetworkInternal"], ["InternalBridgeNetworkCreate"])
        provenance = json.loads((ROOT / "docs/evidence/external-network-cohort-37788762974.json").read_text())
        self.assertEqual(provenance["candidate_sha"], EXTERNAL_CANDIDATE)
        self.assertEqual(provenance["repository"], {"id": 1387403220, "full_name": "Strukturpiloten/docker-lens"})
        self.assertEqual(provenance["pull_request"], 105)
        self.assertEqual(provenance["run"], {
            "id": 37788762974, "attempt": 1, "event": "workflow_dispatch",
            "workflow_path": ".github/workflows/native-validation.yml",
            "workflow_ref": "refs/heads/main",
            "dispatcher_sha": "3742f1136e7921260ffab149ffb47dfecea522d4", "conclusion": "success",
        })
        self.assertNotEqual(provenance["candidate_sha"], provenance["run"]["dispatcher_sha"])
        self.assertEqual(provenance["review"]["native_tests_each_lane"], 15)
        self.assertEqual(provenance["selinux_effect"], "unverified")
        self.assertEqual(provenance["admission_counts"],
                         {"debian": {"capabilities": 29, "shapes": 46},
                          "upstream": {"capabilities": 30, "shapes": 48}})
        self.assertEqual(len(provenance["artifacts"]), 4)
        for artifact in provenance["artifacts"]:
            self.assertFalse(artifact["expired"])
            lane = artifact["name"].removeprefix("dockerlens-native-")
            independent = EXTERNAL_ARCHIVES[artifact["name"]]
            self.assertEqual((artifact["id"], artifact["archive_api_digest"], artifact["size"]),
                             (independent["id"], independent["digest"], independent["size"]))
            self.assertEqual(artifact["member_name"], lane + ".json")
            self.assertEqual(artifact["native_manifest_sha256"], EXTERNAL_MANIFESTS[lane])
            self.assertEqual(artifact["reviewed_record_sha256"], EXTERNAL_REVIEWED[lane])
        self.assertEqual({job["id"] for job in provenance["jobs"]}, {113350256152,113350317080,113353241616,113353241618,113353241623,113353241736,113354704194})
        self.assertTrue(all(job["conclusion"] == "success" for job in provenance["jobs"]))
        forbidden = {"runtime_uid", "outer_id", "container_id", "network_id", "owner",
                     "signed_url", "token", "credential", "private_proof", "log_body"}
        def closed_public(value):
            if isinstance(value, dict):
                self.assertTrue(set(value).isdisjoint(forbidden))
                for child in value.values():
                    closed_public(child)
            elif isinstance(value, list):
                for child in value:
                    closed_public(child)
        closed_public(provenance)

    def test_stop_signal_cohort_retains_every_prior_field_and_adds_only_singleton(self) -> None:
        native = hashed_json("native")
        raw = indexed_native_manifests(native, COHORTS)
        reviewed = bind_cohorts(hashed_json("reviewed"), native, COHORTS)
        self.assertEqual(len(reviewed), 7)
        for lane in LANES:
            manifest = deepcopy(raw[STOP_SIGNAL_MANIFESTS[lane]][1])
            prior_manifest = raw[EXTERNAL_MANIFESTS[lane]][1]
            self.assertEqual(manifest.pop("stop_signal_contract"), "stop-signal-v1")
            self.assertEqual(manifest.pop("stop_signal_probes"), ["StopSignal"])
            self.assertEqual(manifest["admitted_shapes"].pop("StopSignal"), ["StopSignal"])
            self.assertEqual(manifest["capability_outcome"].pop("StopSignal"), "available")
            manifest["candidate_sha"] = prior_manifest["candidate_sha"]
            self.assertEqual(manifest, prior_manifest)

            path, record = reviewed[STOP_SIGNAL_CANDIDATE, STOP_SIGNAL_RUN][lane]
            prior_record = reviewed[EXTERNAL_CANDIDATE, EXTERNAL_RUN][lane][1]
            expected = STOP_SIGNAL_SHAPES if lane.startswith("debian11-") else STOP_SIGNAL_UPSTREAM_SHAPES
            self.assertEqual(path.stem, STOP_SIGNAL_REVIEWED[lane])
            self.assertEqual(record["native_manifest_sha256"], STOP_SIGNAL_MANIFESTS[lane])
            self.assertEqual({entry["name"]: entry["admitted_shapes"] for entry in record["capabilities"]}, expected)
            self.assertEqual((len(expected), sum(map(len, expected.values()))),
                             (30, 47) if lane.startswith("debian11-") else (31, 49))
            self.assertNotIn("HealthStartInterval", expected)
            retained = deepcopy(record)
            retained["capabilities"] = [entry for entry in retained["capabilities"] if entry["name"] != "StopSignal"]
            for field in ("candidate_sha", "run_url", "native_manifest_sha256"):
                retained[field] = prior_record[field]
            self.assertEqual(retained, prior_record)

    def test_stop_signal_public_provenance_binds_independent_sanitized_receipt(self) -> None:
        path = ROOT / "docs/evidence/stop-signal-cohort-38106164571.json"
        provenance = strict_public_json(path.read_bytes())
        receipt = provenance["independent_source_review"]
        self.assertEqual(receipt["receipt_sha256"], STOP_SIGNAL_REVIEW_RECEIPT_SHA256)
        self.assertEqual(receipt["receipt_path"], "docs/evidence/stop-signal-independent-review-38106164571.json")
        raw = (ROOT / receipt["receipt_path"]).read_bytes()
        metadata = strict_public_json(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), STOP_SIGNAL_REVIEW_RECEIPT_SHA256)
        self.assertEqual(metadata["candidate_sha"], STOP_SIGNAL_CANDIDATE)
        self.assertEqual(provenance["candidate_sha"], STOP_SIGNAL_CANDIDATE)
        self.assertEqual(provenance["run"], metadata["run"])
        self.assertEqual(provenance["run"]["id"], 38106164571)
        self.assertEqual(provenance["run"]["attempt"], 1)
        self.assertEqual(provenance["run"]["dispatcher_sha"], "dd8c29435ff7734a567eb1ed4cda7d422d946bcb")
        self.assertNotEqual(provenance["candidate_sha"], provenance["run"]["dispatcher_sha"])
        self.assertEqual(provenance["repository"], {"id": 1387403220, "full_name": "Strukturpiloten/docker-lens"})
        self.assertEqual(provenance["pull_request"], 113)
        self.assertEqual(provenance["review"]["native_tests_each_lane"], 16)
        self.assertEqual(provenance["selinux_effect"], "unverified")
        self.assertEqual(provenance["admission_counts"],
                         {"debian": {"capabilities": 30, "shapes": 47},
                          "upstream": {"capabilities": 31, "shapes": 49}})
        self.assertTrue(all(metadata["independent_api_authentication"].values()))
        closed = metadata["closed_log_observations"]
        self.assertTrue(closed["all_sixteen_required_tests_passed_once_in_order_each_lane"])
        self.assertTrue(closed["native_success_emitted_after_outer_cleanup_each_lane"])
        self.assertFalse(closed["raw_logs_saved"])
        self.assertFalse(closed["raw_logs_printed"])
        self.assertEqual(provenance["jobs"], metadata["jobs"])
        self.assertEqual({job["id"] for job in provenance["jobs"]},
                         {114372045090, 114372068304, 114373096696, 114373096727,
                          114373096744, 114373096796, 114373578811})
        self.assertTrue(all(job["conclusion"] == "success" for job in provenance["jobs"]))
        self.assertEqual(len(provenance["artifacts"]), 4)
        for artifact in provenance["artifacts"]:
            lane = artifact["name"].removeprefix("dockerlens-native-")
            independent = STOP_SIGNAL_ARCHIVES[artifact["name"]]
            self.assertEqual((artifact["id"], artifact["archive_api_digest"], artifact["size"]),
                             (independent["id"], independent["digest"], independent["size"]))
            self.assertFalse(artifact["expired"])
            self.assertEqual(artifact["member_name"], lane + ".json")
            self.assertEqual(artifact["native_manifest_sha256"], STOP_SIGNAL_MANIFESTS[lane])
            self.assertEqual(artifact["reviewed_record_sha256"], STOP_SIGNAL_REVIEWED[lane])
        self.assertIn("sixteen", provenance["remaining_gates"][1])
        self.assertIn("six", provenance["remaining_gates"][2])
        self.assertIn("Nextcloud and Supabase", provenance["remaining_gates"][3])
        self.assertFalse(provenance["maintenance"]["pin_changes"])
        for source, digest in metadata["source_sha256"].items():
            if source.startswith(("scripts/", "src/")):
                self.assertEqual(hashlib.sha256((ROOT / source).read_bytes()).hexdigest(), digest)

    def test_stop_signal_refuses_missing_duplicate_unrelated_and_nonpositive_evidence(self) -> None:
        for lane in LANES:
            for side in ("raw", "reviewed"):
                for fault in ("missing", "empty", "duplicate", "health_interval", "unavailable", "unknown"):
                    reviewed = deepcopy(hashed_json("reviewed"))
                    native = deepcopy(hashed_json("native"))
                    manifest = next(value for path, value in native if path.stem == STOP_SIGNAL_MANIFESTS[lane])
                    record = next(value for path, value in reviewed if path.stem == STOP_SIGNAL_REVIEWED[lane])
                    entry = next(value for value in record["capabilities"] if value["name"] == "StopSignal")
                    if fault == "missing":
                        if side == "raw":
                            del manifest["admitted_shapes"]["StopSignal"]
                        else:
                            record["capabilities"].remove(entry)
                    elif fault in ("unavailable", "unknown"):
                        if side == "raw":
                            manifest["capability_outcome"]["StopSignal"] = fault
                        else:
                            entry["state"] = fault
                    else:
                        shapes = {"empty": [], "duplicate": ["StopSignal", "StopSignal"],
                                  "health_interval": ["HealthStartInterval"]}[fault]
                        if side == "raw":
                            manifest["admitted_shapes"]["StopSignal"] = shapes
                        else:
                            entry["admitted_shapes"] = shapes
                    with self.subTest(lane=lane, side=side, fault=fault), self.assertRaises(ValueError):
                        bind_cohorts(reviewed, native, COHORTS)
            for key, value in (("stop_signal_contract", None), ("stop_signal_contract", "other-v1"),
                               ("stop_signal_probes", []), ("stop_signal_probes", ["StopSignal"] * 2)):
                native = deepcopy(hashed_json("native"))
                manifest = next(value for path, value in native if path.stem == STOP_SIGNAL_MANIFESTS[lane])
                manifest[key] = value
                with self.subTest(lane=lane, key=key, value=value), self.assertRaises(ValueError):
                    bind_cohorts(hashed_json("reviewed"), native, COHORTS)

    def test_stop_signal_public_reader_refuses_duplicate_and_nonfinite_metadata(self) -> None:
        for raw in (b'{"x":1,"x":1}', b'{"x":{"a":1,"a":2}}', b'{"x":NaN}',
                    b'{"x":Infinity}', b'{"x":-Infinity}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_public_json(raw)

    def test_external_group_rejects_partial_created_bridge_and_nonpositive_evidence(self) -> None:
        for lane in LANES:
            for side in ("raw", "reviewed"):
                for fault in ("missing", "false_only", "true_only", "duplicate", "created_bridge", "unavailable", "unknown"):
                    reviewed = deepcopy(hashed_json("reviewed"))
                    native = deepcopy(hashed_json("native"))
                    manifest = next(value for path, value in native if path.stem == EXTERNAL_MANIFESTS[lane])
                    record = next(value for path, value in reviewed if path.stem == EXTERNAL_REVIEWED[lane])
                    name = "NetworkExternalInternalExpectation"
                    entry = next(value for value in record["capabilities"] if value["name"] == name)
                    if fault == "missing":
                        if side == "raw":
                            del manifest["admitted_shapes"][name]
                        else:
                            record["capabilities"].remove(entry)
                    elif fault in ("unavailable", "unknown"):
                        if side == "raw":
                            manifest["capability_outcome"][name] = fault
                        else:
                            entry["state"] = fault
                    else:
                        shapes = {"false_only": [EXTERNAL_EXPECTATION_SHAPES[0]],
                                  "true_only": [EXTERNAL_EXPECTATION_SHAPES[1]],
                                  "duplicate": [EXTERNAL_EXPECTATION_SHAPES[0]] * 2,
                                  "created_bridge": ["InternalBridgeNetworkCreate"]}[fault]
                        if side == "raw":
                            manifest["admitted_shapes"][name] = shapes
                        else:
                            entry["admitted_shapes"] = shapes
                    with self.subTest(lane=lane, side=side, fault=fault), self.assertRaises(ValueError):
                        bind_cohorts(reviewed, native, COHORTS)


if __name__ == "__main__":
    unittest.main()
