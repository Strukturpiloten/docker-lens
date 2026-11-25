"""Closed CommandClear raw-source projection, never catalogue admission.

Expected lane/identity version and port outcomes belong to the accepting caller:
validated private readers in the emitter, immutable reviewed-cohort policy later.
They must not be selected from the untrusted manifest being checked.
"""

PROJECTION_CONTRACT = "command-clear-native-source-v1"
ERROR = "invalid command clear source projection"
_LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
_BASELINE = {
    "StandaloneContainer": ("StandaloneCreate",),
    "NamedVolume": ("NamedVolumeCreate", "NamedVolumeMountReadWrite", "NamedVolumeMountReadOnly"),
    "BridgeNetwork": ("BridgeNetworkCreate", "BridgeNetworkAttach"),
    "PortPublish": ("FixedTcpPort", "FixedUdpPort"),
    "BindMount": ("BindMountReadWrite", "BindMountReadOnly"),
    "EnvironmentAssignment": ("EnvironmentValue", "EnvironmentEmptyValue"),
    "Command": ("ExecCommand",),
    "Entrypoint": ("ExecEntrypoint",),
    "Healthcheck": ("ExecHealthcheck",),
    "RestartPolicy": ("RestartNo", "RestartAlways", "RestartUnlessStopped", "RestartOnFailureUnlimited", "RestartOnFailureLimited"),
    "NetworkInternal": ("InternalBridgeNetworkCreate",),
    "VolumeExternalReference": ("ExternalVolumeReference",),
    "VolumeLabels": ("VolumeCreateLabels",),
    "NetworkExternalReference": ("ExternalNetworkReference",),
    "ContainerLabels": ("ContainerCreateLabels",),
    "HealthShell": ("ShellHealthcheck",),
    "HealthStartPeriod": ("HealthStartPeriodZero", "HealthStartPeriodPositive"),
    "NetworkLabels": ("NetworkCreateLabels",),
    "NetworkAliases": ("NetworkPrimaryAliases", "NetworkSecondaryAliases"),
    "NetworkMultipleAttachment": ("NetworkSecondaryConnect",),
    "BindRelabelShared": ("BindMountSharedRelabelReadWrite", "BindMountSharedRelabelReadOnly"),
    "BindRelabelPrivate": ("BindMountPrivateRelabelReadWrite", "BindMountPrivateRelabelReadOnly"),
    "NetworkExternalInternalExpectation": ("ExternalNetworkInternalFalse", "ExternalNetworkInternalTrue"),
    "StopSignal": ("StopSignal",),
    "PortHostIpv4": ("FixedIpv4HostPort", "EphemeralIpv4HostPort"),
    "PortMultipleBindings": ("MultipleFixedPortBindings", "MultipleEphemeralPortBindings"),
    "PortExposeOnly": ("ExposedOnlyPort",),
    "PortEphemeral": ("EphemeralHostPort",),
}
_PORT_SHAPES = (
    "FixedIpv4HostPort", "EphemeralIpv4HostPort", "FixedIpv6HostPort", "EphemeralIpv6HostPort",
    "MultipleFixedPortBindings", "MultipleEphemeralPortBindings", "ExposedOnlyPort", "EphemeralHostPort",
)
_IDENTITY_CASES = [
    "inherit", "numeric_uid_gid", "numeric_uid", "named_user", "named_user_group",
    "named_user_numeric_group", "numeric_user_named_group", "missing_user", "missing_group", "nondirectory_workdir",
]


def _fail():
    raise ValueError(ERROR) from None


def _exact(actual, expected):
    if type(actual) is not type(expected):
        _fail()
    if type(expected) is dict:
        if actual.keys() != expected.keys():
            _fail()
        for key in expected:
            _exact(actual[key], expected[key])
    elif type(expected) is list:
        if len(actual) != len(expected):
            _fail()
        for left, right in zip(actual, expected):
            _exact(left, right)
    elif actual != expected:
        _fail()


def validate_command_clear_projection(record, *, expected_lane, identity_version, port_outcomes,
                                       expected_projection_contract):
    """Couple one explicit family version to exact closed baseline-plus-singleton maps.

    None explicitly selects the historical observation-only format; it is never
    upgraded to the new source format. This validates no source/run/hash custody.
    """
    try:
        if (type(expected_lane) is not str or expected_lane not in _LANES
                or type(identity_version) is not int or identity_version not in (1, 2)
                or type(record) is not dict):
            _fail()
        _exact(record["schema_version"], 1)
        _exact(record["lane"], expected_lane)
        _exact(record["expected_mode"], expected_lane.rsplit("-", 1)[1])
        if type(port_outcomes) is not list or len(port_outcomes) != len(_PORT_SHAPES):
            _fail()
        ipv6_observed = True
        for shape, entry in zip(_PORT_SHAPES, port_outcomes):
            if type(entry) is not dict:
                _fail()
            if entry.get("outcome") == "observed":
                _exact(entry, {"shape": shape, "outcome": "observed"})
            else:
                if (not expected_lane.startswith("debian11-") or shape not in _PORT_SHAPES[2:4]
                        or type(entry.get("reason")) is not str or entry["reason"] not in (
                            "nested_default_bridge_ipv6_unavailable", "nested_default_bridge_ipv6_runtime_binding_absent")):
                    _fail()
                _exact(entry, {"shape": shape, "outcome": "expected_negative", "reason": entry["reason"]})
                ipv6_observed = False
        _exact(record["port_probes"], port_outcomes)
        identity_keys = {key for key in record if key in ("identity_contract", "identity_cases")}
        if identity_version == 2:
            _exact(identity_keys, {"identity_contract", "identity_cases"})
            _exact(record["identity_contract"], "container-identity-v1")
            _exact(record["identity_cases"], _IDENTITY_CASES)
        elif identity_keys:
            _fail()
        family_keys = {key for key in record if type(key) is str and key.startswith("command_clear_")}
        keys = {"command_clear_contract", "command_clear_outcomes"}
        expected_shapes = {key: list(value) for key, value in _BASELINE.items()}
        if ipv6_observed:
            expected_shapes["PortHostIpv6"] = ["FixedIpv6HostPort", "EphemeralIpv6HostPort"]
        if identity_version == 2:
            expected_shapes.update({"ContainerUser": ["ContainerUser"], "ContainerWorkdir": ["ContainerWorkdir"]})
        _exact(record["command_clear_contract"], "command-clear-v1")
        if expected_projection_contract is None:
            _exact(family_keys, keys)
            _exact(record["command_clear_outcomes"], {
                "admission": "unadmitted", "outcome": "all_four_process_controls_verified"})
            result = "legacy_observation_only"
        else:
            _exact(expected_projection_contract, PROJECTION_CONTRACT)
            _exact(family_keys, keys | {"command_clear_projection_contract"})
            _exact(record["command_clear_projection_contract"], PROJECTION_CONTRACT)
            _exact(record["command_clear_outcomes"], {
                "source_admission": "raw_source_only", "catalogue_admission": "unadmitted",
                "capability": "CommandClear", "shapes": ["ClearCommand"],
                "scope": "explicit_exec_entrypoint_required", "outcome": "all_four_process_controls_verified"})
            expected_shapes["CommandClear"] = ["ClearCommand"]
            result = "raw_source_only"
        _exact(record["admitted_shapes"], expected_shapes)
        _exact(record["capability_outcome"], dict.fromkeys(expected_shapes, "available"))
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        _fail()
