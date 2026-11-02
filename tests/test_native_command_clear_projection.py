"""Literal independent raw maps/version controls; these are not source qualification."""

from copy import deepcopy
import contextlib
import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from native_command_clear_projection import validate_command_clear_projection

LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
CONTRACT = "command-clear-native-source-v1"
SECRET = "PRIVATE_COMMAND_CLEAR_PROJECTION_CANARY"
# Literal expected baseline, independent of both emitter and production validator.
BASELINE = {
    "StandaloneContainer": ["StandaloneCreate"],
    "NamedVolume": ["NamedVolumeCreate", "NamedVolumeMountReadWrite", "NamedVolumeMountReadOnly"],
    "BridgeNetwork": ["BridgeNetworkCreate", "BridgeNetworkAttach"],
    "PortPublish": ["FixedTcpPort", "FixedUdpPort"],
    "BindMount": ["BindMountReadWrite", "BindMountReadOnly"],
    "EnvironmentAssignment": ["EnvironmentValue", "EnvironmentEmptyValue"],
    "Command": ["ExecCommand"], "Entrypoint": ["ExecEntrypoint"], "Healthcheck": ["ExecHealthcheck"],
    "RestartPolicy": ["RestartNo", "RestartAlways", "RestartUnlessStopped", "RestartOnFailureUnlimited", "RestartOnFailureLimited"],
    "NetworkInternal": ["InternalBridgeNetworkCreate"],
    "VolumeExternalReference": ["ExternalVolumeReference"], "VolumeLabels": ["VolumeCreateLabels"],
    "NetworkExternalReference": ["ExternalNetworkReference"], "ContainerLabels": ["ContainerCreateLabels"],
    "HealthShell": ["ShellHealthcheck"], "HealthStartPeriod": ["HealthStartPeriodZero", "HealthStartPeriodPositive"],
    "NetworkLabels": ["NetworkCreateLabels"], "NetworkAliases": ["NetworkPrimaryAliases", "NetworkSecondaryAliases"],
    "NetworkMultipleAttachment": ["NetworkSecondaryConnect"],
    "BindRelabelShared": ["BindMountSharedRelabelReadWrite", "BindMountSharedRelabelReadOnly"],
    "BindRelabelPrivate": ["BindMountPrivateRelabelReadWrite", "BindMountPrivateRelabelReadOnly"],
    "NetworkExternalInternalExpectation": ["ExternalNetworkInternalFalse", "ExternalNetworkInternalTrue"],
    "StopSignal": ["StopSignal"], "PortHostIpv4": ["FixedIpv4HostPort", "EphemeralIpv4HostPort"],
    "PortMultipleBindings": ["MultipleFixedPortBindings", "MultipleEphemeralPortBindings"],
    "PortExposeOnly": ["ExposedOnlyPort"], "PortEphemeral": ["EphemeralHostPort"],
}
PORTS = ["FixedIpv4HostPort", "EphemeralIpv4HostPort", "FixedIpv6HostPort", "EphemeralIpv6HostPort",
         "MultipleFixedPortBindings", "MultipleEphemeralPortBindings", "ExposedOnlyPort", "EphemeralHostPort"]
CASES = ["inherit", "numeric_uid_gid", "numeric_uid", "named_user", "named_user_group",
         "named_user_numeric_group", "numeric_user_named_group", "missing_user", "missing_group", "nondirectory_workdir"]
OUTCOME = {"source_admission": "raw_source_only", "catalogue_admission": "unadmitted",
           "capability": "CommandClear", "shapes": ["ClearCommand"],
           "scope": "explicit_exec_entrypoint_required", "outcome": "all_four_process_controls_verified"}


def ports(lane, *, fully_observed=False):
    entries = [{"shape": shape, "outcome": "observed"} for shape in PORTS]
    if lane.startswith("debian11-") and not fully_observed:
        for entry in entries[2:4]:
            entry.update(outcome="expected_negative", reason="nested_default_bridge_ipv6_runtime_binding_absent")
    return entries


def expected_shapes(lane, *, identity_version=2, fully_observed=False, source=True):
    result = deepcopy(BASELINE)
    if not lane.startswith("debian11-") or fully_observed:
        result["PortHostIpv6"] = ["FixedIpv6HostPort", "EphemeralIpv6HostPort"]
    if identity_version == 2:
        result.update({"ContainerUser": ["ContainerUser"], "ContainerWorkdir": ["ContainerWorkdir"]})
    if source:
        result["CommandClear"] = ["ClearCommand"]
    return result


def record(lane="upstream-rootful", *, identity_version=2, fully_observed=False, source=True):
    groups = expected_shapes(lane, identity_version=identity_version, fully_observed=fully_observed, source=source)
    result = {"schema_version": 1, "lane": lane, "expected_mode": lane.rsplit("-", 1)[1],
              "candidate_sha": "c" * 40 if source else "5fef54d22b62b22304b963748fee45d5a18595c7",
              "port_probes": ports(lane, fully_observed=fully_observed),
              "capability_outcome": dict.fromkeys(groups, "available"), "admitted_shapes": groups,
              "command_clear_contract": "command-clear-v1"}
    if identity_version == 2:
        result.update(identity_contract="container-identity-v1", identity_cases=CASES.copy())
    if source:
        result.update(command_clear_projection_contract=CONTRACT, command_clear_outcomes=deepcopy(OUTCOME))
    else:
        result["command_clear_outcomes"] = {"admission": "unadmitted", "outcome": "all_four_process_controls_verified"}
    return result


class CommandClearProjectionTests(unittest.TestCase):
    def validate(self, value, lane="upstream-rootful", identity_version=2, fully_observed=False, contract=CONTRACT):
        return validate_command_clear_projection(
            value, expected_lane=lane, identity_version=identity_version,
            port_outcomes=ports(lane, fully_observed=fully_observed), expected_projection_contract=contract)

    def reject(self, value, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(ValueError, "^invalid command clear source projection$"):
                self.validate(value, **kwargs)
        self.assertEqual(output.getvalue(), "")

    def test_exact_canonical_baseline_plus_singleton_all_four_lanes(self):
        for lane in LANES:
            value = record(lane)
            self.assertEqual(self.validate(value, lane), "raw_source_only")
            self.assertEqual(value["admitted_shapes"], expected_shapes(lane))
            self.assertEqual(value["capability_outcome"], dict.fromkeys(expected_shapes(lane), "available"))
            self.assertNotIn("EntrypointClear", value["admitted_shapes"])

    def test_existing_identity_and_synthetic_port_contexts_are_explicit_not_fallback(self):
        for lane in LANES:
            for identity in (1, 2):
                for fully in (False, True):
                    value = record(lane, identity_version=identity, fully_observed=fully)
                    self.assertEqual(self.validate(value, lane, identity, fully), "raw_source_only")
                    self.reject(value, lane=lane, identity_version=3 - identity, fully_observed=fully)
        for bad in (None, True, "2", 0, 3):
            self.reject(record(), identity_version=bad)

    def test_historical_native26_format_is_never_reinterpreted_as_new_qualification(self):
        for lane in LANES:
            old = record(lane, source=False)
            self.assertEqual(self.validate(old, lane, contract=None), "legacy_observation_only")
            self.reject(old, lane=lane)
            old["capability_outcome"]["CommandClear"] = "available"
            old["admitted_shapes"]["CommandClear"] = ["ClearCommand"]
            self.reject(old, lane=lane, contract=None)
        new = record()
        self.reject(new, contract=None)

    def test_unknown_versions_types_keys_statuses_scope_and_mixed_forms_fail(self):
        mutations = [
            ("command_clear_projection_contract", "command-clear-native-source-v2"),
            ("command_clear_projection_contract", None), ("command_clear_projection_contract", True),
            ("command_clear_contract", "command-clear-v2"), ("schema_version", True),
            ("command_clear_outcomes", {"admission": "unadmitted", "outcome": "all_four_process_controls_verified"}),
        ]
        for field, bad in mutations:
            value = record()
            value[field] = bad
            self.reject(value)
        for field in OUTCOME:
            for bad in (None, True, SECRET):
                value = record()
                value["command_clear_outcomes"][field] = bad
                self.reject(value)
            value = record()
            del value["command_clear_outcomes"][field]
            self.reject(value)
        for extra in ("admission", SECRET):
            value = record()
            value["command_clear_outcomes"][extra] = SECRET
            self.reject(value)
        value = record()
        value["command_clear_unknown"] = SECRET
        self.reject(value)

    def test_every_baseline_and_singleton_map_entry_is_required_exact_and_typed(self):
        for lane in LANES:
            original = record(lane)
            for name in original["admitted_shapes"]:
                for side in ("capability_outcome", "admitted_shapes"):
                    for fault in ("missing", "empty", "duplicate", "wrong", "boolean"):
                        value = deepcopy(original)
                        if fault == "missing":
                            del value[side][name]
                        elif side == "capability_outcome":
                            value[side][name] = {"empty": "", "duplicate": ["available", "available"],
                                                 "wrong": "unavailable", "boolean": True}[fault]
                        else:
                            value[side][name] = {"empty": [], "duplicate": value[side][name] * 2,
                                                 "wrong": ["ClearEntrypoint"], "boolean": True}[fault]
                        self.reject(value, lane=lane)

    def test_no_neighboring_group_or_shape_promotion_even_if_maps_agree(self):
        for capability, shapes in (("EntrypointClear", ["ClearEntrypoint"]), ("StopTimeout", ["StopTimeoutZero", "StopTimeoutPositive"]),
                                   ("ShmSize", ["ShmSize"]), ("ContainerHostname", ["ContainerHostname"]),
                                   (SECRET, [SECRET])):
            value = record()
            value["capability_outcome"][capability] = "available"
            value["admitted_shapes"][capability] = shapes
            self.reject(value)
        for shapes in ([], ["ClearEntrypoint"], ["ClearCommand", "ClearCommand"], ["ClearCommand", "ClearEntrypoint"]):
            value = record()
            value["command_clear_outcomes"]["shapes"] = shapes
            value["admitted_shapes"]["CommandClear"] = shapes
            self.reject(value)

    def test_lane_and_independent_port_outcomes_cannot_select_their_own_baseline(self):
        for lane in LANES[:2]:
            value = record(lane)
            value["capability_outcome"]["PortHostIpv6"] = "available"
            value["admitted_shapes"]["PortHostIpv6"] = ["FixedIpv6HostPort", "EphemeralIpv6HostPort"]
            value["port_probes"] = ports(lane, fully_observed=True)
            self.reject(value, lane=lane)
        value = record()
        value["lane"] = "upstream-rootless"
        self.reject(value)
        value = record()
        value["port_probes"].reverse()
        self.reject(value)
        value = record()
        value["identity_cases"].pop()
        self.reject(value)


if __name__ == "__main__":
    unittest.main()
