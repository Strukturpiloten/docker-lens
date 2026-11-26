"""Independent schema-2 topology/cost controls; no Engine or admission evidence."""
from copy import deepcopy
from itertools import product
import json
import unittest

from test_native_nofile_proof import bind_context, fixture, refuse_case, reader, unreference_slots


class NofileCaseBridgeTests(unittest.TestCase):
    def validate(self, proof, *, backend="podman"):
        self.assertEqual(reader.validate_nofile_proof(proof, proof["context"], outer_backend=backend),
                         {"contract": "nofile-v1", "capability_admission": [], "catalogue_admission": False})

    def reject(self, proof):
        with self.assertRaisesRegex(ValueError, "^invalid private nofile proof$"):
            reader.validate_nofile_proof(proof, proof["context"], outer_backend="podman")

    @staticmethod
    def normalize(proof, index):
        for item in proof["cases"][index]["containers"]:
            witness = item["effect"]["witness"]
            witness["outcome"] = "finite_kernel_normalization"
            witness["kernel"]["hard"] = 1048576
            if index == 3:
                witness["kernel"]["soft"] = 1048576
            for sample in witness["samples"].values():
                sample.update(witness["kernel"])

    def test_schema_two_keeps_filename_and_public_status_but_rejects_one(self):
        proof = fixture()
        self.validate(proof)
        self.assertEqual(reader.FILENAME, "nofile-v1.json")
        for value in (1, True, 3, "2", None):
            wrong = deepcopy(proof)
            wrong["schema_version"] = value
            self.reject(wrong)

    def test_finite_cases_share_only_the_original_unowned_default(self):
        proof = fixture()
        self.validate(proof)
        self.assertEqual([c["case"] for c in proof["cases"]],
                         ["soft64_hard128", "soft128_hard128", "soft64_hard_unlimited", "both_unlimited"])
        self.assertEqual(proof["network_topology"]["default"]["container_indices"], [0, 1, 2, 3])
        self.assertEqual([x["container_indices"] for x in proof["network_topology"]["owned"]], [[4, 5], [6, 7]])
        self.assertEqual(proof["network_topology"]["default"]["ownership"], "not_owned")
        self.assertEqual(len({x["id"] for x in proof["acquisition"]["networks"]}), 3)
        self.assertEqual(proof["acquisition"]["actual_requests"], 13)
        self.assertEqual(proof["acquisition"]["actual_expansions"], 11)

    def test_independent_unlimited_dispositions_in_all_lanes_and_backends(self):
        for lane, backend, outcomes in product(
                ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"),
                ("podman", "docker"), product(("exact", "normalized", "refused"), repeat=2)):
            with self.subTest(lane=lane, backend=backend, outcomes=outcomes):
                proof = fixture(lane, outer_backend=backend)
                refused = 0
                for index, outcome in zip((2, 3), outcomes):
                    if outcome == "refused":
                        refuse_case(proof, index)
                        refused += 2
                    elif outcome == "normalized":
                        self.normalize(proof, index)
                extra = 1 if backend == "docker" else 0
                self.assertEqual(proof["accounting"]["ordinary_calls"],
                                 (9 if lane.startswith("debian11-") else 8) + extra + 6
                                 + 64 - refused + 1 + 20 + 2 + extra)
                self.assertEqual(proof["accounting"]["cleanup_calls"], 84)
                self.validate(proof, backend=backend)

    def test_aliases_case_audience_ownership_and_cleanup_cannot_be_relabelled(self):
        changes = (
            lambda p: p["network_topology"]["owned"][0].update(id=p["network_topology"]["default"]["id"]),
            lambda p: p["network_topology"]["owned"][1].update(id=p["network_topology"]["owned"][0]["id"]),
            lambda p: p["network_topology"]["owned"][0].update(id=p["cases"][0]["containers"][0]["id"]),
            lambda p: p["network_topology"]["default"].update(ownership="owned"),
            lambda p: p["network_topology"]["default"].update(name="other"),
            lambda p: p["network_topology"]["owned"][0].update(case="both_unlimited"),
            lambda p: p["network_topology"]["owned"][0].update(owner="otherRun"),
            lambda p: p["network_topology"]["owned"][0].update(name="bridge"),
            lambda p: p["network_topology"]["owned"][0].update(driver="host"),
            lambda p: p["network_topology"]["owned"][0].update(container_indices=[0, 1]),
            lambda p: p["network_topology"]["owned"][0].update(cleanup="not_owned"),
            lambda p: p["network_topology"]["owned"][0].update(absence_rounds=1),
            lambda p: p["acquisition"]["networks"][0].update(owner=p["context"]["run_id"]),
            lambda p: p["acquisition"]["networks"][1].update(ownership="not_owned"),
            lambda p: p["acquisition"]["networks"][2].update(id=p["acquisition"]["networks"][1]["id"]),
            lambda p: p["acquisition"]["container_networks"][4].update(name="bridge"),
            lambda p: p["acquisition"]["container_networks"][4].update(container_id=p["cases"][0]["containers"][0]["id"]),
            lambda p: p["cleanup"].update(networks="present"),
            lambda p: p["cleanup"].update(owned_networks=3),
            lambda p: p["cleanup"].update(uncertain=True),
            lambda p: p["network_topology"]["owned"].pop(),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                proof = fixture()
                change(proof)
                self.reject(proof)

    def test_partial_maps_keep_all_independent_cross_case_dispositions(self):
        for lane, backend, outcomes, omitted in product(
                ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"),
                ("podman", "docker"), product(("exact", "normalized", "refused"), repeat=2), (2, 3)):
            with self.subTest(lane=lane, backend=backend, outcomes=outcomes, omitted=omitted):
                proof = fixture(lane, outer_backend=backend)
                for index, outcome in zip((2, 3), outcomes):
                    if outcome == "refused":
                        refuse_case(proof, index)
                    elif outcome == "normalized":
                        self.normalize(proof, index)
                unreference_slots(proof, [2 * omitted, 2 * omitted + 1], "null")
                self.assertEqual(proof["acquisition"]["actual_requests"], 12)
                self.assertEqual(proof["acquisition"]["actual_expansions"], 10)
                self.validate(proof, backend=backend)

    def test_active_membership_is_optional_and_never_an_ownership_claim(self):
        for state in ("missing", "null", "redacted", "empty"):
            proof = fixture()
            for network in proof["acquisition"]["networks"]:
                network.update(active_membership_availability=state, active_selected_ids=[],
                               active_unselected_count=0 if state == "empty" else None)
            self.validate(proof)
        proof = fixture()
        proof["acquisition"]["networks"][1]["active_selected_ids"].pop()
        self.validate(proof)  # Presence is not a complete or atomic membership snapshot.
        proof["acquisition"]["networks"][0]["active_selected_ids"] = []
        proof["acquisition"]["networks"][0]["active_unselected_count"] = 4096
        self.validate(proof)  # Borrowed peers are counted, not adopted or exposed.

    def test_observed_membership_rejects_wrong_audience_order_foreign_peers_and_counts(self):
        changes = (
            lambda n, p: n.update(active_selected_ids=[p["cases"][0]["containers"][0]["id"]]),
            lambda n, p: n["active_selected_ids"].reverse(),
            lambda n, p: n["active_selected_ids"].append(n["active_selected_ids"][0]),
            lambda n, p: n.update(active_unselected_count=1),
            lambda n, p: n.update(active_unselected_count=True),
            lambda n, p: n.update(active_unselected_count=-1),
            lambda n, p: n.update(active_unselected_count=None),
            lambda n, p: n.update(active_selected_ids=[], active_unselected_count=0),
            lambda n, p: n.update(active_membership_availability="missing"),
            lambda n, p: n.update(active_membership_availability="empty"),
            lambda n, p: n.update(active_membership_availability="invented"),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                proof = fixture()
                change(proof["acquisition"]["networks"][1], proof)
                self.reject(proof)
        proof = fixture()
        proof["acquisition"]["networks"][0]["active_unselected_count"] = 4093
        self.reject(proof)  # Four selected + 4093 unselected exceeds the collection cap.

    def test_endpoint_availability_is_preserved_with_actual_name_fallback(self):
        for state in ("missing", "null", "empty", "redacted"):
            proof = fixture()
            for network in proof["acquisition"]["networks"]:
                network["lookup"] = "name"
            for binding in proof["acquisition"]["container_networks"]:
                binding.update(lookup="name", network_id_availability=state,
                               network_id="" if state == "empty" else None)
            self.validate(proof)

    def test_endpoint_values_and_lookup_cannot_invent_or_merge_identity(self):
        changes = (
            {"network_id": None}, {"network_id": ""}, {"network_id": "a" * 64},
            {"network_id_availability": "empty"}, {"network_id_availability": "missing"},
            {"network_id_availability": "null"}, {"network_id_availability": "redacted"},
            {"network_id_availability": "unknown"}, {"lookup": "name"},
            {"lookup": "name", "network_id_availability": "redacted", "network_id": {"__docker_lens_redacted__": True}},
            {"lookup": "name", "network_id_availability": "empty", "network_id": ""},
        )
        for change in changes:
            with self.subTest(change=change):
                proof = fixture()
                proof["acquisition"]["container_networks"][4].update(change)
                self.reject(proof)

    def test_whole_maps_never_invent_peer_bindings_or_unobserved_network_exchanges(self):
        proof = fixture()
        unreference_slots(proof, [5])
        self.validate(proof)  # The peer's real GET is not attributed to slot 5.
        self.assertIsNone(proof["acquisition"]["container_networks"][5]["lookup"])
        proof = fixture()
        refuse_case(proof, 2)
        unreference_slots(proof, [4, 5])
        self.assertEqual(proof["acquisition"]["actual_requests"], 12)
        self.assertEqual(proof["acquisition"]["actual_expansions"], 10)
        self.assertEqual(proof["accounting"]["cleanup_calls"], 84)
        self.validate(proof)  # Both owned bridge lifecycles still completed.
        for state in ("missing", "null", "empty", "redacted"):
            proof = fixture()
            unreference_slots(proof, range(8), state)
            self.assertEqual(proof["acquisition"]["actual_requests"], 10)
            self.assertEqual(proof["acquisition"]["actual_expansions"], 8)
            self.assertIsNone(proof["network_topology"]["default"]["id"])
            self.validate(proof)
        context = deepcopy(proof["context"])
        context["run_id"] = "Ab12Cd34"
        context["outer"].update(name="dl-native-Ab12Cd34", owner="Ab12Cd34", data_volume="dl-native-data-Ab12Cd34")
        self.validate(bind_context(proof, context))

    def test_partial_captures_reject_fabricated_missing_reordered_or_peer_derived_facts(self):
        for field, value in (("name", "dl-nf-private-net"), ("network_id", "a" * 64),
                             ("network_id_availability", "empty"), ("lookup", "name")):
            proof = fixture()
            unreference_slots(proof, [5])
            proof["acquisition"]["container_networks"][5][field] = value
            self.reject(proof)
        proof = fixture()
        saved = deepcopy(proof["acquisition"]["networks"][1])
        unreference_slots(proof, [4, 5])
        proof["acquisition"]["networks"].insert(1, saved)
        proof["acquisition"].update(actual_requests=13, actual_expansions=11)
        self.reject(proof)  # A configured/authenticated network is not an observed exchange.
        proof = fixture()
        proof["acquisition"]["networks"].pop(1)
        proof["acquisition"].update(actual_requests=12, actual_expansions=10)
        self.reject(proof)  # A real endpoint reference still requires its closed inspect.
        proof = fixture()
        unreference_slots(proof, range(4))
        self.validate(proof)
        proof["network_topology"]["default"]["id"] = f"{100:064x}"
        self.reject(proof)
        proof = fixture()
        proof["acquisition"]["networks"].reverse()
        self.reject(proof)
        proof = fixture()
        unreference_slots(proof, [4, 5])
        proof["acquisition"].update(actual_requests=13, actual_expansions=11)
        self.reject(proof)  # The expansion ceiling is not an actual measurement.

    def test_measured_cost_components_caps_and_teardown_must_reconcile(self):
        for field, value in (("setup_calls", 2), ("setup_calls", True), ("setup_bytes", 0),
                             ("cleanup_calls", 5), ("cleanup_bytes", 0), ("cleanup_bytes", 6 * 10240 + 1)):
            proof = fixture()
            proof["network_topology"]["owned"][0][field] = value
            self.reject(proof)
        for field, value in (("network_setup_calls", 5), ("network_setup_bytes", 1023),
                             ("container_cleanup_calls", 71), ("network_cleanup_calls", 11),
                             ("network_cleanup_bytes", 511), ("cleanup_calls", 83), ("cleanup_bytes", 8703),
                             ("ordinary_calls", 100), ("ordinary_bytes", 524288),
                             ("container_cleanup_bytes", 72 * 10240 + 1),
                             ("ordinary_elapsed_ns", 134 * 10**9 + 1),
                             ("cleanup_elapsed_ns", 46 * 10**9 + 1), ("elapsed_ns", 180 * 10**9 + 1)):
            with self.subTest(field=field, value=value):
                proof = fixture()
                proof["accounting"][field] = value
                self.reject(proof)
        for field, value in (("actual_requests", 12), ("actual_requests", 14), ("actual_expansions", 10),
                             ("actual_expansions", 12), ("actual_elapsed_ns", 0),
                             ("actual_elapsed_ns", True), ("actual_elapsed_ns", 10 * 10**9 + 1),
                             ("actual_response_bytes", 0), ("actual_response_bytes", 524289)):
            proof = fixture()
            proof["acquisition"][field] = value
            self.reject(proof)
        for value in (10, 12, True):
            proof = fixture()
            proof["acquisition"]["limits"]["max_expansions"] = value
            self.reject(proof)
        proof = fixture()
        proof["acquisition"]["actual_elapsed_ns"] = proof["accounting"]["ordinary_elapsed_ns"] + 1
        self.reject(proof)

    def test_response_body_identity_floor_is_necessary_and_varies_with_captured_networks(self):
        for count in range(4):
            with self.subTest(captured_networks=count):
                proof = fixture()
                if count < 3:
                    unreference_slots(proof, range((0, 4, 6)[count], 8))
                self.assertEqual(len(proof["acquisition"]["networks"]), count)
                identities = [item["id"] for case in proof["cases"] for item in case["containers"]]
                identities += [network["id"] for network in proof["acquisition"]["networks"]]
                # This compact Id-only object is guaranteed by each identity,
                # not a full response body, measured capture or sufficient proof.
                bound = sum(len(json.dumps({"Id": identity}, separators=(",", ":")).encode())
                            for identity in identities)
                self.assertEqual(bound, 73 * (8 + count))
                self.validate(proof)  # Keep the complete valid proof fixture.
                for value in (1, bound - 1):
                    wrong = deepcopy(proof)
                    wrong["acquisition"]["actual_response_bytes"] = value
                    self.reject(wrong)
                for value in (bound, 524288):
                    bounded = deepcopy(proof)
                    bounded["acquisition"]["actual_response_bytes"] = value
                    self.validate(bounded)  # Necessary consistency only, not a measurement.


if __name__ == "__main__":
    unittest.main()
