"""Literal typed-tree and observed-transition controls, without kernel I/O."""

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_pids_topology", ROOT / "scripts/native_pids_topology.py")
topology = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = topology
SPEC.loader.exec_module(topology)
D = topology.CgroupType.DOMAIN
R = topology.CgroupType.THREAD_ROOT
T = topology.CgroupType.THREADED
Node = topology.Node


class TopologyTests(unittest.TestCase):
    def plan(self, nodes, root=0):
        return [(step.node, step.owner, step.procs_read.value)
                for step in topology.coverage_plan(tuple(nodes), root)]

    def refused(self, operation, *arguments):
        with self.assertRaises(topology.TopologyRefusal) as failure:
            operation(*arguments)
        self.assertEqual(str(failure.exception), "pids-topology")

    def test_exact_complete_type_bytes_only(self):
        for raw, expected in [(b"domain\n", D), (b"domain threaded\n", R), (b"threaded\n", T)]:
            self.assertIs(topology.parse_type(raw), expected)
        for raw in [b"domain invalid\n", b"", b"domain", b"domain\r\n", b"domain\n\n",
                    b" domain\n", b"domain \n", b"domain\x00\n", b"threaded domain\n",
                    b"unknown\n", b"\xff\n", "domain\n", bytearray(b"domain\n"), None]:
            with self.subTest(raw=raw):
                self.refused(topology.parse_type, raw)

    def test_literal_coverage_plans_keep_aggregate_and_local_membership_separate(self):
        self.assertEqual(self.plan([Node(0, None, D)]), [(0, 0, "local")])
        self.assertEqual(self.plan([Node(9, None, R), Node(2, 9, T), Node(4, 2, T)], 9),
                         [(9, 9, "aggregate"), (2, 9, "none"), (4, 9, "none")])
        # Shuffled input, two separate thread domains and ordinary local groups.
        nodes = [Node(8, 7, T), Node(5, 3, T), Node(0, None, D), Node(7, 0, R),
                 Node(6, 0, D), Node(3, 1, R), Node(4, 3, T), Node(1, 0, D)]
        expected = [(0, 0, "local"), (1, 1, "local"), (3, 3, "aggregate"),
                    (4, 3, "none"), (5, 3, "none"), (6, 6, "local"),
                    (7, 7, "aggregate"), (8, 7, "none")]
        self.assertEqual(self.plan(nodes), expected)
        self.assertEqual(self.plan(reversed(nodes)), expected)

    def test_literal_nonroot_edge_table(self):
        for parent, child, permitted in [
            (D, D, True), (D, R, True), (D, T, False),
            (R, D, False), (R, R, False), (R, T, True),
            (T, D, False), (T, R, False), (T, T, True),
        ]:
            with self.subTest(parent=parent, child=child):
                # Give threaded parents an actual enclosing thread root.
                nodes = ([Node(0, None, R), Node(1, 0, T), Node(2, 1, child)]
                         if parent is T else [Node(0, None, parent), Node(2, 0, child)])
                if permitted:
                    self.plan(nodes)
                else:
                    self.refused(topology.coverage_plan, tuple(nodes), 0)

    def test_disconnected_ambiguous_and_unqualified_roots_refuse(self):
        cases = [
            ((), 0), ((Node(0, None, T),), 0),
            ((Node(0, None, D),), 1), ((Node(0, 1, D), Node(1, None, D)), 0),
            ((Node(0, None, D), Node(1, None, D)), 0),
            ((Node(0, None, D), Node(1, 9, D)), 0),
            ((Node(0, None, D), Node(1, 1, D)), 0),
            ((Node(0, None, D), Node(1, 2, D), Node(2, 1, D)), 0),
            ((Node(0, None, D), Node(1, 0, D), Node(1, 0, R)), 0),
            ((Node(True, None, D),), 1), ((Node(0, False, D),), 0),
            ((Node(-1, None, D),), -1), ((Node(0, None, "domain"),), 0),
            ((Node(0, None, D),), False), ((object(),), 0),
        ]
        for nodes, root in cases:
            with self.subTest(nodes=nodes, root=root):
                self.refused(topology.coverage_plan, nodes, root)
        self.refused(topology.coverage_plan, [Node(0, None, D)], 0)

    def test_existing_tree_limits_without_claiming_physical_budget_fit(self):
        wide = tuple([Node(0, None, D)] + [Node(key, 0, D) for key in range(1, 128)])
        self.assertEqual(len(topology.coverage_plan(wide, 0)), 128)
        self.refused(topology.coverage_plan, wide + (Node(128, 0, D),), 0)
        deep = tuple([Node(0, None, D)] + [Node(key, key - 1, D) for key in range(1, 13)])
        self.assertEqual(len(topology.coverage_plan(deep, 0)), 13)
        self.refused(topology.coverage_plan, deep + (Node(13, 12, D),), 0)

    def test_literal_phase_transition_matrix_and_separate_topology_obligation(self):
        # Each phase has independently enumerated allowed same-object pairs.
        allowed = {
            topology.Phase.DISCOVERY_LEASE: [(D, D), (R, R), (T, T)],
            topology.Phase.BETWEEN_LEASES: [(D, D), (D, R), (R, D), (R, R), (T, T)],
            topology.Phase.MEASUREMENTS: [(D, D), (R, R), (T, T)],
            topology.Phase.AFTER_SEAL: [(D, D), (D, R), (R, D), (R, R), (T, T)],
        }
        for phase, permitted in allowed.items():
            for before, after in [(D, D), (D, R), (D, T), (R, D), (R, R), (R, T),
                                  (T, D), (T, R), (T, T)]:
                with self.subTest(phase=phase, before=before, after=after):
                    if (before, after) in permitted:
                        self.assertIsNone(topology.check_transition(before, after, phase))
                    else:
                        self.refused(topology.check_transition, before, after, phase)
        self.refused(topology.check_transition, "domain", R, topology.Phase.BETWEEN_LEASES)
        self.refused(topology.check_transition, D, R, "between_leases")
        topology.check_transition(D, R, topology.Phase.BETWEEN_LEASES)
        # The type pair alone cannot authorize retaining old ordinary children.
        self.refused(topology.coverage_plan, (Node(0, None, R), Node(1, 0, D)), 0)


if __name__ == "__main__":
    unittest.main()
