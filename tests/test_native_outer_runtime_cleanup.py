"""Real fixed-runtime cleanup with authored process responses, never native I/O.

These controls own the root cleanup cases formerly exercised by the shell
campaign. Only the process/custody dependencies are doubles: cleanup and its
fixed command construction execute unchanged. Broker tests supplement, rather
than replace, these ownership and absence predicates.
"""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import replace
from io import StringIO
import json
from types import SimpleNamespace
import unittest

from native_outer_lifecycle import CleanupIdentity, LifecycleError
import test_native_outer_runtime


class FixedRuntimeCleanupTests(unittest.TestCase):
    ID = "9" * 64
    DEADLINE = 123
    PRIVATE = "private-runtime-response-do-not-publish"
    PREFIX = ("/usr/bin/podman", "--remote=false", "--runtime=/usr/bin/crun", "--cgroup-manager=systemd",
              "--transient-store=false", "--hooks-dir=/owned/hooks", "--default-mounts-file=/owned/mounts.conf")

    def fixture(self, responses):
        runtime, expected, unused_calls = test_native_outer_runtime.FixedRuntimeVocabularyTests().runtime([])
        runtime.container_id = self.ID
        identity = CleanupIdentity(self.ID, expected.name, runtime.account.image_digest, expected.owner)
        calls, checks = [], []
        test = self

        class Process:
            budget = object()

            def run(self, argv, deadline, environment, **options):
                calls.append((argv, deadline, dict(environment), options))
                test.assertTrue(responses, "unexpected extra native command")
                response = responses.pop(0)
                if isinstance(response, Exception):
                    raise response
                # Model the real process boundary's exit-status rejection;
                # stdout remains authored fallible input to actual cleanup.
                if response[1] not in options["allowed"]:
                    raise LifecycleError()
                return response

        class OrdinaryProcess:
            def run(self, *_args, **_kwargs):
                test.fail("cleanup used cancellation-poisoned ordinary I/O")

        class Custody:
            def __init__(self, path):
                self.chain = SimpleNamespace(path=path)

            def recheck(self):
                test.fail("cleanup used ordinary custody recheck")

            def recovery_recheck(self, budget, deadline):
                test.assertIs(budget, runtime.recovery_process.budget)
                test.assertEqual(deadline, test.DEADLINE)
                checks.append(self.chain.path)

        runtime.process, runtime.recovery_process = OrdinaryProcess(), Process()
        runtime.executables = tuple(Custody(path) for path in ("/usr/bin/podman", "/usr/bin/crun", "/usr/bin/timeout"))
        runtime.configuration = Custody("configuration")
        self.assertEqual(unused_calls, [])
        observation = {"Id": self.ID, "Name": expected.name, "Image": runtime.image.native_id,
                       "ImageDigest": runtime.image.native_digest,
                       "Config": {"Labels": {"io.dockerlens.native-run": expected.owner}}}
        return runtime, identity, observation, calls, checks

    def raw(self, observation):
        return json.dumps([observation]).encode()

    def refused(self, runtime, identity):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(LifecycleError) as raised:
                runtime.cleanup(identity, self.DEADLINE)
        self.assertEqual(str(raised.exception), "outer lifecycle custody refused")
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
        self.assertFalse(runtime.closed)

    def commands(self, calls):
        for argv, deadline, _environment, _options in calls:
            self.assertEqual(argv[:len(self.PREFIX)], self.PREFIX)
            self.assertEqual(deadline, self.DEADLINE)
        return [argv[len(self.PREFIX):] for argv, _deadline, _environment, _options in calls]

    def test_partial_or_mismatched_exact_id_preinspect_never_authorizes_removal(self):
        runtime, identity, original, _calls, _checks = self.fixture([])
        malformed = [b"", b"[{", b"[]", b"[{},{}]", b"[null]"]
        for key in original:
            edited = deepcopy(original)
            del edited[key]
            malformed.append(self.raw(edited))
        for key, changed in (("Id", "8" * 64), ("Name", "unowned-name"), ("Image", "0" * 64),
                             ("ImageDigest", "sha256:" + "0" * 64), ("Config", None),
                             ("Config", {"Labels": []}), ("Config", {"Labels": {}}),
                             ("Config", {"Labels": {"io.dockerlens.native-run": self.PRIVATE}})):
            edited = deepcopy(original)
            edited[key] = changed
            malformed.append(self.raw(edited))
        for raw in malformed:
            with self.subTest(raw=raw):
                runtime, identity, _observation, calls, _checks = self.fixture([(raw, 0)])
                self.refused(runtime, identity)
                self.assertEqual(self.commands(calls), [("container", "inspect", self.ID)])

    def test_exact_id_preinspect_query_failure_never_deletes_or_leaks(self):
        for response in (RuntimeError(self.PRIVATE), (self.PRIVATE.encode(), 125)):
            with self.subTest(response=type(response).__name__):
                runtime, identity, _observation, calls, _checks = self.fixture([response])
                self.refused(runtime, identity)
                self.assertEqual(self.commands(calls), [("container", "inspect", self.ID)])

    def test_failed_exact_id_removal_never_attempts_absence_or_closes(self):
        for response in (RuntimeError(self.PRIVATE), (self.PRIVATE.encode(), 125)):
            with self.subTest(response=type(response).__name__):
                responses = []
                runtime, identity, observation, calls, _checks = self.fixture(responses)
                responses.extend([(self.raw(observation), 0), response])
                self.refused(runtime, identity)
                self.assertEqual(self.commands(calls), [("container", "inspect", self.ID),
                                                       ("rm", "--force", "--time=0", self.ID)])

    def test_present_or_unknown_id_and_name_readbacks_never_close(self):
        for after_id_absence in (False, True):
            for response in ((b"", 0), (b"", 2), (b"", 125), (self.PRIVATE.encode(), 1),
                             RuntimeError(self.PRIVATE)):
                with self.subTest(name=after_id_absence, response=type(response).__name__):
                    responses = []
                    runtime, identity, observation, calls, _checks = self.fixture(responses)
                    responses.extend([(self.raw(observation), 0), (b"", 0)])
                    if after_id_absence:
                        responses.append((b"", 1))
                    responses.append(response)
                    self.refused(runtime, identity)
                    expected = [("container", "inspect", self.ID), ("rm", "--force", "--time=0", self.ID),
                                ("container", "exists", self.ID)]
                    if after_id_absence:
                        expected.append(("container", "exists", identity.name))
                    self.assertEqual(self.commands(calls), expected)

    def test_only_empty_exact_id_and_name_absence_closes_on_recovery_channel(self):
        responses = []
        runtime, identity, observation, calls, checks = self.fixture(responses)
        responses.extend([(self.raw(observation), 0), (b"", 0), (b"", 1), (b"", 1)])
        self.assertIsNone(runtime.cleanup(identity, self.DEADLINE))
        self.assertTrue(runtime.closed)
        self.assertEqual(responses, [])
        self.assertEqual(self.commands(calls), [("container", "inspect", self.ID),
                                               ("rm", "--force", "--time=0", self.ID),
                                               ("container", "exists", self.ID),
                                               ("container", "exists", identity.name)])
        self.assertEqual([options for _argv, _deadline, _env, options in calls], [
            {"stdout_limit": 65536, "seconds": 8, "allowed": (0,)},
            {"stdout_limit": 65, "seconds": 8, "allowed": (0,)},
            {"stdout_limit": 0, "seconds": 8, "allowed": (0, 1)},
            {"stdout_limit": 0, "seconds": 8, "allowed": (0, 1)},
        ])
        self.assertEqual(checks, ["/usr/bin/podman", "/usr/bin/crun", "/usr/bin/timeout", "configuration"] * 4)
        for _argv, _deadline, environment, _options in calls:
            self.assertEqual(environment, {"PATH": "/usr/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C",
                                           "CONTAINERS_CONF": "/owned/runtime.conf"})

    def test_names_and_drifted_identity_are_never_deletion_authority(self):
        for field, changed in (("container_id", "8" * 64), ("container_id", ""), ("name", self.PRIVATE),
                               ("owner", self.PRIVATE), ("image_digest", "sha256:" + "0" * 64)):
            with self.subTest(field=field, changed=changed):
                runtime, identity, _observation, calls, checks = self.fixture([])
                if field == "container_id" and not changed:
                    changed = identity.name
                self.refused(runtime, replace(identity, **{field: changed}))
                self.assertEqual((calls, checks), ([], []))


if __name__ == "__main__":
    unittest.main()
