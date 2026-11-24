"""Private host APT observations and independently transferred guest contracts."""

import importlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_hosted_zero_swap_trial as wiring

ROOT = wiring.ROOT
with patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
    apt = importlib.import_module("hosted_zero_swap_packages")
SAVED = json.loads((ROOT / "tests/fixtures/hosted-apt-observations.json").read_text())
PINS = wiring.PINS


def parse(raw, **options):
    return apt.policy(raw, PINS, wiring.trial.ARCHIVE, complete=True, **options)


class PackageObservations(unittest.TestCase):
    def test_real_authenticated_model_shapes_and_message_privacy(self):
        cases = SAVED["cases"]
        for name in ("exact-installed", "older-requested-installed", "hwe-owner-installed"):
            with self.subTest(name=name):
                observed = parse(cases[name]["policy"].encode())
                self.assertTrue(
                    all(row["wanted_archive_version"] == "present" for row in observed.values())
                )
                if name == "exact-installed":
                    self.assertTrue(all(row["installed"] == "exact" for row in observed.values()))
                elif name == "older-requested-installed":
                    self.assertEqual(observed["qemu-utils"]["installed"], "different")
                else:
                    self.assertEqual(observed["qemu-utils"]["installed"], "none")
        for name, expected in (
            ("base-only-empty", "requested_version_missing"),
            ("hwe-owner-installed", "removal_disabled"),
        ):
            case = cases[name]
            self.assertIn(
                expected,
                apt.messages(
                    "plan", case["stdout"].encode(), case["stderr"].encode(), PINS["host_packages"]
                ),
            )
        self.assertEqual(
            set(
                apt.messages("update", b"", SAVED["update_stderr"].encode(), PINS["host_packages"])
            ),
            {"fetch", "transport"},
        )
        for text, expected in (
            (b"E: signatures couldn't be verified: NO_PUBKEY PRIVATE", "authentication"),
            (b"E: Release file PRIVATE expired", "index_validity"),
            (b"E: Unmet dependencies. PRIVATE", "unmet_dependencies"),
            (b"E: private held broken packages", "held_broken"),
            (b"private inventory: secret", "unclassified"),
        ):
            result = apt.messages(
                "update" if expected in ("authentication", "index_validity") else "plan",
                b"",
                text,
                PINS["host_packages"],
            )
            self.assertEqual(result, [expected])
            self.assertNotIn("PRIVATE", json.dumps(result))

    def test_policy_requires_complete_identity_bound_records(self):
        raw = SAVED["cases"]["exact-installed"]["policy"].encode()
        self.assertEqual(apt.policy(raw, PINS, wiring.trial.ARCHIVE), apt.unobserved())
        for corrupted in (
            raw[:-1],
            raw[: raw.index(b"xorriso:")],
            raw + b"xorriso:\n",
            raw.replace(b"qemu-utils:", b"foreign-private:"),
            raw + b"\xff\n",
        ):
            with self.subTest(corrupted=corrupted[-20:]):
                self.assertEqual(parse(corrupted), apt.unobserved())
        for old, new in (
            (b"20261017T000000Z", b"20261018T000000Z"),
            (b"https://snapshot.ubuntu.com", b"https://private.example"),
            (b"amd64 Packages", b"arm64 Packages"),
            (b"resolute-updates/main", b"noble-updates/main"),
            (b"resolute-updates/main", b"resolute-updates/private"),
        ):
            with self.subTest(new=new):
                rows = parse(raw.replace(old, new))
                self.assertEqual(rows["qemu-utils"]["wanted_archive_version"], "unobserved")
                self.assertNotIn("private", json.dumps(rows))
        # A status-only matching version is not an archive observation.
        row = "qemu-utils"
        block = raw.decode().split(row + ":\n", 1)[1].split("xorriso:\n", 1)[0]
        source_only = block[block.index(" *** ") :]
        modified = raw.replace(
            block.encode(), (block[: block.index("     ")] + source_only).encode()
        )
        self.assertEqual(
            parse(modified)[row], {"installed": "exact", "wanted_archive_version": "absent"}
        )
        for altered in (
            raw.replace(b"  Candidate:", b"  Installed:"),
            raw.replace(b"  Version table:", b"  Unknown:"),
        ):
            self.assertTrue(
                all(
                    x == {"installed": "unobserved", "wanted_archive_version": "unobserved"}
                    for x in parse(altered).values()
                )
            )
        contradicted = parse(
            raw.replace(b" *** 1:10.2.1+ds-1ubuntu3.2", b" *** 1:10.2.1+ds-1ubuntu3")
        )
        self.assertTrue(
            all(contradicted[name]["installed"] == "unobserved" for name in apt.TARGETS[:-1])
        )
        self.assertEqual(contradicted["xorriso"]["installed"], "exact")
        # Candidate differs, but the wanted snapshot version is still listed.
        candidate = raw.replace(
            b"  Candidate: 1:10.2.1+ds-1ubuntu3.2", b"  Candidate: 1:10.2.1+ds-1ubuntu3"
        )
        self.assertEqual(parse(candidate)[row]["wanted_archive_version"], "present")

    def run_failure(
        self,
        *,
        operation="plan",
        cleanup=False,
        cancel=False,
        now=None,
        policy_failure=None,
        policy_stderr=b"",
        native_output=None,
    ):
        trial = wiring.trial
        clock = [0] if now is None else now
        calls = []
        output = (
            (b"", b"E: Packages need to be removed but remove is disabled.\n")
            if native_output is None
            else native_output
        )
        result = {}
        failure = trial.Refusal("command_failed", 100)
        failure._native_output = output

        def common(_pins, scope, _work, deadline, *, op, run):
            self.assertEqual(scope, "host")
            with op(operation):
                run(
                    [
                        "env",
                        "apt-get",
                        "-o",
                        "Dir::State::lists=PRIVATE",
                        *(["--simulate", "install"] if operation == "plan" else ["-qq", "update"]),
                    ],
                    deadline,
                )

        def capture(argv, deadline):
            calls.append((argv, deadline))
            if "apt-get" in argv:
                if operation == "update":
                    self.assertEqual(argv[-3:], ["-qq", "--error-on=any", "update"])
                raise failure
            self.assertEqual(
                argv,
                ["env", "apt-cache", "-o", "Dir::State::lists=PRIVATE", "policy", *apt.TARGETS],
            )
            if policy_failure:
                raise policy_failure
            return 0, SAVED["cases"]["exact-installed"]["policy"].encode(), policy_stderr

        with (
            patch.dict(
                trial.__dict__,
                packages=common,
                capture=capture,
                command_cleanup_failed=cleanup,
                cancelled=15 if cancel else None,
            ),
            patch.object(trial.time, "monotonic", side_effect=lambda: clock[0]),
        ):
            try:
                apt.install(trial.__dict__, PINS, Path("/owned"), 10, result)
            except trial.Refusal as caught:
                self.assertIs(caught, failure)
            else:
                self.fail("lost primary failure")
        return result, calls

    def test_policy_is_once_read_only_bounded_and_secondary(self):
        result, calls = self.run_failure()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][1], 2)
        self.assertEqual(result["host_package_messages"], ["removal_disabled"])
        self.assertTrue(
            all(x["installed"] == "exact" for x in result["host_package_policy"].values())
        )
        for options in (
            {"operation": "update"},
            {"cleanup": True},
            {"cancel": True},
            {"now": [10]},
        ):
            with self.subTest(options=options):
                _, calls = self.run_failure(**options)
                self.assertEqual(len(calls), 1)
        _, calls = self.run_failure(now=[9])
        self.assertEqual(calls[1][1], 10)
        for failure in (
            wiring.trial.Refusal("timeout", 124),
            wiring.trial.Refusal("cancelled", 143),
            wiring.trial.Refusal("cleanup_failed"),
            OSError("PRIVATE"),
            ValueError("PRIVATE"),
        ):
            with self.subTest(failure=failure):
                result, _ = self.run_failure(policy_failure=failure)
                self.assertEqual(result["host_package_policy"], apt.unobserved())
        result, _ = self.run_failure(policy_stderr=b"PRIVATE")
        self.assertEqual(result["host_package_policy"], apt.unobserved())
        result, calls = self.run_failure(
            native_output=(b"x" * (wiring.trial.OUTPUT_LIMIT + 1), b"")
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["host_package_messages"], ["unobserved"])
        with patch.object(apt, "messages", side_effect=ValueError("PRIVATE")):
            result, calls = self.run_failure()
            self.assertEqual(len(calls), 1)
            self.assertEqual(result["host_package_messages"], ["unobserved"])
        with patch.object(apt, "policy", side_effect=TypeError("PRIVATE")):
            result, _ = self.run_failure()
            self.assertEqual(result["host_package_policy"], apt.unobserved())

    def test_capture_failed_reaping_preserves_native_status(self):
        trial = wiring.trial
        with (
            patch.object(trial, "reap", return_value=False),
            patch.object(trial, "command_cleanup_failed", False),
        ):
            with self.assertRaises(trial.Refusal) as raised:
                trial.capture(
                    [sys.executable, "-c", "import sys;sys.stderr.write('PRIVATE');sys.exit(100)"],
                    trial.time.monotonic() + 3,
                )
            self.assertEqual(
                (raised.exception.code, raised.exception.reason), (100, "command_failed")
            )
            self.assertTrue(trial.command_cleanup_failed)
            self.assertEqual(raised.exception._native_output, (b"", b"PRIVATE"))

    def test_normal_host_receipts_keep_plan_failure_across_policy_outcomes(self):
        runner = wiring.EntrypointTrial()
        raw = SAVED["cases"]["exact-installed"]["policy"].encode()
        for options in (
            {"policy_reply": raw},
            {"policy_reply": raw[:-1]},
            {"policy_reply": wiring.trial.Refusal("timeout", 124)},
            {"policy_cleanup": True},
            {"policy_reply": raw, "policy_advance": 3},
        ):
            with self.subTest(options=options):
                code, report, _ = runner.host((), package_case=("plan", "exit"), **options)
                self.assertEqual(
                    (code, report["reason"], report["cleanup"]), (100, "command_failed", "verified")
                )
                self.assertEqual(report["host_package_operation"], "plan")
                self.assertEqual(report["host_package_messages"], ["unclassified"])
                expected = parse(raw) if options == {"policy_reply": raw} else apt.unobserved()
                self.assertEqual(report["host_package_policy"], expected)
                if options.get("policy_cleanup"):
                    self.assertEqual(report["command_cleanup"], "unverified")
        code, report, _ = runner.host(
            (), package_case=("update", "exit"), package_error=SAVED["update_stderr"].encode()
        )
        self.assertEqual((code, report["reason"]), (100, "command_failed"))
        self.assertEqual(set(report["host_package_messages"]), {"fetch", "transport"})
        self.assertNotIn("host_package_policy", report)

    def test_transferred_guest_imports_without_host_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "observer.py"
            script.write_bytes(wiring.SOURCE.read_bytes())
            result = subprocess.run(
                [sys.executable, "-B", str(script), "guest", "a" * 32, "b" * 64, "{}"],
                env={"PYTHONPATH": "", "PYTHONNOUSERSITE": "1"},
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, b"")
            report = json.loads(result.stdout)
            self.assertEqual(report["stage"], "boot")
            self.assertNotIn("host_package_messages", report)

    def test_normal_script_loads_actual_helper_only_after_host_admission(self):
        bootstrap = textwrap.dedent("""
            import os,sys
            from pathlib import Path
            from types import SimpleNamespace
            from unittest.mock import patch
            patches=[]
            def enter(frame,event,arg):
                if event!='call' or frame.f_code.co_name!='host_trial':return
                sys.setprofile(None);g=frame.f_globals;state=[]
                def admitted(*args):state.append('admitted');return {}
                def path(*args):
                    return SimpleNamespace(read_text=lambda:'MemAvailable: 11000000 kB\\n') if args==('/proc/meminfo',) else Path(*args)
                def capture(argv,deadline,**options):
                    assert state==['admitted'] and argv[-3:]==['-qq','--error-on=any','update']
                    import hosted_zero_swap_packages as helper
                    Path(os.environ['WITNESS']).write_text(helper.__file__)
                    error=g['Refusal']('command_failed',100);error._native_output=(b'',b'E: Failed to fetch PRIVATE')
                    raise error
                g.update(admitted_host=admitted,Path=path,boot_id=lambda:'a'*64,kvm_preflight=lambda record:record.update(operation='complete'),capture=capture)
                for owner,name,value in [(g['os'],'sched_getaffinity',lambda _: {0,1}),(g['shutil'],'disk_usage',lambda _:SimpleNamespace(free=13*g['GIB']))]:
                    p=patch.object(owner,name,value);p.start();patches.append(p)
            sys.setprofile(enter)
        """)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sitecustomize.py").write_text(bootstrap)
            handoff = root / "handoff"
            handoff.touch()
            witness = root / "witness"
            environment = dict(
                os.environ,
                PYTHONPATH=directory,
                RUNNER_TEMP=directory,
                GITHUB_OUTPUT=str(handoff),
                WITNESS=str(witness),
            )
            result = subprocess.run(
                [sys.executable, "-B", str(wiring.SOURCE)],
                env=environment,
                capture_output=True,
                timeout=5,
            )
            self.assertEqual((result.returncode, result.stderr), (100, b""))
            self.assertEqual(
                Path(witness.read_text()).resolve(), ROOT / "scripts/hosted_zero_swap_packages.py"
            )
            report = json.loads(wiring.receipt_path(handoff).read_text())
            self.assertEqual(report["host_package_operation"], "update")
            self.assertEqual(report["host_package_messages"], ["fetch"])
            self.assertNotIn("PRIVATE", json.dumps(report) + result.stdout.decode())


if __name__ == "__main__":
    unittest.main()
