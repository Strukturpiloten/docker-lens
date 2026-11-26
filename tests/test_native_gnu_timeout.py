"""Host provider selection and prerequisite boundaries, without native work."""
import importlib.util
import io
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

from native_timeout_support import TIMER, system_timer

spec = importlib.util.spec_from_file_location("native_gnu_timeout", TIMER)
timer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timer)


class GNUTimeoutTests(unittest.TestCase):
    def test_normal_selector_and_shell_entry_ignore_benign_ambient_python_configuration(self):
        with tempfile.TemporaryDirectory(prefix="timer-ambient-") as tmp:
            root = Path(tmp)
            marker = root / "ambient-started"
            (root / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('benign')\n")
            environment = dict(os.environ, PYTHONPATH=tmp, PYTHONUSERBASE=tmp)
            result = subprocess.run([TIMER, "--path"], env=environment, capture_output=True,
                text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(result.stdout.removesuffix("\n"), ("/usr/bin/gnutimeout", "/usr/bin/timeout"))
            self.assertFalse(marker.exists(), "selector executed ambient Python configuration")
            sudo = root / "sudo"
            sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            sudo.chmod(0o700)
            body = ('source "$1/native-outer-runtime.sh"\n'
                    'native_outer_script_dir=$1\n'
                    'native_outer_cmd=(sudo -n inert-authored-client)\n'
                    'native_outer_command 8 literal\n')
            result = subprocess.run(["/bin/bash", "-c", body, "timer-test", str(Path(TIMER).parent)],
                env=environment | {"PATH": tmp + ":/usr/bin:/bin"}, capture_output=True,
                text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[1], system_timer())
            self.assertFalse(marker.exists(), "normal shell entry executed ambient configuration")

    def test_provider_probe_obeys_an_existing_expired_deadline(self):
        with patch.object(timer.os, "stat", return_value=SimpleNamespace(
                st_mode=0o100755, st_uid=0, st_dev=1, st_ino=1)), \
                patch.object(timer.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "existing GNU timeout"):
                timer.select(deadline=0)
            run.assert_not_called()

    def test_isolated_selection_accepts_only_successful_exact_system_paths(self):
        for status, output, accepted in (
            (0, b"/usr/bin/timeout\n", True), (0, b"/usr/bin/gnutimeout\n", True),
            (1, b"/usr/bin/timeout\n", False), (0, b"", False),
            (0, b"timeout\n", False), (0, b"/tmp/timer\n", False),
            (0, b" /usr/bin/timeout\n", False), (0, b"/usr/bin/timeout\nextra", False),
        ):
            with self.subTest(status=status, output=output), patch.object(timer.subprocess, "run",
                    return_value=SimpleNamespace(returncode=status, stdout=output)) as run:
                if accepted:
                    self.assertEqual(timer.selected_path(), output.decode().removesuffix("\n"))
                else:
                    with self.assertRaisesRegex(RuntimeError, "existing GNU timeout"):
                        timer.selected_path()
                self.assertEqual(run.call_args.args[0][:2], ("/usr/bin/python3", "-I"))

    def test_privileged_python_factories_independently_reject_invalid_selection_before_recording(self):
        root = Path(TIMER).parent
        sys.path.insert(0, str(root))
        self.addCleanup(sys.path.remove, str(root))
        modules = []
        for name in ("native-bridge-prerequisite", "native-rootless-kernel-window", "native-daemon-uid"):
            spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules.append(module)
        for selected in ("/usr/bin/timeout", "/usr/bin/gnutimeout", "", "timeout", "/tmp/timer",
                         " /usr/bin/timeout", "/usr/bin/timeout\nextra", None):
            for index, module in enumerate(modules):
                expected_error = (modules[0].BridgePrerequisiteError, modules[1].Unavailable, ValueError)[index]
                recorded = []
                def operation():
                    if index == 0:
                        argv = module.load_command()
                    elif index == 1:
                        argv = module.command(1000000, 2000000, 1000)
                    else:
                        argv = module.command("a" * 64, "podman", "/tmp/held;literal")
                    recorded.append(tuple(argv))  # Inert privilege argv recorder.
                with self.subTest(module=module.__name__, selected=selected), \
                        patch.object(module.os, "geteuid", return_value=1000), \
                        patch.object(module, "timeout_path", return_value=selected):
                    if selected in ("/usr/bin/timeout", "/usr/bin/gnutimeout"):
                        operation()
                        self.assertEqual(recorded[0][1:3], ("-n", selected))
                    else:
                        with self.assertRaises(expected_error):
                            operation()
                        self.assertEqual(recorded, [])
            for index, module in enumerate(modules):
                expected_error = (modules[0].BridgePrerequisiteError, modules[1].Unavailable, ValueError)[index]
                with self.subTest(module=module.__name__, unavailable=True), \
                        patch.object(module, "timeout_path", side_effect=RuntimeError(timer.PREREQUISITE)):
                    with self.assertRaises(expected_error):
                        if module is modules[0]: module.load_command()
                        elif module is modules[1]: module.command(1000000, 2000000, 1000)
                        else: module.command("a" * 64, "podman", "/tmp/held;literal")

    def test_shell_privilege_entries_reject_invalid_or_failed_selection_before_sudo(self):
        root = Path(TIMER).parent
        runtime = (root / "native-outer-runtime.sh").read_text()
        conformance = (root / "native-conformance.sh").read_text()
        def definition(source, name):
            start = source.index("\n" + name + "() {") + 1
            return source[start:source.index("\n}\n", start) + 3]
        entries = [
            (runtime, "native_outer_command", "native_outer_command 8 literal"),
            (runtime, "native_outer_helper", "native_outer_helper inert-observation"),
            (runtime, "native_outer_helper", "native_outer_helper network-preflight run-id " + "a" * 40),
            (runtime, "native_outer_bridge_command", "native_outer_bridge_command 8 inspect literal"),
            (runtime, "native_outer_preflight", "native_outer_engine=docker; native_outer_preflight"),
            (runtime, "native_outer_presence", 'native_outer_presence container owned "$fixture"'),
            (conformance, "cleanup_podman", "cleanup_podman inspect literal"),
            (conformance, "native_presence", 'native_presence exists sudo -n inert-authored-client container exists owned'),
            (conformance, "rootless_kernel_window_diagnostic", 'native_outer_engine=docker; rootless_kernel_window_diagnostic permission_denied'),
        ]
        with tempfile.TemporaryDirectory(prefix="timer-invalid-selection-") as tmp:
            fixture = Path(tmp)
            selector = fixture / "native_gnu_timeout.py"
            selector.write_text('#!/bin/sh\nprintf "%s" "$SELECTED"\nexit "$SELECTION_STATUS"\n')
            selector.chmod(0o700)
            sudo = fixture / "sudo"
            sudo.write_text('#!/bin/sh\nprintf "<%s>\\n" "$@" >> "$RECORD"\nexit 1\n')
            sudo.chmod(0o700)
            record = fixture / "record"
            for source, name, invocation in entries:
                for selected, status in (("/usr/bin/timeout", 0), ("/usr/bin/gnutimeout", 0),
                                         ("", 0), ("timeout", 0), ("/tmp/timer", 0),
                                         (" /usr/bin/timeout", 0), ("/usr/bin/timeout\nextra", 0),
                                         ("/usr/bin/timeout", 2)):
                    with self.subTest(entry=name, selected=selected, status=status):
                        record.unlink(missing_ok=True)
                        body = ('source "$1/native-outer-runtime.sh"\n' + definition(source, name)
                            + '\nfixture=$2; native_outer_script_dir=$2; script_dir=$2\n'
                            'native_outer_engine=podman; native_outer_directory=$2; run_dir=$2\n'
                            'native_outer_cmd=(sudo -n inert-authored-client); podman_cmd=(sudo -n inert-authored-client)\n'
                            'native_outer_privilege=(sudo -n); expected_mode=rootless\n'
                            'rootless_startup_us=10000000; rootless_startup_boot_ns=495000000000; watchdog_pid=$$; SECONDS=0\n'
                            # Model only timer execution when root has no sudo.
                            # Both allowed strings are testable without assuming
                            # that both programs exist in the utility layout.
                            'function /usr/bin/timeout { printf "<timer>\\n<%s>\\n" "$@" >> "$RECORD"; return 1; }\n'
                            'function /usr/bin/gnutimeout { /usr/bin/timeout "$@"; }\n'
                            + invocation + '\n')
                        environment = dict(PATH=tmp + ":/usr/bin:/bin", RECORD=str(record),
                            SELECTED=selected, SELECTION_STATUS=str(status), GITHUB_ACTIONS="true",
                            RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux", GITHUB_REF="refs/heads/main",
                            GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY="Strukturpiloten/docker-lens",
                            GITHUB_WORKFLOW_REF="Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main",
                            ImageOS="ubuntu24", ImageVersion="20261020.1.0")
                        result = subprocess.run(["/bin/bash", "-c", body, "timer-test", str(root), tmp],
                            env=environment, capture_output=True, text=True, timeout=5, check=False)
                        accepted = status == 0 and selected in ("/usr/bin/timeout", "/usr/bin/gnutimeout")
                        self.assertEqual(record.exists(), accepted, result.stderr)
                        if accepted:
                            if name == "rootless_kernel_window_diagnostic" and os.geteuid() == 0:
                                self.assertTrue(record.read_text().startswith("<timer>\n<--signal=TERM>\n"))
                            else:
                                self.assertIn("<-n>\n<" + selected + ">\n", record.read_text())

    def test_privilege_vectors_resolve_system_timer_before_recording_sudo(self):
        root = Path(TIMER).parent
        sys.path.insert(0, str(root))
        self.addCleanup(sys.path.remove, str(root))
        modules = []
        for name in ("native-bridge-prerequisite", "native-rootless-kernel-window", "native-daemon-uid"):
            spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules.append(module)
        bridge, journal, daemon = modules
        expected = system_timer()
        with patch.object(daemon.os, "geteuid", return_value=1000):
            daemon_vector = tuple(daemon.command("a" * 64, "podman", "/tmp/held;literal"))
        vectors = [bridge.load_command(), journal.command(1000000, 2000000, 1000), daemon_vector]
        with tempfile.TemporaryDirectory(prefix="timer-sudo-stub-") as tmp:
            stub = Path(tmp) / "sudo"
            stub.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
            stub.chmod(0o700)
            for vector in vectors:
                # Model only the privilege executable; forward the actual
                # production arguments unchanged, never run sudo or modprobe.
                self.assertIn(vector[0], ("sudo", "/usr/bin/sudo"))
                actual = subprocess.check_output([str(stub), *vector[1:]], text=True, timeout=5)
                self.assertEqual(json.loads(actual), list(vector[1:]))
                self.assertEqual(vector[1:3], ("-n", expected))
                self.assertNotIn(TIMER, vector)
            body = ('source "$1/native-outer-runtime.sh"\n'
                    'native_outer_script_dir=$1\n'
                    'native_outer_cmd=(sudo -n inert-authored-client)\n'
                    'native_outer_command 8 literal ";not-shell"\n')
            result = subprocess.run(["/bin/bash", "-c", body, "timer-test", str(root)],
                env=dict(os.environ, PATH=tmp + ":/usr/bin:/bin"), capture_output=True,
                text=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), ["-n", expected, "--signal=TERM",
                "--kill-after=2s", "8s", "inert-authored-client", "literal", ";not-shell"])
            source = (root / "native-conformance.sh").read_text()
            start = source.index("\ncleanup_podman() {") + 1
            definition = source[start:source.index("\n}\n", start) + 3]
            body = (definition + '\nscript_dir=$1\n'
                    'podman_cmd=(sudo -n inert-authored-client)\n'
                    'cleanup_podman literal ";not-shell"\n')
            result = subprocess.run(["/bin/bash", "-c", body, "timer-test", str(root)],
                env=dict(os.environ, PATH=tmp + ":/usr/bin:/bin"), capture_output=True,
                text=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), ["-n", expected, "--signal=TERM",
                "--kill-after=2s", "8s", "inert-authored-client", "literal", ";not-shell"])

    def test_real_selected_provider_identity_is_visible_to_offline_ci(self):
        result = subprocess.run([TIMER, "--identify"], capture_output=True, text=True,
                                timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^DOCKERLENS_GNU_TIMEOUT: path=/usr/bin/(gnu)?timeout version=[0-9.]+\n$")
        print(result.stdout, end="", flush=True)

    def test_uutils_is_not_accepted_as_the_original_gnu_owner(self):
        info = SimpleNamespace(st_mode=0o100755, st_uid=0, st_dev=1, st_ino=2)
        def version(argv, **kwargs):
            text = b"timeout (GNU coreutils) 9.7\n" if argv[0].endswith("gnutimeout") else b"timeout (uutils coreutils) 0.10.0\n"
            return SimpleNamespace(returncode=0, stdout=text)
        with patch.object(timer.os, "stat", return_value=info), patch.object(timer.subprocess, "run", side_effect=version):
            self.assertEqual(timer.select(), ("/usr/bin/gnutimeout", "9.7"))
        with patch.object(timer, "PATHS", ("/usr/bin/timeout",)), patch.object(timer.os, "stat", return_value=info), patch.object(timer.subprocess, "run", side_effect=version):
            with self.assertRaisesRegex(RuntimeError, "existing GNU timeout required"):
                timer.select()

    def test_existing_gnu_timeout_distributions_use_the_fixed_system_binary(self):
        info = SimpleNamespace(st_mode=0o100755, st_uid=0, st_dev=1, st_ino=2)
        def metadata(path):
            if path.endswith("gnutimeout"):
                raise FileNotFoundError()
            return info
        with patch.object(timer.os, "stat", side_effect=metadata), patch.object(timer.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"timeout (GNU coreutils) 9.12\n")):
            self.assertEqual(timer.select(), ("/usr/bin/timeout", "9.12"))

    def test_untrusted_changed_hanging_and_incomplete_providers_fail_before_exec(self):
        good = SimpleNamespace(st_mode=0o100755, st_uid=0, st_dev=1, st_ino=2)
        changed = SimpleNamespace(st_mode=0o100755, st_uid=0, st_dev=1, st_ino=3)
        for info in (SimpleNamespace(st_mode=0o100777, st_uid=0), SimpleNamespace(st_mode=0o100755, st_uid=1000)):
            with self.subTest(info=info), patch.object(timer.os, "stat", return_value=info), patch.object(timer.subprocess, "run") as probe:
                with self.assertRaises(RuntimeError):
                    timer.select()
                probe.assert_not_called()
        with patch.object(timer, "PATHS", ("/usr/bin/timeout",)), patch.object(timer.os, "stat", side_effect=[good, changed]), patch.object(timer.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"timeout (GNU coreutils) 9.12\n")):
            with self.assertRaises(RuntimeError):
                timer.select()
        for failure in (FileNotFoundError(), subprocess.TimeoutExpired("closed", 2)):
            with self.subTest(failure=type(failure).__name__), patch.object(timer.os, "stat", return_value=good), patch.object(timer.subprocess, "run", side_effect=failure):
                with self.assertRaises(RuntimeError):
                    timer.select()
        error = io.StringIO()
        with patch.object(timer, "select", side_effect=RuntimeError("private detail")), patch.object(timer.os, "execv") as execute, redirect_stderr(error):
            self.assertEqual(timer.main(["1s", "private-command"]), 2)
            execute.assert_not_called()
        self.assertEqual(error.getvalue(), timer.PREREQUISITE + "\n")

    def test_exec_keeps_original_arguments_without_new_timer_or_session(self):
        args = ["--signal=TERM", "--kill-after=2s", "8s", "original-command", "literal;value"]
        class Executed(BaseException):
            pass
        with patch.object(timer, "select", return_value=("/usr/bin/gnutimeout", "9.7")), patch.object(timer.os, "execv", side_effect=Executed) as execute:
            with self.assertRaises(Executed):
                timer.main(args)
        execute.assert_called_once_with("/usr/bin/gnutimeout", ("/usr/bin/gnutimeout", *args))
