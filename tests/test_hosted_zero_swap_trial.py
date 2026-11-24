"""Contracts for the fixed hosted VM boot trial."""

import errno
import grp
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack, contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/hosted-zero-swap-trial.py"
SPEC = importlib.util.spec_from_file_location("boot_trial", SOURCE)
assert SPEC is not None and SPEC.loader is not None
trial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trial)
PINS = json.loads((ROOT / "scripts/hosted-zero-swap-pins.json").read_text())
FIXTURE = PINS["fixture_image"].split(":v")[0] + "@" + PINS["fixture_image"].rsplit("@", 1)[1]


def host_environment(image_os="ubuntu26"):
    sha = "a" * 40
    return {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "ImageOS": image_os,
        "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_JOB": "hosted-zero-swap-trial",
        "GITHUB_WORKFLOW_REF": "Strukturpiloten/docker-lens/.github/workflows/hosted-zero-swap-trial.yml@refs/heads/main",
        "GITHUB_SHA": sha,
        "GITHUB_WORKFLOW_SHA": sha,
        "GITHUB_RUN_ID": "45153925181",
        "GITHUB_RUN_ATTEMPT": "1",
        "ImageVersion": "20261116.202.1",
    }


def runner_receipt_value(data):
    # Linux file-command semantics from Actions runner v2.338.2. The last
    # line may be unterminated. Only a matching delimiter completes the value.
    opening, *lines = data.split(b"\n")
    key, _, marker = opening.partition(b"<<")
    if key == b"receipt_path" and marker:
        for index, line in enumerate(lines):
            if line == marker:
                return b"\n".join(lines[:index])
    return None


def receipt_path(handoff):
    value = runner_receipt_value(handoff.read_bytes())
    if value is None:
        raise ValueError("No complete receipt handoff")
    return Path(value.decode("ascii"))


def command_json(value):
    return 0, json.dumps(value).encode(), b""


@contextmanager
def inert_kvm(
    *,
    failures=None,
    mode=stat.S_IFCHR,
    device=(10, 232),
    version=12,
    layout=None,
    named_gid=55103,
    effective_gid=55104,
    supplementary=(),
):
    failures = failures or {}
    metadata = {
        "st_mode": stat.S_IFCHR | 0o660,
        "st_rdev": os.makedev(10, 232),
        "st_uid": 0,
        "st_gid": 55103,
    } | (layout or {})
    calls = []
    device_fd, vm_fd = 40821, 40822
    real_open, real_fstat, real_close, real_lstat = os.open, os.fstat, os.close, os.lstat

    def observe(operation, value=None):
        calls.append(operation)
        if operation in failures:
            raise OSError(failures[operation], "private diagnostic", "/private/sentinel")
        return value

    def open_device(path, flags, *args, **kwargs):
        if os.fspath(path) != "/dev/kvm":
            return real_open(path, flags, *args, **kwargs)
        assert flags == os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        return observe("open", device_fd)

    def fstat(fd):
        if fd != device_fd:
            return real_fstat(fd)
        return observe("device_stat", SimpleNamespace(st_mode=mode, st_rdev=os.makedev(*device)))

    def lstat(path, *args, **kwargs):
        if os.fspath(path) != "/dev/kvm":
            return real_lstat(path, *args, **kwargs)
        return observe("device_metadata", SimpleNamespace(**metadata))

    def group_by_name(name):
        assert name == "kvm"
        gid = observe("group_lookup", named_gid)
        if gid is None:
            raise KeyError("missing group")
        return SimpleNamespace(gr_gid=gid)

    def ioctl(fd, number, *args):
        assert fd == device_fd
        if number == 0xAE00:
            assert not args
            return observe("api_version", version)
        assert (number, args) == (0xAE01, (0,))
        return observe("create_vm", vm_fd)

    def close(fd):
        if fd == vm_fd:
            observe("vm_close")
        elif fd == device_fd:
            observe("device_close")
        else:
            real_close(fd)

    with (
        patch.object(trial.os, "open", side_effect=open_device),
        patch.object(trial.os, "fstat", side_effect=fstat),
        patch.object(trial.fcntl, "ioctl", side_effect=ioctl),
        patch.object(trial.os, "close", side_effect=close),
        patch.object(trial.os, "lstat", side_effect=lstat),
        patch.object(grp, "getgrnam", side_effect=group_by_name),
        patch.object(
            trial.os, "getegid", side_effect=lambda: observe("effective_gid", effective_gid)
        ),
        patch.object(
            trial.os,
            "getgroups",
            side_effect=lambda: observe("supplementary_groups", supplementary),
        ),
    ):
        yield calls


class BootTrial(unittest.TestCase):
    def deadline(self):
        return time.monotonic() + 5

    def test_capture_limits_status_and_first_failure(self):
        with patch.object(trial, "OUTPUT_LIMIT", 1024):
            argv = [sys.executable, "-c", "import sys;sys.stdout.write('a'*1024);sys.exit(19)"]
            code, stdout, stderr = trial.capture(argv, self.deadline(), allow_failure=True)
            self.assertEqual((code, len(stdout), stderr), (19, 1024, b""))
            for stream in ("stdout", "stderr"):
                script = f"import sys;sys.{stream}.write('a'*1025)"
                with self.assertRaises(trial.Refusal) as raised:
                    trial.capture([sys.executable, "-c", script], self.deadline())
                self.assertEqual(raised.exception.reason, "output_limit")
            with (
                patch.object(trial, "reap", return_value=False),
                patch.object(trial, "command_cleanup_failed", False),
            ):
                with self.assertRaises(trial.Refusal) as raised:
                    trial.capture(argv, self.deadline())
                self.assertEqual(
                    (raised.exception.reason, raised.exception.code), ("command_failed", 19)
                )
                self.assertTrue(trial.command_cleanup_failed)

    def test_capture_timeout_reaps_its_process(self):
        with patch.object(trial, "reap", wraps=trial.reap) as reap:
            with self.assertRaises(trial.Refusal) as raised:
                trial.capture(
                    [sys.executable, "-c", "import time;time.sleep(60)"], time.monotonic() + 0.15
                )
            self.assertEqual((raised.exception.reason, raised.exception.code), ("timeout", 124))
            self.assertIsNotNone(reap.call_args.args[0].poll())

    def test_cancellation_stops_work_and_preserves_first_signal(self):
        with patch.object(trial, "cancelled", None):
            trial.request_cancel(signal.SIGINT, None)
            trial.request_cancel(signal.SIGTERM, None)
            with self.assertRaises(trial.Refusal) as raised:
                trial.capture([sys.executable, "-c", "raise SystemExit(0)"], self.deadline())
            self.assertEqual((raised.exception.reason, raised.exception.code), ("cancelled", 130))
            self.assertEqual(
                trial.remove_container([], None, "name", "token", self.deadline(), False),
                "not_created",
            )
            self.assertEqual(trial.cancelled, signal.SIGINT)

    def test_real_signal_cancellation_reaps_running_child(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "child"
            control = """
import importlib.util, signal, sys, time
spec = importlib.util.spec_from_file_location("trial", sys.argv[1])
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)
signal.signal(signal.SIGTERM, trial.request_cancel)
program = ("from pathlib import Path; import os, sys, time; dst=Path(sys.argv[1]); "
           "tmp=dst.with_suffix('.tmp'); tmp.write_text(str(os.getpid())); tmp.replace(dst); time.sleep(30)")
try:
    trial.capture([sys.executable, "-c", program, sys.argv[2]], time.monotonic() + 8)
except trial.Refusal as error:
    assert error.reason == "cancelled" and not trial.command_cleanup_failed
    sys.exit(error.code)
"""
            with subprocess.Popen(
                [sys.executable, "-B", "-c", control, str(SOURCE), str(identity)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as parent:
                deadline = self.deadline()
                while (
                    not identity.exists() and parent.poll() is None and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                child = int(identity.read_text())
                parent.send_signal(signal.SIGTERM)
                self.assertEqual(parent.communicate(timeout=5), (b"", b""))
                self.assertEqual(parent.returncode, 143)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)

    def test_admission_binds_protected_main_and_exact_clean_checkout(self):
        sha = "a" * 40
        env = host_environment()
        with patch.object(
            trial, "capture", side_effect=[(0, (sha + "\n").encode(), b""), (0, b"", b"")]
        ) as run:
            self.assertEqual(trial.admitted_host(ROOT, env)["workflow_sha"], sha)
            self.assertEqual(
                [call.args[0][-2:] for call in run.call_args_list],
                [["rev-parse", "HEAD"], ["--porcelain", "--untracked-files=all"]],
            )
        with patch.object(trial, "capture") as run:
            for field in (
                "GITHUB_REF_PROTECTED",
                "GITHUB_REF",
                "GITHUB_WORKFLOW_REF",
                "GITHUB_WORKFLOW_SHA",
                "RUNNER_ENVIRONMENT",
                "GITHUB_EVENT_NAME",
                "ImageOS",
            ):
                with self.subTest(field=field), self.assertRaises(trial.Refusal):
                    trial.admitted_host(ROOT, env | {field: "incorrect"})
            run.assert_not_called()
        for head, status in (("b" * 40, b""), (sha, b"?? unexpected\n")):
            with patch.object(
                trial, "capture", side_effect=[(0, (head + "\n").encode(), b""), (0, status, b"")]
            ):
                with self.assertRaises(trial.Refusal):
                    trial.admitted_host(ROOT, env)

    def test_workflow_runner_binds_admission_and_separate_host_guest_package_plans(self):
        # This independently reviewed tuple must change together. A label-only
        # runner update must not leave admission or package sources behind.
        labels = re.findall(r"(?m)^    runs-on: (\S+)$", (ROOT / trial.WORKFLOW).read_text())
        self.assertEqual(labels, ["ubuntu-26.04"])
        image_os, host_suite = {"ubuntu-26.04": ("ubuntu26", "resolute")}[labels[0]]
        env = host_environment(image_os)
        with patch.object(
            trial,
            "capture",
            side_effect=[(0, (env["GITHUB_SHA"] + "\n").encode(), b""), (0, b"", b"")],
        ):
            trial.admitted_host(ROOT, env)
        for foreign_image in ("ubuntu24", "ubuntu22", "ubuntu28", "ubuntu26-arm64"):
            with patch.object(trial, "capture") as run, self.assertRaises(trial.Refusal):
                trial.admitted_host(ROOT, env | {"ImageOS": foreign_image})
            run.assert_not_called()

        for scope, suite in (("host", host_suite), ("guest", "noble")):
            self.assertEqual(PINS[scope + "_apt_suite"], suite)
            packages = PINS[scope + "_packages"]
            actual = "".join(f"{name}={version} installed\n" for name, version in packages.items())
            with (
                tempfile.TemporaryDirectory() as temporary,
                patch.object(
                    trial, "capture", side_effect=[(0, b"", b"")] * 4 + [(0, actual.encode(), b"")]
                ) as run,
            ):
                trial.packages(PINS, scope, Path(temporary), self.deadline())
                source = (Path(temporary) / "apt.sources").read_text()
                self.assertIn(f"Suites: {suite} {suite}-updates {suite}-security\n", source)
                self.assertIn(f"URIs: {trial.ARCHIVE}{PINS['apt_snapshot']}/\n", source)
                install = run.call_args_list[3].args[0]
                self.assertEqual(
                    install[:2],
                    ["sudo", "-n"]
                    if scope == "host"
                    else ["env", "DEBIAN_FRONTEND=noninteractive"],
                )
                self.assertIn("--no-upgrade", install)
                self.assertIn("--no-remove", install)
                self.assertEqual(
                    install[-len(packages) :], [f"{p}={v}" for p, v in packages.items()]
                )

        self.assertEqual(trial.IMAGE, "ubuntu-24.04-server-cloudimg-amd64.img")
        date, digest = PINS["cloud_image"].split("@sha256:")

        def fetch(_url, path, _limit, _deadline):
            path.write_text(f"{digest} *{trial.IMAGE}\n" if path.name == "SHA256SUMS" else "inert")

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(trial, "fetch", side_effect=fetch),
            patch.object(
                trial,
                "capture",
                side_effect=[
                    (0, b"", b""),
                    (0, f"[GNUPG:] VALIDSIG {trial.SIGNER} \n".encode(), b""),
                ],
            ),
        ):
            self.assertEqual(
                trial.verify_cloud_manifest(Path(temporary), date, digest, self.deadline()),
                f"https://cloud-images.ubuntu.com/releases/noble/release-{date}/",
            )

    def test_real_unadmitted_execution_selects_only_its_fresh_closed_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stale = root / trial.RESULT
            stale.write_text('{"exit":0,"reason":"ok"}\n')
            published = []
            for attempt in (1, 2):
                handoff = root / f"set_output_{attempt}"
                handoff.touch()
                result = subprocess.run(
                    [sys.executable, "-B", str(SOURCE)],
                    env={"RUNNER_TEMP": directory, "GITHUB_OUTPUT": str(handoff)},
                    capture_output=True,
                    check=False,
                    timeout=8,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(
                    result.stdout,
                    b"DOCKERLENS_HOSTED_BOOT_TRIAL: stage=admission exit=1 "
                    b"reason=refused cleanup=not_started\n",
                )
                path = receipt_path(handoff)
                published.append(path)
                self.assertEqual(path.parent.parent, root)
                self.assertEqual(path.name, trial.RESULT)
                self.assertEqual(list(path.parent.iterdir()), [path])
                report = json.loads(path.read_text())
                self.assertEqual(report["exit"], 1)
                self.assertEqual(
                    set(report),
                    {"schema", "trial", "stage", "exit", "reason", "cleanup", "elapsed_ms"},
                )
            self.assertNotEqual(published[0], published[1])
            self.assertEqual(json.loads(stale.read_text())["exit"], 0)
        workflow = (ROOT / trial.WORKFLOW).read_text()
        self.assertIn("id: trial", workflow)
        self.assertIn("always() && steps.trial.outputs.receipt_path != ''", workflow)
        self.assertIn("path: " + chr(36) + "{{ steps.trial.outputs.receipt_path }}", workflow)
        self.assertNotIn("runner.temp", workflow)

    def test_receipt_write_failure_and_destination_collision_do_not_hand_off(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / trial.RESULT
            handoff = root / "set_output"
            with handoff.open("xb", buffering=0) as channel:

                def short_json(_, stream, **_settings):
                    stream.write('{"exit":')
                    raise OSError()

                with (
                    patch.object(trial.json, "dump", side_effect=short_json),
                    self.assertRaises(OSError),
                ):
                    trial.publish_receipt(output, channel.fileno(), {"exit": 1})
                self.assertFalse(output.exists())
                self.assertEqual(list(root.iterdir()), [handoff])
                output.write_text('{"exit":0}\n')
                with self.assertRaises(FileExistsError):
                    trial.publish_receipt(output, channel.fileno(), {"exit": 1})
                self.assertEqual(output.read_text(), '{"exit":0}\n')
                self.assertEqual(handoff.read_bytes(), b"")

    def test_short_handoff_cannot_select_a_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            handoff = root / "set_output"
            output = root / trial.RESULT
            write = os.write
            with handoff.open("xb", buffering=0) as channel:
                with (
                    patch.object(
                        trial.os,
                        "write",
                        side_effect=lambda fd, data: write(
                            fd, data[: data.index(output.name.encode())]
                        ),
                    ),
                    self.assertRaises(OSError),
                ):
                    trial.publish_receipt(output, channel.fileno(), {"exit": 1})
            self.assertEqual(json.loads(output.read_text()), {"exit": 1})
            with self.assertRaises(ValueError):
                receipt_path(handoff)

    def test_apt_exact_source_seed_and_refusal_before_install(self):
        packages = PINS["host_packages"]
        actual = "".join(
            f"{name}={version} installed\n" for name, version in packages.items()
        ).encode()
        for plan, admitted in [
            (b"Inst qemu-utils (exact)\n", True),
            (b"Inst libc6 [1.1] (1.2)\n", False),
            (b"Remv docker-ce [1.1]\n", False),
        ]:
            with self.subTest(plan=plan), tempfile.TemporaryDirectory() as temporary:
                with patch.object(
                    trial,
                    "capture",
                    side_effect=[
                        (0, b"", b""),
                        (0, plan, b""),
                        (0, b"", b""),
                        (0, b"", b""),
                        (0, actual, b""),
                    ],
                ) as run:
                    if admitted:
                        self.assertEqual(
                            trial.packages(PINS, "host", Path(temporary), self.deadline()), packages
                        )
                        self.assertEqual(run.call_args_list[3].args[0][:2], ["sudo", "-n"])
                        self.assertIn("--no-remove", run.call_args_list[3].args[0])
                        self.assertIn("--no-upgrade", run.call_args_list[3].args[0])
                        self.assertEqual(
                            run.call_args.args[0][2],
                            r"-f=${Package}=${Version} ${db:Status-Status}\n",
                        )
                    else:
                        with self.assertRaises(trial.Refusal):
                            trial.packages(PINS, "host", Path(temporary), self.deadline())
                        self.assertEqual(run.call_count, 2)
                self.assertIn("20261017T000000Z/", (Path(temporary) / "apt.sources").read_text())
                self.assertIn(
                    "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg",
                    (Path(temporary) / "apt.sources").read_text(),
                )

    def test_signed_image_row_is_exact_unique_and_valid(self):
        digest = PINS["cloud_image"].split(":", 1)[1]
        row = f"{digest} *{trial.IMAGE}\n"
        trial.verify_manifest_row(row, digest)
        for manifest in (
            row + row,
            row.replace(digest, "a" * 64),
            row.replace(trial.IMAGE, "other.img"),
        ):
            with self.assertRaises(trial.Refusal):
                trial.verify_manifest_row(manifest, digest)

    def test_source_bound_image_inspection_for_both_pinned_store_shapes(self):
        fixture = {"RepoDigests": [FIXTURE], "Os": "linux", "Architecture": "amd64"}
        index = FIXTURE.rsplit("@", 1)[-1]
        config = PINS["fixture_config"]
        manifest = PINS["fixture_platform"]
        classic = fixture | {"Id": config}
        default = fixture | {"Id": index, "Descriptor": {"digest": index}}
        selected = fixture | {"Id": manifest, "Descriptor": {"digest": manifest}}
        for replies, expected in [
            ([classic], (config, None)),
            ([classic | {"Descriptor": None}], (config, None)),
            ([default, selected], (index, manifest)),
            ([classic | {"Id": manifest}], None),
            ([classic | {"Descriptor": {"digest": manifest}}], None),
            ([default | {"Descriptor": {"digest": manifest}}, selected], None),
            ([default | {"Descriptor": None}, selected], None),
            ([default, selected | {"Id": index}], None),
            ([default, selected | {"Descriptor": {"digest": index}}], None),
            ([default, selected | {"Descriptor": "not an object"}], None),
            ([default, selected | {"RepoDigests": [FIXTURE, FIXTURE]}], None),
            *[
                ([classic | {"RepoDigests": value}], None)
                for value in (
                    "prefix;" + FIXTURE + ";suffix",
                    [FIXTURE, 23],
                    [FIXTURE + ";suffix"],
                    None,
                )
            ],
        ]:
            with (
                self.subTest(replies=replies),
                patch.object(trial, "capture", side_effect=list(map(command_json, replies))) as run,
            ):
                args = (["docker"], PINS["fixture_image"], FIXTURE, PINS, self.deadline())
                if expected is None:
                    with self.assertRaises(trial.Refusal):
                        trial.bind_image(*args)
                else:
                    self.assertEqual(trial.bind_image(*args), expected)
                    if len(replies) == 2:
                        self.assertEqual(
                            run.call_args.args[0][-3:],
                            ["--platform", "linux/amd64", PINS["fixture_image"]],
                        )

        for descriptor in ({}, {"ImageManifestDescriptor": None}):
            trial.bind_container_image({"Image": config} | descriptor, config, None)
        trial.bind_container_image(
            {"Image": index, "ImageManifestDescriptor": {"digest": manifest}}, index, manifest
        )
        for image, descriptor in (
            (config, {"digest": manifest}),
            (index, None),
            (index, {"digest": index}),
            (index, "not an object"),
            (index, []),
            (manifest, {"digest": manifest}),
        ):
            with self.subTest(image=image, descriptor=descriptor), self.assertRaises(trial.Refusal):
                expected_id = config if image == config else index
                trial.bind_container_image(
                    {"Image": image, "ImageManifestDescriptor": descriptor},
                    expected_id,
                    None if expected_id == config else manifest,
                )

    def test_cleanup_only_removes_bound_owner_and_checks_id_and_name_absence(self):
        name, token, cid = "dockerlens-boot-trial-" + "1" * 32, "1" * 32, "2" * 64
        original = {
            "Id": cid,
            "Name": "/" + name,
            "Config": {"Labels": {"io.dockerlens.boot-trial": token}},
        }
        absent = [
            (1, b"[]\n", f"Error: No such container: {key}\n".encode()) for key in (cid, name)
        ]
        for same_owner, responses, expected in [
            (True, [(0, b"", b""), *absent], "removed"),
            (
                True,
                [(0, b"", b""), absent[0], (1, b"", b"unclassified private output")],
                "unverified",
            ),
            (False, [], "unverified"),
        ]:
            with self.subTest(expected=expected, same_owner=same_owner):
                info = original if same_owner else original | {"Name": "/another"}
                with (
                    patch.object(trial, "inspect", return_value=info),
                    patch.object(trial, "capture", side_effect=responses) as run,
                ):
                    self.assertEqual(
                        trial.remove_container(["docker"], cid, name, token, self.deadline(), True),
                        expected,
                    )
                    if same_owner:
                        self.assertEqual(
                            [item.args[0][-1] for item in run.call_args_list], [cid, cid, name]
                        )
                    else:
                        run.assert_not_called()

    def test_receipt_requires_matching_status_complete_proof_and_separate_cleanup(self):
        host_boot = "c" * 64
        value = {
            "stage": "complete",
            "reason": "ok",
            "exit": 0,
            "cleanup": "removed",
            "boot": {
                "kernel": "6.8.0-92-generic",
                "identity_sha256": "d" * 64,
                "swap_kib": 0,
                "vcpus": 2,
            },
            "docker": {"server": "29.1.3", "rootful_peer": True},
            "packages": PINS["guest_packages"],
            "fixture": {
                "index": FIXTURE.rsplit("@", 1)[1],
                "platform": PINS["fixture_platform"],
                "package": PINS["fixture_debian_package"],
                "swap_kib": 0,
                "memory_bytes": 4294967296,
                "pids": 512,
                "cpu_quota": 200000,
                "cpu_period": 100000,
            },
            "disk_used_sample_bytes": 2_539_696_128,
        }
        self.assertEqual(trial.verify_guest(value, 0, PINS, host_boot), value)
        for field, wrong in (
            ("boot", value["boot"] | {"identity_sha256": host_boot}),
            ("fixture", value["fixture"] | {"swap_kib": 1}),
            ("cleanup", "unverified"),
            ("disk_used_sample_bytes", True),
            ("private_content", "secret"),
        ):
            with self.subTest(field=field), self.assertRaises(trial.Refusal):
                trial.verify_guest(value | {field: wrong}, 0, PINS, host_boot)
        with self.assertRaises(trial.Refusal):
            trial.json_document(b'{"exit":0,"exit":1}')
        failure = {
            "stage": "fixture_create",
            "reason": "command_failed",
            "exit": 53,
            "cleanup": "unverified",
            "command_cleanup": "unverified",
        }
        self.assertEqual(trial.verify_guest(failure, 53, PINS, host_boot), failure)
        with self.assertRaises(trial.Refusal):
            trial.verify_guest(failure, 1, PINS, host_boot)

    def test_guest_response_framing_retains_transport_status(self):
        host_boot = "c" * 64
        failure = {"stage": "boot", "reason": "refused", "exit": 1, "cleanup": "not_created"}
        raw = json.dumps(failure).encode() + b"\n"
        self.assertEqual(trial.guest_report(raw, 1, PINS, host_boot), failure)
        for receipt, status, expected in [
            (b"", 255, ("command_failed", 255)),
            (raw + raw, 19, ("guest_response", 19)),
            (raw[:-1], 1, ("guest_response", 1)),
            (raw, 0, ("guest_response", 1)),
        ]:
            with (
                self.subTest(status=status, expected=expected),
                self.assertRaises(trial.Refusal) as raised,
            ):
                trial.guest_report(receipt, status, PINS, host_boot)
            self.assertEqual((raised.exception.reason, raised.exception.code), expected)

    def test_kvm_probe_classifies_each_operation_and_preserves_closes(self):
        checked = ["open", "device_stat", "api_version", "create_vm"]
        closed = ["vm_close", "device_close"]
        for options, last, detail, vm_close, device_close, calls in (
            ({}, "complete", "ok", "closed", "closed", checked + closed),
            (
                {"failures": {"open": errno.ENOENT}},
                "open",
                "absent",
                "not_opened",
                "not_opened",
                ["open"],
            ),
            (
                {"failures": {"open": errno.ELOOP}},
                "open",
                "other",
                "not_opened",
                "not_opened",
                ["open"],
            ),
            (
                {"failures": {"device_stat": errno.EIO, "device_close": errno.EPERM}},
                "device_stat",
                "other",
                "not_opened",
                "denied",
                checked[:2] + closed[1:],
            ),
            (
                {"mode": stat.S_IFREG},
                "device_type",
                "mismatch",
                "not_opened",
                "closed",
                checked[:2] + closed[1:],
            ),
            (
                {"device": (1, 3)},
                "device_identity",
                "mismatch",
                "not_opened",
                "closed",
                checked[:2] + closed[1:],
            ),
            (
                {"version": 99, "failures": {"device_close": errno.EIO}},
                "api_version",
                "mismatch",
                "not_opened",
                "other",
                checked[:3] + closed[1:],
            ),
            (
                {"failures": {"api_version": errno.EACCES}},
                "api_version",
                "denied",
                "not_opened",
                "closed",
                checked[:3] + closed[1:],
            ),
            (
                {"failures": {"api_version": errno.ENOTTY}},
                "api_version",
                "unsupported",
                "not_opened",
                "closed",
                checked[:3] + closed[1:],
            ),
            (
                {"failures": {"create_vm": errno.ENODEV}},
                "create_vm",
                "absent",
                "not_opened",
                "closed",
                checked + closed[1:],
            ),
            (
                {"failures": {"vm_close": errno.EIO, "device_close": errno.EPERM}},
                "vm_close",
                "other",
                "other",
                "denied",
                checked + closed,
            ),
            (
                {"failures": {"device_close": errno.EIO}},
                "device_close",
                "other",
                "closed",
                "other",
                checked + closed,
            ),
        ):
            with self.subTest(options=options), inert_kvm(**options) as actual:
                probe = {}
                if last == "complete":
                    trial.kvm_preflight(probe)
                else:
                    with self.assertRaises(trial.Refusal) as raised:
                        trial.kvm_preflight(probe)
                    self.assertEqual(
                        raised.exception.reason,
                        "refused" if detail == "mismatch" else "unavailable",
                    )
                self.assertEqual(actual, calls)
                self.assertEqual(
                    probe,
                    {
                        "operation": last,
                        "detail": detail,
                        "vm_close": vm_close,
                        "device_close": device_close,
                    },
                )

    def test_kvm_denied_open_observes_only_closed_group_facts(self):
        metadata = ["open", "device_metadata"]
        lookup = metadata + ["group_lookup"]
        effective = lookup + ["effective_gid"]
        membership = effective + ["supplementary_groups"]
        for options, status, calls in (
            ({}, "group_rw_not_held", membership),
            ({"layout": {"st_mode": stat.S_IFCHR | 0o664}}, "group_rw_not_held", membership),
            ({"effective_gid": 55103}, "group_rw_held", effective),
            ({"supplementary": (55112, 55103)}, "group_rw_held", membership),
            ({"layout": {"st_mode": stat.S_IFLNK | 0o660}}, "other_layout", metadata),
            ({"layout": {"st_mode": stat.S_IFREG | 0o660}}, "other_layout", metadata),
            ({"layout": {"st_rdev": os.makedev(1, 3)}}, "other_layout", metadata),
            ({"layout": {"st_uid": 55112}}, "other_layout", metadata),
            ({"layout": {"st_gid": 55112}}, "other_layout", lookup),
            ({"layout": {"st_mode": stat.S_IFCHR | 0o640}}, "other_layout", metadata),
            ({"layout": {"st_mode": stat.S_IFCHR | 0o620}}, "other_layout", metadata),
            ({"layout": {"st_mode": stat.S_IFCHR | 0o662}}, "other_layout", metadata),
            ({"failures": {"device_metadata": errno.ENOENT}}, "unobserved", metadata),
            ({"named_gid": None}, "unobserved", lookup),
            ({"failures": {"group_lookup": errno.EIO}}, "unobserved", lookup),
            ({"failures": {"effective_gid": errno.EIO}}, "unobserved", effective),
            ({"failures": {"supplementary_groups": errno.EIO}}, "unobserved", membership),
        ):
            for denial in (errno.EACCES, errno.EPERM):
                settings = options | {"failures": options.get("failures", {}) | {"open": denial}}
                with self.subTest(options=options, denial=denial), inert_kvm(**settings) as actual:
                    probe = {}
                    with self.assertRaises(trial.Refusal) as raised:
                        trial.kvm_preflight(probe)
                    self.assertEqual(
                        (raised.exception.code, raised.exception.reason), (1, "unavailable")
                    )
                    self.assertEqual(actual, calls)
                    self.assertEqual(
                        probe,
                        {
                            "operation": "open",
                            "detail": "denied",
                            "device_close": "not_opened",
                            "vm_close": "not_opened",
                            "group_observation": status,
                        },
                    )

    def test_vm_argv_is_kvm_only_and_probe_shell_is_valid(self):
        with patch.object(trial.subprocess, "Popen") as spawn:
            trial.launch_vm(Path("/own"), 47953)
        argv = spawn.call_args.args[0]
        self.assertIn("accel=kvm", argv)
        self.assertNotIn("accel=tcg", argv)
        self.assertIn("user,id=net,hostfwd=tcp:127.0.0.1:47953-:22", argv)
        self.assertIn("file=/own/seed.iso,format=raw,media=cdrom,readonly=on", argv)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        subprocess.run(
            ["/bin/sh", "-n"], input=trial.CONTAINER_PROBE.encode(), check=True, timeout=5
        )


class EntrypointTrial(unittest.TestCase):
    def guest(self, *, security=(), rootless=..., cancel=False, work_failure=None, absent=True):
        token, cid, host_boot = "a" * 32, "b" * 64, "c" * 64
        boot_row = b"00000000-0000-0000-0000-000000000000\n"
        boot = hashlib.sha256(boot_row).hexdigest()
        cgroup = "/system.slice/docker-fixture.scope"
        name = "dockerlens-boot-trial-" + token
        observed = {
            "Id": cid,
            "Name": "/" + name,
            "Image": PINS["fixture_config"],
            "Config": {"Labels": {"io.dockerlens.boot-trial": token}},
            "State": {"Running": True, "Pid": 42},
            "HostConfig": {
                "CgroupnsMode": "private",
                "Privileged": True,
                "Memory": 4 << 30,
                "PidsLimit": 512,
                "CpuPeriod": 100000,
                "CpuQuota": 200000,
                "NetworkMode": "none",
            },
        }
        fs_reads = {
            "/etc/dockerlens-trial-id": token + "\n",
            "/proc/meminfo": "MemTotal: 7000000 kB\n",
            "/proc/42/cgroup": "0::" + cgroup + "\n",
        }
        fs_stats = {
            "/proc/42/ns/cgroup": 92,
            "/proc/self/ns/cgroup": 91,
            "/sys/fs/cgroup" + cgroup: 90,
        }

        def source_path(*args):
            path = Path(*args)
            key = str(path)
            if key in fs_reads:
                return Mock(read_text=Mock(return_value=fs_reads[key]))
            if key == "/sys/fs/cgroup":
                return sysfs
            if key in fs_stats:
                return Mock(
                    stat=Mock(return_value=SimpleNamespace(st_ino=fs_stats[key], st_dev=23))
                )
            return path

        class CgroupPath:
            def __truediv__(self, key):
                return source_path(Path("/sys/fs/cgroup") / key)

        sysfs = CgroupPath()
        calls = []

        def provision(pins, scope, work, _deadline):
            self.assertEqual(pins, PINS)
            self.assertEqual(scope, "guest")
            self.assertIsInstance(work, Path)
            return PINS["guest_packages"]

        def run(argv, _deadline, **options):
            if argv[:1] == ["systemd-detect-virt"]:
                return 0, b"kvm\n", b""
            if argv[:1] == ["stat"]:
                return 0, b"proc\n", b""
            if argv[:1] == ["systemctl"]:
                return 0, b"", b""
            self.assertEqual(argv[0], "docker")
            command = argv[5:]
            calls.append(tuple(command[:2]))
            if command[0] == "info":
                info = {
                    "ServerVersion": "29.1.3",
                    "OSType": "linux",
                    "DockerRootDir": "/var/lib/docker",
                    "CgroupVersion": "2",
                    "SecurityOptions": list(security) if type(security) is tuple else security,
                }
                if rootless is not ...:
                    info["Rootless"] = rootless
                return command_json(info)
            if command[:2] == ["image", "inspect"]:
                return command_json(
                    {
                        "Id": PINS["fixture_config"],
                        "RepoDigests": [FIXTURE],
                        "Os": "linux",
                        "Architecture": "amd64",
                    }
                )
            if command[:2] == ["container", "create"]:
                Path(argv[argv.index("--cidfile") + 1]).write_text(cid + "\n")
                return 0, (cid + "\n").encode(), b""
            if command[0] == "exec":
                if work_failure is not None:
                    raise trial.Refusal("command_failed", work_failure)
                return (
                    0,
                    b"23 90\n" + PINS["fixture_debian_package"].encode() + b"\n" + boot_row,
                    b"",
                )
            if command[:2] == ["container", "inspect"]:
                if not options.get("allow_failure"):
                    return command_json(observed)
                if argv[-1] == name and cancel:
                    trial.request_cancel(signal.SIGTERM, None)
                if not absent and argv[-1] == name:
                    return 1, b"", b"verification unavailable"
                return 1, b"[]\n", f"Error: No such container: {argv[-1]}\n".encode()
            self.assertTrue(
                command[0] == "pull" or command[:2] in (["container", "start"], ["container", "rm"])
            )
            return 0, b"", b""

        with (
            patch.object(trial, "capture", side_effect=run),
            patch.object(trial, "Path", side_effect=source_path),
            patch.object(trial.os, "geteuid", return_value=0),
            patch.object(trial.os, "cpu_count", return_value=2),
            patch.object(
                trial.os,
                "statvfs",
                return_value=SimpleNamespace(f_blocks=140, f_bfree=40, f_frsize=1024),
            ),
            patch.object(trial, "swap_zero"),
            patch.object(trial, "boot_id", return_value=boot),
            patch.object(trial, "packages", side_effect=provision) as installer,
            patch.object(trial, "docker_peer"),
            patch.object(trial, "fixture_identity", return_value=FIXTURE),
            patch.object(trial, "cancelled", None),
            redirect_stdout(io.StringIO()) as record,
        ):
            code = trial.within_guest([token, host_boot, json.dumps(PINS)])
            installer.assert_called_once()
        return code, json.loads(record.getvalue()), calls

    def test_guest_cancellation_during_real_cleanup_preserves_work_and_cleanup(self):
        for cancel, work_error, absent, expected in (
            (False, None, True, (0, "ok", "removed")),
            (True, None, True, (143, "cancelled", "removed")),
            (True, None, False, (143, "cancelled", "unverified")),
            (True, 41, True, (41, "command_failed", "removed")),
            (False, None, False, (1, "cleanup_failed", "unverified")),
        ):
            with self.subTest(cancel=cancel, work_error=work_error, absent=absent):
                code, report, calls = self.guest(
                    cancel=cancel, work_failure=work_error, absent=absent
                )
                self.assertEqual((code, report["reason"], report["cleanup"]), expected)
                self.assertEqual(report["exit"], code)
                self.assertIn(("container", "rm"), calls)
                self.assertEqual(
                    report["stage"], "fixture_observe" if work_error is not None else "complete"
                )

    def test_guest_refuses_malformed_security_options_before_any_fixture_call(self):
        for options, rootless in (
            ("name=rootless", False),
            (["name=userns"], False),
            (["name=rootless,option=yes"], False),
            (["name=seccomp", 23], False),
            (None, False),
            ([], True),
            ([], None),
            ([], "false"),
        ):
            with self.subTest(options=options, rootless=rootless):
                code, report, calls = self.guest(security=options, rootless=rootless)
                self.assertEqual(
                    (code, report["stage"], report["reason"], report["cleanup"]),
                    (1, "docker_peer", "refused", "not_created"),
                )
                self.assertEqual(calls, [("info", "--format")])
        code, report, _ = self.guest(security=["name=seccomp,profile=builtin", "name=cgroupns"])
        self.assertEqual((code, report["stage"]), (0, "complete"))

    def host(
        self, probes, *, cloud_failure=None, publish_failure=False, vm_exit_after=None, kvm=None
    ):
        now, deadlines, host_boot = [0], [], "e" * 64
        digest = PINS["cloud_image"].split("@sha256:")[1]
        guest_code, guest, _ = self.guest()
        self.assertEqual(guest_code, 0)

        def fake_path(*args):
            if args == ("/proc/meminfo",):
                return Mock(read_text=Mock(return_value="MemAvailable: 11000000 kB\n"))
            return Path(*args)

        def run(argv, deadline, **options):
            if argv[0] == "qemu-img":
                return command_json({"format": "qcow2", "virtual-size": 100})
            self.assertEqual(argv[0], "ssh")
            if "/etc/dockerlens-trial-id" in argv[-1]:
                self.assertTrue(options["allow_failure"])
                outcome = probes[len(deadlines)]
                deadlines.append(deadline)
                if outcome in ("ready", "late_ready"):
                    if outcome == "late_ready":
                        now[0] = 100
                    return 0, b"", b""
                if outcome == "exit":
                    return 255, b"", b""
                if outcome not in ("turn_cancelled", "failure"):
                    now[0] = 100 if outcome == "absolute" else deadline
                if outcome == "lost_cleanup":
                    trial.command_cleanup_failed = True
                if outcome in ("cancelled", "turn_cancelled"):
                    trial.request_cancel(signal.SIGTERM, None)
                if outcome == "turn_cancelled":
                    trial.active(deadline)
                if outcome == "failure":
                    raise trial.Refusal("output_limit")
                raise trial.Refusal("timeout", 124)
            if "--wait" in argv[-1]:
                if cloud_failure is not None:
                    raise trial.Refusal("command_failed", cloud_failure)
                return 0, b"", b""
            self.assertEqual(options["input_bytes"], SOURCE.read_bytes())
            remote = shlex.split(argv[-1])
            self.assertEqual(remote[:6], ["sudo", "-n", "python3", "-B", "-", "guest"])
            self.assertEqual(len(remote), 9)
            self.assertRegex(remote[6], r"^[a-f0-9]{32}$")
            self.assertEqual(remote[7], host_boot)
            self.assertEqual(json.loads(remote[8]), PINS)
            return 0, json.dumps(guest).encode() + b"\n", b""

        listener = Mock()
        listener.getsockname.return_value = ("127.0.0.1", 47953)
        listener_context = Mock()
        listener_context.__enter__ = Mock(return_value=listener)
        listener_context.__exit__ = Mock(return_value=False)
        current_uid = os.geteuid()
        with tempfile.TemporaryDirectory() as temporary:

            def host_provision(pins, scope, work, _deadline):
                self.assertEqual(pins, PINS)
                self.assertEqual(scope, "host")
                self.assertEqual(work.parent, Path(temporary))
                return PINS["host_packages"]

            handoff = Path(temporary) / "set_output"
            handoff.touch()
            with ExitStack() as stack:
                stack.enter_context(inert_kvm(**(kvm or {})))
                provision = stack.enter_context(
                    patch.object(trial, "packages", side_effect=host_provision)
                )
                launch = stack.enter_context(
                    patch.object(
                        trial,
                        "launch_vm",
                        return_value=Mock(
                            poll=Mock(
                                side_effect=lambda: 17 if vm_exit_after == len(deadlines) else None
                            )
                        ),
                    )
                )
                for context in (
                    patch.object(trial, "Path", side_effect=fake_path),
                    patch.dict(
                        trial.os.environ,
                        {"RUNNER_TEMP": temporary, "GITHUB_OUTPUT": str(handoff)},
                        clear=True,
                    ),
                    patch.object(trial.os, "geteuid", return_value=current_uid),
                    patch.object(trial.os, "uname", return_value=SimpleNamespace(machine="x86_64")),
                    patch.object(trial.os, "sched_getaffinity", return_value={0, 1}),
                    patch.object(
                        trial.shutil,
                        "disk_usage",
                        return_value=SimpleNamespace(free=13 * trial.GIB),
                    ),
                    patch.object(trial, "admitted_host", return_value={}),
                    patch.object(trial, "boot_id", return_value=host_boot),
                    patch.object(trial, "verify_cloud_manifest", return_value="inert/"),
                    patch.object(
                        trial,
                        "fetch",
                        side_effect=lambda _url, path, *_args: path.write_bytes(b"test"),
                    ),
                    patch.object(
                        trial.hashlib,
                        "file_digest",
                        return_value=SimpleNamespace(hexdigest=lambda: digest),
                    ),
                    patch.object(trial, "make_seed"),
                    patch.object(trial.socket, "socket", return_value=listener_context),
                    patch.object(trial, "capture", side_effect=run),
                    patch.object(trial, "reap", return_value=True),
                    patch.object(trial, "cancelled", None),
                    patch.object(trial, "command_cleanup_failed", False),
                    patch.object(trial.time, "monotonic", side_effect=lambda: now[0]),
                    patch.object(
                        trial.time,
                        "sleep",
                        side_effect=lambda delay: now.__setitem__(0, now[0] + delay),
                    ),
                ):
                    stack.enter_context(context)
                if publish_failure == "link":
                    stack.enter_context(patch.object(trial.os, "link", side_effect=OSError))
                if publish_failure == "handoff":
                    write = os.write

                    def short_write(fd, data):
                        if data.startswith(b"receipt_path<<"):
                            return write(fd, data[:-1])
                        return write(fd, data)

                    stack.enter_context(patch.object(trial.os, "write", side_effect=short_write))
                summary = stack.enter_context(redirect_stdout(io.StringIO()))
                code = trial.host_trial()
                if kvm:
                    provision.assert_not_called()
                    launch.assert_not_called()
                else:
                    provision.assert_called_once()
            if publish_failure:
                evidence = handoff.read_bytes()
                self.assertIsNone(runner_receipt_value(evidence))
                if publish_failure == "link":
                    self.assertEqual(evidence, b"")
                    self.assertEqual(list(Path(temporary).rglob(trial.RESULT)), [])
                else:
                    self.assertTrue(evidence.endswith(b"\nDOCKERLENS_RECEIP"))
                    self.assertEqual(len(list(Path(temporary).rglob(trial.RESULT))), 1)
                self.assertEqual(list(Path(temporary).rglob("*.partial")), [])
                return code, summary.getvalue(), deadlines
            path = (
                receipt_path(handoff) if handoff.stat().st_size else Path(temporary) / trial.RESULT
            )
            return code, json.loads(path.read_text()), deadlines

    def test_host_publishes_closed_kvm_refusal_before_provisioning(self):
        for options, operation, detail, reason, dev_close, group_status in (
            (
                {"failures": {"open": errno.EACCES}},
                "open",
                "denied",
                "unavailable",
                "not_opened",
                "group_rw_not_held",
            ),
            (
                {"failures": {"open": errno.EPERM, "device_metadata": errno.ENOENT}},
                "open",
                "denied",
                "unavailable",
                "not_opened",
                "unobserved",
            ),
            (
                {"failures": {"open": errno.ENOENT}},
                "open",
                "absent",
                "unavailable",
                "not_opened",
                None,
            ),
            ({"device": (1, 3)}, "device_identity", "mismatch", "refused", "closed", None),
            (
                {"failures": {"api_version": errno.ENOTTY}},
                "api_version",
                "unsupported",
                "unavailable",
                "closed",
                None,
            ),
            (
                {"failures": {"create_vm": errno.ENODEV, "device_close": errno.EIO}},
                "create_vm",
                "absent",
                "unavailable",
                "other",
                None,
            ),
        ):
            with self.subTest(options=options):
                code, report, observed = self.host((), kvm=options)
                self.assertEqual(
                    (code, report["stage"], report["reason"], report["cleanup"]),
                    (1, "kvm", reason, "not_started"),
                )
                self.assertEqual(observed, [])
                self.assertNotIn("kvm_api", report["host"])
                self.assertNotIn("host_packages", report)
                self.assertEqual(
                    report["host"]["kvm_probe"],
                    {
                        "operation": operation,
                        "detail": detail,
                        "vm_close": "not_opened",
                        "device_close": dev_close,
                    }
                    | ({"group_observation": group_status} if group_status else {}),
                )
                for private in (
                    "private diagnostic",
                    "/private/sentinel",
                    "/dev/kvm",
                    "40821",
                    "40822",
                    "55103",
                    "55104",
                ):
                    self.assertNotIn(private, json.dumps(report))

    def test_host_continues_after_a_successful_kvm_probe(self):
        code, report, observed = self.host(("ready",))
        self.assertEqual((code, report["stage"], observed), (0, "complete", [7]))
        self.assertEqual(report["host"]["kvm_api"], 12)
        self.assertEqual(
            report["host"]["kvm_probe"],
            {
                "operation": "complete",
                "detail": "ok",
                "vm_close": "closed",
                "device_close": "closed",
            },
        )

    def test_host_retries_transient_timeouts_within_the_absolute_boot_budget(self):
        for probes, cloud_failure, expected, deadlines in (
            (("timeout", "ready"), None, (0, "complete", "ok"), [7, 15]),
            (("exit", "ready"), None, (0, "complete", "ok"), [7, 8]),
            (("timeout", "ready"), 37, (37, "boot", "command_failed"), [7, 15]),
            (("timeout", "timeout", "ready"), None, (0, "complete", "ok"), [7, 15, 23]),
            (("timeout",) * 13, None, (124, "boot", "timeout"), [*range(7, 100, 8), 100]),
            (("absolute",), None, (124, "boot", "timeout"), [7]),
            (("late_ready",), None, (124, "boot", "timeout"), [7]),
            (("cancelled",), None, (143, "boot", "cancelled"), [7]),
            (("turn_cancelled",), None, (143, "boot", "cancelled"), [7]),
            (("lost_cleanup",), None, (124, "boot", "timeout"), [7]),
            (("failure",), None, (1, "boot", "output_limit"), [7]),
        ):
            with self.subTest(probes=probes, cloud_failure=cloud_failure):
                code, report, observed = self.host(probes, cloud_failure=cloud_failure)
                self.assertEqual((code, report["stage"], report["reason"]), expected)
                self.assertEqual(report["cleanup"], "verified")
                self.assertEqual(
                    report.get("command_cleanup"),
                    "unverified" if probes == ("lost_cleanup",) else None,
                )
                self.assertEqual(observed, deadlines)

    def test_host_stops_retrying_when_qemu_exits(self):
        code, report, deadlines = self.host(("timeout",), vm_exit_after=1)
        self.assertEqual(
            (code, report["stage"], report["reason"], report["cleanup"]),
            (17, "boot", "command_failed", "verified"),
        )
        self.assertEqual(deadlines, [7])

    def test_host_publication_failure_preserves_prior_command_failure(self):
        for fault in ("link", "handoff"):
            for cloud_failure, expected, reason in ((None, 1, "io"), (37, 37, "command_failed")):
                with self.subTest(fault=fault, cloud_failure=cloud_failure):
                    code, summary, _ = self.host(
                        ("ready",), cloud_failure=cloud_failure, publish_failure=fault
                    )
                    self.assertEqual(code, expected)
                    self.assertIn(f"exit={expected} reason={reason} cleanup=verified", summary)

    def test_every_proper_prefix_of_emitted_handoff_is_unselectable(self):
        writes = []
        write = os.write

        def record(fd, data):
            if data.startswith(b"receipt_path<<"):
                writes.append(data)
            return write(fd, data)

        for work_error in (None, 37):
            with self.subTest(work_error=work_error):
                writes.clear()
                with patch.object(trial.os, "write", side_effect=record):
                    code, report, _ = self.host(("ready",), cloud_failure=work_error)
                self.assertEqual(
                    (code, report["exit"], report["cleanup"]),
                    (work_error or 0, work_error or 0, "verified"),
                )
                self.assertEqual(len(writes), 1)
                data = writes[0]
                selected = runner_receipt_value(data)
                self.assertIsNotNone(selected)
                self.assertEqual(Path(os.fsdecode(selected)).name, trial.RESULT)
                # The runner recognizes the full closing delimiter with or
                # without a final newline. The producer ends exactly at EOF.
                self.assertEqual(runner_receipt_value(data + b"\n"), selected)
                for size in range(len(data)):
                    self.assertIsNone(runner_receipt_value(data[:size]), size)


if __name__ == "__main__":
    unittest.main()
