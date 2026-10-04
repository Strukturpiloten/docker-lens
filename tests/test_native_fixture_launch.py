"""Offline launcher/context regressions; not native compatibility evidence."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-fixture-launch.py"
spec = importlib.util.spec_from_file_location("fixture_launch", SCRIPT)
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)
RUN = "Abc12345"
NAME = "dl-native-" + RUN
ID = "a" * 64
IMAGE_ID = "b" * 64


def owned(lane="upstream-rootless", **changes):
    values = dict(ident=ID, name=NAME, running="true", owner=RUN, pid="123",
                  started='"2026-10-04T12:00:00.123456789Z"', image=IMAGE_ID)
    values.update(changes)
    return "|".join(values.values()).encode() + b"\n"


def guest(uid="1000", home="/home/docker", pid="42", start="999"):
    return f"{uid}|{home}|{pid}|{start}|5:99|pid:[7]|user:[8]|mnt:[9]\n".encode()


class FixtureLaunchTests(unittest.TestCase):
    def test_existing_closed_lanes_and_literal_launcher(self):
        self.assertEqual(set(fixture.LANES), {"debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"})
        for name in fixture.LANES:
            lane = fixture.lane_contract(name)
            fixture.validate_declaration(name, fixture.image_for(name), "start-dockerd", lane.account,
                                         lane.home, lane.mode, lane.release, lane.data_root, "native-launcher-default")
            self.assertEqual(fixture.launch_plan(name),
                             ("/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock"))
        self.assertEqual(fixture.LANES["debian11-rootless"].account, "dockertest")
        self.assertEqual(fixture.LANES["upstream-rootless"].account, "docker")

    def test_unknown_or_changed_contract_fails_closed(self):
        for name in ("systemd-rootless", "archive", "", "protected-secret"):
            with self.assertRaises(fixture.Failure):
                fixture.lane_contract(name)
        lane = fixture.LANES["upstream-rootless"]
        declaration = ["upstream-rootless", fixture.image_for("upstream-rootless"), "start-dockerd",
                       "docker", "/home/docker", "rootless", lane.release,
                       "/home/docker/.local/share/docker", "native-launcher-default"]
        for index in range(1, len(declaration)):
            changed = declaration.copy()
            changed[index] = "protected-secret"
            with self.subTest(index=index), self.assertRaises(fixture.Failure):
                fixture.validate_declaration(*changed)
        for kind, category in (("systemd", "unimplemented"), ("arbitrary", "contract")):
            with self.assertRaises(fixture.Failure) as caught:
                fixture.launch_plan("upstream-rootless", kind)
            self.assertEqual(caught.exception.category, category)

    def test_declaration_cli_is_private(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--declaration", "protected-secret"], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"DOCKERLENS_NATIVE_FIXTURE: category=contract\n")

    def test_owned_process_identity_mismatches(self):
        for key, value in ( ("ident", "bad"), ("name", "foreign"), ("running", "false"),
                           ("owner", "foreign"), ("pid", "0"), ("started", '"bad"'),
                           ("started", '"2026-99-99T99:99:99Z"'),
                           ("started", '"2026-02-30T00:00:00Z"'),
                           ("image", "foreign")):
            with self.subTest(key=key), self.assertRaises(fixture.Failure):
                fixture.validate_owned(owned(**{key: value}), NAME, RUN, IMAGE_ID)

    def test_acquisition_rechecks_account_process_and_owned_identity(self):
        commands = []
        replies = iter((IMAGE_ID.encode(), owned(), guest(), guest(), owned()))
        def runner(argv, _deadline, _budget, **_kwargs):
            commands.append(argv)
            return next(replies)
        fixture.collect(NAME, RUN, "upstream-rootless", 108, runner=runner, clock=lambda: 100)
        self.assertEqual(commands[0][4:], ["podman", "image", "inspect", "--format", "{{.Id}}", fixture.image_for("upstream-rootless")])
        self.assertEqual(commands[1][4:], ["podman", "inspect", "--format", fixture.INSPECT, NAME])
        self.assertEqual(commands[2][4:14], ["podman", "exec", "--user", "0", ID, "timeout", "-k", "0.2", "3", "sh"])
        self.assertEqual(commands[2][-4:], ["fixture-context", "docker", "/home/docker", "rootless"])
        self.assertEqual(commands[-1][-1], ID)
        for replies in ((owned(), guest(), guest(start="1000")),
                        (owned(), guest(), guest(), owned(pid="124")),
                        (owned(), guest(), guest(), owned(started='"2026-10-04T12:00:00.123456788Z"')),
                        (owned(), guest(uid="0")), (owned(), guest(uid="1001")), (owned(), guest(home="/root"))):
            replies = iter((IMAGE_ID.encode(), *replies))
            with self.assertRaises(fixture.Failure):
                fixture.collect(NAME, RUN, "upstream-rootless", 108,
                                runner=lambda *a, **k: next(replies), clock=lambda: 100)

    def test_cancellation_or_deadline_prevents_next_read(self):
        for cancel, cutoff, category in ((True, 108, "cancelled"), (False, 100, "budget")):
            with self.assertRaises(fixture.Failure) as caught:
                fixture.collect(NAME, RUN, "upstream-rootless", cutoff,
                                runner=lambda *a, **k: self.fail("must not read"),
                                clock=lambda: 100, cancelled=lambda: cancel)
            self.assertEqual(caught.exception.category, category)
        calls = []
        def runner(*args, **kwargs):
            calls.append(1)
            return owned()
        with self.assertRaises(fixture.Failure):
            fixture.collect(NAME, RUN, "upstream-rootless", 108, runner=runner,
                            clock=lambda: 100, cancelled=lambda: bool(calls))
        self.assertEqual(len(calls), 1)

    def test_image_identity_is_pinned_and_normalizes_only_known_prefix(self):
        for raw in (IMAGE_ID.encode(), ("sha256:" + IMAGE_ID).encode()):
            self.assertEqual(fixture.image_identity(raw), IMAGE_ID)
        for raw in (b"", b"protected-secret", b"sha512:" + IMAGE_ID.encode(), b"x" * 64):
            with self.assertRaises(fixture.Failure):
                fixture.image_identity(raw)
        fixture.validate_owned(owned(image="sha256:" + IMAGE_ID), NAME, RUN, IMAGE_ID)
        with self.assertRaises(fixture.Failure):
            fixture.validate_owned(owned(image="c" * 64), NAME, RUN, IMAGE_ID)

    def test_stalled_oversized_or_failed_collection_is_bounded(self):
        for code in ("import time; time.sleep(5)", "print('x'*8193)", "raise SystemExit(1)"):
            begin = time.monotonic()
            with self.assertRaises(fixture.IO.Unavailable):
                fixture.IO.bounded_command([sys.executable, "-c", code], begin + 0.5, capture_limit=8192)
            self.assertLess(time.monotonic() - begin, 1.5)

    def test_lifecycle_requires_stop_readback_and_owned_cleanup(self):
        lifecycle = fixture.Lifecycle(10)
        for phase in ("launched", "context", "ready", "stop_requested", "stopped", "removed"):
            lifecycle.advance(phase, now=1, owned=True, success=True)
        self.assertEqual(lifecycle.state, "removed")
        for phase, kwargs in (("removed", {}), ("launched", {"owned": False}),
                              ("launched", {"success": False}), ("launched", {"cancelled": True}),
                              ("launched", {"now": 10})):
            lifecycle = fixture.Lifecycle(10)
            values = dict(now=1, owned=True, success=True)
            values.update(kwargs)
            with self.assertRaises(fixture.Failure):
                lifecycle.advance(phase, **values)
            with self.assertRaises(fixture.Failure):
                lifecycle.advance("launched", now=1, owned=True, success=True)
        for failure_phase in ("stop_requested", "stopped"):
            lifecycle = fixture.Lifecycle(10)
            for phase in ("launched", "context", "ready", "stop_requested"):
                if phase == failure_phase:
                    break
                lifecycle.advance(phase, now=1, owned=True, success=True)
            with self.assertRaises(fixture.Failure):
                lifecycle.advance(failure_phase, now=1, owned=True, success=False)
            with self.assertRaises(fixture.Failure):
                lifecycle.advance("removed", now=1, owned=True, success=True)

    def test_read_only_guest_probe_against_independent_proc_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            daemon = proc / "42"
            (daemon / "ns").mkdir(parents=True)
            (proc / "1/ns").mkdir(parents=True)
            (daemon / "comm").write_text("dockerd\n")
            (daemon / "stat").write_text("42 (dockerd) " + " ".join(["S"] + ["0"] * 18 + ["999"]) + "\n")
            (daemon / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
            (daemon / "environ").write_bytes(b"HOME=/home/docker\0PATH=/usr/bin\0")
            binary = root / "dockerd"
            binary.touch()
            (daemon / "exe").symlink_to(binary)
            for name in ("pid", "mnt", "user"):
                (daemon / "ns" / name).symlink_to(name + ":[7]")
            (proc / "1/ns/pid").symlink_to("pid:[7]")
            passwd = root / "passwd"
            passwd.write_text("dockertest:x:1000:1000::/home/docker:/bin/sh\n")
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n")
            (bin_dir / "id").chmod(0o755)
            script = fixture.GUEST.replace("/proc/", str(proc) + "/").replace("/etc/passwd", str(passwd))
            def run(account="dockertest", home="/home/docker", mode="rootless"):
                return subprocess.run(["sh", "-c", script, "fixture-context", account, home, mode],
                                      env={**os.environ, "PATH": str(bin_dir) + ":" + os.environ["PATH"]},
                                      capture_output=True, timeout=3)
            self.assertEqual(run().returncode, 0)
            for path, wrong in ((passwd, b"docker:x:1000:1000::/home/docker:/bin/sh\n"),
                                (passwd, b"dockertest:x:1000:1000::/wrong:/bin/sh\n"),
                                (passwd, passwd.read_bytes() * 2),
                                (daemon / "status", b"Uid:\t0\t0\t0\t0\n"),
                                (daemon / "stat", b"42 (dockerd) malformed\n"),
                                (daemon / "environ", b"HOME=/wrong\0"),
                                (daemon / "environ", b"OTHER=prefix\nHOME=/home/docker\0PATH=/usr/bin\0"),
                                (daemon / "environ", b"OTHER=prefix\rHOME=/home/docker\0PATH=/usr/bin\0"),
                                (daemon / "environ", b"HOME=/home/docker"),
                                (daemon / "environ", b"HOME=/home/docker\0HOME=/home/docker\0"),
                                (daemon / "environ", b"x" * 8193)):
                original = path.read_bytes()
                path.write_bytes(wrong)
                with self.subTest(path=path.name, wrong=wrong[:20]):
                    self.assertNotEqual(run().returncode, 0)
                path.write_bytes(original)
            (proc / "1/ns/pid").unlink()
            (proc / "1/ns/pid").symlink_to("pid:[99]")
            self.assertNotEqual(run().returncode, 0)
            (proc / "1/ns/pid").unlink()
            (proc / "1/ns/pid").symlink_to("pid:[7]")
            for tool in ("head", "od", "id"):
                fake = bin_dir / tool
                original = fake.read_bytes() if fake.exists() else None
                if tool == "id":
                    body = "#!/bin/sh\nprintf '1000\\n'\nexit 1\n"
                elif tool == "head":
                    body = "#!/bin/sh\n/usr/bin/head \"$@\"\ncase \"$*\" in */environ) exit 1;; esac\n"
                else:
                    body = "#!/bin/sh\n/usr/bin/od \"$@\"\nexit 1\n"
                fake.write_text(body)
                fake.chmod(0o755)
                with self.subTest(failed_tool=tool):
                    self.assertNotEqual(run().returncode, 0)
                if original is None:
                    fake.unlink()
                else:
                    fake.write_bytes(original)
            other = proc / "43"
            other.mkdir()
            (other / "comm").write_text("dockerd\n")
            self.assertNotEqual(run().returncode, 0)
            (other / "comm").unlink()
            passwd.write_text("root:x:0:0::/root:/bin/sh\n")
            (bin_dir / "id").write_text("#!/bin/sh\nprintf '0\\n'\n")
            (daemon / "status").write_text("Uid:\t0\t0\t0\t0\n")
            (daemon / "environ").write_bytes(b"HOME=/root\0PATH=/usr/bin\0")
            result = run("root", "/root", "rootful")
            self.assertEqual(result.returncode, 0)
            fixture.validate_guest(result.stdout, fixture.LANES["upstream-rootful"])

    def test_runner_keeps_current_launch_constraints_and_busybox_independent(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertIn("start=(/usr/local/bin/start-dockerd --host=unix:///dockerlens-native/docker.sock)", source)
        self.assertIn("--privileged --pids-limit=512 --memory=4g --cpus=2", source)
        self.assertIn('"$image" "${start[@]}"', source)
        self.assertIn('"${inner_docker[@]}" pull "$FIXTURE_IMAGE"', source)
        self.assertNotIn("launch_plan", source)


if __name__ == "__main__":
    unittest.main()
