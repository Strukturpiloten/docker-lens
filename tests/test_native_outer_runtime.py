"""Synthetic backend controls, never Docker/Podman/native qualification."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts/native-outer-runtime.sh"
SPEC = importlib.util.spec_from_file_location("native_outer_observation", ROOT / "scripts/native-outer-observation.py")
assert SPEC and SPEC.loader
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)
PRESENCE_SPEC = importlib.util.spec_from_file_location("outer_presence_test", ROOT / "scripts/native-presence.py")
assert PRESENCE_SPEC and PRESENCE_SPEC.loader
PRESENCE = importlib.util.module_from_spec(PRESENCE_SPEC)
PRESENCE_SPEC.loader.exec_module(PRESENCE)
HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
          "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
          "GITHUB_WORKFLOW_REF": "Strukturpiloten/docker-lens/.github/workflows/check.yml@refs/heads/main",
          "ImageOS": "ubuntu24", "ImageVersion": "20261001.1.0"}


def shell(body, *, environment=None, args=()):
    environment_base = {key: value for key, value in os.environ.items()
                   if not key.startswith(("DOCKER_", "DOCKERLENS_", "CONTAINER_", "GITHUB_", "RUNNER_", "Image"))
        and key != "PODMAN_CONNECTIONS_CONF"}
    return subprocess.run(["bash", "-c", "set -euo pipefail\nsource " + shlex.quote(str(RUNTIME)) + "\n" + body,
        "mock-runtime", *args], env={**environment_base, **(environment or {})}, text=True,
        capture_output=True, timeout=8, check=False)


class PolicyTests(unittest.TestCase):
    def legacy_selection(self, changes=None):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        function = "select_outer_engine() {" + source.split("select_outer_engine() {", 1)[1].split("\nselect_outer_engine ||", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            git = Path(temporary) / "git"
            git.write_text('#!/bin/sh\ncase " $* " in *" rev-parse "*) printf "%s\\n" "$MOCK_HEAD";; '
                '*" status "*) printf "%s" "$MOCK_DIRTY";; *) exit 99;; esac\n')
            git.chmod(0o700)
            environment = {**HOSTED, "GITHUB_JOB": "native-conformance", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_WORKFLOW_REF": "Strukturpiloten/docker-lens/.github/workflows/native-validation.yml@refs/heads/main",
                "DOCKERLENS_NATIVE_CANDIDATE_SHA": "a" * 40, "MOCK_HEAD": "a" * 40, "MOCK_DIRTY": "",
                "PATH": temporary + ":" + os.environ["PATH"], **(changes or {})}
            return shell('script_dir=' + shlex.quote(str(ROOT / "scripts")) + "\n" + function +
                         '\nselect_outer_engine; printf "%s" "$native_outer_engine"', environment=environment)

    def test_exact_legacy_main_dispatcher_uses_explicit_docker_policy_not_a_probe_fallback(self):
        result = self.legacy_selection()
        self.assertEqual((result.returncode, result.stdout), (0, "docker"))
        self.assertIn("selection=legacy-reviewed-main-dispatcher engine=docker", result.stderr)
        for key in ("GITHUB_JOB", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF"):
            result = self.legacy_selection({key: "near-miss"})
            self.assertEqual((result.returncode, result.stdout), (0, "podman"), key)
            self.assertNotIn("legacy-reviewed-main-dispatcher", result.stderr)
        for key in ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "ImageOS", "ImageVersion"):
            result = self.legacy_selection({key: "near-miss"})
            self.assertEqual(result.returncode, 2, key)
            self.assertNotIn("legacy-reviewed-main-dispatcher", result.stderr)

    def test_legacy_selection_does_not_rescue_explicit_values_or_unbound_candidate(self):
        for explicit in ("", "invalid", "podman", "docker"):
            result = self.legacy_selection({"DOCKERLENS_OUTER_ENGINE": explicit})
            self.assertEqual(result.returncode, 0 if explicit in {"podman", "docker"} else 2)
            self.assertEqual(result.stdout, explicit if explicit in {"podman", "docker"} else "")
            self.assertNotIn("legacy-reviewed-main-dispatcher", result.stderr)
        for change in ({"DOCKERLENS_NATIVE_CANDIDATE_SHA": "b" * 40}, {"DOCKERLENS_NATIVE_CANDIDATE_SHA": ""},
                       {"MOCK_HEAD": "wrong"}, {"MOCK_DIRTY": " M scripts/native-conformance.sh"}):
            result = self.legacy_selection(change)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("legacy-reviewed-main-dispatcher", result.stderr)

    def test_source_has_no_native_or_configuration_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("docker", "podman", "sudo", "curl"):
                tool = directory / name
                tool.write_text('#!/bin/sh\nprintf forbidden >> "$SENTINEL"\nexit 99\n')
                tool.chmod(0o700)
            result = shell("printf sourced", environment={"PATH": str(directory) + ":" + os.environ["PATH"],
                "SENTINEL": str(directory / "called")})
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "sourced", ""))
            self.assertFalse((directory / "called").exists())

    def test_default_is_podman_and_unknown_or_empty_never_falls_back(self):
        result = shell('native_outer_policy; printf "%s" "$native_outer_engine"')
        self.assertEqual((result.returncode, result.stdout), (0, "podman"))
        for engine in ("", "Docker", "auto", "docker-compose", "remote", "podman;echo unsafe"):
            result = shell('native_outer_policy "$1"', args=(engine,))
            self.assertEqual(result.returncode, 2, engine)
            self.assertEqual(result.stdout, "")

    def test_docker_requires_all_explicit_hosted_guard_facts(self):
        self.assertEqual(shell("native_outer_policy docker").returncode, 2)
        self.assertEqual(shell("native_outer_policy docker", environment=HOSTED).returncode, 0)
        for key in HOSTED:
            wrong = {**HOSTED, key: "wrong"}
            self.assertEqual(shell("native_outer_policy docker", environment=wrong).returncode, 2, key)
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION",
                    "CONTAINER_HOST", "CONTAINER_CONNECTION", "PODMAN_CONNECTIONS_CONF"):
            self.assertEqual(shell("native_outer_policy docker", environment={**HOSTED, key: "unexpected"}).returncode, 2, key)

    def test_box_consumer_has_exact_separate_trusted_workflow(self):
        values = {**HOSTED, "GITHUB_REPOSITORY": "Strukturpiloten/boxferry", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_REF": "Strukturpiloten/boxferry/.github/workflows/reviewed-docker-consumer-validation.yml@refs/heads/main"}
        self.assertEqual(shell("native_outer_policy docker", environment=values).returncode, 0)
        self.assertEqual(shell("native_outer_policy docker", environment={**values,
            "GITHUB_WORKFLOW_REF": "Strukturpiloten/boxferry/.github/workflows/check.yml@refs/heads/main"}).returncode, 2)

    def test_selection_binds_private_config_and_fixed_local_endpoint_without_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = shell('native_outer_select docker "$1"; printf "%s\\n" "${native_outer_cmd[@]}"',
                           environment=HOSTED, args=(temporary,))
            self.assertEqual(result.returncode, 0, result.stderr)
            values = result.stdout.splitlines()
            self.assertEqual(values[-5:], ["docker", "--config", temporary + "/docker-client", "--host", "unix:///var/run/docker.sock"])
            self.assertEqual((Path(temporary) / "docker-client").stat().st_mode & 0o777, 0o700)
            self.assertEqual(list((Path(temporary) / "docker-client").iterdir()), [])


class ObservationTests(unittest.TestCase):
    def info(self):
        return {"OSType": "linux", "DockerRootDir": "/var/lib/docker", "SecurityOptions": ["name=seccomp,profile=builtin"],
                "OperatingSystem": "Ubuntu 24.04.3 LTS", "ServerVersion": "29.8.1"}

    def test_info_is_not_itself_rootful_authority_and_rejects_wrong_backends(self):
        self.assertEqual(OBS.docker_info(self.info()), "/var/lib/docker")
        for update in ({"SecurityOptions": ["name=rootless"]}, {"SecurityOptions": ["name=userns"]},
                       {"SecurityOptions": None}, {"OSType": "windows"}, {"OperatingSystem": "Docker Desktop"},
                       {"DockerRootDir": "/"}, {"DockerRootDir": "relative"}, {"DockerRootDir": "/var/../other"},
                       {"ServerVersion": "unversioned"}):
            with self.subTest(update=update), self.assertRaises(OBS.Refused):
                OBS.docker_info(self.info() | update)

    def test_positive_local_peer_requires_root_real_dockerd_executable_and_stable_start(self):
        process_stat = b"123 (dockerd) S " + b"0 " * 18 + b"12345\n"
        unix = (b"Num       RefCount Protocol Flags    Type St Inode Path\n"
                b"0000000000000000: 00000002 00000000 00010000 0001 01 456 /run/docker.sock\n"
                b"0000000000000000: 00000003 00000000 00000000 0001 03 789 /run/docker.sock\n")
        service = "MainPID=123\nActiveState=active\nSubState=running"
        paths = {"/proc/123/stat": process_stat, "/proc/123/comm": b"dockerd\n", "/proc/123/status": b"Uid:\t0\t0\t0\t0\n",
                 "/proc/123/net/unix": unix, "/proc/1/comm": b"systemd\n"}
        socket_info = mock.Mock(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_dev=1, st_ino=2)
        executable = mock.Mock(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_dev=3, st_ino=4)
        root = mock.Mock(st_dev=5, st_ino=6)
        groups = {"uid": "peer-credentials", "proxy": "process-identity", "executable": "process-executable",
                  "socket-symlink": "socket-metadata", "start-changed": "process-stability", "service": "peer-credentials",
                  "service-inactive": "service-state", "root": "process-root", "listener": "listener-owner",
                  "alias": "socket-aliases", "process-uid": "process-uid", "systemd": "systemd-peer",
                  "listener-table": "socket-listener", "connect-io": "peer-connect", "process-io": "process-identity"}
        for fault in (None, "inherited", *groups):
            peer = mock.MagicMock()
            peer.__enter__.return_value = peer
            peer.getsockopt.return_value = struct.pack("3i", 1 if fault in {"inherited", "systemd"} else 123, 1000 if fault == "uid" else 0, 0)
            if fault == "connect-io":
                peer.connect.side_effect = PermissionError("protected-canary /private/socket 987654")
            observed = dict(paths)
            if fault == "proxy":
                observed["/proc/123/comm"] = b"podman\n"
            if fault == "process-uid":
                observed["/proc/123/status"] = b"Uid:\t1000\t1000\t1000\t1000\n"
            if fault == "systemd":
                observed["/proc/1/comm"] = b"not-systemd\n"
            if fault == "listener-table":
                observed["/proc/123/net/unix"] = unix.replace(b"00010000", b"00000000")
            count = 0
            def read(path):
                nonlocal count
                if str(path) == "/proc/123/stat":
                    if fault == "process-io":
                        raise PermissionError("protected-canary /private/process 987654")
                    count += 1
                    if fault == "start-changed" and count == 2:
                        return process_stat.replace(b"12345", b"12346")
                return observed[str(path)]
            def link(path):
                if str(path) == "/proc/1/exe":
                    return "/usr/lib/systemd/systemd"
                if str(path) == "/proc/123/fd/3":
                    return "socket:[789]" if fault == "listener" else "socket:[456]"
                return "/usr/bin/podman" if fault == "executable" else "/usr/bin/dockerd"
            def metadata(path):
                if str(path).endswith("/exe"):
                    return executable
                if str(path).endswith("docker.sock"):
                    return mock.Mock(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=9) if fault == "alias" else socket_info
                if str(path) == "/proc/123/root" and fault == "root":
                    return mock.Mock(st_dev=99, st_ino=99)
                return root
            with mock.patch.object(OBS.socket, "socket", return_value=peer), \
                 mock.patch.object(OBS.os, "lstat", return_value=mock.Mock(st_mode=stat.S_IFLNK) if fault == "socket-symlink" else socket_info), \
                 mock.patch.object(OBS.os, "readlink", side_effect=link), \
                 mock.patch.object(OBS.os, "listdir", return_value=["3"]), \
                 mock.patch.object(OBS.os, "stat", side_effect=metadata), \
                 mock.patch.object(OBS.Path, "read_bytes", read):
                if fault not in {None, "inherited"}:
                    actual_service = service.replace("123", "124") if fault == "service" else service
                    if fault == "service-inactive":
                        actual_service = actual_service.replace("ActiveState=active", "ActiveState=inactive")
                    with self.subTest(fault=fault), self.assertRaises(OBS.Refused) as failure:
                        OBS.docker_peer("/var/run/docker.sock", actual_service)
                    self.assertEqual(failure.exception.group, groups[fault])
                    self.assertEqual(failure.exception.category, "io" if fault.endswith("-io") else "refused")
                    self.assertEqual(str(failure.exception), "outer runtime observation unavailable")
                else:
                    record = OBS.docker_peer("/var/run/docker.sock", service)
                    self.assertEqual((record["daemon_pid"], record["daemon_starttime"], record["uid"]), (123, 12345, 0))
                    self.assertEqual(record["executable"], "/usr/bin/dockerd")
        with self.assertRaises(OBS.Refused):
            OBS.docker_peer("tcp://localhost:2375", service)

    def test_service_and_listener_observations_refuse_inactive_duplicate_or_ambiguous_identity(self):
        for raw in ("MainPID=0\nActiveState=active\nSubState=running", "MainPID=123\nActiveState=inactive\nSubState=dead",
                    "MainPID=123\nMainPID=124\nActiveState=active\nSubState=running", "MainPID=123"):
            with self.subTest(raw=raw), self.assertRaises(OBS.Refused):
                OBS.service_pid(raw)
        header = b"Num RefCount Protocol Flags Type St Inode Path\n"
        row = b"0000000000000000: 00000002 00000000 00010000 0001 01 456 /run/docker.sock\n"
        self.assertEqual(OBS.listener_inode(header + row), "456")
        self.assertEqual(OBS.listener_inode(header + row.replace(b"/run/", b"/var/run/")), "456")
        for raw in (header, header + row + row, header + row.replace(b"00010000", b"00000000"), header + row.replace(b"/run/", b"/other/")):
            with self.subTest(raw=raw), self.assertRaises(OBS.Refused):
                OBS.listener_inode(raw)

    def test_listener_selection_allows_only_well_formed_distinct_connected_streams(self):
        header = b"Num RefCount Protocol Flags Type St Inode Path\n"
        listener = b"0000000000000000: 00000002 00000000 00010000 0001 01 456 /run/docker.sock\n"
        connected = b"0000000000000000: 00000003 00000000 00000000 0001 03 789 /run/docker.sock\n"
        alias = connected.replace(b"789", b"790").replace(b"/run/", b"/var/run/")
        for rows in (listener + connected, connected + listener, connected + alias + listener,
                     listener.replace(b"/run/", b"/var/run/") + connected,
                     listener.replace(b"0000000000000000:", b"00000000:") + connected,
                     b"unrelated malformed inventory /other.sock\n" + listener + connected):
            with self.subTest(rows=rows):
                self.assertEqual(OBS.listener_inode(header + rows), "456")
        invalid = {
            "connected-only": connected + alias,
            "multiple-listeners": listener + listener.replace(b"456", b"457"),
            "aliased-listener": listener + listener.replace(b"456", b"457").replace(b"/run/", b"/var/run/"),
            "duplicate-connected": listener + connected + connected,
            "duplicate-aliased-connected": listener + connected + connected.replace(b"/run/", b"/var/run/"),
            "listener-inode-connected": listener + connected.replace(b"789", b"456"),
            "short-row": listener + b"00000000: /run/docker.sock\n",
            "extra-field": listener + connected.rstrip() + b" extra\n",
        }
        fields = connected.split()
        for index, values in {
            0: (b"000:", b"0000000g:", b"00000000000000000:", b"00000000"),
            1: (b"0", b"0000000g", b"000000000"),
            2: (b"00000001",),
            3: (b"00010000", b"00000001"),
            4: (b"0002",),
            5: (b"01", b"02", b"04"),
            6: (b"0", b"-1", b"abc", b"1" * 21),
        }.items():
            for value in values:
                changed = fields.copy()
                changed[index] = value
                invalid[f"connected-field-{index}-{value!r}"] = listener + b" ".join(changed) + b"\n"
        for index, value in ((2, b"00000001"), (4, b"0002"), (5, b"03")):
            changed = listener.split()
            changed[index] = value
            invalid[f"listener-field-{index}"] = b" ".join(changed) + b"\n"
        for case, rows in invalid.items():
            with self.subTest(case=case), self.assertRaises(OBS.Refused):
                OBS.listener_inode(header + rows)

    @unittest.skipUnless(sys.platform == "linux", "Linux procfs socket observation")
    def test_owned_unix_listener_and_accepted_stream_share_path_but_not_authority(self):
        # A short private path avoids AF_UNIX's pathname limit even under a long gate TMPDIR.
        with tempfile.TemporaryDirectory(prefix="dl-unix-", dir="/tmp") as temporary, \
             socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, \
             socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            path = str(Path(temporary) / "owned.sock")
            listener.settimeout(1)
            client.settimeout(1)
            listener.bind(path)
            listener.listen(1)
            client.connect(path)
            accepted, _ = listener.accept()
            with accepted:
                accepted.settimeout(1)
                rows = []
                # Never retain or print unrelated inventory; bound both rows and line length.
                with Path("/proc/self/net/unix").open("rb") as table:
                    header = table.readline(4097)
                    self.assertLessEqual(len(header), 4096)
                    for _ in range(4096):
                        raw = table.readline(4097)
                        if not raw:
                            break
                        self.assertLessEqual(len(raw), 4096)
                        fields = raw.split()
                        if len(fields) == 8 and fields[7] == os.fsencode(path):
                            rows.append(fields)
                    else:
                        self.fail("bounded synthetic socket inventory exceeded")
                self.assertEqual(len(rows), 2)
                self.assertEqual({tuple(fields[2:6]) for fields in rows}, {
                    (b"00000000", b"00010000", b"0001", b"01"),
                    (b"00000000", b"00000000", b"0001", b"03"),
                })
                canonical = header + b"".join(b" ".join(fields[:7] + [b"/run/docker.sock"]) + b"\n" for fields in rows)
                selected = OBS.listener_inode(canonical)
                listener_link = os.readlink(f"/proc/self/fd/{listener.fileno()}")
                accepted_link = os.readlink(f"/proc/self/fd/{accepted.fileno()}")
                self.assertTrue(listener_link == f"socket:[{selected}]")
                self.assertTrue(accepted_link != listener_link)
                connected_only = header + b"".join(b" ".join(fields[:7] + [b"/run/docker.sock"]) + b"\n"
                    for fields in rows if fields[3] == b"00000000")
                with self.assertRaises(OBS.Refused):
                    OBS.listener_inode(connected_only)

    def test_identity_normalization_requires_exact_id_name_owner_and_handles_docker_slash(self):
        value = {"Id": "a" * 64, "Name": "/owned", "Config": {"Labels": {"io.dockerlens.native-run": "run"}}}
        self.assertEqual(OBS.binding(value, "container", "a" * 64, "owned", "io.dockerlens.native-run", "run"),
                         "a" * 64 + "|owned|run")
        for change in ({"Id": "b" * 64}, {"Name": "/foreign"}, {"Config": {"Labels": {"io.dockerlens.native-run": "foreign"}}}):
            with self.subTest(change=change), self.assertRaises(OBS.Refused):
                OBS.binding(value | change, "container", "a" * 64, "owned", "io.dockerlens.native-run", "run")

    def test_backend_normalization_preserves_mount_state_and_lowercase_network_identity(self):
        network = {"id": "a" * 64, "name": "owned", "labels": {"io.dockerlens.native-run": "run"},
                   "internal": False, "subnets": [{"subnet": "192.0.2.0/24"}]}
        actual = OBS.observe(network, "network", "podman")
        self.assertEqual(actual["Id"], network["id"])
        self.assertEqual(actual["Name"], network["name"])
        self.assertEqual(actual["subnets"], network["subnets"])
        value = {"Id": "a" * 64, "Name": "/owned", "Mounts": [{"Type": "bind"}],
                 "State": {"Running": True}, "HostConfig": {"Privileged": True}}
        self.assertEqual(OBS.observe(value, "container", "docker"), value)
        with self.assertRaises(OBS.Refused):
            OBS.observe(network | {"Id": "b" * 64}, "network", "podman")

    def test_declared_image_volume_and_user_are_closed_before_docker_create(self):
        destination = "/home/docker/.local/share/docker"
        self.assertEqual(OBS.image_config({"Volumes": {destination: {}}, "User": "docker"}, "rootless"), destination)
        for value in ({"Volumes": {destination: {}, "/anonymous": {}}, "User": "docker"},
                      {"Volumes": {}, "User": "docker"}, {"Volumes": {destination: {}}, "User": "root"}):
            with self.subTest(value=value), self.assertRaises(OBS.Refused):
                OBS.image_config(value, "rootless")

    def test_mount_readback_refuses_anonymous_extra_host_socket_wrong_name_or_readonly(self):
        data_path = "/var/lib/docker/volumes/owned-data/_data"
        mounts = [{"Type": "volume", "Name": "owned-data", "Destination": "/var/lib/docker", "RW": True,
                   "Driver": "local", "Source": data_path},
                  {"Type": "bind", "Source": "/tmp/owned/socket", "Destination": "/dockerlens-native", "RW": True}]
        OBS.mounts({"Mounts": mounts}, "owned-data", "/var/lib/docker", "/tmp/owned/socket", "/dockerlens-native", data_path)
        for mutate in (lambda value: value.append({"Type": "volume", "Name": "anonymous", "Destination": "/other"}),
                       lambda value: value[0].update(Name="other"), lambda value: value[0].update(RW=False),
                       lambda value: value[0].update(Source="/foreign"), lambda value: value[0].update(Driver="other"),
                       lambda value: value[1].update(Source="/var/run/docker.sock")):
            values = copy.deepcopy(mounts)
            mutate(values)
            with self.assertRaises(OBS.Refused):
                OBS.mounts({"Mounts": values}, "owned-data", "/var/lib/docker", "/tmp/owned/socket", "/dockerlens-native", data_path)

    def test_data_preparation_is_empty_exact_path_only_nonrecursive_and_rechecked(self):
        before = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0, st_dev=1, st_ino=2)
        after = mock.Mock(st_uid=1000, st_gid=1000, st_dev=1, st_ino=2)
        with mock.patch.object(OBS.os, "geteuid", return_value=0), mock.patch.object(OBS.os, "open", return_value=7), \
             mock.patch.object(OBS.os, "fstat", side_effect=[before, after]), mock.patch.object(OBS.os, "listdir", return_value=[]), \
             mock.patch.object(OBS.os, "fchown") as chown, mock.patch.object(OBS.os, "close"):
            OBS.prepare_data("/var/lib/docker/volumes/owned/_data", "/var/lib/docker", "owned", "rootless")
            chown.assert_called_once_with(7, 1000, 1000)
        with self.assertRaises(OBS.Refused):
            OBS.prepare_data("/var/lib/docker", "/var/lib/docker", "owned", "rootless")

    def test_finite_json_refuses_duplicate_nonfinite_and_deep_input(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.5}', b'x' * (OBS.LIMIT + 1),
                    b'{"x":' + b'[' * 25 + b'0' + b']' * 25 + b'}'):
            with self.subTest(raw=raw[:30]), self.assertRaises((OBS.Refused, ValueError)):
                OBS.document(raw)


class LifecycleControls(unittest.TestCase):
    def create(self, engine, lane):
        body = '''native_outer_engine=$1
native_outer_directory=/tmp/owned
native_outer_script_dir=/mock
exec 3>&1
native_outer_command() { printf '%s\\n' "$@" >&3; }
python3() { printf '%064d\\n' 0; }
declare -A held=( [name]=owned [run]=run [owner_key]=io.dockerlens.native-run [network]=owned-net
 [volume]=owned-data [socket_dir]=/tmp/owned/socket [guest_dir]=/dockerlens-native [lane]="$2"
 [image]="example.invalid/engine:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
 [log_path]=/tmp/owned/daemon.log )
native_outer_create_daemon held
'''
        return shell(body, args=(engine, lane))

    def test_both_backends_keep_four_inner_lanes_and_distinct_mount_logger_remove_semantics(self):
        for engine in ("podman", "docker"):
            for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
                result = self.create(engine, lane)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = result.stdout.splitlines()
                self.assertEqual(arguments[:2], ["120", "run"])
                self.assertIn("--privileged", arguments)
                self.assertIn("--memory=4g", arguments)
                self.assertIn("--pids-limit=512", arguments)
                self.assertEqual("--cpus=2" in arguments, engine == "podman")
                self.assertEqual("--cpu-period=100000" in arguments, engine == "docker")
                self.assertEqual("--cpu-quota=200000" in arguments, engine == "docker")
                self.assertEqual("--storage-driver=vfs" in arguments, lane == "debian11-rootless")
                self.assertEqual("--oom-score-adj=0" in arguments, lane == "debian11-rootless")
                self.assertEqual("--image-volume=ignore" in arguments, engine == "podman")
                self.assertIn("--log-driver=k8s-file" if engine == "podman" else "--log-driver=json-file", arguments)
                destination = "/home/docker/.local/share/docker" if lane.endswith("rootless") else "/var/lib/docker"
                mount = "owned-data:" + destination + (":U" if engine == "podman" else "")
                if engine == "podman" and lane == "debian11-rootless":
                    mount += ",suid,dev"
                self.assertIn(mount, arguments)
                self.assertIn("/tmp/owned/socket:/dockerlens-native", arguments)
                self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", arguments)
                if engine == "docker":
                    self.assertFalse(any(value.endswith(":U") or ",suid,dev" in value for value in arguments))

    def test_remove_binds_exact_id_and_owner_then_verifies_both_absences(self):
        for engine in ("podman", "docker"):
            for fault in ("", "owner", "remove", "presence"):
                body = '''native_outer_engine=$1
native_outer_binding() { [[ $2 == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa && $3 == owned && $4 == io.dockerlens.native-run && $5 == run && $FAULT != owner ]]; }
native_outer_command() { [[ $FAULT != remove ]] || return 2; printf '%s\\n' "$@" >> "$CALLS"; }
native_outer_presence() { printf '%s\\n' "$2" >> "$QUERIES"; [[ $FAULT == presence ]] && return 2; return 1; }
native_outer_remove aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa owned io.dockerlens.native-run run /tmp/owned
'''
                with tempfile.TemporaryDirectory() as temporary:
                    calls, queries = Path(temporary) / "calls", Path(temporary) / "queries"
                    result = shell(body, environment={"FAULT": fault, "CALLS": str(calls), "QUERIES": str(queries)}, args=(engine,))
                    self.assertEqual(result.returncode == 0, not fault, result.stderr)
                    if not fault:
                        expected = ["8", "rm", "--force"] + (["--time", "0"] if engine == "podman" else []) + ["a" * 64]
                        self.assertEqual(calls.read_text().splitlines(), expected)
                        self.assertEqual(queries.read_text().splitlines(), ["a" * 64, "owned"])
                    if fault == "owner":
                        self.assertFalse(calls.exists())

    def test_docker_presence_needs_one_exact_success_or_completed_empty_success(self):
        cases = ((0, b"", True, ("absent", 1)), (0, b"present\n", True, ("present", 0)),
                 (0, b"other\n", True, ("absent", 1)), (0, b"other\npresent\nother\n", True, ("present", 0)),
                 (1, b"", True, ("unknown", 2)), (0, b"present\npresent\n", True, ("unknown", 2)),
                 (0, b"private warning", True, ("unknown", 2)), (0, b"", False, ("unknown", 2)))
        for status, output, complete, expected in cases:
            self.assertEqual(PRESENCE.classify(status, output, complete, "exact-list"), expected)

    def test_exact_list_mode_never_treats_stderr_marker_or_warning_as_an_inventory_row(self):
        for stdout, stderr, expected in ((b"other\n", b"", ("absent", 1)),
                (b"present\nother\n", b"", ("present", 0)), (b"", b"other\n", ("unknown", 2)),
                (b"", b"present\n", ("unknown", 2)), (b"other\n", b"private warning", ("unknown", 2))):
            with tempfile.TemporaryDirectory() as temporary:
                code = f"import os; os.write(1, {stdout!r}); os.write(2, {stderr!r})"
                self.assertEqual(PRESENCE.query([sys.executable, "-c", code], Path(temporary), "exact-list"), expected)

    def test_docker_listing_argv_uses_actual_per_kind_fields_not_regex_absence_or_exists(self):
        for kind, identity, field in (("container", "owned", "Names"), ("network", "owned", "Name"),
                                     ("volume", "owned", "Name"), ("network", "a" * 64, "ID")):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                client = directory / "mock-client"
                client.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
                    'open(os.environ["ARGV"],"w").write(json.dumps(sys.argv[1:]))\n'
                    'print("other")\n')
                client.chmod(0o700)
                result = shell('native_outer_engine=docker; native_outer_cmd=("$1"); native_outer_privilege=(); '
                    'native_outer_script_dir="$2"; status=0; native_outer_presence "$3" "$4" "$5" || status=$?; exit "$status"',
                    environment={"ARGV": str(directory / "argv")}, args=(str(client), str(ROOT / "scripts"), kind, identity, temporary))
                self.assertEqual(result.returncode, 1, result.stderr)
                arguments = json.loads((directory / "argv").read_text())
                self.assertEqual(arguments[:2], [kind, "ls"])
                self.assertNotIn("exists", arguments)
                self.assertEqual("--no-trunc" in arguments, kind != "volume")
                self.assertEqual("-a" in arguments, kind == "container")
                expected_filter = "id=" + identity if field == "ID" else "name=" + identity
                self.assertEqual(arguments[arguments.index("--filter") + 1], expected_filter)
                self.assertEqual(arguments[arguments.index("--format") + 1],
                    '{{if eq .' + field + ' "' + identity + '"}}present{{else}}other{{end}}')

    def test_canonical_three_workflow_consumers_select_docker_and_verify_setup_after_admission(self):
        for name in ("check.yml", "native-validation.yml", "release-validation.yml"):
            value = (ROOT / ".github/workflows" / name).read_text()
            self.assertEqual(value.count("DOCKERLENS_OUTER_ENGINE: docker"), 2)
            self.assertEqual(value.count("bash ./scripts/native-outer-setup.sh"), 1)
            self.assertLess(value.index("bash ./scripts/native-outer-setup.sh"), value.index("run: ./scripts/native-conformance.sh"))
        native = (ROOT / "scripts/native-conformance.sh").read_text()
        self.assertIn('source "$script_dir/native-outer-runtime.sh"', native)
        self.assertIn('native_outer_bridge_command 120 create-daemon', native)
        self.assertIn('collector=unavailable', native.split('port_start_failure_diagnostic() {', 1)[1])


if __name__ == "__main__":
    unittest.main()
