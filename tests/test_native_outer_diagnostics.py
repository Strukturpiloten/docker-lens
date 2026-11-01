"""Closed preflight failure labels; all process/socket/client observations mocked."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from test_native_outer_runtime import shell

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("outer_diagnostic_observation", ROOT / "scripts/native-outer-observation.py")
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)
CANARY = "protected-canary /private/socket uid=987654 pid=876543 env=secret"


class ObservationDiagnosticsTests(unittest.TestCase):
    def invoke(self, args, raw=b""):
        output, error = io.StringIO(), io.StringIO()
        with mock.patch.object(OBS.sys, "stdin", mock.Mock(buffer=io.BytesIO(raw))), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = OBS.main(args)
        return status, output.getvalue(), error.getvalue()

    def failure(self, actual, mode, group, category="refused"):
        self.assertEqual(actual, (2, "", f"outer runtime observation unavailable: mode={mode} group={group} category={category}\n"))
        self.assertNotIn(CANARY, actual[2])

    def test_peer_io_and_invalid_endpoint_have_fixed_group_and_no_native_metadata(self):
        with mock.patch.object(OBS.os, "lstat", side_effect=PermissionError(CANARY)):
            self.failure(self.invoke(["docker-peer", "/var/run/docker.sock", CANARY]), "peer", "socket-metadata", "io")
        self.failure(self.invoke(["docker-peer", CANARY, CANARY]), "peer", "socket-metadata")
        # Every possible peer label is emitted through the same closed CLI owner.
        for group in OBS.GROUPS:
            for category in ("io", "refused"):
                with self.subTest(group=group, category=category), \
                     mock.patch.object(OBS, "docker_peer", side_effect=OBS.GroupRefused(group, category)):
                    self.failure(self.invoke(["docker-peer", "/var/run/docker.sock", CANARY]), "peer", group, category)
        with self.assertRaises(OBS.Refused):
            OBS.GroupRefused(CANARY, "io")
        with self.assertRaises(OBS.Refused):
            OBS.GroupRefused("socket-metadata", CANARY)

    def test_info_parser_and_real_predicate_groups_remain_distinct_and_private(self):
        info = {"OSType": "linux", "DockerRootDir": "/var/lib/docker", "SecurityOptions": [],
                "OperatingSystem": "Ubuntu", "ServerVersion": "29.8.1"}
        self.failure(self.invoke(["docker-info"], b'{"protected":1,"protected":2}'), "info", "input-json")
        for update, group in (({"OSType": CANARY}, "info-storage"),
                              ({"SecurityOptions": ["name=rootless", CANARY]}, "info-security"),
                              ({"ServerVersion": CANARY}, "info-version")):
            self.failure(self.invoke(["docker-info"], json.dumps(info | update).encode()), "info", group)
        self.assertEqual(self.invoke(["docker-info"], json.dumps(info).encode()), (0, "/var/lib/docker\n", ""))

    def test_receipt_input_versions_destination_and_publication_are_closed_groups(self):
        keys = {"schema_version", "kind", "socket", "socket_device", "socket_inode", "peer_pid", "listener_inode",
                "daemon_pid", "daemon_starttime", "uid", "gid", "executable", "executable_device", "executable_inode"}
        peer = dict.fromkeys(keys, 0)
        peer.update(schema_version=1, kind="local-root-dockerd-observation", socket=CANARY, executable=CANARY)
        raw = json.dumps(peer).encode()
        with tempfile.TemporaryDirectory() as directory:
            args = ["runtime-receipt", str(Path(directory) / "outer-runtime.json"), "29.8.1", "29.8.1", "20261020.1.0", "/var/lib/docker"]
            self.failure(self.invoke(args, b"{}"), "receipt", "receipt-input")
            changed = list(args)
            changed[2] = CANARY
            self.failure(self.invoke(changed, raw), "receipt", "receipt-versions")
            changed = list(args)
            changed[1] = str(Path(directory) / "wrong-file")
            self.failure(self.invoke(changed, raw), "receipt", "receipt-destination")
            with mock.patch.object(OBS.os, "open", side_effect=PermissionError(CANARY)):
                self.failure(self.invoke(args, raw), "receipt", "receipt-publication", "io")
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(self.invoke([CANARY]), (2, "", "outer runtime observation unavailable\n"))
        self.assertEqual(self.invoke([[]]), (2, "", "outer runtime observation unavailable\n"))

    def test_private_client_custody_uses_held_owner_or_root_not_effective_or_ambient_uid(self):
        root = Path("/private/held-run")
        parent = mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=1001)
        for effective in (0, 1001):
            for owner in (0, 1001, 1002):
                client = mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=owner)
                with self.subTest(effective=effective, owner=owner), \
                     mock.patch.object(OBS.Path, "resolve", return_value=root), \
                     mock.patch.object(OBS.Path, "iterdir", return_value=iter(())), \
                     mock.patch.object(OBS.os, "lstat", side_effect=lambda path: client if Path(path).name == "docker-client" else parent), \
                     mock.patch.object(OBS.os, "geteuid", return_value=effective), \
                     mock.patch.dict(OBS.os.environ, {"SUDO_UID": "1002"}):
                    if owner == 1002:
                        with self.assertRaises(OBS.Refused):
                            OBS.client_context(str(root), "docker")
                    else:
                        OBS.client_context(str(root), "docker")


class ShellPreflightDiagnosticsTests(unittest.TestCase):
    BODY = '''native_outer_engine=docker
native_outer_privilege=()
native_outer_directory=/private/held-run
ImageOS=ubuntu24
ImageVersion=20261020.1.0
[[ $MOCK_STAGE != runner-image ]] || ImageVersion=protected-canary
timeout() {
  [[ $1 == --signal=TERM && $2 == --kill-after=2s && $3 == 8s && $4 == systemctl && $5 == show && $6 == docker.service ]] || return 99
  [[ $MOCK_STAGE != service-query ]] || return "$MOCK_STATUS"
  printf 'MainPID=876543\\nActiveState=active\\nSubState=running\\n'
}
native_outer_command() {
  [[ $1 == 8 ]] || return 99
  case $2 in
    info) printf '{"protected":"private-canary"}\\n'; [[ $MOCK_STAGE != info-command ]] || return "$MOCK_STATUS" ;;
    version)
      [[ $MOCK_STAGE != version-query ]] || return "$MOCK_STATUS"
      if [[ $MOCK_STAGE == version-format ]]; then printf 'protected-canary\\n'; else printf '29.8.1|29.8.1\\n'; fi ;;
    *) return 97 ;;
  esac
}
native_outer_helper() {
  case $1 in
    docker-peer) [[ $MOCK_STAGE != peer-observation ]] || return "$MOCK_STATUS"; printf '{"protected":"private-canary"}\\n' ;;
    docker-info)
      while IFS= read -r ignored; do :; done
      [[ $MOCK_STAGE != info-observation ]] || return "$MOCK_STATUS"
      if [[ $MOCK_STAGE == store-path ]]; then printf '/\\n'; else printf '/var/lib/docker\\n'; fi ;;
    runtime-receipt)
      while IFS= read -r ignored; do :; done
      [[ $MOCK_STAGE != receipt-publication ]] || return "$MOCK_STATUS" ;;
    *) return 98 ;;
  esac
}
status=0
native_outer_preflight || status=$?
if (( status == 0 )); then printf '%s\\n' "$native_outer_store_root"; fi
exit "$status"
'''

    def test_each_preflight_owner_classifies_failure_without_changing_failure_status(self):
        for group in ("service-query", "peer-observation", "info-command", "info-observation", "version-query",
                      "version-format", "runner-image", "receipt-publication", "store-path"):
            for status, category in ((2, "refused"), (125, "command"), (124, "timeout"), (137, "killed"), (130, "cancelled"), (143, "cancelled")):
                if group in {"version-format", "runner-image", "store-path"}:
                    category = "refused"
                with self.subTest(group=group, status=status):
                    result = shell(self.BODY, environment={"MOCK_STAGE": group, "MOCK_STATUS": str(status)})
                    self.assertEqual((result.returncode, result.stdout), (2, ""), result.stderr)
                    self.assertIn(f"DOCKERLENS_NATIVE_OUTER_PREFLIGHT: group={group} category={category}\n", result.stderr)
                    self.assertNotIn("canary", result.stderr)
                    self.assertNotIn("/private", result.stderr)
                    self.assertNotIn("876543", result.stderr)
        result = shell(self.BODY, environment={"MOCK_STAGE": "success", "MOCK_STATUS": "0"})
        self.assertEqual((result.returncode, result.stdout), (0, "/var/lib/docker\n"), result.stderr)
        self.assertNotIn("DOCKERLENS_NATIVE_OUTER_PREFLIGHT", result.stderr)

    def test_unrecognized_diagnostic_values_cannot_escape_the_allowlist(self):
        result = shell('native_outer_preflight_failure "$CANARY" "$CANARY"', environment={"CANARY": CANARY})
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, "", "DOCKERLENS_NATIVE_OUTER_PREFLIGHT: group=unclassified category=command\n"))


if __name__ == "__main__":
    unittest.main()
