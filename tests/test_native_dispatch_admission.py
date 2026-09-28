"""Offline admission contracts for manual privileged native validation."""

import importlib.util
import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-dispatch-admission.py"
spec = importlib.util.spec_from_file_location("native_dispatch_admission", SCRIPT)
assert spec and spec.loader
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def trusted_env(repository: str = admission.REPOSITORY, repo_id: str = "42") -> dict[str, str]:
    env = {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": repository,
        "GITHUB_REPOSITORY_ID": repo_id,
        "GITHUB_ACTOR": "original-author",
        "GITHUB_TRIGGERING_ACTOR": "rerun-reviewer",
        "PR_NUMBER": "13",
        "EXPECTED_SHA": "a" * 40,
    }
    if repository == admission.BOXFERRY_REPOSITORY:
        env["EXPECTED_REPOSITORY"] = repository
    return env


def trusted_pull(repository: str = admission.REPOSITORY, repo_id: int = 42) -> dict:
    return {
        "number": 13,
        "state": "open",
        "draft": False,
        "head": {"sha": "a" * 40, "repo": {"id": repo_id, "full_name": repository}},
        "base": {"ref": "main", "repo": {"id": repo_id, "full_name": repository}},
    }


class NativeDispatchAdmissionTests(unittest.TestCase):
    def test_http_helper_only_accepts_closed_paths_in_selected_repository(self) -> None:
        for repository in (admission.REPOSITORY, admission.BOXFERRY_REPOSITORY):
            self.assertTrue(admission.allowed_api_path(f"/repos/{repository}/pulls/13", repository))
            self.assertTrue(admission.allowed_api_path(
                f"/repos/{repository}/collaborators/original-author/permission", repository
            ))
            for path in (
                f"/repos/{repository}/pulls/0",
                f"/repos/{repository}/pulls/13/merge",
                f"/repos/{repository}/collaborators/a%2Fb/permission",
                f"/repos/{repository}/issues/13",
                "/repos/someone/fork/pulls/13",
            ):
                self.assertFalse(admission.allowed_api_path(path, repository))
                with self.assertRaisesRegex(admission.AdmissionError, "invalid-api-path"):
                    admission.fetch_json(path, "synthetic-token", repository)

    def test_repository_policy_defaults_to_dockerlens_and_only_two_trusted_consumers(self) -> None:
        self.assertEqual(admission.expected_repository_from_env({}), admission.REPOSITORY)
        for repository in (admission.REPOSITORY, admission.BOXFERRY_REPOSITORY):
            self.assertEqual(
                admission.expected_repository_from_env({"EXPECTED_REPOSITORY": repository}),
                repository,
            )
        for repository in ("", "someone/fork", "Strukturpiloten/Docker-Lens"):
            with self.subTest(repository=repository), self.assertRaisesRegex(
                admission.AdmissionError, "invalid-repository-policy"
            ):
                admission.expected_repository_from_env({"EXPECTED_REPOSITORY": repository})

    def test_boxferry_policy_checks_actual_repository_identity_and_both_actors(self) -> None:
        # Numeric IDs are synthetic fixtures; full names are the participating repositories.
        env = trusted_env(admission.BOXFERRY_REPOSITORY, "84")
        pull = trusted_pull(admission.BOXFERRY_REPOSITORY, 84)
        seen: list[str] = []

        def get(path: str) -> dict:
            seen.append(path)
            if path.endswith("/permission"):
                return {"permission": "maintain" if "rerun-reviewer" in path else "write"}
            return pull

        admission.admit(env, get, admission.BOXFERRY_REPOSITORY)
        self.assertEqual(set(seen), {
            f"/repos/{admission.BOXFERRY_REPOSITORY}/collaborators/original-author/permission",
            f"/repos/{admission.BOXFERRY_REPOSITORY}/collaborators/rerun-reviewer/permission",
            f"/repos/{admission.BOXFERRY_REPOSITORY}/pulls/13",
        })
        self.assertEqual(len(seen), 3)
        for actor in ("original-author", "rerun-reviewer"):
            with self.subTest(actor=actor):
                def deny(path: str) -> dict:
                    if actor in path:
                        return {"permission": "read"}
                    return {"permission": "admin"} if path.endswith("/permission") else pull

                with self.assertRaisesRegex(admission.AdmissionError, "insufficient-actor-permission"):
                    admission.admit(env, deny, admission.BOXFERRY_REPOSITORY)

    def test_policy_event_and_pr_repository_mismatch_fail_without_cross_repo_get(self) -> None:
        for env, policy in (
            (trusted_env(), admission.BOXFERRY_REPOSITORY),
            (trusted_env(admission.BOXFERRY_REPOSITORY, "84"), admission.REPOSITORY),
        ):
            with self.subTest(event=env["GITHUB_REPOSITORY"], policy=policy):
                with self.assertRaisesRegex(admission.AdmissionError, "untrusted-dispatch-ref"):
                    admission.admit(env, lambda _path: self.fail("no GET before event identity"), policy)
        with self.assertRaisesRegex(admission.AdmissionError, "invalid-repository-policy"):
            admission.admit(trusted_env(), lambda _path: self.fail("no arbitrary repo GET"), "someone/fork")

        box_env = trusted_env(admission.BOXFERRY_REPOSITORY, "84")
        for field, changed in (
            ("head.repo.full_name", admission.REPOSITORY),
            ("base.repo.full_name", admission.REPOSITORY),
            ("head.repo.id", 42),
            ("base.repo.id", 42),
            ("head.sha", "b" * 40),
            ("base.ref", "feature"),
            ("state", "closed"),
        ):
            with self.subTest(field=field):
                pull = trusted_pull(admission.BOXFERRY_REPOSITORY, 84)
                target = pull
                path = field.split(".")
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = changed
                def get(request: str) -> dict:
                    return {"permission": "admin"} if request.endswith("/permission") else pull
                with self.assertRaisesRegex(admission.AdmissionError, "pull-head-mismatch"):
                    admission.admit(box_env, get, admission.BOXFERRY_REPOSITORY)

    def test_numeric_api_ids_and_closed_policy_errors_fail_closed(self) -> None:
        env = trusted_env(admission.BOXFERRY_REPOSITORY, "1")
        for field, value in (("head.repo.id", True), ("base.repo.id", "1"),
                             ("number", True), ("head.repo.id", 1.0)):
            with self.subTest(field=field, value=value):
                pull = trusted_pull(admission.BOXFERRY_REPOSITORY, 1)
                if field == "number":
                    env["PR_NUMBER"] = "1"
                else:
                    env["PR_NUMBER"] = "13"
                target = pull
                path = field.split(".")
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                def get(request: str) -> dict:
                    return {"permission": "admin"} if request.endswith("/permission") else pull
                with self.assertRaisesRegex(admission.AdmissionError, "pull-head-mismatch"):
                    admission.admit(env, get, admission.BOXFERRY_REPOSITORY)
        for env_update, args, secret in (
            ({"EXPECTED_REPOSITORY": "private/canary"}, [], "private/canary"),
            ({"EXPECTED_REPOSITORY": ""}, [], None),
            ({}, ["--expected-repository", admission.BOXFERRY_REPOSITORY], admission.BOXFERRY_REPOSITORY),
            ({}, ["--other", "private/canary"], "private/canary"),
        ):
            with self.subTest(env_update=env_update, args=args):
                output = io.StringIO()
                cli_env = trusted_env()
                cli_env.update(env_update)
                cli_env["GITHUB_TOKEN"] = "synthetic-token"
                with patch.dict(os.environ, cli_env, clear=True), patch.object(
                    admission, "fetch_json", side_effect=AssertionError("no GET before policy admission")
                ), redirect_stderr(output):
                    self.assertEqual(admission.main(args), 1)
                self.assertIn("invalid-repository-policy", output.getvalue())
                if secret is not None:
                    self.assertNotIn(secret, output.getvalue())

    def test_boxferry_cli_uses_literal_environment_policy(self) -> None:
        env = trusted_env(admission.BOXFERRY_REPOSITORY, "84")
        env["GITHUB_TOKEN"] = "synthetic-token"
        pull = trusted_pull(admission.BOXFERRY_REPOSITORY, 84)
        paths: list[str] = []
        def get(path: str, _token: str, _repository: str) -> dict:
            paths.append(path)
            return {"permission": "admin"} if path.endswith("/permission") else pull
        output = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(admission, "fetch_json", side_effect=get), \
             redirect_stdout(output):
            self.assertEqual(admission.main([]), 0)
        self.assertEqual(len(paths), 3)
        self.assertTrue(all(path.startswith(f"/repos/{admission.BOXFERRY_REPOSITORY}/") for path in paths))
        self.assertIn("application validation only", output.getvalue())

    def test_default_cli_stays_dockerlens_without_repository_argument(self) -> None:
        env = trusted_env()
        env["GITHUB_TOKEN"] = "synthetic-token"
        paths: list[str] = []
        def get(path: str, _token: str, repository: str) -> dict:
            self.assertEqual(repository, admission.REPOSITORY)
            paths.append(path)
            return {"permission": "admin"} if path.endswith("/permission") else trusted_pull()
        output = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(admission, "fetch_json", side_effect=get), \
             redirect_stdout(output):
            self.assertEqual(admission.main([]), 0)
        self.assertEqual(len(paths), 3)
        self.assertTrue(all(path.startswith(f"/repos/{admission.REPOSITORY}/") for path in paths))
        self.assertIn("native validation only", output.getvalue())

    def test_http_lookup_rejects_errors_and_oversized_responses(self) -> None:
        class Response:
            def __init__(self, status: int, body: bytes) -> None:
                self.status = status
                self.body = body

            def read(self, limit: int) -> bytes:
                return self.body[:limit]

        class Connection:
            def __init__(self, response: Response) -> None:
                self.response = response

            def request(self, *_args: object, **_kwargs: object) -> None:
                pass

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                pass

        for response, reason in (
            (Response(403, b"{}"), "api-unavailable"),
            (Response(200, b"x" * 65_537), "api-response-too-large"),
            (Response(200, b"not-json"), "api-unavailable"),
        ):
            with self.subTest(reason=reason), patch.object(
                admission.http.client, "HTTPSConnection", return_value=Connection(response)
            ):
                with self.assertRaisesRegex(admission.AdmissionError, reason):
                    admission.fetch_json("/repos/Strukturpiloten/docker-lens/pulls/13", "token")

    def test_both_original_and_rerun_actors_need_current_write_roles(self) -> None:
        seen: list[str] = []

        def get(path: str) -> dict:
            seen.append(path)
            if path.endswith("/permission"):
                return {"permission": "maintain" if "rerun-reviewer" in path else "write"}
            return trusted_pull()

        admission.admit(trusted_env(), get)
        self.assertEqual(len(seen), 3)
        self.assertTrue(any(path.endswith("/collaborators/original-author/permission") for path in seen))
        self.assertTrue(any(path.endswith("/collaborators/rerun-reviewer/permission") for path in seen))

        for denied_actor in ("original-author", "rerun-reviewer"):
            with self.subTest(denied_actor=denied_actor):
                def deny(path: str) -> dict:
                    if denied_actor in path:
                        return {"permission": "read"}
                    if path.endswith("/permission"):
                        return {"permission": "admin"}
                    return trusted_pull()

                with self.assertRaisesRegex(admission.AdmissionError, "insufficient-actor-permission"):
                    admission.admit(trusted_env(), deny)

    def test_malformed_permission_roles_are_closed_value_free_denials(self) -> None:
        env = trusted_env()
        env["GITHUB_TOKEN"] = "synthetic-token"
        for malformed_role in (["write", "private-role-value"], {"private-role-value": "write"}):
            with self.subTest(malformed_role=malformed_role):
                paths: list[str] = []

                def get(path: str, _token: str, _repository: str) -> dict:
                    paths.append(path)
                    if path.endswith("/permission"):
                        return {"permission": malformed_role}
                    return trusted_pull()

                stderr = io.StringIO()
                stdout = io.StringIO()
                with patch.dict(os.environ, env, clear=True), patch.object(
                    admission, "fetch_json", side_effect=get
                ), redirect_stderr(stderr), redirect_stdout(stdout):
                    self.assertEqual(admission.main([]), 1)
                self.assertEqual(len(paths), 1)
                self.assertTrue(paths[0].endswith("/permission"))
                self.assertEqual(stderr.getvalue(), "native dispatch denied: insufficient-actor-permission\n")
                self.assertEqual(stdout.getvalue(), "")

    def test_api_error_and_unknown_rerun_actor_fail_closed(self) -> None:
        def unavailable(_path: str) -> dict:
            raise admission.AdmissionError("api-unavailable")

        with self.assertRaisesRegex(admission.AdmissionError, "api-unavailable"):
            admission.admit(trusted_env(), unavailable)
        env = trusted_env()
        env["GITHUB_TRIGGERING_ACTOR"] = ""
        with self.assertRaisesRegex(admission.AdmissionError, "unknown-actor"):
            admission.admit(env, lambda _path: trusted_pull())

    def test_exact_current_same_repository_pr_head_is_required(self) -> None:
        for field, changed in (
            ("head.sha", "b" * 40),
            ("head.repo.id", 99),
            ("head.repo.full_name", "someone/docker-lens"),
            ("base.ref", "other"),
            ("state", "closed"),
        ):
            with self.subTest(field=field):
                pull = trusted_pull()
                target = pull
                path = field.split(".")
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = changed

                def get(path: str) -> dict:
                    return {"permission": "admin"} if path.endswith("/permission") else pull

                with self.assertRaisesRegex(admission.AdmissionError, "pull-head-mismatch"):
                    admission.admit(trusted_env(), get)

    def test_open_draft_pr_is_admitted_at_exact_reviewed_head(self) -> None:
        pull = trusted_pull()
        pull["draft"] = True

        def get(path: str) -> dict:
            return {"permission": "write"} if path.endswith("/permission") else pull

        admission.admit(trusted_env(), get)

    def test_dispatch_and_metadata_are_fail_closed(self) -> None:
        for field, changed, reason in (
            ("GITHUB_EVENT_NAME", "pull_request", "untrusted-dispatch-ref"),
            ("GITHUB_REF", "refs/heads/feature", "untrusted-dispatch-ref"),
            ("GITHUB_REPOSITORY", "someone/docker-lens", "untrusted-dispatch-ref"),
            ("GITHUB_REPOSITORY_ID", "", "invalid-input"),
            ("PR_NUMBER", "13/../../x", "invalid-input"),
            ("EXPECTED_SHA", "short", "invalid-input"),
            ("GITHUB_ACTOR", "", "unknown-actor"),
        ):
            with self.subTest(field=field):
                env = trusted_env()
                env[field] = changed
                with self.assertRaisesRegex(admission.AdmissionError, reason):
                    admission.admit(env, lambda _path: trusted_pull())


if __name__ == "__main__":
    unittest.main()
