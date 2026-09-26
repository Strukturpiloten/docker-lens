"""Offline admission contracts for manual privileged native validation."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native-dispatch-admission.py"
spec = importlib.util.spec_from_file_location("native_dispatch_admission", SCRIPT)
assert spec and spec.loader
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def trusted_env() -> dict[str, str]:
    return {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "Strukturpiloten/docker-lens",
        "GITHUB_REPOSITORY_ID": "42",
        "GITHUB_ACTOR": "original-author",
        "GITHUB_TRIGGERING_ACTOR": "rerun-reviewer",
        "PR_NUMBER": "13",
        "EXPECTED_SHA": "a" * 40,
    }


def trusted_pull() -> dict:
    return {
        "number": 13,
        "state": "open",
        "draft": False,
        "head": {"sha": "a" * 40, "repo": {"id": 42, "full_name": "Strukturpiloten/docker-lens"}},
        "base": {"ref": "main", "repo": {"id": 42, "full_name": "Strukturpiloten/docker-lens"}},
    }


class NativeDispatchAdmissionTests(unittest.TestCase):
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
                    admission.fetch_json("/safe", "token")

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
