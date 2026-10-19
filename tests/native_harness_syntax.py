"""Independent bounded syntax readers for canonical harness test assertions.

Expected native calls and ownership remain in each test. This module recognizes
the two actual shell invocation forms and the coordinator's fixed producer;
it does not rewrite source into a fictional historical shell implementation.
"""

import ast
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RUNNER = re.compile(r'^"(?:\$\(dirname "\$0"\)|\$script_dir)/run-exact-native-test\.sh" '
                    r'(\w+) (\w+)(?: <&"\$canonical_read" >&"\$canonical_write")?$', re.M)
OWNER = "native_conformance_outer_v1"
EMITTER = "canonical_phase emitter"
PIDS_READER = "canonical_phase reader"

# Cases retained in the old shell campaign, plus their independently exercised
# production owners. The shell double does not claim to validate these APIs.
ROOT_BOUNDARY_COVERAGE = {
    ("run", "run_partial"): (
        "test_native_outer_runtime.FixedRuntimeVocabularyTests.test_malformed_create_never_recovers_an_id_from_a_name",
        "test_native_outer_broker.SeparateBrokerTests.test_unknown_create_wrong_digest_and_failed_cleanup_never_ack_success",
    ),
    ("container_query_error", "container_remains", "container_inspect_partial"): (
        "test_native_outer_runtime_cleanup.FixedRuntimeCleanupTests.test_exact_id_preinspect_query_failure_never_deletes_or_leaks",
        "test_native_outer_runtime_cleanup.FixedRuntimeCleanupTests.test_partial_or_mismatched_exact_id_preinspect_never_authorizes_removal",
        "test_native_outer_runtime_cleanup.FixedRuntimeCleanupTests.test_failed_exact_id_removal_never_attempts_absence_or_closes",
        "test_native_outer_runtime_cleanup.FixedRuntimeCleanupTests.test_present_or_unknown_id_and_name_readbacks_never_close",
        "test_native_outer_runtime_cleanup.FixedRuntimeCleanupTests.test_only_empty_exact_id_and_name_absence_closes_on_recovery_channel",
        "test_native_outer_runtime_cleanup.FixedRuntimeCleanupTests.test_names_and_drifted_identity_are_never_deletion_authority",
        "test_native_outer_broker.SeparateBrokerTests.test_unknown_create_wrong_digest_and_failed_cleanup_never_ack_success",
        "test_native_outer_broker.SeparateBrokerTests.test_eof_after_start_retains_exact_id_cleanup",
    ),
    ("log_registration_id", "log_registration_digest", "log_registration_missing_digest", "log_registration_path"): (
        "test_native_outer_runtime.RuntimeNormalizationTests.test_identity_and_restart_drift_refuse",
        "test_native_outer_runtime.RuntimeNormalizationTests.test_index_and_selected_native_digest_are_not_blind_aliases",
        "test_native_outer_lifecycle.SplitCustodyTests.test_caller_log_replacement_cannot_be_hidden_by_root_custody",
    ),
    ("unexpected_mount", "legacy_podman_json"): (
        "test_native_outer_runtime.FixedRuntimeVocabularyTests.test_create_uses_fixed_recipe_and_two_original_mounts",
        "test_native_outer_lifecycle.OuterLifecycleTests.test_oci_exact_independent_launch_hooks_annotations_unified_namespaces_and_limits",
        "test_native_outer_canonical.CanonicalTests.test_setup_claims_root_roles_before_spawn_and_validates_original_oci_before_start",
    ),
}


@dataclass(frozen=True)
class Invocation:
    target: str
    test: str
    start: int
    command: str


def invocations(source):
    parsed = [Invocation(*match.groups(), match.start(), match.group()) for match in RUNNER.finditer(source)]
    candidates = re.findall(r'^"[^\n]*run-exact-native-test\.sh"[^\n]*$', source, re.M)
    if len(parsed) != len(candidates):
        raise AssertionError("unrecognized native runner syntax")
    return parsed


def native_calls(source):
    return [(item.target, item.test) for item in invocations(source)]


def logical_owner_scopes(source, coordinator_source=None):
    """Read five isolated shell owners and the private coordinator producer."""
    opening = '(\n  export NATIVE_LIFECYCLE_CLEANUP_OWNER=' + OWNER + '\n'
    pattern = re.compile(re.escape(opening) + r'(.*?)\n\)', re.S)
    scopes = [(match.start(), native_calls(match.group(1))) for match in pattern.finditer(source)]
    if len(scopes) != source.count("export NATIVE_LIFECYCLE_CLEANUP_OWNER="):
        raise AssertionError("cleanup owner escaped an isolated shell scope")
    coordinator_source = ((ROOT / "scripts/native_outer_canonical.py").read_text()
                          if coordinator_source is None else coordinator_source)
    tree = ast.parse(coordinator_source)
    constants = {node.targets[0].id: node.value.value for node in tree.body
                 if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                 and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}
    producer = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "producer")
    owners = [(node, index) for node in ast.walk(producer) if isinstance(node, ast.Dict)
              for index, key in enumerate(node.keys) if isinstance(key, ast.Constant) and key.value == "NATIVE_LIFECYCLE_CLEANUP_OWNER"]
    if len(owners) != 1 or not isinstance(owners[0][0].values[owners[0][1]], ast.Constant) or owners[0][0].values[owners[0][1]].value != OWNER:
        raise AssertionError("coordinator producer lacks its fixed private cleanup owner")
    if sum(isinstance(key, ast.Constant) and key.value == "NATIVE_LIFECYCLE_CLEANUP_OWNER"
           for node in ast.walk(tree) if isinstance(node, ast.Dict) for key in node.keys) != 1:
        raise AssertionError("coordinator cleanup owner escaped its producer")
    child_calls = [node for node in ast.walk(producer) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "run_private_role"]
    if len(child_calls) != 1 or not isinstance(child_calls[0].args[0], ast.Tuple):
        raise AssertionError("producer must dispatch exactly one fixed private child")
    command = child_calls[0].args[0].elts
    if len(command) != 4 or not all(isinstance(node, ast.Name) and node.id in constants for node in command[2:]):
        raise AssertionError("producer target must use fixed candidate-owned literals")
    pair = tuple(constants[node.id] for node in command[2:])
    positions = [item.start for item in invocations(source) if (item.target, item.test) == pair]
    if len(positions) != 1:
        raise AssertionError("coordinator producer must have exactly one shell invocation")
    scopes.append((positions[0], [pair]))
    return [calls for _position, calls in sorted(scopes)]


def emitter_cli(result):
    positions = [index for index, value in enumerate(result.args) if Path(str(value)).name == "native-evidence.py"]
    if len(positions) != 1:
        raise AssertionError("expected one actual emitter script in child argv")
    arguments = list(result.args[positions[0] + 1:])
    if len(arguments) != 19:
        raise AssertionError("emitter ABI changed")
    return arguments


def run_emitter(result, extra_environment=None):
    """Repeat an actual emitter child with independent anonymous stdin input."""
    import os
    import test_native_evidence as fixture
    arguments = emitter_cli(result)
    command = ["python3", str(fixture.SCRIPT), *arguments]
    lane = arguments[13]
    return fixture.run_with_context(command, capture_output=True, text=True, check=False, timeout=5,
                                    env={**os.environ, "NATIVE_FIXTURE_IMAGE": fixture.HEALTH_FIXTURE_IMAGE,
                                         "NATIVE_OUTER_CONTAINER_ID": "f" * 64,
                                         "NATIVE_BIND_RELABEL_DAEMON_UID": "1000" if lane.endswith("-rootless") else "0",
                                         **(extra_environment or {})})


def rerun_emitter(test, result, destination):
    """Negative proof controls must reach their predicates with valid stdin."""
    output = run_emitter(result)
    test.assertNotEqual(output.returncode, 0)
    test.assertFalse(destination.exists())
    test.assertEqual(output.stderr.strip(), "native evidence rejected")
    return output


def assert_positive_emitter_rerun(test, result, destination):
    """Prove the same independent stdin transport reaches unchanged publication.

    Mutation campaigns must establish this before expecting proof refusal; an
    import/transport failure is not evidence that a proof predicate ran.
    """
    original = destination.read_bytes()
    destination.unlink()
    output = run_emitter(result)
    test.assertEqual(output.returncode, 0, output.stderr)
    test.assertEqual((output.stdout, output.stderr), ("", ""))
    test.assertEqual(destination.read_bytes(), original)


@contextmanager
def authored_emitter_authority(arguments):
    """Same authored acquisition seam as the real emitter child fixture."""
    import native_outer_coordinator as coordinator
    import test_native_evidence as fixture
    context, account, options, prefix = fixture.emitter_context(arguments[11], arguments[13], arguments[14], arguments[17])
    original = coordinator.derive_consumer_authority
    def derive(value, expected, budget=None):
        return original(value, expected, account_loader=lambda *_args: account,
                        socket_options=lambda _path: options, log_reader=lambda _i, _l, observed: observed == prefix)
    with patch.object(coordinator, "derive_consumer_authority", side_effect=derive):
        yield context


def fake_teardown_boundary():
    """Shell-fault double only; the actual root broker is tested separately."""
    return '''
canonical_phase() {
  [[ $# == 1 && $1 == teardown ]] || return 97
  cleanup_container "$container" container "$outer_container_id" "$outer_attempted"
}
'''


def shell_tail(source, runner):
    """Model only producer dispatch; keep all actual mandatory proof readers."""
    replacements = invocations(source)
    for item in reversed(replacements):
        call = runner + " " + item.target + " " + item.test
        if '<&"$canonical_read" >&"$canonical_write"' in item.command:
            call = '( export NATIVE_LIFECYCLE_CLEANUP_OWNER=' + OWNER + '; ' + call + ' )'
        source = source[:item.start] + call + source[item.start + len(item.command):]
    adapter = '''
canonical_phase() {
  [[ ${1:-} == reader ]] || return 97
  shift
  python3 "zHELPER" reader "$@"
}
'''.replace("zHELPER", str(Path(__file__).resolve()))
    return adapter + source


def bind_tail_pids_proof(proof, directory, lane, image, candidate):
    import test_native_evidence as fixture
    from test_native_outer_authority import bind_proof_boundary
    context, _account, _options, _prefix = fixture.emitter_context(directory, lane, image, candidate)
    bind_proof_boundary(proof, context["boundary"])


def actual_pids_reader(arguments):
    """Run the actual mandatory reader with independently authored stdin input."""
    import io
    import os
    import sys
    from native_outer_coordinator import serialize_consumer_context
    from native_pids_limit_v2_proof import main
    if len(arguments) != 12:
        raise ValueError("invalid reader ABI")
    # Match the emitter CLI positions expected by the common authority fixture;
    # no proof field supplies the independent source boundary.
    cli = [None] * 19
    cli[11], cli[13], cli[14], cli[17] = arguments[0], arguments[3], arguments[9], arguments[1]
    with authored_emitter_authority(cli) as context, \
         patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(serialize_consumer_context(context)))), \
         patch.dict(os.environ, NATIVE_PIDS_LIMIT_DEADLINE_EPOCH=str(context["pids"]["deadline_epoch"])):
        main(arguments)


def shell_fault_campaign(source):
    """Replace ONLY the top coordinator bootstrap in the old shell campaign.

    This models root's boundary with the campaign's synthetic Podman. Actual
    runtime create/init, original OCI/log custody, protocol/EOF and once-only
    cleanup are checked by ROOT_BOUNDARY_COVERAGE, never by this test double.
    """
    marker = 'script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)\n'
    if source.count(marker) != 1:
        raise AssertionError("canonical bootstrap anchor changed")
    prefix, body = source.split(marker, 1)
    for anchor in ('coproc CANONICAL_RELAY', 'unset DOCKERLENS_CANONICAL_REQUEST_FD DOCKERLENS_CANONICAL_REPLY_FD',
                   'canonical_phase() {'):
        if prefix.count(anchor) != 1:
            raise AssertionError("canonical bootstrap shape changed")
    boundary = '''
fake_bound_outer_id=
canonical_phase() {
  case ${1:-} in
    setup)
      [[ $# == 5 && $2 == "$run_dir" && $3 == "$run_id" && $4 == "$lane" && $5 == "$image" ]] || return 96
      python3 "$script_dir/native-port-start-diagnostic.py" prepare "$run_dir" "$run_id" "$lane" || return
      fake_bound_outer_id=$(timeout --signal=TERM --kill-after=2s 120s "${podman_cmd[@]}" run --pull=never -d --name "$container" \
        --label "io.dockerlens.native-run=$run_id" --log-driver=k8s-file \
        --log-opt "path=$run_dir/diagnostics/daemon.log" --log-opt max-size=1048576 --network "$outer_network" \
        --privileged --pids-limit=512 --memory=4g --cpus=2 "${run_flags[@]}" \
        --volume "$storage_mount" --volume "$socket_dir:/dockerlens-native" "$image" "${start[@]}" 2>/dev/null) || {
          fake_bound_outer_id=; return 1;
        }
      [[ $fake_bound_outer_id =~ ^[0-9a-f]{64}$ ]] ;;
    teardown)
      [[ $# == 1 ]] || return 96
      cleanup_container "$container" container "$fake_bound_outer_id" "$outer_attempted" ;;
    *) return 97 ;;
  esac
}
'''
    return 'set -euo pipefail\nscript_dir=' + shlex.quote(str(ROOT / "scripts")) + '\n' + boundary + body


if __name__ == "__main__":
    import sys
    # Standalone test child: full-gate discovery does not export its sys.path.
    # Resolve only this checkout's production modules, never inherited PYTHONPATH.
    sys.path.insert(0, str(ROOT / "scripts"))
    if sys.argv[1:2] != ["reader"]:
        raise SystemExit("invalid synthetic boundary mode")
    try:
        actual_pids_reader(sys.argv[2:])
    except (OSError, ValueError):
        raise SystemExit("invalid private pids limit proof") from None
