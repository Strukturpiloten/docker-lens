"""Private bounded init/rootfs effect controls; never capability admission.

Unregistered preparation for DockerLens #115. Init means only observed PID1
indirection, not zombie reaping or general signal behavior. Missing, failing or
unavailable effects are invalid proof, never evidence of unsupported platforms.
"""

from native_external_network_proof import validate_context
from native_health_metadata_proof import timestamp_ns
from native_network_attachment_proof import canonical, keys, read_private_proof

CONTRACT = "runtime-filesystem-v1"
FILENAME = "runtime-filesystem-v1.json"
SECOND = 1_000_000_000
CASES = (("omitted", None), ("false", False), ("true", True))
FIELDS = ("role", "id", "name", "owner", "image", "image_id", "wire",
          "cli_api", "init_configured", "readonly_configured", "worker_pid",
          "worker_ppid", "worker_state", "pid1_pid", "rootfs_probe_path",
          "probe_path_mount", "write_exit", "write_effect", "readback",
          "started_at", "process_observed_at", "write_observed_at", "running_after_at",
          "running_after", "restart_count", "cleanup")


def fail():
    raise ValueError("invalid private runtime filesystem proof")


def exact(value, expected):
    if type(value) is not type(expected) or value != expected:
        fail()


def validate_runtime_filesystem_proof(proof, expected_context):
    """Check six actual controls against an independently supplied context.

    Return an explicit empty admission result. Even a complete private effect
    proof must be independently reviewed and cannot edit sealed catalogue facts.
    """
    try:
        validate_context(expected_context)
        keys(proof, ("schema_version", "contract", "context", "capability_admission",
                     "catalogue_admission", "init_effect_scope", "borrowed_image", "cases", "cleanup"))
        for key, value in (("schema_version", 1), ("contract", CONTRACT),
                           ("context", expected_context), ("capability_admission", []),
                           ("catalogue_admission", False), ("init_effect_scope", "pid1_indirection_only")):
            exact(proof[key], value)
        validate_context(proof["context"])
        image = proof["borrowed_image"]
        keys(image, ("id", "identity", "removal"))
        if type(image["id"]) is not str or not image["id"].startswith("sha256:") or not canonical(image["id"][7:]):
            fail()
        exact(image["identity"], "unchanged")
        exact(image["removal"], "not_owned")
        cleanup = proof["cleanup"]
        keys(cleanup, ("containers", "rounds", "outstanding", "uncertain"))
        for key, value in (("containers", "absent"), ("rounds", 2), ("outstanding", 0), ("uncertain", False)):
            exact(cleanup[key], value)
        if type(proof["cases"]) is not list or len(proof["cases"]) != 3:
            fail()
        # The outer daemon container and fixtures are the same native kind.
        # Reserve the independently bound outer ID before accepting any fixture.
        seen = {expected_context["outer"]["id"]}
        clocks = []
        for case, (name, authored) in zip(proof["cases"], CASES):
            keys(case, ("case", "authored_init", "authored_readonly", "containers"))
            exact(case["case"], name)
            exact(case["authored_init"], authored)
            exact(case["authored_readonly"], authored)
            if type(case["containers"]) is not list or len(case["containers"]) != 2:
                fail()
            for record, role in zip(case["containers"], ("oracle", "rendered")):
                keys(record, FIELDS)
                if not canonical(record["id"]) or record["id"] in seen:
                    fail()
                seen.add(record["id"])
                for key, value in (("role", role), ("name", f"dl-runtime-{expected_context['run_id']}-{name}-{role}"),
                                   ("owner", expected_context["run_id"]), ("image", expected_context["fixture_image"]),
                                   ("image_id", image["id"]),
                                   ("wire", "independent_cli" if role == "oracle" else "literal_rendered"),
                                   ("cli_api", expected_context["rendering_api"]),
                                   ("readonly_configured", authored is True), ("pid1_pid", 1),
                                   ("rootfs_probe_path", "/dockerlens-rootfs-canary"), ("probe_path_mount", False),
                                   ("running_after", True), ("restart_count", 0), ("cleanup", "absent")):
                    exact(record[key], value)
                # Omitted *bool may serialize absent/null or normalized false.
                if authored is None:
                    if record["init_configured"] is not None and record["init_configured"] is not False:
                        fail()
                else:
                    exact(record["init_configured"], authored)
                pid, ppid = record["worker_pid"], record["worker_ppid"]
                if type(pid) is not int or type(ppid) is not int or not 1 <= pid <= 4194304 or not 0 <= ppid <= 4194304:
                    fail()
                if (authored is True and not (pid > 1 and ppid == 1)) or (authored is not True and (pid != 1 or ppid != 0)):
                    fail()
                if record["worker_state"] not in ("R", "S"):
                    fail()
                code = record["write_exit"]
                if type(code) is not int or not 0 <= code <= 255:
                    fail()
                if authored is True:
                    if code == 0:
                        fail()
                    exact(record["write_effect"], "erofs")
                    exact(record["readback"], "absent")
                else:
                    exact(code, 0)
                    exact(record["write_effect"], "written")
                    exact(record["readback"], "exact_canary")
                times = [timestamp_ns(record[key]) for key in
                         ("started_at", "process_observed_at", "write_observed_at", "running_after_at")]
                if not times[0] < times[1] <= times[2] <= times[3] <= times[0] + 180 * SECOND:
                    fail()
                clocks.extend(times)
        if max(clocks) - min(clocks) > 180 * SECOND:
            fail()
        return {"contract": CONTRACT, "capability_admission": [], "catalogue_admission": False}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()


def read_runtime_filesystem_proof(path, capture_dir, expected_context):
    """Borrow the existing stable, bounded owner-private direct-child reader."""
    try:
        return read_private_proof(path, capture_dir, FILENAME, expected_context, validate_runtime_filesystem_proof)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fail()
