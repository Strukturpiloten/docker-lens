"""Independent eleven-control proof semantics and custody; no native execution."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_capabilities_proof as reader
from test_native_external_network_proof import fixture as context_fixture
LANES = ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless")
ROLES = ("default-cli", "add-cli", "add-rendered", "drop-cli", "drop-rendered", "both-cli", "both-rendered", "drop-all-cli", "netbind-only-cli", "all-cli", "all-minus-sysadmin-cli")
CONFIGS = ((None, []), (["NET_BIND_SERVICE"], []), (["NET_BIND_SERVICE"], None), ([], ["SYS_ADMIN"]), (None, ["SYS_ADMIN"]), (["NET_BIND_SERVICE"], ["SYS_ADMIN"]), (["NET_BIND_SERVICE"], ["SYS_ADMIN"]), (None, ["ALL"]), (["NET_BIND_SERVICE"], ["ALL"]), (["ALL"], []), (["ALL"], ["SYS_ADMIN"]))
ZERO = "0001-01-01T00:00:00Z"


def packet(raw):
    return {"raw": raw, "sha256": sha256(raw.encode()).hexdigest()}


def report(index, effective):
    # Literal UAPI bit10 / bit21 masks, independent of all production parsing.
    context = f"1 {1000+index} 42 {2000+index} user:[{3000+index}] user:[{3000+index}] held_current_pid1 sleep\nuid 0 0 0 0\nCapInh 0000000000000000\nCapPrm {effective:016x}\nCapEff {effective:016x}\nCapBnd {effective:016x}\nCapAmb 0000000000000000\n"
    return packet(f"named-capabilities-v1\nhostname {index+1:012x}\nbefore " + context + "after " + context)


def fixture(lane="upstream-rootful", *, outer_backend="podman"):
    c = deepcopy(context_fixture(lane)["context"])
    c["fixture_image"] = "docker.io/library/busybox:1.37.0@sha256:" + "b" * 64
    image = "sha256:" + "d" * 64
    masks = (1025, 1025, 1025, 1025, 1025, 1025, 1025, 0, 1024, 2098177, 1025)
    records = []
    for i, (role, caps, mask) in enumerate(zip(ROLES, CONFIGS, masks)):
        name = f"dl-cap-{c['run_id']}-{role}"
        created = {"id": f"{i+1:012x}" + "0"*52, "name": "/" + name, "image": image, "config_image": c["fixture_image"], "owner": c["run_id"], "hostname": f"{i+1:012x}", "cmd": ["sleep", "180"], "entrypoint": None, "user": "", "init": None, "running": False, "pid": 0, "started_at": ZERO, "finished_at": ZERO, "oom": False, "exit": 0, "status": "created", "restarts": 0, "error": "", "restarting": False, "paused": False, "dead": False, "privileged": False, "cap_add": deepcopy(caps[0]), "cap_drop": deepcopy(caps[1]), "mounts": [], "devices": [], "ports": {}}
        running = deepcopy(created)
        running.update(running=True, pid=100+i, started_at="2026-09-01T10:00:01.000000000Z", status="running")
        records.append({"role": role, "id": created["id"], "name": name, "owner": c["run_id"], "wire": "literal_rendered" if role.endswith("-rendered") else "independent_cli", "created": created, "running": running, "after": deepcopy(running), "effect": report(i, mask), "cleanup": "absent"})
    extra = {"podman": 0, "docker": 1}[outer_backend]
    calls = (9 if lane.startswith("debian11-") else 8) + extra
    return {"schema_version": 1, "contract": "named-capabilities-v1", "context": c, "outer_backend": outer_backend, "capability_admission": [], "catalogue_admission": False, "scope": "cli_causal_transitions_and_rendered_retention_namespace_local", "normalization": "four_profiles_named_optional_CAP_prefix_ALL_literal", "borrowed_image": {"id": image, "identity": "unchanged", "removal": "not_owned"}, "containers": records, "daemon_health": "version_matches_after_controls", "accounting": {"context_calls": calls, "slot_calls": [8]*11, "daemon_health_calls": 1, "final_readback_calls": 2+extra, "ordinary_calls": calls+91+extra, "ordinary_bytes": 1000000+2*65536*extra, "small_calls": 88, "small_bytes": 200000, "cleanup_calls": 99, "cleanup_bytes": 200000, "deadline_seconds": 180, "cleanup_reserve_seconds": 46, "ordinary_elapsed_ns": 5_000_000_000, "cleanup_elapsed_ns": 2_000_000_000, "elapsed_ns": 8_000_000_000, "initial_context_acquisition": {"max_requests": 16, "max_total_bytes": 2097152, "max_elapsed_seconds": 15, "accounting": "separate_existing_bound"}}, "cleanup": {"containers": "absent", "rounds": 2, "outstanding": 0, "uncertain": False}}


def bind_context(proof, context):
    old = proof["context"]["run_id"]
    proof["context"] = deepcopy(context)
    for item in proof["containers"]:
        item["owner"] = context["run_id"]
        item["name"] = item["name"].replace(old, context["run_id"])
        for phase in ("created", "running", "after"):
            item[phase]["owner"] = context["run_id"]
            item[phase]["name"] = "/" + item["name"]
            item[phase]["config_image"] = context["fixture_image"]
    return proof


def rebind(proof):
    for item in proof["containers"]:
        item["effect"]["sha256"] = sha256(item["effect"]["raw"].encode()).hexdigest()


def mutations():
    return {
        "swapped-roles": lambda p: p["containers"].reverse(),
        "missing-role": lambda p: p["containers"].pop(),
        "duplicate-id": lambda p: p["containers"][1].update(id=p["containers"][0]["id"]),
        "outer-id": lambda p: p["containers"][0].update(id=p["context"]["outer"]["id"]),
        "swapped-source-report": lambda p: p["containers"][2].update(effect=deepcopy(p["containers"][1]["effect"])),
        "wire": lambda p: p["containers"][2].update(wire="independent_cli"),
        "default-as-causal-zero": lambda p: p["containers"][7].update(effect=deepcopy(p["containers"][0]["effect"])),
        "default-as-addback": lambda p: p["containers"][8].update(effect=deepcopy(p["containers"][0]["effect"])),
        "sysadmin-not-dropped": lambda p: p["containers"][10].update(effect=deepcopy(p["containers"][9]["effect"])),
        "extra-addback-bit": lambda p: p["containers"][8].update(effect=report(8,1025)),
        "missing-netbind-default": lambda p: p["containers"][0].update(effect=report(0,1)),
        "sysadmin-default": lambda p: p["containers"][0].update(effect=report(0,2098177)),
        "all-no-sysadmin": lambda p: p["containers"][9].update(effect=report(9,1025)),
        "other-bit-dropped": lambda p: p["containers"][10].update(effect=report(10,1024)),
        "extra-rendered-bit": lambda p: p["containers"][2].update(effect=report(2,1027)),
        "borrowed-delete": lambda p: p["borrowed_image"].update(removal="deleted"),
        "ordinary-calls": lambda p: p["accounting"].update(ordinary_calls=1),
        "cleanup-calls": lambda p: p["accounting"].update(cleanup_calls=98),
        "cleanup-overflow": lambda p: p["accounting"].update(cleanup_bytes=1013761),
        "small-overflow": lambda p: p["accounting"].update(small_bytes=720897),
        "missing-reserve": lambda p: p["accounting"].update(cleanup_reserve_seconds=45),
        "work-time": lambda p: p["accounting"].update(ordinary_elapsed_ns=134000000001),
        "total-time": lambda p: p["accounting"].update(elapsed_ns=1),
        "cleanup-uncertain": lambda p: p["cleanup"].update(uncertain=True),
        "admission": lambda p: p.update(capability_admission=["LinuxCapabilities"]),
        "catalogue": lambda p: p.update(catalogue_admission=True),
        "private-extra": lambda p: p.update(PRIVATE_CAP_CANARY="PRIVATE_CAP_CANARY"),
    }


class CapabilitiesProofTests(unittest.TestCase):
    def reject(self, proof, context=None):
        with self.assertRaisesRegex(ValueError, "invalid private named capabilities proof"):
            reader.validate_capabilities_proof(proof, context or fixture()["context"], outer_backend="podman")

    def test_four_profiles_both_bound_backends_and_closed_result(self):
        for lane in LANES:
            for backend in ("podman", "docker"):
                p = fixture(lane, outer_backend=backend)
                self.assertLess(len(json.dumps(p).encode()),65536)
                self.assertEqual(reader.validate_capabilities_proof(p, p["context"], outer_backend=backend), {"contract":"named-capabilities-v1","capability_admission":[],"catalogue_admission":False})
                with self.assertRaises(ValueError):
                    reader.validate_capabilities_proof(p, p["context"], outer_backend="docker" if backend == "podman" else "podman")

    def test_rebound_semantics_and_false_causal_agreement_refuse(self):
        for name, mutate in mutations().items():
            with self.subTest(name=name):
                p=fixture(); mutate(p); rebind(p); self.reject(p)
        # Every raw field has independent semantic requirements after rebinding.
        for old,new in (("hostname 000000000001","hostname 000000000002"),("before 1 ","before 2 "),("after 1 1000","after 1 1001"),("after 1 1000 42 2000","after 1 1000 42 2001"),("user:[3000] user:[3000]","user:[3000] user:[3001]"),("uid 0 0 0 0","uid 0 1 0 0"),("sleep","sh"),("held_current_pid1","unheld"),("CapEff 0000000000000401","CapEff 0000000000200401"),("CapPrm 0000000000000401","CapPrm 0000000000000000"),("CapEff 0000000000000401","CapEff 10000000000000401"),("CapEff 0000000000000401","CapEff 0x00000000000401"),("CapEff 0000000000000401","CapEff 00000000000004A1"),("CapEff 0000000000000401","CapBnd 0000000000000401"),("CapAmb 0000000000000000\n",""),("\n","\r\n")):
            with self.subTest(raw=(old,new)):
                p=fixture(); p["containers"][0]["effect"]["raw"]=p["containers"][0]["effect"]["raw"].replace(old,new); rebind(p); self.reject(p)
        self.assertEqual(reader.cap_mask("ffffffffffffffff"),18446744073709551615)

    def test_each_native_config_and_context_binding_is_required(self):
        for phase in ("created","running","after"):
            for key,value in (("id","e"*64),("name","/other"),("image","sha256:"+"e"*64),("config_image","other"),("owner","Other123"),("hostname","wrong"),("cmd",["sh","-c","sleep 180"]),("entrypoint",["sh"]),("user","1000"),("init",True),("privileged",True),("mounts",[{}]),("devices",[{}]),("ports",{"80/tcp":[]}),("cap_add",["ALL"]),("cap_drop",["NET_BIND_SERVICE"]),("pid",0 if phase!="created" else 1),("oom",True),("error","error"),("restarts",1),("dead",True)):
                with self.subTest(phase=phase,key=key):
                    p=fixture();p["containers"][2][phase][key]=value;self.reject(p)
        for key,value in (("candidate_sha","e"*40),("run_id","Other123"),("lane","debian11-rootful"),("rendering_api","1.49"),("acquisition_api","1.56"),("mode","rootless"),("daemon_uid",1000),("fixture_image","other")):
            p=fixture();p["context"][key]=value;self.reject(p)
        # Only finite documented aliases are accepted; keep the genuine raw text.
        p=fixture()
        for item in p["containers"]:
            for phase in ("created","running","after"):
                for key in ("cap_add","cap_drop"):
                    if item[phase][key] and item[phase][key] != ["ALL"]:
                        item[phase][key]=["CAP_"+item[phase][key][0]]
        reader.validate_capabilities_proof(p,p["context"],outer_backend="podman")
        p["containers"][7]["running"]["cap_drop"]=["CAP_ALL"];self.reject(p)

    def test_private_custody_malformed_and_substitution_controls(self):
        for mutation in ("valid","duplicate","malformed","oversize","mode","dir-mode","symlink","hardlink","missing","fifo","replaced"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);root.chmod(0o700);p=fixture();path=root/reader.FILENAME
                path.write_text(json.dumps(p));path.chmod(0o600)
                if mutation=="duplicate":path.write_text('{"contract":"named-capabilities-v1",'+json.dumps(p)[1:])
                if mutation=="malformed":path.write_text('{')
                if mutation=="oversize":path.write_text(' '*65537)
                if mutation=="mode":path.chmod(0o644)
                if mutation=="dir-mode":root.chmod(0o755)
                if mutation=="symlink":path.rename(root/'other');path.symlink_to(root/'other')
                if mutation=="hardlink":os.link(path,root/'other')
                if mutation=="missing":path.unlink()
                if mutation=="fifo":path.unlink();os.mkfifo(path,0o600)
                if mutation=="valid":
                    self.assertEqual(reader.read_capabilities_proof(path,root,p['context'],outer_backend='podman'),reader.RESULT)
                elif mutation=="replaced":
                    import native_network_attachment_proof as custody
                    original=custody.os.open
                    def replace_open(name, flags, *args, **kwargs):
                        fd=original(name,flags,*args,**kwargs)
                        if str(name)==reader.FILENAME:
                            replacement=root/'replacement';replacement.write_text(path.read_text());replacement.chmod(0o600);replacement.replace(path)
                        return fd
                    with patch.object(custody.os,'open',side_effect=replace_open),self.assertRaises(ValueError):
                        reader.read_capabilities_proof(path,root,p['context'],outer_backend='podman')
                else:
                    with self.assertRaises(ValueError):reader.read_capabilities_proof(path,root,p['context'],outer_backend='podman')

    def test_held_directory_and_file_identity_replacement_refuses(self):
        for swap_directory in (False, True):
            with self.subTest(directory=swap_directory), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "capture"
                root.mkdir(mode=0o700)
                proof = fixture()
                path = root / reader.FILENAME
                path.write_text(json.dumps(proof)); path.chmod(0o600)
                original_read = os.read
                swapped = False
                def replaced_read(fd, size):
                    nonlocal swapped
                    data = original_read(fd, size)
                    if not swapped:
                        swapped = True
                        if swap_directory:
                            root.rename(root.with_name("old")); root.mkdir(mode=0o700)
                        else:
                            path.unlink(); path.write_text(json.dumps(proof)); path.chmod(0o600)
                    return data
                with patch("native_network_attachment_proof.os.read", side_effect=replaced_read), self.assertRaises(ValueError):
                    reader.read_capabilities_proof(path, root, proof["context"], outer_backend="podman")
                self.assertTrue(swapped)


if __name__ == '__main__':
    unittest.main()
