"""Pure controls: never build or execute the native fork witness."""

import hashlib
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pids_worker_builder", ROOT / "scripts/build-native-pids-worker.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def elf(machine=62, program_types=(1,), dynamic=None):
    """Independently authored minimal executable headers; never executable code."""
    offset = 64 + 56 * len(program_types)
    payload = dynamic if dynamic is not None else b"\x00" * 16
    data = bytearray(offset + len(payload))
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0,
                     b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
                     3, machine, 1, 0, 64, 0, 0, 64, 56, len(program_types), 0, 0, 0)
    for index, kind in enumerate(program_types):
        struct.pack_into("<IIQQQQQQ", data, 64 + 56 * index,
                         kind, 4, offset, 0, 0, len(payload), len(payload), 8)
    data[offset:] = payload
    return data


def successful_compiler(argv, env, deadline, log, **_options):
    """Pure substitute: write inert ELF bytes without invoking any process."""
    if argv[0] == "rustc":
        metadata = b"release: 1.98.1\nhost: x86_64-unknown-linux-gnu\n"
        log.extend(metadata)
        return metadata
    destination = Path(env["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/release/examples/native-pids-worker"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(elf())
    log.extend(b"fake compiler success\n")
    return b"fake compiler success\n"


class ElfTests(unittest.TestCase):
    def test_both_native_architectures_and_static_pie(self):
        for machine in (62, 183):
            static = elf(machine, (1, 2), struct.pack("<qQqQ", 7, 128, 0, 0))
            self.assertEqual(BUILDER.inspect_elf(static, machine), {
                "class": 64, "endianness": "little", "machine": machine,
                "pt_interp": False, "dt_needed": False})

    def test_loader_and_needed_library_refused(self):
        for data in (elf(program_types=(1, 3)),
                     elf(program_types=(1, 2), dynamic=struct.pack("<qQqQ", 1, 4, 0, 0))):
            with self.assertRaisesRegex(BUILDER.Refused, "^loader$"):
                BUILDER.inspect_elf(data, 62)

    def test_wrong_architecture_class_endian_header_and_truncation(self):
        bad = []
        for index, value in ((4, 1), (5, 2), (6, 0)):
            data = elf(); data[index] = value; bad.append(data)
        for offset, fmt, value in ((18, "<H", 183), (52, "<H", 63),
                                   (54, "<H", 55), (56, "<H", 65535),
                                   (32, "<Q", 2**64 - 1)):
            data = elf(); struct.pack_into(fmt, data, offset, value); bad.append(data)
        bad.extend((elf()[:63], elf()[:-1], b"\x00" * 80,
                    elf(program_types=(2,), dynamic=struct.pack("<qQ", 7, 1)),
                    elf(program_types=(1, 2, 2)), elf(program_types=(4,))))
        for data in bad:
            with self.subTest(data=hashlib.sha256(data).hexdigest()):
                with self.assertRaises(BUILDER.Refused):
                    BUILDER.inspect_elf(data, 62)

    def test_segment_bounds_and_unterminated_dynamic(self):
        for offset, value in ((64 + 8, 2**64 - 1), (64 + 32, 2**64 - 1), (64 + 40, 0)):
            data = elf(); struct.pack_into("<Q", data, offset, value)
            with self.assertRaises(BUILDER.Refused):
                BUILDER.inspect_elf(data, 62)
        for dynamic in (b"\x00", struct.pack("<qQ", 7, 1)):
            with self.assertRaises(BUILDER.Refused):
                BUILDER.inspect_elf(elf(program_types=(1, 2), dynamic=dynamic), 62)


class CustodyTests(unittest.TestCase):
    def test_native_gnu_vendor_aliases_are_closed_and_architecture_exact(self):
        for architecture in ("x86_64", "aarch64"):
            target = architecture + "-unknown-linux-gnu"
            for suffix in ("linux-gnu", "unknown-linux-gnu", "pc-linux-gnu", "suse-linux-gnu",
                           "redhat-linux-gnu", "suse-linux", "redhat-linux"):
                self.assertTrue(BUILDER.native_gnu_target(architecture + "-" + suffix, target), suffix)
            for suffix in ("linux", "unknown-linux", "pc-linux", "custom-linux", "linux-musl", "linux-uclibc",
                           "suse-linux-musl", "redhat-linux-uclibc", "linux-android", "linux-gnux32",
                           "linux-gnueabi", "linux-gnueabihf", "unknown-extra-linux-gnu", "musl-linux-gnu",
                           "uclibc-linux-gnu", "android-linux-gnu", "suse-linux-unknown"):
                self.assertFalse(BUILDER.native_gnu_target(architecture + "-" + suffix, target), suffix)
            for vendor in ("custom_musl", "custom_MUSL", "custom_uClibc", "custom_Android", "preandroidpost"):
                self.assertFalse(BUILDER.native_gnu_target(architecture + "-" + vendor + "-linux-gnu", target), vendor)
            vendor_length = 128 - len(architecture + "--linux-gnu")
            boundary = architecture + "-" + "v" * vendor_length + "-linux-gnu"
            oversized = architecture + "-" + "v" * (vendor_length + 1) + "-linux-gnu"
            self.assertEqual(len(boundary.encode("ascii")), 128)
            self.assertEqual(len(oversized.encode("ascii")), 129)
            self.assertTrue(BUILDER.native_gnu_target(boundary, target))
            self.assertFalse(BUILDER.native_gnu_target(oversized, target))
            self.assertFalse(BUILDER.native_gnu_target(architecture + "-vendör-linux-gnu", target))
        self.assertFalse(BUILDER.native_gnu_target("aarch64-suse-linux", "x86_64-unknown-linux-gnu"))
        self.assertFalse(BUILDER.native_gnu_target("x86_64-redhat-linux", "aarch64-unknown-linux-gnu"))
        self.assertFalse(BUILDER.native_gnu_target("i686-suse-linux", "x86_64-unknown-linux-gnu"))
        self.assertFalse(BUILDER.native_gnu_target("aarch64_be-suse-linux", "aarch64-unknown-linux-gnu"))
        self.assertFalse(BUILDER.native_gnu_target("x86_64-suse-linux", "x86_64-unknown-linux-musl"))
    def test_build_tools_refuse_root_without_changing_process_identity(self):
        with patch.object(BUILDER.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(BUILDER.Refused, "^build-tools$"):
                BUILDER.require_unprivileged()
        with patch.object(BUILDER.os, "geteuid", return_value=1000):
            BUILDER.require_unprivileged()
    def test_compiler_snapshot_rejects_symlink_third_link_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "compiler-output"
            path.write_bytes(b"abcd")
            os.link(path, root / "cargo-alias")
            alias = root / "symlink"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                BUILDER.compiler_bytes(alias, 4)
            os.link(path, root / "third-link")
            with self.assertRaises(BUILDER.Refused):
                BUILDER.compiler_bytes(path, 4)
            (root / "third-link").unlink()
            original_read = os.read
            changed = False
            def read_then_change(fd, count):
                nonlocal changed
                data = original_read(fd, count)
                if not changed:
                    changed = True
                    path.write_bytes(b"changed")
                return data
            with patch.object(BUILDER.os, "read", side_effect=read_then_change):
                with self.assertRaises(BUILDER.Refused):
                    BUILDER.compiler_bytes(path, 8)

    def test_compiler_snapshot_rejects_name_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "compiler-output"
            path.write_bytes(b"abcd")
            os.link(path, root / "cargo-alias")
            original_read = os.read
            changed = False
            def read_then_replace(fd, count):
                nonlocal changed
                data = original_read(fd, count)
                if not changed:
                    changed = True
                    path.unlink()
                    path.write_bytes(b"abcd")
                return data
            with patch.object(BUILDER.os, "read", side_effect=read_then_replace):
                with self.assertRaises(BUILDER.Refused):
                    BUILDER.compiler_bytes(path, 4)

    def test_regular_owned_single_link_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"abcd")
            self.assertEqual(BUILDER.regular_bytes(path, 4), b"abcd")
            with self.assertRaises(BUILDER.Refused):
                BUILDER.regular_bytes(path, 3)
            with self.assertRaises(BUILDER.Refused):
                BUILDER.regular_bytes(path, 4, owner=os.geteuid() + 1)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                BUILDER.regular_bytes(link, 4)
            link.unlink(); os.link(path, link)
            with self.assertRaises(BUILDER.Refused):
                BUILDER.regular_bytes(path, 4)

    def test_private_directory_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(BUILDER.private_directory(root), root)
            BUILDER.exclusive_write(root, "record", b"hello", 0o600)
            self.assertEqual(stat.S_IMODE((root / "record").stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                BUILDER.exclusive_write(root, "record", b"replacement", 0o600)
            link = root / "alias"; link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(BUILDER.Refused):
                BUILDER.private_directory(link)
            root.chmod(0o755)
            with self.assertRaises(BUILDER.Refused):
                BUILDER.private_directory(root)

    def test_exclusive_write_close_failure_removes_only_new_inode(self):
        original_close = os.close
        def close_then_fail(fd):
            original_close(fd)
            raise OSError("injected close failure")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new-output"
            with patch.object(BUILDER.os, "close", side_effect=close_then_fail):
                with self.assertRaises(OSError):
                    BUILDER.exclusive_write(Path(directory), path.name, b"bytes", 0o600)
            self.assertFalse(path.exists())

    def test_original_deadline_not_renewed(self):
        with patch.object(BUILDER.time, "monotonic_ns", return_value=10):
            BUILDER.reserve(10 + BUILDER.CLEANUP_NS + 1)
            for deadline in (10, 10 + BUILDER.CLEANUP_NS,
                             10 + BUILDER.MAX_RUN_NS + 1):
                with self.assertRaisesRegex(BUILDER.Refused, "^deadline$"):
                    BUILDER.reserve(deadline)

    def test_no_build_on_invalid_context(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=AssertionError("no process allowed")):
                with self.assertRaises(BUILDER.Refused):
                    BUILDER.build(directory, "bad", BUILDER.time.monotonic_ns() + 100_000_000_000)


class FakeToolBuild:
    """Artifact/CLI controls mock tools; separate tests exercise real policy."""
    def setUp(self):
        super().setUp()
        def prepare(scratch, target, *_args):
            self.tool_wrapper = Path(scratch) / "fake-driver"
            return {"wrapper": self.tool_wrapper, "guarded": (), "target": target}
        def finish(plan, _path, binary, _deadline):
            files = (b"fake driver\n", b"fake linker\n", b"fake invocation\n", b"fake dependency\n")
            identity = {"device": 1, "inode": 2, "uid": os.geteuid(), "gid": os.getegid(),
                        "mode": stat.S_IFREG | 0o755, "links": 1, "mtime_ns": 1, "ctime_ns": 1}
            def tool(path):
                return {"path": path, "file_kind": "script", "size": 4, "sha256": hashlib.sha256(b"tool").hexdigest(),
                        "identity": identity, "package": {"status": "unavailable", "reason": "os-bootstrap-not-queried",
                                                          "unverified_path_hint": None}}
            record = {"schema": "dockerlens-pids-build-tools-v1", "policy": "native-gcc-bfd-v1",
                      "driver": {**tool("/usr/bin/gcc"), "version": "gcc (GCC) fake", "native_target": plan["target"].replace("-unknown-", "-")},
                      "linker": {**tool("/usr/bin/ld.bfd"), "version": "GNU ld fake"},
                      "wrappers": {"driver_sha256": hashlib.sha256(files[0]).hexdigest(),
                                   "linker_sha256": hashlib.sha256(files[1]).hexdigest()},
                      "invocation": {"count": 1, "size": len(files[2]), "sha256": hashlib.sha256(files[2]).hexdigest(),
                                     "output_size": len(binary), "output_sha256": hashlib.sha256(binary).hexdigest()},
                      "dependencies": {"size": len(files[3]), "sha256": hashlib.sha256(files[3]).hexdigest()},
                      "crt": [{**tool("/usr/lib/" + name), "file_kind": "archive" if name.endswith(".a") else "elf", "role": role} for name, role in
                              [("crt1.o", "start"), ("crti.o", "init"), ("crtn.o", "fini"),
                               ("crtbegin.o", "begin"), ("crtend.o", "end"), ("libc.a", "libc")]],
                      "hashed_input_bytes": 64, "scope": "installed-tools-and-consumed-crt-only-v1",
                      "implementation_closure": "unresolved"}
            return record, files
        for name, fake in (("prepare_tools", prepare), ("finish_tools", finish)):
            replacement = patch.object(BUILDER, name, side_effect=fake)
            replacement.start()
            self.addCleanup(replacement.stop)


class BuildReceiptTests(FakeToolBuild, unittest.TestCase):
    def test_missing_required_tool_receipt_refuses_artifact_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=successful_compiler), \
                    patch.object(BUILDER, "finish_tools", side_effect=BUILDER.Refused("build-tools")), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaisesRegex(BUILDER.Refused, "^build-tools$"):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            self.assertFalse((Path(directory) / BUILDER.OUTPUT).exists())
            self.assertFalse((Path(directory) / BUILDER.MANIFEST).exists())

    def test_tool_record_write_failure_rolls_back_private_records_and_artifacts(self):
        original_write = BUILDER.exclusive_write
        def fail_record(root, name, data, mode):
            if name == BUILDER.TOOL_FILES[2]:
                raise OSError("injected tool receipt publication failure")
            return original_write(root, name, data, mode)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=successful_compiler), \
                    patch.object(BUILDER, "exclusive_write", side_effect=fail_record), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaises(OSError):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            self.assertEqual({path.name for path in Path(directory).iterdir()}, {BUILDER.LOG})

    def test_missing_controller_source_refuses_before_any_compiler(self):
        original_read = BUILDER.regular_bytes
        def missing_controller(path, limit, owner=None):
            if Path(path) == ROOT / "examples/native-pids-controller/mod.rs":
                raise FileNotFoundError("injected missing mandatory controller source")
            return original_read(path, limit, owner)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "regular_bytes", side_effect=missing_controller), \
                    patch.object(BUILDER, "command", side_effect=AssertionError("compiler must not start")), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaises(FileNotFoundError):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            self.assertFalse((Path(directory) / BUILDER.OUTPUT).exists())
            self.assertFalse((Path(directory) / BUILDER.MANIFEST).exists())

    def test_controller_source_change_across_build_refuses_artifact(self):
        original_read = BUILDER.regular_bytes
        reads = 0
        def changed_controller(path, limit, owner=None):
            nonlocal reads
            data = original_read(path, limit, owner)
            if Path(path) == ROOT / "examples/native-pids-controller/mod.rs":
                reads += 1
                if reads == 2:
                    return data + b"changed during build"
            return data
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "regular_bytes", side_effect=changed_controller), \
                    patch.object(BUILDER, "command", side_effect=successful_compiler), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaisesRegex(BUILDER.Refused, "^source$"):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            self.assertEqual(reads, 2)
            self.assertFalse((Path(directory) / BUILDER.OUTPUT).exists())
            self.assertFalse((Path(directory) / BUILDER.MANIFEST).exists())

    def test_mandatory_log_failure_never_leaves_executable_or_manifest(self):
        original_write = BUILDER.exclusive_write
        for fail_after_write in (False, True):
            with self.subTest(fail_after_write=fail_after_write), tempfile.TemporaryDirectory() as directory:
                writes = []
                def fail_log(root, name, data, mode):
                    writes.append(name)
                    if name == BUILDER.LOG:
                        if fail_after_write:
                            original_write(root, name, data, mode)
                        raise OSError("injected mandatory log failure")
                    return original_write(root, name, data, mode)
                with patch.object(BUILDER, "command", side_effect=successful_compiler), \
                        patch.object(BUILDER, "exclusive_write", side_effect=fail_log), \
                        patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                        patch.object(BUILDER.platform, "system", return_value="Linux"):
                    with self.assertRaises(OSError):
                        BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
                self.assertEqual(writes, [BUILDER.LOG])
                self.assertFalse((Path(directory) / BUILDER.OUTPUT).exists())
                self.assertFalse((Path(directory) / BUILDER.MANIFEST).exists())

    def test_log_verification_failure_precedes_artifact_publication(self):
        original_read = BUILDER.regular_bytes
        def changed_log(path, limit, owner=None):
            if Path(path).name == BUILDER.LOG:
                return b"altered log"
            return original_read(path, limit, owner)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=successful_compiler), \
                    patch.object(BUILDER, "regular_bytes", side_effect=changed_log), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaisesRegex(BUILDER.Refused, "^build-log$"):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            self.assertFalse((Path(directory) / BUILDER.OUTPUT).exists())
            self.assertFalse((Path(directory) / BUILDER.MANIFEST).exists())

    def test_manifest_fsync_failure_rolls_back_new_artifact_inodes(self):
        original_fsync = os.fsync
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def fail_manifest_fsync(fd):
                manifest = root / BUILDER.MANIFEST
                if manifest.exists():
                    actual, named = os.fstat(fd), manifest.stat()
                    if (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino):
                        raise OSError("injected manifest fsync failure")
                return original_fsync(fd)
            with patch.object(BUILDER, "command", side_effect=successful_compiler), \
                    patch.object(BUILDER.os, "fsync", side_effect=fail_manifest_fsync), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaises(OSError):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            self.assertFalse((root / BUILDER.OUTPUT).exists())
            self.assertFalse((root / BUILDER.MANIFEST).exists())
            self.assertTrue((root / BUILDER.LOG).is_file())

    def test_preexisting_names_are_preserved_without_compiler_or_writes(self):
        for name in (BUILDER.OUTPUT, BUILDER.MANIFEST, BUILDER.LOG, *BUILDER.TOOL_FILES):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                sentinel = Path(directory) / name
                sentinel.write_bytes(b"belongs to someone else")
                before = sentinel.stat()
                with patch.object(BUILDER, "command", side_effect=AssertionError("no compiler allowed")), \
                        patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                        patch.object(BUILDER.platform, "system", return_value="Linux"):
                    with self.assertRaisesRegex(BUILDER.Refused, "^output$"):
                        BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
                after = sentinel.stat()
                self.assertEqual((before.st_dev, before.st_ino, before.st_mode), (after.st_dev, after.st_ino, after.st_mode))
                self.assertEqual(sentinel.read_bytes(), b"belongs to someone else")

    def test_missing_static_crt_fails_without_fallback_or_usable_output(self):
        calls = []
        def unavailable_crt(argv, env, deadline, log, **_options):
            calls.append(argv)
            if argv[0] == "rustc":
                return b"release: 1.98.1\nhost: x86_64-unknown-linux-gnu\n"
            log.extend(b"private missing static CRT diagnostic\n")
            raise BUILDER.Refused("compiler")
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=unavailable_crt), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaisesRegex(BUILDER.Refused, "^compiler$"):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            self.assertEqual(len(calls), 2)
            self.assertEqual({path.name for path in Path(directory).iterdir()}, {BUILDER.LOG})
            self.assertEqual((Path(directory) / BUILDER.LOG).read_bytes(), b"private missing static CRT diagnostic\n")

    def test_wrong_compiler_or_target_refuses_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", return_value=b"release: 0.0.0\nhost: x86_64-unknown-linux-gnu\n") as command, \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaisesRegex(BUILDER.Refused, "^toolchain$"):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
                self.assertEqual(command.call_count, 1)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=AssertionError("no process allowed")), \
                    patch.object(BUILDER.platform, "machine", return_value="armv7l"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaisesRegex(BUILDER.Refused, "^target$"):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)

    def test_fake_compiler_static_bytes_closed_receipt(self):
        """No subprocess: fake commands emit metadata and inert ELF header bytes."""
        compiler = b"rustc 1.98.1 (test)\nrelease: 1.98.1\nhost: x86_64-unknown-linux-gnu\n"
        calls = []
        cargo_flags = []
        compiler_inode = None
        def fake_command(argv, env, deadline, log, **_options):
            nonlocal compiler_inode
            calls.append(argv)
            self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
            expected_flags = BUILDER.FLAGS if argv[0] == "rustc" else BUILDER.FLAGS + " -C linker-flavor=gcc -C linker-features=-lld"
            self.assertEqual(env["RUSTFLAGS"], expected_flags)
            self.assertNotIn("RUSTC_WRAPPER", env)
            self.assertNotIn("CARGO_BUILD_JOBS", env)
            self.assertFalse(any(key.startswith("CARGO_PROFILE_") for key in env))
            for name in ("GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", "COLLECT_GCC_OPTIONS"):
                self.assertNotIn(name, env)
            if argv[0] == "rustc":
                log.extend(compiler); return compiler
            cargo_flags.append(env["RUSTFLAGS"])
            self.assertEqual(argv[argv.index("--jobs") + 1], "2")
            overrides = [argv[index + 1] for index, value in enumerate(argv) if value == "--config"]
            self.assertEqual(overrides[:3], ['profile.release.opt-level="z"', 'profile.release.lto="fat"',
                                         'profile.release.codegen-units=1'])
            self.assertEqual(len(overrides), 4)
            self.assertEqual(tomllib.loads(overrides[3])["target"]["x86_64-unknown-linux-gnu"]["linker"], str(self.tool_wrapper))
            configured = {}
            for override in overrides[:3]:
                configured.update(tomllib.loads(override)["profile"]["release"])
            self.assertEqual(configured, {"opt-level": "z", "lto": "fat", "codegen-units": 1})
            self.assertNotIn("lto", env["RUSTFLAGS"])
            self.assertNotIn("embed-bitcode", env["RUSTFLAGS"])
            destination = Path(env["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/release/examples/native-pids-worker"
            destination.parent.mkdir(parents=True)
            destination.write_bytes(elf())
            os.link(destination, destination.with_name("native-pids-worker-cargo-alias"))
            compiler_inode = destination.stat().st_ino
            self.assertEqual(destination.stat().st_nlink, 2)
            # Artifact readers remain strict even for a valid compiler output.
            with self.assertRaises(BUILDER.Refused):
                BUILDER.regular_bytes(destination, BUILDER.MAX_BINARY)
            log.extend(b"fake success\n")
            return b"fake success\n"
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=fake_command), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"), \
                    patch.dict(os.environ, {"RUSTC_WRAPPER": "untrusted", "CARGO_BUILD_JOBS": "99",
                                            "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3",
                                            "CARGO_PROFILE_RELEASE_LTO": "off",
                                            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "256",
                                            "GCC_EXEC_PREFIX": "/forbidden", "COMPILER_PATH": "/forbidden",
                                            "LIBRARY_PATH": "/forbidden", "COLLECT_GCC_OPTIONS": "forbidden"}):
                BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            root = Path(directory)
            receipt = json.loads((root / BUILDER.MANIFEST).read_text())
            self.assertEqual(set(receipt), {
                "schema", "candidate", "toolchain", "compiler", "target", "flags", "profile", "build_tools", "binary", "size", "sha256", "elf",
                "source_sha256", "controller_source_sha256", "cargo_lock_sha256", "cargo_manifest_sha256", "build_log_sha256", "build_log_size", "original_deadline_ns"})
            self.assertEqual(set(receipt["compiler"]), {"release", "host", "commit_hash", "commit_date", "llvm_version"})
            self.assertEqual(receipt["profile"], {"name": "release", "opt-level": "z", "lto": "fat", "codegen-units": 1})
            self.assertEqual(receipt["flags"], "-C target-feature=+crt-static -C panic=abort -C strip=symbols -C linker-flavor=gcc -C linker-features=-lld")
            self.assertEqual(cargo_flags, [receipt["flags"]])
            self.assertEqual(receipt["build_tools"]["schema"], "dockerlens-pids-build-tools-v1")
            self.assertEqual(receipt["build_tools"]["invocation"]["output_sha256"], receipt["sha256"])
            self.assertEqual(receipt["sha256"], hashlib.sha256(bytes(elf())).hexdigest())
            self.assertEqual(receipt["size"], len(elf()))
            self.assertEqual(receipt["controller_source_sha256"], hashlib.sha256((ROOT / "examples/native-pids-controller/mod.rs").read_bytes()).hexdigest())
            self.assertEqual(receipt["build_log_sha256"], hashlib.sha256((root / BUILDER.LOG).read_bytes()).hexdigest())
            self.assertIn("--locked", calls[1]); self.assertIn("--offline", calls[1])
            self.assertEqual(stat.S_IMODE((root / BUILDER.OUTPUT).stat().st_mode), 0o700)
            artifact = root / BUILDER.OUTPUT
            self.assertEqual(artifact.stat().st_nlink, 1)
            self.assertEqual(artifact.stat().st_uid, os.geteuid())
            self.assertTrue(stat.S_ISREG(artifact.stat().st_mode))
            self.assertNotEqual(artifact.stat().st_ino, compiler_inode)
            self.assertEqual(BUILDER.regular_bytes(artifact, BUILDER.MAX_BINARY), bytes(elf()))

    def test_aarch64_receipt_records_actual_flags_without_x86_lld_setting(self):
        cargo_flags = []
        def fake_command(argv, env, deadline, log, **_options):
            if argv[0] == "rustc":
                raw = b"release: 1.98.1\nhost: aarch64-unknown-linux-gnu\n"
                log.extend(raw)
                return raw
            self.assertEqual(argv[argv.index("--target") + 1], "aarch64-unknown-linux-gnu")
            self.assertEqual(argv[argv.index("--jobs") + 1], "2")
            cargo_flags.append(env["RUSTFLAGS"])
            destination = Path(env["CARGO_TARGET_DIR"]) / "aarch64-unknown-linux-gnu/release/examples/native-pids-worker"
            destination.parent.mkdir(parents=True)
            destination.write_bytes(elf(183))
            return b""
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=fake_command), \
                    patch.object(BUILDER.platform, "machine", return_value="aarch64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            receipt = json.loads((Path(directory) / BUILDER.MANIFEST).read_text())
            self.assertEqual(receipt["flags"], "-C target-feature=+crt-static -C panic=abort -C strip=symbols -C linker-flavor=gcc")
            self.assertEqual(cargo_flags, [receipt["flags"]])
            self.assertEqual(receipt["target"], "aarch64-unknown-linux-gnu")

    def test_failed_static_validation_never_publishes_binary_or_manifest(self):
        def fake_command(argv, env, deadline, log, **_options):
            if argv[0] == "rustc":
                return b"release: 1.98.1\nhost: x86_64-unknown-linux-gnu\n"
            path = Path(env["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/release/examples/native-pids-worker"
            path.parent.mkdir(parents=True)
            path.write_bytes(elf(program_types=(1, 3)))
            log.extend(b"fake compiler details\n")
            return b""
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(BUILDER, "command", side_effect=fake_command), \
                    patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                    patch.object(BUILDER.platform, "system", return_value="Linux"):
                with self.assertRaisesRegex(BUILDER.Refused, "^loader$"):
                    BUILDER.build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
            root = Path(directory)
            self.assertFalse((root / BUILDER.OUTPUT).exists())
            self.assertFalse((root / BUILDER.MANIFEST).exists())
            self.assertEqual((root / BUILDER.LOG).read_bytes(), b"fake compiler details\n")


class CliCancellationTests(FakeToolBuild, unittest.TestCase):
    @contextmanager
    def cli_signals(self):
        previous = {BUILDER.signal.SIGTERM: BUILDER.signal.SIG_DFL,
                    BUILDER.signal.SIGINT: BUILDER.signal.default_int_handler}
        handlers = dict(previous)
        ignored = []
        def install(number, handler):
            old = handlers[number]
            handlers[number] = handler
            return old
        def deliver(number):
            handler = handlers[number]
            if handler == BUILDER.signal.SIG_IGN:
                ignored.append(number)
            else:
                handler(number, None)
        with patch.object(BUILDER.signal, "getsignal", side_effect=lambda number: handlers[number]), \
                patch.object(BUILDER.signal, "signal", side_effect=install):
            yield deliver, ignored
        self.assertEqual(handlers, previous)
        self.assertFalse(BUILDER._CANCEL_REQUESTED)

    def test_cancel_during_compiler_startup_reaps_owned_group_despite_repeat(self):
        deadline = BUILDER.time.monotonic_ns() + 100_000_000_000
        process = Mock(pid=12345)
        process.returncode = None
        process.poll.return_value = None
        with self.cli_signals() as (deliver, ignored):
            def start(*args, **kwargs):
                self.assertTrue(kwargs["start_new_session"])
                deliver(BUILDER.signal.SIGTERM)
                return process
            def reap(timeout):
                self.assertLessEqual(timeout, 100)
                deliver(BUILDER.signal.SIGINT)
                return 0
            process.wait.side_effect = reap
            def invoke(_output, _candidate, original_deadline):
                self.assertEqual(original_deadline, deadline)
                return BUILDER.command(["inert-compiler"], {}, original_deadline, bytearray())
            with patch.object(BUILDER, "build", side_effect=invoke), \
                    patch.object(BUILDER.subprocess, "Popen", side_effect=start), \
                    patch.object(BUILDER.os, "killpg") as kill:
                with self.assertRaisesRegex(BUILDER.Refused, "^cancelled$"):
                    BUILDER.run_cli_build("unused", "a" * 40, deadline)
                kill.assert_called_once_with(process.pid, BUILDER.signal.SIGKILL)
            process.wait.assert_called_once()
            process.stdout.close.assert_called_once()
            self.assertEqual(ignored, [BUILDER.signal.SIGINT])

    def test_cancel_after_compiler_output_closed_uses_bounded_wait_then_cleanup(self):
        deadline = BUILDER.time.monotonic_ns() + 100_000_000_000
        process = Mock(pid=12345)
        process.returncode = None
        process.poll.return_value = None
        selector = Mock()
        selector.get_map.return_value = {}
        selector_context = Mock()
        selector_context.__enter__ = Mock(return_value=selector)
        selector_context.__exit__ = Mock(return_value=False)
        waits = []
        with self.cli_signals() as (deliver, ignored):
            def wait(timeout):
                waits.append(timeout)
                if len(waits) == 1:
                    self.assertLessEqual(timeout, 0.05)
                    deliver(BUILDER.signal.SIGINT)
                    raise BUILDER.subprocess.TimeoutExpired("inert-compiler", timeout)
                self.assertLessEqual(timeout, 100)
                deliver(BUILDER.signal.SIGTERM)
                return 0
            process.wait.side_effect = wait
            with patch.object(BUILDER, "build", side_effect=lambda _o, _c, d: BUILDER.command(["inert-compiler"], {}, d, bytearray())), \
                    patch.object(BUILDER.subprocess, "Popen", return_value=process), \
                    patch.object(BUILDER.selectors, "DefaultSelector", return_value=selector_context), \
                    patch.object(BUILDER.os, "killpg") as kill:
                with self.assertRaisesRegex(BUILDER.Refused, "^cancelled$"):
                    BUILDER.run_cli_build("unused", "a" * 40, deadline)
                kill.assert_called_once_with(process.pid, BUILDER.signal.SIGKILL)
            self.assertEqual(len(waits), 2)
            self.assertEqual(ignored, [BUILDER.signal.SIGTERM])
            process.stdout.close.assert_called_once()

    def test_metadata_overflow_unwinds_owned_process_cleanup_before_capture(self):
        process = Mock(pid=12345)
        process.returncode = None
        process.wait.return_value = 0
        deadline = BUILDER.time.monotonic_ns() + 100_000_000_000
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "known-private-record"
            trace.write_bytes(b"too large")
            with patch.object(BUILDER.subprocess, "Popen", return_value=process), patch.object(BUILDER.os, "killpg") as kill:
                with self.assertRaisesRegex(BUILDER.Refused, "^build-tools$"):
                    BUILDER.command(["inert-compiler"], {}, deadline, bytearray(), guarded=((trace, 1),))
                kill.assert_called_once_with(process.pid, BUILDER.signal.SIGKILL)
            process.wait.assert_called_once()
            process.stdout.close.assert_called_once()

    def test_cancel_during_publication_rolls_back_registered_artifacts(self):
        original_write = BUILDER.exclusive_write
        for cancel_name in (BUILDER.LOG, BUILDER.OUTPUT, BUILDER.MANIFEST):
            with self.subTest(cancel_name=cancel_name), tempfile.TemporaryDirectory() as directory, self.cli_signals() as (deliver, _):
                def publish(root, name, data, mode):
                    identity = original_write(root, name, data, mode)
                    if name == cancel_name:
                        deliver(BUILDER.signal.SIGTERM)
                    return identity
                with patch.object(BUILDER, "command", side_effect=successful_compiler), \
                        patch.object(BUILDER, "exclusive_write", side_effect=publish), \
                        patch.object(BUILDER.platform, "machine", return_value="x86_64"), \
                        patch.object(BUILDER.platform, "system", return_value="Linux"):
                    with self.assertRaisesRegex(BUILDER.Refused, "^cancelled$"):
                        BUILDER.run_cli_build(directory, "a" * 40, BUILDER.time.monotonic_ns() + 100_000_000_000)
                self.assertFalse((Path(directory) / BUILDER.OUTPUT).exists())
                self.assertFalse((Path(directory) / BUILDER.MANIFEST).exists())

    def test_cli_cancellation_is_fixed_nonzero(self):
        deadline = BUILDER.time.monotonic_ns() + 100_000_000_000
        with self.cli_signals() as (deliver, _):
            def cancel_build(_output, _candidate, original_deadline):
                deliver(BUILDER.signal.SIGINT)
                BUILDER.reserve(original_deadline)
            argv = ["builder", "--output-directory", "unused", "--candidate", "a" * 40,
                    "--deadline-ns", str(deadline)]
            with patch.object(BUILDER, "build", side_effect=cancel_build), patch("sys.argv", argv):
                with self.assertRaises(SystemExit) as failure:
                    BUILDER.main()
            self.assertEqual(failure.exception.code, "native-pids-worker-build: refused")


class ToolReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.driver, self.linker = self.root / "gcc", self.root / "ld.bfd"
        for path in (self.driver, self.linker):
            path.write_bytes(b"#!/bin/sh\n# inert tool bytes\n")
            path.chmod(0o755)
        self.crt = {}
        for name in BUILDER.CRT_ROLES:
            path = self.root / name
            path.write_bytes(b"!<arch>\n" + name.encode() if name.endswith(".a") else bytes(elf()))
            path.chmod(0o644)
            self.crt[name] = path
        self.deadline = BUILDER.time.monotonic_ns() + 100_000_000_000
        for replacement in (
            patch.object(BUILDER, "SYSTEM_ROOTS", (self.root,)),
            patch.object(BUILDER, "require_unprivileged"),
            patch.object(BUILDER.shutil, "which", side_effect=lambda name: str({"gcc": self.driver, "ld.bfd": self.linker}[name])),
            patch.object(BUILDER, "command", side_effect=self.query),
        ):
            replacement.start(); self.addCleanup(replacement.stop)
        self.plan = BUILDER.prepare_tools(self.scratch, "x86_64-unknown-linux-gnu", {}, self.deadline, bytearray())

    def query(self, argv, _env, _deadline, _log, **_options):
        if argv == [str(self.driver), "--version"]:
            return b"gcc (GCC) 16.2.1\n"
        if argv == [str(self.linker), "--version"]:
            return b"GNU ld (GNU Binutils) 2.45\n"
        if argv == [str(self.driver), "-dumpmachine"]:
            return b"x86_64-linux-gnu\n"
        name = argv[1].removeprefix("-print-file-name=")
        return (str(self.crt[name]) + "\n").encode()

    def evidence(self):
        native = self.plan["native_root"] / "native_pids_worker-0123456789abcdef"
        native.parent.mkdir(parents=True)
        native.write_bytes(elf())
        binary = native.with_name("native-pids-worker")
        os.link(native, binary)
        names = ["rcrt1.o", "crti.o", "crtn.o", "crtbeginS.o", "crtendS.o", "libc.a", "libgcc.a", "libgcc_eh.a"]
        inputs = [str(self.crt[name]) for name in names]
        argv = ["-o", str(native), *inputs, "--dependency-file=" + str(self.plan["depfile"])]
        record = {"schema": "dockerlens-pids-link-v1", "linker": str(self.linker), "output": str(native), "argv": argv}
        self.plan["receipt"].write_text(json.dumps(record))
        deps = str(native) + ": " + " \\\n ".join(inputs) + "\n" + "".join(path + ":\n" for path in inputs)
        self.plan["depfile"].write_text(deps)
        return binary, native, record

    def test_actual_consumption_receipt_binds_static_pie_and_output_bytes(self):
        binary, _native, _record = self.evidence()
        value, files = BUILDER.finish_tools(self.plan, binary, bytes(elf()), self.deadline)
        self.assertEqual(set(value), {"schema", "policy", "driver", "linker", "wrappers", "invocation",
                                     "dependencies", "crt", "hashed_input_bytes", "scope", "implementation_closure"})
        self.assertEqual(value["policy"], "native-gcc-bfd-v1")
        self.assertEqual(value["driver"]["file_kind"], "script")
        self.assertEqual(value["implementation_closure"], "unresolved")
        self.assertEqual(value["invocation"], {"count": 1, "size": len(files[2]), "sha256": hashlib.sha256(files[2]).hexdigest(),
                                              "output_size": len(elf()), "output_sha256": hashlib.sha256(elf()).hexdigest()})
        self.assertEqual({Path(record["path"]).name for record in value["crt"]},
                         {"rcrt1.o", "crti.o", "crtn.o", "crtbeginS.o", "crtendS.o", "libc.a", "libgcc.a", "libgcc_eh.a"})
        self.assertEqual(value["crt"][0]["package"], {"status": "unavailable", "reason": "os-bootstrap-not-queried", "unverified_path_hint": None})
        self.assertEqual(value["dependencies"]["sha256"], hashlib.sha256(files[3]).hexdigest())
        for source in (self.plan["driver_source"], self.plan["linker_source"]):
            compile(source, "inert-generated-shim", "exec")

    def test_vendor_alias_probe_is_preserved_separately_from_rust_target(self):
        for architecture in ("x86_64", "aarch64"):
            for vendor in ("suse", "redhat"):
                target = architecture + "-unknown-linux-gnu"
                reported = architecture + "-" + vendor + "-linux"
                scratch = self.root / (architecture + "-" + vendor)
                scratch.mkdir(mode=0o700)
                def alias_query(argv, env, deadline, log, **options):
                    if argv == [str(self.driver), "-dumpmachine"]:
                        return (reported + "\n").encode()
                    return self.query(argv, env, deadline, log, **options)
                with patch.object(BUILDER, "command", side_effect=alias_query):
                    plan = BUILDER.prepare_tools(scratch, target, {}, self.deadline, bytearray())
                self.assertEqual(plan["driver"]["native_target"], reported)
                self.assertEqual(plan["native_root"], scratch / "target" / target / "release/examples")

    def test_shim_invokes_only_selected_linker_and_refuses_duplicate_final_link(self):
        _binary, native, record = self.evidence()
        self.plan["receipt"].unlink()
        argv = [str(self.plan["wrapper"].with_name("ld.bfd")), *record["argv"][:-1]]
        with patch("sys.argv", argv), patch.object(BUILDER.os, "geteuid", return_value=1000), \
                patch.object(BUILDER.os, "execv") as execute:
            exec(compile(self.plan["linker_source"], "inert-shim", "exec"), {})
            execute.assert_called_once()
            self.assertEqual(execute.call_args.args[0], str(self.linker))
            self.assertEqual(execute.call_args.args[1][-1], "--dependency-file=" + str(self.plan["depfile"]))
            with self.assertRaises(FileExistsError):
                exec(compile(self.plan["linker_source"], "inert-shim", "exec"), {})
            execute.assert_called_once()
        observed = json.loads(self.plan["receipt"].read_text())
        self.assertEqual(observed["output"], str(native))

    def test_missing_witness_bypass_never_accepts_existing_binary(self):
        binary, _native, _record = self.evidence()
        self.plan["receipt"].unlink()
        with self.assertRaises(FileNotFoundError):
            BUILDER.finish_tools(self.plan, binary, bytes(elf()), self.deadline)

    def test_wrong_backend_output_duplicate_keys_and_dependency_override_refuse(self):
        binary, _native, original = self.evidence()
        variants = []
        wrong = dict(original); wrong["linker"] = "/usr/bin/not-the-selected-linker"; variants.append(json.dumps(wrong))
        wrong = dict(original); wrong["output"] = str(self.root / "foreign"); variants.append(json.dumps(wrong))
        wrong = dict(original); wrong["argv"] = original["argv"] + ["--dependency-file=foreign"]; variants.append(json.dumps(wrong))
        variants.append('{"schema":"duplicate",' + json.dumps(original)[1:])
        variants.append("[]")
        for raw in variants:
            self.plan["receipt"].write_text(raw)
            with self.assertRaises(BUILDER.Refused):
                BUILDER.finish_tools(self.plan, binary, bytes(elf()), self.deadline)

    def test_crt_mutation_unresolved_archive_and_wrapper_change_refuse(self):
        binary, native, _record = self.evidence()
        original = self.crt["libc.a"].read_bytes()
        self.crt["libc.a"].write_bytes(b"changed CRT")
        with self.assertRaises(BUILDER.Refused):
            BUILDER.finish_tools(self.plan, binary, bytes(elf()), self.deadline)
        self.crt["libc.a"].write_bytes(original)
        self.plan["files"][str(self.crt["libc.a"])]=BUILDER.system_file(self.crt["libc.a"], self.deadline)
        missing = self.root / "unresolved" / "libc.a"
        missing.parent.mkdir(); missing.write_bytes(b"unresolved CRT")
        self.plan["depfile"].write_text(str(native) + ": " + str(missing) + "\n")
        with self.assertRaises(BUILDER.Refused):
            BUILDER.finish_tools(self.plan, binary, bytes(elf()), self.deadline)
        self.plan["wrapper"].write_bytes(b"changed wrapper")
        with self.assertRaises(BUILDER.Refused):
            BUILDER.finish_tools(self.plan, binary, bytes(elf()), self.deadline)

    def test_dependency_escape_parser_rejects_evaluation_and_bad_rules(self):
        raw = b"/tmp/final: /usr/lib/a\\ b.o \\\n /usr/lib/c\\#d.o\n/usr/lib/a\\ b.o:\n/usr/lib/c\\#d.o:\n"
        self.assertEqual(BUILDER.dependency_inputs(raw, "/tmp/final"), {"/usr/lib/a b.o", "/usr/lib/c#d.o"})
        for raw in (b"/tmp/final: $expand\n", b"/tmp/final: path\\q\n", b"/tmp/final: x\\",
                    b"/tmp/final: x\nforeign: y\n", b"wrong: x\n", b"/tmp/final:\n", b"/tmp/final: x:y\n"):
            with self.assertRaises(BUILDER.Refused):
                BUILDER.dependency_inputs(raw, "/tmp/final")

    def test_system_path_size_permissions_and_cancellation_are_checked_before_read(self):
        with self.assertRaises(BUILDER.Refused):
            BUILDER.system_path("/outside/credential")
        installed = self.root / "installed"
        installed.mkdir()
        entry = installed / "gcc"
        entry.write_bytes(b"#!/bin/sh\n")
        alias = self.root / "profile-gcc"
        alias.symlink_to(entry)
        with patch.object(BUILDER, "SYSTEM_ROOTS", (installed,)):
            with self.assertRaises(BUILDER.Refused):
                BUILDER.system_path(alias)
            self.assertEqual(BUILDER.system_path(alias, tool_alias=True), entry)
        with self.assertRaises(BUILDER.Refused):
            BUILDER.system_file(self.driver, self.deadline, expected_kinds=("elf",))
        with patch.object(BUILDER.os, "read", side_effect=AssertionError("no content read")):
            with self.assertRaises(BUILDER.Refused):
                BUILDER.system_file(self.driver, self.deadline, remaining=1)
        self.driver.chmod(0o777)
        with self.assertRaises(BUILDER.Refused):
            BUILDER.system_file(self.driver, self.deadline)
        self.driver.chmod(0o755)
        self.driver.chmod(0o4755)
        with self.assertRaises(BUILDER.Refused):
            BUILDER.system_file(self.driver, self.deadline)
        self.driver.chmod(0o755)
        with patch.object(BUILDER, "_CANCEL_REQUESTED", True):
            with self.assertRaisesRegex(BUILDER.Refused, "^cancelled$"):
                BUILDER.system_file(self.driver, self.deadline)
        with self.assertRaisesRegex(BUILDER.Refused, "^deadline$"):
            BUILDER.system_file(self.driver, 1)

    def test_metadata_capture_limits_refuse_symlink_and_overflow(self):
        path = self.scratch / "record"
        path.write_bytes(b"12345")
        with self.assertRaises(BUILDER.Refused):
            BUILDER.guard_metadata(((path, 4),))
        path.unlink(); path.symlink_to(self.driver)
        with self.assertRaises(BUILDER.Refused):
            BUILDER.guard_metadata(((path, 100),))

    def test_unavailable_versions_wrong_family_or_target_refuse_before_linking(self):
        variants = (("--version", b""), ("--version", b"gcc (GCC)\n"),
                    ("--version", b"clang 23.1.3\n"), ("-dumpmachine", b"aarch64-linux-gnu\n"))
        for option, raw in variants:
            def invalid(argv, env, deadline, log, **kwargs):
                if argv == [str(self.driver), option]:
                    return raw
                return self.query(argv, env, deadline, log, **kwargs)
            with self.subTest(option=option, raw=raw), patch.object(BUILDER, "command", side_effect=invalid):
                with self.assertRaises(BUILDER.Refused):
                    BUILDER.prepare_tools(self.scratch, "x86_64-unknown-linux-gnu", {}, self.deadline, bytearray())


if __name__ == "__main__":
    unittest.main()
