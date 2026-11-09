"""Guarded fake-harness tests; no reserved allocation or native workload."""

from contextlib import ExitStack
import ctypes as c
import errno
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aepm.model import AepmError, canonical, digest
from aepm.private_process import DarwinBackend
from aepm.supervision import Recorder
from tests.discovery_observer import DiscoveryObserver
from tests import test_discovery_observer as fake
from tests import run_android_discovery_fixture as entry


class GuardedTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.guards.enter_context(patch("ctypes.CDLL", side_effect=AssertionError("native library forbidden")))
        self.guards.enter_context(patch.object(DarwinBackend, "__init__", side_effect=AssertionError("native backend forbidden")))
        self.guards.enter_context(patch("subprocess.Popen", side_effect=AssertionError("subprocess forbidden")))
        self.guards.enter_context(patch.object(os, "kill", side_effect=AssertionError("signal forbidden")))
        self.guards.enter_context(patch.object(os, "killpg", side_effect=AssertionError("group signal forbidden")))

    def observer(self, original=None, modes=("success",)):
        class Backend(DarwinBackend):
            def __init__(self):
                bindings = fake.FakeBindings(modes)
                self.info, self.path, self.extended, self.listing = bindings.info, bindings.path, bindings.extended, bindings.listing
                self.send = bindings.backend.send

        calls = []
        returned = (0, 1, "", b"SYNTHETIC_SECRET_OUTPUT")

        def run(*args, **kwargs):
            calls.append((args, kwargs, c.get_errno()))
            Backend().capture(424242)
            c.set_errno(errno.EBUSY)
            return returned

        contextual = SimpleNamespace(run=original or run)
        harness = SimpleNamespace(pack=Mock(return_value=dict(entry.EXPECTED)))
        observer = entry.AndroidObserver(harness, contextual, Backend, Recorder, DiscoveryObserver, self.root, "a" * 64)
        self.addCleanup(observer.close)
        observer.start()
        return observer, contextual, harness, Backend, calls, returned


class AndroidObserverTests(GuardedTests):
    def test_zero_attached_backends_cannot_claim_complete_observation(self):
        observer, _, _, _, _, _ = self.observer()
        self.assertFalse(observer.document()["observationComplete"])
        binding = {"accepted": True}
        observer.persist_final(binding)
        self.assertFalse(binding["accepted"])
        document = json.loads((self.root / "final.json").read_bytes())
        self.assertFalse(document["observationComplete"])
        self.assertFalse(document["harness"]["accepted"])

    def test_setup_validation_and_selected_ordinals(self):
        observer, contextual, _, backend, calls, returned = self.observer()
        backend().capture(424242)
        arguments = (["SYNTHETIC_SECRET_ARGUMENT"], object(), {"secret": "SYNTHETIC_SECRET_ENV"}, 900, 100)
        for index in range(4):
            keywords = {"diagnostics": Recorder()} if index >= 2 else {}
            c.set_errno(errno.ENOENT)
            self.assertIs(contextual.run(*arguments, **keywords), returned)
            self.assertEqual(c.get_errno(), errno.EBUSY)
            self.assertEqual(calls[-1], (arguments, keywords, errno.ENOENT))
        document = observer.document()
        self.assertEqual([(item["globalRun"], item["selectedStep"], item["scope"]) for item in document["backends"]],
                         [(None, None, "setup"), (0, None, "validation-discovery"), (1, None, "validation-discovery"),
                          (2, 0, "preparation"), (3, 1, "main")])
        self.assertFalse(document["constructorChecksObserved"])
        self.assertTrue(document["observationComplete"])
        self.assertNotIn(b"SYNTHETIC_SECRET", entry.encoded(document))

    def test_checkpoint_failure_preserves_return_and_errno(self):
        observer, contextual, _, _, _, returned = self.observer()
        def broken(*_args):
            c.set_errno(errno.EFAULT)
            raise OSError("SYNTHETIC_SECRET_DISK")
        with patch.object(entry, "atomic", side_effect=broken):
            self.assertIs(contextual.run("argument"), returned)
            self.assertEqual(c.get_errno(), errno.EBUSY)
        with patch.object(observer, "checkpoint", side_effect=broken):
            self.assertIs(contextual.run("argument"), returned)
            self.assertEqual(c.get_errno(), errno.EBUSY)
        self.assertTrue(observer.incomplete)

    def test_checkpoint_failure_preserves_original_exception(self):
        original = OSError(errno.EIO, "SYNTHETIC_SECRET_ORIGINAL")
        def run(*args, **kwargs):
            c.set_errno(errno.EINTR)
            raise original
        observer, contextual, _, _, _, _ = self.observer(original=run)
        with patch.object(observer, "checkpoint", side_effect=RuntimeError("checkpoint")):
            with self.assertRaises(OSError) as caught:
                contextual.run("argument", diagnostics=Recorder())
            self.assertIs(caught.exception, original)
            self.assertEqual(c.get_errno(), errno.EINTR)
        self.assertEqual(observer.active, 0)

    def test_constructor_gap_is_explicit(self):
        class Broken:
            def __init__(self):
                c.set_errno(errno.EACCES)
                raise OSError("constructor")
        contextual = SimpleNamespace(run=Mock())
        harness = SimpleNamespace(pack=Mock())
        observer = entry.AndroidObserver(harness, contextual, Broken, Recorder, DiscoveryObserver, self.root, "a" * 64)
        observer.start()
        try:
            with self.assertRaises(OSError):
                Broken()
            self.assertEqual(c.get_errno(), errno.EACCES)
            self.assertEqual(observer.errors[0]["phase"], "constructor-gap")
            self.assertFalse(observer.document()["observationComplete"])
        finally:
            observer.close()

    def test_archive_mismatch_stops_before_signing_authorization(self):
        observer, _, harness, _, _, _ = self.observer()
        for key in entry.EXPECTED:
            calls = []
            def pack(*args, **kwargs):
                calls.append("pack")
                c.set_errno(errno.EBUSY)
                return {**entry.EXPECTED, key: "changed"}
            observer.original_pack = pack
            with self.subTest(key=key), self.assertRaises(ValueError):
                harness.pack("source", "store")
                calls.extend(["sign", "authorize"])
            self.assertEqual(calls, ["pack"])
            self.assertEqual(c.get_errno(), errno.EBUSY)

    def test_caps_and_error_strings_are_bounded(self):
        observer, contextual, _, _, _, _ = self.observer()
        for _ in range(66):
            contextual.run("argument")
        for index in range(40):
            observer.error(str(index) + "x" * 1000, RuntimeError("SYNTHETIC_SECRET"))
        document = observer.document()
        self.assertEqual(len(document["backends"]), 32)
        self.assertEqual(len(document["runs"]), 64)
        self.assertLessEqual(len(document["errors"]), 32)
        self.assertTrue(document["errorsCapped"])
        self.assertFalse(document["observationComplete"])
        self.assertTrue(all(len(error["phase"]) <= 64 for error in document["errors"]))
        self.assertLessEqual(len(entry.encoded(document)), entry.LIMIT)

    def test_detach_waits_for_return_and_failure_keeps_first_branch(self):
        observer, contextual, _, _, _, _ = self.observer(modes=("path-race",))
        with self.assertRaises(AepmError):
            contextual.run("argument", diagnostics=Recorder())
        first = observer.document()["backends"][0]["detail"]["firstFailure"]
        self.assertEqual(first["location"], "private-process-discovery")
        attached = observer.backends[0][1]
        observer.active = 1
        with patch.object(attached, "__exit__", side_effect=OSError("detach")) as detach:
            observer.close()
            detach.assert_not_called()
            observer.active = 0
            observer.close()
            detach.assert_called_once()
        binding = {"accepted": True}
        with patch.object(entry, "atomic", side_effect=OSError("persist")), patch("builtins.print") as output:
            observer.persist_final(binding)
        self.assertFalse(binding["accepted"])
        self.assertIn('"evidencePersistenceFailed": true', output.call_args.args[0])
        self.assertEqual(observer.document()["backends"][0]["detail"]["firstFailure"], first)
        attached.__exit__(None, None, None)


class AndroidInventoryTests(GuardedTests):
    def test_normal_result_index_and_blobs_are_only_read_and_validated(self):
        check = self.root / "check"
        logs = check / "focused-evidence/logs"
        logs.mkdir(parents=True)
        suite = {"package": entry.EXPECTED["digest"], "id": "android-media"}
        output = b"opaque ordinary output"
        (logs / (digest(output) + ".log")).write_bytes(output)
        command = {"step": 0, "preparation": False, "seconds": 1, "exitCode": 0,
                   "reason": "", "logDigest": digest(output)}
        recorder = Recorder()
        recorder.finish(0, "", True, True, True)
        raw = canonical(recorder.document(suite, 0, False))
        diagnostic = logs / (digest(raw) + ".log")
        diagnostic.write_bytes(raw)
        index = canonical([command, {**command, "step": "supervisor-v1/0", "seconds": 0, "logDigest": digest(raw)}])
        (logs / (digest(index) + ".json")).write_bytes(index)
        focused = {"ref": dict(entry.EXPECTED), "result": {**suite, "logDigest": digest(index)}, "accepted": False}
        (check / "focused-result.json").write_bytes(canonical(focused))
        before = {path: path.read_bytes() for path in check.rglob("*") if path.is_file()}
        binding = entry.harness_evidence(check)
        self.assertFalse(binding["harnessAccepted"])
        self.assertEqual(binding["indexDigest"], digest(index))
        self.assertEqual(before, {path: path.read_bytes() for path in check.rglob("*") if path.is_file()})
        diagnostic.write_bytes(b"changed")
        with self.assertRaises(AepmError):
            entry.harness_evidence(check)

    def inventory(self):
        root, originals = self.root / "inputs", self.root / "originals"
        root.mkdir()
        originals.mkdir()
        (root / "installer").mkdir()
        (root / "android").mkdir()
        java = self.root / "java/bin/java"
        java.parent.mkdir(parents=True)
        java.write_bytes(b"java")
        java.chmod(0o755)
        context = {"resources": [{"id": "androidJavaHome", "path": str(java.parent.parent)}]}
        files = []
        for index, (name, content) in enumerate((("installer/module.py", b"source"),
                                                ("android/input", b"android"), ("android-context.json", entry.encoded(context)))):
            original, copied = originals / str(index), root / name
            original.write_bytes(content)
            copied.write_bytes(content)
            files.append({"path": name, "source": str(original), "sha256": entry.sha(copied),
                          "mode": stat.S_IMODE(copied.stat().st_mode)})
        python = self.root / "python"
        python.write_bytes(b"interpreter")
        python.chmod(0o755)
        alias = self.root / "python3"
        alias.symlink_to("python")
        node = self.root / "node"
        node.write_bytes(b"node")
        node.chmod(0o755)
        bindings = {name: {"alias": str(candidate), "canonicalPath": str(target), "sha256": entry.sha(target),
                           "mode": 0o755, "links": links}
                    for name, candidate, target, links in (
                        ("python3", alias, python, [{"path": str(alias), "target": "python"}]),
                        ("node", node, node, []), ("java", java, java, []))}
        context_digest = entry.sha(root / "android-context.json")
        self.guards.enter_context(patch.object(entry, "CONTEXT_DIGEST", context_digest))
        self.guards.enter_context(patch.object(entry.sys, "executable", str(python)))
        value = {"format": 2, "files": files, "launchPath": [str(self.root), *os.defpath.split(os.pathsep)], "toolBindings": bindings,
                 "directories": [{"path": name, "mode": stat.S_IMODE((root / name).stat().st_mode)}
                                 for name in (".", "installer", "android")],
                 "python": {"path": str(python), "sha256": entry.sha(python), "mode": 0o755, "version": "3.12.8"},
                 "androidSourceSnapshotDigest": entry.SOURCE_DIGEST, "androidContextDigest": context_digest,
                 "androidExpectedPackageDigest": entry.EXPECTED["digest"]}
        path = root / "inventory.json"
        path.write_bytes(entry.encoded(value))
        return path, entry.sha(path), self.root / "output"

    def test_exact_membership_modes_sources_and_occupied_output(self):
        path, identifier, out = self.inventory()
        entry.inventory_check(path, identifier, out)
        self.assertFalse(out.exists())
        out.mkdir()
        with self.assertRaisesRegex(ValueError, "occupied output"):
            entry.inventory_check(path, identifier, out)
        out.rmdir()
        extra = path.parent / "extra"
        extra.write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "membership drift"):
            entry.inventory_check(path, identifier, out)
        extra.unlink()
        copied = path.parent / "android/input"
        copied.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "mode drift"):
            entry.inventory_check(path, identifier, out)

    def test_source_inventory_and_context_drift_refused_before_work(self):
        path, identifier, out = self.inventory()
        with self.assertRaisesRegex(ValueError, "inventory drift"):
            entry.inventory_check(path, "0" * 64, out)
        copied = path.parent / "android/input"
        copied.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "file drift"):
            entry.inventory_check(path, identifier, out)
        self.assertFalse(out.exists())

    def test_resource_drift_blocks_workload_preparation(self):
        context = self.root / "android-context.json"
        context.write_text(json.dumps({"resources": [{"id": "fixture"}]}))
        source_snapshot = []
        with patch("tests.run_android_component_fixture.inputs") as inputs, \
                patch("aepm.io.snapshot", return_value=source_snapshot), \
                patch.object(entry, "SOURCE_DIGEST", digest(canonical(source_snapshot))), \
                patch("aepm.environment.validate_resource", side_effect=AepmError("resource-changed", "fixture")), \
                patch("tests.run_android_component_fixture.check", side_effect=AssertionError("workload forbidden")) as check:
            with self.assertRaises(AepmError):
                entry.workload_inputs(self.root, self.root / "absent-check")
            inputs.assert_called_once()
            check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
