"""Conflict sidecar: names the process, never changes the outcome; fake backend, no launches or signals."""

import contextlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aepm import contextual, private_process
from aepm.model import AepmError
from aepm.private_process import Identity, PrivateScope, enroll_root
from aepm.supervision import Recorder
from tests.test_capture_race import Guarded
from tests.test_private_process import FakeBackend


def process(pid, cwd="/outside", executable="/outside/tools/helper", parent=1, group=999, status=2):
    return Identity(pid, pid, os.geteuid(), parent, group, status, executable, cwd, started_ns=1)


class CountingBackend(FakeBackend):
    def __init__(self, records):
        super().__init__(records)
        self.calls = 0

    def capture(self, pid, **kwargs):
        self.calls += 1
        return super().capture(pid, **kwargs)


class ConflictRecordTests(Guarded):
    def records(self):
        return sorted(path.name for path in self.root.glob("conflict-*.json"))

    def load(self, name="conflict-1.json"):
        path = self.root / name
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        return json.loads(path.read_text())

    def assert_conflict(self, action):
        with self.assertRaises(AepmError) as caught:
            action()
        self.assertEqual((caught.exception.code, caught.exception.path), ("cleanup-failed", "private-process-conflict"))

    def scan_conflict(self, backend, root=None, during=None):
        root = root or self.root
        with patch("aepm.private_process.DarwinBackend", return_value=backend), \
                patch("aepm.private_process.LinuxBackend", return_value=backend):
            scope = PrivateScope(root)
        self.addCleanup(scope.close)
        scope.bind(300)
        backend.records[200].cwd = str(root / "root/ios")
        with during() if during else contextlib.nullcontext():
            self.assert_conflict(lambda: scope.scan(force=True))
        return scope

    def test_scan_conflict_named_beside_copied_tree(self):
        (self.root / "root/ios").mkdir(parents=True)
        self.scan_conflict(FakeBackend({200: process(200)}))
        self.assertEqual(self.records(), ["conflict-1.json"])
        value = self.load()
        self.assertEqual({key: value[key] for key in ("format", "site", "pid", "uniqueIdentity", "executableBasename",
                                                      "executableInsideRoot", "cwdInsideRoot", "cwdRelative",
                                                      "parentPid", "launchdParent", "group", "scopeGroup")},
                         {"format": 1, "site": "scan", "pid": 200, "uniqueIdentity": 200, "executableBasename": "helper",
                          "executableInsideRoot": False, "cwdInsideRoot": True, "cwdRelative": "root/ios",
                          "parentPid": 1, "launchdParent": True, "group": 999, "scopeGroup": 300})
        self.assertGreaterEqual(value["atSeconds"], 0)
        self.assertIsInstance(value["startedBeforeScopeSeconds"], float)
        self.assertFalse(list((self.root / "root").rglob("conflict-*")))
        self.assertNotIn("/outside", json.dumps(value))

    def test_constructor_conflict_named(self):
        enroll_root(self.root, before_work=True, backend=FakeBackend({200: process(200)}))
        inside = process(200, cwd=str(self.root))
        self.assert_conflict(lambda: self.scope(FakeBackend({200: inside})))
        self.assertEqual(self.load()["site"], "constructor")

    def test_enroll_conflict_named(self):
        self.assert_conflict(lambda: enroll_root(self.root, before_work=False,
                                                 backend=FakeBackend({200: process(200, executable=str(self.root / "tool"))})))
        value = self.load()
        self.assertEqual((value["site"], value["executableInsideRoot"], value["scopeGroup"]), ("enroll", True, None))

    def test_existing_file_and_link_are_never_overwritten_or_followed(self):
        (self.root / "root/ios").mkdir(parents=True)
        (self.root / "conflict-1.json").write_text("kept")
        target = self.root.parent / (self.root.name + "-outside-target")
        target.write_text("untouched")
        self.addCleanup(target.unlink)
        (self.root / "conflict-2.json").symlink_to(target)
        self.scan_conflict(FakeBackend({200: process(200)}))
        self.assertEqual((self.root / "conflict-1.json").read_text(), "kept")
        self.assertEqual(target.read_text(), "untouched")
        self.assertTrue((self.root / "conflict-2.json").is_symlink())
        self.assertEqual(self.load("conflict-3.json")["site"], "scan")

    def test_cap_and_write_failure_leave_conflict_unchanged(self):
        (self.root / "root/ios").mkdir(parents=True)
        for number in range(1, 17):
            (self.root / ("conflict-%d.json" % number)).write_text("full")
        self.scan_conflict(FakeBackend({200: process(200)}))
        self.assertEqual(len(self.records()), 16)
        self.assertFalse((self.root / "conflict-17.json").exists())

    def test_os_error_skips_silently(self):
        (self.root / "root/ios").mkdir(parents=True)
        self.scan_conflict(FakeBackend({200: process(200)}),
                           during=lambda: patch.object(private_process.os, "open", side_effect=PermissionError("denied")))
        self.assertEqual(self.records(), [])

    def test_no_extra_process_queries(self):
        counts = []
        for disabled in (False, True):
            root = self.root / ("disabled" if disabled else "enabled")
            (root / "root/ios").mkdir(parents=True)
            root.chmod(0o700)
            backend = CountingBackend({200: process(200)})
            during = (lambda: patch.object(private_process, "_record_conflict", lambda *a, **k: None)) if disabled else None
            self.scan_conflict(backend, root, during)
            counts.append(backend.calls)
            self.assertEqual(backend.signals, [])
            self.assertEqual(bool(list(root.glob("conflict-*.json"))), not disabled)
        self.assertEqual(counts[0], counts[1])

    def test_clean_run_writes_nothing(self):
        scope = self.scope(FakeBackend({200: process(200)}))
        scope.bind(300)
        scope.scan(force=True)
        self.assertTrue(scope.finish(__import__("time").monotonic() + .3))
        self.assertEqual(self.records(), [])

    def test_conflict_root_retained_with_record(self):
        private = self.root / "private"
        private.mkdir(mode=0o700)
        workspace = Mock(preserve=False)
        workspace.__enter__ = Mock(return_value=private)
        workspace.__exit__ = Mock(return_value=False)
        source = self.root / "source"
        source.mkdir()
        suite = {"package": "a" * 64, "id": "apple", "scope": "platform", "root": "package", "argv": ["fixture"],
                 "cwd": ".", "prepare": [], "tools": {}, "fixtures": [], "locks": [], "network": False,
                 "timeoutSeconds": 30, "requirements": [], "execution": {"kind": "local", "simulation": False,
                 "operations": [], "settings": [], "secrets": [], "resources": [], "assertions": [], "cleanup": None}}
        execution = SimpleNamespace(check_time=lambda: None, run_id="fixture", authorization=None,
                                    prepare=lambda *_: ("local", {"settings": {}, "operations": [], "simulationKind": None}, [], [], {}))

        def run(argv, cwd, environment, timeout, limit, *, diagnostics=None, **_):
            backend = FakeBackend({200: process(200)})
            with patch("aepm.private_process.DarwinBackend", return_value=backend):
                scope = PrivateScope(environment["AEPM_PRIVATE_ROOT"])
            try:
                scope.bind(300)
                backend.records[200].cwd = str(Path(environment["AEPM_PRIVATE_ROOT"]) / "root")
                scope.scan(force=True)
            except AepmError:
                return -9, 1, "cleanup-failed", b""
            finally:
                scope.close()
            return 0, 1, "", b""

        with patch.object(contextual, "VerificationDirectory", return_value=workspace), \
                patch.object(contextual, "tool_environment", side_effect=lambda home, *a, **k: {"PATH": "/usr/bin",
                             "AEPM_PRIVATE_ROOT": str(home.parent)}), \
                patch.object(contextual, "tool_versions", return_value={}), \
                patch.object(contextual, "prerequisites", return_value=[]), \
                patch.object(contextual, "resolve_command", side_effect=lambda argv, *a, **k: argv), \
                patch.object(contextual, "run", side_effect=run):
            result, record = contextual.execute(suite, source, False, self.root / "logs", execution)
        self.assertEqual((result["status"], result["reason"]), ("failed", "cleanup-failed"))
        self.assertTrue(workspace.preserve)
        self.assertFalse(record["cleanup"]["completed"])
        value = json.loads((private / "conflict-1.json").read_text())
        self.assertEqual((value["site"], value["cwdRelative"]), ("scan", "root"))


if __name__ == "__main__":
    import unittest
    unittest.main()
