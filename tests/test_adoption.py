"""Bounded adoption of a run-started launchd Xcode service; fake backend, no launches or real signals."""

import json
import os
from pathlib import Path
import signal
import time
from unittest.mock import Mock, patch

from aepm import contextual, private_process, update, verification
from aepm.supervision import Recorder, validate_document, validate_log_index
from aepm.model import AepmError
from aepm.private_process import Identity, PrivateScope, adoption_root, enroll_root
from tests.test_capture_race import Guarded
from tests.test_private_process import FakeBackend


class Stubborn(FakeBackend):
    """Signals are recorded but the target never exits."""

    def terminate(self, record, number):
        self.signals.append((record.key, number))


class AdoptionTests(Guarded):
    def setUp(self):
        super().setUp()
        for name, value in (("_WINDOWS", []), ("_WINDOWS_FULL", False)):
            guard = patch.object(private_process, name, value)
            guard.start()
            self.addCleanup(guard.stop)
        self.xcode = self.root / "Xcode.app/Contents"
        self.daemon_path = self.xcode / "Developer/usr/bin/ibtoold"
        self.daemon_path.parent.mkdir(parents=True)
        self.daemon_path.write_bytes(b"daemon")
        self.anchor = adoption_root(self.xcode)
        self.roots = []

    def private_root(self, name):
        self.roots.append(name)
        root = self.root / ("%s-%d" % (name, len(self.roots)))
        (root / "root/ios").mkdir(parents=True)
        root.chmod(0o700)
        return root

    def build(self, backend, root, anchor="default"):
        with patch("aepm.private_process.DarwinBackend", return_value=backend), \
                patch("aepm.private_process.LinuxBackend", return_value=backend):
            scope = PrivateScope(root, adoption_root=self.anchor if anchor == "default" else anchor)
        self.addCleanup(scope.close)
        return scope

    def daemon(self, started_ns, parent=1, executable="default", key=7000):
        executable = str(self.daemon_path) if executable == "default" else executable
        return Identity(7000, key, os.geteuid(), parent, 7000, 2, executable, "/", started_ns=started_ns)

    def earlier_step(self):
        """A completed step whose window contains the daemon start; returns that start time."""
        backend = FakeBackend({})
        scope = self.build(backend, self.private_root("catalyst"))
        started = time.time_ns()
        time.sleep(.002)
        scope.bind(100)
        self.assertTrue(scope.finish(time.monotonic() + .3))
        scope.close()
        return started

    def later_step(self, record, backend_type=FakeBackend, anchor="default"):
        root = self.private_root("phone")
        backend = backend_type({7000: record})
        scope = self.build(backend, root, anchor)
        scope.bind(300)
        backend.records[7000].cwd = str(root / "root/ios")
        return backend, scope, root

    def assert_conflict(self, record, **options):
        backend, scope, root = self.later_step(record, **options)
        with self.assertRaises(AepmError) as caught:
            scope.scan(force=True)
        self.assertEqual((caught.exception.code, caught.exception.path), ("cleanup-failed", "private-process-conflict"))
        self.assertEqual(backend.signals, [])
        value = json.loads((root / "conflict-1.json").read_text())
        self.assertNotIn("adopted", value)
        return value

    def test_positive_adopted_terminated_and_recorded(self):
        started = self.earlier_step()
        backend, scope, root = self.later_step(self.daemon(started))
        scope.scan(force=True)
        self.assertIn(7000, scope.owned)
        self.assertTrue(scope.finish(time.monotonic() + 1))
        self.assertEqual(backend.signals, [(7000, signal.SIGTERM)])
        value = json.loads((root / "conflict-1.json").read_text())
        self.assertEqual((value["adopted"], value["executableRelative"], value["adoptionRoot"], value["windowIndex"],
                          value["launchdParent"], value["cwdRelative"]),
                         (True, "Developer/usr/bin/ibtoold", str(self.anchor), 0, True, "root/ios"))

    def test_repeated_scans_record_once_and_later_conflict_still_records(self):
        started = self.earlier_step()
        backend, scope, root = self.later_step(self.daemon(started))
        for _ in range(5):
            scope.scan(force=True)
        self.assertEqual(sorted(path.name for path in root.glob("conflict-*.json")), ["conflict-1.json"])
        backend.records[8000] = Identity(8000, 8000, os.geteuid(), 4242, 8000, 2, "/outside/other", str(root / "root"),
                                         started_ns=1)
        scope.baseline.add(8000)
        with self.assertRaises(AepmError) as caught:
            scope.scan(force=True)
        self.assertEqual(caught.exception.path, "private-process-conflict")
        second = json.loads((root / "conflict-2.json").read_text())
        self.assertEqual((second["pid"], second.get("adopted")), (8000, None))
        self.assertTrue(json.loads((root / "conflict-1.json").read_text())["adopted"])

    def test_not_launchd_parent_is_conflict(self):
        self.assert_conflict(self.daemon(self.earlier_step(), parent=4242))

    def test_same_basename_outside_adoption_root_is_conflict(self):
        elsewhere = self.root / "elsewhere/ibtoold"
        elsewhere.parent.mkdir()
        elsewhere.write_bytes(b"other")
        self.assert_conflict(self.daemon(self.earlier_step(), executable=str(elsewhere)))

    def test_link_into_adoption_root_resolves_canonically(self):
        link = self.root / "linked-ibtoold"
        link.symlink_to(self.daemon_path)
        started = self.earlier_step()
        backend, scope, root = self.later_step(self.daemon(started, executable=str(link)))
        scope.scan(force=True)
        self.assertIn(7000, scope.owned)

    def test_missing_executable_is_conflict(self):
        record = self.daemon(self.earlier_step(), executable=None)
        self.assert_conflict(record)
        missing = self.daemon(self.earlier_step(), key=7001)
        missing.executable_missing = True
        missing.key = 7000
        self.assert_conflict(missing)

    def test_no_adoption_root_is_conflict(self):
        self.assert_conflict(self.daemon(self.earlier_step()), anchor=None)

    def test_start_outside_windows_or_missing_is_conflict(self):
        before = time.time_ns() - 10 ** 9
        self.earlier_step()
        between = time.time_ns()
        for started in (before, between, 0, None):
            with self.subTest(started=started):
                self.assert_conflict(self.daemon(started))

    def test_window_cap_disables_adoption(self):
        started = self.earlier_step()
        with patch.object(private_process, "_WINDOWS_FULL", True):
            self.assert_conflict(self.daemon(started))

    def test_constructor_and_enroll_sites_stay_conflicts(self):
        started = self.earlier_step()
        root = self.private_root("phone")
        inside = self.daemon(started)
        inside.cwd = str(root / "root/ios")
        with self.assertRaises(AepmError) as caught:
            enroll_root(root, backend=FakeBackend({7000: inside}))
        self.assertEqual(caught.exception.path, "private-process-conflict")
        root2 = self.private_root("phone2")
        enroll_root(root2, backend=FakeBackend({7000: self.daemon(started)}))
        inside2 = self.daemon(started)
        inside2.cwd = str(root2)
        with self.assertRaises(AepmError) as caught:
            self.build(FakeBackend({7000: inside2}), root2)
        self.assertEqual(caught.exception.path, "private-process-conflict")

    def test_reused_number_never_signaled(self):
        started = self.earlier_step()
        backend, scope, root = self.later_step(self.daemon(started))
        scope.scan(force=True)
        backend.records[7000] = Identity(7000, 9999, os.geteuid(), 1, 9999, 2, "/outside/other", "/outside", started_ns=1)
        self.assertTrue(scope.finish(time.monotonic() + 1))
        self.assertEqual(backend.signals, [])
        self.assertNotIn(9999, scope.owned)

    def test_adopted_target_live_at_deadline_fails_closed(self):
        started = self.earlier_step()
        backend, scope, root = self.later_step(self.daemon(started), backend_type=Stubborn)
        scope.scan(force=True)
        self.assertFalse(scope.finish(time.monotonic() + .8))
        self.assertFalse(scope.completed)
        self.assertIn((7000, signal.SIGKILL), backend.signals)


class AdoptionLogTests(AdoptionTests):
    def test_ninth_adoption_in_one_step_is_conflict(self):
        started = self.earlier_step()
        root = self.private_root("phone")
        records = {7000 + index: Identity(7000 + index, 7000 + index, os.geteuid(), 1, 7000 + index, 2,
                                          str(self.daemon_path), "/", started_ns=started) for index in range(9)}
        backend = FakeBackend(records)
        scope = self.build(backend, root)
        scope.bind(300)
        for record in backend.records.values():
            record.cwd = str(root / "root/ios")
        with self.assertRaises(AepmError) as caught:
            scope.scan(force=True)
        self.assertEqual(caught.exception.path, "private-process-conflict")
        self.assertEqual(len(scope.adopted), 8)

    def execute_step(self, started, adopt):
        self.roots.append("context")
        private = self.root / ("context-%d" % len(self.roots))
        private.mkdir(mode=0o700)
        workspace = Mock(preserve=False)
        workspace.__enter__ = Mock(return_value=private)
        workspace.__exit__ = Mock(return_value=False)
        source = self.root / ("source-%d" % len(self.roots))
        source.mkdir()
        suite = {"package": "a" * 64, "id": "apple", "scope": "platform", "root": "package", "argv": ["fixture"],
                 "cwd": ".", "prepare": [], "tools": {}, "fixtures": [], "locks": [], "network": False,
                 "timeoutSeconds": 30, "requirements": [], "execution": {"kind": "local", "simulation": False,
                 "operations": [], "settings": [], "secrets": [], "resources": [], "assertions": [], "cleanup": None}}
        execution = Mock(run_id="fixture", authorization=None)
        execution.check_time.return_value = None
        execution.prepare.return_value = ("local", {"settings": {}, "operations": [], "simulationKind": None}, [], [], {})

        def run(argv, cwd, environment, timeout, limit, *, diagnostics=None, adoption_root=None, **_):
            backend = FakeBackend({7000: self.daemon(started)})
            with patch("aepm.private_process.DarwinBackend", return_value=backend):
                scope = PrivateScope(environment["AEPM_PRIVATE_ROOT"], diagnostics=diagnostics, adoption_root=adoption_root)
            try:
                scope.bind(300)
                if adopt:
                    backend.records[7000].cwd = str(Path(environment["AEPM_PRIVATE_ROOT"]) / "root")
                scope.scan(force=True)
                cleaned = scope.finish(time.monotonic() + 1)
            finally:
                scope.close()
            diagnostics.stopped("exit-observation", "natural-exit", exit_code=0)
            diagnostics.finish(0, "", True, cleaned, True, scope)
            return 0, 1, "", b""

        logs = self.root / ("logs-%d" % len(self.roots))
        with patch.object(contextual, "VerificationDirectory", return_value=workspace), \
                patch.object(contextual, "tool_environment", side_effect=lambda home, *a, **k: {"PATH": "/usr/bin",
                             "AEPM_PRIVATE_ROOT": str(home.parent)}), \
                patch.object(contextual, "tool_versions", return_value={}), \
                patch.object(contextual, "prerequisites", return_value=[]), \
                patch.object(contextual, "resolve_command", side_effect=lambda argv, *a, **k: argv), \
                patch.object(contextual, "run", side_effect=run):
            result, _ = contextual.execute(suite, source, False, logs, execution,
                                           adoption_root=self.anchor if adopt else None)
        import shutil
        shutil.rmtree(private)
        self.assertFalse(private.exists())
        events = json.loads((logs / (result["logDigest"] + ".json")).read_text())
        [path] = validate_log_index(suite, events, logs)
        return result, json.loads(path.read_text())

    def test_clean_step_adoption_survives_root_deletion_in_log(self):
        result, document = self.execute_step(self.earlier_step(), adopt=True)
        self.assertEqual((result["status"], result["reason"]), ("passed", ""))
        self.assertEqual(document["adoptions"], [{"uniqueIdentity": 7000, "generation": 0,
                                                  "executableRelative": "Developer/usr/bin/ibtoold", "windowIndex": 0}])
        self.assertFalse(document["recorderFailed"])

    def test_no_adoption_root_emits_no_slot(self):
        result, document = self.execute_step(self.earlier_step(), adopt=False)
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("adoptions", document)


class AdoptionSlotTests(Guarded):
    suite = {"package": "a" * 64, "id": "fixture"}

    def document(self, adoptions="absent"):
        recorder = Recorder()
        recorder.finish(0, "", True, True, True)
        value = recorder.document(self.suite, 0, False)
        if adoptions != "absent":
            value["adoptions"] = adoptions
        return value

    def check(self, value):
        validate_document(value, self.suite, {"preparation": False, "exitCode": 0, "reason": ""}, 0)

    def test_valid_with_and_without_adoptions(self):
        self.check(self.document())
        entry = {"uniqueIdentity": 1, "generation": 2, "executableRelative": "Developer/usr/bin/ibtoold", "windowIndex": 4095}
        self.check(self.document([entry] * 8))

    def test_malformed_slots_rejected(self):
        good = {"uniqueIdentity": 1, "generation": 2, "executableRelative": "Developer/usr/bin/ibtoold", "windowIndex": 0}
        cases = [[], [good] * 9, [{**good, "extra": 1}], [{key: good[key] for key in good if key != "generation"}],
                 [{**good, "executableRelative": "/Developer/usr/bin/ibtoold"}],
                 [{**good, "executableRelative": "Developer/../ibtoold"}], [{**good, "executableRelative": "./ibtoold"}],
                 [{**good, "executableRelative": "a" * 257}], [{**good, "executableRelative": ""}],
                 [{**good, "windowIndex": 4096}], [{**good, "windowIndex": -1}], [{**good, "windowIndex": True}],
                 [{**good, "uniqueIdentity": 2 ** 53}], [{**good, "generation": 2 ** 32}], {"not": "a list"}]
        for index, adoptions in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(AepmError):
                self.check(self.document(adoptions))

    def test_recorder_bounds_and_failure_never_raise(self):
        recorder = Recorder()
        for index in range(9):
            recorder.adopted(index, 1, "Developer/usr/bin/ibtoold", 0)
        self.assertEqual(len(recorder.adoptions), 8)
        self.assertTrue(recorder.failed)
        bad = Recorder()
        bad.adopted(1, 1, "/absolute", 0)
        self.assertEqual(bad.adoptions, [])
        self.assertTrue(bad.failed)


class AdoptionRootTests(Guarded):
    def test_validator(self):
        self.assertIsNone(adoption_root(None))
        self.assertEqual(adoption_root(self.root), self.root.resolve())
        target = self.root / "real"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target)
        (self.root / "file").write_text("x")
        for value in ("relative/path", str(self.root / "absent"), str(self.root / "file"), str(link / "."), str(link), 42):
            with self.subTest(value=value), self.assertRaises(AepmError) as caught:
                adoption_root(value)
            self.assertEqual((caught.exception.code, caught.exception.path), ("adoption-root-invalid", "adoptionRoot"))

    def test_entry_points_validate_and_propose_forwards(self):
        for call in (lambda: verification.verify_application(self.root, self.root / "p", True, adoption_root="relative"),
                     lambda: verification.review_package({}, self.root, self.root / "p", True, adoption_root="relative"),
                     lambda: update.propose(self.root, {}, self.root, self.root / "p", True, adoption_root="relative")):
            with self.assertRaises(AepmError) as caught:
                call()
            self.assertEqual(caught.exception.code, "adoption-root-invalid")
        source = Path(update.__file__).read_text()
        self.assertIn("adoption_root=adoption_root,", source[source.index("report = verify_application(stage"):][:400])

    def test_make_report_forwards_to_ordinary_and_contextual(self):
        seen = []
        suites = [{"package": "a" * 64, "id": "ordinary", "root": "package", "scope": "platform", "requirements": []},
                  {"package": "a" * 64, "id": "contextual", "root": "package", "scope": "platform", "requirements": [],
                   "execution": {"assertions": [], "resources": []}}]
        result = {"package": "a" * 64, "scope": "platform", "status": "blocked", "exitCode": None, "seconds": 0,
                  "reason": "tool-unavailable", "logDigest": "0" * 64}
        execution = Mock()
        execution.publish.side_effect = lambda report, records: report
        with patch("aepm.trust.load_policy", return_value={"trustedExecution": ["a" * 64]}), \
                patch.object(verification, "declarations", return_value=suites), \
                patch("aepm.authorization.bindings", return_value={}), \
                patch("aepm.environment.Execution", return_value=execution), \
                patch.object(verification, "execute_suite",
                             side_effect=lambda *a, **k: seen.append(("ordinary", k.get("adoption_root"))) or {**result, "id": "ordinary"}), \
                patch("aepm.contextual.execute",
                      side_effect=lambda *a, **k: seen.append(("contextual", k.get("adoption_root"))) or
                      ({**result, "id": "contextual"}, {})):
            verification.make_report({"packages": [{"digest": "a" * 64, "name": "x", "version": "1.0.0", "dependencies": []}]},
                                     "", {}, {"a" * 64: self.root}, None, self.root / "p", True, False, "review",
                                     self.root / "logs", adoption_root=self.root)
        self.assertEqual(seen, [("ordinary", self.root.resolve()), ("contextual", self.root.resolve())])


if __name__ == "__main__":
    import unittest
    unittest.main()
