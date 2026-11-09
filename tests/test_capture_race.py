"""Capture-race correction checks with fake bindings; no processes, signals or native calls."""

from contextlib import ExitStack
from copy import deepcopy
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import queue
import tempfile
from types import SimpleNamespace
import time
import unittest
from unittest.mock import Mock, patch

from aepm import process
from aepm.model import AepmError
from aepm.private_process import CaptureRace, DarwinBackend, Identity, PrivateScope, enroll_root
from aepm.supervision import Recorder
from tests.test_discovery_observer import FakeBindings
from tests.test_private_process import FakeBackend


class RacingBackend(FakeBackend):
    def __init__(self, records):
        super().__init__(records)
        self.races = {}

    def capture(self, pid, *, paths=True, allow_missing_executable=False):
        if paths and self.races.get(pid, 0) > 0:
            self.races[pid] -= 1
            raise CaptureRace()
        return super().capture(pid, paths=paths, allow_missing_executable=allow_missing_executable)


def unrelated(pid, group=999, status=2):
    return Identity(pid, pid, os.geteuid(), 1, group, status, "/outside/program", "/outside")


class Guarded(unittest.TestCase):
    def setUp(self):
        guards = ExitStack()
        self.addCleanup(guards.close)
        guards.enter_context(patch.object(ctypes, "CDLL", side_effect=AssertionError("native library forbidden")))
        guards.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")))
        guards.enter_context(patch.object(os, "kill", side_effect=AssertionError("signal forbidden")))
        guards.enter_context(patch.object(os, "killpg", side_effect=AssertionError("group signal forbidden")))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def scope(self, backend, recorder=None):
        with patch("aepm.private_process.DarwinBackend", return_value=backend), \
                patch("aepm.private_process.LinuxBackend", return_value=backend):
            scope = PrivateScope(self.root, diagnostics=recorder)
        self.addCleanup(scope.close)
        return scope


class BackendCaptureTests(Guarded):
    def capture(self, modes):
        fake = FakeBindings(modes)
        with patch("aepm.private_process.time.sleep", side_effect=AssertionError("no sleep")):
            try:
                return fake, fake.backend.capture(424242), None
            except AepmError as error:
                return fake, None, error

    def test_homogeneous_races_raise_capture_race_with_unchanged_code(self):
        for mode in ("path-race", "directory-race", "identity-change", "generation-change"):
            with self.subTest(mode=mode):
                fake, _, error = self.capture((mode,))
                self.assertIsInstance(error, CaptureRace)
                self.assertIsInstance(error, AepmError)
                self.assertEqual((error.code, error.path), ("cleanup-failed", "private-process-discovery"))
                outer = [call for call in fake.calls if call[0] == "identity"]
                self.assertEqual(len(outer), 4)
                fake.backend.send.assert_not_called()

    def test_exhaustion_makes_one_identity_only_query(self):
        fake, _, error = self.capture(("path-race",))
        self.assertIsInstance(error, CaptureRace)
        paths = [call for call in fake.calls if call[0] == "executable-path"]
        self.assertEqual(len(paths), 3)
        self.assertEqual(fake.calls[-1][0], "identity")

    def test_final_query_gone_or_exited_returns_existing_result(self):
        _, result, error = self.capture(("path-race", "path-race", "path-race", "gone"))
        self.assertIsNone(error)
        self.assertIsNone(result)
        _, result, error = self.capture(("directory-race", "directory-race", "directory-race", "exited"))
        self.assertIsNone(error)
        self.assertEqual(result.status, 5)

    def test_mixed_races_ending_live_raise_capture_race(self):
        _, _, error = self.capture(("path-race", "directory-race", "generation-change"))
        self.assertIsInstance(error, CaptureRace)

    def test_other_failures_keep_their_locations(self):
        for mode, location in (("path-denied", "private-process-path"), ("partial", "private-process-identity"),
                               ("info-denied", "private-process-identity"),
                               ("directory-denied", "private-process-directory"),
                               ("confirmation-denied", "private-process-identity")):
            with self.subTest(mode=mode):
                _, _, error = self.capture((mode,))
                self.assertNotIsInstance(error, CaptureRace)
                self.assertEqual((error.code, error.path), ("cleanup-failed", location))

    def test_self_check_race_stays_fail_closed(self):
        fake = FakeBindings(("path-race",))
        library = SimpleNamespace()
        for name, function in (("proc_pidinfo", fake.info), ("proc_listpids", fake.listing),
                               ("proc_pidpath_audittoken", fake.path),
                               ("proc_signal_with_audittoken", Mock(side_effect=AssertionError("signal")))):
            setattr(library, name, lambda *args, function=function: function(*args))
        setattr(library, "__proc_info_extended_id", lambda *args: fake.extended(*args))
        with patch("aepm.private_process.c.CDLL", return_value=library), self.assertRaises(AepmError) as caught:
            DarwinBackend()
        self.assertEqual((caught.exception.code, caught.exception.path), ("cleanup-failed", "private-process-discovery"))


class ScriptedBackend(FakeBackend):
    """Full captures follow a per-pid script of "race", None, an Identity or an exception, then the record."""

    def __init__(self, records, scripts=None):
        super().__init__(records)
        self.scripts = {pid: list(steps) for pid, steps in (scripts or {}).items()}
        self.full = {}

    def capture(self, pid, *, paths=True, allow_missing_executable=False):
        if not paths:
            return super().capture(pid, paths=False)
        self.full[pid] = self.full.get(pid, 0) + 1
        steps = self.scripts.get(pid)
        if steps:
            step = steps.pop(0)
            if step == "race":
                raise CaptureRace()
            if isinstance(step, BaseException):
                raise step
            return deepcopy(step)
        return super().capture(pid, paths=paths, allow_missing_executable=allow_missing_executable)


class Clock:
    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def monotonic(self):
        return self.now

    def time_ns(self):
        return int(self.now * 1e9)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class EnrollmentRecheckTests(Guarded):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        guard = patch("aepm.private_process.time", self.clock)
        guard.start()
        self.addCleanup(guard.stop)

    def enroll(self, backend):
        return enroll_root(self.root, before_work=True, backend=backend)

    def constructed(self, scripted):
        enroll_root(self.root, before_work=True, backend=FakeBackend({pid: unrelated(pid) for pid in scripted.records}))
        return self.scope(scripted)

    def assert_race(self, action):
        with self.assertRaises(AepmError) as caught:
            action()
        self.assertIsInstance(caught.exception, CaptureRace)
        self.assertEqual((caught.exception.code, caught.exception.path), ("cleanup-failed", "private-process-discovery"))

    def test_transient_race_resolves_by_full_capture_and_only_racing_pid_is_rechecked(self):
        backend = ScriptedBackend({200: unrelated(200), 201: unrelated(201)}, {200: ["race", "race"]})
        entry = self.enroll(backend)
        self.assertEqual(entry.generations.get(200), unrelated(200).generation)
        self.assertEqual(backend.full, {200: 3, 201: 1})
        self.assertEqual(self.clock.sleeps, [.05, .05])
        self.assertEqual(backend.signals, [])

    def test_resolved_in_root_candidate_still_conflicts(self):
        inside = Identity(200, 200, os.geteuid(), 1, 999, 2, "/outside/program", str(self.root))
        backend = ScriptedBackend({200: unrelated(200)}, {200: ["race", inside]})
        with self.assertRaises(AepmError) as caught:
            self.enroll(backend)
        self.assertEqual(caught.exception.path, "private-process-conflict")

    def test_resolved_gone_or_exited_behaves_as_today(self):
        gone = ScriptedBackend({200: unrelated(200)}, {200: ["race", None]})
        self.assertNotIn(200, self.enroll(gone).generations)
        root = self.root / "second"
        root.mkdir(mode=0o700)
        exited = ScriptedBackend({200: unrelated(200)}, {200: ["race", unrelated(200, status=5)]})
        self.assertIn(200, enroll_root(root, before_work=True, backend=exited).generations)

    def test_persistent_race_fails_closed_within_bound(self):
        backend = ScriptedBackend({200: unrelated(200)}, {200: ["race"] * 1000})
        self.assert_race(lambda: self.enroll(backend))
        self.assertLessEqual(sum(self.clock.sleeps), 2.0 + 1e-9)
        self.assertTrue(all(0 < value <= .05 for value in self.clock.sleeps))
        self.assertEqual(backend.full[200], len(self.clock.sleeps) + 1)
        self.assertEqual(backend.signals, [])

    def test_other_failure_during_recheck_keeps_its_location(self):
        denied = AepmError("cleanup-failed", "private-process-path")
        backend = ScriptedBackend({200: unrelated(200)}, {200: ["race", denied]})
        with self.assertRaises(AepmError) as caught:
            self.enroll(backend)
        self.assertEqual(caught.exception.path, "private-process-path")

    def test_no_race_means_no_sleep(self):
        self.enroll(ScriptedBackend({200: unrelated(200)}))
        self.assertEqual(self.clock.sleeps, [])

    def test_constructor_parity(self):
        scope = self.constructed(ScriptedBackend({200: unrelated(200)}, {200: ["race", "race"]}))
        self.assertIn(200, scope.baseline)
        self.assertEqual(scope.owned, {})
        self.assertEqual(self.clock.sleeps, [.05, .05])

    def test_constructor_resolved_in_root_candidate_conflicts(self):
        inside = Identity(200, 200, os.geteuid(), 1, 999, 2, "/outside/program", str(self.root))
        with self.assertRaises(AepmError) as caught:
            self.constructed(ScriptedBackend({200: unrelated(200)}, {200: ["race", inside]}))
        self.assertEqual(caught.exception.path, "private-process-conflict")

    def test_constructor_resolved_gone_joins_initial_gone(self):
        scope = self.constructed(ScriptedBackend({200: unrelated(200)}, {200: ["race", None]}))
        self.assertIn(200, scope.initial_gone)
        self.assertNotIn(200, scope.baseline)

    def test_constructor_persistent_race_fails_closed(self):
        backend = ScriptedBackend({200: unrelated(200)}, {200: ["race"] * 1000})
        self.assert_race(lambda: self.constructed(backend))
        self.assertLessEqual(sum(self.clock.sleeps), 2.0 + 1e-9)
        self.assertEqual(backend.signals, [])


class ScopeRaceTests(Guarded):

    def test_unrelated_race_is_unresolved_then_clean(self):
        recorder = Recorder()
        backend = RacingBackend({200: unrelated(200)})
        scope = self.scope(backend, recorder)
        scope.bind(300)
        baseline = set(scope.baseline)
        backend.records[201] = unrelated(201)
        backend.races.update({200: 1, 201: 1})
        scope.scan(force=True)
        self.assertTrue(scope.unresolved)
        self.assertFalse(scope.failed)
        self.assertEqual(scope.owned, {})
        self.assertEqual(scope.baseline, baseline)
        self.assertEqual(recorder.failure["state"], "not-observed")
        self.assertTrue(scope.finish(time.monotonic() + .5))
        self.assertEqual(backend.signals, [])

    def test_race_flag_set_for_initially_gone_pid(self):
        backend = RacingBackend({200: unrelated(200), 205: None})
        scope = self.scope(backend)
        self.assertIn(205, scope.initial_gone)
        scope.bind(300)
        backend.records[205] = unrelated(205)
        backend.races[205] = 1
        scope.scan(force=True)
        self.assertTrue(scope.unresolved)
        self.assertFalse(scope.failed)

    def test_owned_group_candidate_is_owned_after_race_and_signaled(self):
        backend = RacingBackend({})
        scope = self.scope(backend)
        scope.bind(300)
        backend.records[210] = unrelated(210, group=300)
        backend.races[210] = 1
        scope.scan(force=True)
        self.assertNotIn(210, scope.owned)
        self.assertTrue(scope.unresolved)
        scope.scan(force=True)
        self.assertIn(210, scope.owned)
        self.assertTrue(scope.finish(time.monotonic() + 1))
        self.assertIn((210, signal.SIGTERM), backend.signals)

    def test_persistent_race_fails_at_deadline_without_sticky_failure(self):
        recorder = Recorder()
        backend = RacingBackend({200: unrelated(200)})
        scope = self.scope(backend, recorder)
        scope.bind(300)
        backend.races[200] = 10000
        self.assertFalse(scope.finish(time.monotonic() + .3))
        self.assertFalse(scope.completed)
        self.assertFalse(scope.failed)
        observation = recorder.failure["observation"]
        self.assertEqual((observation["phase"], observation["kind"]), ("private-scan", "cleanup-deadline"))
        self.assertEqual(backend.signals, [])

    def test_list_rejection_still_fails(self):
        recorder = Recorder()
        backend = RacingBackend({})
        scope = self.scope(backend, recorder)
        scope.bind(300)
        backend.pids = Mock(side_effect=AepmError("cleanup-failed", "private-process-discovery"))
        self.assertFalse(scope.finish(time.monotonic() + .2))
        self.assertTrue(scope.failed)
        observation = recorder.failure["observation"]
        self.assertEqual((observation["phase"], observation["kind"]), ("private-scan", "exception"))
        self.assertEqual(observation["error"]["location"], "private-process-discovery")

    def test_race_during_bind_and_sampling_does_not_end_run(self):
        backend = RacingBackend({200: unrelated(200)})
        scope = self.scope(backend)
        backend.races[200] = 1
        scope.bind(300)
        self.assertFalse(scope.failed)
        backend.races[200] = 1
        instance = Mock(scope=scope, stdout=Mock(), stderr=Mock())
        instance.sample_private.side_effect = lambda: scope.scan(force=True)
        instance.observe_exit.return_value = 0
        instance.terminate_tree.return_value = True
        instance.reap.return_value = 0
        messages = Mock()
        messages.get_nowait.side_effect = queue.Empty
        messages.get.side_effect = [(0, b""), (1, b"")]
        thread = Mock()
        thread.is_alive.return_value = False
        with patch("aepm.posix_process.ContainedProcess", return_value=instance), \
                patch.object(process.threading, "Thread", return_value=thread), \
                patch.object(process.queue, "Queue", return_value=messages):
            code, _, reason, _ = process.run(["fixture"], self.root, {}, 10)
        self.assertEqual((code, reason), (0, ""))
        self.assertEqual(backend.races[200], 0)
        self.assertGreaterEqual(instance.sample_private.call_count, 2)
        self.assertFalse(scope.failed)
        self.assertFalse(scope.unresolved)

    def test_race_during_final_cleanup_after_exit_completes(self):
        recorder = Recorder()
        backend = RacingBackend({200: unrelated(200)})
        scope = self.scope(backend, recorder)
        scope.bind(300)
        backend.races[200] = 2
        self.assertTrue(scope.finish(time.monotonic() + 1))
        self.assertEqual(backend.races[200], 0)
        self.assertTrue(scope.completed)
        self.assertFalse(scope.failed)
        self.assertEqual(recorder.failure["state"], "not-observed")
        self.assertEqual(backend.signals, [])


if __name__ == "__main__":
    unittest.main()
