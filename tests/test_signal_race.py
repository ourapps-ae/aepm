"""Signal races on exiting owned processes; fake backend, controlled clock, no launches or real signals."""

import errno
import os
import queue
import signal
from unittest.mock import Mock, patch

from aepm import process
from aepm.model import AepmError
from aepm.private_process import AuditToken, DarwinBackend, Identity, SignalRace
from aepm.supervision import Recorder
from tests.test_capture_race import Clock, Guarded
from tests.test_private_process import FakeBackend


def owned(pid=210, key=7210, group=300, status=2):
    return Identity(pid, key, os.geteuid(), 1, group, status, "/outside/program", "/outside", token=AuditToken())


class SignalBackend(FakeBackend):
    """FakeBackend discovery with the real DarwinBackend.terminate retry loop."""

    terminate = DarwinBackend.terminate

    def __init__(self, records, results):
        super().__init__(records)
        self.results = list(results)
        self.sends = []

    def send(self, _token, number):
        self.sends.append(number)
        result = self.results.pop(0) if self.results else 0
        return result() if callable(result) else result


class SignalRaceTests(Guarded):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        guard = patch("aepm.private_process.time", self.clock)
        guard.start()
        self.addCleanup(guard.stop)

    def scope_with_target(self, results, recorder=None):
        backend = SignalBackend({}, results)
        scope = self.scope(backend, recorder)
        scope.bind(300)
        backend.records[210] = owned()
        scope.scan(force=True)
        self.assertIn(7210, scope.owned)
        return backend, scope

    def exit_target(self, backend, result=errno.ESRCH):
        def change():
            backend.records[210].status = 5
            return result
        return change

    def test_direct_three_esrch_while_live_raises_signal_race_with_errno(self):
        backend = SignalBackend({210: owned()}, [errno.ESRCH] * 3)
        with self.assertRaises(SignalRace) as caught:
            backend.terminate(owned(), signal.SIGKILL)
        self.assertEqual((caught.exception.code, caught.exception.path, caught.exception.errno),
                         ("cleanup-failed", "private-process-signal", errno.ESRCH))
        self.assertEqual(len(backend.sends), 3)

    def test_exiting_target_completes(self):
        recorder = Recorder()
        backend, scope = self.scope_with_target([], recorder)
        backend.results = [errno.ESRCH, errno.ESRCH, self.exit_target(backend)]
        self.assertTrue(scope.finish(self.clock.now + 5))
        self.assertFalse(scope.failed)
        self.assertEqual(len(backend.sends), 3)
        self.assertEqual(recorder.failure["state"], "not-observed")

    def test_v3_timing_two_successes_then_race_then_gone(self):
        recorder = Recorder()
        backend, scope = self.scope_with_target([], recorder)
        backend.results = [0, 0, errno.ESRCH, errno.ESRCH, errno.ESRCH]
        after = []

        def maybe_gone():
            if len(backend.sends) >= 5:
                after.append(1)
                if len(after) > 1:
                    backend.records[210].status = 5
        original = scope.backend.refresh
        scope.backend.refresh = lambda record: maybe_gone() or original(record)
        self.assertTrue(scope.finish(self.clock.now + 5))
        self.assertTrue(scope.completed)
        self.assertFalse(scope.failed)
        self.assertEqual(recorder.failure["state"], "not-observed")
        outcomes = [event["outcome"] for event in recorder.events if event["action"] == "signal"]
        self.assertEqual(outcomes, ["attempted", "succeeded"] * 2 + ["attempted", "failed"] * 3)

    def test_persistent_race_fails_at_deadline_not_sticky(self):
        recorder = Recorder()
        backend, scope = self.scope_with_target([errno.ESRCH] * 100000, recorder)
        self.assertFalse(scope.finish(self.clock.now + .5))
        self.assertFalse(scope.completed)
        self.assertFalse(scope.failed)
        observation = recorder.failure["observation"]
        self.assertEqual((observation["phase"], observation["kind"]), ("private-scan", "cleanup-deadline"))

    def test_eperm_fails_immediately_and_sticky_with_number(self):
        recorder = Recorder()
        backend, scope = self.scope_with_target([errno.EPERM], recorder)
        self.assertFalse(scope.finish(self.clock.now + .3))
        self.assertTrue(scope.failed)
        observation = recorder.failure["observation"]
        self.assertEqual((observation["phase"], observation["error"]["location"], observation["error"]["number"]),
                         ("private-signal", "private-process-signal", errno.EPERM))

    def test_mixed_esrch_esrch_eperm_is_sticky_with_number_one(self):
        recorder = Recorder()
        backend, scope = self.scope_with_target([errno.ESRCH, errno.ESRCH, errno.EPERM], recorder)
        self.assertFalse(scope.finish(self.clock.now + .3))
        self.assertTrue(scope.failed)
        self.assertEqual(backend.sends[:3], [signal.SIGTERM] * 3)
        self.assertEqual(recorder.failure["observation"]["error"]["number"], 1)

    def test_reused_number_is_target_gone_and_never_signaled(self):
        backend, scope = self.scope_with_target([])

        def reuse():
            backend.records[210] = Identity(210, 9999, os.geteuid(), 1, 999, 2, "/outside/other", "/outside",
                                            token=AuditToken())
            return errno.ESRCH
        backend.results = [reuse]
        self.assertTrue(scope.finish(self.clock.now + 5))
        self.assertEqual(len(backend.sends), 1)
        self.assertNotIn(9999, scope.owned)

    def test_gone_during_retry_loop_returns_without_raising(self):
        backend = SignalBackend({210: owned()}, [])
        target = owned()
        backend.results = [errno.ESRCH, self.exit_target(backend)]
        backend.terminate(target, signal.SIGKILL)
        self.assertEqual(len(backend.sends), 2)

    def test_grace_window_not_extended_by_races(self):
        backend, scope = self.scope_with_target([errno.ESRCH] * 100000)
        start = self.clock.now
        times = []
        original = backend.send

        def timed(token, number):
            times.append((self.clock.now, number))
            if self.clock.now - start >= .7:
                backend.records[210].status = 5
            return original(token, number)
        backend.send = timed
        self.assertTrue(scope.finish(start + 5))
        for moment, number in times:
            self.assertEqual(number, signal.SIGTERM if moment < start + .5 else signal.SIGKILL)
        self.assertIn(signal.SIGTERM, [number for _, number in times])
        self.assertIn(signal.SIGKILL, [number for _, number in times])

    def test_quiescence_needs_two_consecutive_clean_scans_after_race(self):
        backend, scope = self.scope_with_target([errno.ESRCH] * 100000)
        start = self.clock.now
        original = backend.refresh

        def scripted(record):
            iteration = round((self.clock.now - start) / .05)
            backend.records[210].status = 2 if iteration in (0, 2) else 5
            return original(record)
        backend.refresh = scripted
        self.assertTrue(scope.finish(start + 5))
        self.assertFalse(scope.failed)
        # Race at 0, clean at 1, race at 2 resets, clean at 3 and 4: completion at iteration 4, not 2 or 3.
        self.assertAlmostEqual(self.clock.now - start, .2)

    def test_end_to_end_run_with_exiting_target_completes_clean(self):
        recorder = Recorder()
        backend, scope = self.scope_with_target([], recorder)
        backend.results = [errno.ESRCH, errno.ESRCH, self.exit_target(backend)]
        cleaned = {}

        def terminate_tree():
            if "value" not in cleaned:
                cleaned["value"] = scope.finish(self.clock.now + 5)
            return cleaned["value"]

        instance = Mock(scope=scope, stdout=Mock(), stderr=Mock())
        instance.observe_exit.return_value = 0
        instance.terminate_tree.side_effect = terminate_tree
        instance.reap.return_value = 0
        messages = Mock()
        messages.get_nowait.side_effect = queue.Empty
        messages.get.side_effect = [(0, b""), (1, b"")]
        thread = Mock()
        thread.is_alive.return_value = False
        with patch("aepm.posix_process.ContainedProcess", return_value=instance), \
                patch.object(process.threading, "Thread", return_value=thread), \
                patch.object(process.queue, "Queue", return_value=messages):
            code, _, reason, _ = process.run(["fixture"], self.root, {}, 10, diagnostics=recorder)
        self.assertEqual((code, reason), (0, ""))
        self.assertEqual(recorder.failure["state"], "not-observed")
        self.assertTrue(recorder.final["outcome"]["cleanupCompleted"])
        failed = [event for event in recorder.events if event["action"] == "signal" and event["outcome"] == "failed"]
        self.assertEqual(len(failed), 3)


if __name__ == "__main__":
    import unittest
    unittest.main()
