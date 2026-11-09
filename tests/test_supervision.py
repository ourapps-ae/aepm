"""Simulated diagnostic contract and supervisor observation tests."""

from copy import deepcopy
import errno
from pathlib import Path
import queue
import tempfile
import unittest
from unittest.mock import Mock, patch

from aepm.model import AepmError, canonical, digest
from aepm.supervision import Recorder, observe, supervision_step_index, validate_log_index
from aepm import process
from aepm.private_process import Identity, PrivateScope
from aepm.posix_process import ContainedProcess


class SupervisionContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.suite = {"package": "a" * 64, "id": "fixture"}

    def fixture(self, number=0):
        recorder = Recorder()
        recorder.stopped("exit-observation", "natural-exit", exit_code=0)
        recorder.finish(0, "", True, True, True)
        command = {"step": number, "preparation": False, "seconds": 1, "exitCode": 0, "reason": ""}
        document = recorder.document(self.suite, number, False)
        raw = canonical(document)
        path = self.root / (digest(raw) + ".log")
        path.write_bytes(raw)
        event = {**command, "step": "supervisor-v1/" + str(number), "seconds": 0, "logDigest": digest(raw)}
        return command, event, document, path

    def replace_document(self, event, value):
        raw = canonical(value)
        event["logDigest"] = digest(raw)
        (self.root / (digest(raw) + ".log")).write_bytes(raw)

    def test_empty_and_diagnostic_only_paths(self):
        self.assertEqual(validate_log_index(self.suite, [], self.root), ())
        command, event, _, path = self.fixture()
        command["logDigest"] = "f" * 64
        self.assertEqual(validate_log_index(self.suite, [command, event], self.root), (path,))

    def test_first_occurrence_order_and_ordinary_prefix(self):
        a, ea, _, pa = self.fixture(0)
        b, eb, _, pb = self.fixture(1)
        self.assertEqual(validate_log_index(self.suite, [a, b, ea, eb], self.root), (pa, pb))
        for events in ([a, ea, b, eb], [a, b, eb, ea], [a, ea, ea], [ea]):
            with self.subTest(events=events), self.assertRaises(AepmError):
                validate_log_index(self.suite, events, self.root)

    def test_reserved_discriminator_rejection(self):
        self.assertEqual(supervision_step_index("supervisor-v1/12"), 12)
        for step in (0, None, "cleanup", "validation-inputs"):
            self.assertIsNone(supervision_step_index(step))
        for step in ("supervisor-v2/0", "supervisor-v1/01", "supervisor-v1/-1", "supervisor-v1/", "supervisor-other"):
            with self.subTest(step=step), self.assertRaises(AepmError) as caught:
                supervision_step_index(step)
            self.assertEqual((caught.exception.code, caught.exception.path), ("result-invalid", "verification"))

    def test_missing_changed_linked_or_noncanonical_blob_rejected(self):
        command, event, document, path = self.fixture()
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(AepmError):
            validate_log_index(self.suite, [command, event], self.root)
        path.write_bytes(original + b" ")
        with self.assertRaises(AepmError):
            validate_log_index(self.suite, [command, event], self.root)
        path.unlink()
        target = self.root / "target"
        target.write_bytes(original)
        path.symlink_to(target)
        with self.assertRaises(AepmError):
            validate_log_index(self.suite, [command, event], self.root)
        raw = original + b"\n"
        event["logDigest"] = digest(raw)
        (self.root / (digest(raw) + ".log")).write_bytes(raw)
        with self.assertRaises(AepmError):
            validate_log_index(self.suite, [command, event], self.root)

    def test_schema_version_bounds_and_binding_rejected(self):
        command, event, document, _ = self.fixture()
        changes = ({"format": 2}, {"format": True}, {"extra": 1}, {"step": True},
                   {"package": "b" * 64}, {"suiteIdDigest": "c" * 64}, {"events": [None] * 65})
        for change in changes:
            value = {**deepcopy(document), **change}
            with self.subTest(change=change):
                self.replace_document(event, value)
                with self.assertRaises(AepmError):
                    validate_log_index(self.suite, [command, event], self.root)

    def test_recorder_preserves_first_cause_and_redacts_messages(self):
        recorder = Recorder()
        first = AepmError("cleanup-failed", "private-process-directory")
        recorder.fault("sample", error=first)
        recorder.stopped("sample", "exception", first)
        recorder.fault("reap", error=OSError("SECRET_MESSAGE"))
        for _ in range(100):
            recorder.event("private-scan", "failure", "failed")
        recorder.finish(-9, "cleanup-failed", True, False, True)
        document = recorder.document(self.suite, 0, False)
        self.assertTrue(document["truncated"])
        self.assertEqual(len(document["events"]), 64)
        self.assertEqual(document["firstFailure"]["observation"]["phase"], "sample")
        self.assertEqual(document["finalOutcome"]["outcome"]["exitCode"], -9)
        self.assertNotIn(b"SECRET_MESSAGE", canonical(document))
        self.assertLessEqual(len(canonical(document)), 32768)

    def test_unknown_path_and_recorder_failure_do_not_escape(self):
        recorder = Recorder()
        recorder.fault("sample", error=AepmError("cleanup-failed", "SECRET_PATH"))
        self.assertNotIn(b"SECRET_PATH", canonical(recorder.document(self.suite, 0, False)))
        with patch.object(recorder, "stopped", side_effect=RuntimeError("broken recorder")):
            observe(recorder, "stopped", "sample", "exception")
        self.assertTrue(recorder.failed)
        self.assertEqual(recorder.failure["state"], "observed")


class SimulatedRunnerObservationTests(unittest.TestCase):
    def run_fixture(self, recorder, *, fault=False, timeout=False, limit=False, reader=False, cleanup=False, exit_code=0,
                    read_error=None):
        calls = []
        instance = Mock(scope=None, stdout=Mock(), stderr=Mock())

        def sample():
            calls.append("sample")
            if fault:
                raise AepmError("cleanup-failed", "private-process-directory")

        def terminate():
            calls.append("terminate")
            return cleanup

        instance.sample_private.side_effect = sample
        instance.observe_exit.side_effect = lambda: calls.append("observe") or exit_code
        instance.terminate_tree.side_effect = terminate
        instance.reap.side_effect = lambda: calls.append("reap") or -9
        instance.close.side_effect = lambda: calls.append("close")
        messages = Mock()
        messages.get_nowait.side_effect = queue.Empty
        messages.get.side_effect = [(0, b"large" if limit else b""), (1, b"")]
        thread = Mock()
        thread.is_alive.return_value = reader

        def thread_factory(*, target, args, **_kwargs):
            if read_error is not None:
                stream, index = args

                def read(_size):
                    calls.append("read-" + str(index))
                    raise read_error if index == 0 else ValueError("SECOND_READER_SECRET")

                stream.read.side_effect = read
                instance_thread = Mock()
                instance_thread.start.side_effect = lambda: target(*args)
                instance_thread.is_alive.return_value = reader
                return instance_thread
            return thread

        with patch("aepm.posix_process.ContainedProcess", return_value=instance), \
                patch.object(process.threading, "Thread", side_effect=thread_factory), \
                patch.object(process.queue, "Queue", return_value=messages), \
                patch.object(process.time, "monotonic", return_value=1):
            result = process.run(["fixture"], Path("."), {}, 0 if timeout else 10,
                                 1 if limit else 100, diagnostics=recorder)
        return result, calls

    def test_recording_preserves_calls_and_return_tuple(self):
        for options in ({"fault": True}, {"timeout": True}, {"limit": True},
                        {"exit_code": -9}, {"cleanup": True}, {"reader": True, "cleanup": True}):
            with self.subTest(options=options):
                plain, calls = self.run_fixture(None, **options)
                recorded, observed_calls = self.run_fixture(Recorder(), **options)
                self.assertEqual(recorded, plain)
                self.assertEqual(observed_calls, calls)

    def test_first_discovery_cause_survives_cleanup_failure(self):
        recorder = Recorder()
        result, _ = self.run_fixture(recorder, fault=True)
        self.assertEqual((result[0], result[2]), (-9, "cleanup-failed"))
        self.assertEqual(recorder.stop["observation"]["phase"], "sample")
        self.assertEqual(recorder.failure["observation"]["error"]["location"], "private-process-directory")
        self.assertFalse(recorder.final["outcome"]["cleanupCompleted"])

    def test_timeout_output_limit_and_external_exit_remain_distinct(self):
        for options, expected in (({"timeout": True}, "timeout"), ({"limit": True}, "output-limit"),
                                  ({"exit_code": -9}, "natural-exit")):
            with self.subTest(expected=expected):
                recorder = Recorder()
                self.run_fixture(recorder, **options)
                self.assertEqual(recorder.stop["observation"]["kind"], expected)

    def test_successful_cleanup_does_not_erase_discovery_failure(self):
        recorder = Recorder()
        self.run_fixture(recorder, fault=True, cleanup=True)
        self.assertEqual(recorder.failure["observation"]["phase"], "sample")
        self.assertTrue(recorder.final["outcome"]["cleanupCompleted"])

    def test_natural_success_and_late_reader_failure_are_separate(self):
        recorder = Recorder()
        result, _ = self.run_fixture(recorder, reader=True, cleanup=True)
        self.assertEqual(result[2], "cleanup-failed")
        self.assertEqual(recorder.stop["observation"]["kind"], "natural-exit")
        self.assertEqual(recorder.failure["observation"]["kind"], "reader-incomplete")

    def test_reader_exception_survives_successful_joins_and_later_failure(self):
        for error, name in ((OSError(errno.EIO, "FIRST_READER_SECRET"), "OSError"),
                            (ValueError("FIRST_READER_SECRET"), "other")):
            with self.subTest(error=name):
                expected, calls = self.run_fixture(None, read_error=error, fault=True)
                recorder = Recorder()
                actual, recorded_calls = self.run_fixture(recorder, read_error=error, fault=True)
                self.assertEqual(actual, expected)
                self.assertEqual(recorded_calls, calls)
                self.assertEqual(actual[2], "cleanup-failed")
                first = recorder.failure["observation"]
                self.assertEqual((first["phase"], first["kind"], first["error"]["class"]),
                                 ("reader-join", "exception", name))
                self.assertEqual(first["error"]["number"], errno.EIO if name == "OSError" else None)
                joins = [event for event in recorder.events if event["phase"] == "reader-join"]
                self.assertEqual([(event["action"], event["outcome"]) for event in joins],
                                 [("enter", "attempted"), ("return", "succeeded")] * 2)
                self.assertTrue(recorder.final["outcome"]["readersJoined"])
                self.assertNotIn(b"READER_SECRET", canonical(recorder.document({"package": "a" * 64, "id": "fixture"}, 0, False)))

    def test_each_incomplete_reader_join_is_recorded(self):
        recorder = Recorder()
        self.run_fixture(recorder, reader=True, cleanup=True)
        joins = [event for event in recorder.events if event["phase"] == "reader-join"]
        self.assertEqual([(event["action"], event["outcome"]) for event in joins],
                         [("enter", "attempted"), ("return", "failed")] * 2)


class SimulatedCleanupObservationTests(unittest.TestCase):
    def test_final_outcome_cannot_replace_observed_failure(self):
        recorder = Recorder()
        recorder.finish(-9, "cleanup-failed", True, False, False)
        original = deepcopy(recorder.final)
        recorder.finish(0, "", True, True, True)
        self.assertEqual(recorder.final, original)

    def test_private_scan_refresh_signal_and_deadline_are_distinct(self):
        for failure, phase in (("scan", "private-scan"), ("refresh", "private-refresh"),
                               ("signal", "private-signal"), ("deadline", "private-scan")):
            with self.subTest(failure=failure):
                recorder = Recorder()
                scope = PrivateScope.__new__(PrivateScope)
                scope.diagnostics = recorder
                scope.failed = scope.completed = scope.unresolved = scope.root_exited = False
                record = Identity(123, 701, 501, 1, 123, 2)
                scope.owned = {701: record}
                scope.backend = Mock()
                scope.backend.refresh.return_value = record
                scope._scan = Mock()
                if failure == "scan":
                    scope._scan.side_effect = AepmError("cleanup-failed", "private-process-directory")
                if failure == "refresh":
                    scope.backend.refresh.side_effect = AepmError("cleanup-failed", "private-process-identity")
                if failure == "signal":
                    scope.backend.terminate.side_effect = AepmError("cleanup-failed", "private-process-signal")
                clock = [0.0]

                def sleep(seconds):
                    clock[0] += seconds

                with patch("aepm.private_process.time.monotonic", side_effect=lambda: clock[0]), \
                        patch("aepm.private_process.time.sleep", side_effect=sleep):
                    self.assertFalse(scope.finish(.2))
                self.assertEqual(recorder.failure["observation"]["phase"], phase)
                self.assertEqual(recorder.failure["observation"]["kind"],
                                 "cleanup-deadline" if failure == "deadline" else "exception")

    def test_termination_exception_precedes_reap_failure(self):
        recorder = Recorder()
        instance = ContainedProcess.__new__(ContainedProcess)
        instance.diagnostics = recorder
        instance.signaling_finished = instance.cleaned = False
        instance.observe_exit = Mock(side_effect=AepmError("cleanup-failed", "child-ownership"))
        self.assertFalse(instance.terminate_tree())
        self.assertTrue(instance.signaling_finished)
        recorder.fault("reap", error=OSError("later failure"))
        self.assertEqual(recorder.failure["observation"]["phase"], "group-cleanup")
        self.assertEqual(recorder.failure["observation"]["error"]["location"], "child-ownership")

    def test_unavailable_final_slot_preserves_first_cause(self):
        recorder = Recorder()
        recorder.fault("sample", error=AepmError("cleanup-failed", "private-process-path"))
        recorder.finish(0, "", True, True, True)
        recorder.final["outcome"]["privateFailed"] = "invalid"
        document = recorder.document({"package": "a" * 64, "id": "fixture"}, 0, False)
        self.assertEqual(document["firstFailure"]["state"], "observed")
        self.assertEqual(document["finalOutcome"]["state"], "unavailable")
        self.assertTrue(document["recorderFailed"])


if __name__ == "__main__":
    unittest.main()
