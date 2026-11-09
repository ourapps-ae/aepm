"""Failure-path tests with fake runners and no native process operations."""

from contextlib import ExitStack
import ctypes
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from aepm.private_process import DarwinBackend
from tests import run_discovery_owned_fixture as controller


class ControllerFailureTests(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.guards.enter_context(patch.object(ctypes, "CDLL", side_effect=AssertionError("native call forbidden")))
        self.guards.enter_context(patch.object(DarwinBackend, "__init__", side_effect=AssertionError("backend forbidden")))
        self.guards.enter_context(patch("subprocess.Popen", side_effect=AssertionError("child forbidden")))
        self.guards.enter_context(patch.object(os, "kill", side_effect=AssertionError("signal forbidden")))
        self.guards.enter_context(patch.object(os, "killpg", side_effect=AssertionError("group signal forbidden")))
        self.guards.enter_context(patch("aepm.process.run", side_effect=AssertionError("runner forbidden")))

    def test_release_failure_still_joins_and_retains_original_cause(self):
        root = Mock()
        release = Mock()
        root.__truediv__ = Mock(return_value=release)
        release.touch.side_effect = PermissionError("SYNTHETIC_PRIVATE_PATH")
        worker = Mock(ident=123)
        worker.is_alive.return_value = False
        summary = {"accepted": True}
        with patch.object(controller.time, "monotonic", return_value=10):
            controller.release_and_join(root, worker, 40, summary)
        worker.join.assert_called_once_with(timeout=30)
        self.assertTrue(summary["workerJoined"])
        self.assertFalse(summary["accepted"])
        self.assertEqual(summary["releaseFailure"], "PermissionError")
        self.assertEqual(summary["controllerFailure"], "release-publication")
        observer = Mock()
        observer.__exit__ = Mock(side_effect=OSError("detach failure"))
        observer.document.side_effect = ValueError("evidence failure")
        attachment = Mock()
        controller.observer_evidence([observer], attachment, summary)
        attachment.stop.assert_called_once_with()
        self.assertEqual(summary["controllerFailure"], "release-publication")
        self.assertEqual(summary["releaseFailure"], "PermissionError")
        self.assertFalse(summary["recordsComplete"])
        self.assertTrue(summary["observerDocuments"][0]["unavailable"])
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory).resolve()
            controller.retain_evidence(out, summary)
            value = (out / "summary.json").read_text()
            self.assertIn('"releaseFailure": "PermissionError"', value)
            self.assertNotIn("SYNTHETIC_PRIVATE_PATH", value)
            self.assertNotIn("detach failure", value)

    def test_expired_join_budget_is_not_extended_and_interception_stays(self):
        root = Mock()
        root.__truediv__ = Mock(return_value=Mock())
        worker = Mock(ident=123)
        worker.is_alive.return_value = True
        summary = {"accepted": False}
        with patch.object(controller.time, "monotonic", return_value=50):
            controller.release_and_join(root, worker, 40, summary)
        worker.join.assert_called_once_with(timeout=0)
        self.assertFalse(summary["workerJoined"])
        observer = Mock()
        observer.__exit__ = Mock()
        observer.document.return_value = {"unavailable": False}
        attachment = Mock()
        controller.observer_evidence([observer], attachment, summary)
        observer.__exit__.assert_not_called()
        attachment.stop.assert_not_called()

    def test_persistence_failure_reports_original_release_error(self):
        summary = {"accepted": False, "controllerFailure": "release-publication",
                   "releaseFailure": "PermissionError", "recordsComplete": False}
        with patch.object(controller, "write", side_effect=OSError("disk unavailable")) as write, \
                patch("builtins.print") as output:
            controller.retain_evidence(Path("unused"), summary)
        self.assertEqual(write.call_count, 3)
        self.assertEqual(summary["controllerFailure"], "release-publication")
        self.assertEqual(summary["releaseFailure"], "PermissionError")
        self.assertFalse(summary["accepted"])
        self.assertIn('"evidencePersistenceFailed": true', output.call_args.args[0])
        self.assertIn('"releaseFailure": "PermissionError"', output.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
