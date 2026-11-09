"""Small subprocess failure-classification fixtures, not a new application proof."""

from copy import deepcopy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from aepm import contextual
from aepm.environment import Execution
from aepm.io import load
from aepm.verification import summary


class FailureReasonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "fixture").write_text("test input")
        self.logs = self.root / "logs"
        self.execution = Execution({}, self.root / "unused-policy", self.root / "evidence")
        self.suite = {"package": "a" * 64, "id": "fixture", "root": "package", "scope": "platform",
                      "argv": ["python3", "-c", "pass"], "cwd": ".", "prepare": [], "tools": {"python3": "3"},
                      "fixtures": ["fixture"], "locks": [], "network": False, "timeoutSeconds": 30,
                      "expectedExit": 0, "requirements": [], "execution": {"kind": "local", "simulation": False,
                      "operations": [], "settings": [], "secrets": [], "resources": [], "assertions": [], "cleanup": None}}

    def execute(self, suite):
        result, evidence = contextual.execute(suite, self.source, False, self.logs, self.execution)
        events = load(self.logs / (result["logDigest"] + ".json"))
        for event in events:
            if event["step"] == "retained-private-root":
                retained = Path(event["path"])
                self.assertTrue(retained.name.startswith("aepm-context-"))
                self.addCleanup(shutil.rmtree, retained)
        return result, evidence, events

    def test_nonzero_preparation_has_reason_and_prevents_main(self):
        suite = deepcopy(self.suite)
        suite["prepare"] = [{"argv": ["python3", "-c", "raise SystemExit(1)"], "cwd": ".", "network": False}]
        suite["argv"] = ["python3", "-c", "raise AssertionError('main must not run')"]
        result, evidence, events = self.execute(suite)
        self.assertEqual((result["status"], result["exitCode"], result["reason"]), ("failed", 1, "preparation-failed"))
        self.assertFalse(evidence["checkStarted"])
        steps = [event for event in events if type(event["step"]) is int]
        self.assertEqual(len(steps), 1)
        self.assertEqual((steps[0]["preparation"], steps[0]["exitCode"], steps[0]["reason"]), (True, 1, "preparation-failed"))

    def test_nonzero_main_preserves_successful_preparation_and_partitions(self):
        suite = deepcopy(self.suite)
        suite["prepare"] = [{"argv": ["python3", "-c", "pass"], "cwd": ".", "network": False}]
        suite["argv"] = ["python3", "-c", "raise SystemExit(1)"]
        result, evidence, events = self.execute(suite)
        self.assertEqual((result["status"], result["exitCode"], result["reason"]), ("failed", 1, "process-failed"))
        self.assertTrue(evidence["checkStarted"])
        steps = [event for event in events if type(event["step"]) is int]
        self.assertEqual([(item["preparation"], item["exitCode"], item["reason"]) for item in steps], [(True, 0, ""), (False, 1, "process-failed")])
        local = deepcopy(self.suite)
        local.update(id="local", scope="required-local")
        passed, _, _ = self.execute(local)
        unavailable = deepcopy(self.suite)
        unavailable.update(id="external", scope="deployed", requirements=["external:unavailable-fixture"])
        blocked, _, _ = self.execute(unavailable)
        self.assertEqual(summary([passed, result, blocked]), {"required-local": "passed", "platform": "failed", "deployed": "blocked"})

    def test_zero_exit_remains_passed_with_empty_reason(self):
        result, evidence, events = self.execute(self.suite)
        self.assertEqual((result["status"], result["exitCode"], result["reason"]), ("passed", 0, ""))
        self.assertTrue(evidence["cleanup"]["completed"])
        self.assertEqual([event["reason"] for event in events if type(event["step"]) is int], [""])

    def test_recognized_runner_errors_keep_precedence(self):
        actual = contextual.run
        for error in ("timeout", "output-limit", "cleanup-failed"):
            with self.subTest(error=error):
                def controlled(argv, *args, **kwargs):
                    if "--version" in argv:
                        return actual(argv, *args, **kwargs)
                    return 1, 0, error, b""
                with patch("aepm.contextual.run", controlled):
                    result, _, events = self.execute(self.suite)
                self.assertEqual((result["status"], result["reason"]), ("failed", error))
                self.assertEqual(next(event["reason"] for event in events if type(event["step"]) is int), error)
