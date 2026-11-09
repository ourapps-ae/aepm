"""Non-build contextual retention and Windows consumer compatibility."""

from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from aepm import contextual
from aepm.io import load
from aepm.model import AepmError, canonical, digest
from aepm.supervision import Recorder, supervision_step_index, validate_log_index
from tests.windows import test_native_process as windows


class ContextualObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.logs = self.root / "logs"
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.suite = {"package": "a" * 64, "id": "fixture", "scope": "platform", "root": "package",
                      "argv": ["fixture"], "cwd": ".", "prepare": [], "tools": {}, "fixtures": [], "locks": [],
                      "network": False, "timeoutSeconds": 30, "requirements": [], "execution": {
                          "kind": "local", "simulation": False, "operations": [], "settings": [],
                          "secrets": [], "resources": [], "assertions": [], "cleanup": None}}

    def execute(self, *, expired=False, failed=False, suppressed=False, resource_failure=False, nonzero=False):
        state = {"ran": False}
        suite = deepcopy(self.suite)
        if suppressed:
            suite["execution"]["secrets"] = ["SYNTHETIC_ONLY"]
        workspace = Mock(preserve=False)
        workspace.__enter__ = Mock(return_value=self.private)
        workspace.__exit__ = Mock(return_value=False)

        def check_time():
            if expired and state["ran"]:
                raise AepmError("authorization-expired", "fixture")

        execution = SimpleNamespace(check_time=check_time, run_id="fixture", authorization=None,
                                    prepare=lambda *_: ("local", {"settings": {}, "operations": [], "simulationKind": None},
                                                        [{}] if resource_failure else [], [], {}))

        def run(_argv, _cwd, _environment, _timeout, _limit, *, diagnostics):
            state["ran"] = True
            if failed:
                error = AepmError("cleanup-failed", "private-process-directory")
                diagnostics.fault("sample", error=error)
                diagnostics.stopped("sample", "exception", error)
            else:
                diagnostics.stopped("exit-observation", "natural-exit", exit_code=1 if nonzero else 0)
            exit_code = -9 if failed else 1 if nonzero else 0
            diagnostics.finish(exit_code, "cleanup-failed" if failed else "", True, not failed, True)
            return exit_code, 0, "cleanup-failed" if failed else "", b"SYNTHETIC_SECRET_OUTPUT"

        def resource(_value):
            if state["ran"]:
                raise AepmError("resource-changed", "fixture")

        with ExitStack() as stack:
            for name, value in (("VerificationDirectory", Mock(return_value=workspace)),
                                ("tool_environment", Mock(return_value={})), ("tool_versions", Mock(return_value={})),
                                ("prerequisites", Mock(return_value=[])), ("resolve_command", lambda argv, *_, **__: argv),
                                ("run", run), ("validate_resource", resource)):
                stack.enter_context(patch.object(contextual, name, value))
            result, evidence = contextual.execute(suite, self.source, False, self.logs, execution)
        events = load(self.logs / (result["logDigest"] + ".json"))
        paths = validate_log_index(suite, events, self.logs)
        self.assertEqual(len(paths), 1)
        return result, evidence, events, load(paths[0]), workspace

    def test_first_cause_retained_with_failed_root(self):
        result, evidence, events, document, workspace = self.execute(failed=True)
        self.assertEqual(result["reason"], "cleanup-failed")
        self.assertFalse(evidence["cleanup"]["completed"])
        self.assertTrue(workspace.preserve)
        self.assertEqual(document["firstFailure"]["observation"]["error"]["location"], "private-process-directory")
        self.assertTrue(any(e["step"] == "retained-private-root" for e in events))

    def test_post_run_expiry_retains_diagnostic_and_command_order(self):
        result, _, events, document, _ = self.execute(expired=True)
        self.assertEqual(result["reason"], "authorization-expired")
        self.assertEqual([e["step"] for e in events], ["validation-inputs", 0, "supervisor-v1/0"])
        self.assertEqual(document["executionStop"]["observation"]["kind"], "natural-exit")

    def test_post_run_resource_failure_retains_diagnostic(self):
        result, _, _, document, _ = self.execute(resource_failure=True)
        self.assertEqual(result["reason"], "resource-changed")
        self.assertEqual(document["finalOutcome"]["state"], "observed")

    def test_secret_output_stays_suppressed(self):
        result, _, events, document, _ = self.execute(suppressed=True)
        self.assertEqual(result["status"], "passed")
        command = next(event for event in events if type(event["step"]) is int)
        self.assertTrue(command["suppressed"])
        self.assertNotIn("logDigest", command)
        self.assertNotIn(b"SYNTHETIC_SECRET_OUTPUT", canonical(document))

    def test_contextual_classification_matches_command_binding(self):
        result, _, _, document, _ = self.execute(nonzero=True)
        self.assertEqual(result["reason"], "process-failed")
        self.assertEqual(document["finalOutcome"]["outcome"]["reason"], "process-failed")
        self.assertEqual(document["executionStop"]["observation"]["exitCode"], 1)


class SimulatedWindowsConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.suite = {"package": "a" * 64, "id": "fixture"}

    def report(self, *, ordinary=True, diagnostic=True, unknown=False):
        raw = canonical({"privateRoot": str(self.root / "absent-root"), "profile": str(self.root / "absent-profile")})
        (self.logs / (digest(raw) + ".log")).write_bytes(raw)
        command = {"step": "unknown" if unknown else 0, "preparation": False, "seconds": 1,
                   "exitCode": 0, "reason": "", "logDigest": digest(raw)}
        if not ordinary:
            command.pop("logDigest")
            command["suppressed"] = True
        events = [command]
        if diagnostic:
            recorder = Recorder()
            recorder.finish(0, "", True, True, True)
            raw = canonical(recorder.document(self.suite, 0, False))
            (self.logs / (digest(raw) + ".log")).write_bytes(raw)
            events.append({"step": "supervisor-v1/0", "preparation": False, "seconds": 0,
                           "exitCode": 0, "reason": "", "logDigest": digest(raw)})
        raw = canonical(events)
        (self.logs / (digest(raw) + ".json")).write_bytes(raw)
        return {"suites": [{**self.suite, "logDigest": digest(raw)}]}

    def test_ordinary_and_diagnostic_mixed_evidence(self):
        consumer = windows.NativeWindowsTests()
        consumer.assert_private_cleanup(self.report(), self.root)
        consumer.assert_private_cleanup(self.report(diagnostic=False), self.root)

    def test_diagnostic_cannot_replace_command_paths(self):
        with self.assertRaises(AssertionError):
            windows.NativeWindowsTests().assert_private_cleanup(self.report(ordinary=False), self.root)

    def test_unknown_ordinary_shape_is_not_skipped(self):
        with self.assertRaises(AssertionError):
            windows.NativeWindowsTests().assert_private_cleanup(self.report(unknown=True, diagnostic=False), self.root)


if __name__ == "__main__":
    unittest.main()
