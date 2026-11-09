"""Closed helper output checks before any result is retained."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from aepm.contextual import result_document
from aepm.io import immutable_blob, write
from aepm.model import AepmError


class ResultProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.protocol = self.root / "protocol"
        (self.protocol / "ownership").mkdir(parents=True)
        self.path = self.protocol / "result.json"
        self.suite = {"package": "a" * 64, "id": "fixture", "execution": {"assertions": ["version-match"]}}
        self.result = {"format": 1, "runId": "b" * 64, "package": "a" * 64, "id": "fixture",
                       "assertions": [{"id": "version-match", "passed": True, "actual": True}],
                       "artifacts": [], "resources": [], "cleanup": {"required": False, "attempted": False, "completed": True, "reason": ""}}

    def check(self, value):
        write(self.path, value)
        return result_document(self.path, self.suite, "b" * 64, self.root, [])

    def test_missing_duplicate_extra_and_secret_assertions_reject(self):
        self.assertEqual(self.check(self.result), self.result)
        for assertions in ([], self.result["assertions"] * 2,
                           [*self.result["assertions"], {"id": "unexpected", "passed": True, "actual": True}],
                           [{"id": "version-match", "passed": True, "actual": "PRIVATE_SENTINEL"}]):
            with self.subTest(assertions=assertions), self.assertRaises(AepmError):
                self.check({**self.result, "assertions": assertions})

    def test_child_cannot_attest_its_own_termination(self):
        self.suite["execution"]["assertions"] = ["process-tree-terminated"]
        self.result["assertions"] = [{"id": "process-tree-terminated", "passed": False, "actual": None}]
        self.check(self.result)
        self.result["assertions"][0].update(passed=True, actual=True)
        with self.assertRaisesRegex(AepmError, "runner-owned-assertion"):
            self.check(self.result)

    def test_artifact_escape_and_protocol_symlink_reject(self):
        outside = self.root.parent / (self.root.name + "-outside")
        outside.write_bytes(b"unchanged")
        self.addCleanup(outside.unlink)
        value = deepcopy(self.result)
        value["artifacts"] = [{"path": "../" + outside.name, "digest": "0" * 64, "architecture": None}]
        with self.assertRaises(AepmError):
            self.check(value)
        self.path.unlink()
        self.path.symlink_to(outside)
        with self.assertRaises(AepmError):
            result_document(self.path, self.suite, "b" * 64, self.root, [])

    def test_immutable_logs_reject_existing_symlink_without_overwrite(self):
        outside = self.root / "outside"
        outside.write_bytes(b"unchanged")
        path = self.root / "logs/output.log"
        path.parent.mkdir()
        path.symlink_to(outside)
        with self.assertRaises(AepmError):
            immutable_blob(path, b"new output")
        self.assertEqual(outside.read_bytes(), b"unchanged")
        path.unlink()
        immutable_blob(path, b"new output")
        immutable_blob(path, b"new output")
        with self.assertRaises(AepmError):
            immutable_blob(path, b"different output")
