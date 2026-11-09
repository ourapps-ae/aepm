"""Android harness input and evidence guards without build execution."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from aepm.model import AepmError
from tests import run_android_component_fixture as harness


class AndroidComponentGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.context = self.root / "context.json"
        self.context.write_text("{}")
        self.out = self.root / "output"

    def reject(self, source, context, out):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        with patch.object(harness, "load", side_effect=AssertionError("validation read before path guard")):
            with self.assertRaises((AepmError, ValueError)):
                harness.inputs(source, context, out)
        self.assertEqual(before, sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*")))

    def test_source_context_and_output_links_are_rejected_before_reads(self):
        for kind in ("source", "context", "output"):
            with self.subTest(kind=kind):
                link = self.root / (kind + "-link")
                target = self.context if kind == "context" else self.source
                link.symlink_to(target, target_is_directory=kind != "context")
                self.reject(link if kind == "source" else self.source,
                            link if kind == "context" else self.context,
                            link if kind == "output" else self.out)

    def test_dangling_output_link_is_occupied(self):
        target = self.root / "absent"
        self.out.symlink_to(target)
        self.reject(self.source, self.context, self.out)
        self.assertTrue(self.out.is_symlink())
        self.assertFalse(target.exists())

    def test_linked_output_ancestor_is_rejected(self):
        link = self.root / "linked-parent"
        link.symlink_to(self.source, target_is_directory=True)
        self.reject(self.source, self.context, link / "new-output")

    def test_occupied_output_is_rejected_without_writes(self):
        self.out.mkdir()
        marker = self.out / "preserve"
        marker.write_bytes(b"unchanged")
        self.reject(self.source, self.context, self.out)
        self.assertEqual(marker.read_bytes(), b"unchanged")

    def test_packed_metadata_allows_only_derived_tree_digest_change(self):
        initial = {"identity": {"name": "ourapps-ae/video-calls", "version": "0.1.2",
                                "sourceTreeDigest": "initial"},
                   "verification": [{"id": "android-media", "argv": ["approved"]}]}
        packed = deepcopy(initial)
        packed["identity"]["sourceTreeDigest"] = "derived"
        harness.bind_manifest(initial, packed)
        for field in ("name", "version", "declaration"):
            changed = deepcopy(packed)
            if field == "declaration":
                changed["verification"][0]["argv"] = ["different"]
            else:
                changed["identity"][field] = "different"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Packed identity or declaration"):
                harness.bind_manifest(initial, changed)
        self.assertEqual(initial["identity"]["sourceTreeDigest"], "initial")

    def returned(self):
        self.out.mkdir()
        return {"complete": False, "completionPublished": False,
                "result": {"status": "passed", "steps": [{"outputDigest": "retained"}]},
                "evidence": {"log": "raw-log", "assertions": ["returned"]}}

    def assert_retained(self, output):
        retained = json.loads((self.out / "focused-result.json").read_text())
        self.assertEqual(retained["result"], output["result"])
        self.assertEqual(retained["evidence"], output["evidence"])
        self.assertFalse(retained["accepted"])
        self.assertFalse(retained["complete"])
        self.assertFalse(retained["completionPublished"])
        self.assertEqual(retained["postChecks"], "failed")

    def test_expiry_preserves_returned_result_before_check(self):
        output = self.returned()

        def expire():
            retained = json.loads((self.out / "focused-result.json").read_text())
            self.assertEqual(retained["evidence"], output["evidence"])
            self.assertEqual(retained["postChecks"], "pending")
            raise AepmError("execution-expired", "fixture")

        with self.assertRaises(AepmError):
            harness.retain_result(self.out, output, Mock(check_time=expire), self.source, [])
        self.assert_retained(output)

    def test_source_inspection_exception_preserves_returned_evidence(self):
        output = self.returned()
        with patch.object(harness, "snapshot", side_effect=OSError("fixture")):
            with self.assertRaises(OSError):
                harness.retain_result(self.out, output, Mock(), self.source, [])
        self.assert_retained(output)

    def test_source_drift_preserves_evidence_and_returns_failure(self):
        output = self.returned()
        with patch.object(harness, "snapshot", return_value=["changed"]):
            self.assertFalse(harness.retain_result(self.out, output, Mock(), self.source, []))
        self.assert_retained(output)

    def test_success_stays_incomplete_without_publishing_completion(self):
        output = self.returned()
        with patch.object(harness, "snapshot", return_value=[]):
            self.assertTrue(harness.retain_result(self.out, output, Mock(), self.source, []))
        retained = json.loads((self.out / "focused-result.json").read_text())
        self.assertTrue(retained["accepted"])
        self.assertFalse(retained["complete"])
        self.assertFalse(retained["completionPublished"])


if __name__ == "__main__":
    unittest.main()
