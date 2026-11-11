"""Frozen prerequisite validation and complete blocked evidence."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aepm.model import AepmError, canonical, digest, validate_component
from aepm.verification import declarations, execute_suite, summary
from tests.core.test_core import fixture


class PrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.manifest = fixture(self.root / "package")
        self.manifest["verification"][1]["requirements"] = ["external:native-host"]

    def test_unknown_labels_reject_real_manifest_validation(self):
        validate_component(self.manifest)
        for label in ("language", "resources", "native", "external:", "external:bad/name", "external:Bad", "external:two words"):
            with self.subTest(label=label):
                manifest = deepcopy(self.manifest)
                manifest["verification"][0]["requirements"] = [label]
                with self.assertRaises(AepmError):
                    validate_component(manifest)
        self.manifest["verification"][0]["requirements"] = ["external:livekit-project"]
        validate_component(self.manifest)

    def test_external_names_survive_every_partition_without_execution(self):
        results = []
        for scope in ("required-local", "platform", "deployed"):
            suite = {**self.manifest["verification"][0], "package": "a" * 64, "id": scope, "scope": scope,
                     "requirements": ["external:windows-host", "external:livekit-project"]}
            with patch("aepm.verification.run", side_effect=AssertionError("must not execute")):
                result = execute_suite(suite, self.root / "package", True, self.root / "logs")
            self.assertEqual(result["status"], "blocked")
            self.assertIsNone(result["exitCode"])
            self.assertEqual(result["reason"], "external-prerequisites-unavailable:external:livekit-project,external:windows-host")
            results.append(result)
        self.assertEqual(summary(results), {scope: "blocked" for scope in ("required-local", "platform", "deployed")})

    def test_empty_requirements_still_check_installed_tools(self):
        suite = {**self.manifest["verification"][0], "package": "a" * 64,
                 "tools": {"aepm_nonexistent_compiler": "1.0"}}
        result = execute_suite(suite, self.root / "package", False, self.root / "logs")
        self.assertEqual((result["status"], result["reason"]), ("blocked", "tool-unavailable"))

    def test_full_declaration_binding_uses_archive_digest_and_order(self):
        refs = [{"digest": "b" * 64}, {"digest": "a" * 64}]
        manifests = {ref["digest"]: deepcopy(self.manifest) for ref in refs}
        records = declarations(refs, manifests, "review")
        expected = sorted([{**suite, "package": ref["digest"]} for ref in refs
                           for suite in self.manifest["verification"]], key=lambda item: (item["package"], item["id"]))
        self.assertEqual(records, expected)
        changed = deepcopy(expected)
        changed[0]["requirements"] = ["external:changed"]
        self.assertNotEqual(digest(canonical(records)), digest(canonical(changed)))
        manifests[refs[0]["digest"]]["verification"].append(self.manifest["verification"][0])
        with self.assertRaises(AepmError):
            declarations(refs, manifests, "review")
