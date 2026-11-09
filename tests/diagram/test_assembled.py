from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from aepm.application import projected_definition
from aepm.diagram import generate as renderer
from aepm.model import AepmError
from tests.diagram.test_generate import design


class AssembledDiagramTests(unittest.TestCase):
    def test_invalid_package_visual_uses_public_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "visual.json").write_text("{}")
            with self.assertRaisesRegex(AepmError, "diagram-definition"):
                projected_definition({"visual": {"definition": "visual.json"}}, root, {})

    def document(self):
        value = design()
        value.update(schemaVersion=2, status="assembled", lockDigest="a" * 64)
        for definition in value["definitions"]:
            definition["status"] = "assembled"
            if definition["kind"] == "component":
                definition["digest"] = "b" * 64
        return value

    def test_assembled_design_boundaries(self):
        value = self.document()
        self.assertEqual(renderer.validate_design(value), value)
        self.assertIn(b"Assembled", renderer.to_dot(value))
        for mutation in (lambda d: d.pop("lockDigest"), lambda d: d["definitions"][0].pop("digest"),
                         lambda d: d.update(status="example"), lambda d: d.update(schemaVersion=1),
                         lambda d: d["definitions"][0].update(version="0.1.0-beta"),
                         lambda d: d["definitions"][1].update(digest="c" * 64)):
            changed = deepcopy(value)
            mutation(changed)
            with self.assertRaises(renderer.DesignError):
                renderer.validate_design(changed)


class OptionalPortTests(unittest.TestCase):
    def test_optional_input_port_renders_and_needs_no_connection(self):
        value = design()
        value["connections"] = []
        value["definitions"][1]["ports"][0]["required"] = False
        self.assertEqual(renderer.validate_design(value), value)
        dot = renderer.to_dot(value)
        self.assertIn(b"optional / one", dot)
        self.assertNotIn(b"required / one", dot)
        value["definitions"][1]["ports"][0]["required"] = True
        with self.assertRaises(renderer.DesignError):
            renderer.validate_design(value)

    def test_projected_port_follows_manifest_optional_flag(self):
        base = {"id": "ourapps-ae.sample", "name": "Sample", "kind": "component", "status": "example", "package": "ourapps-ae/sample",
                "version": "0.1.0", "settings": [],
                "ports": [{"id": "rules", "name": "Rules", "direction": "input", "kind": "interface", "type": "ae/contract",
                           "version": "1.0.0", "required": False, "cardinality": "one"}]}
        manifest = {"kind": "component", "visual": {"definition": "visual.json"}, "collect": [], "provides": [],
                    "requires": [{"id": "rules", "type": "ae/contract", "version": "1.0.0", "path": "interface.txt"}]}
        ref = {"name": "ourapps-ae/sample", "version": "0.1.0", "digest": "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "visual.json").write_text(json.dumps(base))
            self.assertFalse(projected_definition(manifest, root, ref)["ports"][0]["required"])
            manifest["requires"][0]["optional"] = True
            self.assertFalse(projected_definition(manifest, root, ref)["ports"][0]["required"])
            base["ports"][0]["required"] = True
            (root / "visual.json").write_text(json.dumps(base))
            with self.assertRaisesRegex(AepmError, "diagram-interface"):
                projected_definition(manifest, root, ref)
            manifest["requires"][0]["optional"] = False
            self.assertTrue(projected_definition(manifest, root, ref)["ports"][0]["required"])
