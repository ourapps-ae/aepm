import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from aepm.__main__ import main
from aepm.application import validate_definition
from aepm.bundle import pack
from aepm.io import load, write
from aepm.model import canonical
from aepm.recipe import CelError, World, evaluate, evaluate_condition, parse_condition, question_kinds, questions
from tests.core.test_core import fixture


def component(root, name, provides=(), requires=(), collect=(), profiles=None):
    manifest = fixture(root, name)
    for port in (*provides, *requires):
        (root / f"{port}.json").write_text("{}")
    manifest["files"] += [{"path": f"{port}.json", "executable": False} for port in (*provides, *requires)]
    manifest["provides"] = [{"id": port, "type": "ae/" + port, "version": "1.0.0", "path": f"{port}.json"} for port in provides]
    manifest["requires"] = [{"id": port, "type": "ae/" + port, "version": "1.0.0", "path": f"{port}.json"} for port in requires]
    manifest["collect"] = list(collect)
    write(root / "suitability.json", {"format": 1, "jobs": [name], "profiles": profiles or [
        {"id": "any", "load": {}, "cost": "none", "regions": ["any"], "compliance": []}], "notes": ""})
    manifest["files"].append({"path": "suitability.json", "executable": False})
    manifest["files"].sort(key=lambda item: item["path"])
    (root / "component.json").write_bytes(canonical(manifest))
    return manifest


RECIPE = {
    "format": 1, "name": "ourapps-ae/game", "version": "0.1.0", "title": "Game",
    "components": [
        {"id": "deck", "name": "ourapps-ae/deck", "version": "0.1.0", "configuration": {}, "includedWhen": None},
        {"id": "video", "name": "ourapps-ae/video", "version": "0.1.0", "configuration": {}, "includedWhen": "video"},
        {"id": "host", "name": "ourapps-ae/host", "version": "0.1.0", "configuration": {}, "includedWhen": None},
    ],
    "jobs": [{"id": "server", "overrideQuestion": "server", "candidates": [
        {"component": "ourapps-ae/host", "profile": "free"}, {"component": "ourapps-ae/host", "profile": "paid"}]}],
    "scale": {"question": "scale", "bands": [
        {"id": "small", "label": "small", "load": {"concurrentPeople": 10}},
        {"id": "large", "label": "large", "load": {"concurrentPeople": 1000}}]},
    "questions": [
        {"id": "targets", "ask": "Devices?", "askAgent": "infer", "type": "set", "options": ["web", "ios"], "default": ["web"],
         "effects": [{"sets": {"deck.targets": "$answer"}}]},
        {"id": "video", "ask": "Video?", "askAgent": "ask", "type": "boolean", "default": False, "effects": []},
        {"id": "videoKey", "ask": "Key?", "askAgent": "ask", "type": "secretRef", "askWhen": "video",
         "effects": [{"sets": {"video.key": {"ref": "videoKey"}}}]},
        {"id": "scale", "ask": "How many?", "askAgent": "infer", "type": "choice", "options": ["small", "large"], "default": "small",
         "effects": []},
        {"id": "server", "ask": "Server?", "askAgent": "ask", "type": "text", "default": "cloudflare", "effects": []},
    ],
    "connections": [{"source": {"instance": "deck", "port": "deck"}, "target": {"instance": "application", "port": "deck"}}],
    "tests": {"defaultAnswers": {}, "answerSets": []},
}


class RecipeDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name).resolve()
        cls.store = cls.root / "store"
        component(cls.root / "deck", "deck", provides=["deck"],
                  collect=[{"id": "targets", "type": "string", "grammar": "label", "required": True, "secret": False, "default": "web"}])
        component(cls.root / "video", "video",
                  collect=[{"id": "key", "type": "string", "grammar": "identifier", "required": False, "secret": True}])
        component(cls.root / "host", "host",
                  collect=[{"id": "provider", "type": "string", "grammar": "slug", "required": True, "secret": False, "default": "none"}],
                  profiles=[{"id": "free", "load": {"concurrentPeople": 50}, "cost": "free", "regions": ["any"], "compliance": [],
                             "provider": {"name": "Cloudflare Workers", "tier": "free", "limitsSource": None}},
                            {"id": "paid", "load": {}, "cost": "paid", "regions": ["any"], "compliance": [],
                             "provider": {"name": "Cloudflare Workers", "tier": "paid", "limitsSource": None}}])
        for name in ("deck", "video", "host"):
            pack(cls.root / name, cls.store)
        recipe = component(cls.root / "game", "game", requires=["deck"])
        recipe["kind"] = "recipe"
        write(cls.root / "game" / "recipe.json", RECIPE)
        recipe["files"].append({"path": "recipe.json", "executable": False})
        recipe["files"].sort(key=lambda item: item["path"])
        (cls.root / "game" / "component.json").write_bytes(canonical(recipe))
        pack(cls.root / "game", cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(item) for item in args])
        return code, json.loads(output.getvalue())

    def test_world_from_store_matches_source_directories(self):
        stored = World.from_store("ourapps-ae/game", "0.1.0", self.store)
        self.assertEqual(stored.recipe, RECIPE)
        self.assertEqual(set(stored.manifests), {"deck", "video", "host", "application"})
        sources = self.root / "sources"
        sources.mkdir(exist_ok=True)
        for name in ("deck", "video", "host"):
            if not (sources / name).exists():
                (sources / name).symlink_to(self.root / name)
        directories = World.from_directories(self.root / "game", sources)
        self.assertEqual(evaluate(stored, {})["design"]["components"], evaluate(directories, {})["design"]["components"])

    def test_design_defaults_selection_and_conditions(self):
        result = evaluate(World.from_store("ourapps-ae/game", "0.1.0", self.store), {})
        self.assertTrue(result["ok"], result)
        design = validate_definition(result["design"])
        self.assertEqual([item["id"] for item in design["components"]], ["deck", "host"])
        self.assertEqual(design["selections"]["server"]["profile"], "free")
        self.assertEqual(next(c for c in design["components"] if c["id"] == "host")["configuration"], {"provider": "free"})
        large = evaluate(World.from_store("ourapps-ae/game", "0.1.0", self.store), {"scale": "large", "targets": ["ios", "web"]})
        self.assertEqual(large["design"]["selections"]["server"]["profile"], "paid")
        self.assertEqual(large["design"]["components"][0]["configuration"], {"targets": "web ios"})
        self.assertEqual(large["design"]["answers"]["targets"], ["web", "ios"])

    def test_errors_are_values(self):
        world = World.from_store("ourapps-ae/game", "0.1.0", self.store)
        self.assertEqual(evaluate(world, {"video": True})["errors"], [{"code": "unanswered", "path": "answers.videoKey"}])
        self.assertEqual(evaluate(world, {"scale": "huge"})["errors"][0], {"code": "invalid-answer", "path": "answers.scale"})
        self.assertEqual(evaluate(world, {"server": "nobody"})["errors"], [{"code": "uncovered", "path": "server"}])
        with_video = evaluate(world, {"video": True, "videoKey": "keys/video"})
        self.assertEqual(next(c for c in with_video["design"]["components"] if c["id"] == "video")["configuration"],
                         {"key": {"secretRef": "keys/video"}})

    def test_cel_subset(self):
        kinds = question_kinds(RECIPE)
        self.assertTrue(evaluate_condition("'ios' in targets && !video", {"targets": ["ios"], "video": False}, kinds))
        self.assertTrue(evaluate_condition("size(targets) >= 2", {"targets": ["ios", "web"]}, kinds))
        for text in ("targets + 1", "has(video)", "video ? 1 : 2", "1.5 == 1.5", "unknown", "-1 < 0 && -video"):
            with self.subTest(text=text), self.assertRaises(CelError):
                evaluate_condition(text, {"targets": [], "video": False}, kinds)
        self.assertEqual(parse_condition("video"), ("id", "video"))

    def test_commands(self):
        answers = self.root / "answers.json"
        write(answers, {"targets": ["web", "ios"]})
        out = self.root / "definition.json"
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--answers", answers, "--out", out)
        self.assertEqual(code, 0, value)
        self.assertEqual(validate_definition(load(out))["answers"], {"targets": ["web", "ios"], "video": False, "scale": "small", "server": "cloudflare"})
        code, value = self.command("design", "ourapps-ae/game@0.1.0", "--store", self.store, "--out", self.root / "none.json")
        self.assertEqual(code, 0, value)
        write(answers, {"video": True})
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--answers", answers, "--out", self.root / "bad.json")
        self.assertEqual((code, value), (1, {"ok": False, "errors": [{"code": "unanswered", "path": "answers.videoKey"}]}))
        self.assertFalse((self.root / "bad.json").exists())
        code, value = self.command("questions", "game@0.1.0", "--store", self.store)
        self.assertEqual(code, 0)
        self.assertEqual(value["result"], questions(RECIPE))
        self.assertEqual(value["result"][2], {"id": "videoKey", "ask": "Key?", "askAgent": "ask", "type": "secretRef", "askWhen": "video"})
        code, value = self.command("design", "deck@0.1.0", "--store", self.store, "--out", self.root / "x.json")
        self.assertEqual((code, value["error"]["code"]), (1, "not-a-recipe"))
        code, value = self.command("questions", "game@9.9.9", "--store", self.store)
        self.assertEqual((code, value["error"]["code"]), (1, "unknown-package"))


if __name__ == "__main__":
    unittest.main()
