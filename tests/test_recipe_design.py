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
from aepm.recipe import CelError, World, evaluate, evaluate_condition, fit, parse_condition, question_kinds, questions, slot_fit
from tests.core.test_core import fixture


def component(root, name, provides=(), requires=(), collect=(), profiles=None, document="{}"):
    manifest = fixture(root, name)
    for port in (*provides, *requires):
        (root / f"{port}.json").write_text(document)
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


LABEL = {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9 -]{0,63}$"}


def slot(identifier, name, provides=(), properties=None, required=(), includedWhen=None):
    return {"id": identifier,
            "class": {"provides": [{"type": "ae/" + port, "version": "1.0.0"} for port in provides], "requires": [],
                      "configuration": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                                        "properties": properties or {}, "required": list(required), "additionalProperties": True}},
            "preferred": {"name": name, "version": "0.1.0"}, "configuration": {}, "includedWhen": includedWhen}


RECIPE = {
    "format": 1, "name": "ourapps-ae/game", "version": "0.1.0", "title": "Game",
    "components": [
        slot("deck", "ourapps-ae/deck", ["deck"], {"targets": LABEL}, ["targets"]),
        slot("video", "ourapps-ae/video", properties={"key": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]{0,63}$"}},
             includedWhen="video"),
        slot("host", "ourapps-ae/host", properties={"provider": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,63}$"}}),
    ],
    "jobs": [{"id": "server", "slot": "host", "overrideQuestion": "server", "candidates": [
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


DECK_SETTINGS = [{"id": "targets", "type": "string", "grammar": "label", "required": True, "secret": False, "default": "web"}]
HOST_SETTINGS = [{"id": "provider", "type": "string", "grammar": "slug", "required": True, "secret": False, "default": "none"}]
HOST_PROFILES = [{"id": "free", "load": {"concurrentPeople": 50}, "cost": "free", "regions": ["any"], "compliance": [],
                  "provider": {"name": "Cloudflare Workers", "tier": "free", "limitsSource": None}},
                 {"id": "paid", "load": {}, "cost": "paid", "regions": ["any"], "compliance": [],
                  "provider": {"name": "Cloudflare Workers", "tier": "paid", "limitsSource": None}}]


class RecipeDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name).resolve()
        cls.store = cls.root / "store"
        component(cls.root / "deck", "deck", provides=["deck"], collect=DECK_SETTINGS)
        component(cls.root / "video", "video",
                  collect=[{"id": "key", "type": "string", "grammar": "identifier", "required": False, "secret": True}])
        component(cls.root / "host", "host", collect=HOST_SETTINGS, profiles=HOST_PROFILES)
        component(cls.root / "deck2", "deck2", provides=["deck"], collect=DECK_SETTINGS)
        component(cls.root / "deck3", "deck3", provides=["deck"], collect=DECK_SETTINGS, document='{"other": true}')
        component(cls.root / "deck4", "deck4", provides=["deck"],
                  collect=[{"id": "targets", "type": "string", "grammar": "slug", "required": True, "secret": False, "default": "web"},
                           {"id": "size", "type": "integer", "grammar": "integer", "required": True, "secret": False}],
                  requires=["random-source"])
        for name in ("deck", "video", "host", "deck2", "deck3", "deck4"):
            pack(cls.root / name, cls.store)
        recipe = component(cls.root / "game", "game", requires=["deck"])
        recipe["kind"] = "recipe"
        recipe["artefacts"][0]["destination"] = "run.sh"
        write(cls.root / "game" / "recipe.json", RECIPE)
        recipe["files"].append({"path": "recipe.json", "executable": False})
        recipe["files"].sort(key=lambda item: item["path"])
        (cls.root / "game" / "component.json").write_bytes(canonical(recipe))
        pack(cls.root / "game", cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def world(self, **substitutes):
        return World.from_store("ourapps-ae/game", "0.1.0", self.store,
                                {key: ("ourapps-ae/" + value, "0.1.0") for key, value in substitutes.items()})

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(item) for item in args])
        return code, json.loads(output.getvalue())

    def test_world_from_store_matches_source_directories(self):
        stored = self.world()
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
        result = evaluate(self.world(), {})
        self.assertTrue(result["ok"], result)
        design = validate_definition(result["design"])
        self.assertEqual([(item["id"], item["name"]) for item in design["components"]], [("deck", "ourapps-ae/deck"), ("host", "ourapps-ae/host")])
        self.assertEqual(design["selections"]["server"], {"component": "ourapps-ae/host", "version": "0.1.0", "profile": "free",
                                                         "reason": "scale small; 2 of 2 candidates fit; lowest cost free"})
        self.assertEqual(next(c for c in design["components"] if c["id"] == "host")["configuration"], {"provider": "free"})
        large = evaluate(self.world(), {"scale": "large", "targets": ["ios", "web"]})
        self.assertEqual(large["design"]["selections"]["server"]["profile"], "paid")
        self.assertEqual(large["design"]["components"][0]["configuration"], {"targets": "web ios"})
        self.assertEqual(large["design"]["answers"]["targets"], ["web", "ios"])

    def test_errors_are_values(self):
        world = self.world()
        self.assertEqual(evaluate(world, {"video": True})["errors"], [{"code": "unanswered", "path": "answers.videoKey"}])
        self.assertEqual(evaluate(world, {"scale": "huge"})["errors"][0], {"code": "invalid-answer", "path": "answers.scale"})
        self.assertEqual(evaluate(world, {"server": "nobody"})["errors"], [{"code": "uncovered", "path": "server"}])
        with_video = evaluate(world, {"video": True, "videoKey": "keys/video"})
        self.assertEqual(next(c for c in with_video["design"]["components"] if c["id"] == "video")["configuration"],
                         {"key": {"secretRef": "keys/video"}})

    def test_fit_rule(self):
        world = self.world()
        packages = {key[0].split("/")[1]: package for key, package in world.packages.items()}
        self.assertEqual(slot_fit(world, "deck", packages["deck"]), [])
        alternative = self.world(deck="deck2")
        self.assertEqual(slot_fit(alternative, "deck", alternative.filling["deck"]), [])
        for name, reasons in (("deck3", ["document:ae/deck@1.0.0"]),
                              ("deck4", ["requires:ae/random-source@1.0.0", "setting-type:targets", "unset-setting:size"]),
                              ("host", ["provides:ae/deck@1.0.0", "setting:targets"])):
            other = self.world(deck=name)
            with self.subTest(name=name):
                self.assertEqual(slot_fit(other, "deck", other.filling["deck"]), reasons)

    def test_entry_modules_are_part_of_the_fit(self):
        document = json.dumps({"x-ourapps-modules": {"web": "web/index.ts", "apple": "apple/Sources"}})
        world = self.world()
        preferred = world.filling["deck"]
        manifest = json.loads(json.dumps(preferred.manifest))
        bytes_for = {"deck.json": document.encode()}

        class Fake:
            def __init__(self, destinations):
                self.manifest = {**manifest, "artefacts": [{"destination": "components/deck/" + item} for item in destinations]}
                self.name, self.version = "ourapps-ae/deck", "0.1.0"

            def file(self, path):
                return bytes_for.get(path)

        self.assertEqual(fit(RECIPE["components"][0]["class"], Fake(["web/index.ts", "apple/Sources/Deck.swift"]), Fake([])), [])
        self.assertEqual(fit(RECIPE["components"][0]["class"], Fake(["web/deck.ts"]), Fake([])),
                         ["module:web:web/index.ts", "module:apple:apple/Sources"])

    def test_substitution(self):
        result = evaluate(self.world(deck="deck2"), {})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["design"]["components"][0], {"id": "deck", "name": "ourapps-ae/deck2", "version": "0.1.0",
                                                             "configuration": {"targets": "web"}})
        self.assertEqual(result["design"]["selections"]["deck"], {"component": "ourapps-ae/deck2", "version": "0.1.0", "reason": "substituted"})
        refused = evaluate(self.world(deck="deck3"), {})
        self.assertEqual(refused["errors"], [{"code": "unfit", "path": "deck:document:ae/deck@1.0.0"}])
        self.assertEqual(evaluate(self.world(nowhere="deck2"), {})["errors"], [{"code": "unknown-slot", "path": "nowhere"}])

    def test_alternatives_from_the_catalogue(self):
        import http.server
        import threading
        from tests.test_fetch import Catalogue
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Catalogue)
        origin = f"http://127.0.0.1:{server.server_port}"
        catalogue = json.loads((self.store / "catalogue.json").read_text())["entries"]
        Catalogue.routes = {"/api/components?provides=ae%2Fdeck&limit=100": {"components": [
            {"name": "ourapps-ae/" + name, "version": "0.1.0"} for name in ("deck", "deck2", "deck3")]}}
        for entry in catalogue:
            short = entry["name"].split("/")[1]
            base = f"/api/components/{short}/0.1.0"
            Catalogue.routes[base] = {"name": entry["name"], "version": "0.1.0", "digest": "sha256:" + entry["digest"]}
            Catalogue.routes[base + "/bundle"] = {"digest": "sha256:" + entry["digest"], "url": f"{origin}/dl/{short}"}
            Catalogue.routes[f"/dl/{short}"] = (self.store / "objects" / (entry["digest"] + ".tar")).read_bytes()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        code, value = self.command("alternatives", "game@0.1.0", "deck", "--store", self.store, "--from", origin)
        self.assertEqual(code, 0, value)
        self.assertEqual(value["result"], [
            {"name": "ourapps-ae/deck", "version": "0.1.0", "fits": True, "reasons": []},
            {"name": "ourapps-ae/deck2", "version": "0.1.0", "fits": True, "reasons": []},
            {"name": "ourapps-ae/deck3", "version": "0.1.0", "fits": False, "reasons": ["document:ae/deck@1.0.0"]}])
        code, value = self.command("alternatives", "game@0.1.0", "nowhere", "--store", self.store, "--from", origin)
        self.assertEqual((code, value["error"]["code"]), (1, "unknown-slot"))

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
        code, value = self.command("design", "ourapps-ae/game@0.1.0", "--store", self.store, "--substitute", "deck=deck2@0.1.0",
                                   "--out", self.root / "substituted.json")
        self.assertEqual(code, 0, value)
        self.assertEqual(load(self.root / "substituted.json")["components"][0]["name"], "ourapps-ae/deck2")
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--substitute", "deck=deck9@0.1.0", "--out", self.root / "x.json")
        self.assertEqual((code, value["error"]["code"]), (1, "unknown-package"))
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
