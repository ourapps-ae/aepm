import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

from aepm.__main__ import main
from aepm.bundle import pack, read_package
from aepm.fetch import fetch
from aepm.model import AepmError, canonical, digest
from tests.core.test_core import fixture


class Catalogue(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def do_GET(self):
        body = self.routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body if type(body) is bytes else json.dumps(body).encode())

    def log_message(self, *args):
        pass


class FetchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.source = self.root / "source-store"
        fixture(self.root / "leaf", "leaf")
        fixture(self.root / "sample", dependencies=[{"name": "ourapps-ae/leaf", "version": "0.1.0"}])
        self.leaf = pack(self.root / "leaf", self.source)
        self.sample = pack(self.root / "sample", self.source)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Catalogue)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        Catalogue.routes = {}
        for ref in (self.leaf, self.sample):
            self.publish(ref)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.store = self.root / "store"

    def publish(self, ref, *, served=None, listed=None):
        short = ref["name"].split("/")[1]
        base = f"/api/components/{short}/{ref['version']}"
        data = served if served is not None else (self.source / "objects" / (ref["digest"] + ".tar")).read_bytes()
        Catalogue.routes[base] = {"name": ref["name"], "version": ref["version"], "digest": "sha256:" + (listed or ref["digest"]),
                                  "source": {"repository": "ourapps-ae/" + short, "tag": "v" + ref["version"]}}
        Catalogue.routes[base + "/bundle"] = {"digest": "sha256:" + (listed or ref["digest"]), "url": f"{self.origin}/dl/{short}"}
        Catalogue.routes[f"/dl/{short}"] = data
        return f"/gh/ourapps-ae/{short}/releases/download/v{ref['version']}/{short}-{ref['version']}"

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(item) for item in args])
        return code, json.loads(output.getvalue())

    def test_fetch_adds_archive_and_assets_like_pack(self):
        assets = self.publish(self.sample)
        envelope = {"payload": "e30=", "payloadType": "application/vnd.in-toto+json", "signatures": []}
        report = {"format": 1, "context": "review"}
        Catalogue.routes[assets + ".release.dsse.json"] = canonical(envelope)
        Catalogue.routes[assets + ".review.json"] = canonical(report)
        results = fetch(self.store, [("ourapps-ae/sample", "0.1.0")], origin=self.origin, assets=self.origin + "/gh")
        self.assertEqual(results, [{**self.sample, "kind": "component", "assets": ["release", "review"]}])
        self.assertEqual((self.store / "objects" / (self.sample["digest"] + ".tar")).read_bytes(),
                         (self.source / "objects" / (self.sample["digest"] + ".tar")).read_bytes())
        self.assertEqual(json.loads((self.store / "catalogue.json").read_text())["entries"], [self.sample])
        read_package(self.sample, self.store)
        self.assertEqual((self.store / "statements" / self.sample["digest"] / "release.dsse.json").read_bytes(), canonical(envelope))
        self.assertFalse((self.store / "statements" / self.sample["digest"] / "guardian.dsse.json").exists())
        self.assertTrue((self.store / "reports" / (digest(canonical(report)) + ".json")).is_file())

    def test_dependencies_and_command(self):
        code, value = self.command("fetch", "sample@0.1.0", "--store", self.store, "--from", self.origin, "--with-dependencies")
        self.assertEqual(code, 0, value)
        self.assertEqual([item["name"] for item in value["result"]], ["ourapps-ae/sample", "ourapps-ae/leaf"])
        self.assertEqual(sorted(e["name"] for e in json.loads((self.store / "catalogue.json").read_text())["entries"]),
                         ["ourapps-ae/leaf", "ourapps-ae/sample"])

    def test_recipe_dependencies_follow_slots_and_job_candidates(self):
        from aepm.io import write
        recipe_root = self.root / "game"
        manifest = fixture(recipe_root, "game")
        manifest["kind"] = "recipe"
        manifest["artefacts"][0]["destination"] = "run.sh"
        write(recipe_root / "recipe.json", {"name": "ourapps-ae/game", "version": "0.1.0", "components": [
            {"id": "sample", "class": {"provides": [], "requires": [], "configuration": {}},
             "preferred": {"name": "ourapps-ae/sample", "version": "0.1.0"}, "configuration": {}, "includedWhen": None}],
            "jobs": [{"id": "job", "slot": "sample", "candidates": [
                {"component": "ourapps-ae/sample", "profile": "any"},
                {"component": "ourapps-ae/leaf", "version": "0.1.0", "profile": "any"}]}]})
        manifest["files"].append({"path": "recipe.json", "executable": False})
        manifest["files"].sort(key=lambda item: item["path"])
        (recipe_root / "component.json").write_bytes(canonical(manifest))
        game = pack(recipe_root, self.source)
        short = "game"
        Catalogue.routes[f"/api/components/{short}/0.1.0"] = None
        Catalogue.routes[f"/api/recipes/{short}/0.1.0"] = {"name": game["name"], "version": "0.1.0", "digest": "sha256:" + game["digest"]}
        Catalogue.routes[f"/api/recipes/{short}/0.1.0/bundle"] = {"digest": "sha256:" + game["digest"], "url": f"{self.origin}/dl/{short}"}
        Catalogue.routes[f"/dl/{short}"] = (self.source / "objects" / (game["digest"] + ".tar")).read_bytes()
        results = fetch(self.store, [("ourapps-ae/game", "0.1.0")], with_dependencies=True, origin=self.origin)
        self.assertEqual([item["name"] for item in results], ["ourapps-ae/game", "ourapps-ae/sample", "ourapps-ae/leaf"])

    def test_digest_mismatch_and_unknown_are_refused(self):
        leaf_bytes = (self.source / "objects" / (self.leaf["digest"] + ".tar")).read_bytes()
        self.publish(self.sample, served=leaf_bytes)
        with self.assertRaisesRegex(AepmError, "archive-digest"):
            fetch(self.store, [("ourapps-ae/sample", "0.1.0")], origin=self.origin)
        self.publish(self.sample, served=leaf_bytes, listed=self.leaf["digest"])
        with self.assertRaisesRegex(AepmError, "identity-mismatch"):
            fetch(self.store, [("ourapps-ae/sample", "0.1.0")], origin=self.origin)
        self.assertFalse((self.store / "catalogue.json").exists())
        with self.assertRaisesRegex(AepmError, "unknown-package"):
            fetch(self.store, [("ourapps-ae/absent", "0.1.0")], origin=self.origin)

    def test_noncanonical_report_refused(self):
        assets = self.publish(self.sample)
        Catalogue.routes[assets + ".review.json"] = b'{"format": 1}'
        with self.assertRaisesRegex(AepmError, "invalid-report"):
            fetch(self.store, [("ourapps-ae/sample", "0.1.0")], origin=self.origin, assets=self.origin + "/gh")


if __name__ == "__main__":
    unittest.main()
