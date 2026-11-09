"""Opt-in signed simulation of the actual packaged recipe update runner."""

from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from aepm.authorization import execution_request, authorize_execution
from aepm.bundle import pack, read_package
from aepm.environment import clock
from aepm.io import load, write
from aepm.model import AepmError, canonical, digest
from aepm.test_identities import generate
from aepm.trust import sign, review_bindings, validate_report_evidence, verify_package
from aepm.verification import review_package
from tests.core.test_core import fixture


ASSERTIONS = ["delivery-origin-allowed", "invitation-whole-segment", "no-install", "platform-selection", "response-valid", "version-match"]
GUARD = """import assert from 'node:assert/strict';
globalThis.fetch = async () => { throw new Error('Real network forbidden in fixture'); };
const original = Response.json;
let replies = 0;
Response.json = (...args) => { assert.equal(++replies, 1, 'Only the fixture endpoint read is permitted'); return original(...args); };
process.on('exit', () => { if (replies !== 1) process.exitCode = 1; });
"""


@unittest.skipUnless(os.environ.get("AEPM_RECIPE_SOURCE"), "Set AEPM_RECIPE_SOURCE for actual source-byte integration")
class RecipeUpdateContextTests(unittest.TestCase):
    def test_public_private_desktop_and_testflight_through_signed_context(self):
        repository = Path(os.environ["AEPM_RECIPE_SOURCE"]).resolve()
        workspace = repository.parent
        paths = {
            "verification/update-runner.mjs": repository / "recipe/verification/update-runner.mjs",
            "verification/update-check.mjs": repository / "recipe/verification/update-check.mjs",
            "web/src/store-response.ts": repository / "recipe/web/src/store-response.ts",
            "web/test/fixtures/store-latest.json": repository / "recipe/web/test/fixtures/store-latest.json",
            "components/store-update/server/store.ts": workspace / "components/store-update/implementation/server/store.ts",
            "components/store-update/web/update.ts": workspace / "components/store-update/implementation/web/update.ts",
            "components/video-calls/verification/result.mjs": workspace / "components/video-calls/implementation/verification/result.mjs",
        }
        source_bytes = {target: path.read_bytes() for target, path in paths.items()}
        cases = [("browser-public", "public", "browser", "web", "https://play.example", "2.1.0"),
                 ("browser-private", "private", "browser", "web", "https://play.example", "2.1.0"),
                 ("windows-public", "desktop-public", "windows", "direct", "https://delivery.example", "2.1.0"),
                 ("windows-private", "desktop-private", "windows", "direct", "https://delivery.example", "2.1.0"),
                 ("testflight-public", "public", "ios", "testflight", "https://testflight.apple.com", "1.9.0"),
                 ("testflight-private", "private", "ios", "testflight", "https://testflight.apple.com", "1.9.0")]
        with tempfile.TemporaryDirectory(prefix="aepm-recipe-context-") as temporary:
            root = Path(temporary).resolve()
            policy_path = generate(root / "keys")
            policy = load(policy_path)
            store, refs = root / "store", []
            for name, route, platform, channel, delivery, version in cases:
                package = root / name
                manifest = fixture(package, "fixture-" + name)
                manifest["format"] = 2
                manifest["artefacts"][0]["destination"] = "components/fixture-" + name + "/run.sh"
                manifest["verification"] = manifest["verification"][:1]
                manifest["verification"][0]["execution"] = {"kind": "local", "simulation": False, "operations": [], "settings": [],
                                                            "secrets": [], "resources": [], "assertions": [], "cleanup": None}
                for target, data in {**source_bytes, "deny-network.mjs": GUARD.encode()}.items():
                    path = package / target
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    path.chmod(0o644)
                    manifest["files"].append({"path": target, "executable": False})
                setting_names = ["expectedUpdateVersion", "updateChannel", "updateDeliveryOrigin", "updatePlatform", "updateReadOrigin"]
                if route.endswith("public"):
                    setting_names.append("updateUrl")
                if route.startswith("desktop-"):
                    setting_names += ["updateArchitecture", "updateSystemVersion"]
                provider = {"id": "actual-update-fixture", "root": "package", "argv": ["node", "--import", "./deny-network.mjs", "verification/update-runner.mjs", route],
                            "cwd": ".", "prepare": [], "tools": {"node": "26.5.0"}, "fixtures": ["web/test/fixtures/store-latest.json"],
                            "locks": [], "network": False, "timeoutSeconds": 30, "expectedExit": 0, "scope": "required-local",
                            "requirements": ["external:published-update-service"],
                            "execution": {"kind": "provider", "simulation": True, "operations": ["update-get"], "settings": sorted(setting_names),
                                          "secrets": ["updateInvitation"] if route.endswith("private") else [], "resources": [], "assertions": ASSERTIONS, "cleanup": None}}
                manifest["verification"] += [provider, {**deepcopy(provider), "id": "deployed-update-fixture", "scope": "deployed"}]
                write(package / "component.json", manifest)
                ref = pack(package, store)
                refs.append(ref)
                actual, _ = read_package(ref, store)
                release = {"format": 1, "role": "release", "keyId": "local-release", **ref,
                           "sourceTreeDigest": actual["identity"]["sourceTreeDigest"]}
                statements = store / "statements" / ref["digest"]
                statements.mkdir(parents=True)
                write(statements / "release.json", release)
                (statements / "release.sig").write_bytes(sign(release, "release", root / "keys/release.pem"))
            policy["trustedExecution"] = [ref["digest"] for ref in refs]
            write(policy_path, policy)
            reports = []
            for case, ref in zip(cases, refs):
                name, route, platform, channel, delivery, version = case
                settings = {"expectedUpdateVersion": version, "updatePlatform": platform, "updateChannel": channel,
                            "updateReadOrigin": "https://localhost:9443", "updateDeliveryOrigin": delivery}
                invitation = "https://localhost:9443/l/0123456789abcdef01234567"
                if route.endswith("public"):
                    settings["updateUrl"] = invitation
                if route.startswith("desktop-"):
                    settings.update(updateArchitecture="x64", updateSystemVersion="10")
                descriptor = {"format": 1, "id": name, "pathPlatform": "posix", "mode": "simulation", "simulationKind": "fixture",
                              "settings": settings, "resources": [], "secrets": {"updateInvitation": {"secretRef": "fixture-invitation", "version": "1"}} if route.endswith("private") else {}}
                context, request, state = root / (name + ".json"), root / (name + "-request.json"), root / (name + "-state")
                authorization = root / (name + "-authorization")
                write(context, descriptor)
                secret_file = root / (name + "-secrets.json")
                write(secret_file, {"format": 1, "values": {"fixture-invitation": {"version": "1", "value": invitation}}})
                execution_request(ref=ref, store=store, context=context, policy=policy_path, execution_state=state,
                                  expires_at=clock() + 600, out=request)
                authorize_execution(request, root / "keys/owner.pem", policy_path, authorization)
                report = review_package(ref, store, policy_path, True, execution_context=context, authorization=authorization,
                                        execution_state=state, secrets=secret_file if descriptor["secrets"] else None)
                self.assertEqual(report["summary"], {"required-local": "passed", "platform": "not-applicable", "deployed": "blocked"}, report)
                validate_report_evidence(report, review_bindings(ref, store), "review", store, policy_path, adoption=True)
                evidence = load(store / "execution-evidence" / (report["execution"]["evidenceDigest"] + ".json"))
                for suite in evidence["suites"]:
                    if suite["id"] != "unit":
                        self.assertEqual(suite["kind"], "simulation")
                        self.assertTrue(all(assertion["passed"] for assertion in suite["assertions"]))
                guardian = {"format": 1, "role": "guardian", "keyId": "local-guardian", **ref, "dependencies": [],
                            "previousReviewedDigest": None, "scope": ["deployed", "required-local"], "verdict": "accepted", "reportDigest": digest(canonical(report))}
                statements = store / "statements" / ref["digest"]
                write(statements / "guardian.json", guardian)
                (statements / "guardian.sig").write_bytes(sign(guardian, "guardian", root / "keys/guardian.pem"))
                verify_package(ref, store, policy_path)
                retained_context = store / "contexts" / (report["execution"]["contextDigest"] + ".json")
                original = retained_context.read_bytes()
                changed = load(retained_context)
                changed["settings"]["updateDeliveryOrigin"] = "https://substituted.example"
                write(retained_context, changed)
                with self.assertRaises(AepmError):
                    verify_package(ref, store, policy_path)
                retained_context.write_bytes(original)
                reports.append({"case": name, "ref": ref, "report": report, "evidence": evidence, "deliveryTamperRejected": True,
                                "realNetworkGuarded": True, "fixtureEndpointReadsPerSuite": 1})
            evidence_path = os.environ.get("AEPM_RECIPE_EVIDENCE")
            if evidence_path:
                preserved_store = Path(evidence_path + ".store").resolve()
                self.assertFalse(Path(evidence_path).exists(), "Preserve earlier evidence; choose a fresh output")
                self.assertFalse(preserved_store.exists(), "Preserve earlier signed store")
                shutil.copytree(store, preserved_store)
                write(preserved_store / "policy.json", policy)
                write(Path(evidence_path), {"format": 1, "sourceDigests": [{"source": str(paths[target].relative_to(workspace)),
                                                                           "destination": target, "digest": digest(data)} for target, data in sorted(source_bytes.items())],
                                           "store": str(preserved_store), "reviews": reports})
        if evidence_path:
            for ref in refs:
                verify_package(ref, preserved_store, preserved_store / "policy.json")


@unittest.skipUnless(os.environ.get("AEPM_RECIPE_RECHECK"), "Set AEPM_RECIPE_RECHECK for preserved signed evidence only")
class RetainedRecipeEvidenceTests(unittest.TestCase):
    def test_independent_signatures_after_temporary_keys_and_registry_removed(self):
        evidence = load(Path(os.environ["AEPM_RECIPE_RECHECK"]).resolve())
        store = Path(evidence["store"]).resolve()
        self.assertEqual(len(evidence["reviews"]), 6)
        for result in evidence["reviews"]:
            with self.subTest(case=result["case"]):
                verify_package(result["ref"], store, store / "policy.json")
                self.assertEqual(result["report"]["summary"]["required-local"], "passed")
                self.assertEqual(result["report"]["summary"]["deployed"], "blocked")
