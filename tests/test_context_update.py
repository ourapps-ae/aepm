from copy import deepcopy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from aepm.application import assemble, requirements
from aepm.authorization import execution_request, authorize_execution
from aepm.bundle import pack, read_package, resolve
from aepm.environment import clock
from aepm.io import load, snapshot, write
from aepm.model import AepmError, canonical, digest
from aepm.test_identities import generate
from aepm.trust import EXECUTION_AUTHORIZATION, publish_release, publish_review, verify, verify_package
from aepm.update import propose, approve, apply
from aepm.verification import review_package
from tests.test_application import source
from tests.test_execution_context import SCRIPT


class ContextUpdateTests(unittest.TestCase):
    def test_preview_request_approved_update_and_expired_adoption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            store = root / "store"
            policy_path = generate(root / "keys")
            policy = load(policy_path)
            refs = []
            for name, version, recipe in (("sample", "0.1.0", False), ("sample", "0.1.1", False), ("recipe", "0.1.0", True)):
                directory = root / (name + version)
                manifest = source(directory, name, version, recipe)
                if recipe:
                    manifest["format"] = 2
                    for suite in manifest["verification"]:
                        suite["execution"] = {"kind": "local", "simulation": False, "operations": [], "settings": [], "secrets": [],
                                              "resources": [], "assertions": [], "cleanup": None}
                    manifest["verification"][1]["execution"].update(kind="native", assertions=["build-produced"])
                    provider = deepcopy(manifest["verification"][-1])
                    provider.update(id="context-fixture", argv=["python3", "check.py"], fixtures=["fixture.json"])
                    provider["execution"] = {"kind": "provider", "simulation": True, "operations": [], "settings": ["expectedUpdateVersion"],
                                             "secrets": ["livekitKey"], "resources": [], "assertions": ["version-match"], "cleanup": None}
                    manifest["verification"].append(provider)
                    (directory / "check.py").write_text(SCRIPT)
                    write(directory / "fixture.json", {"version": "1.2.3"})
                    for name_file in ("check.py", "fixture.json"):
                        manifest["files"].append({"path": name_file, "executable": False})
                        manifest["artefacts"].append({"source": name_file, "destination": name_file, "template": False, "executable": False})
                    write(directory / "component.json", manifest)
                ref = pack(directory, store)
                refs.append(ref)
                actual, _ = read_package(ref, store)
                statements = store / "statements" / ref["digest"]
                statements.mkdir(parents=True)
                publish_release(store, ref, root / "keys/release.pem")
            policy["trustedExecution"] = [ref["digest"] for ref in refs]
            write(policy_path, policy)
            for ref in refs:
                report = review_package(ref, store, policy_path, True)
                self.assertEqual(report["summary"]["required-local"], "passed", report)
                publish_review(store, ref, report, root / "keys/guardian.pem")
                verify_package(ref, store, policy_path)
            definition = {"format": 1, "id": "context-app", "title": "Context App", "recipe": {"name": "ourapps-ae/recipe", "version": "0.1.0"},
                          "components": [{"id": "sample", "name": "ourapps-ae/sample", "version": "0.1.0", "configuration": {}}],
                          "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []}, "updatePolicy": "patch"}
            lock = resolve(requirements(definition), store / "catalogue.json", definition["id"], digest(canonical(definition)))
            app = root / "application"
            assemble(definition, lock, store, app, policy_path)
            definition["components"][0]["version"] = "0.1.1"
            lock = resolve(requirements(definition), store / "catalogue.json", definition["id"], digest(canonical(definition)))
            preview = root / "preview"
            assemble(definition, lock, store, preview, policy_path)
            context, secret_file = root / "context.json", root / "secrets.json"
            write(context, {"format": 1, "id": "fixture", "pathPlatform": "posix", "mode": "simulation", "simulationKind": "fixture",
                            "settings": {"expectedUpdateVersion": "1.2.3"}, "resources": [],
                            "secrets": {"livekitKey": {"secretRef": "test-key", "version": "1"}}})
            write(secret_file, {"format": 1, "values": {"test-key": {"version": "1", "value": "SYNTHETIC"}}})
            request, authorization, state = root / "request.json", root / "authorization.dsse.json", root / "state"
            execution_request(app=preview, context=context, policy=policy_path, execution_state=state, expires_at=clock() + 600, out=request)
            authorize_execution(request, root / "keys/owner.pem", policy_path, authorization)
            proposal = propose(app, definition, store, policy_path, True, execution_context=context,
                               authorization=authorization, execution_state=state, secrets=secret_file)
            proposal_path = root / "proposal.json"
            write(proposal_path, proposal)
            approval = approve(proposal_path, root / "keys/owner.pem", policy_path)
            before = snapshot(app)
            expires = verify(authorization.read_bytes(), "owner", policy_path, EXECUTION_AUTHORIZATION)[0]["predicate"]["expiresAt"]
            with patch("aepm.trust.time.time", return_value=expires), self.assertRaises(AepmError):
                apply(app, proposal_path, approval, policy_path)
            self.assertEqual(snapshot(app), before)
            with self.assertRaisesRegex(AepmError, "statement-role"):
                apply(app, proposal_path, authorization, policy_path)
            result = apply(app, proposal_path, approval, policy_path)
            self.assertEqual(result["lock"], lock)
