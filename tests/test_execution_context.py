import contextlib
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from aepm.__main__ import main
from aepm.authorization import execution_request, authorize_execution
from aepm.bundle import pack, read_package
from aepm.environment import clock, claim_key
from aepm.io import load, write
from aepm.model import AepmError, canonical, digest
from aepm.test_identities import generate
from aepm.trust import sign, review_bindings, validate_report_evidence
from aepm.verification import review_package
from tests.core.test_core import fixture


SCRIPT = '''import json, os
from pathlib import Path
context=json.loads(Path(os.environ['AEPM_CONTEXT_FILE']).read_text())
values=json.loads(Path(os.environ['AEPM_SECRETS_FILE']).read_text())['values']
print(values['livekitKey']['value'])
assert 'AWS_SECRET_ACCESS_KEY' not in os.environ
assert set(context['settings']) == {'expectedUpdateVersion'}
assert not context['resources']
fixture=json.loads(Path('fixture.json').read_text())
matches=fixture['version']==context['settings']['expectedUpdateVersion']
assertions=[{'id':'version-match','passed':matches,'actual':matches}]
result={'format':1,'runId':context['runId'],'package':context['package'],'id':context['id'],
 'assertions':assertions,'artifacts':[],'resources':[],
 'cleanup':{'required':False,'attempted':False,'completed':True,'reason':''}}
Path(os.environ['AEPM_RESULT_FILE']).write_text(json.dumps(result,sort_keys=True,separators=(',',':')))
'''


class ExecutionContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.policy = generate(self.root / "keys")
        self.source, self.store = self.root / "source", self.root / "store"
        manifest = fixture(self.source)
        manifest["format"] = 2
        manifest["verification"] = manifest["verification"][:1]
        manifest["verification"][0]["execution"] = {"kind": "local", "simulation": False, "operations": [],
                                                       "settings": [], "secrets": [], "resources": [], "assertions": [], "cleanup": None}
        provider = deepcopy(manifest["verification"][0])
        provider.update(id="provider-fixture", argv=["python3", "check.py"], fixtures=["fixture.json"])
        provider["execution"] = {"kind": "provider", "simulation": True, "operations": [], "settings": ["expectedUpdateVersion"],
                                 "secrets": ["livekitKey"], "resources": [], "assertions": ["version-match"], "cleanup": None}
        manifest["verification"].append(provider)
        (self.source / "check.py").write_text(SCRIPT)
        write(self.source / "fixture.json", {"version": "1.2.3"})
        manifest["files"] += [{"path": "check.py", "executable": False}, {"path": "fixture.json", "executable": False}]
        write(self.source / "component.json", manifest)
        self.ref = pack(self.source, self.store)
        manifest, _ = read_package(self.ref, self.store)
        statement = {"format": 1, "role": "release", "keyId": "local-release", **self.ref,
                     "sourceTreeDigest": manifest["identity"]["sourceTreeDigest"]}
        statements = self.store / "statements" / self.ref["digest"]
        statements.mkdir(parents=True)
        write(statements / "release.json", statement)
        (statements / "release.sig").write_bytes(sign(statement, "release", self.root / "keys/release.pem"))
        policy = load(self.policy)
        policy["trustedExecution"] = [self.ref["digest"]]
        write(self.policy, policy)
        self.context = self.root / "context.json"
        write(self.context, {"format": 1, "id": "fixture", "pathPlatform": "posix", "mode": "simulation", "simulationKind": "fixture",
                             "settings": {"expectedUpdateVersion": "1.2.3", "maximumSeconds": 10}, "resources": [],
                             "secrets": {"livekitKey": {"secretRef": "synthetic", "version": "1"}}})
        self.secret_file = self.root / "secrets.json"
        write(self.secret_file, {"format": 1, "values": {"synthetic": {"version": "1", "value": "NEVER_RETAIN_SYNTHETIC_SECRET"}}})
        self.request, self.authorization, self.state = self.root / "request.json", self.root / "authorization", self.root / "state"

    def authorize(self):
        execution_request(ref=self.ref, store=self.store, context=self.context, policy=self.policy, execution_state=self.state,
                          expires_at=clock() + 600, out=self.request)
        authorize_execution(self.request, self.root / "keys/owner.pem", self.policy, self.authorization)

    def run_review(self):
        return review_package(self.ref, self.store, self.policy, True, execution_context=self.context,
                              authorization=self.authorization, execution_state=self.state, secrets=self.secret_file)

    def test_actual_fixture_execution_signed_binding_and_no_secret_logs(self):
        self.authorize()
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "DO_NOT_INHERIT"}):
            report = self.run_review()
        self.assertEqual(report["summary"]["required-local"], "passed", report)
        self.assertEqual(report["format"], 2)
        validate_report_evidence(report, review_bindings(self.ref, self.store), "review", self.store, self.policy, adoption=True)
        evidence = load(self.store / "execution-evidence" / (report["execution"]["evidenceDigest"] + ".json"))
        observed = next(item for item in evidence["suites"] if item["id"] == "provider-fixture")
        self.assertTrue(observed["checkStarted"])
        self.assertEqual(observed["kind"], "simulation")
        self.assertEqual(observed["assertions"], [{"id": "version-match", "passed": True, "actual": True}])
        for path in self.store.rglob("*"):
            if path.is_file() and path.suffix != ".tar":
                self.assertNotIn(b"NEVER_RETAIN_SYNTHETIC_SECRET", path.read_bytes())
        def guarded_load(path):
            if Path(path) == self.secret_file:
                raise AssertionError("Replay reached secret loader")
            return load(path)

        with patch("aepm.environment.load", guarded_load), patch("aepm.contextual.prerequisites", side_effect=AssertionError("Replay reached probe")), self.assertRaisesRegex(AepmError, "execution-replayed"):
            self.run_review()

    def test_missing_context_blocks_without_fake_pass(self):
        report = review_package(self.ref, self.store, self.policy, True)
        self.assertEqual(report["summary"]["required-local"], "blocked")
        self.assertEqual(next(item for item in report["suites"] if item["id"] == "provider-fixture")["reason"], "context-missing")

    def test_changed_context_and_request_evidence_fail_before_claim(self):
        self.authorize()
        changed = load(self.context)
        changed["settings"]["expectedUpdateVersion"] = "9.9.9"
        write(self.context, changed)
        with self.assertRaisesRegex(AepmError, "authorization-binding"):
            self.run_review()
        self.assertFalse(list((self.state / "claims").iterdir()))
        request = load(self.request)
        request["suiteSetDigest"] = "f" * 64
        write(self.request, request)
        with self.assertRaisesRegex(AepmError, "request-binding"):
            authorize_execution(self.request, self.root / "keys/owner.pem", self.policy, self.root / "other")

    def test_expired_and_missing_secret_fail(self):
        self.authorize()
        statement = load(self.authorization / "authorization.json")
        with patch("aepm.environment.clock", return_value=statement["expiresAt"]), self.assertRaises(AepmError):
            self.run_review()
        write(self.secret_file, {"format": 1, "values": {}})
        report = self.run_review()
        self.assertEqual(next(item for item in report["suites"] if item["id"] == "provider-fixture")["reason"], "secret-unavailable")

    def test_deployed_simulation_never_reports_live_pass(self):
        self.authorize()
        from aepm.contextual import execute
        from aepm.environment import Execution
        binding = review_bindings(self.ref, self.store)
        execution = Execution({**binding, "context": "review"}, self.policy, self.store,
                              execution_context=self.context, authorization=self.authorization, execution_state=self.state, secrets=self.secret_file)
        suite = next(item for item in binding["suites"] if item["id"] == "provider-fixture")
        suite = {**suite, "scope": "deployed"}
        result, evidence = execute(suite, self.source, False, self.store / "logs", execution)
        self.assertEqual((result["status"], result["reason"]), ("blocked", "simulation-not-live"))
        self.assertTrue(evidence["assertions"][0]["passed"])

    def test_cli_request_authorization_roundtrip(self):
        def command(arguments):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(list(map(str, arguments)))
            value = json.loads(output.getvalue())
            self.assertEqual(code, 0, value)
            return value
        command(["execution-request", "--review", self.ref["digest"], "--store", self.store, "--context", self.context,
                 "--policy", self.policy, "--execution-state", self.state, "--expires-at", clock() + 600, "--out", self.request])
        command(["authorize-execution", self.request, "--key", self.root / "keys/owner.pem", "--policy", self.policy, "--out", self.authorization])
        result = command(["review", self.ref["digest"], "--store", self.store, "--policy", self.policy, "--trusted",
                          "--context", self.context, "--authorization", self.authorization, "--execution-state", self.state, "--secrets", self.secret_file])
        self.assertEqual(result["result"]["format"], 2)

    def test_failed_real_assertion_and_profile_cleanup_failure(self):
        context = load(self.context)
        context["settings"]["expectedUpdateVersion"] = "9.9.9"
        write(self.context, context)
        self.authorize()
        report = self.run_review()
        result = next(item for item in report["suites"] if item["id"] == "provider-fixture")
        self.assertEqual((result["status"], result["reason"]), ("failed", "assertion-failed"))

    def test_profile_cleanup_failure_cannot_pass(self):
        import shutil
        original = shutil.rmtree

        def refuse_profile(path, *args, **kwargs):
            if Path(path).name == "profiles":
                raise PermissionError("synthetic failure")
            return original(path, *args, **kwargs)

        self.authorize()
        with patch("aepm.contextual.shutil.rmtree", refuse_profile):
            report = self.run_review()
        self.assertTrue(all(item["status"] == "failed" and item["reason"] == "cleanup-failed" for item in report["suites"]))
        for suite in report["suites"]:
            events = load(self.store / "logs" / (suite["logDigest"] + ".json"))
            retained = [Path(event["path"]) for event in events if event["step"] == "retained-private-root"]
            self.assertEqual(len(retained), 1)
            self.assertTrue((retained[0] / "protocol/profiles").exists())
            self.assertFalse((retained[0] / "protocol/secrets.json").exists())
            original(retained[0])

    def test_concurrent_invocations_consume_authorization_once(self):
        self.authorize()

        def attempt():
            try:
                return self.run_review()["summary"]["required-local"]
            except AepmError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(2)))
        self.assertCountEqual(outcomes, ["passed", "execution-replayed"])

    def test_authorized_extra_operation_rejects_before_claim(self):
        self.authorize()
        statement = load(self.authorization / "authorization.json")
        statement["suites"][0]["operations"] = ["update-get"]
        write(self.authorization / "authorization.json", statement)
        (self.authorization / "authorization.sig").write_bytes(sign(statement, "owner", self.root / "keys/owner.pem"))
        with self.assertRaisesRegex(AepmError, "authorization-denied"):
            self.run_review()
        self.assertFalse(list((self.state / "claims").iterdir()))

    def test_expiry_after_real_execution_prevents_completion(self):
        from aepm import contextual
        self.authorize()
        statement = load(self.authorization / "authorization.json")
        actual_run, state = contextual.run, {"now": clock()}

        def expire(argv, *args, **kwargs):
            result = actual_run(argv, *args, **kwargs)
            if "check.py" in argv:
                state["now"] = statement["expiresAt"]
            return result

        with patch("aepm.environment.clock", side_effect=lambda: state["now"]), patch("aepm.contextual.run", expire), self.assertRaisesRegex(AepmError, "authorization-expired"):
            self.run_review()
        self.assertEqual(len(list((self.state / "claims").iterdir())), 1)
        self.assertFalse(list((self.state / "completions").iterdir()))
        self.assertTrue(list((self.store / "execution-evidence").iterdir()))

    def test_completion_tampering_rejected_by_shared_adoption(self):
        self.authorize()
        report = self.run_review()
        statement = load(self.authorization / "authorization.json")
        path = self.state / "completions" / (claim_key(statement) + ".json")
        value = load(path)
        value["reportDigest"] = "f" * 64
        write(path, value)
        with self.assertRaises(AepmError):
            validate_report_evidence(report, review_bindings(self.ref, self.store), "review", self.store, self.policy, adoption=True)
