"""Signed subset fixtures; no simulator, emulator or provider is executed."""

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aepm.__main__ import main
from aepm.authorization import execution_request, authorize_execution
from aepm.bundle import pack, read_package
from aepm.environment import clock, describe_resource
from aepm.io import load, write
from aepm.model import AepmError, canonical, digest
from aepm.test_identities import generate
from aepm.trust import publish_release, publish_review, review_bindings, sign, validate_report_evidence
from aepm.verification import review_package
from tests.core.test_core import fixture


BUILD = '''import hashlib,json,os,py_compile
from pathlib import Path
c=json.loads(Path(os.environ['AEPM_CONTEXT_FILE']).read_text())
assert c['operations']==['native-build'] and not c['resources']
py_compile.compile('test.py', cfile='built.pyc', doraise=True)
result={'format':1,'runId':c['runId'],'package':c['package'],'id':c['id'],
 'assertions':[{'id':'build-produced','passed':True,'actual':True}],
 'artifacts':[{'path':'built.pyc','digest':hashlib.sha256(Path('built.pyc').read_bytes()).hexdigest(),'architecture':None}],
 'resources':[],'cleanup':{'required':False,'attempted':False,'completed':True,'reason':''}}
Path(os.environ['AEPM_RESULT_FILE']).write_text(json.dumps(result,sort_keys=True,separators=(',',':')))
'''


class SuiteSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.policy = generate(self.root / "keys")
        source = self.root / "source"
        manifest = fixture(source)
        manifest["format"] = 2
        unit = manifest["verification"][0]
        unit["execution"] = dict(kind="local", simulation=False, operations=[], settings=[], secrets=[], resources=[], assertions=[], cleanup=None)
        build = deepcopy(unit)
        build.update(id="build", argv=["python3", "build.py"], scope="platform")
        build["execution"].update(kind="native", operations=["native-build"], assertions=["build-produced"])
        runtime = deepcopy(unit)
        runtime.update(id="runtime", argv=["python3", "-c", "raise AssertionError('Runtime must not execute')"], scope="platform",
                       requirements=["external:android-test-environment"])
        runtime["execution"] = dict(kind="native", simulation=False, operations=["create-temporary-emulator", "native-test"],
                                    settings=["androidDeviceProfile", "androidSystemImage"], secrets=[],
                                    resources=[dict(id="androidJavaHome", required=True, access="read-only"), dict(id="androidSdk", required=True, access="copy")],
                                    assertions=["tests-discovered", "tests-executed", "tests-passed"],
                                    cleanup=dict(argv=["python3", "-c", "raise AssertionError('Cleanup must not execute')"], cwd=".", timeoutSeconds=10))
        provider = deepcopy(unit)
        provider.update(id="provider", scope="deployed")
        provider["execution"].update(kind="provider", assertions=["response-valid"])
        manifest["verification"] = [unit, build, runtime, provider]
        (source / "build.py").write_text(BUILD)
        manifest["files"].append(dict(path="build.py", executable=False))
        write(source / "component.json", manifest)
        self.store = self.root / "store"
        self.ref = pack(source, self.store)
        actual, _ = read_package(self.ref, self.store)
        statements = self.store / "statements" / self.ref["digest"]
        statements.mkdir(parents=True)
        publish_release(self.store, self.ref, self.root / "keys/release.pem")
        policy = load(self.policy)
        policy["trustedExecution"] = [self.ref["digest"]]
        write(self.policy, policy)
        resources = []
        for identifier in ("androidJavaHome", "androidSdk"):
            path = self.root / identifier
            path.mkdir()
            resources.append(describe_resource(identifier, path))
        self.context = self.root / "context.json"
        write(self.context, dict(format=1, id="native-fixture", pathPlatform="posix", mode="local", simulationKind=None,
                                 settings=dict(androidDeviceProfile="pixel_6", androidSystemImage="system-images;android-36;google_apis;arm64-v8a"),
                                 resources=resources, secrets={}))
        self.request, self.state, self.authorization = self.root / "request.json", self.root / "state", self.root / "authorization"

    def pairs(self, *identifiers):
        return [dict(package=self.ref["digest"], id=value) for value in identifiers]

    def request_authority(self, selection=None):
        return execution_request(ref=self.ref, store=self.store, context=self.context, policy=self.policy,
                                 execution_state=self.state, expires_at=clock() + 600, out=self.request, selected_pairs=selection)

    def test_build_only_with_runtime_settings_blocks_runtime_for_absent_authority(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(list(map(str, ["execution-request", "--review", self.ref["digest"], "--store", self.store,
                                      "--context", self.context, "--policy", self.policy, "--execution-state", self.state,
                                      "--expires-at", clock() + 600, "--out", self.request, "--suite", self.ref["digest"] + ":build"])))
        self.assertEqual(code, 0, output.getvalue())
        request = load(self.request)
        self.assertEqual([grant["id"] for grant in request["suites"]], ["build"])
        self.assertEqual(request["suites"][0]["operations"], ["native-build"])
        self.assertEqual(load(Path(str(self.request) + ".evidence/selection.json")), {"format": 1, "suites": self.pairs("build")})
        authorize_execution(self.request, self.root / "keys/owner.pem", self.policy, self.authorization)
        from aepm import contextual
        actual_probe = contextual.prerequisites

        def probe(suite, *args, **kwargs):
            self.assertNotEqual(suite["id"], "runtime", "Unselected runtime reached its probe")
            return actual_probe(suite, *args, **kwargs)

        with patch("aepm.contextual.prerequisites", probe):
            report = review_package(self.ref, self.store, self.policy, True, execution_context=self.context,
                                    authorization=self.authorization, execution_state=self.state)
        results = {suite["id"]: suite for suite in report["suites"]}
        self.assertEqual(set(results), {"unit", "build", "runtime", "provider"})
        self.assertEqual(results["build"]["status"], "passed")
        self.assertEqual((results["runtime"]["status"], results["runtime"]["reason"]), ("blocked", "authorization-denied"))
        binding = review_bindings(self.ref, self.store)
        self.assertEqual(report["suiteSetDigest"], binding["suiteSetDigest"])
        validate_report_evidence(report, binding, "review", self.store, self.policy, adoption=True)

    def test_invalid_selections_create_no_outputs_or_registry(self):
        for selection in ([], self.pairs("build", "build"), self.pairs("unknown"), self.pairs("unit"), self.pairs("provider"),
                          [dict(package="not-a-digest", id="build")]):
            with self.subTest(selection=selection), self.assertRaises(AepmError):
                self.request_authority(selection)
            self.assertFalse(self.request.exists())
            self.assertFalse(Path(str(self.request) + ".evidence").exists())
            self.assertFalse(self.state.exists())

    def test_selection_request_and_grant_tampering_reject(self):
        self.request_authority(self.pairs("build"))
        selection_path = Path(str(self.request) + ".evidence/selection.json")
        original = load(self.request)
        mutations = [lambda: write(selection_path, {"format": 1, "suites": self.pairs("runtime")}),
                     lambda: write(self.request, {**original, "suites": []}),
                     lambda: write(self.request, {**original, "suites": [{**original["suites"][0], "operations": ["create-temporary-emulator", "native-build"]}]})]
        for mutation in mutations:
            write(selection_path, {"format": 1, "suites": self.pairs("build")})
            write(self.request, original)
            mutation()
            with self.assertRaises(AepmError):
                authorize_execution(self.request, self.root / "keys/owner.pem", self.policy, self.authorization)
            self.assertFalse(self.authorization.exists())

    def test_absent_selector_selects_all_mode_compatible_suites(self):
        self.request_authority()
        self.assertFalse(Path(str(self.request) + ".evidence/selection.json").exists())
        self.assertEqual([grant["id"] for grant in load(self.request)["suites"]], ["build", "runtime"])
        authorize_execution(self.request, self.root / "keys/owner.pem", self.policy, self.authorization)
