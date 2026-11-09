"""Real temporary signatures/archives with synthetic execution observations."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from aepm.bundle import extract_review, pack, validate_extracted_mode, validate_windows_paths
from aepm.model import (AepmError, canonical, digest, execution_document, validate_absolute_path,
                        validate_component, validate_execution_assertions,
                        validate_execution_context)
from aepm.trust import (review_bindings, sign, validate_report_evidence,
                        validate_statement, verify, verify_package)
from tests.core import test_core as core


def local_execution():
    return {"kind": "local", "simulation": False, "operations": [], "settings": [],
            "secrets": [], "resources": [], "assertions": [], "cleanup": None}


class ExecutionEvidenceTests(unittest.TestCase):
    setUpClass = classmethod(core.CoreTests.setUpClass.__func__)
    setUp = core.CoreTests.setUp
    release = core.CoreTests.release
    statement = core.CoreTests.statement
    guardian = core.CoreTests.guardian
    update = core.CoreTests.update

    def build(self, *, windows=False, android=False, authorized=True):
        self.component["format"] = 2
        for suite in self.component["verification"]:
            suite["execution"] = local_execution()
        native = self.component["verification"][1]
        native["requirements"] = ["external:windows-host"] if windows else []
        native["execution"].update(kind="native", operations=["native-test"],
                                   settings=["windowsArchitecture"] if windows else [],
                                   assertions=["tests-discovered", "tests-executed", "tests-passed"])
        if android:
            native["requirements"] = ["external:android-test-environment"]
            native["execution"]["resources"] = [
                {"id": "androidJavaHome", "required": True, "access": "read-only"},
                {"id": "androidSdk", "required": True, "access": "copy"},
            ]
        self.update()
        self.ref = pack(self.source, self.store)
        self.release(self.ref)
        self.binding = review_bindings(self.ref, self.store)
        self.run_id = "1" * 64
        self.registry = self.root / "execution-state"
        self.descriptor = {"format": 1, "id": "fixture", "pathPlatform": "windows" if windows else "posix", "mode": "local",
                           "simulationKind": None, "settings": {"windowsArchitecture": "x64"} if windows else {}, "resources": [], "secrets": {}}
        if android:
            self.descriptor["resources"] = [{"id": name, "kind": "directory", "path": "/absent/" + name, "digest": "a" * 64, "executables": []}
                                            for name in ("androidJavaHome", "androidSdk")]
        self.context_digest = self.retain("contexts", self.descriptor) if authorized else None
        self.authorization = {"format": 2, "role": "owner", "keyId": "owner-test", "purpose": "verification-authorization",
                              "runId": self.run_id, "contextDigest": self.context_digest, "policyDigest": digest(canonical(json.loads(self.policy.read_text()))),
                              "executionState": {"path": "C:\\proof\\execution-state" if windows else str(self.registry), "id": "2" * 64, "pathPlatform": self.descriptor["pathPlatform"]},
                              "context": "review", **{k: self.binding[k] for k in ("lockDigest", "assemblyDigest", "suiteSetDigest")},
                              "suites": [{"package": self.ref["digest"], "id": "native", "operations": ["native-test"], "origins": [],
                                          "settings": ["windowsArchitecture"] if windows else [], "secrets": [], "resources": []}],
                              "issuedAt": 1000, "expiresAt": 1100}
        if android:
            self.authorization["suites"][0]["resources"] = ["androidJavaHome", "androidSdk"]
        authorization_digest = self.retain_authorization() if authorized else None
        self.evidence = {"format": 1, "runId": self.run_id, "contextDigest": self.context_digest, "authorizationDigest": authorization_digest,
                         **{k: self.binding[k] for k in ("lockDigest", "assemblyDigest", "suiteSetDigest")},
                         "startedAt": 1001, "completedAt": 1004, "suites": []}
        results = []
        for suite in self.binding["suites"]:
            is_native = suite["id"] == "native"
            started = authorized or not is_native
            assertions = [{"id": key, "passed": started, "actual": (0 if key == "tests-passed" else 1) if started else None}
                          for key in suite["execution"]["assertions"]]
            prerequisites = [{"id": "external:windows-host", "status": "passed" if started else "blocked", "reason": "" if started else "context-missing",
                              "observations": {"platform": "win32", "architecture": "x64", "osVersion": "10.0", "containment": "job-object"} if started else None}] if windows and is_native else []
            if android and is_native:
                prerequisites = [{"id": "external:android-test-environment", "status": "passed" if started else "blocked", "reason": "" if started else "context-missing",
                                  "observations": {"sdkApi": 34, "javaVersion": "26.0.1", "systemImage": None, "deviceProfile": None, "available": True} if started else None}]
            record = {"package": self.ref["digest"], "id": suite["id"], "kind": ("native" if is_native else "local") if started else "not-run",
                      "startedAt": 1002 if started else None, "completedAt": 1003 if started else None,
                      "phase": "complete" if started else "not-started", "checkStarted": started, "prerequisites": prerequisites,
                      "resources": [], "assertions": assertions, "artifacts": [], "ownedResources": [],
                      "cleanup": {"required": False, "attempted": False, "completed": True, "reason": ""}}
            if android and is_native:
                record["resources"] = [{"id": name, "digest": "a" * 64 if started else None} for name in ("androidJavaHome", "androidSdk")]
            self.evidence["suites"].append(record)
            results.append({"package": self.ref["digest"], "id": suite["id"], "scope": suite["scope"], "status": "passed" if started else "blocked",
                            "exitCode": 0 if started else None, "seconds": 1, "reason": "" if started else "context-missing", "logDigest": digest(b"")})
        self.report = {"format": 2, "context": "review", **{k: self.binding[k] for k in ("lockDigest", "assemblyDigest", "packages", "suiteSetDigest")},
                       "suites": results, "summary": {"required-local": "passed", "platform": "passed" if authorized else "blocked", "deployed": "not-applicable"},
                       "execution": {"runId": self.run_id, "mode": "local", "simulationKind": None, "contextDigest": self.context_digest,
                                     "authorizationDigest": authorization_digest, "evidenceDigest": "0" * 64, "startedAt": 1001, "completedAt": 1004}}
        self.publish()

    def retain(self, directory, value):
        data = canonical(value)
        identifier = digest(data)
        target = self.store / directory
        target.mkdir(parents=True, exist_ok=True)
        (target / (identifier + ".json")).write_bytes(data)
        return identifier

    def retain_authorization(self):
        identifier = self.retain("authorizations", self.authorization)
        (self.store / "authorizations" / (identifier + ".sig")).write_bytes(sign(self.authorization, "owner", self.root / "owner.pem"))
        return identifier

    def publish(self):
        self.report["execution"]["evidenceDigest"] = self.retain("execution-evidence", self.evidence)

    def check(self, *, adoption=False, now=1050):
        return validate_report_evidence(self.report, self.binding, "review", self.store, self.policy, adoption=adoption, now=now)

    def completion(self):
        self.registry.mkdir(exist_ok=True)
        (self.registry / "registry.json").write_bytes(canonical({"format": 1, "id": "2" * 64}))
        key = digest(canonical({"keyId": "owner-test", "runId": self.run_id}))
        claim = {"format": 1, "keyId": "owner-test", "runId": self.run_id,
                 "authorizationDigest": self.report["execution"]["authorizationDigest"],
                 **{k: self.authorization[k] for k in ("contextDigest", "policyDigest", "lockDigest", "assemblyDigest", "suiteSetDigest")}, "claimedAt": 1001}
        completion = {"format": 1, "keyId": "owner-test", "runId": self.run_id,
                      "authorizationDigest": self.report["execution"]["authorizationDigest"], "reportDigest": digest(canonical(self.report)),
                      "evidenceDigest": self.report["execution"]["evidenceDigest"], "completedAt": 1004}
        for directory, value in (("claims", claim), ("completions", completion)):
            (self.registry / directory).mkdir(exist_ok=True)
            (self.registry / directory / (key + ".json")).write_bytes(canonical(value))
        return key

    def test_real_archive_signatures_and_format_one_report(self):
        self.build()
        self.assertIs(self.check(), self.report)
        self.guardian(self.ref, self.report)
        verify_package(self.ref, self.store, self.policy)
        extract_review(self.ref, self.store, self.root / "extracted", self.policy)
        ordinary_source = self.root / "ordinary"
        core.fixture(ordinary_source, "ordinary")
        ordinary_ref = pack(ordinary_source, self.store)
        release = self.release(ordinary_ref)
        signature = sign(release, "release", self.root / "release.pem")
        self.assertEqual(verify(canonical(release), signature, "release", self.policy), release)
        ordinary_report = core.CoreTests.report(self, ordinary_ref)
        self.guardian(ordinary_ref, ordinary_report)
        verify_package(ordinary_ref, self.store, self.policy)
        binding = review_bindings(ordinary_ref, self.store)
        self.assertIs(validate_report_evidence(ordinary_report, binding, "review", None, None), ordinary_report)

    def test_owner_domain_and_purpose_separation(self):
        self.build()
        signature = sign(self.authorization, "owner", self.root / "owner.pem")
        self.assertEqual(verify(canonical(self.authorization), signature, "owner", self.policy), self.authorization)
        with self.assertRaises(AepmError):
            verify(canonical(self.authorization), signature, "guardian", self.policy)
        bad = {**self.authorization, "purpose": "update-approval"}
        with self.assertRaises(AepmError):
            sign(bad, "owner", self.root / "owner.pem")
        from aepm.trust import _crypto
        import base64
        wrong_domain = base64.b64decode(_crypto("sign", self.keys["owner"]["privateKey"], b"aepm/owner/1\n" + canonical(self.authorization)))
        with self.assertRaises(AepmError):
            verify(canonical(self.authorization), wrong_domain, "owner", self.policy)
        with self.assertRaises(AepmError):
            validate_statement(self.authorization, "release")

    def test_report_downgrade_and_missing_evidence(self):
        self.build()
        stripped = copy.deepcopy(self.report)
        stripped["format"] = 1
        del stripped["execution"]
        with self.assertRaisesRegex(AepmError, "report-downgrade"):
            validate_report_evidence(stripped, self.binding, "review", None, None)
        with self.assertRaisesRegex(AepmError, "evidence-required"):
            validate_report_evidence(self.report, self.binding, "review", None, None)

    def test_no_context_external_checks_stay_blocked(self):
        self.build(authorized=False)
        self.check()
        self.evidence["suites"][0]["kind"] = "native"
        self.publish()
        with self.assertRaises(AepmError):
            self.check()

    def test_exact_suite_and_assertion_coverage(self):
        self.build()
        original = copy.deepcopy(self.evidence)
        for mutate in (
            lambda e: e["suites"].pop(),
            lambda e: e["suites"].append(copy.deepcopy(e["suites"][0])),
            lambda e: e["suites"][0]["assertions"].pop(),
            lambda e: e["suites"][0]["assertions"].append({"id": "window-live", "passed": True, "actual": True}),
            lambda e: e["suites"][0]["assertions"][0].update(actual=0),
            lambda e: e["suites"][0]["assertions"][0].update(actual=True),
            lambda e: e["suites"][0].update(unexpected=True),
        ):
            self.evidence = copy.deepcopy(original)
            mutate(self.evidence)
            self.publish()
            with self.subTest(mutate=mutate), self.assertRaises(AepmError):
                self.check()

    def test_altered_bindings_and_canonical_documents(self):
        self.build()
        for key in ("lockDigest", "assemblyDigest", "suiteSetDigest", "contextDigest", "authorizationDigest"):
            original = self.evidence[key]
            self.evidence[key] = "f" * 64
            self.publish()
            with self.subTest(key=key), self.assertRaises(AepmError):
                self.check()
            self.evidence[key] = original
        self.publish()
        context_path = self.store / "contexts" / (self.context_digest + ".json")
        context_path.write_bytes(context_path.read_bytes() + b" ")
        with self.assertRaisesRegex(AepmError, "evidence-digest"):
            self.check()

    def test_historical_windows_paths_on_posix_and_adoption_host(self):
        self.build(windows=True)
        self.check(now=2000)
        self.guardian(self.ref, self.report)
        verify_package(self.ref, self.store, self.policy)
        if os.name != "nt":
            with self.assertRaisesRegex(AepmError, "unsupported-host"):
                self.check(adoption=True)
        for path in ("C:relative", "\\root-relative", "C:\\proof\\..\\state", "\\\\server\\share", "C:\\proof\\file:stream", "c:\\proof", "C:\\proof\\CON"):
            with self.subTest(path=path), self.assertRaises(AepmError):
                validate_absolute_path(path, "windows")
        self.assertEqual(validate_absolute_path("C:\\", "windows"), "C:\\")

    def test_completed_registry_and_expired_adoption(self):
        self.build()
        key = self.completion()
        self.check(adoption=True)
        self.check(now=2000)
        with self.assertRaisesRegex(AepmError, "authorization-expired"):
            self.check(adoption=True, now=2000)
        completion_path = self.registry / "completions" / (key + ".json")
        value = json.loads(completion_path.read_text())
        for field in ("reportDigest", "evidenceDigest", "authorizationDigest", "runId", "keyId", "completedAt"):
            changed = {**value, field: 1005 if field == "completedAt" else "f" * 64}
            completion_path.write_bytes(canonical(changed))
            with self.subTest(field=field), self.assertRaises(AepmError):
                self.check(adoption=True)
        completion_path.unlink()
        with self.assertRaises(AepmError):
            self.check(adoption=True)

    def test_registry_replacement_claim_and_future_time(self):
        self.build()
        key = self.completion()
        claim = self.registry / "claims" / (key + ".json")
        data = json.loads(claim.read_text())
        claim.write_bytes(canonical({**data, "claimedAt": 1002}))
        with self.assertRaisesRegex(AepmError, "claim-binding"):
            self.check(adoption=True)
        claim.write_bytes(canonical(data))
        (self.registry / "registry.json").write_bytes(canonical({"format": 1, "id": "f" * 64}))
        with self.assertRaisesRegex(AepmError, "registry-binding"):
            self.check(adoption=True)
        with self.assertRaises(AepmError):
            self.check(now=900)

    def test_incomplete_cleanup_and_substituted_ownership(self):
        self.build()
        original = copy.deepcopy(self.evidence)
        for owned in (
            {"kind": "process", "id": "123", "namespace": "f" * 64, "createdByRunId": self.run_id, "created": True, "cleaned": True},
            {"kind": "provider-room", "id": "unowned", "namespace": self.run_id, "createdByRunId": self.run_id, "created": True, "cleaned": True},
        ):
            self.evidence = copy.deepcopy(original)
            self.evidence["suites"][0]["ownedResources"] = [owned]
            self.evidence["suites"][0]["cleanup"] = {"required": True, "attempted": True, "completed": True, "reason": ""}
            self.publish()
            with self.assertRaises(AepmError):
                self.check()
        self.evidence = original
        self.evidence["suites"][0]["cleanup"] = {"required": True, "attempted": True, "completed": False, "reason": "cleanup-failed"}
        self.publish()
        with self.assertRaisesRegex(AepmError, "evidence-verdict"):
            self.check()

    def test_simulation_cannot_pass_platform_scope(self):
        self.component["verification"][1]["execution"] = {}
        self.build()
        # A claimed simulation contradicts the signed native declaration and descriptor.
        self.evidence["suites"][0]["kind"] = "simulation"
        self.publish()
        with self.assertRaisesRegex(AepmError, "execution-kind"):
            self.check()

    def test_assertions_are_typed_and_process_termination_is_runner_owned(self):
        placeholder = [{"id": "process-tree-terminated", "passed": False, "actual": None}]
        validate_execution_assertions(placeholder, ["process-tree-terminated"], helper=True)
        claimed = [{"id": "process-tree-terminated", "passed": True, "actual": True}]
        with self.assertRaisesRegex(AepmError, "runner-owned-assertion"):
            validate_execution_assertions(claimed, ["process-tree-terminated"], helper=True)
        validate_execution_assertions(claimed, ["process-tree-terminated"])

    def test_closed_context_and_declaration_schemas(self):
        self.build()
        for mutate in (lambda c: c.update(extra=1), lambda c: c["settings"].update(maximumSeconds=True),
                       lambda c: c["settings"].update(livekitUrl="https://provider.example"),
                       lambda c: c["secrets"].update(livekitKey={"secretRef": "key", "version": "one", "value": "hidden"})):
            value = copy.deepcopy(self.descriptor)
            mutate(value)
            with self.assertRaises(AepmError):
                validate_execution_context(value)
        original = copy.deepcopy(self.component)
        for mutate in (lambda e: e.update(extra=True), lambda e: e.update(assertions=[]),
                       lambda e: e.update(operations=["native-test", "native-test"]),
                       lambda e: e.update(assertions=["room-deleted", "tests-discovered", "tests-executed", "tests-passed"]),
                       lambda e: e.update(resources=[{"id": "androidSdk", "required": False, "access": "read-only"}]),
                       lambda e: e.update(operations=["create-temporary-emulator", "native-test"])):
            value = copy.deepcopy(original)
            mutate(value["verification"][1]["execution"])
            with self.assertRaises(AepmError):
                validate_component(value)

    def test_extracted_mode_posix_and_simulated_windows(self):
        path = self.source / "test.py"
        validate_extracted_mode(path, False)
        path.chmod(0o755)
        with self.assertRaisesRegex(AepmError, "mode-mismatch"):
            validate_extracted_mode(path, False)
        with patch("aepm.bundle.os.name", "nt"):
            validate_extracted_mode(path, False)
            with self.assertRaisesRegex(AepmError, "unsupported-host"):
                pack(self.source, self.store)
        path.unlink()
        path.symlink_to(self.source / "NOTICE")
        with self.assertRaisesRegex(AepmError, "unsafe-file"):
            validate_extracted_mode(path, False)

    def test_context_platform_channel_literal(self):
        descriptor = {"format": 1, "id": "update-fixture", "pathPlatform": "posix", "mode": "simulation",
                      "simulationKind": "fixture", "settings": {"updatePlatform": "browser", "updateChannel": "web"}, "resources": [], "secrets": {}}
        validate_execution_context(descriptor)
        for platform, channel in (("web", "web"), ("browser", "direct"), ("android", "testflight")):
            descriptor["settings"] = {"updatePlatform": platform, "updateChannel": channel}
            with self.subTest(platform=platform, channel=channel), self.assertRaises(AepmError):
                validate_execution_context(descriptor)
        for address in ("http://bad..host/l/id", "http://localhost/l/id%", "http://localhost/l/id%2fpart"):
            descriptor["settings"] = {"updatePlatform": "browser", "updateChannel": "web", "updateUrl": address}
            with self.subTest(address=address), self.assertRaises(AepmError):
                validate_execution_context(descriptor)

    def test_resource_coverage_digest_and_kind(self):
        self.build(android=True)
        self.check()
        original = copy.deepcopy(self.evidence)
        for mutate in (lambda e: e["suites"][0]["resources"].pop(),
                       lambda e: e["suites"][0]["resources"][0].update(digest="b" * 64),
                       lambda e: e["suites"][0]["resources"][0].update(digest=None)):
            self.evidence = copy.deepcopy(original)
            mutate(self.evidence)
            self.publish()
            with self.assertRaises(AepmError):
                self.check()
        self.evidence = original
        self.descriptor["resources"][0]["kind"] = "file"
        self.authorization["contextDigest"] = self.retain("contexts", self.descriptor)
        self.report["execution"]["contextDigest"] = self.evidence["contextDigest"] = self.authorization["contextDigest"]
        self.report["execution"]["authorizationDigest"] = self.evidence["authorizationDigest"] = self.retain_authorization()
        self.publish()
        with self.assertRaisesRegex(AepmError, "resource-binding"):
            self.check()

    def test_grants_cannot_escalate_or_borrow_another_suite(self):
        self.build()
        original = copy.deepcopy(self.authorization)
        for mutate in (lambda a: a["suites"][0].update(operations=["native-build", "native-test"]),
                       lambda a: a["suites"][0].update(operations=[]),
                       lambda a: a["suites"][0].update(origins=["https://other.example"]),
                       lambda a: a["suites"][0].update(id="unit")):
            self.authorization = copy.deepcopy(original)
            mutate(self.authorization)
            self.report["execution"]["authorizationDigest"] = self.evidence["authorizationDigest"] = self.retain_authorization()
            self.publish()
            with self.assertRaises(AepmError):
                self.check()

    def test_resource_executable_limit_is_scoped_and_document_bound_remains(self):
        descriptor = {"format": 1, "id": "toolchain", "pathPlatform": "posix", "mode": "local",
                      "simulationKind": None, "settings": {}, "secrets": {}, "resources": [
                          {"id": "androidSdk", "kind": "directory", "path": "/absent/android", "digest": "a" * 64, "executables": []}]}
        resource = descriptor["resources"][0]
        for count in (403, 8192):
            resource["executables"] = [f"bin/tool-{index:05d}" for index in range(count)]
            validate_execution_context(descriptor)
        resource["executables"].append("bin/tool-08192")
        with self.assertRaisesRegex(AepmError, "metadata-limit"):
            validate_execution_context(descriptor)
        with self.assertRaisesRegex(AepmError, "metadata-limit"):
            execution_document({"unrelated": [0] * 257}, "fixture", resource_executables=True)
        with self.assertRaisesRegex(AepmError, "metadata-limit"):
            execution_document({"resources": [{"unrelated": [0] * 257}]}, "fixture", resource_executables=True)
        resource["executables"] = ["bin/" + "a" * 200 + f"-{index:05d}" for index in range(8192)]
        with self.assertRaisesRegex(AepmError, "metadata-limit"):
            validate_execution_context(descriptor)

    def test_inventory_root_relation_and_closed_resource_scope(self):
        descriptor = {"format": 1, "id": "toolchain", "pathPlatform": "posix", "mode": "local",
                      "simulationKind": None, "settings": {}, "secrets": {}, "resources": [
                          {"id": "appleDeveloperDirectory", "kind": "directory", "path": "/absent/Xcode.app/Contents/Developer",
                           "inventoryRoot": "/absent/Xcode.app/Contents", "digest": "a" * 64, "executables": ["Developer/usr/bin/tool"]}]}
        validate_execution_context(descriptor)
        original = copy.deepcopy(descriptor)
        for mutate in (lambda r: r.update(id="androidSdk"), lambda r: r.update(id="androidJavaHome"),
                       lambda r: r.update(inventoryRoot="/absent/Xcode.app"),
                       lambda r: r.update(path="/other/Contents/Developer"), lambda r: r.update(kind="file")):
            descriptor = copy.deepcopy(original)
            mutate(descriptor["resources"][0])
            with self.assertRaisesRegex(AepmError, "invalid-inventory-root"):
                validate_execution_context(descriptor)
        descriptor = copy.deepcopy(original)
        descriptor["pathPlatform"] = "windows"
        descriptor["resources"][0].update(path="C:\\Xcode.app\\Contents\\Developer", inventoryRoot="C:\\Xcode.app\\Contents")
        validate_execution_context(descriptor)

    def test_historical_signed_context_accepts_large_readonly_inventory(self):
        self.build(windows=True)
        self.descriptor["resources"] = [{"id": "appleDeveloperDirectory", "kind": "directory",
                                         "path": "C:\\Xcode.app\\Contents\\Developer", "inventoryRoot": "C:\\Xcode.app\\Contents",
                                         "digest": "a" * 64, "executables": [f"Developer/usr/bin/tool-{index:05d}" for index in range(403)]}]
        self.authorization["contextDigest"] = self.retain("contexts", self.descriptor)
        self.report["execution"]["contextDigest"] = self.evidence["contextDigest"] = self.authorization["contextDigest"]
        self.report["execution"]["authorizationDigest"] = self.evidence["authorizationDigest"] = self.retain_authorization()
        self.publish()
        self.check(now=2000)
        self.guardian(self.ref, self.report)
        verify_package(self.ref, self.store, self.policy)

    def test_simulation_delivery_reference_does_not_authorize_remote_operations(self):
        descriptor = {"format": 1, "id": "update-fixture", "pathPlatform": "posix", "mode": "simulation",
                      "simulationKind": "fixture", "settings": {"updatePlatform": "browser", "updateChannel": "web",
                      "updateUrl": "http://127.0.0.1:9010/l/example-id", "updateReadOrigin": "http://127.0.0.1:9010",
                      "updateDeliveryOrigin": "https://play.example"}, "resources": [], "secrets": {}}
        for delivery in ("https://play.example", "https://testflight.apple.com", "http://127.0.0.1:9011"):
            descriptor["settings"]["updateDeliveryOrigin"] = delivery
            validate_execution_context(descriptor)
        for delivery in ("http://play.example", "https://user@play.example", "https://play.example/path",
                         "https://play.example?query=fixture", "https://play.example#fragment", "wss://play.example"):
            descriptor["settings"]["updateDeliveryOrigin"] = delivery
            with self.subTest(delivery=delivery), self.assertRaises(AepmError):
                validate_execution_context(descriptor)
        descriptor["settings"]["updateDeliveryOrigin"] = "https://play.example"
        for field, value in (("updateUrl", "https://play.example/l/example-id"),
                             ("updateReadOrigin", "https://play.example"), ("livekitUrl", "wss://play.example")):
            changed = copy.deepcopy(descriptor)
            changed["settings"][field] = value
            with self.subTest(operation=field), self.assertRaisesRegex(AepmError, "invalid-simulation-origin"):
                validate_execution_context(changed)

    def test_windows_archive_names_rejected_before_extraction_writes(self):
        invalid = ["CON", "nul.txt", "AUX.log", "PRN", "COM1.data", "LPT9", "COM¹.txt",
                   "CONIN$", "CONOUT$.txt", "nested/aux/file.txt", "CON .txt",
                   "name.", "name ", "directory./file.txt", "directory /file.txt", "wild?.txt"]
        for path in invalid:
            with self.subTest(path=path), self.assertRaises(AepmError):
                validate_windows_paths(["component.json", path])
        validate_windows_paths(["component.json", "console.txt", "auxiliary/file.txt", "COM10.txt"])
        for paths in (["name", "name."], ["directory/file", "directory /other"], ["a/file", "A/other"]):
            with self.subTest(paths=paths), self.assertRaises(AepmError):
                validate_windows_paths(paths)
        if os.name == "nt":
            self.skipTest("Unix fixture creation required for Windows-incompatible archive names")
        (self.source / "NUL.txt").write_text("ordinary Unix file")
        (self.source / "name.").write_text("ordinary Unix file")
        self.component["files"].extend([{"path": "NUL.txt", "executable": False}, {"path": "name.", "executable": False}])
        self.update()
        ref = pack(self.source, self.store)
        self.release(ref)
        destination = self.root / "must-not-exist" / "extracted"
        with patch("aepm.bundle.os.name", "nt"), self.assertRaisesRegex(AepmError, "unsafe-windows-path"):
            extract_review(ref, self.store, destination, self.policy)
        self.assertFalse(destination.parent.exists())
        extract_review(ref, self.store, self.root / "unix-extraction", self.policy)
        self.assertEqual((self.root / "unix-extraction/NUL.txt").read_text(), "ordinary Unix file")


if __name__ == "__main__":
    unittest.main()
