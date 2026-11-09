"""Actual Windows checks with retained process identities and public signed fixtures."""

from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aepm.application import assemble
from aepm.contextual import tool_environment
from aepm.io import load, private_directory
from aepm.model import canonical, digest
from aepm.process import run
from aepm.supervision import supervision_step_index, validate_log_index
from aepm.trust import review_bindings, validate_report_evidence, verify_package
from aepm.verification import review_package, verify_application, retained_manifests, transaction_path
from aepm.authorization import bindings


@unittest.skipUnless(os.name == "nt", "Actual Windows host unavailable; no native success claimed")
class NativeWindowsTests(unittest.TestCase):
    def test_hanging_descendant_terminated_after_exit_and_timeout(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        for mode in ("exit", "hang"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = private_directory(Path(directory))
                identity_file = root / "child.json"
                release = Path(str(identity_file) + ".release")
                environment = tool_environment(root / "home", {}, [])
                handle = None
                with ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(run, [sys.executable, str(Path(__file__).with_name("descendant_fixture.py")), mode, str(identity_file)], root, environment, 8)
                    try:
                        deadline = time.monotonic() + 6
                        while not identity_file.exists() and time.monotonic() < deadline:
                            time.sleep(.01)
                        self.assertTrue(identity_file.exists())
                        identity = load(identity_file)
                        handle = kernel.OpenProcess(0x100000 | 0x1000, False, identity["pid"])
                        self.assertTrue(handle)
                        times = [wintypes.FILETIME() for _ in range(4)]
                        self.assertTrue(kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)))
                        self.assertEqual(times[0].dwLowDateTime | times[0].dwHighDateTime << 32, identity["created"])
                        release.write_text("ready")
                        code, _, reason, _ = result.result(timeout=15)
                        self.assertEqual((code, reason), (0, "") if mode == "exit" else (None, "timeout"))
                        self.assertEqual(kernel.WaitForSingleObject(handle, 5000), 0)
                    finally:
                        release.write_text("ready")
                        if handle:
                            kernel.CloseHandle(handle)

    def test_normal_success_and_output_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = private_directory(Path(directory))
            environment = tool_environment(root / "home", {}, [])
            result = run([sys.executable, "-c", "print('normal success')"], root, environment, 5)
            self.assertEqual((result[0], result[2]), (0, ""))
            self.assertIn(b"normal success", result[3])
            result = run([sys.executable, "-c", "print('x'*100000)"], root, environment, 5, 1024)
            self.assertEqual(result[2], "output-limit")
            self.assertLessEqual(len(result[3]), 1024)

    def public_fixture(self, destination):
        configured = os.environ.get("AEPM_WINDOWS_FIXTURE")
        if not configured:
            self.skipTest("Set AEPM_WINDOWS_FIXTURE to a public fixture prepared on a supported packing host")
        source = Path(configured).resolve()
        self.assertEqual(load(source / "fixture.json")["preparedOn"], "posix")
        shutil.copytree(source, destination)
        return load(destination / "fixture.json"), destination / "store", destination / "policy.json"

    def assert_private_cleanup(self, report, evidence):
        observed = []
        for suite in report["suites"]:
            logs = evidence / "logs"
            index = logs / (suite["logDigest"] + ".json")
            self.assertEqual(digest(index.read_bytes()), suite["logDigest"])
            events = load(index)
            validate_log_index(suite, events, logs)
            for event in events:
                if supervision_step_index(event["step"]) is not None:
                    continue
                step = event["step"]
                self.assertTrue(type(step) is int and step >= 0 or step in ("validation-inputs", "cleanup", "retained-private-root"))
                required = {"step", "preparation", "seconds", "exitCode", "reason"}
                self.assertTrue(required <= set(event) <= required | {"logDigest", "suppressed", "path"})
                self.assertIs(type(event["preparation"]), bool)
                self.assertTrue(type(event["seconds"]) is int and event["seconds"] >= 0)
                self.assertTrue(event["exitCode"] is None or type(event["exitCode"]) is int)
                self.assertIsInstance(event["reason"], str)
                if "logDigest" not in event:
                    self.assertTrue(event.get("suppressed") is True or step == "retained-private-root")
                    continue
                text = (evidence / "logs" / (event["logDigest"] + ".log")).read_text().strip()
                self.assertEqual(digest((logs / (event["logDigest"] + ".log")).read_bytes()), event["logDigest"])
                if text:
                    record = json.loads(text)
                    observed.append(record)
                    self.assertFalse(Path(record["privateRoot"]).exists())
                    self.assertFalse(Path(record["profile"]).exists())
        self.assertTrue(observed, "The signed fixture must report its private paths")

    def test_actual_package_review_and_private_file_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = private_directory(Path(directory))
            fixture, store, policy = self.public_fixture(root / "public")
            verify_package(fixture["ref"], store, policy)
            with patch.dict(os.environ, {"AEPM_WINDOWS_TEST_SECRET": "SYNTHETIC_ONLY"}):
                report = review_package(fixture["ref"], store, policy, True)
            self.assertEqual(report["summary"]["required-local"], "passed")
            validate_report_evidence(report, review_bindings(fixture["ref"], store), "review", store, policy)
            self.assert_private_cleanup(report, store)

    def test_actual_generated_application_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = private_directory(Path(directory))
            fixture, store, policy = self.public_fixture(root / "public")
            application = root / "application"
            assembly = assemble(load(root / "public/definition.json"), load(root / "public/lock.json"), store, application, policy)
            self.assertEqual(digest(canonical(assembly)), fixture["assemblyDigest"])
            report = verify_application(application, policy, True)
            self.assertEqual(report["summary"]["required-local"], "passed")
            assembly, manifests = retained_manifests(application, policy)
            evidence = transaction_path(application) / "verification"
            validate_report_evidence(report, bindings(assembly["lock"], digest(canonical(assembly)), manifests, "application"), "application", evidence, policy)
            self.assert_private_cleanup(report, evidence)
