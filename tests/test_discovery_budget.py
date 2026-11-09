"""Simulated clocks and process responses; no simulator or build is executed."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aepm import contextual
from aepm.contextual import SuiteBudget, prerequisites
from aepm.environment import Execution, describe_resource
from aepm.io import write
from aepm.model import AepmError, digest


class Clock:
    def __init__(self):
        self.mono, self.wall = 100.0, 1000.0

    def advance(self, seconds):
        self.mono += seconds
        self.wall += seconds


class Authority:
    def __init__(self, clock, expires):
        self.clock = clock
        self.authorization = {"expiresAt": expires}
        self.checks = 0

    def check_time(self):
        self.checks += 1
        if self.clock.wall >= self.authorization["expiresAt"]:
            raise AepmError("authorization-expired", "authorization")


class DiscoveryBudgetTests(unittest.TestCase):
    def test_fractional_authority_and_original_start_restriction(self):
        clock = Clock()
        authority = Authority(clock, 1000.25)
        with patch("aepm.contextual.time.monotonic", side_effect=lambda: clock.mono), patch("aepm.contextual.time.time", side_effect=lambda: clock.wall):
            budget = SuiteBudget(30, authority)
            self.assertEqual(budget.remaining(20), .25)
            budget = SuiteBudget(30)
            clock.advance(5)
            budget.restrict(10)
            self.assertEqual(budget.remaining(), 5)
            clock.advance(5)
            with self.assertRaisesRegex(AepmError, "timeout"):
                budget.remaining()

    def nested_fixture(self, root):
        protocol = root / "protocol"
        (protocol / "ownership").mkdir(parents=True)
        (protocol / "profiles/apple" / ("a" * 64)).mkdir(parents=True)
        for name in ("First", "Second"):
            (root / (name + ".xcodeproj")).mkdir()
        write(protocol / "ownership/created-0.json", {"kind": "apple-device", "runId": "a" * 64, "resourceId": "owned-device"})
        suite = {"requirements": ["external:compatible-apple-simulator"], "timeoutSeconds": 30}
        descriptor = {"runId": "a" * 64, "settings": {"applePlatform": "ios-simulator", "appleRuntime": "runtime", "appleDeviceType": "device"}}
        environment = {"PATH": "/fixture", "AEPM_CONTEXT_FILE": str(protocol / "context.json"), "AEPM_OWNERSHIP_DIRECTORY": str(protocol / "ownership")}
        return suite, descriptor, environment

    def test_nested_project_scheme_probes_share_one_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            suite, descriptor, environment = self.nested_fixture(root)
            clock, calls = Clock(), []

            def response(argv, _cwd, _environment, timeout, *_args, **_kwargs):
                calls.append((argv, timeout))
                clock.advance(1)
                if "runtimes" in argv:
                    value = {"runtimes": [{"identifier": "runtime", "isAvailable": True}]}
                elif "devicetypes" in argv:
                    value = {"devicetypes": [{"identifier": "device"}]}
                elif "-list" in argv:
                    value = {"project": {"schemes": ["one", "two", "three"]}}
                else:
                    return 0, 1, "", b"{ id: owned-device, name: fixture }"
                return 0, 1, "", json.dumps(value).encode()

            with patch("aepm.contextual.time.monotonic", side_effect=lambda: clock.mono), patch("aepm.contextual.shutil.which", return_value="/fixture/tool"), patch("aepm.contextual.run", response):
                budget = SuiteBudget(3.5)
                with self.assertRaisesRegex(AepmError, "discovery-timeout"):
                    prerequisites(suite, descriptor, [], root, environment, {"xcodebuild": "27.2"}, final=True, budget=budget)
            self.assertEqual([timeout for _, timeout in calls], [3.5, 2.5, 1.5, .5])
            self.assertEqual(sum("-showdestinations" in argv for argv, _ in calls), 1)

    def test_expiry_prevents_the_next_nested_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            suite, descriptor, environment = self.nested_fixture(root)
            clock, calls = Clock(), []
            authority = Authority(clock, 1000.4)

            def response(argv, _cwd, _environment, timeout, *_args, **_kwargs):
                calls.append((argv, timeout))
                clock.advance(.2)
                value = {"runtimes": [{"identifier": "runtime", "isAvailable": True}]} if "runtimes" in argv else {"devicetypes": [{"identifier": "device"}]}
                return 0, 1, "", json.dumps(value).encode()

            with patch("aepm.contextual.time.monotonic", side_effect=lambda: clock.mono), patch("aepm.contextual.time.time", side_effect=lambda: clock.wall), patch("aepm.contextual.shutil.which", return_value="/fixture/tool"), patch("aepm.contextual.run", response):
                with self.assertRaisesRegex(AepmError, "authorization-expired"):
                    prerequisites(suite, descriptor, [], root, environment, {"xcodebuild": "27.2"}, final=True, budget=SuiteBudget(30, authority))
            self.assertEqual(len(calls), 2)
            self.assertGreaterEqual(authority.checks, len(calls))

    def final_probe(self, root, clock, *, expires=False, candidate=False):
        suite, descriptor, environment = self.nested_fixture(root)
        (root / "Second.xcodeproj").rmdir()
        calls = []

        def response(argv, _cwd, _environment, timeout, *_args, **_kwargs):
            calls.append((argv, timeout))
            clock.advance(1)
            if "runtimes" in argv:
                value = {"runtimes": [{"identifier": "runtime", "isAvailable": True}]}
            elif "devicetypes" in argv:
                value = {"devicetypes": [{"identifier": "device"}]}
            elif "-list" in argv:
                value = {"project": {"schemes": ["only-scheme"]}}
            else:
                if expires:
                    clock.advance(1)
                    return 0, 2, "", b"{ id: owned-device, name: fixture }" if candidate else b"no matching destination"
                return None, 1, "timeout", b""
            return 0, 1, "", json.dumps(value).encode()

        return suite, descriptor, environment, calls, response

    def test_final_scheme_timeout_preserves_discovery_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root, clock = Path(directory).resolve(), Clock()
            suite, descriptor, environment, calls, response = self.final_probe(root, clock)
            with patch("aepm.contextual.time.monotonic", side_effect=lambda: clock.mono), patch("aepm.contextual.shutil.which", return_value="/fixture/tool"), patch("aepm.contextual.run", response):
                with self.assertRaisesRegex(AepmError, "discovery-timeout"):
                    prerequisites(suite, descriptor, [], root, environment, {"xcodebuild": "27.2"}, final=True, budget=SuiteBudget(30))
            self.assertEqual(len(calls), 4)
            self.assertIn("-showdestinations", calls[-1][0])
            self.assertLess(clock.mono, 130)

    def test_final_probe_expiry_precedes_candidate_or_unsupported_classification(self):
        for candidate in (False, True):
            with self.subTest(candidate=candidate), tempfile.TemporaryDirectory() as directory:
                root, clock = Path(directory).resolve(), Clock()
                suite, descriptor, environment, calls, response = self.final_probe(root, clock, expires=True, candidate=candidate)
                authority = Authority(clock, 1004.5)
                with patch("aepm.contextual.time.monotonic", side_effect=lambda: clock.mono), patch("aepm.contextual.time.time", side_effect=lambda: clock.wall), patch("aepm.contextual.shutil.which", return_value="/fixture/tool"), patch("aepm.contextual.run", response):
                    with self.assertRaisesRegex(AepmError, "authorization-expired"):
                        prerequisites(suite, descriptor, [], root, environment, {"xcodebuild": "27.2"}, final=True, budget=SuiteBudget(30, authority))
                self.assertEqual(len(calls), 4)
                self.assertIn("-showdestinations", calls[-1][0])

    def test_final_input_revalidation_overrun_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.mkdir()
            (source / "fixture").write_text("input")
            resource_root = root / "cache"
            resource_root.mkdir()
            (resource_root / "value").write_text("pinned")
            resource = describe_resource("androidCache", resource_root)
            execution = Execution({}, root / "unused-policy", root / "evidence")
            actual_prepare = execution.prepare

            def prepare(suite, private):
                kind, descriptor, _selected, records, environment = actual_prepare(suite, private)
                return kind, descriptor, [resource], records, environment

            execution.prepare = prepare
            suite = {"package": "a" * 64, "id": "budget", "root": "package", "scope": "required-local", "argv": ["python3", "-c", "pass"],
                     "cwd": ".", "prepare": [], "tools": {"python3": "3"}, "fixtures": ["fixture"], "locks": [], "network": False,
                     "timeoutSeconds": 10, "requirements": [], "execution": {"kind": "local", "settings": [], "secrets": [], "resources": [], "assertions": []}}
            suite["execution"].update(simulation=False, operations=[], cleanup=None)
            clock, checks, commands = Clock(), [], []
            actual_validate = contextual.validate_resource

            def revalidate(value):
                actual_validate(value)
                checks.append(value)
                if len(checks) == 2:
                    clock.advance(11)

            def response(argv, *_args, **_kwargs):
                commands.append(argv)
                return 0, 1, "", b"Python 3.12.8\n" if "--version" in argv else b""

            with patch("aepm.contextual.time.monotonic", side_effect=lambda: clock.mono), patch("aepm.contextual.run", response), patch("aepm.contextual.validate_resource", revalidate):
                result, record = contextual.execute(suite, source, False, root / "logs", execution)
            self.assertEqual(len(checks), 2)
            self.assertEqual(result["exitCode"], 0)
            self.assertEqual((result["status"], result["reason"]), ("failed", "timeout"))
            self.assertTrue(record["checkStarted"])
            self.assertTrue(record["cleanup"]["completed"])
