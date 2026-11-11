"""Tool-selection validator and propagation checks; fake executables, no launched tools."""

from contextlib import ExitStack
from copy import deepcopy
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aepm import contextual, verification
from aepm.model import AepmError
from aepm.tool_selection import ToolSelection, load_tool_selection, require_selection


def executable(path, content=b"#!/bin/sh\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o755)
    return path


def binding(alias, canonical=None):
    from hashlib import sha256
    alias = Path(alias)
    canonical = Path(canonical or alias)
    links = [] if alias == canonical else [{"path": str(alias), "target": os.readlink(alias)}]
    return {"status": "bound", "alias": str(alias), "links": links, "canonicalPath": str(canonical),
            "sha256": sha256(canonical.read_bytes()).hexdigest(), "mode": 0o755}


class Guarded(unittest.TestCase):
    def setUp(self):
        guards = ExitStack()
        self.addCleanup(guards.close)
        guards.enter_context(patch.object(ctypes, "CDLL", side_effect=AssertionError("native library forbidden")))
        guards.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")))
        guards.enter_context(patch.object(os, "kill", side_effect=AssertionError("signal forbidden")))
        guards.enter_context(patch.object(os, "killpg", side_effect=AssertionError("group signal forbidden")))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bin = self.root / "bound"
        self.python = executable(self.bin / "python3.12", b"python")
        (self.bin / "python3").symlink_to("python3.12")
        self.node = executable(self.bin / "node", b"node")
        self.shadow = self.root / "shadow"
        for name in ("python3", "node", "xcrun", "xcodebuild"):
            executable(self.shadow / name, b"ambient " + name.encode())
        self.document = {"format": 1, "platform": "posix", "python": {"name": "python3", "version": "3.12.8"},
                         "searchPath": [str(self.bin), "/usr/bin", "/bin"],
                         "tools": {"python3": binding(self.bin / "python3", self.python), "node": binding(self.node),
                                   "xcrun": {"status": "unavailable"}}}
        self.required = {"python3", "node", "xcrun"}

    def selection(self, document=None, required=None):
        return load_tool_selection(document or self.document, required or self.required)


class ValidatorTests(Guarded):
    def test_valid_document_and_members(self):
        selection = self.selection()
        self.assertEqual(selection.directories, (str(self.bin), "/usr/bin", "/bin"))
        self.assertEqual(selection.path, os.pathsep.join(selection.directories))
        self.assertEqual(len(selection.digest), 64)
        self.assertEqual(selection.resolve("python3"), self.bin / "python3")
        self.assertEqual(selection.canonical("python3"), str(self.python))
        selection.check("python3", str(self.python), selection.path)
        with self.assertRaises(AttributeError):
            selection.digest = "changed"

    def test_invalid_documents_rejected(self):
        changes = [
            lambda d: d.update(format=2), lambda d: d.update(platform="windows"), lambda d: d.update(extra=1),
            lambda d: d.update(searchPath=[str(self.bin), "/usr/bin"]), lambda d: d.update(searchPath=[str(self.bin), "/bin"]),
            lambda d: d.update(searchPath=["relative", "/usr/bin", "/bin"]),
            lambda d: d.update(searchPath=[str(self.bin), str(self.bin), "/usr/bin", "/bin"]),
            lambda d: d["tools"]["node"].update(phase="main"), lambda d: d["tools"]["xcrun"].update(alias="/x"),
            lambda d: d["tools"]["python3"].update(links=[]), lambda d: d["python"].update(name="xcrun"),
            lambda d: d["tools"].pop("node"), lambda d: d["tools"].update(git={"status": "unavailable"}),
        ]
        for index, change in enumerate(changes):
            document = deepcopy(self.document)
            change(document)
            with self.subTest(index=index), self.assertRaises(AepmError) as caught:
                self.selection(document)
            self.assertEqual(caught.exception.code, "tool-selection-invalid")

    def test_required_names_must_match_exactly(self):
        for required in (self.required - {"node"}, self.required | {"git"}):
            with self.subTest(required=sorted(required)), self.assertRaises(AepmError) as caught:
                self.selection(required=required)
            self.assertEqual(caught.exception.code, "tool-selection-invalid")

    def test_non_posix_and_wrong_type_rejected(self):
        with patch.object(os, "name", "nt"), self.assertRaises(AepmError):
            self.selection()
        for value in ({"path": "x"}, "selection", 1):
            with self.subTest(value=value), self.assertRaises(AepmError) as caught:
                require_selection(value)
            self.assertEqual(caught.exception.code, "tool-selection-invalid")
        self.assertIsNone(require_selection(None))

    def test_system_directory_cannot_shadow_a_binding(self):
        executable(self.bin / "true", b"bound true")
        document = deepcopy(self.document)
        document["searchPath"] = ["/usr/bin", "/bin", str(self.bin)]
        document["tools"]["true"] = binding(self.bin / "true")
        with self.assertRaises(AepmError) as caught:
            self.selection(document, self.required | {"true"})
        self.assertEqual((caught.exception.code, caught.exception.path), ("resource-changed", "tool"))

    def test_drift_fails_closed(self):
        selection = self.selection()
        for fault in ("bytes", "mode", "link", "canonical-mismatch", "path-mismatch"):
            with self.subTest(fault=fault):
                original = self.python.read_bytes()
                if fault == "bytes":
                    self.python.write_bytes(b"changed")
                elif fault == "mode":
                    self.python.chmod(0o700)
                elif fault == "link":
                    (self.bin / "python3").unlink()
                    (self.bin / "python3").symlink_to("node")
                with self.assertRaises(AepmError) as caught:
                    if fault == "canonical-mismatch":
                        selection.check("python3", str(self.shadow / "python3"), selection.path)
                    elif fault == "path-mismatch":
                        selection.check("python3", str(self.python), os.pathsep.join([str(self.shadow), selection.path]))
                    else:
                        selection.validate()
                self.assertEqual((caught.exception.code, caught.exception.path), ("resource-changed", "tool"))
                self.python.write_bytes(original)
                self.python.chmod(0o755)
                (self.bin / "python3").unlink()
                (self.bin / "python3").symlink_to("python3.12")

    def test_unavailable_and_unknown_names(self):
        selection = self.selection()
        with self.assertRaises(AepmError) as caught:
            selection.resolve("xcrun")
        self.assertEqual((caught.exception.code, caught.exception.path), ("tool-unavailable", "xcrun"))
        with self.assertRaises(AepmError) as caught:
            selection.resolve("git")
        self.assertEqual((caught.exception.code, caught.exception.path), ("tool-unavailable", "tools"))


class ContextualTests(Guarded):
    def setUp(self):
        super().setUp()
        self.java_home = self.root / "java"
        executable(self.java_home / "bin/java", b"resource java")
        self.java = {"id": "androidJavaHome", "path": str(self.java_home)}

    def environment(self, tools, selected=(), selection=None):
        home = self.root / "private" / "home"
        if (home.parent / "tools").is_dir():
            (home.parent / "tools").chmod(0o700)
        shutil.rmtree(home.parent, ignore_errors=True)
        home.parent.mkdir(mode=0o700)
        with patch.dict(os.environ, {"PATH": os.pathsep.join([str(self.shadow), os.environ.get("PATH", os.defpath)])}):
            return contextual.tool_environment(home, tools, list(selected), tool_selection=selection)

    def test_without_selection_path_is_ambient(self):
        environment = self.environment({"node": "1"})
        self.assertTrue(environment["PATH"].startswith(str(self.shadow)))
        self.assertTrue(environment["PATH"].endswith(os.defpath))

    def test_finite_path_ignores_ambient_shadow_and_resolves_binding(self):
        selection = self.selection()
        environment = self.environment({"python3": "3.12", "node": "26.5"}, selection=selection)
        aliases = self.root / "private/tools"
        self.assertEqual(environment["PATH"], os.pathsep.join([str(aliases), selection.path]))
        self.assertEqual(sorted(path.name for path in aliases.iterdir()), ["node", "python3"])
        self.assertEqual(os.readlink(aliases / "python3"), str(self.python))
        self.assertEqual(aliases.stat().st_mode & 0o7777, 0o500)
        for tail in (["--version"], ["scripts/platform-check.py", "android"]):
            argv = contextual.resolve_command(["python3", *tail], self.root, {"python3": "3.12"}, environment,
                                              tool_selection=selection)
            self.assertEqual(argv, [str(self.python), *tail])
        shadowed = {**environment, "PATH": os.pathsep.join([str(self.shadow), environment["PATH"]])}
        with self.assertRaises(AepmError) as caught:
            contextual.resolve_command(["python3", "--version"], self.root, {"python3": "3.12"}, shadowed,
                                       tool_selection=selection)
        self.assertEqual(caught.exception.code, "resource-changed")

    def test_resource_directory_python3_does_not_shadow_binding(self):
        developer = self.root / "Developer"
        executable(developer / "usr/bin/xcodebuild", b"resource xcodebuild")
        executable(developer / "usr/bin/python3", b"xcode python 3.9")
        apple = {"id": "appleDeveloperDirectory", "path": str(developer)}
        selection = self.selection()
        environment = self.environment({"python3": "3.12", "xcodebuild": "27.2"}, [apple], selection)
        aliases = self.root / "private/tools"
        self.assertEqual(environment["PATH"].split(os.pathsep)[:3], [str(aliases), str(self.bin), str(developer / "usr/bin")])
        self.assertEqual(Path(shutil.which("python3", path=environment["PATH"]) or "").resolve(), self.python)
        self.assertEqual(os.readlink(aliases / "xcodebuild"), str(developer / "usr/bin/xcodebuild"))

    def xcrun_selection(self):
        executable(self.bin / "xcrun", b"bound xcrun")
        executable(self.bin / "xcodebuild", b"generic-directory xcodebuild shim")
        document = deepcopy(self.document)
        document["tools"]["xcrun"] = binding(self.bin / "xcrun")
        return self.selection(document)

    def test_generic_directory_holding_resource_name_does_not_shadow_it(self):
        developer = self.root / "Developer"
        executable(developer / "usr/bin/xcodebuild", b"resource xcodebuild")
        executable(developer / "usr/bin/python3", b"xcode python 3.9")
        apple = {"id": "appleDeveloperDirectory", "path": str(developer)}
        selection = self.xcrun_selection()
        tools = {"python3": "3.12", "xcodebuild": "27.2", "xcrun": "72"}
        environment = self.environment(tools, [apple], selection)
        self.assertEqual(environment["DEVELOPER_DIR"], str(developer))
        names = contextual._resource_tools(tools, [apple])
        self.assertEqual(names, {"xcodebuild"})
        expected = {"xcodebuild": developer / "usr/bin/xcodebuild", "xcrun": self.bin / "xcrun", "python3": self.python}
        for name, path in expected.items():
            argv = contextual.resolve_command([name, "-version"], self.root, tools, environment, {},
                                              tool_selection=selection, resource_names=names)
            self.assertEqual(argv[0], str(path), name)
        self.assertEqual(sorted(path.name for path in (self.root / "private/tools").iterdir()), sorted(tools))

    def test_alias_directory_tampering_fails_closed(self):
        developer = self.root / "Developer"
        executable(developer / "usr/bin/xcodebuild", b"resource xcodebuild")
        apple = {"id": "appleDeveloperDirectory", "path": str(developer)}
        selection = self.xcrun_selection()
        tools = {"xcodebuild": "27.2", "xcrun": "72"}
        aliases = self.root / "private/tools"
        for fault in ("preexisting", "retargeted", "shadowed"):
            with self.subTest(fault=fault), self.assertRaises(AepmError) as caught:
                if fault == "preexisting":
                    home = self.root / "private/home"
                    shutil.rmtree(home.parent, ignore_errors=True)
                    aliases.mkdir(parents=True, mode=0o700)
                    executable(aliases / "xcodebuild", b"planted")
                    contextual.tool_environment(home, tools, [apple], tool_selection=selection)
                else:
                    environment = self.environment(tools, [apple], selection)
                    if fault == "retargeted":
                        aliases.chmod(0o700)
                        (aliases / "xcrun").unlink()
                        (aliases / "xcrun").symlink_to(self.shadow / "xcrun")
                    else:
                        environment = {**environment, "PATH": os.pathsep.join([str(self.shadow), environment["PATH"]])}
                    contextual._selected_which("xcrun", environment, selection, frozenset({"xcodebuild"}))
            self.assertEqual((caught.exception.code, caught.exception.path), ("resource-changed", "tool"))

    def test_resource_takes_precedence_and_global_binding_used_without_resource(self):
        global_java = executable(self.root / "global" / "java", b"global java")
        document = deepcopy(self.document)
        document["searchPath"].insert(1, str(global_java.parent))
        document["tools"]["java"] = binding(global_java)
        selection = self.selection(document, self.required | {"java"})
        environment = self.environment({"java": "17", "python3": "3.12"}, [self.java], selection)
        self.assertEqual(environment["PATH"].split(os.pathsep)[:3],
                         [str(self.root / "private/tools"), str(self.bin), str(self.java_home / "bin")])
        self.assertEqual(os.readlink(self.root / "private/tools/java"), str(self.java_home / "bin/java"))
        names = contextual._resource_tools({"java": "17", "python3": "3.12"}, [self.java])
        self.assertEqual(names, {"java"})
        argv = contextual.resolve_command(["java", "-version"], self.root, {"java": "17"}, environment,
                                          tool_selection=selection, resource_names=names)
        self.assertEqual(argv[0], str(self.java_home / "bin/java"))
        other = self.environment({"java": "26.0.1"}, selection=selection)
        argv = contextual.resolve_command(["java", "-version"], self.root, {"java": "26.0.1"}, other, tool_selection=selection)
        self.assertEqual(argv[0], str(global_java))

    def test_selection_on_windows_fails_explicitly(self):
        selection = self.selection()
        with patch.object(contextual.os, "name", "nt"), self.assertRaises(AepmError) as caught:
            contextual.tool_environment(self.root / "private/home", {"python3": "3.12"}, [], tool_selection=selection)
        self.assertEqual((caught.exception.code, caught.exception.path), ("tool-selection-invalid", "toolSelection"))
        self.assertFalse((self.root / "private").exists())

    def run_altered(self, alter, *, during="step0", hook=False):
        """Execute a two-step suite whose step `during` alters the alias directory; returns result and launches."""
        selection = self.selection()
        private = self.root / "private"
        if (private / "tools").is_dir():
            (private / "tools").chmod(0o700)
        shutil.rmtree(private, ignore_errors=True)
        private.mkdir(mode=0o700)
        workspace = Mock(preserve=False)
        workspace.__enter__ = Mock(return_value=private)
        workspace.__exit__ = Mock(return_value=False)
        source = self.root / "source"
        source.mkdir(exist_ok=True)
        cleanup = {"argv": ["python3", "hook"], "cwd": ".", "timeoutSeconds": 5} if hook else None
        suite = {"package": "a" * 64, "id": "aliases", "scope": "platform", "root": "package", "argv": ["python3", "main"],
                 "cwd": ".", "prepare": [{"argv": ["python3", "step0"], "cwd": ".", "network": False}],
                 "tools": {"python3": "3.12", "node": "26.5"}, "fixtures": [], "locks": [], "network": False,
                 "timeoutSeconds": 30, "requirements": [], "execution": {"kind": "local", "simulation": False,
                 "operations": [], "settings": [], "secrets": [], "resources": [], "assertions": [], "cleanup": cleanup}}
        execution = SimpleNamespace(check_time=lambda: None, run_id="fixture", authorization=None,
                                    prepare=lambda *_: ("local", {"settings": {}, "operations": [], "simulationKind": None}, [], [], {}))
        launched = []

        def run(argv, cwd, environment, *args, **kwargs):
            launched.append(argv[1])
            if argv[1] == during:
                aliases = private / "tools"
                alter(aliases)
                if hook:
                    (private / "protocol/ownership").mkdir(parents=True, exist_ok=True)
                    (private / "protocol/ownership/intent-1.json").write_text("{}")
            return 0, 0, "", b"v3.12.8 26.5.0"

        with patch.object(contextual, "VerificationDirectory", return_value=workspace), \
                patch.object(contextual, "run", side_effect=run):
            result, _ = contextual.execute(suite, source, False, self.root / "logs", execution, tool_selection=selection)
        self.retained = [event for event in json.loads((self.root / "logs" / (result["logDigest"] + ".json")).read_text())
                         if event["step"] == "retained-private-root"]
        return result, launched, workspace

    def test_alias_changes_between_steps_fail_closed_before_the_next_launch(self):
        def retarget(aliases):
            aliases.chmod(0o700)
            (aliases / "python3").unlink()
            (aliases / "python3").symlink_to(self.shadow / "python3")
            aliases.chmod(0o500)

        def plant(aliases):
            aliases.chmod(0o700)
            (aliases / "git").symlink_to(self.shadow / "node")
            aliases.chmod(0o500)

        def remove(aliases):
            aliases.chmod(0o700)
            (aliases / "node").unlink()
            aliases.chmod(0o500)

        def reopen(aliases):
            aliases.chmod(0o700)

        for alter in (retarget, plant, remove, reopen):
            with self.subTest(fault=alter.__name__):
                result, launched, workspace = self.run_altered(alter)
                self.assertEqual(launched[-1], "step0")
                self.assertNotIn("main", launched)
                self.assertEqual((result["status"], result["reason"]), ("failed", "resource-changed"))
                self.assertTrue(workspace.preserve)
                self.assertEqual([(event["reason"], event["path"]) for event in self.retained],
                                 [("resource-changed", str(self.root / "private"))])
                self.assertTrue((self.root / "private/tools").is_dir())

    def test_unaltered_aliases_pass_and_directory_is_released(self):
        result, launched, workspace = self.run_altered(lambda aliases: None)
        self.assertEqual(launched[-2:], ["step0", "main"])
        self.assertEqual((result["status"], result["reason"]), ("passed", ""))
        self.assertEqual((self.root / "private/tools").stat().st_mode & 0o7777, 0o700)
        self.assertFalse(workspace.preserve)
        self.assertEqual(self.retained, [])

    def test_alias_change_in_the_last_step_fails_at_the_end(self):
        def plant(aliases):
            aliases.chmod(0o700)
            (aliases / "git").symlink_to(self.shadow / "node")
            aliases.chmod(0o500)

        result, launched, workspace = self.run_altered(plant, during="main")
        self.assertEqual(launched[-1], "main")
        self.assertEqual((result["status"], result["reason"]), ("failed", "resource-changed"))
        self.assertTrue(workspace.preserve)
        self.assertEqual([event["reason"] for event in self.retained], ["resource-changed"])

    def test_alias_change_blocks_the_cleanup_hook(self):
        def retarget(aliases):
            aliases.chmod(0o700)
            (aliases / "node").unlink()
            (aliases / "node").symlink_to(self.shadow / "node")
            aliases.chmod(0o500)

        result, launched, workspace = self.run_altered(retarget, during="main", hook=True)
        self.assertNotIn("hook", launched)
        self.assertEqual((result["status"], result["reason"]), ("failed", "cleanup-failed"))
        self.assertTrue(workspace.preserve)
        self.assertEqual([event["reason"] for event in self.retained], ["cleanup-failed"])

    def test_unavailable_tool_blocks_contextual_suite(self):
        selection = self.selection()
        with self.assertRaises(AepmError) as caught:
            self.environment({"xcrun": "72"}, selection=selection)
        self.assertEqual((caught.exception.code, caught.exception.path), ("tool-unavailable", "xcrun"))
        workspace = Mock(preserve=False)
        workspace.__enter__ = Mock(return_value=self.root / "private")
        workspace.__exit__ = Mock(return_value=False)
        (self.root / "private").mkdir(mode=0o700, exist_ok=True)
        source = self.root / "source"
        source.mkdir()
        suite = {"package": "a" * 64, "id": "apple", "scope": "platform", "root": "package", "argv": ["xcrun", "x"],
                 "cwd": ".", "prepare": [], "tools": {"xcrun": "72"}, "fixtures": [], "locks": [], "network": False,
                 "timeoutSeconds": 30, "requirements": [], "execution": {"kind": "local", "simulation": False,
                 "operations": [], "settings": [], "secrets": [], "resources": [], "assertions": [], "cleanup": None}}
        execution = SimpleNamespace(check_time=lambda: None, run_id="fixture", authorization=None,
                                    prepare=lambda *_: ("local", {"settings": {}, "operations": [], "simulationKind": None}, [], [], {}))
        with patch.object(contextual, "VerificationDirectory", return_value=workspace), \
                patch.object(contextual, "run", side_effect=AssertionError("no launch")):
            result, _ = contextual.execute(suite, source, False, self.root / "logs", execution, tool_selection=selection)
        self.assertEqual((result["status"], result["reason"]), ("blocked", "tool-unavailable"))

    def test_probe_lookups_apply_the_selection(self):
        executable(self.bin / "xcrun", b"bound xcrun")
        document = deepcopy(self.document)
        document["tools"]["xcrun"] = binding(self.bin / "xcrun")
        selection = self.selection(document)
        environment = {"PATH": selection.path}
        launched = []

        def run(argv, *args, **kwargs):
            launched.append(argv)
            return 0, 0, "", b"{}"

        with patch.object(contextual, "run", side_effect=run):
            contextual.probe_json(["xcrun", "simctl", "list", "-j"], self.root, environment, tool_selection=selection)
            self.assertEqual(launched[-1][0], str(self.bin / "xcrun"))
            shadowed = {"PATH": os.pathsep.join([str(self.shadow), selection.path])}
            with self.assertRaises(AepmError) as caught:
                contextual.probe_json(["xcrun", "simctl", "list", "-j"], self.root, shadowed, tool_selection=selection)
            self.assertEqual(caught.exception.code, "resource-changed")
            self.assertEqual(len(launched), 1)
            resource = {"PATH": os.pathsep.join([str(self.shadow), selection.path])}
            contextual.probe_json(["xcodebuild", "-list"], self.root, resource, tool_selection=selection,
                                  resource_names=frozenset({"xcodebuild"}))
            self.assertEqual(launched[-1][0], str(self.shadow / "xcodebuild"))
        with self.assertRaises(AepmError) as caught:
            contextual._selected_which("xcodebuild", shadowed, selection, frozenset())
        self.assertEqual(caught.exception.code, "tool-unavailable")

    def test_undeclared_system_programs_resolve(self):
        selection = self.selection()
        environment = self.environment({"python3": "3.12"}, selection=selection)
        for name in ("sh", "uname", "env", "dirname"):
            self.assertIsNotNone(shutil.which(name, path=environment["PATH"]), name)


class OrdinarySuiteTests(Guarded):
    def suite(self, tools):
        return {"package": "a" * 64, "id": "ordinary", "scope": "platform", "root": "package", "argv": ["python3", "-c", "pass"],
                "cwd": ".", "prepare": [], "tools": tools, "fixtures": [], "locks": [], "network": False,
                "timeoutSeconds": 30, "expectedExit": 0, "requirements": []}

    def execute(self, selection, tools, run=None):
        private = self.root / "private"
        shutil.rmtree(private, ignore_errors=True)
        private.mkdir(mode=0o700)
        workspace = Mock(preserve=False)
        workspace.__enter__ = Mock(return_value=private)
        workspace.__exit__ = Mock(return_value=False)
        source = self.root / "source"
        source.mkdir(exist_ok=True)
        with patch.object(verification, "VerificationDirectory", return_value=workspace), \
                patch.object(verification, "run", side_effect=run or AssertionError("no launch")), \
                patch.dict(os.environ, {"PATH": os.pathsep.join([str(self.shadow), os.environ.get("PATH", os.defpath)])}):
            return verification.execute_suite(self.suite(tools), source, False, self.root / "logs", tool_selection=selection), private

    def test_links_target_binding_and_path_is_finite(self):
        selection = self.selection()
        home = self.root / "home-check"
        environment = verification.execution_environment(home, {"python3": "3.12"}, tool_selection=selection)
        self.assertEqual(os.readlink(home / "bin/python3"), str(self.python))
        self.assertEqual(environment["PATH"], os.pathsep.join([str(home / "bin"), selection.path]))
        for name in ("sh", "uname", "env", "dirname"):
            self.assertIsNotNone(shutil.which(name, path=environment["PATH"]), name)

    def test_unavailable_name_blocks_without_launch(self):
        result, _ = self.execute(self.selection(), {"xcrun": "72"})
        self.assertEqual((result["status"], result["reason"]), ("blocked", "tool-unavailable"))

    def test_version_outputs_are_strict(self):
        for output, status, reason in ((b"Python 3.9.6\n", "blocked", "tool-version-mismatch"),
                                       (b"Python 3.12.8\n", "passed", "")):
            with self.subTest(output=output):
                calls = []

                def run(argv, *args, **kwargs):
                    calls.append(argv)
                    return 0, 0, "", output

                result, _ = self.execute(self.selection(), {"python3": "3.12"}, run)
                self.assertEqual((result["status"], result["reason"]), (status, reason))

    def test_link_drift_before_launch_fails_closed(self):
        selection = self.selection()

        def run(argv, cwd, environment, *args):
            link = Path(environment["PATH"].split(os.pathsep)[0]) / "python3"
            link.unlink()
            link.symlink_to(self.shadow / "python3")
            return 0, 0, "", b"Python 3.12.8\n"

        with self.assertRaises(AepmError) as caught:
            self.execute(selection, {"python3": "3.12"}, run)
        self.assertEqual(caught.exception.code, "resource-changed")


class EntryTests(Guarded):
    def test_entry_points_reject_non_selection(self):
        from aepm import update
        calls = [lambda: verification.verify_application(self.root, self.root / "p", True, tool_selection="x"),
                 lambda: verification.review_package({}, self.root, self.root / "p", True, tool_selection="x"),
                 lambda: update.propose(self.root, {}, self.root, self.root / "p", True, tool_selection="x"),
                 lambda: verification.make_report({}, "", {}, {}, None, self.root / "p", True, False, "review",
                                                  self.root / "logs", tool_selection="x")]
        for index, call in enumerate(calls):
            with self.subTest(index=index), self.assertRaises(AepmError) as caught:
                call()
            self.assertEqual(caught.exception.code, "tool-selection-invalid")

    def test_make_report_forwards_selection_without_changing_execution_options(self):
        selection = self.selection()
        suites = [{"package": "a" * 64, "id": "ordinary", "root": "package", "scope": "platform", "requirements": []}]
        seen = []
        with patch("aepm.trust.load_policy", return_value={"trustedExecution": ["a" * 64]}), \
                patch.object(verification, "declarations", return_value=suites), \
                patch("aepm.authorization.bindings", return_value={}), \
                patch("aepm.environment.Execution", side_effect=AssertionError("no contextual execution")), \
                patch.object(verification, "execute_suite",
                             side_effect=lambda *a, tool_selection=None: seen.append(tool_selection) or
                             {"package": "a" * 64, "id": "ordinary", "scope": "platform", "status": "blocked",
                              "exitCode": None, "seconds": 0, "reason": "tool-unavailable", "logDigest": "0" * 64}):
            report = verification.make_report({"packages": [{"digest": "a" * 64, "name": "x", "version": "1.0.0",
                                                             "dependencies": []}]}, "", {}, {"a" * 64: self.root}, None,
                                              self.root / "p", True, False, "review", self.root / "logs",
                                              tool_selection=selection)
        self.assertEqual(seen, [selection])
        self.assertEqual(report["suites"][0]["reason"], "tool-unavailable")


if __name__ == "__main__":
    unittest.main()
