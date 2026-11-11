"""Scoped selection tests using fake executables and no launched tools."""

from copy import deepcopy
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aepm import contextual
from aepm.model import AepmError
from aepm.supervision import Recorder
from tests import test_android_discovery_fixture as fixtures
from tests import run_android_discovery_fixture as entry


class PythonSelectionTests(fixtures.GuardedTests):
    def selection(self):
        path, _, _ = fixtures.AndroidInventoryTests.inventory(self)
        inventory = entry.json.loads(path.read_bytes())
        context = entry.json.loads((path.parent / "android-context.json").read_bytes())
        return entry.PythonSelection(inventory, context), inventory, context

    def observer(self, selection):
        proxy = SimpleNamespace(run=Mock(return_value=(0, 0, "", b"unchanged")),
                                tool_environment=contextual.tool_environment,
                                resolve_command=contextual.resolve_command)
        harness = SimpleNamespace(pack=Mock(return_value=dict(entry.EXPECTED)))
        backend = type("FakeBackend", (), {"__init__": lambda self: None})
        observer = entry.AndroidObserver(harness, proxy, backend, Recorder, Mock(), self.root, "a" * 64, selection)
        observer.start()
        self.addCleanup(observer.close)
        return observer, proxy, harness

    def test_same_pin_for_version_preparation_and_main_with_unchanged_java_node(self):
        selection, _, context = self.selection()
        shim_dir = self.root / "ambient"
        shim_dir.mkdir()
        shim = shim_dir / "python3"
        shim.write_bytes(b"older shim")
        shim.chmod(0o755)
        old_path = os.pathsep.join([str(shim_dir), str(self.root), os.defpath])
        tools = {"java": "17", "python3": "3.12"}
        home = self.root / "private/home"
        with patch.dict(os.environ, {"PATH": old_path}):
            self.assertEqual(shutil.which("python3"), str(shim))
            self.assertEqual(shutil.which("node"), selection.tools["node"]["alias"])
            original_environment = contextual.tool_environment(home, tools, context["resources"])
            with selection.scoped():
                observer, proxy, _ = self.observer(selection)
                environment = proxy.tool_environment(home, tools, context["resources"])
                self.assertEqual({k: v for k, v in environment.items() if k != "PATH"},
                                 {k: v for k, v in original_environment.items() if k != "PATH"})
                self.assertEqual(shutil.which("node"), selection.tools["node"]["alias"])
                bindings = {}
                for tail in (["--version"], ["scripts/platform-check.py", "prepare-android"],
                             ["scripts/platform-check.py", "android"]):
                    argv = proxy.resolve_command(["python3", *tail], self.root, tools, environment, bindings)
                    self.assertEqual(argv, [selection.python["path"], *tail])
                    keywords = {} if tail == ["--version"] else {"diagnostics": Recorder()}
                    result = proxy.run(argv, self.root, environment, 900, 65536, **keywords)
                    self.assertEqual(result, (0, 0, "", b"unchanged"))
                    observer.original_run.assert_called_with(argv, self.root, environment, 900, 65536, **keywords)
                java = proxy.resolve_command(["java", "-version"], self.root, tools, environment, bindings)
                self.assertEqual(java[0], selection.tools["java"]["canonicalPath"])
                observer.close()
            self.assertEqual(os.environ["PATH"], old_path)

    def test_scoped_path_restored_on_success_and_exception(self):
        selection, _, _ = self.selection()
        with patch.dict(os.environ, {"PATH": "original-parent-path"}):
            with selection.scoped():
                self.assertEqual(os.environ["PATH"], selection.path)
            self.assertEqual(os.environ["PATH"], "original-parent-path")
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with selection.scoped():
                    raise RuntimeError("fixture")
            self.assertEqual(os.environ["PATH"], "original-parent-path")

    def test_alias_bytes_mode_and_path_drift_refused_before_pack(self):
        selection, _, _ = self.selection()
        alias = Path(selection.tools["python3"]["alias"])
        target = Path(selection.python["path"])
        original = target.read_bytes()
        with selection.scoped():
            observer, _, harness = self.observer(selection)
            for fault in ("missing", "redirect", "bytes", "mode", "path", "node"):
                with self.subTest(fault=fault):
                    if fault == "missing":
                        alias.unlink()
                    elif fault == "redirect":
                        alias.unlink()
                        alias.symlink_to("node")
                    elif fault == "bytes":
                        target.write_bytes(b"changed")
                    elif fault == "mode":
                        target.chmod(0o644)
                    elif fault == "path":
                        os.environ["PATH"] = os.defpath
                    else:
                        Path(selection.tools["node"]["canonicalPath"]).write_bytes(b"changed")
                    with self.assertRaises((ValueError, OSError)):
                        harness.pack("source", "store")
                    observer.original_pack.assert_not_called()
                    if fault in ("missing", "redirect"):
                        alias.unlink(missing_ok=True)
                        alias.symlink_to("python")
                    target.write_bytes(original)
                    target.chmod(0o755)
                    os.environ["PATH"] = selection.path
                    Path(selection.tools["node"]["canonicalPath"]).write_bytes(b"node")

    def test_inventory_and_controller_mismatch_rejected(self):
        _, inventory, context = self.selection()
        for fault in ("version", "alias", "target", "controller", "fallback"):
            changed = deepcopy(inventory)
            with self.subTest(fault=fault):
                if fault == "version":
                    changed["python"]["version"] = "3.9.6"
                elif fault == "alias":
                    changed["toolBindings"]["python3"]["links"][0]["target"] = "node"
                elif fault == "target":
                    changed["toolBindings"]["python3"]["canonicalPath"] = str(self.root / "node")
                elif fault == "fallback":
                    changed["launchPath"].append("/unreviewed")
                with patch.object(entry.sys, "executable", str(self.root / "node") if fault == "controller" else inventory["python"]["path"]):
                    with self.assertRaises((ValueError, OSError)):
                        entry.PythonSelection(changed, context)

    def test_resolution_and_launch_refuse_late_alias_change(self):
        selection, _, context = self.selection()
        tools = {"java": "17", "python3": "3.12"}
        with selection.scoped():
            observer, proxy, _ = self.observer(selection)
            environment = proxy.tool_environment(self.root / "home", tools, context["resources"])
            argv = proxy.resolve_command(["python3", "--version"], self.root, tools, environment, {})
            Path(selection.tools["python3"]["alias"]).unlink()
            with self.assertRaises((ValueError, OSError)):
                proxy.resolve_command(["python3", "--version"], self.root, tools, environment, {})
            with self.assertRaises((ValueError, OSError)):
                proxy.run(argv, self.root, environment, 10, 65536)
            observer.original_run.assert_not_called()

    def test_version_comparison_is_strict(self):
        for output, matched in ((b"Python 3.9.6\n", False), (b"Python 3.12.8\n", True)):
            with self.subTest(output=output), patch.object(contextual, "resolve_command", return_value=["fake-python", "--version"]), \
                    patch.object(contextual, "run", return_value=(0, 0, "", output)):
                if matched:
                    self.assertEqual(contextual.tool_versions({"tools": {"python3": "3.12"}}, self.root, {}), {"python3": "3.12.8"})
                else:
                    with self.assertRaises(AepmError) as caught:
                        contextual.tool_versions({"tools": {"python3": "3.12"}}, self.root, {})
                    self.assertEqual(caught.exception.code, "tool-version-mismatch")
