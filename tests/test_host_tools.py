import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aepm.host_tools import host_tool, version_matches
from aepm.model import AepmError, validate_component
from aepm.verification import execution_environment
from tests.core.test_core import fixture


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    return path


class HostToolTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.real = executable(self.root / ".pyenv/versions/3.12.8/bin/python3.12", "#!/bin/sh\necho Python 3.12.8\n")
        (self.real.parent / "python3").symlink_to("python3.12")
        executable(self.root / ".pyenv/shims/python3", "#!/bin/sh\nexit 3\n")
        executable(self.root / ".pyenv/bin/pyenv",
                   f"#!/bin/sh\n[ \"$1\" = which ] && [ \"$2\" = python3 ] && echo {self.real.parent / 'python3'} && exit 0\nexit 1\n")
        self.path = str(self.root / ".pyenv/shims") + os.pathsep + "/usr/bin:/bin"

    def test_shim_resolves_to_the_managers_real_executable(self):
        self.assertEqual(host_tool("python3", self.path), self.real)
        self.assertIsNone(host_tool("absent-tool-name", self.path))

    def test_plain_executable_and_links_resolve(self):
        link = self.root / "bin/python3"
        link.parent.mkdir()
        link.symlink_to(self.real)
        self.assertEqual(host_tool("python3", str(link.parent)), self.real)

    def test_unresolvable_shim_is_unavailable(self):
        (self.root / ".pyenv/bin/pyenv").write_text("#!/bin/sh\nexit 1\n")
        self.assertIsNone(host_tool("python3", self.path))
        (self.root / ".pyenv/bin/pyenv").unlink()
        with patch("aepm.host_tools.shutil.which", side_effect=lambda name, path=None:
                   str(self.root / ".pyenv/shims/python3") if name == "python3" else None):
            self.assertIsNone(host_tool("python3"))

    def test_execution_environment_links_the_real_executable(self):
        with patch.dict(os.environ, {"PATH": self.path}):
            environment = execution_environment(self.root / "home", {"python3": "3.12"})
        self.assertEqual(Path(os.readlink(self.root / "home/bin/python3")), self.real)
        self.assertTrue(environment["PATH"].startswith(str(self.root / "home/bin")))

    def test_versions_match_by_leading_components(self):
        self.assertEqual(version_matches("Python 3.12.8", "3.12"), "3.12.8")
        self.assertEqual(version_matches("v26.5.0", "26"), "26.5.0")
        self.assertEqual(version_matches("Xcode 27.2\nBuild version 27B52", "27.2"), "27.2")
        self.assertIsNone(version_matches("Python 3.1.4", "3.12"))
        self.assertIsNone(version_matches("Python 13.12.0", "3.12"))

    def test_manifest_pins_are_numeric_versions(self):
        component = fixture(self.root / "pin")
        for pin in ("3", "3.12", "26.5", "0.1"):
            changed = copy.deepcopy(component)
            changed["verification"][0]["tools"] = {"python3": pin}
            validate_component(changed)
        for pin in ("v3", "3.x", "03.1", "", "3.12-rc", "3.12.8.1"):
            changed = copy.deepcopy(component)
            changed["verification"][0]["tools"] = {"python3": pin}
            with self.subTest(pin=pin), self.assertRaises(AepmError) as caught:
                validate_component(changed)
            self.assertEqual(caught.exception.code, "invalid-tool-version")


if __name__ == "__main__":
    unittest.main()
