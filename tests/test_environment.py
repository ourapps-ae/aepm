import os
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest.mock import patch

from aepm.environment import materialize, resource_records, validate_resource, prepare_working_resources, describe_resource
from aepm.contextual import tool_environment, tool_versions
from aepm.process import run
from aepm.model import AepmError, canonical, digest


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "cache"
        self.source.mkdir()
        (self.source / "lock").write_text("pinned bytes")
        self.resource = {"id": "androidCache", "kind": "directory", "path": str(self.source), "digest": "0" * 64, "executables": []}
        self.resource["digest"] = digest(canonical(resource_records(self.resource)))

    def test_real_copy_and_mutation_rejection(self):
        copied = materialize(self.resource, self.root / "private")
        self.assertEqual(resource_records(copied), resource_records(self.resource))
        (Path(copied["path"]) / "lock").write_text("altered")
        with self.assertRaisesRegex(AepmError, "resource-changed"):
            validate_resource(copied)

    def test_declared_root_kind_must_match(self):
        for changed in ({**self.resource, "kind": "file"}, {**self.resource, "path": str(self.source / "lock")}):
            with self.assertRaisesRegex(AepmError, "resource-kind"):
                resource_records(changed)

    @unittest.skipIf(os.name == "nt", "Windows rejects reparse points")
    def test_contained_links_materialize_and_escape_cycle_reject(self):
        (self.source / "alias").symlink_to("lock")
        self.resource["digest"] = digest(canonical(resource_records(self.resource)))
        copied = materialize(self.resource, self.root / "private")
        self.assertFalse((Path(copied["path"]) / "alias").is_symlink())
        (self.source / "cycle").symlink_to(self.source)
        with self.assertRaises(AepmError):
            resource_records(self.resource)
        (self.source / "cycle").unlink()
        (self.root / "outside").write_text("outside")
        (self.source / "escape").symlink_to(self.root / "outside")
        with self.assertRaises(AepmError):
            resource_records(self.resource)

    def test_source_change_during_copy_rejects(self):
        import shutil
        original = shutil.copyfile

        def changed(source, target):
            result = original(source, target)
            (self.source / "lock").write_text("changed after copying")
            return result

        with patch("aepm.environment.shutil.copyfile", changed), self.assertRaises(AepmError):
            materialize(self.resource, self.root / "private")

    @unittest.skipIf(os.name == "nt", "POSIX symbolic links required")
    def test_readonly_inventory_binds_links_without_expanding_ancestors(self):
        contents = self.root / "Xcode.app/Contents"
        developer = contents / "Developer"
        developer.mkdir(parents=True)
        framework = contents / "SharedFrameworks"
        framework.mkdir()
        (framework / "tool").write_text("real tool bytes")
        (developer / "alias").symlink_to("../SharedFrameworks/tool")
        (developer / "ancestor").symlink_to(".")
        resource = {"id": "appleDeveloperDirectory", "kind": "directory", "path": str(developer),
                    "inventoryRoot": str(contents), "digest": "0" * 64, "executables": []}
        records = resource_records(resource)
        self.assertEqual(len(records), 6)
        self.assertEqual(sum(item["kind"] == "link" for item in records), 2)
        resource["digest"] = digest(canonical(records))
        validate_resource(resource)
        (framework / "tool").write_text("modified target")
        with self.assertRaisesRegex(AepmError, "resource-changed"):
            validate_resource(resource)
        (developer / "alias").unlink()
        (developer / "alias").symlink_to("../SharedFrameworks/./tool")
        self.assertNotEqual(digest(canonical(resource_records(resource))), resource["digest"])
        (developer / "loop-a").symlink_to("loop-b")
        (developer / "loop-b").symlink_to("loop-a")
        with self.assertRaisesRegex(AepmError, "resource-cycle"):
            resource_records(resource)

    def test_inventory_root_refused_for_copies_and_wrong_relation(self):
        for resource in ({**self.resource, "inventoryRoot": str(self.root)},
                         {**self.resource, "id": "appleDeveloperDirectory", "inventoryRoot": str(self.root)}):
            with self.assertRaisesRegex(AepmError, "resource-boundary"):
                resource_records(resource)

    def test_four_hundred_three_executable_inputs_are_representable(self):
        executable_paths = []
        for index in range(403):
            name = "tool" + str(index)
            path = self.source / name
            path.write_bytes(b"synthetic executable")
            path.chmod(0o755)
            executable_paths.append(name)
        resource = {**self.resource, "id": "androidSdk", "executables": sorted(executable_paths)}
        records = resource_records(resource)
        self.assertEqual(sum(item["mode"] == 0o755 and item["kind"] == "file" for item in records), 403)
        described = describe_resource("androidSdk", self.source, executables=sorted(executable_paths) if os.name == "nt" else None)
        self.assertEqual(described["executables"], resource["executables"])
        validate_resource(described)

    def test_working_cache_mutation_leaves_validated_input_unchanged(self):
        protocol = self.root / "protocol"
        prepare_working_resources([self.resource], protocol)
        self.assertEqual((protocol / "gradle-working/lock").read_bytes(), (self.source / "lock").read_bytes())
        (protocol / "gradle-working/lock").write_text("derived cache update")
        (protocol / "gradle-working/new-index").write_text("generated metadata")
        validate_resource(self.resource)
        environment = tool_environment(self.root / "home", {}, [self.resource])
        self.assertEqual(environment["GRADLE_USER_HOME"], str(protocol / "gradle-working"))

    def test_missing_optional_cache_is_private_empty_directory(self):
        prepare_working_resources([], self.root / "protocol")
        environment = tool_environment(self.root / "home", {}, [])
        cache = Path(environment["GRADLE_USER_HOME"])
        self.assertEqual(cache, self.root / "protocol/gradle-working")
        self.assertEqual(list(cache.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture; actual Windows test is separate")
    def test_sdk_tool_selection_uses_verified_working_clone_and_rejects_escape(self):
        platform_tools = self.source / "platform-tools"
        platform_tools.mkdir()
        (platform_tools / "adb").write_text("#!/bin/sh\nexit 0\n")
        (platform_tools / "adb").chmod(0o755)
        resource = {**self.resource, "id": "androidSdk", "executables": ["platform-tools/adb"]}
        resource["digest"] = digest(canonical(resource_records(resource)))
        prepare_working_resources([resource], self.root / "protocol")
        environment = tool_environment(self.root / "home", {"adb": "1"}, [resource])
        working = self.root / "protocol/android-sdk-working"
        self.assertEqual(environment["ANDROID_HOME"], str(working))
        self.assertIn(str(working / "platform-tools"), environment["PATH"].split(os.pathsep))
        target = working / "platform-tools/adb"
        target.unlink()
        target.symlink_to(platform_tools / "adb")
        with self.assertRaisesRegex(AepmError, "resource-changed"):
            tool_environment(self.root / "other-home", {"adb": "1"}, [resource])

    @unittest.skipIf(os.name == "nt", "Simulated POSIX installed-tool fixture")
    def test_simulated_integer_tool_version_is_accepted(self):
        tool = self.root / "xcrun"
        tool.write_text("#!/bin/sh\nprintf 'xcrun version 72.\\n'\n")
        tool.chmod(0o755)
        environment = {"PATH": str(self.root) + os.pathsep + os.defpath}
        self.assertEqual(tool_versions({"tools": {"xcrun": "72"}}, self.root, environment), {"xcrun": "72"})

    @unittest.skipUnless(shutil.which("java"), "Installed Java unavailable for private-home check")
    def test_installed_java_observes_private_home_with_spaces(self):
        home = self.root / "private home"
        environment = tool_environment(home, {"java": "installed"}, [])
        command = shutil.which("java", path=environment["PATH"])
        code, _, reason, output = run([command, "-XshowSettings:properties", "-version"], self.root, environment, 10, 65536)
        self.assertEqual((code, reason), (0, ""))
        self.assertIn(("user.home = " + str(home)).encode(), output)
