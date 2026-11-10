import contextlib
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from aepm import update
from aepm.__main__ import main
from aepm.application import assemble, configuration, read_assembly, requirements, substitute, validate_definition
from aepm.bundle import pack, read_package, resolve
from aepm.export import export_design
from aepm.io import load, snapshot, write
from aepm.model import AepmError, canonical, digest
from aepm.test_identities import generate
from aepm.trust import (RELEASE, publish_release, publish_review, release_statement, review_bindings, sign, verify,
                        verify_package)
from aepm.verification import check_report, retained_manifests, review_package, verify_application
from aepm.verification import execute_suite
from tests.core.test_core import fixture


def source(root, name, version="0.1.0", recipe=False):
    manifest = fixture(root, name, version)
    manifest["verification"][1]["requirements"] = ["external:native-host"]
    manifest["kind"] = "recipe" if recipe else "component"
    manifest["collect"] = [{"id": "count", "type": "integer", "grammar": "integer", "required": True, "secret": False, "default": 7}]
    visual = {"id": "ourapps-ae." + name, "name": name, "kind": "application" if recipe else "component", "status": "example",
              "ports": [], "settings": [{"id": "count", "name": "Count", "type": "number", "required": True, "secret": False, "default": 7}]}
    visual.update({"revision": version} if recipe else {"package": "ourapps-ae/" + name, "version": version})
    write(root / "visual.json", visual)
    (root / "source.txt").write_text("count={{count}}\nversion=" + version + "\n")
    manifest["files"].append({"path": "source.txt", "executable": False})
    manifest["artefacts"] = [{"source": "source.txt", "destination": "app.txt" if recipe else "components/" + name + "/value.txt",
                              "template": True, "executable": False}]
    if recipe:
        manifest["verification"].append({**deepcopy(manifest["verification"][0]), "id": "assembled", "root": "application",
                                          "argv": ["python3", "-c", "from pathlib import Path; assert Path('app.txt').read_text().startswith('count=7'); assert Path('components/sample/value.txt').exists()"],
                                          "fixtures": ["app.txt"]})
    write(root / "component.json", manifest)
    return manifest


class ApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.base = Path(cls.workspace.name).resolve()
        cls.identities = cls.base / "identities"
        cls.policy = generate(cls.identities)
        cls.store = cls.base / "store"
        cls.refs = []
        for name, version, recipe in (("sample", "0.1.0", False), ("sample", "0.1.1", False), ("recipe", "0.1.0", True)):
            directory = cls.base / (name + version)
            source(directory, name, version, recipe)
            ref = pack(directory, cls.store)
            cls.refs.append(ref)
            component, _ = read_package(ref, cls.store)
            statements = cls.store / "statements" / ref["digest"]
            statements.mkdir(parents=True)
            publish_release(cls.store, ref, cls.identities / "release.pem")
        policy = load(cls.policy)
        policy["trustedExecution"] = [ref["digest"] for ref in cls.refs]
        write(cls.policy, policy)
        for ref in cls.refs:
            report = review_package(ref, cls.store, cls.policy, True)
            if report["summary"]["required-local"] != "passed":
                raise AssertionError(report)
            binding = review_bindings(ref, cls.store)
            for field in ("lockDigest", "assemblyDigest", "packages", "suiteSetDigest"):
                if report[field] != binding[field]:
                    raise AssertionError(field)
            statements = cls.store / "statements" / ref["digest"]
            publish_review(cls.store, ref, report, cls.identities / "guardian.pem")
            verify_package(ref, cls.store, cls.policy)
        cls.definition = {"format": 1, "id": "sample-app", "title": "Sample", "recipe": {"name": "ourapps-ae/recipe", "version": "0.1.0"},
                          "components": [{"id": "sample", "name": "ourapps-ae/sample", "version": "0.1.0", "configuration": {}}],
                          "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []}, "updatePolicy": "patch"}
        cls.lock = resolve(requirements(cls.definition), cls.store / "catalogue.json", cls.definition["id"], digest(canonical(cls.definition)))
        cls.assembly = assemble(cls.definition, cls.lock, cls.store, cls.base / "baseline", cls.policy)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.app = self.root / "app"
        shutil.copytree(self.base / "baseline", self.app)
        self.definition = deepcopy(type(self).definition)

    def proposal(self):
        self.definition["components"][0]["version"] = "0.1.1"
        value = update.propose(self.app, self.definition, self.store, self.policy, True)
        path = self.root / "proposal.json"
        write(path, value)
        return path, value

    def approval(self, proposal):
        return update.approve(proposal, self.identities / "owner.pem", self.policy)

    def publish_recipe(self, mutate):
        self.store = self.root / "store"
        shutil.copytree(type(self).store, self.store)
        directory = self.root / "recipe"
        manifest = source(directory, "recipe", "0.1.1", True)
        mutate(manifest)
        write(directory / "component.json", manifest)
        ref = pack(directory, self.store)
        component, _ = read_package(ref, self.store)
        statements = self.store / "statements" / ref["digest"]
        statements.mkdir(parents=True)
        publish_release(self.store, ref, self.identities / "release.pem")
        policy = load(type(self).policy)
        policy["trustedExecution"].append(ref["digest"])
        self.policy = self.root / "policy.json"
        write(self.policy, policy)
        report = review_package(ref, self.store, self.policy, True)
        publish_review(self.store, ref, report, self.identities / "guardian.pem")
        self.definition["recipe"]["version"] = "0.1.1"
        return ref

    def command(self, *args, code=0):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            actual = main(list(map(str, args)))
        result = json.loads(output.getvalue())
        self.assertEqual(actual, code, result)
        return result

    def test_complete_report_private_execution_and_integer_export(self):
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "DO-NOT-INHERIT"}):
            report = verify_application(self.app, self.policy, True)
        self.assertEqual(report["summary"], {"required-local": "passed", "platform": "blocked", "deployed": "not-applicable"})
        self.assertEqual(len(report["suites"]), 5)
        self.assertEqual(snapshot(self.app), snapshot(self.base / "baseline"))
        output = export_design(self.assembly, self.root / "diagrams")
        design = load(output["design"])
        self.assertEqual(design["schemaVersion"], 2)
        for instance in design["instances"]:
            self.assertEqual(instance["configuration"], self.assembly["configuration"][instance["id"]])
        self.assertEqual(design["definitions"][0]["settings"][0]["type"], "number")
        self.assertGreater(Path(output["png"]).stat().st_size, 100)

    def test_report_omission_duplicate_extra_and_partition_fail_closed(self):
        assembly, manifests = retained_manifests(self.app, self.policy)
        report = verify_application(self.app, self.policy, True)
        for mutation in (lambda r: r["suites"].pop(), lambda r: r["suites"].append(r["suites"][0]),
                         lambda r: r["summary"].update(platform="passed"),
                         lambda r: r["suites"].append({**r["suites"][0], "id": "extra"})):
            changed = deepcopy(report)
            mutation(changed)
            with self.assertRaises(AepmError):
                check_report(changed, assembly["lock"], digest(canonical(assembly)), manifests)

    def test_configuration_delimiters_types_and_single_pass(self):
        declaration = [{"id": "value", "type": "string", "grammar": "label", "required": True, "secret": False}]
        for value in ('bad"', "bad'", "bad$", "bad`", "bad\\", "bad\n", "{{other}}", "{{value}}", "bad{", "bad}"):
            with self.subTest(value=value), self.assertRaises(AepmError):
                configuration(declaration, {"value": value})
        values = configuration(declaration, {"value": "Safe Label"})
        self.assertEqual(substitute('"{{value}}"', declaration, values), '"Safe Label"')
        with self.assertRaises(AepmError):
            substitute("const name = {{value}}", declaration, values)
        with self.assertRaises(AepmError):
            substitute('echo "{{value}}"', declaration, values, shell=True)
        for text in ("{{unknown}}", "{{ value }}", "{{value}", "{{{value}}}"):
            with self.assertRaises(AepmError):
                substitute(text, declaration, values)
        with self.assertRaises(AepmError):
            substitute("{{value}}", declaration, values, destination=True)
        integer = [{"id": "count", "type": "integer", "grammar": "integer", "required": True, "secret": False}]
        for value in (True, 1.5, "1", 2 ** 31):
            with self.assertRaises(AepmError):
                configuration(integer, {"count": value})

    def test_untrusted_and_retained_edits_rejected(self):
        with self.assertRaises(AepmError):
            verify_application(self.app, self.policy, False)
        policy = load(self.policy)
        policy["trustedExecution"] = []
        write(self.root / "policy.json", policy)
        with self.assertRaises(AepmError):
            verify_application(self.app, self.root / "policy.json", True)
        ref = self.refs[0]
        (self.app / ".aepm/packages" / ref["digest"] / "test.py").write_text("raise SystemExit(0)")
        with self.assertRaises(AepmError):
            verify_application(self.app, self.policy, True)

    def test_update_preserves_unmanaged_and_keeps_backup(self):
        self.app.chmod(0o750)
        (self.app / "notes.txt").write_text("keep me")
        (self.app / ".aepm/custom-empty").mkdir()
        proposal, value = self.proposal()
        approval = self.approval(proposal)
        assembly = update.apply(self.app, proposal, approval, self.policy)
        self.assertIn("0.1.1", (self.app / "components/sample/value.txt").read_text())
        self.assertEqual((self.app / "notes.txt").read_text(), "keep me")
        self.assertTrue((self.app / ".aepm/custom-empty").is_dir())
        self.assertEqual(self.app.stat().st_mode & 0o7777, 0o750)
        self.assertTrue((Path(value["stage"]).parent / "backup/notes.txt").exists())
        self.assertEqual(update.recover(self.app), assembly)

    def test_owned_edits_prevent_proposal(self):
        (self.app / "app.txt").write_text("local edit")
        with self.assertRaises(AepmError):
            self.proposal()

    def test_forged_assembly_file_hash_is_rejected(self):
        (self.app / "app.txt").write_text("local edit")
        assembly = load(self.app / ".aepm/assembly.json")
        next(item for item in assembly["files"] if item["path"] == "app.txt")["digest"] = digest(b"local edit")
        write(self.app / ".aepm/assembly.json", assembly)
        with self.assertRaises(AepmError):
            self.proposal()

    def test_failed_application_verification_blocks_proposal(self):
        self.publish_recipe(lambda manifest: manifest["verification"][-1].update(argv=["python3", "-c", "raise SystemExit(9)"]))
        before = snapshot(self.app)
        with self.assertRaisesRegex(AepmError, "report-verdict"):
            self.proposal()
        self.assertEqual(snapshot(self.app), before)

    def test_new_owned_file_and_unmanaged_ancestor_collisions(self):
        self.publish_recipe(lambda manifest: manifest["artefacts"].append({"source": "source.txt", "destination": "custom/new.txt", "template": True, "executable": False}))
        (self.app / "custom").mkdir()
        with self.assertRaisesRegex(AepmError, "unmanaged-collision"):
            self.proposal()
        (self.app / "custom/new.txt").write_text("my file")
        with self.assertRaisesRegex(AepmError, "unmanaged-collision"):
            self.proposal()

    def test_scrubbed_environment_rooted_preparation_network_and_output_limit(self):
        directory = self.root / "execution"
        directory.mkdir()
        (directory / "fixture").write_text("fixture")
        suite = {"package": "0" * 64, "id": "scrub", "scope": "required-local", "root": "package",
                 "argv": ["python3", "-c", "import os; from pathlib import Path; assert 'AWS_SECRET_ACCESS_KEY' not in os.environ; assert Path('prepared').read_text() == 'ready'"],
                 "cwd": ".", "prepare": [{"argv": ["python3", "-c", "from pathlib import Path; Path('prepared').write_text('ready')"], "cwd": ".", "network": False}],
                 "tools": {"python3": "3"}, "fixtures": ["fixture"], "locks": [], "network": False, "timeoutSeconds": 10,
                 "expectedExit": 0, "requirements": []}
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "PRIVATE_SENTINEL"}):
            report = execute_suite(suite, directory, False, self.root / "logs")
        self.assertEqual(report["status"], "passed", report)
        events = load(self.root / "logs" / (report["logDigest"] + ".json"))
        self.assertTrue(events[0]["preparation"])
        self.assertFalse(events[1]["preparation"])
        self.assertFalse((directory / "prepared").exists())
        suite["prepare"][0]["network"] = True
        self.assertEqual(execute_suite(suite, directory, False, self.root / "logs")["status"], "blocked")
        suite["prepare"] = []
        suite["argv"] = ["python3", "-c", "import sys; sys.stdout.write('x' * (8 * 1024 * 1024 + 1))"]
        self.assertEqual(execute_suite(suite, directory, False, self.root / "logs")["reason"], "output-limit")

    def test_stale_unmanaged_addition_deletion_edit_mode(self):
        for mode in ("addition", "deletion", "edit", "mode", "root-mode"):
            with self.subTest(mode=mode):
                app = self.root / mode
                shutil.copytree(self.base / "baseline", app)
                (app / "notes").write_text("old")
                self.app = app
                proposal, _ = self.proposal()
                approval = self.approval(proposal)
                if mode == "addition":
                    (app / "new").write_text("new")
                elif mode == "deletion":
                    (app / "notes").unlink()
                elif mode == "edit":
                    (app / "notes").write_text("edited")
                elif mode == "mode":
                    (app / "notes").chmod(0o755)
                else:
                    app.chmod(0o750)
                before = snapshot(app)
                with self.assertRaises(AepmError):
                    update.apply(app, proposal, approval, self.policy)
                self.assertEqual(snapshot(app), before)

    def test_missing_wrong_role_stale_owner_and_staged_edit(self):
        proposal, value = self.proposal()
        with self.assertRaises((AepmError, OSError)):
            update.apply(self.app, proposal, self.root / "missing", self.policy)
        with self.assertRaises(AepmError):
            update.approve(proposal, self.identities / "guardian.pem", self.policy)
        approval = self.approval(proposal)
        (Path(value["stage"]) / "extra.txt").write_text("unapproved")
        with self.assertRaises(AepmError):
            update.apply(self.app, proposal, approval, self.policy)

    def test_interrupt_both_renames_before_and_after(self):
        actual_rename = update.rename
        for boundary in range(1, 3):
            for after in (False, True):
                with self.subTest(boundary=boundary, after=after):
                    self.app = self.root / ("app" + str(boundary) + str(after))
                    shutil.copytree(self.base / "baseline", self.app)
                    self.app.chmod(0o750)
                    (self.app / "notes").write_text("preserve")
                    before = snapshot(self.app)
                    proposal, _ = self.proposal()
                    approval = self.approval(proposal)
                    calls = 0

                    def interrupted(source, target):
                        nonlocal calls
                        calls += 1
                        if calls == boundary and not after:
                            raise InterruptedError()
                        actual_rename(source, target)
                        if calls == boundary and after:
                            raise InterruptedError()

                    with patch.object(update, "rename", interrupted), self.assertRaises(AepmError):
                        update.apply(self.app, proposal, approval, self.policy)
                    update.recover(self.app)
                    self.assertEqual(snapshot(self.app), before)

    def test_interrupt_journal_writes(self):
        actual_journal = update.journal
        for phase in ("prepared", "moving-old", "old-moved", "moving-new", "new-moved", "committed"):
            with self.subTest(phase=phase):
                self.app = self.root / phase
                shutil.copytree(self.base / "baseline", self.app)
                before = snapshot(self.app)
                proposal, _ = self.proposal()
                approval = self.approval(proposal)

                def interrupted(directory, value, current):
                    if current == phase:
                        raise InterruptedError()
                    actual_journal(directory, value, current)

                with patch.object(update, "journal", interrupted), self.assertRaises(AepmError):
                    update.apply(self.app, proposal, approval, self.policy)
                if phase != "prepared":
                    update.recover(self.app)
                self.assertEqual(snapshot(self.app), before)

    def test_recovery_preserves_mismatched_backup_and_stage_for_inspection(self):
        actual_journal = update.journal
        proposal, value = self.proposal()
        approval = self.approval(proposal)

        def interrupted(directory, state, phase):
            actual_journal(directory, state, phase)
            if phase == "old-moved":
                raise InterruptedError()

        with patch.object(update, "journal", interrupted), self.assertRaises(AepmError):
            update.apply(self.app, proposal, approval, self.policy)
        self.assertFalse(self.app.exists())
        stage = Path(value["stage"])
        (stage / "unapproved").write_text("new content")
        with self.assertRaisesRegex(AepmError, "recovery-stage-changed"):
            update.recover(self.app)
        self.assertTrue((stage / "unapproved").exists())
        self.assertTrue((stage.parent / "backup").exists())
        self.assertFalse(self.app.exists())
        (stage / "unapproved").unlink()
        (stage.parent / "backup/notes").write_text("unapproved old content")
        with self.assertRaisesRegex(AepmError, "recovery-backup-changed"):
            update.recover(self.app)
        self.assertEqual((stage.parent / "backup/notes").read_text(), "unapproved old content")

    def requiring_recipe(self, optional=None, port_required=True, connect=None, provided="ae/contract"):
        """Publish a recipe requiring `rules`; `optional` None omits the manifest field."""
        for stale in ("store", "recipe", "installed"):
            shutil.rmtree(self.root / stale, ignore_errors=True)
        entry = {"id": "rules", "type": "ae/contract", "version": "1.0.0", "path": "interface.txt"}
        if optional is not None:
            entry["optional"] = optional

        def mutate(manifest):
            manifest["requires"] = [entry]
            visual = load(self.root / "recipe/visual.json")
            visual["ports"] = [{"id": "rules", "name": "Rules", "direction": "input", "kind": "interface",
                                "type": "ae/contract", "version": "1.0.0", "required": port_required, "cardinality": "one"}]
            write(self.root / "recipe/visual.json", visual)

        self.publish_recipe(mutate)
        self.definition["design"] = {
            "definitions": [{"id": "provider", "name": "Provider", "kind": "service", "status": "example", "revision": "0.1.0",
                             "ports": [{"id": "rules", "name": "Rules", "direction": "output", "kind": "interface",
                                        "type": provided, "version": "1.0.0"}], "settings": []}],
            "instances": [{"id": "provider", "name": "Provider", "definition": "provider", "configuration": {}}],
            "connections": [{"source": {"instance": "provider", "port": "rules"}, "target": {"instance": "application", "port": "rules"}}]
            if connect else []}

    def install(self):
        lock = resolve(requirements(self.definition), self.store / "catalogue.json", self.definition["id"], digest(canonical(self.definition)))
        return assemble(self.definition, lock, self.store, self.root / "installed", self.policy)

    def application_port(self, assembly):
        recipe = next(item for item in assembly["design"]["definitions"] if item["kind"] == "application")
        return next(port for port in recipe["ports"] if port["id"] == "rules")

    def test_unconnected_optional_requirement_installs_and_keeps_records(self):
        self.requiring_recipe(optional=True, port_required=False)
        assembly = self.install()
        self.assertFalse(self.application_port(assembly)["required"])
        self.assertEqual(assembly["design"]["connections"], [])
        self.assertEqual(read_assembly(self.root / "installed"), assembly)
        retained_manifests(self.root / "installed", self.policy)
        output = export_design(assembly, self.root / "diagrams")
        self.assertIn(b"optional / one", Path(output["svg"]).read_bytes())
        self.assertGreater(Path(output["png"]).stat().st_size, 100)

    def test_unconnected_required_requirement_fails_install(self):
        for optional in (None, False):
            with self.subTest(optional=optional):
                self.requiring_recipe(optional=optional)
                with self.assertRaisesRegex(AepmError, "diagram"):
                    self.install()
                self.assertFalse((self.root / "installed").exists())

    def test_connected_optional_requirement_is_checked_for_type_and_version(self):
        self.requiring_recipe(optional=True, port_required=False, connect=True)
        assembly = self.install()
        self.assertEqual(len(assembly["design"]["connections"]), 1)
        retained_manifests(self.root / "installed", self.policy)
        shutil.rmtree(self.root / "installed")
        self.definition["design"]["definitions"][0]["ports"][0]["type"] = "ae/other"
        with self.assertRaisesRegex(AepmError, "diagram"):
            self.install()
        self.definition["design"]["definitions"][0]["ports"][0].update(type="ae/contract", version="2.0.0")
        with self.assertRaisesRegex(AepmError, "diagram"):
            self.install()

    def test_optional_requirement_needs_package_visual_port_not_required(self):
        self.requiring_recipe(optional=True, port_required=True)
        with self.assertRaisesRegex(AepmError, "diagram-interface"):
            self.install()

    def test_non_optional_requirement_takes_requiredness_from_visual_port(self):
        for optional in (None, False):
            with self.subTest(optional=optional):
                self.requiring_recipe(optional=optional, port_required=False)
                self.assertFalse(self.application_port(self.install())["required"])
                shutil.rmtree(self.root / "installed")

    def conditional_recipe(self, entries, components=True):
        """Publish a recipe whose extra artefacts are (destination, component-or-None) pairs."""
        for stale in ("store", "recipe", "installed"):
            shutil.rmtree(self.root / stale, ignore_errors=True)

        def mutate(manifest):
            for index, (destination, component) in enumerate(entries):
                path = "extra%d.txt" % index
                (self.root / "recipe" / path).write_text("extra %d\n" % index)
                manifest["files"].append({"path": path, "executable": False})
                artefact = {"source": path, "destination": destination, "template": False, "executable": False}
                if component:
                    artefact["component"] = component
                manifest["artefacts"].append(artefact)

        self.publish_recipe(mutate)
        self.definition["components"] = deepcopy(type(self).definition["components"]) if components else []

    def owned(self, assembly):
        return [item["path"] for item in assembly["files"]]

    def test_conditional_artefact_installs_only_with_its_component(self):
        sample = "ourapps-ae/sample"
        self.conditional_recipe([("optional.txt", sample)])
        with_component = self.install()
        self.assertIn("optional.txt", self.owned(with_component))
        self.assertEqual(read_assembly(self.root / "installed"), with_component)
        retained_manifests(self.root / "installed", self.policy)
        self.assertEqual((self.root / "installed/optional.txt").read_text(), "extra 0\n")
        shutil.rmtree(self.root / "installed")
        self.conditional_recipe([("optional.txt", sample)], components=False)
        without = self.install()
        self.assertEqual(self.owned(without), ["app.txt"])
        self.assertFalse((self.root / "installed/optional.txt").exists())
        self.assertEqual(read_assembly(self.root / "installed"), without)
        retained_manifests(self.root / "installed", self.policy)
        self.assertEqual([item["id"] for item in without["design"]["instances"]], ["application"])
        output = export_design(without, self.root / "diagrams")
        self.assertGreater(Path(output["png"]).stat().st_size, 100)

    def test_unconditional_and_other_component_artefacts_install(self):
        self.conditional_recipe([("plain.txt", None), ("missing.txt", "ourapps-ae/absent")])
        assembly = self.install()
        self.assertEqual(self.owned(assembly), ["app.txt", "components/sample/value.txt", "plain.txt"])

    def test_collision_and_owner_rules_apply_only_to_installed_artefacts(self):
        sample = "ourapps-ae/sample"
        for entries, code in ((
                [("notes", None), ("notes/extra.txt", sample)], "artefact-collision"),
                ([("components/sample/value.txt", sample)], "artefact-owner"),
                ([("components/other/x.txt", sample)], "artefact-owner")):
            with self.subTest(entries=entries):
                self.conditional_recipe(entries)
                with self.assertRaisesRegex(AepmError, code):
                    self.install()
                self.assertFalse((self.root / "installed").exists())
                self.conditional_recipe(entries, components=False)
                installed = self.install()
                self.assertNotIn(entries[-1][0], self.owned(installed))
                shutil.rmtree(self.root / "installed")

    def test_update_stages_conditional_artefact_when_component_is_present(self):
        self.conditional_recipe([("optional.txt", "ourapps-ae/sample")])
        shutil.rmtree(self.root / "installed", ignore_errors=True)
        value = update.propose(self.app, self.definition, self.store, self.policy, True)
        self.assertIn("optional.txt", [item["path"] for item in value["changes"]])
        staged = read_assembly(Path(value["stage"]))
        self.assertIn("optional.txt", self.owned(staged))

    def test_definition_answers_and_selections_round_trip_and_bind_digest(self):
        plain_digest = digest(canonical(self.definition))
        self.assertEqual(validate_definition(self.definition), self.definition)
        self.definition["answers"] = {"players": 6, "name": "Home", "nested": {"on": True, "list": [1, "a", None]}}
        self.definition["selections"] = {"platform": ["ios", "web"]}
        self.assertEqual(validate_definition(self.definition), self.definition)
        changed = digest(canonical(self.definition))
        self.assertNotEqual(plain_digest, changed)
        lock = resolve(requirements(self.definition), self.store / "catalogue.json", self.definition["id"], changed)
        self.assertEqual(lock["definitionDigest"], changed)
        installed = assemble(self.definition, lock, self.store, self.root / "installed", self.policy)
        self.assertEqual(load(self.root / "installed/.aepm/definition.json"), self.definition)
        self.assertEqual(installed["lock"]["definitionDigest"], changed)
        self.assertEqual(read_assembly(self.root / "installed"), installed)
        retained_manifests(self.root / "installed", self.policy)
        with self.assertRaisesRegex(AepmError, "lock-definition"):
            assemble(self.definition, type(self).lock, self.store, self.root / "other", self.policy)
        self.definition["answers"] = {}
        self.assertNotEqual(digest(canonical(self.definition)), plain_digest)

    def test_definition_answers_and_selections_are_validated(self):
        for key in ("answers", "selections"):
            for value in (None, [], "x", 1, True, {"big": "x" * 70000}, {"float": float("nan")}, {"bad": object()}, {1: "x"}):
                with self.subTest(key=key, value=str(value)[:20]):
                    definition = deepcopy(self.definition)
                    definition[key] = value
                    with self.assertRaises(AepmError):
                        validate_definition(definition)
        definition = deepcopy(self.definition)
        definition["extra"] = {}
        with self.assertRaises(AepmError):
            validate_definition(definition)

    def test_all_frozen_commands(self):
        definition = self.root / "definition.json"
        write(definition, self.definition)
        archive = self.command("pack", self.base / "sample0.1.0", "--store", self.store)["result"]
        self.command("inspect", archive["digest"], "--store", self.store)
        lock = self.root / "lock.json"
        self.command("resolve", definition, "--catalogue", self.store / "catalogue.json", "--out", lock)
        statement = self.root / "release-statement.json"
        component, _ = read_package(archive, self.store)
        write(statement, release_statement(archive, component))
        envelope = self.root / "release.dsse.json"
        self.command("sign", statement, "--role", "release", "--key", self.identities / "release.pem", "--out", envelope)
        self.assertEqual(verify(envelope.read_bytes(), "release", self.policy, RELEASE)[0], load(statement))
        self.command("bom", archive["digest"], "--store", self.store, "--out", self.root / "sample-0.1.0.cdx.json")
        self.command("review", archive["digest"], "--store", self.store, "--policy", self.policy, "--trusted")
        app = self.root / "installed"
        self.command("install", definition, "--lock", lock, "--store", self.store, "--policy", self.policy, "--target", app)
        self.command("verify", app, "--policy", self.policy, "--trusted")
        self.command("export", app, "--out", self.root / "exported")
        self.definition["components"][0]["version"] = "0.1.1"
        write(definition, self.definition)
        proposal = self.root / "command-proposal.json"
        self.command("propose-update", app, definition, "--store", self.store, "--policy", self.policy, "--trusted", "--out", proposal)
        approval = self.root / "approval"
        self.command("approve", proposal, "--key", self.identities / "owner.pem", "--policy", self.policy, "--out", approval)
        self.command("apply", app, proposal, "--approval", approval, "--policy", self.policy)
        self.command("recover", app)
        self.command("verify", app, "--policy", self.policy, code=1)


if __name__ == "__main__":
    unittest.main()
