import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from aepm.bundle import extract, extract_review, pack, read_package, resolve
from aepm.model import AepmError, canonical, digest, loads, validate_component, validate_lock
from aepm.trust import review_bindings, sign, verify, verify_package


def fixture(root, name="sample", version="0.1.0", dependencies=None):
    root.mkdir(parents=True)
    content = {"CONTRACT.md": b"# Contract\n", "interface.txt": b"interface\n",
               "example.json": b'{"format":1}', "NOTICE": b"Licence deferred\n",
               "visual.json": b"{}", "visual.svg": b"<svg/>", "visual.png": b"PNG",
               "description.txt": b"Connected example\n", "fixture.txt": b"fixture\n",
               "test.py": b"assert 2 + 2 == 4\n", "run.sh": b"#!/bin/sh\nexit 0\n"}
    for path, data in content.items():
        (root / path).write_bytes(data)
        (root / path).chmod(0o755 if path == "run.sh" else 0o644)
    c = {"format": 1, "kind": "component",
         "identity": {"name": "ourapps-ae/" + name, "version": version,
                      "sourceRevision": "test-revision", "sourceTreeDigest": "0" * 64,
                      "licenceStatus": "deferred"},
         "facilities": [{"id": "sample", "description": "Sample fixture"}],
         "documents": {"contract": "CONTRACT.md", "interfaces": ["interface.txt"],
                       "examples": ["example.json"], "licenceNotice": "NOTICE"},
         "collect": [], "files": [{"path": p, "executable": p == "run.sh"} for p in sorted(content)],
         "artefacts": [{"source": "run.sh", "destination": "components/sample/run.sh",
                        "template": False, "executable": True}],
         "dependencies": dependencies or [], "provides": [], "requires": [],
         "visual": {"definition": "visual.json", "examples": ["example.json"],
                    "outputs": ["visual.svg", "visual.png"], "descriptions": ["description.txt"]},
         "capabilities": {"hosts": [], "secrets": [], "writes": []},
         "infrastructure": {"accounts": [], "costStatus": "unmeasured", "deployedReason": "Not deployed"},
         "verification": [{"id": "unit", "root": "package", "argv": ["python3", "test.py"],
                           "cwd": ".", "prepare": [], "tools": {"python3": "3"},
                           "fixtures": ["fixture.txt"], "locks": [], "network": False,
                           "timeoutSeconds": 10, "expectedExit": 0, "scope": "required-local", "requirements": []},
                          {"id": "native", "root": "package", "argv": ["unavailable"],
                           "cwd": ".", "prepare": [], "tools": {"unavailable": "1"},
                           "fixtures": ["fixture.txt"], "locks": [], "network": False,
                           "timeoutSeconds": 10, "expectedExit": 0, "scope": "platform", "requirements": ["external:native"]}],
         "upgrade": {"policy": "patch", "migration": "files-only"}}
    (root / "component.json").write_bytes(canonical(c))
    return c


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = json.loads(subprocess.check_output([
            "node", "--input-type=module", "-e",
            "import {generateKeyPairSync} from 'node:crypto'; const out={}; "
            "for(const role of ['release','guardian','owner']) {const k=generateKeyPairSync('ed25519');"
            "out[role]={publicKey:k.publicKey.export({type:'spki',format:'pem'}),"
            "privateKey:k.privateKey.export({type:'pkcs8',format:'pem'})};} console.log(JSON.stringify(out));"
        ]))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source, self.store = self.root / "source", self.root / "store"
        self.component = fixture(self.source)
        self.policy = self.root / "policy.json"
        policy = {"format": 1, "keys": {role: [{"id": role + "-test", "publicKey": key["publicKey"]}]
                                       for role, key in self.keys.items()}, "trustedExecution": []}
        self.policy.write_bytes(canonical(policy))
        for role, key in self.keys.items():
            (self.root / (role + ".pem")).write_text(key["privateKey"])

    def update(self):
        (self.source / "component.json").write_bytes(canonical(self.component))

    def release(self, ref):
        c, _ = read_package(ref, self.store)
        statement = {"format": 1, "role": "release", "keyId": "release-test", **ref,
                     "sourceTreeDigest": c["identity"]["sourceTreeDigest"]}
        self.statement(ref, statement)
        return statement

    def statement(self, ref, statement):
        directory = self.store / "statements" / ref["digest"]
        directory.mkdir(parents=True, exist_ok=True)
        role = statement["role"]
        (directory / (role + ".json")).write_bytes(canonical(statement))
        (directory / (role + ".sig")).write_bytes(sign(statement, role, self.root / (role + ".pem")))

    def report(self, ref):
        binding = review_bindings(ref, self.store)
        suites = [{"package": s["package"], "id": s["id"], "scope": s["scope"],
                   "status": "passed" if s["scope"] == "required-local" else "blocked",
                   "exitCode": 0 if s["scope"] == "required-local" else None,
                   "seconds": 0, "reason": "" if s["scope"] == "required-local" else "Tool unavailable",
                   "logDigest": digest(b"")}
                  for s in binding["suites"]]
        return {"format": 1, "context": "review",
                **{k: binding[k] for k in ("lockDigest", "assemblyDigest", "packages", "suiteSetDigest")},
                "suites": suites, "summary": {"required-local": "passed", "platform": "blocked", "deployed": "not-applicable"}}

    def guardian(self, ref, report=None):
        report = report if report is not None else self.report(ref)
        data = canonical(report)
        directory = self.store / "reports"
        directory.mkdir(exist_ok=True)
        (directory / (digest(data) + ".json")).write_bytes(data)
        statement = {"format": 1, "role": "guardian", "keyId": "guardian-test", **ref,
                     "dependencies": sorted(p["digest"] for p in report["packages"] if p["digest"] != ref["digest"]),
                     "previousReviewedDigest": None, "scope": ["platform", "required-local"],
                     "verdict": "accepted", "reportDigest": digest(data)}
        self.statement(ref, statement)
        return statement

    def rejected_before_write(self, ref, code=None, review=True):
        destination = self.root / "absent" / "destination"
        with self.assertRaises(AepmError) as error:
            (extract_review if review else extract)(ref, self.store, destination, self.policy)
        if code:
            self.assertEqual(error.exception.code, code)
        self.assertFalse(destination.parent.exists())

    def mutate_archive(self, ref, transform):
        path = self.store / "objects" / (ref["digest"] + ".tar")
        with tarfile.open(path) as archive:
            members = [(m, archive.extractfile(m).read()) for m in archive]
        members = transform(members)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for info, data in members:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        data = output.getvalue()
        modified = {**ref, "digest": digest(data)}
        (self.store / "objects" / (modified["digest"] + ".tar")).write_bytes(data)
        return modified

    def test_repeat_pack_child_store_and_normalization(self):
        self.store = self.source / "output-store"
        original = (self.source / "component.json").read_bytes()
        first = pack(self.source, self.store)
        (self.source / "ignored").mkdir()
        (self.source / "ignored" / "cache").write_text("unlisted")
        self.assertEqual(first, pack(self.source, self.store))
        self.assertEqual(original, (self.source / "component.json").read_bytes())
        with tarfile.open(self.store / "objects" / (first["digest"] + ".tar")) as archive:
            names = archive.getnames()
            self.assertEqual(names, sorted(["component.json"] + [f["path"] for f in self.component["files"]]))
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.mtime, member.uname, member.gname), (0, 0, 0, "", ""))
                self.assertEqual(member.mode, 0o755 if member.name == "run.sh" else 0o644)
        self.release(first)
        target = self.root / "review"
        extract_review(first, self.store, target, self.policy)
        subprocess.run(["python3", "test.py"], cwd=target, check=True)
        self.assertEqual((target / "run.sh").stat().st_mode & 0o777, 0o755)

    def test_source_execute_mode_mismatch(self):
        (self.source / "run.sh").chmod(0o644)
        with self.assertRaisesRegex(AepmError, "mode-mismatch"):
            pack(self.source, self.store)
        self.assertFalse(self.store.exists())

    def test_identity_rebinding(self):
        pack(self.source, self.store)
        before = (self.store / "catalogue.json").read_bytes()
        (self.source / "CONTRACT.md").write_text("Altered contract")
        with self.assertRaisesRegex(AepmError, "identity-rebinding"):
            pack(self.source, self.store)
        self.assertEqual(before, (self.store / "catalogue.json").read_bytes())

    def test_exclusions_and_store_listing(self):
        for name in (".env", ".git/config", "node_modules/x", "secret.pem", "archive.tar"):
            with self.subTest(name=name):
                self.component["files"].append({"path": name, "executable": False})
                self.update()
                with self.assertRaisesRegex(AepmError, "excluded-path"):
                    pack(self.source, self.store)
                self.component["files"].pop()
        self.store = self.source / "output"
        self.store.mkdir()
        (self.store / "record.json").write_text("{}")
        self.component["files"].append({"path": "output/record.json", "executable": False})
        self.update()
        with self.assertRaisesRegex(AepmError, "store-listed"):
            pack(self.source, self.store)

    def test_source_link_and_embedded_key(self):
        path = self.source / "interface.txt"
        path.unlink()
        path.symlink_to(self.source / "NOTICE")
        with self.assertRaisesRegex(AepmError, "unsafe-file"):
            pack(self.source, self.store)
        path.unlink()
        path.write_text(self.keys["release"]["privateKey"])
        with self.assertRaisesRegex(AepmError, "private-key"):
            pack(self.source, self.store)

    def test_source_hardlink_and_large_file(self):
        path = self.source / "interface.txt"
        path.unlink()
        os.link(self.source / "NOTICE", path)
        with self.assertRaisesRegex(AepmError, "unsafe-file"):
            pack(self.source, self.store)
        path.unlink()
        with path.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(AepmError, "file-limit"):
            pack(self.source, self.store)
        self.assertFalse(self.store.exists())

    def test_strict_documents_and_paths(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
            with self.subTest(data=data), self.assertRaises(AepmError):
                loads(data)
        self.assertEqual(canonical(loads(b'{"position":1.2}')), b'{"position":1.2}')
        for alter in (lambda c: c.update(extra=True),
                      lambda c: c["identity"].update(version="^1.0.0"),
                      lambda c: c["documents"].update(contract="absent.md"),
                      lambda c: c["files"].append({"path": "../escape", "executable": False}),
                      lambda c: c["files"].append({"path": "TEST.py", "executable": False}),
                      lambda c: c["verification"].clear(),
                      lambda c: c["verification"][0].update(fixtures=[]),
                      lambda c: c["verification"][0].update(unknown=True),
                      lambda c: c["collect"].append({"id": "secret", "type": "string", "grammar": "label", "required": True, "secret": True, "default": "hidden"})):
            c = copy.deepcopy(self.component)
            alter(c)
            with self.assertRaises(AepmError):
                validate_component(c)

    def test_wrong_field_types_raise_public_error(self):
        for key in self.component:
            for value in (None, [], {}, True, 1):
                c = copy.deepcopy(self.component)
                c[key] = value
                if value == self.component[key] and type(value) is type(self.component[key]):
                    continue
                # Several lists legitimately accept the empty list.
                if value == [] and key in ("collect", "artefacts", "dependencies", "provides", "requires"):
                    continue
                with self.subTest(key=key, value=value), self.assertRaises(AepmError):
                    validate_component(c)

    def test_prerequisite_grammar(self):
        for prerequisites in ([], ["external:livekit-project"], ["external:windows-host"],
                              ["external:a"], ["external:" + "a" * 64],
                              ["external:host-1", "external:provider"]):
            with self.subTest(prerequisites=prerequisites):
                c = copy.deepcopy(self.component)
                c["verification"][1]["requirements"] = prerequisites
                self.assertEqual(validate_component(c)["verification"][1]["requirements"], prerequisites)
        for prerequisite in ("native", "coverage", "external:", "external:Windows", "external:1host",
                             "external:windows_host", "external:windows/host", "external:windows.host",
                             "external:host\n", " external:host", "external:host:extra",
                             "external:" + "a" * 65, "external:höst", "EXTERNAL:host", None, True, {}):
            with self.subTest(prerequisite=prerequisite):
                c = copy.deepcopy(self.component)
                c["verification"][1]["requirements"] = [prerequisite]
                with self.assertRaises(AepmError) as raised:
                    validate_component(c)
                self.assertEqual(raised.exception.path, "verification.requirements")

    def test_optional_requirement_flag(self):
        entry = {"id": "rules", "type": "ae/contract", "version": "1.0.0", "path": "interface.txt"}
        for optional in (None, True, False):
            with self.subTest(optional=optional):
                c = copy.deepcopy(self.component)
                c["requires"] = [dict(entry) if optional is None else {**entry, "optional": optional}]
                self.assertEqual(validate_component(c)["requires"], c["requires"])
        for optional in (None, 0, 1, "true", "", [], {}):
            with self.subTest(optional=optional):
                c = copy.deepcopy(self.component)
                c["requires"] = [{**entry, "optional": optional}]
                with self.assertRaises(AepmError) as raised:
                    validate_component(c)
                self.assertEqual(raised.exception.path, "requires.optional")
        c = copy.deepcopy(self.component)
        c["provides"] = [{**entry, "optional": True}]
        with self.assertRaises(AepmError):
            validate_component(c)
        c = copy.deepcopy(self.component)
        c["requires"] = [{**entry, "extra": True}]
        with self.assertRaises(AepmError):
            validate_component(c)

    def test_optional_flag_is_bound_into_the_package_digest(self):
        entry = {"id": "rules", "type": "ae/contract", "version": "1.0.0", "path": "interface.txt"}
        self.component["requires"] = [entry]
        self.update()
        plain = pack(self.source, self.store)
        self.component["requires"] = [{**entry, "optional": True}]
        self.update()
        other = self.root / "other-store"
        marked = pack(self.source, other)
        self.assertNotEqual(plain["digest"], marked["digest"])
        self.assertIn(b'"optional":true', canonical(read_package(marked, other)[0]))

    def test_artefact_component_condition(self):
        plain = self.component["artefacts"][0]
        for value in ("ourapps-ae/other", "ourapps-ae/a1-b"):
            with self.subTest(value=value):
                c = copy.deepcopy(self.component)
                c["artefacts"][0] = {**plain, "component": value}
                self.assertEqual(validate_component(c)["artefacts"][0]["component"], value)
        for value in ("ourapps-ae/sample", "other/name", "ourapps-ae/Upper", "", None, True, 1, [], {}):
            with self.subTest(value=value):
                c = copy.deepcopy(self.component)
                c["artefacts"][0] = {**plain, "component": value}
                with self.assertRaises(AepmError):
                    validate_component(c)
        c = copy.deepcopy(self.component)
        c["artefacts"][0] = {**plain, "component": "ourapps-ae/sample"}
        with self.assertRaises(AepmError) as raised:
            validate_component(c)
        self.assertEqual(raised.exception.code, "artefact-self-component")

    def test_artefact_component_is_bound_into_the_package_digest(self):
        plain = pack(self.source, self.store)
        self.component["artefacts"][0]["component"] = "ourapps-ae/other"
        self.update()
        other = self.root / "other-store"
        marked = pack(self.source, other)
        self.assertNotEqual(plain["digest"], marked["digest"])
        self.assertIn(b'"component":"ourapps-ae/other"', canonical(read_package(marked, other)[0]))

    def test_invalid_prerequisite_rejected_before_pack_writes(self):
        self.component["verification"][0]["requirements"] = ["native"]
        self.update()
        with self.assertRaisesRegex(AepmError, "invalid-prerequisite"):
            pack(self.source, self.store)
        self.assertFalse(self.store.exists())

    def test_review_bindings_exact_shape_and_transitive_closure(self):
        leaf = self.root / "leaf"
        fixture(leaf, "leaf")
        leaf_ref = pack(leaf, self.store)
        middle = self.root / "middle"
        fixture(middle, "middle", dependencies=[{"name": leaf_ref["name"], "version": leaf_ref["version"]}])
        middle_ref = pack(middle, self.store)
        self.component["dependencies"] = [{"name": middle_ref["name"], "version": middle_ref["version"]}]
        self.update()
        ref = pack(self.source, self.store)
        binding = review_bindings(ref, self.store)
        self.assertEqual(set(binding), {"lock", "packages", "suites", "lockDigest", "assemblyDigest", "suiteSetDigest"})
        self.assertEqual(binding["lockDigest"], digest(canonical(binding["lock"])))
        refs = sorted([ref, middle_ref, leaf_ref], key=lambda p: p["name"])
        self.assertEqual(binding["assemblyDigest"], digest(canonical({"packages": refs})))
        declarations = sorted([{"package": p["digest"], **suite} for p in refs
                               for suite in read_package(p, self.store)[0]["verification"]],
                              key=lambda suite: (suite["package"], suite["id"]))
        self.assertEqual(binding["suites"], declarations)
        self.assertEqual(binding["suiteSetDigest"], digest(canonical(declarations)))
        self.assertEqual(binding["packages"][-1]["dependencies"], [middle_ref["digest"]])
        for p in refs:
            self.release(p)
        statement = self.guardian(ref)
        self.assertEqual(statement["dependencies"], sorted([leaf_ref["digest"], middle_ref["digest"]]))
        self.assertEqual(statement["scope"], sorted({suite["scope"] for suite in declarations}))
        verify_package(ref, self.store, self.policy)
        statement["dependencies"] = [middle_ref["digest"]]
        self.statement(ref, statement)
        self.rejected_before_write(ref, "guardian-dependencies", review=False)

    def test_review_bindings_reject_dependency_cycles(self):
        other = self.root / "other"
        fixture(other, "other", dependencies=[{"name": "ourapps-ae/sample", "version": "0.1.0"}])
        pack(other, self.store)
        self.component["dependencies"] = [{"name": "ourapps-ae/other", "version": "0.1.0"}]
        self.update()
        ref = pack(self.source, self.store)
        with self.assertRaisesRegex(AepmError, "dependency-cycle"):
            review_bindings(ref, self.store)

    def test_nested_directory_collision_and_missing_working_directory(self):
        (self.source / "nested").mkdir()
        (self.source / "nested" / "one").write_text("one")
        (self.source / "nested" / "two").write_text("two")
        self.component["files"].extend([{"path": "nested/one", "executable": False},
                                        {"path": "Nested/two", "executable": False}])
        self.update()
        with self.assertRaisesRegex(AepmError, "case-collision"):
            pack(self.source, self.store)
        self.component["verification"][0]["cwd"] = "missing"
        with self.assertRaisesRegex(AepmError, "missing-required-path"):
            validate_component(self.component)

    def test_signed_noncanonical_statement_and_unknown_fields(self):
        ref = pack(self.source, self.store)
        statement = self.release(ref)
        encoded = json.dumps(statement, indent=2).encode()
        request = {"key": self.keys["release"]["privateKey"], "message": (b"aepm/release/1\n" + encoded).hex()}
        signature = subprocess.check_output([
            "node", "--input-type=module", "-e",
            "import {sign} from 'node:crypto'; let s=''; for await(const c of process.stdin)s+=c;"
            "const r=JSON.parse(s); process.stdout.write(sign(null,Buffer.from(r.message,'hex'),r.key));"
        ], input=canonical(request))
        with self.assertRaisesRegex(AepmError, "noncanonical-statement"):
            verify(encoded, signature, "release", self.policy)
        statement["publicKey"] = self.keys["release"]["publicKey"]
        with self.assertRaisesRegex(AepmError, "invalid-fields"):
            sign(statement, "release", self.root / "release.pem")

    def test_transitive_resolution_and_conflict(self):
        leaf = self.root / "leaf"
        fixture(leaf, "leaf")
        leaf_ref = pack(leaf, self.store)
        middle = self.root / "middle"
        fixture(middle, "middle", dependencies=[{"name": leaf_ref["name"], "version": "0.1.0"}])
        middle_ref = pack(middle, self.store)
        newer = self.root / "newer"
        fixture(newer, "leaf", "0.1.1")
        pack(newer, self.store)
        self.component["dependencies"] = [{"name": middle_ref["name"], "version": "0.1.0"}]
        self.update()
        root_ref = pack(self.source, self.store)
        lock = resolve([{"name": root_ref["name"], "version": "0.1.0"}], self.store / "catalogue.json", "app", "a" * 64)
        self.assertEqual([p["name"] for p in lock["packages"]], ["ourapps-ae/leaf", "ourapps-ae/middle", "ourapps-ae/sample"])
        self.assertEqual(lock["packages"][1]["dependencies"], [{"name": leaf_ref["name"], "digest": leaf_ref["digest"]}])
        with self.assertRaisesRegex(AepmError, "dependency-conflict"):
            resolve([{"name": root_ref["name"], "version": "0.1.0"}, {"name": leaf_ref["name"], "version": "0.1.1"}], self.store / "catalogue.json", "app", "a" * 64)

    def test_lock_validation(self):
        ref = pack(self.source, self.store)
        lock = resolve([{"name": ref["name"], "version": ref["version"]}], self.store / "catalogue.json", "app", "a" * 64)
        for alter in (lambda c: c.update(extra=True), lambda c: c["packages"].append(c["packages"][0]),
                      lambda c: c["packages"][0]["dependencies"].append({"name": "ourapps-ae/absent", "digest": "b" * 64})):
            c = copy.deepcopy(lock)
            alter(c)
            with self.assertRaises(AepmError):
                validate_lock(c)

    def test_changed_archive_bytes_before_writes(self):
        ref = pack(self.source, self.store)
        path = self.store / "objects" / (ref["digest"] + ".tar")
        path.write_bytes(path.read_bytes() + b"changed")
        self.rejected_before_write(ref, "archive-digest")

    def test_malicious_members_before_writes(self):
        ref = pack(self.source, self.store)
        for kind in ("traversal", "link", "hardlink", "duplicate", "case", "missing", "mode", "contract", "test"):
            def transform(members):
                if kind == "duplicate":
                    return members + [members[-1]]
                if kind == "missing":
                    return [(m, b) for m, b in members if m.name != "interface.txt"]
                if kind == "case":
                    info = tarfile.TarInfo("TEST.py")
                    info.mode = 0o644
                    return sorted(members + [(info, b"new")], key=lambda t: t[0].name)
                for m, data in members:
                    if m.name == "test.py":
                        if kind == "traversal":
                            m.name = "../escaped"
                        elif kind in ("link", "hardlink"):
                            m.type = tarfile.SYMTYPE if kind == "link" else tarfile.LNKTYPE
                            m.linkname = "../outside"
                        elif kind == "mode":
                            m.mode = 0o755
                if kind in ("contract", "test"):
                    target = "CONTRACT.md" if kind == "contract" else "test.py"
                    return [(m, b"altered" if m.name == target else b) for m, b in members]
                return members
            with self.subTest(kind=kind):
                modified = self.mutate_archive(ref, transform)
                self.rejected_before_write(modified)

    def test_archive_size_limit_before_writes(self):
        ref = pack(self.source, self.store)
        path = self.store / "objects" / (ref["digest"] + ".tar")
        with path.open("r+b") as stream:
            stream.truncate(512 * 1024 * 1024 + 1)
        self.rejected_before_write(ref, "archive-limit")

    def test_release_only_and_guardian_required(self):
        ref = pack(self.source, self.store)
        self.release(ref)
        self.rejected_before_write(ref, "missing-path", review=False)
        extract_review(ref, self.store, self.root / "review", self.policy)
        self.guardian(ref)
        extract(ref, self.store, self.root / "installed", self.policy)
        self.assertEqual((self.root / "installed" / "test.py").read_bytes(), (self.source / "test.py").read_bytes())

    def test_role_swapping_and_external_pins(self):
        ref = pack(self.source, self.store)
        statement = self.release(ref)
        signature = sign(statement, "release", self.root / "guardian.pem")
        with self.assertRaisesRegex(AepmError, "invalid-signature"):
            verify(canonical(statement), signature, "release", self.policy)
        signature = sign(statement, "release", self.root / "release.pem")
        with self.assertRaisesRegex(AepmError, "invalid-signature"):
            verify(canonical(statement), signature, "guardian", self.policy)
        self.assertEqual(verify(canonical(statement), signature, "release", self.policy), statement)
        policy = loads(self.policy.read_bytes())
        policy["keys"]["guardian"][0]["publicKey"] = policy["keys"]["release"][0]["publicKey"]
        self.policy.write_bytes(canonical(policy))
        with self.assertRaisesRegex(AepmError, "duplicate-value"):
            verify(canonical(statement), signature, "release", self.policy)

    def test_statement_identity_version_rebinding(self):
        ref = pack(self.source, self.store)
        statement = self.release(ref)
        for key, value in (("name", "ourapps-ae/other"), ("version", "0.1.1"), ("sourceTreeDigest", "a" * 64)):
            altered = {**statement, key: value}
            self.statement(ref, altered)
            self.rejected_before_write(ref, "statement-binding")

    def test_report_bytes_and_suite_coverage(self):
        ref = pack(self.source, self.store)
        self.release(ref)
        for mutation in ("omit", "duplicate", "extra", "failed", "scope", "digest", "packages", "summary"):
            report = self.report(ref)
            if mutation == "omit":
                report["suites"].pop()
            elif mutation == "duplicate":
                report["suites"].append(report["suites"][0])
            elif mutation == "extra":
                report["suites"].append({**report["suites"][0], "id": "extra"})
            elif mutation == "failed":
                report["suites"][1]["status"] = "failed"
                report["suites"][1]["exitCode"] = 1
            elif mutation == "scope":
                report["suites"][0]["scope"] = "required-local"
            elif mutation == "digest":
                report["suiteSetDigest"] = "a" * 64
            elif mutation == "packages":
                report["packages"][0]["version"] = "0.1.1"
            else:
                report["summary"]["platform"] = "not-applicable"
            self.guardian(ref, report)
            with self.subTest(mutation=mutation):
                self.rejected_before_write(ref, review=False)
        statement = self.guardian(ref)
        path = self.store / "reports" / (statement["reportDigest"] + ".json")
        path.write_bytes(path.read_bytes() + b" ")
        self.rejected_before_write(ref, "report-digest", review=False)

    def test_guardian_transitive_dependencies(self):
        leaf = self.root / "leaf"
        fixture(leaf, "leaf")
        leaf_ref = pack(leaf, self.store)
        self.release(leaf_ref)
        self.component["dependencies"] = [{"name": leaf_ref["name"], "version": leaf_ref["version"]}]
        self.update()
        ref = pack(self.source, self.store)
        self.release(ref)
        report = self.report(ref)
        self.assertEqual(len(report["suites"]), 4)
        self.guardian(ref, report)
        verify_package(ref, self.store, self.policy)
        statement = self.guardian(ref, report)
        statement["dependencies"] = []
        self.statement(ref, statement)
        self.rejected_before_write(ref, "guardian-dependencies", review=False)

    def test_recipe_review_excludes_application_suites(self):
        self.component["kind"] = "recipe"
        application_suite = {**self.component["verification"][0], "id": "application", "root": "application"}
        self.component["verification"].append(application_suite)
        self.update()
        ref = pack(self.source, self.store)
        self.release(ref)
        binding = review_bindings(ref, self.store)
        self.assertEqual({s["id"] for s in binding["suites"]}, {"unit", "native"})
        self.guardian(ref)
        verify_package(ref, self.store, self.policy)

    def test_destination_link_and_existing_content(self):
        ref = pack(self.source, self.store)
        self.release(ref)
        target = self.root / "target"
        target.mkdir()
        (target / "keep").write_text("keep")
        with self.assertRaisesRegex(AepmError, "destination-not-empty"):
            extract_review(ref, self.store, target, self.policy)
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(AepmError, "unsafe-file"):
            extract_review(ref, self.store, alias / "child", self.policy)
        self.assertEqual((target / "keep").read_text(), "keep")
        self.assertFalse((target / "child").exists())


if __name__ == "__main__":
    unittest.main()
