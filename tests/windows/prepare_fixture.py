"""Prepare public Windows fixtures through real supported-host signing and review."""

import argparse
import os
from pathlib import Path
import tempfile

from aepm.application import assemble, requirements
from aepm.bundle import pack, read_package, resolve
from aepm.io import load, private_directory, write
from aepm.model import canonical, digest
from aepm.test_identities import generate
from aepm.trust import sign, verify_package
from aepm.verification import review_package, verify_application
from tests.test_application import source


CHECK = '''const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
assert.equal(process.env.AEPM_WINDOWS_TEST_SECRET,undefined);
const context=JSON.parse(fs.readFileSync(process.env.AEPM_CONTEXT_FILE,'utf8'));
if(process.argv[2]==='package') assert.equal(fs.readFileSync('fixture.txt','utf8'),'fixture\\n');
else assert.ok(fs.readFileSync('app.txt','utf8').startsWith('count=7'));
const profile=path.join(path.dirname(process.env.AEPM_CONTEXT_FILE),'profiles','desktop');
fs.writeFileSync(path.join(profile,'marker'),'test-only');
const result={artifacts:[],assertions:[{actual:true,id:'response-valid',passed:true}],
 cleanup:{attempted:false,completed:false,reason:'',required:true},format:1,id:context.id,package:context.package,resources:[],runId:context.runId};
fs.writeFileSync(process.env.AEPM_RESULT_FILE,JSON.stringify(result));
console.log(JSON.stringify({privateRoot:process.env.AEPM_PRIVATE_ROOT,profile}));
'''


def prepare(out):
    if os.name == "nt":
        raise RuntimeError("Source packing is unsupported on Windows; prepare fixtures on a supported host")
    out = Path(out).resolve()
    if out.exists():
        raise FileExistsError("Choose a fresh public fixture directory")
    private_directory(out)
    with tempfile.TemporaryDirectory(prefix="aepm-windows-fixture-") as temporary:
        root = Path(temporary).resolve()
        policy_path = generate(root / "private-identities")
        package = root / "source"
        manifest = source(package, "windows-verification", recipe=True)
        manifest["format"] = 2
        (package / "check.cjs").write_text(CHECK)
        manifest["files"].append({"path": "check.cjs", "executable": False})
        manifest["artefacts"].append({"source": "check.cjs", "destination": "check.cjs", "template": False, "executable": False})
        manifest["verification"] = []
        for location in ("package", "application"):
            manifest["verification"].append({"id": location, "root": location, "argv": ["node", "check.cjs", location], "cwd": ".", "prepare": [],
                                              "tools": {"node": "26"}, "fixtures": ["fixture.txt" if location == "package" else "app.txt"], "locks": [],
                                              "network": False, "timeoutSeconds": 20, "expectedExit": 0, "scope": "required-local", "requirements": [],
                                              "execution": {"kind": "local", "simulation": False, "operations": [], "settings": [], "secrets": [], "resources": [],
                                                            "assertions": ["response-valid"], "cleanup": None}})
        write(package / "component.json", manifest)
        store = out / "store"
        ref = pack(package, store)
        policy = load(policy_path)
        policy["trustedExecution"] = [ref["digest"]]
        write(out / "policy.json", policy)
        component, _ = read_package(ref, store)
        statement = {"format": 1, "role": "release", "keyId": "local-release", **ref,
                     "sourceTreeDigest": component["identity"]["sourceTreeDigest"]}
        statements = store / "statements" / ref["digest"]
        statements.mkdir(parents=True)
        write(statements / "release.json", statement)
        (statements / "release.sig").write_bytes(sign(statement, "release", root / "private-identities/release.pem"))
        report = review_package(ref, store, out / "policy.json", True)
        if report["summary"]["required-local"] != "passed":
            raise AssertionError(report)
        guardian = {"format": 1, "role": "guardian", "keyId": "local-guardian", **ref, "dependencies": [], "previousReviewedDigest": None,
                    "scope": ["required-local"], "verdict": "accepted", "reportDigest": digest(canonical(report))}
        write(statements / "guardian.json", guardian)
        (statements / "guardian.sig").write_bytes(sign(guardian, "guardian", root / "private-identities/guardian.pem"))
        verify_package(ref, store, out / "policy.json")
        definition = {"format": 1, "id": "windows-fixture", "title": "Windows Fixture",
                      "recipe": {"name": ref["name"], "version": ref["version"]}, "components": [], "configuration": {},
                      "design": {"definitions": [], "instances": [], "connections": []}, "updatePolicy": "patch"}
        lock = resolve(requirements(definition), store / "catalogue.json", definition["id"], digest(canonical(definition)))
        assembly = assemble(definition, lock, store, root / "application", out / "policy.json")
        generated = verify_application(root / "application", out / "policy.json", True)
        if generated["summary"]["required-local"] != "passed":
            raise AssertionError(generated)
        write(out / "definition.json", definition)
        write(out / "lock.json", lock)
        write(out / "fixture.json", {"format": 1, "ref": ref, "assemblyDigest": digest(canonical(assembly)), "preparedOn": os.name})
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    print(prepare(parser.parse_args().out))
