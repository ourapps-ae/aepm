"""Scoped video-calls 0.1.2 Android check; never a complete package/application proof."""

import argparse
from copy import deepcopy
from pathlib import Path
import sys

from aepm.authorization import execution_request, authorize_execution
from aepm.bundle import extract_review, ordinary_path, pack, read_package
from aepm.contextual import execute
from aepm.environment import Execution, clock
from aepm.io import load, private_directory, snapshot, write
from aepm.model import AepmError, canonical, digest, package_ref, validate_component, validate_execution_context
from aepm.test_identities import generate
from aepm.trust import load_policy, review_bindings, sign, verify_release


def inputs(source, context, out):
    source, context, out = (Path(value) for value in (source, context, out))
    ordinary_path(source)
    ordinary_path(context)
    ordinary_path(out, missing=True)
    if out.exists() or not out.parent.is_dir():
        raise ValueError("Use a fresh output with an existing ordinary parent")
    source, context, out = (value.resolve() for value in (source, context, out))
    if out.exists() or not out.parent.is_dir() or (source / ".git").exists():
        raise ValueError("Use a fresh output and an ordinary private source copy")
    descriptor = validate_execution_context(load(context))
    if (descriptor["mode"] != "local" or descriptor["simulationKind"] is not None or descriptor["secrets"]
            or set(descriptor["settings"]) != {"maximumSeconds"}
            or {item["id"] for item in descriptor["resources"]} != {"androidSdk", "androidJavaHome"}):
        raise ValueError("Only the reviewed Android resources/time are permitted; no cache, devices or providers")
    for original in (source, context, *(Path(item["path"]) for item in descriptor["resources"])):
        ordinary_path(original)
        original = original.resolve()
        if out.is_relative_to(original) or original.is_relative_to(out):
            raise ValueError("Output and inputs must be disjoint")
    manifest = validate_component(load(source / "component.json"))
    if (manifest["identity"]["name"], manifest["identity"]["version"], manifest["kind"]) != ("ourapps-ae/video-calls", "0.1.2", "component") or manifest["dependencies"]:
        raise ValueError("This release covers only the dependency-free video-calls 0.1.2 component")
    matches = [suite for suite in manifest["verification"] if suite["id"] == "android-media"]
    if len(matches) != 1:
        raise ValueError("Expected the exact reviewed Android declaration")
    suite = matches[0]
    expected_prepare = [{"argv": ["python3", "scripts/platform-check.py", "prepare-android"], "cwd": ".", "network": True}]
    if (suite["root"] != "package" or suite["cwd"] != "." or suite["prepare"] != expected_prepare
            or suite["argv"] != ["python3", "scripts/platform-check.py", "android"] or suite["network"]
            or suite["timeoutSeconds"] != 900 or suite["scope"] != "platform"
            or suite["tools"] != {"java": "17", "python3": "3.12.8"}
            or suite["requirements"] != ["external:android-test-environment"]):
        raise ValueError("Unreviewed command, tool, prerequisite or time change")
    expected_execution = {"kind": "native", "simulation": False,
                          "operations": ["copy-dependency-cache", "dependency-download", "native-build", "native-test"],
                          "settings": ["maximumSeconds"], "secrets": [],
                          "resources": [{"id": "androidCache", "required": False, "access": "copy"},
                                        {"id": "androidJavaHome", "required": True, "access": "read-only"},
                                        {"id": "androidSdk", "required": True, "access": "copy"}],
                          "assertions": ["build-produced", "tests-discovered", "tests-executed", "tests-passed"], "cleanup": None}
    if suite["execution"] != expected_execution:
        raise ValueError("Unreviewed execution authority or assertions")
    return source, context, out, manifest


def bind_manifest(initial, archived):
    expected, actual = deepcopy(initial), deepcopy(archived)
    for value in (expected, actual):
        value["identity"].pop("sourceTreeDigest", None)
    if actual != expected:
        raise ValueError("Packed identity or declaration differs from validated input")


def retain_result(out, output, execution, source, before):
    output.update(sourceUnchanged=None, postChecks="pending", accepted=False)
    write(out / "focused-result.json", output)
    try:
        execution.check_time()
        after = snapshot(source)
        write(out / "source-after.json", after)
        output["sourceUnchanged"] = after == before
        output["postChecks"] = "passed" if after == before else "failed"
        output["accepted"] = after == before and output["result"]["status"] == "passed"
        write(out / "focused-result.json", output)
        return output["accepted"]
    except BaseException as error:
        output.update(postChecks="failed", accepted=False,
                      postCheckReason=error.code if isinstance(error, AepmError) else type(error).__name__)
        write(out / "focused-result.json", output)
        raise


def check(source, context, out):
    source, context, out, manifest = inputs(source, context, out)
    before = snapshot(source)
    before_digest = digest(canonical(before))
    out.mkdir(mode=0o700, exist_ok=False)
    write(out / "allocation.json", {"source": str(source), "context": str(context), "output": str(out)})
    write(out / "state.json", {"phase": "setup", "completeProof": False, "sourceSnapshotDigest": before_digest,
                               "paths": {"source": str(source), "context": str(context), "output": str(out)}})
    try:
        write(out / "source-before.json", before)
        policy_path = generate(out / "private-identities")
        store = out / "store"
        if store.exists():
            raise ValueError("Fresh catalogue collision check failed")
        ref = pack(source, store)
        archived, _ = read_package(ref, store)
        bind_manifest(manifest, archived)
        if snapshot(source) != before:
            raise ValueError("Source drift during packing")
        policy = load_policy(policy_path)
        policy["trustedExecution"] = [ref["digest"]]
        write(policy_path, policy)
        release = {"format": 1, "role": "release", "keyId": "local-release", **ref,
                   "sourceTreeDigest": archived["identity"]["sourceTreeDigest"]}
        statements = private_directory(store / "statements" / ref["digest"])
        write(statements / "release.json", release)
        (statements / "release.sig").write_bytes(sign(release, "release", out / "private-identities/release.pem"))
        verify_release(ref, store, policy_path)
        request, authority, registry = out / "request.json", out / "authorization", out / "execution-state"
        execution_request(ref=ref, store=store, context=context, policy=policy_path, execution_state=registry,
                          expires_at=clock() + 1800, out=request,
                          selected_pairs=[{"package": ref["digest"], "id": "android-media"}])
        authorize_execution(request, out / "private-identities/owner.pem", policy_path, authority)
        binding = review_bindings(ref, store)
        checked_policy = load_policy(policy_path)
        if not {item["digest"] for item in binding["packages"]} <= set(checked_policy["trustedExecution"]):
            raise ValueError("Entire execution closure must be externally trusted")
        if len(binding["packages"]) != 1:
            raise ValueError("Unexpected component closure")
        retained = out / "release-verified-package"
        actual = extract_review(package_ref(ref), store, retained, policy_path)
        if actual != archived or snapshot(source) != before:
            raise ValueError("Verified input drift before execution")
        selected = next(item for item in binding["suites"] if (item["package"], item["id"]) == (ref["digest"], "android-media"))
        evidence_root = out / "focused-evidence"
        execution = Execution({**binding, "context": "review"}, policy_path, evidence_root,
                              execution_context=context, authorization=authority, execution_state=registry,
                              forbidden_roots=[source, store, retained, evidence_root])
        write(out / "state.json", {"phase": "executing", "completeProof": False, "ref": ref,
                                   "sourceSnapshotDigest": before_digest, "sourceTreeDigest": archived["identity"]["sourceTreeDigest"]})
        result, evidence = execute(selected, retained, True, evidence_root / "logs", execution)
        output = {"format": 1, "kind": "focused-component-check", "complete": False, "ref": ref,
                   "sourceSnapshotDigest": before_digest, "sourceTreeDigest": archived["identity"]["sourceTreeDigest"],
                   "result": result, "evidence": evidence,
                  "notExecuted": [{key: item[key] for key in ("package", "id", "scope")} for item in binding["suites"] if item is not selected],
                  "authorizationDigest": execution.authorization_digest, "contextDigest": execution.context_digest,
                   **{key: binding[key] for key in ("lockDigest", "assemblyDigest", "suiteSetDigest")},
                   "completionPublished": False,
                   "paths": {"source": str(source), "context": str(context), "output": str(out)}}
        accepted = retain_result(out, output, execution, source, before)
        write(out / "state.json", {"phase": "finished", "completeProof": False,
                                   "status": "passed" if accepted else "failed",
                                   "sourceUnchanged": output["sourceUnchanged"]})
        return 0 if accepted else 1
    except BaseException as error:
        write(out / "state.json", {"phase": "failed", "completeProof": False,
                                   "reason": error.code if isinstance(error, AepmError) else type(error).__name__})
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    sys.exit(check(arguments.source, arguments.context, arguments.out))
