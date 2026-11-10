"""Derive and sign execution authority from independently verified package bytes."""

from copy import deepcopy
import os
from pathlib import Path
import secrets
import shutil

from .environment import clock, initialize_registry, suite_origins, path_platform
from .io import fail, fields, immutable, load, private_directory, snapshot, write
from .model import AepmError, canonical, digest, guarded, validate_execution_context, package_ref


def bindings(lock, assembly_digest, manifests, context):
    from .verification import declarations, package_records
    suites = declarations(lock["packages"], manifests, context)
    return {"lock": lock, "packages": package_records(lock), "suites": suites,
            "lockDigest": digest(canonical(lock)), "assemblyDigest": assembly_digest,
            "suiteSetDigest": digest(canonical(suites))}


def grants(binding, context):
    result = []
    for suite in binding["suites"]:
        declaration = suite.get("execution")
        if not declaration or declaration["kind"] == "local":
            continue
        supported = (context["mode"] == "simulation" and declaration["simulation"]
                     or context["mode"] == "local" and declaration["kind"] == "native"
                     or context["mode"] == "live" and declaration["kind"] == "provider")
        if not supported:
            continue
        result.append({"package": suite["package"], "id": suite["id"],
                       **{key: deepcopy(declaration[key]) for key in ("operations", "settings", "secrets")},
                       "origins": suite_origins(suite, context),
                       "resources": sorted(item["id"] for item in declaration["resources"]
                                           if item["id"] in {value["id"] for value in context["resources"]})})
    return result


def select_grants(binding, context, selected_pairs=None):
    available = grants(binding, context)
    if selected_pairs is None:
        return available
    if not isinstance(selected_pairs, list) or not selected_pairs:
        fail("invalid-selection", "suites")
    indexed = {(item["package"], item["id"]): item for item in available}
    selected = set()
    for pair in selected_pairs:
        fields(pair, ("package", "id"), path="selection")
        if not isinstance(pair["package"], str) or not isinstance(pair["id"], str):
            fail("invalid-selection", "suites")
        key = (pair["package"], pair["id"])
        if key not in indexed or key in selected:
            fail("invalid-selection", "suites")
        selected.add(key)
    return [indexed[key] for key in sorted(selected)]


def derive(evidence, policy):
    from .trust import review_bindings, verify_package, verify_release
    from .verification import retained_manifests
    evidence = Path(evidence)
    target = load(evidence / "target.json")
    store = evidence / "store"
    if target.get("context") == "review" and set(target) == {"context", "ref"}:
        binding = review_bindings(target["ref"], store)
        for ref in binding["packages"]:
            verify_release(package_ref({key: ref[key] for key in ("name", "version", "digest")}), store, policy)
    elif target == {"context": "application"}:
        root = evidence / "application"
        assembly, manifests = retained_manifests(root, policy)
        for ref in assembly["lock"]["packages"]:
            verify_package(package_ref({key: ref[key] for key in ("name", "version", "digest")}), store, policy)
        binding = bindings(assembly["lock"], digest(canonical(assembly)), manifests, "application")
    else:
        fail("request-target", "request")
    return target["context"], binding


@guarded
def execution_request(*, app=None, ref=None, store=None, context, policy, execution_state, expires_at, out, selected_pairs=None):
    from .bundle import pack, read_package
    from .trust import load_policy, review_bindings, verify_release
    from .verification import retained_manifests
    out, policy = Path(out), Path(policy)
    evidence = Path(str(out) + ".evidence")
    if (app is None) == (ref is None) or (app is not None and store is not None):
        fail("request-target", "request")
    if out.exists() or evidence.exists() or out.is_symlink() or evidence.is_symlink():
        fail("request-exists", "request")
    descriptor = validate_execution_context(load(context))
    managed = [Path(value).resolve() for value in (app, store) if value is not None]
    for external in (context, execution_state, out, evidence):
        if any(Path(external).resolve().is_relative_to(path) for path in managed):
            fail("context-invalid", "external-input-location")
    issued = clock()
    if type(expires_at) is not int or not issued < expires_at <= issued + 86400:
        fail("authorization-expired", "expiresAt")
    if descriptor["pathPlatform"] != path_platform():
        fail("unsupported-host", "context")
    if app is not None:
        assembly, manifests = retained_manifests(Path(app), policy)
        preview_binding = bindings(assembly["lock"], digest(canonical(assembly)), manifests, "application")
    else:
        if store is None or ref is None:
            fail("request-target", "request")
        preview_binding = review_bindings(ref, Path(store))
        for reference in preview_binding["packages"]:
            verify_release(package_ref({key: reference[key] for key in ("name", "version", "digest")}), Path(store), policy)
    selected = select_grants(preview_binding, descriptor, selected_pairs)
    state = initialize_registry(execution_state)
    private_directory(evidence)
    target_store = private_directory(evidence / "store")
    if app is not None:
        assembly, _ = retained_manifests(Path(app), policy)
        snapshot(app)
        shutil.copytree(app, evidence / "application")
        private_directory(target_store / "objects")
        entries = []
        for reference in assembly["lock"]["packages"]:
            archived = Path(app) / ".aepm/archives" / (reference["digest"] + ".tar")
            if archived.exists():
                actual = package_ref({key: reference[key] for key in ("name", "version", "digest")})
                shutil.copyfile(archived, target_store / "objects" / archived.name)
                read_package(actual, target_store)
            else:
                actual = pack(Path(app) / ".aepm/packages" / reference["digest"], target_store)
            if actual != {key: reference[key] for key in ("name", "version", "digest")}:
                fail("request-archive", "application")
            entries.append(actual)
            shutil.copytree(Path(app) / ".aepm/receipts" / reference["digest"], target_store / "statements" / reference["digest"])
        write(target_store / "catalogue.json", {"format": 1, "entries": entries})
        for name in ("reports", "contexts", "authorizations", "execution-evidence"):
            source = Path(app) / ".aepm/evidence" / name
            if source.exists():
                shutil.copytree(source, target_store / name)
        write(evidence / "target.json", {"context": "application"})
    else:
        if store is None or ref is None:
            fail("request-target", "request")
        store = Path(store)
        binding = review_bindings(ref, store)
        private_directory(target_store / "objects")
        entries = []
        for reference in binding["packages"]:
            reference = package_ref({key: reference[key] for key in ("name", "version", "digest")})
            verify_release(reference, store, policy)
            read_package(reference, store)
            entries.append(reference)
            shutil.copyfile(store / "objects" / (reference["digest"] + ".tar"), target_store / "objects" / (reference["digest"] + ".tar"))
            destination = private_directory(target_store / "statements" / reference["digest"])
            for name in ("release.dsse.json",):
                shutil.copyfile(store / "statements" / reference["digest"] / name, destination / name)
        write(target_store / "catalogue.json", {"format": 1, "entries": entries})
        write(evidence / "target.json", {"context": "review", "ref": ref})
    context_name, binding = derive(evidence, policy)
    if binding != preview_binding or select_grants(binding, descriptor, selected_pairs) != selected:
        fail("request-binding", "request")
    write(evidence / "binding.json", binding)
    write(evidence / "context.json", descriptor)
    if selected_pairs is not None:
        write(evidence / "selection.json", {"format": 1, "suites": [{key: item[key] for key in ("package", "id")} for item in selected]})
    request = {"runId": secrets.token_hex(32), "contextDigest": digest(canonical(descriptor)),
               "policyDigest": digest(canonical(load_policy(policy))), "executionState": state, "context": context_name,
               **{key: binding[key] for key in ("lockDigest", "assemblyDigest", "suiteSetDigest")},
               "suites": selected, "issuedAt": issued, "expiresAt": expires_at}
    immutable(out, request)
    return {"request": str(out), "runId": request["runId"]}


@guarded
def authorize_execution(request, private_key, policy, out):
    from .trust import load_policy, sign, verify
    request_path, policy, out = Path(request), Path(policy), Path(out)
    request = load(request_path)
    evidence = Path(str(request_path) + ".evidence")
    context_name, binding = derive(evidence, policy)
    context = validate_execution_context(load(evidence / "context.json"))
    selected_pairs = None
    if (evidence / "selection.json").exists():
        selection = load(evidence / "selection.json")
        fields(selection, ("format", "suites"), path="selection")
        if type(selection["format"]) is not int or selection["format"] != 1:
            fail("invalid-selection", "selection")
        selected_pairs = selection["suites"]
    selected = select_grants(binding, context, selected_pairs)
    if selected_pairs is not None and selected_pairs != [{key: item[key] for key in ("package", "id")} for item in selected]:
        fail("invalid-selection", "selection")
    expected = {"contextDigest": digest(canonical(context)), "policyDigest": digest(canonical(load_policy(policy))),
                "context": context_name, **{key: binding[key] for key in ("lockDigest", "assemblyDigest", "suiteSetDigest")},
                "suites": selected}
    if any(request.get(key) != value for key, value in expected.items()):
        fail("request-binding", "request")
    if not request["issuedAt"] <= clock() < request["expiresAt"]:
        fail("authorization-expired", "request")
    state = request["executionState"]
    if load(Path(state["path"]) / "registry.json") != {"format": 1, "id": state["id"]}:
        fail("authorization-binding", "execution-state")
    if out.exists() or out.is_symlink():
        fail("authorization-exists", "out")
    from .trust import EXECUTION_AUTHORIZATION, authorization_statement
    envelope = sign(authorization_statement(request), "owner", Path(private_key))
    try:
        verify(canonical(envelope), "owner", policy, EXECUTION_AUTHORIZATION)
    except AepmError:
        fail("owner-key", "policy")
    if not out.parent.is_dir():
        fail("missing-path", "out")
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical(envelope))
        stream.flush()
        os.fsync(stream.fileno())
    return {"authorization": str(out)}
