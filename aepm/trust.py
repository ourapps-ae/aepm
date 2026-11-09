"""Externally pinned Ed25519 roles and complete guardian evidence."""

from __future__ import annotations

import base64
import os
import re
import time
from typing import cast
from pathlib import Path
import subprocess

from .model import (PackageRef, array, canonical, choice, digest, fail, fields,
                    guarded, integer, loads, name, package_ref, read_json, sha256, text,
                    unique, version)
from .model import (boolean, bounded_text, execution_document, execution_origin,
                    execution_url, safe_path, sorted_strings, validate_absolute_path,
                    validate_execution, validate_execution_assertions,
                    validate_execution_authorization, validate_execution_context,
                    validate_lock, EXECUTION_REASONS)

ROLES = ("release", "guardian", "owner")
SCOPES = ("required-local", "platform", "deployed")


def _crypto(operation: str, key: str, data: bytes = b"", signature: bytes = b"") -> bytes:
    request = {"operation": operation, "key": key,
               "data": base64.b64encode(data).decode(),
               "signature": base64.b64encode(signature).decode()}
    try:
        result = subprocess.run(["node", str(Path(__file__).with_name("crypto.mjs"))],
                                input=canonical(request), capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        fail("crypto-unavailable", "signature")
    if result.returncode:
        fail("invalid-key", "signature")
    return result.stdout


@guarded
def load_policy(path: Path) -> dict:
    from .bundle import ordinary_path
    ordinary_path(path)
    policy = fields(read_json(path), "format keys trustedExecution", "policy")
    if type(policy["format"]) is not int or policy["format"] != 1:
        fail("invalid-format", "policy")
    keys = fields(policy["keys"], "release guardian owner", "policy.keys")
    identities, material = [], []
    for role in ROLES:
        for key in array(keys[role], "policy.keys." + role, True):
            fields(key, "id publicKey", "policy.keys")
            identities.append(text(key["id"], "policy.keys.id"))
            text(key["publicKey"], "policy.keys.publicKey")
            material.append(_crypto("public", key["publicKey"]))
    unique(identities, "policy.keys.id")
    unique(material, "policy.keys.publicKey")
    for value in array(policy["trustedExecution"], "policy.trustedExecution"):
        sha256(value, "policy.trustedExecution")
    unique(policy["trustedExecution"], "policy.trustedExecution")
    return policy


def validate_statement(statement: object, role: str) -> dict:
    choice(role, ROLES, "role")
    if role == "owner" and type(statement) is dict and statement.get("format") == 2:
        return validate_execution_authorization(statement)
    extra = {
        "release": "name version digest sourceTreeDigest",
        "guardian": "name version digest dependencies previousReviewedDigest scope verdict reportDigest",
        "owner": "application previousLockDigest nextLockDigest configurationDigest designDigest assemblyDigest reportDigest proposalDigest snapshotDigest stageDigest",
    }[role]
    s = fields(statement, "format role keyId " + extra, "statement")
    if type(s["format"]) is not int or s["format"] != 1 or s["role"] != role:
        fail("statement-role", "statement")
    text(s["keyId"], "statement.keyId")
    if role in ("release", "guardian"):
        name(s["name"], "statement.name")
        version(s["version"], "statement.version")
        sha256(s["digest"], "statement.digest")
    for key in extra.split():
        if key.endswith("Digest") and not (key == "previousReviewedDigest" and s[key] is None):
            sha256(s[key], "statement." + key)
    if role == "guardian":
        for dep in array(s["dependencies"], "statement.dependencies"):
            sha256(dep, "statement.dependencies")
        unique(s["dependencies"], "statement.dependencies")
        if s["dependencies"] != sorted(s["dependencies"]):
            fail("unsorted-dependencies", "statement")
        for scope in array(s["scope"], "statement.scope", True):
            choice(scope, SCOPES, "statement.scope")
        unique(s["scope"], "statement.scope")
        choice(s["verdict"], ("accepted",), "statement.verdict")
    if role == "owner":
        text(s["application"], "statement.application")
    return s


@guarded
def sign(statement: dict, role: str, private_key: Path) -> bytes:
    validate_statement(statement, role)
    from .bundle import ordinary_path
    ordinary_path(private_key)
    try:
        key = private_key.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        fail("read-failed", "private-key")
    message = b"aepm/" + role.encode() + b"/" + str(statement["format"]).encode() + b"\n" + canonical(statement)
    return base64.b64decode(_crypto("sign", key, message), validate=True)


@guarded
def verify(statement_bytes: bytes, signature: bytes, role: str, policy: Path) -> dict:
    choice(role, ROLES, "role")
    if len(signature) != 64 or len(statement_bytes) > 1024 * 1024:
        fail("invalid-signature", "signature")
    pinned = load_policy(policy)
    matched = []
    for domain_version in ((1, 2) if role == "owner" else (1,)):
        message = b"aepm/" + role.encode() + b"/" + str(domain_version).encode() + b"\n" + statement_bytes
        matched.extend((key["id"], domain_version) for key in pinned["keys"][role]
                       if _crypto("verify", key["publicKey"], message, signature) == b"true")
    if not matched:
        fail("invalid-signature", "signature")
    statement = validate_statement(loads(statement_bytes, "statement"), role)
    if canonical(statement) != statement_bytes:
        fail("noncanonical-statement", "statement")
    if (statement["keyId"], statement["format"]) not in matched:
        fail("key-id-mismatch", "statement")
    return statement


def _stored_statement(ref: PackageRef, store: Path, role: str, policy: Path) -> dict:
    from .bundle import ordinary_path
    package_ref(ref)
    directory = store / "statements" / ref["digest"]
    path, signature = directory / (role + ".json"), directory / (role + ".sig")
    ordinary_path(path)
    ordinary_path(signature)
    if path.stat().st_size > 1024 * 1024 or signature.stat().st_size != 64:
        fail("invalid-signature", role)
    statement = verify(path.read_bytes(), signature.read_bytes(), role, policy)
    if any(statement[k] != ref[k] for k in ("name", "version", "digest")):
        fail("statement-binding", role)
    return statement


@guarded
def verify_release(ref: PackageRef, store: Path, policy: Path) -> None:
    from .bundle import read_package
    component, _ = read_package(ref, store)
    release = _stored_statement(ref, store, "release", policy)
    if release["sourceTreeDigest"] != component["identity"]["sourceTreeDigest"]:
        fail("statement-binding", "release.sourceTreeDigest")


@guarded
def review_bindings(ref: PackageRef, store: Path) -> dict:
    """Derive review identities and suite declarations from archive bytes."""
    from .bundle import read_package, resolve
    component, payloads = read_package(ref, store)
    lock = resolve([{"name": ref["name"], "version": ref["version"]}], store / "catalogue.json",
                   "review/" + ref["name"], digest(payloads["component.json"]))
    if next(p for p in lock["packages"] if p["name"] == ref["name"])["digest"] != ref["digest"]:
        fail("catalogue-binding", "review")
    refs = [cast(PackageRef, {k: p[k] for k in ("name", "version", "digest")}) for p in lock["packages"]]
    packages = [{**p, "dependencies": sorted(d["digest"] for d in locked["dependencies"])}
                for p, locked in zip(refs, lock["packages"])]
    suites = []
    for p in refs:
        manifest, _ = read_package(p, store)
        suites.extend({"package": p["digest"], **s} for s in manifest["verification"] if s["root"] == "package")
    suites.sort(key=lambda s: (s["package"], s["id"]))
    return {"lock": lock, "packages": packages, "suites": suites,
            "lockDigest": digest(canonical(lock)),
            "assemblyDigest": digest(canonical({"packages": refs})),
            "suiteSetDigest": digest(canonical(suites))}


@guarded
def verify_package(ref: PackageRef, store: Path, policy: Path) -> None:
    from .bundle import ordinary_path
    verify_release(ref, store, policy)
    guardian = _stored_statement(ref, store, "guardian", policy)
    binding = review_bindings(ref, store)
    dependencies = sorted(p["digest"] for p in binding["packages"] if p["digest"] != ref["digest"])
    if guardian["dependencies"] != dependencies:
        fail("guardian-dependencies", "guardian")
    for p in binding["packages"]:
        verify_release(cast(PackageRef, {k: p[k] for k in ("name", "version", "digest")}), store, policy)
    scopes = sorted({s["scope"] for s in binding["suites"]})
    if guardian["scope"] != scopes:
        fail("guardian-scope", "guardian")
    report_path = store / "reports" / (guardian["reportDigest"] + ".json")
    ordinary_path(report_path)
    if report_path.stat().st_size > 1024 * 1024:
        fail("metadata-limit", "report")
    data = report_path.read_bytes()
    if digest(data) != guardian["reportDigest"]:
        fail("report-digest", "report")
    report = loads(data, "report")
    if data != canonical(report):
        fail("invalid-report", "report")
    validate_report_evidence(report, binding, "review", store, policy)


@guarded
def validate_report_evidence(report: dict, binding: dict, context: str,
                             evidence_root: Path | None, policy: Path | None, *,
                             adoption: bool = False, now: int | None = None) -> dict:
    """Validate retained signed evidence without executing package code."""
    fields(binding, "lock packages suites lockDigest assemblyDigest suiteSetDigest", "binding")
    lock = validate_lock(binding["lock"])
    packages = [{**{k: p[k] for k in ("name", "version", "digest")},
                 "dependencies": sorted(d["digest"] for d in p["dependencies"])} for p in lock["packages"]]
    declarations = array(binding["suites"], "binding.suites", True)
    keys = [(s["package"], s["id"]) for s in declarations]
    if (keys != sorted(set(keys)) or any(s["package"] not in {p["digest"] for p in packages} for s in declarations)
            or binding["packages"] != packages or binding["lockDigest"] != digest(canonical(lock))
            or binding["suiteSetDigest"] != digest(canonical(declarations))):
        fail("invalid-binding", "binding")
    sha256(binding["assemblyDigest"], "binding.assemblyDigest")
    choice(context, ("review", "application"), "context")
    fields(report, "format context lockDigest assemblyDigest packages suiteSetDigest suites summary", "report", "execution")
    if type(report["format"]) is not int or report["format"] not in (1, 2) or report["context"] != context:
        fail("invalid-report", "report")
    modern = report["format"] == 2
    if ("execution" in report) != modern or (not modern and any("execution" in s for s in declarations)):
        fail("report-downgrade", "report")
    if modern:
        if evidence_root is None or policy is None:
            fail("evidence-required", "report")
        execution_document(report, "report")
    for key in ("lockDigest", "assemblyDigest", "packages", "suiteSetDigest"):
        if report[key] != binding[key]:
            fail("report-binding", "report." + key)
    expected = {(s["package"], s["id"]): s for s in binding["suites"]}
    seen = set()
    statuses = {scope: [] for scope in SCOPES}
    for suite in array(report["suites"], "report.suites"):
        fields(suite, "package id scope status exitCode seconds reason logDigest", "report.suites")
        text(suite["package"], "report.suites.package")
        text(suite["id"], "report.suites.id")
        key = (suite["package"], suite["id"])
        if key in seen or key not in expected or suite["scope"] != expected[key]["scope"]:
            fail("suite-coverage", "report.suites")
        seen.add(key)
        choice(suite["status"], ("passed", "failed", "blocked"), "report.suites.status")
        if suite["exitCode"] is not None:
            integer(suite["exitCode"], "report.suites.exitCode")
        if suite["status"] == "passed" and suite["exitCode"] != 0:
            fail("suite-result", "report.suites")
        if integer(suite["seconds"], "report.suites.seconds") < 0:
            fail("suite-result", "report.suites")
        if type(suite["reason"]) is not str:
            fail("suite-result", "report.suites")
        sha256(suite["logDigest"], "report.suites.logDigest")
        statuses[suite["scope"]].append(suite["status"])
    if seen != expected.keys():
        fail("suite-coverage", "report.suites")
    summary = {scope: ("not-applicable" if not values else "failed" if "failed" in values else
                       "blocked" if "blocked" in values else "passed") for scope, values in statuses.items()}
    if report["summary"] != summary or summary["required-local"] != "passed":
        fail("report-verdict", "report.summary")
    if modern:
        _validate_execution_evidence(report, binding, evidence_root, policy, adoption,
                                     int(time.time()) if now is None else integer(now, "now"))
    return report


def _retained_document(root, folder, identifier):
    from .bundle import ordinary_path
    sha256(identifier, folder)
    path = root / folder / (identifier + ".json")
    ordinary_path(path)
    if not path.is_file() or path.stat().st_nlink != 1:
        fail("unsafe-file", folder)
    value = read_json(path)
    encoded = canonical(value)
    if digest(encoded) != identifier or path.read_bytes() != encoded:
        fail("evidence-digest", folder)
    execution_document(value, folder, resource_executables=folder == "contexts")
    return value


def _timestamp(value, path):
    if integer(value, path) < 0:
        fail("invalid-time", path)
    return value


def _validate_cleanup(value):
    fields(value, "required attempted completed reason", "cleanup")
    for key in ("required", "attempted", "completed"):
        boolean(value[key], "cleanup." + key)
    if not value["required"]:
        if value != {"required": False, "attempted": False, "completed": True, "reason": ""}:
            fail("invalid-cleanup", "cleanup")
    elif value["completed"]:
        if not value["attempted"] or value["reason"] != "":
            fail("invalid-cleanup", "cleanup")
    elif value["reason"] != "cleanup-failed":
        fail("invalid-cleanup", "cleanup")


def _validate_owned(records, run_id, operations, cleanup, descriptor):
    owned = array(records, "ownedResources")
    if len(owned) > 32:
        fail("metadata-limit", "ownedResources")
    identities = []
    operation_for = {"apple-device": "create-temporary-simulator", "android-device": "create-temporary-emulator", "provider-room": "create-room"}
    for resource in owned:
        fields(resource, "kind id namespace createdByRunId created cleaned", "ownedResources")
        choice(resource["kind"], ("apple-device", "android-device", "process", "provider-room"), "ownedResources.kind")
        bounded_text(resource["id"], "ownedResources.id")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", resource["id"]):
            fail("invalid-resource-id", "ownedResources")
        if resource["namespace"] != run_id or resource["createdByRunId"] != run_id:
            fail("resource-ownership", "ownedResources")
        boolean(resource["created"], "ownedResources.created")
        boolean(resource["cleaned"], "ownedResources.cleaned")
        if resource["kind"] == "process":
            if not re.fullmatch(r"[0-9]+", resource["id"]):
                fail("invalid-process-id", "ownedResources")
        elif operation_for[resource["kind"]] not in operations:
            fail("resource-authority", "ownedResources")
        if resource["kind"] == "provider-room":
            prefix = descriptor["settings"].get("ephemeralRoomPrefix", "") if descriptor else ""
            pattern = re.escape(prefix + "-" + run_id + "-") + r"(?:[0-9]|[12][0-9]|3[01])"
            if not prefix or not re.fullmatch(pattern, resource["id"]):
                fail("resource-namespace", "ownedResources")
        if cleanup["completed"] and not resource["cleaned"]:
            fail("cleanup-ownership", "ownedResources")
        identities.append((resource["kind"], resource["id"]))
    unique(identities, "ownedResources")
    if owned and not cleanup["required"]:
        fail("cleanup-required", "ownedResources")


def _validate_artifacts(records):
    artifacts = array(records, "artifacts")
    if len(artifacts) > 16:
        fail("metadata-limit", "artifacts")
    paths = []
    for artifact in artifacts:
        fields(artifact, "path digest architecture", "artifacts")
        paths.append(safe_path(artifact["path"]))
        sha256(artifact["digest"], "artifacts.digest")
        choice(artifact["architecture"], (None, "x64", "arm64"), "artifacts.architecture")
    unique(paths, "artifacts", folded=True)


def _validate_prerequisite(record, descriptor, settings):
    fields(record, "id status reason observations", "prerequisites")
    choice(record["status"], ("passed", "blocked", "failed"), "prerequisites.status")
    choice(record["reason"], tuple(EXECUTION_REASONS), "prerequisites.reason")
    observation = record["observations"]
    shapes = {
        "external:compatible-apple-simulator": "platform developerVersion runtime deviceType available privateSetSupported",
        "external:android-test-environment": "sdkApi javaVersion systemImage deviceProfile available",
        "external:windows-host": "platform architecture osVersion containment",
        "external:livekit-project": "origin transport credentialsAvailable",
        "external:published-update-service": "endpointOrigin deliveryOrigin platform channel architecture systemVersion",
    }
    if record["status"] != "passed":
        if observation is not None or not record["reason"]:
            fail("invalid-observation", "prerequisites")
        return
    if not descriptor or record["id"] not in shapes or record["reason"]:
        fail("invalid-observation", "prerequisites")
    fields(observation, shapes[record["id"]], "observations")
    for key in ("available", "privateSetSupported", "credentialsAvailable"):
        if key in observation and observation[key] is not True:
            fail("invalid-observation", "observations." + key)
    for key in ("developerVersion", "javaVersion", "osVersion"):
        if key in observation:
            bounded_text(observation[key], "observations." + key, 128)
            if not re.fullmatch(r"[A-Za-z0-9_. +()-]+", observation[key]):
                fail("invalid-observation", "observations." + key)
    if record["id"] == "external:compatible-apple-simulator":
        mapping = {"platform": "applePlatform", "runtime": "appleRuntime", "deviceType": "appleDeviceType"}
        if any(observation[key] != settings.get(setting) for key, setting in mapping.items()) or descriptor["pathPlatform"] != "posix":
            fail("observation-binding", "prerequisites")
    elif record["id"] == "external:android-test-environment":
        if not 1 <= integer(observation["sdkApi"], "observations.sdkApi") <= 1000:
            fail("invalid-observation", "observations.sdkApi")
        if (observation["systemImage"] != settings.get("androidSystemImage")
                or observation["deviceProfile"] != settings.get("androidDeviceProfile")
                or (observation["systemImage"] is None) != (observation["deviceProfile"] is None)):
            fail("observation-binding", "prerequisites")
    elif record["id"] == "external:windows-host":
        if (observation["platform"] != "win32" or observation["architecture"] != "x64"
                or observation["containment"] != "job-object" or descriptor["pathPlatform"] != "windows"):
            fail("observation-binding", "prerequisites")
    elif record["id"] == "external:livekit-project":
        endpoint = settings.get("livekitUrl")
        if not endpoint or observation["origin"] != execution_origin(endpoint) or observation["transport"] != execution_url(endpoint, "livekitUrl", ("http", "https", "ws", "wss")).scheme:
            fail("observation-binding", "prerequisites")
    else:
        mapping = {"endpointOrigin": "updateReadOrigin", "deliveryOrigin": "updateDeliveryOrigin", "platform": "updatePlatform", "channel": "updateChannel", "architecture": "updateArchitecture", "systemVersion": "updateSystemVersion"}
        if any(observation[key] != settings.get(setting) for key, setting in mapping.items()):
            fail("observation-binding", "prerequisites")


def _grant_origins(declaration, descriptor, grant):
    from urllib.parse import urlsplit, urlunsplit
    settings = {key: descriptor["settings"][key] for key in grant["settings"] if key in descriptor["settings"]}
    operations = set(grant["operations"])
    origins = set()
    if "livekitUrl" in settings:
        address = urlsplit(settings["livekitUrl"])
        if operations & {"join-room", "publish-synthetic-media", "subscribe-media"}:
            scheme = {"http": "ws", "https": "wss"}.get(address.scheme, address.scheme)
            origins.add(execution_origin(urlunsplit(address._replace(scheme=scheme))))
        if operations & {"create-room", "delete-created-room", "list-account-rooms"}:
            scheme = {"ws": "http", "wss": "https"}.get(address.scheme, address.scheme)
            origins.add(execution_origin(urlunsplit(address._replace(scheme=scheme))))
    if "update-get" in operations:
        for key in ("updateReadOrigin", "updateDeliveryOrigin"):
            if key in settings:
                origins.add(settings[key])
        if "updateUrl" in settings and "updateReadOrigin" in settings and execution_origin(settings["updateUrl"]) != settings["updateReadOrigin"]:
            fail("origin-binding", "authorization")
    if grant["origins"] != sorted(origins):
        fail("origin-authority", "authorization.suites")


def _validate_grants(authorization, descriptor, declarations):
    expected = {(s["package"], s["id"]): s for s in declarations}
    for grant in authorization["suites"]:
        key = (grant["package"], grant["id"])
        declaration = expected.get(key, {})
        execution = declaration.get("execution")
        if not execution or execution["kind"] == "local":
            fail("authorization-selection", "authorization.suites")
        for field in ("operations", "settings", "secrets", "resources"):
            allowed = {r["id"] for r in execution[field]} if field == "resources" else set(execution[field])
            if not set(grant[field]) <= allowed:
                fail("authorization-escalation", "authorization.suites")
        _grant_origins(execution, descriptor, grant)


def _validate_suite_evidence(record, result, declaration, execution, descriptor, grant):
    fields(record, "package id kind startedAt completedAt phase checkStarted prerequisites resources assertions artifacts ownedResources cleanup", "execution.suites")
    choice(record["kind"], ("local", "native", "live", "simulation", "not-run"), "execution.suites.kind")
    choice(record["phase"], ("not-started", "preparing", "checking", "cleanup", "complete"), "execution.suites.phase")
    boolean(record["checkStarted"], "execution.suites.checkStarted")
    if (record["startedAt"] is None) != (record["completedAt"] is None):
        fail("invalid-time", "execution.suites")
    if record["startedAt"] is not None:
        if not execution["startedAt"] <= _timestamp(record["startedAt"], "suite.startedAt") <= _timestamp(record["completedAt"], "suite.completedAt") <= execution["completedAt"]:
            fail("invalid-time", "execution.suites")
    elif record["checkStarted"] or record["phase"] != "not-started":
        fail("execution-phase", "execution.suites")
    if record["phase"] == "not-started" and (record["startedAt"] is not None or record["checkStarted"]):
        fail("execution-phase", "execution.suites")
    spec = declaration.get("execution")
    assertions = spec["assertions"] if spec else []
    validate_execution_assertions(record["assertions"], assertions)
    if not record["checkStarted"] and any(a["actual"] is not None for a in record["assertions"]):
        fail("unstarted-assertion", "execution.suites")
    if result["reason"] in ("result-invalid", "result-missing") and any(a["actual"] is not None for a in record["assertions"]):
        fail("invalid-result-assertion", "execution.suites")
    _validate_artifacts(record["artifacts"])
    _validate_cleanup(record["cleanup"])
    _validate_owned(record["ownedResources"], execution["runId"], grant["operations"] if grant else [], record["cleanup"], descriptor)
    prerequisites = array(record["prerequisites"], "execution.prerequisites")
    if sorted(p["id"] for p in prerequisites) != sorted(declaration["requirements"]):
        fail("prerequisite-coverage", "execution.suites")
    unique([p["id"] for p in prerequisites], "execution.prerequisites")
    settings = {k: descriptor["settings"][k] for k in grant["settings"] if k in descriptor["settings"]} if descriptor and grant else {}
    for prerequisite in prerequisites:
        _validate_prerequisite(prerequisite, descriptor if spec and grant else None, settings)
    resources = array(record["resources"], "execution.resources")
    expected_resources = spec["resources"] if spec else []
    if [r["id"] for r in resources] != [r["id"] for r in expected_resources]:
        fail("resource-coverage", "execution.resources")
    descriptor_resources = {r["id"]: r for r in descriptor["resources"]} if descriptor else {}
    for resource in resources:
        fields(resource, "id digest", "execution.resources")
        if resource["digest"] is not None:
            sha256(resource["digest"], "execution.resources.digest")
            source = descriptor_resources.get(resource["id"])
            if (not grant or resource["id"] not in grant["resources"] or not source
                    or source["digest"] != resource["digest"] or source["kind"] != "directory"):
                fail("resource-binding", "execution.resources")
    if spec:
        validate_execution(spec, declaration)
        choice(result["reason"], tuple(EXECUTION_REASONS), "report.suites.reason")
    if spec and spec["kind"] != "local":
        mode = descriptor["mode"] if descriptor else None
        permitted = descriptor and grant and ((spec["kind"] == "native" and mode == "local") or
                    (mode == "simulation" and spec["simulation"]) or (spec["kind"] == "provider" and mode == "live"))
        expected_kind = ("simulation" if mode == "simulation" else "native" if mode == "local" else "live") if permitted else "not-run"
        if record["kind"] not in (expected_kind, "not-run"):
            fail("execution-kind", "execution.suites")
        if not permitted and (record["checkStarted"] or record["startedAt"] is not None):
            fail("execution-authority", "execution.suites")
        if record["checkStarted"]:
            if record["kind"] != expected_kind:
                fail("execution-kind", "execution.suites")
            for key in ("operations", "settings", "secrets"):
                if not set(spec[key]) <= set(grant[key]):
                    fail("missing-authority", "execution.suites")
            if not set(spec["settings"]) <= descriptor["settings"].keys() or not set(spec["secrets"]) <= descriptor["secrets"].keys():
                fail("missing-context-input", "execution.suites")
            for resource, requirement in zip(resources, expected_resources):
                if requirement["required"] and resource["digest"] is None:
                    fail("missing-resource", "execution.suites")
            if any(p["status"] != "passed" for p in prerequisites):
                fail("unvalidated-prerequisite", "execution.suites")
    else:
        if record["kind"] not in ("local", "not-run"):
            fail("execution-kind", "execution.suites")
        if (not spec and (declaration["requirements"] or declaration["scope"] == "deployed")
                and (record["checkStarted"] or result["status"] != "blocked")):
            fail("undeclared-execution", "execution.suites")
    observed_failure = any(a["actual"] is not None and not a["passed"] for a in record["assertions"])
    if (observed_failure or not record["cleanup"]["completed"]) and result["status"] != "failed":
        fail("evidence-verdict", "execution.suites")
    if result["status"] == "passed":
        if (not record["checkStarted"] or record["phase"] != "complete" or record["kind"] == "not-run"
                or not all(a["passed"] for a in record["assertions"])
                or any(p["status"] != "passed" for p in prerequisites)):
            fail("evidence-verdict", "execution.suites")
        if record["kind"] == "simulation" and declaration["scope"] in ("platform", "deployed"):
            fail("simulation-not-live", "execution.suites")
    if record["kind"] == "simulation" and record["checkStarted"] and result["status"] == "blocked" and result["reason"] != "simulation-not-live":
        fail("simulation-verdict", "execution.suites")


def _validate_execution_evidence(report, binding, root, policy, adoption, now):
    run = fields(report["execution"], "runId mode simulationKind contextDigest authorizationDigest evidenceDigest startedAt completedAt", "execution")
    sha256(run["runId"], "execution.runId")
    choice(run["mode"], ("local", "simulation", "live"), "execution.mode")
    choice(run["simulationKind"], ("fixture", "local-provider") if run["mode"] == "simulation" else (None,), "execution.simulationKind")
    start, end = _timestamp(run["startedAt"], "execution.startedAt"), _timestamp(run["completedAt"], "execution.completedAt")
    if not start <= end <= now + 30:
        fail("invalid-time", "execution")
    if (run["contextDigest"] is None) != (run["authorizationDigest"] is None):
        fail("execution-binding", "execution")
    descriptor = authorization = None
    if run["contextDigest"] is not None:
        descriptor = validate_execution_context(_retained_document(root, "contexts", run["contextDigest"]))
        authorization = _retained_document(root, "authorizations", run["authorizationDigest"])
        from .bundle import ordinary_path
        signature_path = root / "authorizations" / (run["authorizationDigest"] + ".sig")
        ordinary_path(signature_path)
        if signature_path.stat().st_size != 64:
            fail("invalid-signature", "authorization")
        verify(canonical(authorization), signature_path.read_bytes(), "owner", policy)
        validate_execution_authorization(authorization)
        for key in ("runId", "contextDigest"):
            if authorization[key] != run[key]:
                fail("authorization-binding", key)
        for key in ("lockDigest", "assemblyDigest", "suiteSetDigest"):
            if authorization[key] != binding[key]:
                fail("authorization-binding", key)
        if (authorization["context"] != report["context"] or authorization["policyDigest"] != digest(canonical(load_policy(policy)))
                or authorization["executionState"]["pathPlatform"] != descriptor["pathPlatform"]
                or run["mode"] != descriptor["mode"] or run["simulationKind"] != descriptor["simulationKind"]):
            fail("authorization-binding", "execution")
        if not authorization["issuedAt"] <= start <= end < authorization["expiresAt"]:
            fail("authorization-validity", "execution")
        _validate_grants(authorization, descriptor, binding["suites"])
        if adoption:
            if not authorization["issuedAt"] <= now < authorization["expiresAt"]:
                fail("authorization-expired", "execution")
            _validate_completion(report, authorization, descriptor, policy)
    elif run["mode"] != "local" or run["simulationKind"] is not None:
        fail("context-missing", "execution")
    evidence = _retained_document(root, "execution-evidence", run["evidenceDigest"])
    fields(evidence, "format runId contextDigest authorizationDigest lockDigest assemblyDigest suiteSetDigest startedAt completedAt suites", "evidence")
    if type(evidence["format"]) is not int or evidence["format"] != 1:
        fail("invalid-format", "evidence")
    for key in ("runId", "contextDigest", "authorizationDigest", "startedAt", "completedAt"):
        if evidence[key] != run[key]:
            fail("evidence-binding", key)
    for key in ("lockDigest", "assemblyDigest", "suiteSetDigest"):
        if evidence[key] != binding[key]:
            fail("evidence-binding", key)
    suites = array(evidence["suites"], "evidence.suites")
    keys = [(s["package"], s["id"]) for s in suites]
    expected = {(s["package"], s["id"]): s for s in binding["suites"]}
    if len(keys) != len(set(keys)) or set(keys) != expected.keys():
        fail("suite-coverage", "evidence.suites")
    results = {(s["package"], s["id"]): s for s in report["suites"]}
    grants = {(s["package"], s["id"]): s for s in authorization["suites"]} if authorization else {}
    for record, key in zip(suites, keys):
        _validate_suite_evidence(record, results[key], expected[key], run, descriptor, grants.get(key))


def _local_document(path):
    from .bundle import ordinary_path
    ordinary_path(path)
    if not path.is_file() or path.stat().st_nlink != 1:
        fail("unsafe-file", "execution-state")
    value = read_json(path)
    if path.read_bytes() != canonical(value):
        fail("noncanonical-document", "execution-state")
    return value


def _validate_completion(report, authorization, descriptor, policy):
    from .bundle import ordinary_path
    platform = "windows" if os.name == "nt" else "posix"
    state = authorization["executionState"]
    if state["pathPlatform"] != platform or descriptor["pathPlatform"] != platform:
        fail("unsupported-host", "execution-state")
    root = Path(state["path"])
    ordinary_path(root)
    if not root.is_dir() or str(root.resolve()) != state["path"]:
        fail("registry-binding", "execution-state")
    registry = _local_document(root / "registry.json")
    if registry != {"format": 1, "id": state["id"]}:
        fail("registry-binding", "execution-state")
    key = digest(canonical({"keyId": authorization["keyId"], "runId": authorization["runId"]}))
    claim = _local_document(root / "claims" / (key + ".json"))
    fields(claim, "format keyId runId authorizationDigest contextDigest policyDigest lockDigest assemblyDigest suiteSetDigest claimedAt", "claim")
    run = report["execution"]
    expected = {"format": 1, "keyId": authorization["keyId"], "runId": run["runId"], "authorizationDigest": run["authorizationDigest"],
                **{k: authorization[k] for k in ("contextDigest", "policyDigest", "lockDigest", "assemblyDigest", "suiteSetDigest")}, "claimedAt": claim["claimedAt"]}
    if claim != expected or type(claim["format"]) is not int or not authorization["issuedAt"] <= _timestamp(claim["claimedAt"], "claim.claimedAt") <= run["startedAt"]:
        fail("claim-binding", "execution-state")
    completion = _local_document(root / "completions" / (key + ".json"))
    expected = {"format": 1, "keyId": authorization["keyId"], "runId": run["runId"], "authorizationDigest": run["authorizationDigest"],
                "reportDigest": digest(canonical(report)), "evidenceDigest": run["evidenceDigest"], "completedAt": run["completedAt"]}
    if completion != expected or type(completion["format"]) is not int:
        fail("completion-binding", "execution-state")
    from .environment import revalidate_resources
    revalidate_resources(descriptor)
