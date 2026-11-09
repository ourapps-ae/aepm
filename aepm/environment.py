"""Validated external inputs, private materialization and single-use execution."""

import hashlib
import os
from pathlib import Path
import re
import secrets as random_secrets
import shutil
import stat
import time
from urllib.parse import urlsplit, urlunsplit

from .io import exclusive, fail, fields, immutable, immutable_blob, load, private_directory, relative, rooted, write
from .model import (canonical, digest, guarded, validate_execution_context,
                    validate_execution_authorization, EXECUTION_RESOURCES)


def path_platform():
    return "windows" if os.name == "nt" else "posix"


def clock():
    return int(time.time())


def origin(value):
    parts = urlsplit(value)
    port = parts.port
    host = parts.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    if port is not None and port != {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(parts.scheme):
        host += ":" + str(port)
    return parts.scheme.lower() + "://" + host.lower()


def suite_origins(suite, context):
    settings, operations = context["settings"], suite["execution"]["operations"]
    result = set()
    if "livekitUrl" in suite["execution"]["settings"] and "livekitUrl" in settings:
        parsed = urlsplit(settings["livekitUrl"])
        secure = parsed.scheme in ("https", "wss")
        if set(operations) & {"join-room", "publish-synthetic-media", "subscribe-media"}:
            result.add(origin(urlunsplit(parsed._replace(scheme="wss" if secure else "ws"))))
        if set(operations) & {"create-room", "delete-created-room", "list-account-rooms"}:
            result.add(origin(urlunsplit(parsed._replace(scheme="https" if secure else "http"))))
    if "update-get" in operations:
        for name in ("updateReadOrigin", "updateDeliveryOrigin"):
            if name in settings:
                result.add(settings[name])
    return sorted(result)


def file_digest(path, *, expected_size=None):
    value = hashlib.sha256()
    count = 0
    with Path(path).open("rb") as stream:
        while data := stream.read(1024 * 1024):
            count += len(data)
            if expected_size is not None and count > expected_size:
                fail("resource-changed", "resource")
            value.update(data)
    if expected_size is not None and count != expected_size:
        fail("resource-changed", "resource")
    return value.hexdigest()


def resource_records(resource, *, derive_executables=False):
    """Bind read-only link graphs or expanded copied inputs."""
    source = Path(resource["path"])
    if not source.is_absolute() or not source.exists() or source.is_symlink():
        fail("resource-missing", resource["id"])
    base = source.resolve()
    if (resource["kind"] == "directory") != base.is_dir() or (resource["kind"] == "file") != base.is_file():
        fail("resource-kind", resource["id"])
    readonly = resource["id"] in ("appleDeveloperDirectory", "androidJavaHome")
    if "inventoryRoot" in resource:
        inventory = Path(resource["inventoryRoot"])
        if (resource["id"] != "appleDeveloperDirectory" or not inventory.is_absolute() or inventory.name != "Contents"
                or inventory.is_symlink() or not inventory.is_dir() or source != inventory / "Developer"
                or source.resolve() != inventory.resolve() / "Developer"):
            fail("resource-boundary", resource["id"])
        source, base = inventory, inventory.resolve()
    allowed = base if base.is_dir() else base.parent
    executables = set(resource["executables"])
    records, paths, active, used = [], {}, set(), set()
    total = 0

    def visit(path, key, depth):
        nonlocal total
        if depth > 64 or len(records) >= 1000000 or len(key.encode("utf-8")) > 4096:
            fail("resource-limit", resource["id"])
        info = path.lstat()
        if os.name == "nt" and getattr(info, "st_file_attributes", 0) & 0x400:
            fail("resource-link", resource["id"])
        try:
            real = path.resolve()
        except RuntimeError:
            fail("resource-cycle", resource["id"])
        if not real.is_relative_to(allowed):
            fail("resource-escape", resource["id"])
        if path.is_symlink():
            if readonly:
                if paths.setdefault(key.casefold(), key) != key:
                    fail("resource-case-collision", resource["id"])
                target = os.readlink(path)
                if len(target.encode("utf-8")) > 4096:
                    fail("resource-limit", resource["id"])
                records.append({"path": key, "kind": "link", "mode": 0o777, "digest": digest(target.encode("utf-8"))})
                return
            info = real.stat()
        if paths.setdefault(key.casefold(), key) != key:
            fail("resource-case-collision", resource["id"])
        if stat.S_ISDIR(info.st_mode):
            if real in active:
                fail("resource-cycle", resource["id"])
            records.append({"path": key, "kind": "directory", "mode": 0o755, "digest": None})
            active.add(real)
            for child in sorted(real.iterdir(), key=lambda item: item.name):
                relative(child.name)
                visit(child, child.name if key == "." else key + "/" + child.name, depth + 1)
            active.remove(real)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            if info.st_size > 8 * 1024 ** 3 or total + info.st_size > 64 * 1024 ** 3:
                fail("resource-limit", resource["id"])
            total += info.st_size
            executable = bool(info.st_mode & 0o111) if derive_executables else key in executables
            if os.name != "nt" and (bool(info.st_mode & 0o111) != executable or info.st_mode & 0o7000):
                fail("resource-mode", resource["id"])
            if executable:
                used.add(key)
            records.append({"path": key, "kind": "file", "mode": 0o755 if executable else 0o644,
                            "digest": file_digest(real, expected_size=info.st_size)})
        else:
            fail("resource-special-file", resource["id"])

    visit(source, ".", 0)
    if not derive_executables and used != executables:
        fail("resource-executables", resource["id"])
    return sorted(records, key=lambda item: item["path"])


@guarded
def describe_resource(identifier, path, *, inventory_root=None, executables=None):
    """Create a descriptor using the same inventory consumed by execution."""
    if identifier not in EXECUTION_RESOURCES:
        fail("invalid-resource", "resource.id")
    if os.name == "nt" and executables is None:
        fail("resource-executables-required", identifier)
    path = Path(path).resolve()
    resource = {"id": identifier, "kind": "directory" if path.is_dir() else "file", "path": str(path),
                "digest": "0" * 64, "executables": sorted(executables or [])}
    if inventory_root is not None:
        resource["inventoryRoot"] = str(Path(inventory_root).resolve())
    records = resource_records(resource, derive_executables=executables is None)
    if executables is None:
        resource["executables"] = sorted(item["path"] for item in records if item["kind"] == "file" and item["mode"] == 0o755)
    if len(resource["executables"]) > 8192 or len(canonical(resource)) > 1024 * 1024:
        fail("metadata-limit", identifier)
    resource["digest"] = digest(canonical(records))
    validate_execution_context({"format": 1, "id": "resource-description", "pathPlatform": path_platform(), "mode": "local",
                                "simulationKind": None, "settings": {}, "resources": [resource], "secrets": {}})
    return resource


def validate_resource(resource):
    if digest(canonical(resource_records(resource))) != resource["digest"]:
        fail("resource-changed", resource["id"])


def revalidate_resources(context):
    """Adoption-only local validation; historical review never calls this."""
    validate_execution_context(context)
    if context["pathPlatform"] != path_platform():
        fail("unsupported-host", "context.pathPlatform")
    for resource in context["resources"]:
        validate_resource(resource)


def materialize(resource, destination):
    before = resource_records(resource)
    if digest(canonical(before)) != resource["digest"]:
        fail("resource-changed", resource["id"])
    source, destination = Path(resource["path"]), Path(destination)
    for record in before:
        target = destination if record["path"] == "." else rooted(destination, record["path"])
        original = source if record["path"] == "." else source / record["path"]
        if record["kind"] == "directory":
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original.resolve(), target)
            target.chmod(record["mode"])
    copied = {**resource, "path": str(destination)}
    if resource_records(resource) != before:
        fail("resource-changed", resource["id"])
    if resource_records(copied) != before:
        fail("resource-copy-mismatch", resource["id"])
    return copied


def prepare_working_resources(selected, protocol):
    protocol = private_directory(protocol)
    for resource in selected:
        if resource["id"] in ("androidSdk", "androidCache"):
            working_name = "android-sdk-working" if resource["id"] == "androidSdk" else "gradle-working"
            materialize(resource, protocol / working_name)
    if not (protocol / "gradle-working").exists():
        private_directory(protocol / "gradle-working")


def initialize_registry(path):
    from .bundle import ordinary_path
    path = Path(path).absolute()
    ordinary_path(path, missing=True)
    private_directory(path)
    registry = path / "registry.json"
    if not registry.exists():
        exclusive(registry, {"format": 1, "id": random_secrets.token_hex(32)})
    value = load(registry)
    fields(value, ("format", "id"))
    if value["format"] != 1 or not re.fullmatch(r"[0-9a-f]{64}", value["id"]):
        fail("execution-state", "registry")
    for name in ("claims", "completions"):
        private_directory(path / name)
    return {"path": str(path), "id": value["id"], "pathPlatform": path_platform()}


def claim_key(authorization):
    return digest(canonical({key: authorization[key] for key in ("keyId", "runId")}))


class Execution:
    def __init__(self, binding, policy, evidence_root, *, execution_context=None, authorization=None,
                 execution_state=None, secrets=None, allow_live=False, forbidden_roots=()):
        from .trust import load_policy, verify
        self.binding, self.policy, self.root = binding, Path(policy), Path(evidence_root)
        self.context = self.authorization = None
        self.values = {}
        self.context_digest = self.authorization_digest = None
        self.run_id = random_secrets.token_hex(32)
        self.started = clock()
        self.state = None
        for value in (execution_context, execution_state, secrets):
            if value is not None and any(Path(value).resolve().is_relative_to(Path(root).resolve()) for root in forbidden_roots):
                fail("context-invalid", "external-input-location")
        if any(value is not None for value in (execution_context, authorization, execution_state)):
            if execution_context is None or authorization is None or execution_state is None:
                fail("context-invalid", "execution-options")
            self.context = validate_execution_context(load(execution_context))
            if self.context["pathPlatform"] != path_platform():
                fail("unsupported-host", "context.pathPlatform")
            authorization = Path(authorization)
            data, signature = (authorization / "authorization.json").read_bytes(), (authorization / "authorization.sig").read_bytes()
            value = verify(data, signature, "owner", self.policy)
            self.authorization = validate_execution_authorization(value)
            self.context_digest, self.authorization_digest = digest(canonical(self.context)), digest(data)
            for key in ("lockDigest", "assemblyDigest", "suiteSetDigest"):
                if value[key] != binding[key]:
                    fail("authorization-binding", key)
            if value["context"] != binding["context"] or value["contextDigest"] != self.context_digest:
                fail("authorization-binding", "context")
            if value["policyDigest"] != digest(canonical(load_policy(self.policy))):
                fail("authorization-binding", "policy")
            declared = {(suite["package"], suite["id"]): suite for suite in binding["suites"]}
            for grant in value["suites"]:
                suite = declared.get((grant["package"], grant["id"]))
                if suite is None or "execution" not in suite or suite["execution"]["kind"] == "local":
                    fail("authorization-denied", "suite")
                for field in ("operations", "settings", "secrets"):
                    if not set(grant[field]) <= set(suite["execution"][field]):
                        fail("authorization-denied", field)
                if not set(grant["resources"]) <= {item["id"] for item in suite["execution"]["resources"]}:
                    fail("authorization-denied", "resources")
                if not set(grant["origins"]) <= set(suite_origins(suite, self.context)):
                    fail("authorization-denied", "origins")
            if allow_live != (self.context["mode"] == "live"):
                if allow_live or self.context["mode"] == "live":
                    fail("authorization-denied", "live")
            self.state = Path(execution_state).absolute()
            state = value["executionState"]
            if state["pathPlatform"] != path_platform() or str(self.state) != state["path"]:
                fail("authorization-binding", "execution-state")
            from .bundle import ordinary_path
            ordinary_path(self.state)
            if load(self.state / "registry.json") != {"format": 1, "id": state["id"]}:
                fail("authorization-binding", "execution-state")
            self.run_id = value["runId"]
            self.check_time()
            claimed = clock()
            claim = {"format": 1, **{key: value[key] for key in ("keyId", "runId", "contextDigest", "policyDigest", "lockDigest", "assemblyDigest", "suiteSetDigest")},
                     "authorizationDigest": self.authorization_digest, "claimedAt": claimed}
            exclusive(self.state / "claims" / (claim_key(value) + ".json"), claim)
            self.claim = claim
            self.started = max(clock(), claimed)
            if secrets is not None:
                secret_path = Path(secrets)
                ordinary_path(secret_path)
                if os.name != "nt" and secret_path.stat().st_mode & 0o077:
                    fail("secret-unavailable", "secrets")
                material = load(secret_path)
                fields(material, ("format", "values"))
                if material["format"] != 1 or not isinstance(material["values"], dict):
                    fail("secret-unavailable", "secrets")
                self.values = material["values"]
            immutable(self.root / "contexts" / (self.context_digest + ".json"), self.context)
            immutable(self.root / "authorizations" / (self.authorization_digest + ".json"), value)
            signature_path = self.root / "authorizations" / (self.authorization_digest + ".sig")
            immutable_blob(signature_path, signature)
        elif secrets is not None or allow_live:
            fail("context-invalid", "execution-options")

    def check_time(self):
        if self.authorization:
            now = clock()
            if now < self.authorization["issuedAt"]:
                fail("authorization-not-yet-valid", "authorization")
            if now >= self.authorization["expiresAt"]:
                fail("authorization-expired", "authorization")

    def selection(self, suite):
        declaration = suite["execution"]
        if declaration["kind"] == "local":
            return "local", {"operations": [], "origins": [], "settings": [], "secrets": [], "resources": []}
        if not self.context:
            fail("context-missing", "context")
        if self.authorization is None:
            fail("authorization-missing", "authorization")
        self.check_time()
        selected = [item for item in self.authorization["suites"] if (item["package"], item["id"]) == (suite["package"], suite["id"])]
        if len(selected) != 1:
            fail("authorization-denied", "suite")
        grant = selected[0]
        for key in ("operations", "settings", "secrets"):
            if set(grant[key]) != set(declaration[key]):
                fail("authorization-denied", key)
        if grant["origins"] != suite_origins(suite, self.context):
            fail("authorization-denied", "origins")
        if set(grant["resources"]) - {item["id"] for item in declaration["resources"]}:
            fail("authorization-denied", "resources")
        mode = self.context["mode"]
        if mode == "simulation" and declaration["simulation"]:
            return "simulation", grant
        if mode == "local" and declaration["kind"] == "native":
            return "native", grant
        if mode == "live" and declaration["kind"] == "provider":
            return "live", grant
        fail("authorization-denied", "mode")

    def prepare(self, suite, private):
        kind, grant = self.selection(suite)
        declaration = suite["execution"]
        context = self.context or {"mode": "local", "simulationKind": None, "settings": {}, "resources": [], "secrets": {}}
        settings = {}
        for key in grant["settings"]:
            if key not in context["settings"]:
                fail("context-missing-setting", key)
            settings[key] = context["settings"][key]
        selected, records, declared = [], [], {item["id"]: item for item in context["resources"]}
        for resource in declaration["resources"]:
            key = resource["id"]
            if key not in grant["resources"] or key not in declared:
                if resource["required"]:
                    fail("authorization-denied" if key not in grant["resources"] else "resource-missing", key)
                records.append({"id": key, "digest": None})
                continue
            item = declared[key]
            if item["kind"] != "directory":
                fail("resource-missing", key)
            validate_resource(item)
            actual = materialize(item, private / "resources" / key) if resource["access"] == "copy" else item
            selected.append(actual)
            records.append({"id": key, "digest": item["digest"]})
        values, references = {}, {}
        for name in grant["secrets"]:
            reference = context["secrets"].get(name)
            if reference is None:
                fail("secret-unavailable", name)
            value = self.values.get(reference["secretRef"])
            if not isinstance(value, dict) or set(value) != {"version", "value"} or value["version"] != reference["version"] or not isinstance(value["value"], str):
                fail("secret-unavailable", name)
            references[name] = reference
            values[name] = value
        protocol = private_directory(private / "protocol")
        prepare_working_resources(selected, protocol)
        private_directory(protocol / "android-user")
        private_directory(protocol / "profiles/desktop")
        private_directory(protocol / "ownership")
        descriptor = {"format": 1, "runId": self.run_id, "package": suite["package"], "id": suite["id"],
                      "mode": context["mode"] if kind != "local" else "local",
                      "simulationKind": context["simulationKind"] if kind == "simulation" else None,
                      "settings": settings, "resources": [{key: item[key] for key in ("id", "path", "digest")} for item in selected],
                      "secrets": references, "operations": grant["operations"], "origins": grant["origins"], "assertions": declaration["assertions"]}
        write(protocol / "context.json", descriptor)
        environment = {"AEPM_CONTEXT_FILE": str(protocol / "context.json"), "AEPM_RESULT_FILE": str(protocol / "result.json"),
                       "AEPM_OWNERSHIP_DIRECTORY": str(protocol / "ownership"), "AEPM_CLEANUP_RESULT_FILE": str(protocol / "cleanup.json")}
        if values:
            write(protocol / "secrets.json", {"format": 1, "runId": self.run_id, "package": suite["package"], "id": suite["id"], "values": values})
            environment["AEPM_SECRETS_FILE"] = str(protocol / "secrets.json")
        return kind, descriptor, selected, records, environment

    def publish(self, report, suites):
        completed = clock()
        evidence = {"format": 1, "runId": self.run_id, "contextDigest": self.context_digest,
                    "authorizationDigest": self.authorization_digest,
                    **{key: self.binding[key] for key in ("lockDigest", "assemblyDigest", "suiteSetDigest")},
                    "startedAt": self.started, "completedAt": completed, "suites": suites}
        evidence_digest = digest(canonical(evidence))
        report["format"] = 2
        report["execution"] = {"runId": self.run_id, "mode": self.context["mode"] if self.context else "local",
                               "simulationKind": self.context["simulationKind"] if self.context else None,
                               "contextDigest": self.context_digest, "authorizationDigest": self.authorization_digest,
                               "evidenceDigest": evidence_digest, "startedAt": self.started, "completedAt": completed}
        immutable(self.root / "execution-evidence" / (evidence_digest + ".json"), evidence)
        report_digest = digest(canonical(report))
        immutable(self.root / "reports" / (report_digest + ".json"), report)
        if report["summary"]["required-local"] == "passed":
            from .trust import validate_report_evidence
            self.check_time()
            binding = {key: value for key, value in self.binding.items() if key != "context"}
            validate_report_evidence(report, binding, self.binding["context"], self.root, self.policy)
        if self.authorization:
            if self.state is None:
                fail("authorization-binding", "execution-state")
            self.check_time()
            if load(self.state / "registry.json") != {"format": 1, "id": self.authorization["executionState"]["id"]}:
                fail("authorization-binding", "execution-state")
            if load(self.state / "claims" / (claim_key(self.authorization) + ".json")) != self.claim:
                fail("authorization-binding", "execution-state")
            exclusive(self.state / "completions" / (claim_key(self.authorization) + ".json"),
                      {"format": 1, "keyId": self.authorization["keyId"], "runId": self.run_id,
                       "authorizationDigest": self.authorization_digest, "reportDigest": report_digest,
                       "evidenceDigest": evidence_digest, "completedAt": completed})
        return report
