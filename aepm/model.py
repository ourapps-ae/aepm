"""Validated package records and canonical document encoding."""

from __future__ import annotations

import decimal
import hashlib
from functools import wraps
import json
import math
import re
import ipaddress
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any, NoReturn, NotRequired, TypedDict, cast


class AepmError(Exception):
    def __init__(self, code: str, path: str):
        self.code, self.path = code, path
        super().__init__(f"{code}: {path}")


class Requirement(TypedDict):
    name: str
    version: str


class PackageRef(Requirement):
    digest: str


class LockedPackage(PackageRef):
    dependencies: list[dict[str, str]]


class Lock(TypedDict):
    format: int
    application: str
    definitionDigest: str
    packages: list[LockedPackage]


class Component(TypedDict):
    format: int
    kind: str
    identity: dict[str, str]
    facilities: list[dict[str, str]]
    documents: dict[str, Any]
    collect: list[dict[str, Any]]
    files: list[dict[str, Any]]
    artefacts: list[dict[str, Any]]
    dependencies: list[Requirement]
    provides: list[dict[str, str]]
    requires: list[dict[str, Any]]
    visual: dict[str, Any]
    capabilities: dict[str, list[str]]
    infrastructure: dict[str, Any]
    verification: list[dict[str, Any]]
    upgrade: dict[str, str]


class Definition(TypedDict):
    format: int
    id: str
    title: str
    recipe: Requirement
    components: list[dict[str, Any]]
    configuration: dict[str, Any]
    design: dict[str, Any]
    updatePolicy: str


class Assembly(TypedDict):
    format: int
    application: str
    lock: Lock
    configuration: dict[str, Any]
    design: dict[str, Any]
    files: list[dict[str, Any]]


class ReportExecution(TypedDict):
    runId: str
    mode: str
    simulationKind: str | None
    contextDigest: str | None
    authorizationDigest: str | None
    evidenceDigest: str
    startedAt: int
    completedAt: int


class Report(TypedDict):
    format: int
    context: str
    lockDigest: str
    assemblyDigest: str
    packages: list[dict[str, Any]]
    suiteSetDigest: str
    suites: list[dict[str, Any]]
    summary: dict[str, str]
    execution: NotRequired[ReportExecution]


class Proposal(TypedDict):
    format: int
    application: str
    previousLockDigest: str
    nextLockDigest: str
    configurationDigest: str
    designDigest: str
    assemblyDigest: str
    reportDigest: str
    snapshotDigest: str
    stageDigest: str
    stage: str
    changes: list[dict[str, Any]]


def fail(code: str, path: str) -> NoReturn:
    raise AepmError(code, path)


def guarded(function):
    """Keep malformed input and filesystem failures inside the public error contract."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except AepmError:
            raise
        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            fail("invalid-input", function.__name__)
    return wrapped


SAFE_INTEGER = 2 ** 53 - 1


def _number(value: float) -> str:
    """ECMAScript Number::toString, as RFC 8785 section 3.2.2.3 requires."""
    if not math.isfinite(value):
        fail("invalid-json", "document")
    if value == 0:
        return "0"
    if value < 0:
        return "-" + _number(-value)
    shortest = decimal.Decimal(repr(value)).as_tuple()
    digits = "".join(map(str, shortest.digits)).lstrip("0")
    exponent = cast(int, shortest.exponent) + len(digits) - len(digits.rstrip("0"))
    digits = digits.rstrip("0")
    k = len(digits)
    n = k + exponent
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * -n + digits
    sign = "+" if n - 1 >= 0 else "-"
    return digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + sign + str(abs(n - 1))


@guarded
def canonical(value: object) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme; integers outside plus or minus 2^53-1 are refused."""
    parts: list[str] = []

    def emit(item: object) -> None:
        if item is None:
            parts.append("null")
        elif item is True:
            parts.append("true")
        elif item is False:
            parts.append("false")
        elif type(item) is int:
            if abs(item) > SAFE_INTEGER:
                fail("invalid-number", "document")
            parts.append(str(item))
        elif type(item) is float:
            parts.append(_number(item))
        elif type(item) is str:
            parts.append(json.dumps(item, ensure_ascii=False))
        elif type(item) is list:
            parts.append("[")
            for index, child in enumerate(item):
                if index:
                    parts.append(",")
                emit(child)
            parts.append("]")
        elif type(item) is dict and all(type(key) is str for key in item):
            parts.append("{")
            for index, key in enumerate(sorted(item, key=lambda name: name.encode("utf-16-be", "surrogatepass"))):
                if index:
                    parts.append(",")
                parts.append(json.dumps(key, ensure_ascii=False))
                parts.append(":")
                emit(item[key])
            parts.append("}")
        else:
            fail("invalid-json-type", "document")

    emit(value)
    try:
        return "".join(parts).encode("utf-8")
    except UnicodeError:
        fail("invalid-json", "document")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def loads(data: bytes, path: str = "document") -> Any:
    if len(data) > 1024 * 1024:
        fail("metadata-limit", path)
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                fail("duplicate-key", path)
            result[key] = value
        return result
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: fail("invalid-number", path))
        canonical(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        fail("invalid-json", path)


def read_json(path: Path) -> Any:
    try:
        with path.open("rb") as stream:
            return loads(stream.read(1024 * 1024 + 1), str(path))
    except OSError:
        fail("read-failed", str(path))


def fields(value: object, required: str, path: str, optional: str = "") -> dict:
    if type(value) is not dict:
        fail("expected-object", path)
    need, allowed = set(required.split()), set((required + " " + optional).split())
    if not need <= value.keys() or not value.keys() <= allowed:
        fail("invalid-fields", path)
    return value


def text(value: object, path: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        fail("expected-string", path)
    return value


def array(value: object, path: str, nonempty: bool = False) -> list:
    if type(value) is not list or (nonempty and not value):
        fail("expected-array", path)
    return value


def boolean(value: object, path: str) -> bool:
    if type(value) is not bool:
        fail("expected-boolean", path)
    return value


def integer(value: object, path: str) -> int:
    if type(value) is not int:
        fail("expected-integer", path)
    return value


def choice(value: object, choices: tuple, path: str) -> Any:
    if value not in choices:
        fail("invalid-value", path)
    return value


def sha256(value: object, path: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        fail("invalid-digest", path)
    return value


def version(value: object, path: str) -> str:
    if type(value) is not str or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value):
        fail("invalid-version", path)
    return value


def name(value: object, path: str) -> str:
    if type(value) is not str or not re.fullmatch(r"ourapps-ae/[a-z][a-z0-9-]*", value):
        fail("invalid-name", path)
    return value


SPDX_ID = r"[A-Za-z0-9.-]+"
SPDX_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.:+-]+)")


def licence(value: object, path: str) -> str:
    """An SPDX licence expression (SPDX 2.3 Annex D syntax; identifiers are not checked against the list)."""
    if type(value) is not str or not 0 < len(value) <= 512 or value != value.strip():
        fail("invalid-licence", path)
    tokens, position = [], 0
    while position < len(value):
        match = SPDX_TOKEN.match(value, position)
        if not match:
            fail("invalid-licence", path)
        tokens.append(match.group(1))
        position = match.end()
    index = 0

    def peek() -> str | None:
        return tokens[index] if index < len(tokens) else None

    def take() -> str:
        nonlocal index
        if index >= len(tokens):
            fail("invalid-licence", path)
        index += 1
        return tokens[index - 1]

    def identifier(token: str, prefix: str) -> bool:
        if token.startswith("DocumentRef-"):
            document, _, token = token.partition(":")
            if not re.fullmatch("DocumentRef-" + SPDX_ID, document):
                return False
            return re.fullmatch(prefix + SPDX_ID, token) is not None
        if token in ("AND", "OR", "WITH"):
            return False
        if token.startswith(prefix):
            return re.fullmatch(prefix + SPDX_ID, token) is not None
        return re.fullmatch(SPDX_ID + ("\\+?" if prefix == "LicenseRef-" else ""), token) is not None

    def primary() -> None:
        token = take()
        if token == "(":
            disjunction()
            if take() != ")":
                fail("invalid-licence", path)
            return
        if not identifier(token, "LicenseRef-"):
            fail("invalid-licence", path)
        if peek() == "WITH":
            take()
            if not identifier(take(), "AdditionRef-"):
                fail("invalid-licence", path)

    def conjunction() -> None:
        primary()
        while peek() == "AND":
            take()
            primary()

    def disjunction() -> None:
        conjunction()
        while peek() == "OR":
            take()
            conjunction()

    disjunction()
    if index != len(tokens):
        fail("invalid-licence", path)
    return value


def safe_path(value: object, path: str = "path", *, dot: bool = False) -> str:
    value = text(value, path)
    if dot and value == ".":
        return value
    if ("\\" in value or any(ord(c) < 32 for c in value) or ":" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        fail("unsafe-path", path)
    return value


def unique(values: list, path: str, *, folded: bool = False) -> None:
    keys = [value.casefold() if folded else value for value in values]
    if len(keys) != len(set(keys)):
        fail("duplicate-value", path)


def requirement(value: object, path: str) -> Requirement:
    value = fields(value, "name version", path)
    name(value["name"], path)
    version(value["version"], path)
    return cast(Requirement, value)


def package_ref(value: object) -> PackageRef:
    value = fields(value, "name version digest", "package")
    name(value["name"], "package.name")
    version(value["version"], "package.version")
    sha256(value["digest"], "package.digest")
    return cast(PackageRef, value)


@guarded
def validate_component(value: object) -> Component:
    c = fields(value, "format kind identity facilities documents collect files artefacts dependencies provides requires visual capabilities infrastructure verification upgrade", "component")
    if type(c["format"]) is not int or c["format"] not in (1, 2):
        fail("invalid-format", "component")
    choice(c["kind"], ("component", "recipe"), "kind")
    identity = fields(c["identity"], "name version sourceRevision sourceTreeDigest licence", "identity")
    name(identity["name"], "identity.name")
    version(identity["version"], "identity.version")
    text(identity["sourceRevision"], "identity.sourceRevision")
    sha256(identity["sourceTreeDigest"], "identity.sourceTreeDigest")
    licence(identity["licence"], "identity.licence")
    for item in array(c["facilities"], "facilities", True):
        fields(item, "id description", "facilities")
        for val in item.values():
            text(val, "facilities")
    unique([x["id"] for x in c["facilities"]], "facilities")
    docs = fields(c["documents"], "contract interfaces examples licenceNotice", "documents")
    required_paths = [docs["contract"], docs["licenceNotice"]]
    for key in ("interfaces", "examples"):
        required_paths.extend(array(docs[key], "documents." + key, True))
    visual = fields(c["visual"], "definition examples outputs descriptions", "visual")
    required_paths.append(visual["definition"])
    for key in ("examples", "outputs", "descriptions"):
        required_paths.extend(array(visual[key], "visual." + key, True))
    file_modes = {}
    for item in array(c["files"], "files", True):
        fields(item, "path executable", "files")
        p = safe_path(item["path"], "files.path")
        boolean(item["executable"], "files.executable")
        if p == "component.json":
            fail("manifest-listed", p)
        file_modes[p] = item["executable"]
    unique([item["path"] for item in c["files"]], "files", folded=True)
    # A file cannot also be an ancestor of another file.
    folded = {p.casefold() for p in file_modes}
    for p in file_modes:
        parts = p.casefold().split("/")
        if any("/".join(parts[:i]) in folded for i in range(1, len(parts))):
            fail("path-collision", p)
    for item in array(c["artefacts"], "artefacts"):
        fields(item, "source destination template executable", "artefacts", "component")
        if "component" in item:
            if name(item["component"], "artefacts.component") == identity["name"]:
                fail("artefact-self-component", "artefacts.component")
        required_paths.append(item["source"])
        safe_path(item["destination"], "artefacts.destination")
        if item["destination"].split("/")[0].casefold() == ".aepm":
            fail("reserved-path", "artefacts.destination")
        boolean(item["template"], "artefacts.template")
        boolean(item["executable"], "artefacts.executable")
        if file_modes.get(item["source"]) != item["executable"]:
            fail("mode-mismatch", "artefacts.source")
    unique([a["destination"] for a in c["artefacts"]], "artefacts", folded=True)
    for dep in array(c["dependencies"], "dependencies"):
        requirement(dep, "dependencies")
    unique([d["name"] for d in c["dependencies"]], "dependencies")
    for key in ("provides", "requires"):
        for port in array(c[key], key):
            fields(port, "id type version path", key, "optional" if key == "requires" else "")
            text(port["id"], key)
            text(port["type"], key)
            version(port["version"], key)
            safe_path(port["path"], key)
            if "optional" in port:
                boolean(port["optional"], key + ".optional")
        unique([p["id"] for p in c[key]], key)
    for setting in array(c["collect"], "collect"):
        fields(setting, "id type grammar required secret", "collect", "default")
        text(setting["id"], "collect.id")
        choice(setting["type"], ("string", "boolean", "integer"), "collect.type")
        grammars = ("identifier", "qualified", "slug", "label", "environment", "address") if setting["type"] == "string" else (setting["type"],)
        choice(setting["grammar"], grammars, "collect.grammar")
        boolean(setting["required"], "collect.required")
        boolean(setting["secret"], "collect.secret")
        if "default" in setting:
            if setting["secret"]:
                fail("secret-default", "collect")
            expected = {"string": str, "boolean": bool, "integer": int}[setting["type"]]
            if type(setting["default"]) is not expected:
                fail("invalid-default", "collect")
            if expected is int and not -(2**31) <= setting["default"] < 2**31:
                fail("invalid-default", "collect")
    unique([s["id"] for s in c["collect"]], "collect")
    caps = fields(c["capabilities"], "hosts secrets writes", "capabilities")
    for key, vals in caps.items():
        for val in array(vals, "capabilities." + key):
            (safe_path if key == "writes" else text)(val, "capabilities." + key)
    infra = fields(c["infrastructure"], "accounts costStatus deployedReason", "infrastructure")
    for account in array(infra["accounts"], "infrastructure.accounts"):
        text(account, "infrastructure.accounts")
    choice(infra["costStatus"], ("unmeasured",), "infrastructure.costStatus")
    text(infra["deployedReason"], "infrastructure.deployedReason")
    package_directories = {"."}
    for p in file_modes:
        parts = p.split("/")
        package_directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    for suite in array(c["verification"], "verification", True):
        fields(suite, "id root argv cwd prepare tools fixtures locks network timeoutSeconds expectedExit scope requirements" + (" execution" if c["format"] == 2 else ""), "verification")
        text(suite["id"], "verification.id")
        choice(suite["root"], ("package", "application"), "verification.root")
        if c["kind"] != "recipe" and suite["root"] == "application":
            fail("invalid-suite-root", "verification")
        choice(suite["scope"], ("required-local", "platform", "deployed"), "verification.scope")
        safe_path(suite["cwd"], "verification.cwd", dot=True)
        if suite["root"] == "package" and suite["cwd"] not in package_directories:
            fail("missing-required-path", "verification.cwd")
        for arg in array(suite["argv"], "verification.argv", True):
            text(arg, "verification.argv")
        for prep in array(suite["prepare"], "verification.prepare"):
            fields(prep, "argv cwd network", "verification.prepare")
            for arg in array(prep["argv"], "verification.prepare.argv", True):
                text(arg, "verification.prepare.argv")
            safe_path(prep["cwd"], "verification.prepare.cwd", dot=True)
            if suite["root"] == "package" and prep["cwd"] not in package_directories:
                fail("missing-required-path", "verification.prepare.cwd")
            boolean(prep["network"], "verification.prepare.network")
        if type(suite["tools"]) is not dict:
            fail("expected-object", "verification.tools")
        for tool, ver in suite["tools"].items():
            text(tool, "verification.tools")
            text(ver, "verification.tools")
        for key in ("fixtures", "locks"):
            for p in array(suite[key], "verification." + key, key == "fixtures"):
                safe_path(p, "verification." + key)
                if suite["root"] == "package" and not (key == "fixtures" and p in package_directories):
                    required_paths.append(p)
        for req in array(suite["requirements"], "verification.requirements"):
            text(req, "verification.requirements")
            if not re.fullmatch(r"external:[a-z][a-z0-9-]{0,63}", req):
                fail("invalid-prerequisite", "verification.requirements")
        boolean(suite["network"], "verification.network")
        if integer(suite["timeoutSeconds"], "verification.timeoutSeconds") <= 0:
            fail("invalid-timeout", "verification")
        if integer(suite["expectedExit"], "verification.expectedExit") != 0:
            fail("invalid-exit", "verification")
        if c["format"] == 2:
            validate_execution(suite["execution"], suite)
            cleanup = suite["execution"]["cleanup"]
            if cleanup and suite["root"] == "package" and cleanup["cwd"] not in package_directories:
                fail("missing-required-path", "verification.execution.cleanup.cwd")
    unique([s["id"] for s in c["verification"]], "verification")
    if not any(s["root"] == "package" and s["scope"] == "required-local" for s in c["verification"]):
        fail("missing-local-suite", "verification")
    for p in required_paths:
        safe_path(p, "required-path")
        if p not in file_modes:
            fail("missing-required-path", p)
    upgrade = fields(c["upgrade"], "policy migration", "upgrade")
    choice(upgrade["policy"], ("patch", "minor", "none"), "upgrade.policy")
    choice(upgrade["migration"], ("files-only",), "upgrade.migration")
    canonical(c)
    return cast(Component, c)


@guarded
def validate_lock(value: object) -> Lock:
    lock = fields(value, "format application definitionDigest packages", "lock")
    if type(lock["format"]) is not int or lock["format"] != 1:
        fail("invalid-format", "lock")
    text(lock["application"], "lock.application")
    sha256(lock["definitionDigest"], "lock.definitionDigest")
    packages = array(lock["packages"], "lock.packages", True)
    for p in packages:
        fields(p, "name version digest dependencies", "lock.packages")
        package_ref({k: p[k] for k in ("name", "version", "digest")})
        for dep in array(p["dependencies"], "lock.dependencies"):
            fields(dep, "name digest", "lock.dependencies")
            name(dep["name"], "lock.dependencies.name")
            sha256(dep["digest"], "lock.dependencies.digest")
        names = [d["name"] for d in p["dependencies"]]
        unique(names, "lock.dependencies")
        if names != sorted(names):
            fail("unsorted-lock", "lock.dependencies")
    names = [p["name"] for p in packages]
    unique(names, "lock.packages")
    unique([p["digest"] for p in packages], "lock.packages")
    if names != sorted(names):
        fail("unsorted-lock", "lock.packages")
    refs = {p["name"]: p["digest"] for p in packages}
    for p in packages:
        for d in p["dependencies"]:
            if refs.get(d["name"]) != d["digest"]:
                fail("dependency-mismatch", "lock.dependencies")
    remaining = {p["name"]: len(p["dependencies"]) for p in packages}
    dependents = {p["name"]: [] for p in packages}
    for p in packages:
        for dep in p["dependencies"]:
            dependents[dep["name"]].append(p["name"])
    ready = [name for name, count in remaining.items() if count == 0]
    visited = 0
    while ready:
        visited += 1
        for dependent in dependents[ready.pop()]:
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                ready.append(dependent)
    if visited != len(packages):
        fail("dependency-cycle", "lock.dependencies")
    return cast(Lock, lock)


EXECUTION_OPERATIONS: frozenset[str] = frozenset("dependency-download copy-dependency-cache native-build native-test create-temporary-simulator create-temporary-emulator windows-package windows-execute create-room join-room publish-synthetic-media subscribe-media list-account-rooms delete-created-room update-get".split())
EXECUTION_SETTINGS = frozenset("applePlatform appleRuntime appleDeviceType androidSystemImage androidDeviceProfile windowsArchitecture livekitUrl updateUrl updateReadOrigin updateDeliveryOrigin expectedUpdateVersion updatePlatform updateChannel updateArchitecture updateSystemVersion ephemeralRoomPrefix maximumSeconds".split())
EXECUTION_SECRETS = frozenset(("livekitKey", "livekitSecret", "updateInvitation"))
EXECUTION_RESOURCES = {
    "appleDeveloperDirectory": (True, "read-only"), "androidSdk": (True, "copy"),
    "androidJavaHome": (True, "read-only"), "androidCache": (False, "copy"),
}
OPERATION_ASSERTIONS = {
    "native-build": {"build-produced"},
    "native-test": {"tests-discovered", "tests-executed", "tests-passed"},
    "windows-package": set("executable-architecture entrypoint-present component-present relocated-web script-integrity".split()),
    "windows-execute": set("window-live assets-loaded navigation-denied board-capture-denied mode-transition process-tree-terminated".split()),
    "create-room": set("publisher-joined subscriber-joined subscriber-publish-denied synthetic-track-received board-capture-denied reconnected media-stopped-on-close room-deleted".split()),
    "update-get": set("invitation-whole-segment response-valid platform-selection version-match delivery-origin-allowed no-install".split()),
}
NATIVE_ASSERTIONS = set("camera-selection capture-permission sound-callback late-join-ignored retry-after-failure preferences-preserved scope-released".split())
EXECUTION_ASSERTIONS = set.union(*OPERATION_ASSERTIONS.values(), NATIVE_ASSERTIONS, {"room-listed", "private-cards-hidden", "participant-mapping"})
EXECUTION_REASONS = frozenset([""] + "context-missing context-invalid context-missing-setting secret-unavailable authorization-missing authorization-denied authorization-not-yet-valid authorization-expired execution-replayed unsupported-prerequisite host-unavailable tool-unavailable tool-version-mismatch discovery-timeout private-destination-unsupported resource-missing resource-changed resource-copy-mismatch network-not-authorized simulation-not-live preparation-failed assertion-failed result-missing result-invalid timeout output-limit process-failed cleanup-failed windows-containment-unavailable unsupported-filesystem".split())


def bounded_text(value: object, path: str, maximum: int = 256, *, empty: bool = False) -> str:
    if (type(value) is not str or len(value) > maximum or (not value and not empty)
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        fail("invalid-string", path)
    try:
        value.encode("utf-8")
    except UnicodeError:
        fail("invalid-string", path)
    return value


def execution_document(value: object, path: str, *, resource_executables: bool = False) -> None:
    def check(item, depth=0, location=()):
        if depth > 32:
            fail("metadata-limit", path)
        if item is None or type(item) in (int, bool):
            return
        if type(item) is str:
            bounded_text(item, path, 4096, empty=True)
        elif type(item) is dict:
            for key, child in item.items():
                bounded_text(key, path)
                check(child, depth + 1, location + (key,))
        elif type(item) is list:
            executable_list = (resource_executables and len(location) == 3
                               and location[0] == "resources" and type(location[1]) is int
                               and location[2] == "executables")
            if len(item) > (8192 if executable_list else 256):
                fail("metadata-limit", path)
            for index, child in enumerate(item):
                check(child, depth + 1, location + (index,))
        else:
            fail("invalid-json-type", path)
    check(value)
    if len(canonical(value)) > 1024 * 1024:
        fail("metadata-limit", path)


def slug(value: object, path: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value):
        fail("invalid-identifier", path)
    return value


def sorted_strings(value: object, path: str, allowed=None, maximum: int = 32) -> list:
    items = array(value, path)
    if len(items) > maximum:
        fail("metadata-limit", path)
    for item in items:
        bounded_text(item, path)
        if allowed is not None and item not in allowed:
            fail("invalid-value", path)
    if items != sorted(set(items)):
        fail("unsorted-or-duplicate", path)
    return items


@guarded
def validate_absolute_path(value: object, platform: str) -> str:
    value = bounded_text(value, "absolute-path", 4096)
    choice(platform, ("posix", "windows"), "pathPlatform")
    if platform == "posix":
        if not value.startswith("/") or "\\" in value:
            fail("unsafe-path", "absolute-path")
        parts = value[1:].split("/") if value != "/" else []
    else:
        if not re.match(r"^[A-Z]:\\", value) or "/" in value or ":" in value[2:]:
            fail("unsafe-path", "absolute-path")
        parts = value[3:].split("\\") if len(value) > 3 else []
        for part in parts:
            if (part.endswith((".", " ")) or re.search(r'[<>"|?*]', part)
                    or re.fullmatch(r"(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?", part)):
                fail("unsafe-path", "absolute-path")
    if any(part in ("", ".", "..") for part in parts):
        fail("unsafe-path", "absolute-path")
    return value


def execution_url(value: object, path: str, schemes=("http", "https")):
    value = bounded_text(value, path, 2048)
    if re.search(r"\s|\\", value):
        fail("invalid-address", path)
    parsed = urlsplit(value)
    if (parsed.scheme not in schemes or not parsed.netloc or not parsed.hostname
            or "@" in parsed.netloc or parsed.username or parsed.password
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
        fail("invalid-address", path)
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", parsed.hostname):
        fail("invalid-address", path)
    if ":" in parsed.hostname:
        try:
            ipaddress.IPv6Address(parsed.hostname)
        except ValueError:
            fail("invalid-address", path)
    elif (len(parsed.hostname) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                          for label in parsed.hostname.rstrip(".").split("."))):
        fail("invalid-address", path)
    return parsed


def execution_origin(value: object, path: str = "origin") -> str:
    parsed = execution_url(value, path, ("http", "https", "ws", "wss"))
    host = bounded_text(parsed.hostname, path, 253).lower()
    if ":" in host:
        host = "[" + host + "]"
    default = 443 if parsed.scheme in ("https", "wss") else 80
    port = ":" + str(parsed.port) if parsed.port is not None and parsed.port != default else ""
    return parsed.scheme + "://" + host + port


def validate_origin(value: object) -> str:
    value = bounded_text(value, "origin", 2048)
    if execution_origin(value) != value:
        fail("invalid-origin", "origin")
    return value


def _validate_setting(key, value):
    if key not in EXECUTION_SETTINGS:
        fail("invalid-setting", "context.settings")
    if key == "maximumSeconds":
        if not 1 <= integer(value, key) <= 900:
            fail("invalid-setting", key)
        return
    bounded_text(value, key, 2048 if key.endswith(("Url", "Origin")) else 256)
    choices = {"applePlatform": ("ios-simulator", "tvos-simulator", "mac-catalyst"),
               "windowsArchitecture": ("x64",), "updateArchitecture": ("x64", "arm64"),
               "updatePlatform": ("browser", "android", "ios", "macos", "tvos", "windows"),
               "updateChannel": ("web", "direct", "testflight")}
    if key in choices:
        choice(value, choices[key], key)
    elif key in ("appleRuntime", "appleDeviceType", "androidSystemImage", "androidDeviceProfile"):
        if not re.fullmatch(r"[A-Za-z0-9_.:;-]+", value):
            fail("invalid-setting", key)
    elif key == "updateSystemVersion":
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value):
            fail("invalid-setting", key)
    elif key == "expectedUpdateVersion":
        version(value, key)
    elif key == "ephemeralRoomPrefix":
        slug(value, key)
    elif key.endswith("Origin"):
        validate_origin(value)
        execution_url(value, key)
    elif key in ("livekitUrl", "updateUrl"):
        parsed = execution_url(value, key, ("http", "https", "ws", "wss") if key == "livekitUrl" else ("http", "https"))
        if key == "livekitUrl" and (parsed.query or parsed.fragment):
            fail("invalid-address", key)
        if key == "updateUrl":
            from urllib.parse import unquote
            if (not re.fullmatch(r"/l/[^/]+", parsed.path)
                    or re.search(r"%2f|%5c", parsed.path, re.I)
                    or re.search(r"%(?![0-9a-fA-F]{2})", parsed.path)
                    or any(ord(c) < 32 for c in unquote(parsed.path))):
                fail("invalid-address", key)


@guarded
def validate_execution_context(value: object) -> dict:
    execution_document(value, "context", resource_executables=True)
    c = fields(value, "format id pathPlatform mode simulationKind settings resources secrets", "context")
    if type(c["format"]) is not int or c["format"] != 1:
        fail("invalid-format", "context")
    slug(c["id"], "context.id")
    choice(c["pathPlatform"], ("posix", "windows"), "context.pathPlatform")
    choice(c["mode"], ("local", "simulation", "live"), "context.mode")
    choice(c["simulationKind"], ("fixture", "local-provider") if c["mode"] == "simulation" else (None,), "context.simulationKind")
    if type(c["settings"]) is not dict or len(c["settings"]) > 32:
        fail("invalid-settings", "context.settings")
    for key, val in c["settings"].items():
        _validate_setting(key, val)
        if key in ("livekitUrl", "updateUrl", "updateReadOrigin", "updateDeliveryOrigin"):
            parsed = execution_url(val, key, ("http", "https", "ws", "wss"))
            if c["mode"] == "local":
                fail("invalid-mode", "context.settings")
            if c["mode"] == "live" and parsed.scheme not in ("https", "wss"):
                fail("invalid-address", key)
            if c["mode"] == "simulation":
                host = bounded_text(parsed.hostname, key, 253)
                try:
                    loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
                except ValueError:
                    loopback = False
                comparison_only = key == "updateDeliveryOrigin" and parsed.scheme == "https"
                if not loopback and not comparison_only:
                    fail("invalid-simulation-origin", key)
    settings = c["settings"]
    if "updatePlatform" in settings and "updateChannel" in settings:
        channels = {"browser": {"web"}, "android": {"direct"}, "ios": {"testflight"},
                    "macos": {"direct", "testflight"}, "tvos": {"testflight"}, "windows": {"direct"}}
        if settings["updateChannel"] not in channels[settings["updatePlatform"]]:
            fail("invalid-channel", "context.settings")
    resources = array(c["resources"], "context.resources")
    if len(resources) > 4:
        fail("metadata-limit", "context.resources")
    for resource in resources:
        fields(resource, "id kind path digest executables", "context.resources", "inventoryRoot")
        choice(resource["id"], tuple(EXECUTION_RESOURCES), "context.resources.id")
        choice(resource["kind"], ("directory", "file"), "context.resources.kind")
        validate_absolute_path(resource["path"], c["pathPlatform"])
        if "inventoryRoot" in resource:
            if resource["id"] != "appleDeveloperDirectory" or resource["kind"] != "directory":
                fail("invalid-inventory-root", "context.resources")
            boundary = validate_absolute_path(resource["inventoryRoot"], c["pathPlatform"])
            separator = "/" if c["pathPlatform"] == "posix" else "\\"
            if boundary.rsplit(separator, 1)[-1] != "Contents" or resource["path"] != boundary + separator + "Developer":
                fail("invalid-inventory-root", "context.resources")
        sha256(resource["digest"], "context.resources.digest")
        for path in sorted_strings(resource["executables"], "context.resources.executables", maximum=8192):
            safe_path(path, dot=resource["kind"] == "file")
    sorted_strings([r["id"] for r in resources], "context.resources", maximum=4)
    if type(c["secrets"]) is not dict or len(c["secrets"]) > 3:
        fail("invalid-secrets", "context.secrets")
    for key, secret in c["secrets"].items():
        choice(key, tuple(EXECUTION_SECRETS), "context.secrets")
        fields(secret, "secretRef version", "context.secrets")
        slug(secret["secretRef"], "context.secrets.secretRef")
        bounded_text(secret["version"], "context.secrets.version", 128)
    if "updateUrl" in settings and "updateInvitation" in c["secrets"]:
        fail("ambiguous-invitation", "context")
    return c


@guarded
def validate_execution(value: object, suite: dict) -> dict:
    execution_document(value, "execution")
    e = fields(value, "kind simulation operations settings secrets resources assertions cleanup", "execution")
    choice(e["kind"], ("local", "native", "provider"), "execution.kind")
    boolean(e["simulation"], "execution.simulation")
    for key, allowed in (("operations", EXECUTION_OPERATIONS), ("settings", EXECUTION_SETTINGS),
                         ("secrets", EXECUTION_SECRETS), ("assertions", EXECUTION_ASSERTIONS)):
        sorted_strings(e[key], "execution." + key, allowed)
    resources = array(e["resources"], "execution.resources")
    for resource in resources:
        fields(resource, "id required access", "execution.resources")
        if resource["id"] not in EXECUTION_RESOURCES:
            fail("invalid-resource", "execution.resources")
        boolean(resource["required"], "execution.resources.required")
        if (resource["required"], resource["access"]) != EXECUTION_RESOURCES[resource["id"]]:
            fail("invalid-resource-access", "execution.resources")
    ids = sorted_strings([r["id"] for r in resources], "execution.resources", maximum=4)
    operations = set(e["operations"])
    if e["kind"] == "local" and (e["simulation"] or operations or e["settings"] or e["secrets"] or resources):
        fail("invalid-local-authority", "execution")
    if e["kind"] == "provider" and resources:
        fail("invalid-provider-resource", "execution")
    if e["kind"] == "native" and e["secrets"]:
        fail("invalid-native-secret", "execution")
    if e["kind"] != "local" and not e["assertions"]:
        fail("missing-assertions", "execution")
    required = set()
    for operation, assertions in OPERATION_ASSERTIONS.items():
        if operation in operations:
            required.update(assertions)
    if "list-account-rooms" in operations:
        required.add("room-listed")
    if not required <= set(e["assertions"]):
        fail("missing-assertions", "execution")
    if e["kind"] == "native":
        applicable = NATIVE_ASSERTIONS | set.union(*(OPERATION_ASSERTIONS[k] for k in ("native-build", "native-test", "windows-package", "windows-execute")))
        if not set(e["assertions"]) <= applicable:
            fail("inapplicable-assertion", "execution")
    elif e["kind"] == "provider":
        applicable = OPERATION_ASSERTIONS["create-room"] | OPERATION_ASSERTIONS["update-get"] | {"private-cards-hidden", "participant-mapping"}
        if "list-account-rooms" in operations:
            applicable.add("room-listed")
        if not set(e["assertions"]) <= applicable:
            fail("inapplicable-assertion", "execution")
    provider_ops = set("create-room join-room publish-synthetic-media subscribe-media list-account-rooms delete-created-room update-get".split())
    native_ops = EXECUTION_OPERATIONS - provider_ops - {"dependency-download", "copy-dependency-cache"}
    if (e["kind"] == "native" and operations & provider_ops) or (e["kind"] == "provider" and operations & native_ops):
        fail("invalid-operation-kind", "execution")
    prerequisites = suite.get("requirements", [])
    if "external:compatible-apple-simulator" in prerequisites and "appleDeveloperDirectory" not in ids:
        fail("missing-resource", "execution")
    if "external:android-test-environment" in prerequisites and not {"androidSdk", "androidJavaHome"} <= set(ids):
        fail("missing-resource", "execution")
    cleanup = e["cleanup"]
    if operations & {"create-temporary-simulator", "create-temporary-emulator", "create-room"} and cleanup is None:
        fail("missing-cleanup", "execution")
    if cleanup is not None:
        fields(cleanup, "argv cwd timeoutSeconds", "execution.cleanup")
        for arg in array(cleanup["argv"], "execution.cleanup.argv", True):
            bounded_text(arg, "execution.cleanup.argv", 4096)
        if cleanup["argv"][0] not in suite.get("tools", {}):
            fail("undeclared-tool", "execution.cleanup.argv")
        safe_path(cleanup["cwd"], "execution.cleanup.cwd", dot=True)
        if not 1 <= integer(cleanup["timeoutSeconds"], "execution.cleanup.timeoutSeconds") <= 60:
            fail("invalid-timeout", "execution.cleanup")
    return e


@guarded
def validate_execution_authorization(value: object) -> dict:
    execution_document(value, "authorization")
    """The grant an owner's execution-authorization attestation carries, with its signing keyid and assembly."""
    a = fields(value, "keyId runId contextDigest policyDigest executionState context lockDigest assemblyDigest suiteSetDigest suites issuedAt expiresAt", "authorization")
    for key in ("keyId", "runId", "contextDigest", "policyDigest", "lockDigest", "assemblyDigest", "suiteSetDigest"):
        sha256(a[key], "authorization." + key)
    state = fields(a["executionState"], "path id pathPlatform", "authorization.executionState")
    validate_absolute_path(state["path"], state["pathPlatform"])
    sha256(state["id"], "authorization.executionState.id")
    choice(a["context"], ("review", "application"), "authorization.context")
    pairs = []
    for suite in array(a["suites"], "authorization.suites"):
        fields(suite, "package id operations origins settings secrets resources", "authorization.suites")
        sha256(suite["package"], "authorization.suites.package")
        bounded_text(suite["id"], "authorization.suites.id")
        pairs.append((suite["package"], suite["id"]))
        for key, allowed in (("operations", EXECUTION_OPERATIONS), ("settings", EXECUTION_SETTINGS),
                             ("secrets", EXECUTION_SECRETS), ("resources", EXECUTION_RESOURCES)):
            sorted_strings(suite[key], "authorization.suites." + key, allowed, 4 if key == "resources" else 32)
        for origin in sorted_strings(suite["origins"], "authorization.suites.origins"):
            validate_origin(origin)
    if pairs != sorted(set(pairs)):
        fail("suite-coverage", "authorization.suites")
    start, end = integer(a["issuedAt"], "authorization.issuedAt"), integer(a["expiresAt"], "authorization.expiresAt")
    if start < 0 or not 0 < end - start <= 86400:
        fail("invalid-validity", "authorization")
    return a


@guarded
def validate_execution_assertions(value: object, expected: list[str], *, helper: bool = False) -> list:
    records = array(value, "assertions")
    if len(records) > 32:
        fail("metadata-limit", "assertions")
    ids = []
    for record in records:
        fields(record, "id passed actual", "assertions")
        ids.append(record["id"])
        choice(record["id"], tuple(EXECUTION_ASSERTIONS), "assertions.id")
        boolean(record["passed"], "assertions.passed")
        actual = record["actual"]
        if helper and record["id"] == "process-tree-terminated":
            if record != {"id": "process-tree-terminated", "passed": False, "actual": None}:
                fail("runner-owned-assertion", "assertions")
        if actual is None:
            if record["passed"]:
                fail("contradictory-assertion", "assertions")
        elif record["id"] in ("tests-discovered", "tests-executed", "tests-passed", "synthetic-track-received"):
            if not 0 <= integer(actual, "assertions.actual") <= 2**31 - 1:
                fail("invalid-assertion", "assertions")
            passed = actual == 0 if record["id"] == "tests-passed" else actual >= 1
            if record["passed"] != passed:
                fail("contradictory-assertion", "assertions")
        elif type(actual) is not bool or actual != record["passed"]:
            fail("contradictory-assertion", "assertions")
    if ids != sorted(expected) or len(set(ids)) != len(ids):
        fail("assertion-coverage", "assertions")
    return records
