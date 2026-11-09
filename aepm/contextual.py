"""Private structured suite execution and concrete prerequisite observations."""

import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import tempfile
import time
from urllib.parse import urlsplit

from .environment import clock, origin, validate_resource, file_digest
from .io import VerificationDirectory, fail, fields, immutable_blob, load, private_directory, rooted, snapshot, write
from .model import AepmError, canonical, digest, validate_execution_assertions, validate_execution_context, EXECUTION_REASONS
from .process import run
from .supervision import Recorder, validate_document
from .tool_selection import require_selection


EMPTY_CLEANUP = {"required": False, "attempted": False, "completed": True, "reason": ""}


class SuiteBudget:
    """One deadline for validation, preparation and the check; cleanup is separate."""

    def __init__(self, seconds, execution=None, *, started=None):
        self.started = time.monotonic() if started is None else started
        self.deadline = self.started + seconds
        self.execution = execution

    def restrict(self, seconds):
        if seconds is not None:
            self.deadline = min(self.deadline, self.started + seconds)

    def remaining(self, maximum=None, *, reason="timeout"):
        remaining = self.deadline - time.monotonic()
        if self.execution is not None:
            self.execution.check_time()
            authorization = self.execution.authorization
            if authorization is not None:
                lifetime = authorization["expiresAt"] - time.time()
                if lifetime <= 0:
                    fail("authorization-expired", "authorization")
                remaining = min(remaining, lifetime)
        if remaining <= 0:
            fail(reason, "verification-budget")
        return remaining if maximum is None else min(remaining, maximum)


def check_probe_completion(reason, budget):
    if reason == "cleanup-failed":
        fail("cleanup-failed", "process-containment")
    if budget is not None:
        budget.remaining(reason="discovery-timeout")
    if reason == "timeout":
        fail("discovery-timeout", "prerequisite")


def evidence_record(suite):
    specification = suite.get("execution", {"assertions": [], "resources": []})
    return {"package": suite["package"], "id": suite["id"], "kind": "not-run", "startedAt": None, "completedAt": None,
            "phase": "not-started", "checkStarted": False,
            "prerequisites": [{"id": item, "status": "blocked", "reason": "context-missing", "observations": None} for item in suite["requirements"]],
            "resources": [{"id": item["id"], "digest": None} for item in specification["resources"]],
            "assertions": [{"id": item, "passed": False, "actual": None} for item in specification["assertions"]],
            "artifacts": [], "ownedResources": [], "cleanup": dict(EMPTY_CLEANUP)}


RESOURCE_TOOLS = {"java": "androidJavaHome", "javac": "androidJavaHome", "xcodebuild": "appleDeveloperDirectory",
                  "swift": "appleDeveloperDirectory", "swiftc": "appleDeveloperDirectory",
                  "adb": "androidSdk", "emulator": "androidSdk"}


def _resource_tools(tools, selected):
    identifiers = {item["id"] for item in selected}
    return frozenset(name for name in tools if RESOURCE_TOOLS.get(name) in identifiers)


def _run_alias(name, resolved, environment, target):
    """True when a lookup found this run's single-hop alias for name, pointing at target."""
    private = environment.get("AEPM_PRIVATE_ROOT")
    if not resolved or not private or Path(resolved) != Path(private) / "tools" / name:
        return False
    return Path(resolved).is_symlink() and os.readlink(resolved) == str(target)


def check_aliases(directory, expected):
    """The alias directory must still be 0500, ours, and hold exactly the expected names and targets."""
    try:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o500 or info.st_uid != os.geteuid()
                or {path.name: os.readlink(path) for path in directory.iterdir()} != expected):
            fail("resource-changed", "tool")
    except OSError:
        fail("resource-changed", "tool")


def _selected_which(name, environment, tool_selection, resource_names):
    """Resolve a declared bare name; with a selection, generic names must reach their binding."""
    if tool_selection is not None and name not in resource_names:
        tool_selection.resolve(name)
    resolved = shutil.which(name, path=environment["PATH"])
    if tool_selection is not None and name not in resource_names:
        canonical_path = tool_selection.canonical(name)
        if _run_alias(name, resolved, environment, canonical_path):
            tool_selection.check(name, canonical_path, tool_selection.path)
        else:
            tool_selection.check(name, str(Path(resolved).resolve()) if resolved else "", environment["PATH"])
    return resolved


def resolve_command(argv, cwd, tools, environment, bindings=None, *, tool_selection=None, resource_names=frozenset()):
    argv = list(argv)
    identity_key = argv[0]
    files = []
    if "/" in argv[0] or "\\" in argv[0]:
        candidate = argv[0][2:] if argv[0].startswith("./") else argv[0]
        argv[0] = str(rooted(cwd, candidate))
    elif argv[0] not in tools:
        fail("tool-unavailable", "undeclared-tool")
    else:
        resolved = _selected_which(argv[0], environment, require_selection(tool_selection), resource_names)
        if not resolved:
            fail("tool-unavailable", "tools")
        if os.name == "nt" and Path(resolved).suffix.lower() in (".cmd", ".bat"):
            if argv[0] not in ("npm", "npx") or "node" not in tools:
                fail("tool-unavailable", "tools")
            script = Path(resolved).parent / "node_modules/npm/bin" / (argv[0] + "-cli.js")
            node = shutil.which("node", path=environment["PATH"])
            if not node or not script.is_file() or script.is_symlink():
                fail("tool-unavailable", "tools")
            files.extend((Path(resolved), script))
            argv = [str(Path(node).resolve()), str(script.resolve()), *argv[1:]]
        else:
            argv[0] = str(Path(resolved).resolve())
    if bindings is not None:
        files.insert(0, Path(argv[0]))
        identities = []
        for path in files:
            identities.append((str(path.resolve()), file_digest(path), path.stat().st_mode & 0o7777))
        if bindings.setdefault(identity_key, identities) != identities:
            fail("resource-changed", "tool")
    return argv


def tool_environment(home, tools, selected, *, tool_selection=None):
    """With a selection, PATH starts with a private directory holding one alias per declared tool."""
    tool_selection = require_selection(tool_selection)
    if tool_selection is not None and os.name == "nt":
        fail("tool-selection-invalid", "toolSelection")
    private_directory(home)
    roots = {item["id"]: Path(item["path"]) for item in selected}
    protocol = home.parent / "protocol"
    for name, working in (("androidSdk", "android-sdk-working"), ("androidCache", "gradle-working")):
        if name in roots:
            path = protocol / working
            if not path.is_dir() or path.is_symlink():
                fail("resource-copy-mismatch", name)
            roots[name] = path
    directories, generic, resources, targets = [], [], {}, {}
    for name in tools:
        if "/" in name or "\\" in name:
            fail("tool-unavailable", "tools")
        executable = None
        if name in ("java", "javac") and "androidJavaHome" in roots:
            executable = roots["androidJavaHome"] / "bin" / (name + (".exe" if os.name == "nt" else ""))
        elif name == "xcodebuild" and "appleDeveloperDirectory" in roots:
            executable = roots["appleDeveloperDirectory"] / "usr/bin/xcodebuild"
        elif name in ("swift", "swiftc") and "appleDeveloperDirectory" in roots:
            executable = roots["appleDeveloperDirectory"] / "Toolchains/XcodeDefault.xctoolchain/usr/bin" / name
        elif name in ("adb", "emulator") and "androidSdk" in roots:
            executable = roots["androidSdk"] / ("platform-tools" if name == "adb" else "emulator") / (name + (".exe" if os.name == "nt" else ""))
        elif tool_selection is not None:
            executable = Path(tool_selection.canonical(name))
        else:
            resolved = shutil.which(name)
            if resolved:
                executable = Path(resolved).resolve()
        if executable is None or not executable.is_file():
            fail("tool-unavailable", name)
        if os.name == "nt" and getattr(executable.resolve().lstat(), "st_file_attributes", 0) & 0x400:
            fail("tool-unavailable", name)
        bound_resource = ("androidJavaHome" if name in ("java", "javac") else
                          "androidSdk" if name in ("adb", "emulator") else
                          "appleDeveloperDirectory" if name in ("xcodebuild", "swift", "swiftc") else None)
        if bound_resource in roots:
            resource = next(item for item in selected if item["id"] == bound_resource)
            boundary = (roots[bound_resource] if bound_resource == "androidSdk" else Path(resource.get("inventoryRoot", resource["path"]))).resolve()
            if not executable.resolve().is_relative_to(boundary):
                fail("resource-changed", bound_resource)
            if bound_resource == "androidSdk":
                seed = Path(resource["path"]) / executable.relative_to(roots[bound_resource])
                if not seed.is_file() or file_digest(seed) != file_digest(executable):
                    fail("resource-copy-mismatch", bound_resource)
        targets[name] = executable
        if tool_selection is None:
            directories.append(str(executable.parent))
        elif bound_resource in roots:
            resources[name] = executable
        else:
            generic.append(str(tool_selection.resolve(name).parent))
    if tool_selection is not None:
        aliases = private_directory(home.parent / "tools")
        if any(aliases.iterdir()):
            fail("resource-changed", "tool")
        for name, executable in targets.items():
            (aliases / name).symlink_to(executable)
        aliases.chmod(0o500)
        directories = [str(aliases)] + generic + [str(executable.parent) for executable in resources.values()]
    tail = list(tool_selection.directories) if tool_selection is not None else os.defpath.split(os.pathsep)
    environment = {"PATH": os.pathsep.join(dict.fromkeys(directories + tail)),
                   "AEPM_PRIVATE_ROOT": str(home.parent),
                   "HOME": str(home), "TMPDIR": str(home), "USER": "aepm", "LOGNAME": "aepm",
                   "XDG_CACHE_HOME": str(home / "cache"), "XDG_CONFIG_HOME": str(home / "config"),
                   "npm_config_cache": str(home / "npm"), "npm_config_userconfig": str(home / "npmrc"),
                   "GRADLE_USER_HOME": str(protocol / "gradle-working"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "ANDROID_USER_HOME": str(protocol / "android-user"), "ANDROID_AVD_HOME": str(protocol / "profiles/android"),
                   "JAVA_TOOL_OPTIONS": json.dumps("-Duser.home=" + str(home)),
                   "CI": "true", "PYTHONDONTWRITEBYTECODE": "1"}
    if "androidSdk" in roots:
        environment["ANDROID_HOME"] = environment["ANDROID_SDK_ROOT"] = str(roots["androidSdk"])
    if "androidJavaHome" in roots:
        environment["JAVA_HOME"] = str(roots["androidJavaHome"])
    if "androidCache" in roots:
        environment["GRADLE_USER_HOME"] = str(roots["androidCache"])
    if "appleDeveloperDirectory" in roots:
        environment["DEVELOPER_DIR"] = str(roots["appleDeveloperDirectory"])
    if tool_selection is not None:
        for name in tools:
            if not _run_alias(name, shutil.which(name, path=environment["PATH"]), environment, targets[name]):
                fail("resource-changed", "tool")
            if name not in resources:
                tool_selection.check(name, tool_selection.canonical(name), tool_selection.path)
    if os.name == "nt":
        from .windows import system_paths
        system, binaries = system_paths()
        environment.update(USERPROFILE=str(home), APPDATA=str(home / "roaming"), LOCALAPPDATA=str(home / "local"),
                           TEMP=str(home), TMP=str(home), USERNAME="aepm", SystemRoot=str(system),
                           ComSpec=str(binaries / "cmd.exe"), PATHEXT=".COM;.EXE;.BAT;.CMD",
                           PATH=os.pathsep.join(dict.fromkeys(directories + [str(binaries)])))
    return environment


def tool_versions(suite, root, environment, bindings=None, *, budget=None, tool_selection=None, resource_names=frozenset()):
    versions = {}
    for name, expected in suite["tools"].items():
        flag = "-version" if name in ("java", "javac", "swift", "xcodebuild", "kotlinc") else "--version"
        argv = resolve_command([name, flag], root, suite["tools"], environment, bindings,
                               tool_selection=tool_selection, resource_names=resource_names)
        timeout = budget.remaining(10, reason="discovery-timeout") if budget else 10
        code, _, reason, output = run(argv, root, environment, timeout, 65536)
        check_probe_completion(reason, budget)
        if code != 0 or reason:
            fail("tool-unavailable", name)
        matches = re.findall(r"(?<![0-9])([0-9]+(?:\.[0-9]+)*)", output.decode("utf-8", errors="replace"))
        match = next((value for value in matches if value == expected or value.startswith(expected + ".")), None)
        if match is None:
            fail("tool-version-mismatch", name)
        versions[name] = match
    return versions


def probe_json(argv, root, environment, *, budget=None, tool_selection=None, resource_names=frozenset()):
    command = _selected_which(argv[0], environment, require_selection(tool_selection), resource_names)
    if not command:
        fail("tool-unavailable", "prerequisite")
    timeout = budget.remaining(20, reason="discovery-timeout") if budget else 20
    code, _, reason, output = run([str(Path(command).resolve()), *argv[1:]], root, environment, timeout, 1024 * 1024, stdout_only=True)
    check_probe_completion(reason, budget)
    if code != 0 or reason:
        fail("host-unavailable", "prerequisite")
    try:
        return json.loads(output)
    except ValueError:
        fail("host-unavailable", "prerequisite")


def prerequisites(suite, descriptor, selected, root, environment, versions, *, final=False, budget=None,
                  tool_selection=None, resource_names=frozenset()):
    tool_selection = require_selection(tool_selection)
    probe = {"tool_selection": tool_selection, "resource_names": resource_names}
    budget = budget or SuiteBudget(suite["timeoutSeconds"])
    results = []
    settings = descriptor["settings"]
    resources = {item["id"]: item for item in selected}
    for requirement in suite["requirements"]:
        budget.remaining(reason="discovery-timeout")
        observation = None
        if requirement == "external:windows-host":
            if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
                fail("host-unavailable", requirement)
            code, _, reason, _ = run([sys.executable, "-c", "pass"], root, environment, budget.remaining(10, reason="discovery-timeout"))
            check_probe_completion(reason, budget)
            if code or reason:
                fail("windows-containment-unavailable", requirement)
            observation = {"platform": "win32", "architecture": "x64", "osVersion": platform.version(), "containment": "job-object"}
        elif requirement == "external:android-test-environment":
            sdk = Path(resources["androidSdk"]["path"])
            versions_found = [int(path.name.split("-")[-1]) for path in (sdk / "platforms").glob("android-*")
                              if path.name.split("-")[-1].isdigit() and (path / "android.jar").is_file()]
            if not versions_found or "java" not in versions:
                fail("host-unavailable", requirement)
            image, profile = settings.get("androidSystemImage"), settings.get("androidDeviceProfile")
            if bool(image) != bool(profile):
                fail("context-missing-setting", requirement)
            if image:
                image_path = sdk / Path(*image.split(";"))
                if not image_path.is_dir() or not image_path.resolve().is_relative_to(sdk.resolve()):
                    fail("host-unavailable", requirement)
                working = Path(environment["ANDROID_HOME"])
                manager = working / "cmdline-tools/latest/bin" / ("avdmanager.bat" if os.name == "nt" else "avdmanager")
                seed_manager = sdk / manager.relative_to(working)
                if os.name == "nt" or not manager.is_file() or not seed_manager.is_file():
                    fail("tool-unavailable", requirement)
                if not manager.resolve().is_relative_to(working.resolve()) or file_digest(manager) != file_digest(seed_manager):
                    fail("resource-copy-mismatch", requirement)
                profile_code, _, profile_reason, output = run([str(manager), "list", "device", "-c"], root, environment, budget.remaining(20, reason="discovery-timeout"), 65536, stdout_only=True)
                check_probe_completion(profile_reason, budget)
                if profile_code != 0 or profile_reason or profile not in output.decode("utf-8", errors="replace").splitlines():
                    fail("host-unavailable", requirement)
            observation = {"sdkApi": max(versions_found), "javaVersion": versions["java"], "systemImage": image,
                           "deviceProfile": profile, "available": True}
        elif requirement == "external:compatible-apple-simulator":
            if sys.platform != "darwin":
                fail("host-unavailable", requirement)
            runtimes = probe_json(["xcrun", "simctl", "list", "runtimes", "-j"], root, environment, budget=budget, **probe)
            devices = probe_json(["xcrun", "simctl", "list", "devicetypes", "-j"], root, environment, budget=budget, **probe)
            if not any(item.get("identifier") == settings["appleRuntime"] and item.get("isAvailable") for item in runtimes.get("runtimes", [])):
                fail("host-unavailable", requirement)
            if not any(item.get("identifier") == settings["appleDeviceType"] for item in devices.get("devicetypes", [])):
                fail("host-unavailable", requirement)
            if not final:
                results.append({"id": requirement, "status": "blocked", "reason": "private-destination-unsupported", "observations": None})
                continue
            ownership = Path(environment["AEPM_OWNERSHIP_DIRECTORY"])
            created = [load(path) for path in ownership.glob("created-*.json")]
            ids = [item["resourceId"] for item in created if item.get("kind") == "apple-device" and item.get("runId") == descriptor["runId"]]
            projects = []
            for directory, directories, _ in os.walk(root, followlinks=False):
                budget.remaining(reason="discovery-timeout")
                directories[:] = sorted(name for name in directories if name not in {".aepm", ".packages", "node_modules", "packages"})
                for name in list(directories):
                    if name.endswith(".xcodeproj"):
                        project = Path(directory) / name
                        if project.is_symlink():
                            fail("result-invalid", "verification-project")
                        projects.append(project)
                        directories.remove(name)
                if len(projects) > 8:
                    fail("private-destination-unsupported", requirement)
            if len(projects) > 8 or not ids or not projects:
                fail("private-destination-unsupported", requirement)
            supported = False
            executable = _selected_which("xcodebuild", environment, tool_selection, resource_names)
            if not executable:
                fail("tool-unavailable", requirement)
            private_set = Path(environment["AEPM_CONTEXT_FILE"]).parent / "profiles/apple" / descriptor["runId"]
            if not private_set.is_dir() or private_set.is_symlink():
                fail("private-destination-unsupported", requirement)
            discovery_environment = {**environment, "SIMULATOR_DEVICE_SET_PATH": str(private_set),
                                     "CORE_SIMULATOR_DEVICE_SET_PATH": str(private_set)}
            for project in projects:
                budget.remaining(reason="discovery-timeout")
                preparation_flags = ["-disableAutomaticPackageResolution", "-onlyUsePackageVersionsFromResolvedFile"]
                caches = [project.parent / ".packages", project.parent / "build/packages"]
                cache = next((path for path in caches if path.is_dir() and path.resolve().is_relative_to(root.resolve())), None)
                if cache:
                    preparation_flags += ["-clonedSourcePackagesDirPath", str(cache), "-packageCachePath", str(cache.parent / ".package-cache"), "-disablePackageRepositoryCache"]
                listing = probe_json(["xcodebuild", "-project", str(project), "-list", "-json", *preparation_flags], root, discovery_environment, budget=budget, **probe)
                for scheme in listing.get("project", {}).get("schemes", [])[:8]:
                    timeout = budget.remaining(20, reason="discovery-timeout")
                    code, _, reason, output = run([str(Path(executable).resolve()), "-project", str(project), "-scheme", scheme, "-showdestinations", *preparation_flags], root, discovery_environment, timeout, 1024 * 1024)
                    check_probe_completion(reason, budget)
                    if code == 0 and not reason and any(re.search(rb"id:\s*" + re.escape(value.encode()) + rb"(?:[, }])", output) for value in ids):
                        supported = True
            if not supported:
                fail("private-destination-unsupported", requirement)
            observation = {"platform": settings["applePlatform"], "developerVersion": versions["xcodebuild"],
                           "runtime": settings["appleRuntime"], "deviceType": settings["appleDeviceType"], "available": True, "privateSetSupported": True}
        elif requirement == "external:livekit-project":
            address = settings.get("livekitUrl")
            if not address or not {"livekitKey", "livekitSecret"} <= descriptor["secrets"].keys():
                fail("secret-unavailable", requirement)
            if descriptor["mode"] == "simulation" and urlsplit(address).hostname not in ("localhost", "127.0.0.1", "::1"):
                fail("authorization-denied", requirement)
            observation = {"origin": origin(address), "transport": urlsplit(address).scheme, "credentialsAvailable": True}
        elif requirement == "external:published-update-service":
            required = {"updateReadOrigin", "updateDeliveryOrigin", "updatePlatform", "updateChannel", "expectedUpdateVersion"}
            if not required <= settings.keys():
                fail("context-missing-setting", requirement)
            if ("updateUrl" in settings) == ("updateInvitation" in descriptor["secrets"]):
                fail("context-invalid", requirement)
            if "updateUrl" in settings and origin(settings["updateUrl"]) != settings["updateReadOrigin"]:
                fail("authorization-denied", requirement)
            if "updateInvitation" in descriptor["secrets"]:
                secret = load(environment["AEPM_SECRETS_FILE"])["values"]["updateInvitation"]["value"]
                try:
                    validate_execution_context({"format": 1, "id": "invitation-probe", "pathPlatform": "windows" if os.name == "nt" else "posix",
                                                "mode": descriptor["mode"], "simulationKind": descriptor["simulationKind"],
                                                "settings": {"updateUrl": secret}, "resources": [], "secrets": {}})
                except AepmError:
                    fail("context-invalid", requirement)
                if origin(secret) != settings["updateReadOrigin"]:
                    fail("authorization-denied", requirement)
            if descriptor["mode"] == "simulation" and urlsplit(settings["updateReadOrigin"]).hostname not in ("localhost", "127.0.0.1", "::1"):
                fail("authorization-denied", requirement)
            if "node" not in suite["tools"]:
                fail("tool-unavailable", requirement)
            command = resolve_command(["node", str(Path(__file__).with_name("update_probe.mjs")), str(root)], root, suite["tools"], environment,
                                      tool_selection=tool_selection, resource_names=resource_names)
            probe_code, _, probe_reason, probe_output = run(command, root, environment, budget.remaining(10, reason="discovery-timeout"), 65536, stdout_only=True)
            check_probe_completion(probe_reason, budget)
            try:
                probe = json.loads(probe_output)
            except ValueError:
                fail("context-invalid", requirement)
            if probe_code != 0 or probe_reason or probe != {"valid": True}:
                fail("context-invalid", requirement)
            observation = {"endpointOrigin": settings["updateReadOrigin"], "deliveryOrigin": settings["updateDeliveryOrigin"],
                           "platform": settings["updatePlatform"], "channel": settings["updateChannel"],
                           "architecture": settings.get("updateArchitecture"), "systemVersion": settings.get("updateSystemVersion")}
        else:
            fail("unsupported-prerequisite", requirement)
        results.append({"id": requirement, "status": "passed", "reason": "", "observations": observation})
    budget.remaining(reason="discovery-timeout")
    return results


def protocol_document(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        fail("result-missing", "result")
    value = load(path)
    if path.read_bytes() != canonical(value):
        fail("result-invalid", "result")
    return value


def owned_records(directory, suite, run_id, resources, operations, settings):
    intents, creations = {}, {}
    for path in directory.iterdir():
        match = re.fullmatch(r"(intent|created)-(0|[1-9][0-9]?)\.json", path.name)
        if not match or int(match[2]) > 31:
            fail("result-invalid", "ownership")
        item = protocol_document(path)
        keys = ("format", "runId", "package", "id", "counter", "kind", "requestedId", "namespace")
        fields(item, keys + (("resourceId",) if match[1] == "created" else ()), path="ownership")
        if type(item["format"]) is not int or item["format"] != 1 or item["runId"] != run_id or item["namespace"] != run_id or item["package"] != suite["package"] or item["id"] != suite["id"] or type(item["counter"]) is not int or item["counter"] != int(match[2]):
            fail("result-invalid", "ownership")
        for field in ("requestedId", *(("resourceId",) if match[1] == "created" else ())):
            if not isinstance(item[field], str) or len(item[field]) > 256 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", item[field]):
                fail("result-invalid", "ownership")
        required_operation = {"apple-device": "create-temporary-simulator", "android-device": "create-temporary-emulator",
                              "process": "windows-execute", "provider-room": "create-room"}.get(item["kind"])
        if required_operation not in operations or run_id not in item["requestedId"]:
            fail("result-invalid", "ownership")
        (intents if match[1] == "intent" else creations)[item["counter"]] = item
    if creations.keys() - intents.keys():
        fail("result-invalid", "ownership")
    for key, creation in creations.items():
        if {field: value for field, value in creation.items() if field != "resourceId"} != intents[key]:
            fail("result-invalid", "ownership")
    expected = {(item["kind"], creations[key]["resourceId"] if key in creations else item["requestedId"]) for key, item in intents.items()}
    if len(expected) != len(intents):
        fail("result-invalid", "ownership")
    actual = set()
    for resource in resources:
        fields(resource, ("kind", "id", "namespace", "createdByRunId", "created", "cleaned"), path="ownership")
        key = (resource["kind"], resource["id"])
        if not isinstance(resource["id"], str) or len(resource["id"]) > 256 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", resource["id"]):
            fail("result-invalid", "ownership")
        if resource["kind"] == "process" and not resource["id"].isdigit():
            fail("result-invalid", "ownership")
        if resource["kind"] == "provider-room":
            prefix = settings.get("ephemeralRoomPrefix")
            if not prefix or not re.fullmatch(re.escape(prefix + "-" + run_id + "-") + r"(?:[0-9]|[12][0-9]|3[01])", resource["id"]):
                fail("result-invalid", "ownership")
        if key in actual or resource["namespace"] != run_id or resource["createdByRunId"] != run_id or type(resource["created"]) is not bool or type(resource["cleaned"]) is not bool:
            fail("result-invalid", "ownership")
        actual.add(key)
    if actual != expected:
        fail("result-invalid", "ownership")
    return resources


def result_document(path, suite, run_id, root, operations, cleanup=False, settings=None):
    value = protocol_document(path)
    keys = ("format", "runId", "package", "id", "resources", "cleanup")
    fields(value, keys if cleanup else keys + ("assertions", "artifacts"), path="result")
    if type(value["format"]) is not int or value["format"] != 1 or any(value[key] != expected for key, expected in (("runId", run_id), ("package", suite["package"]), ("id", suite["id"]))):
        fail("result-invalid", "result")
    fields(value["cleanup"], ("required", "attempted", "completed", "reason"), path="cleanup")
    if any(type(value["cleanup"][key]) is not bool for key in ("required", "attempted", "completed")) or value["cleanup"]["reason"] not in ("", "cleanup-failed"):
        fail("result-invalid", "cleanup")
    if not isinstance(value["resources"], list) or len(value["resources"]) > 32:
        fail("result-invalid", "ownership")
    owned_records(path.parent / "ownership", suite, run_id, value["resources"], operations, settings or {})
    if not cleanup:
        validate_execution_assertions(value["assertions"], suite["execution"]["assertions"], helper=True)
        if not isinstance(value["artifacts"], list) or len(value["artifacts"]) > 16:
            fail("result-invalid", "artifacts")
        seen = set()
        for artifact in value["artifacts"]:
            fields(artifact, ("path", "digest", "architecture"), path="artifacts")
            file = rooted(root, artifact["path"])
            if artifact["path"] in seen or artifact["architecture"] not in (None, "x64", "arm64") or not file.is_file() or file_digest(file) != artifact["digest"]:
                fail("result-invalid", "artifacts")
            seen.add(artifact["path"])
    return value


def execute(suite, source, allow_network, logs, execution, *, tool_selection=None, adoption_root=None):
    tool_selection = require_selection(tool_selection)
    adoption = {} if adoption_root is None else {"adoption_root": adoption_root}
    wall_started = time.monotonic()
    budget = SuiteBudget(suite["timeoutSeconds"], execution, started=wall_started)
    validation_recorded = False
    record = evidence_record(suite)
    status, code, reason, seconds, events = "blocked", None, "", 0, []
    diagnostic_events = []
    output_remaining = 8 * 1024 * 1024
    launch_bindings = {}
    containment_failed = False
    workspace = VerificationDirectory(prefix="aepm-context-")
    with workspace as temporary:
        private = private_directory(Path(temporary).resolve())
        selected, environment, descriptor, aliases = [], {}, None, None
        alias_failed = False

        def aliases_unchanged():
            nonlocal alias_failed
            try:
                check_aliases(private / "tools", aliases)
            except AepmError:
                alias_failed = True
                raise
        selection = {"tool_selection": tool_selection, "resource_names": frozenset()}
        suppressed = suite["execution"]["kind"] == "provider" or bool(suite["execution"]["secrets"])
        root, protocol = private / "root", private / "protocol"
        try:
            snapshot(source)
            shutil.copytree(source, root)
            kind, descriptor, selected, record["resources"], injected = execution.prepare(suite, private)
            budget.restrict(descriptor["settings"].get("maximumSeconds"))
            budget.remaining()
            record["kind"] = kind
            if suite["execution"]["kind"] == "provider" and descriptor["simulationKind"] != "fixture":
                if not allow_network or not suite["network"]:
                    fail("network-not-authorized", "verification")
            if tool_selection is not None:
                selection["resource_names"] = _resource_tools(suite["tools"], selected)
            environment = tool_environment(private / "home", suite["tools"], selected, tool_selection=tool_selection)
            if tool_selection is not None:
                aliases = {name: os.readlink(private / "tools" / name) for name in suite["tools"]}
                aliases_unchanged()
            environment.update(injected)
            versions = tool_versions(suite, root, environment, launch_bindings, budget=budget, **selection)
            for name in [*suite["fixtures"], *suite["locks"]]:
                if not rooted(root, name).exists():
                    fail("result-invalid", "verification-input")
            record["prerequisites"] = prerequisites(suite, descriptor, selected, root, environment, versions, budget=budget, **selection)
            validation_seconds = math.ceil(time.monotonic() - wall_started)
            events.append({"step": "validation-inputs", "preparation": True, "seconds": validation_seconds,
                           "exitCode": 0, "reason": "", "suppressed": True})
            validation_recorded = True
            seconds += validation_seconds
            steps = [*suite["prepare"], {"argv": suite["argv"], "cwd": suite["cwd"], "network": suite["network"]}]
            for index, step in enumerate(steps):
                execution.check_time()
                if step["network"] and not allow_network:
                    fail("network-not-authorized", "verification")
                for resource in selected:
                    validate_resource(resource)
                    budget.remaining()
                main = index == len(steps) - 1
                if main:
                    record["prerequisites"] = prerequisites(suite, descriptor, selected, root, environment, versions, final=True, budget=budget, **selection)
                record["startedAt"] = record["startedAt"] or clock()
                record["phase"], record["checkStarted"] = ("checking", True) if main else ("preparing", False)
                cwd = rooted(root, step["cwd"], dot=True)
                if aliases is not None:
                    aliases_unchanged()
                argv = resolve_command(step["argv"], cwd, suite["tools"], environment, launch_bindings, **selection)
                timeout = budget.remaining()
                recorder = Recorder()
                code, duration, error, output = run(argv, cwd, environment, timeout, output_remaining, diagnostics=recorder, **adoption)
                containment_failed = containment_failed or error == "cleanup-failed"
                output_remaining -= len(output)
                seconds += duration
                step_reason = ""
                if error or code != 0:
                    step_reason = error if error and error in EXECUTION_REASONS else "process-failed" if main else "preparation-failed"
                event = {"step": index, "preparation": not main, "seconds": duration, "exitCode": code, "reason": step_reason}
                events.append(event)
                diagnostic = recorder.document(suite, index, not main)
                if diagnostic["finalOutcome"]["state"] == "observed":
                    diagnostic["finalOutcome"]["outcome"]["reason"] = step_reason
                diagnostic_event = {**event, "step": "supervisor-v1/" + str(index), "seconds": 0}
                validate_document(diagnostic, suite, diagnostic_event, index)
                diagnostic_bytes = canonical(diagnostic)
                diagnostic_event["logDigest"] = digest(diagnostic_bytes)
                private_directory(logs)
                immutable_blob(logs / (diagnostic_event["logDigest"] + ".log"), diagnostic_bytes)
                diagnostic_events.append(diagnostic_event)
                if suppressed:
                    event["suppressed"] = True
                else:
                    event["logDigest"] = digest(output)
                    private_directory(logs)
                    immutable_blob(logs / (event["logDigest"] + ".log"), output)
                for resource in selected:
                    validate_resource(resource)
                    budget.remaining()
                if error or code != 0:
                    status = "failed"
                    fail(step_reason, "verification")
            if suite["execution"]["assertions"] or suite["execution"]["kind"] != "local":
                try:
                    result = result_document(protocol / "result.json", suite, execution.run_id, root, descriptor["operations"], settings=descriptor["settings"])
                except AepmError as error:
                    status = "failed"
                    fail("result-missing" if error.code == "result-missing" else "result-invalid", "result")
                record["assertions"], record["artifacts"], record["ownedResources"] = result["assertions"], result["artifacts"], result["resources"]
                if result["cleanup"]["reason"] == "cleanup-failed":
                    status = "failed"
                    fail("cleanup-failed", "cleanup")
                for assertion in record["assertions"]:
                    if assertion["id"] == "process-tree-terminated":
                        assertion.update(passed=True, actual=True)
                if not all(item["passed"] for item in record["assertions"]):
                    status = "failed"
                    fail("assertion-failed", "result")
            budget.remaining()
            status, record["phase"] = "passed", "complete"
            if kind == "simulation" and suite["scope"] in ("platform", "deployed"):
                status, reason = "blocked", "simulation-not-live"
        except (AepmError, OSError, ValueError, KeyError, TypeError) as error:
            if isinstance(error, AepmError) and error.code == "cleanup-failed" and error.path == "process-containment":
                containment_failed = True
            reason = error.code if isinstance(error, AepmError) and error.code in EXECUTION_REASONS else "result-invalid"
            if record["checkStarted"]:
                status = "failed"
            for prerequisite in record["prerequisites"]:
                if prerequisite["status"] != "passed":
                    prerequisite["reason"] = reason
        finally:
            if not validation_recorded:
                events.append({"step": "validation-inputs", "preparation": True, "seconds": math.ceil(time.monotonic() - wall_started),
                               "exitCode": None, "reason": reason, "suppressed": True})
            intents = list((protocol / "ownership").glob("intent-*.json")) if (protocol / "ownership").is_dir() else []
            cleanup_ok = not containment_failed
            if intents:
                hook = suite["execution"]["cleanup"]
                cleanup_ok = False
                if hook and environment and descriptor and not containment_failed:
                    try:
                        cwd = rooted(root, hook["cwd"], dot=True)
                        cleanup_environment = dict(environment)
                        cleanup_descriptor = dict(descriptor)
                        cleanup_descriptor["operations"] = [value for value in descriptor["operations"] if value == "delete-created-room"]
                        write(protocol / "context.json", cleanup_descriptor)
                        if aliases is not None:
                            aliases_unchanged()
                        cleanup_code, duration, cleanup_reason, _ = run(resolve_command(hook["argv"], cwd, suite["tools"], environment, launch_bindings, **selection), cwd, cleanup_environment, hook["timeoutSeconds"], **adoption)
                        seconds += duration
                        events.append({"step": "cleanup", "preparation": False, "seconds": duration, "exitCode": cleanup_code, "reason": cleanup_reason, "suppressed": True})
                        value = result_document(protocol / "cleanup.json", suite, execution.run_id, root, descriptor["operations"], cleanup=True, settings=descriptor["settings"])
                        record["ownedResources"] = value["resources"]
                        cleanup_ok = cleanup_code == 0 and not cleanup_reason and value["cleanup"]["completed"] and all(item["cleaned"] for item in value["resources"])
                    except (AepmError, OSError, ValueError, KeyError, TypeError):
                        cleanup_ok = False
            if aliases is not None:
                try:
                    aliases_unchanged()
                except AepmError:
                    if status != "failed":
                        status, reason = "failed", "resource-changed"
                if not alias_failed:
                    try:
                        (private / "tools").chmod(0o700)
                    except OSError:
                        pass
            try:
                if cleanup_ok:
                    for name in ("profiles", "android-sdk-working", "gradle-working", "android-user"):
                        if (protocol / name).exists():
                            shutil.rmtree(protocol / name)
                        if (protocol / name).exists():
                            cleanup_ok = False
            except OSError:
                cleanup_ok = False
            finally:
                try:
                    (protocol / "secrets.json").unlink(missing_ok=True)
                except OSError:
                    cleanup_ok = False
            if record["startedAt"] is not None:
                record["completedAt"] = clock()
            if record["startedAt"] is not None or not cleanup_ok or intents:
                record["cleanup"] = {"required": True, "attempted": True, "completed": cleanup_ok, "reason": "" if cleanup_ok else "cleanup-failed"}
            if not cleanup_ok:
                status, reason = "failed", "cleanup-failed"
                workspace.preserve = True
                events.append({"step": "retained-private-root", "preparation": False, "seconds": 0,
                               "exitCode": None, "reason": "cleanup-failed", "path": str(private)})
            elif alias_failed:
                workspace.preserve = True
                events.append({"step": "retained-private-root", "preparation": False, "seconds": 0,
                               "exitCode": None, "reason": "resource-changed", "path": str(private)})
    private_directory(logs)
    seconds = max(seconds, math.ceil(time.monotonic() - wall_started))
    log = canonical(events + diagnostic_events)
    immutable_blob(logs / (digest(log) + ".json"), log)
    return ({"package": suite["package"], "id": suite["id"], "scope": suite["scope"], "status": status,
             "exitCode": code, "seconds": seconds, "reason": reason, "logDigest": digest(log)}, record)
