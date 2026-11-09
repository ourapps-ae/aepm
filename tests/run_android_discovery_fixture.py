"""Observe the unchanged Android harness; live invocation requires release."""

import argparse
from contextlib import ExitStack, contextmanager
import ctypes as c
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import threading
from unittest.mock import patch


EXPECTED = {"name": "ourapps-ae/video-calls", "version": "0.1.2",
            "digest": "2acd6afd9cea6a8931717a4793557231bcb2acf999fef8e3ddc3218ec28993e6"}
SOURCE_DIGEST = "c030d34518c9089d08fc51ff478a0a4b3bd6a80e9a9a62ebef0a4595325cb358"
CONTEXT_DIGEST = "5414ee4feb104c9d57ba2582c20bebfaa3d1e6793270e5b0a7bdf666a7614af7"
HARNESS_DIGEST = "52ff072ca460a9a550c3653257e4bbdef69dc7470ad83aa6782208173d18ef16"
OBSERVER_DIGEST = "facb05280dc1b5fdae6e691d0175cbc5a7ff6a9d320de4b251f4e9c4684f97c9"
LIMIT = 320 * 1024


def require(value, reason):
    if not value:
        raise ValueError(reason)


def ordinary(path, missing=False):
    require(path.is_absolute(), "absolute path required")
    for item in (*reversed(path.parents), path):
        try:
            mode = item.lstat().st_mode
        except FileNotFoundError:
            require(missing, "missing ordinary path")
            continue
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "nonordinary path")


def sha(path):
    ordinary(path)
    require(path.is_file(), "regular file required")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def relative(value, dot=False):
    require(isinstance(value, str) and value and "\\" not in value, "relative path required")
    if dot and value == ".":
        return value
    require(not PurePosixPath(value).is_absolute() and all(part not in ("", ".", "..") for part in value.split("/")),
            "unsafe relative path")
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def atomic(path, value):
    raw = encoded(value)
    require(len(raw) <= LIMIT, "sidecar size")
    temporary = path.with_suffix(".pending")
    temporary.write_bytes(raw)
    temporary.replace(path)


def metadata(function, *args, **kwargs):
    saved = c.get_errno()
    try:
        return function(*args, **kwargs)
    finally:
        c.set_errno(saved)


def inventory_check(path, expected_digest, out, *, fresh=True):
    ordinary(path)
    require(path.name == "inventory.json" and path.stat().st_size <= 4 * 1024 * 1024, "inventory path/size")
    require(sha(path) == expected_digest, "inventory drift")
    value = json.loads(path.read_bytes())
    require(set(value) == {"format", "files", "directories", "python", "launchPath", "toolBindings", "androidSourceSnapshotDigest",
                           "androidContextDigest", "androidExpectedPackageDigest"} and type(value["format"]) is int
            and value["format"] == 2, "inventory format")
    require(value["androidSourceSnapshotDigest"] == SOURCE_DIGEST and value["androidContextDigest"] == CONTEXT_DIGEST
            and value["androidExpectedPackageDigest"] == EXPECTED["digest"], "workload binding")
    root = path.parent
    ordinary(out, missing=True)
    require(out.parent.is_dir() and not out.is_relative_to(root) and not root.is_relative_to(out), "output boundary")
    if fresh:
        require(not out.exists(), "occupied output")
    files, directories = {}, {}
    for entry in value["files"]:
        require(set(entry) == {"path", "source", "sha256", "mode"}, "file binding fields")
        name = relative(entry["path"])
        require(name != "inventory.json" and name not in files, "duplicate file")
        original, copied = Path(entry["source"]), root / name
        require(not original.is_relative_to(out) and not out.is_relative_to(original), "original/output boundary")
        require(type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o7777, "file mode")
        require(sha(original) == entry["sha256"] == sha(copied), "file drift")
        require(stat.S_IMODE(original.stat().st_mode) == entry["mode"] == stat.S_IMODE(copied.stat().st_mode), "file mode drift")
        files[name] = entry
    for entry in value["directories"]:
        require(set(entry) == {"path", "mode"}, "directory binding fields")
        name = relative(entry["path"], dot=True)
        require(name not in directories and type(entry["mode"]) is int, "directory binding")
        ordinary(root / name)
        require((root / name).is_dir() and stat.S_IMODE((root / name).stat().st_mode) == entry["mode"], "directory drift")
        directories[name] = entry
    actual_files, actual_directories = set(), {"."}
    for folder, child_directories, child_files in os.walk(root, followlinks=False):
        for name in child_directories + child_files:
            candidate = Path(folder) / name
            ordinary(candidate)
            key = candidate.relative_to(root).as_posix()
            (actual_directories if candidate.is_dir() else actual_files).add(key)
    require(actual_files == set(files) | {"inventory.json"} and actual_directories == set(directories), "membership drift")
    python = value["python"]
    require(set(python) == {"path", "sha256", "mode", "version"}, "interpreter fields")
    interpreter = Path(python["path"])
    require(sha(interpreter) == python["sha256"] and stat.S_IMODE(interpreter.stat().st_mode) == python["mode"], "interpreter drift")
    require(interpreter == Path(sys.executable).resolve() and python["version"] == "3.12.8"
            and sys.version_info[:3] == (3, 12, 8), "interpreter selection")
    require(sha(root / "android-context.json") == CONTEXT_DIGEST, "context drift")
    PythonSelection(value, json.loads((root / "android-context.json").read_bytes()))
    return value


class PythonSelection:
    def __init__(self, inventory, context):
        self.python = inventory["python"]
        self.tools = inventory["toolBindings"]
        self.directories = inventory["launchPath"]
        require(set(self.tools) == {"python3", "node", "java"}, "exact tool bindings required")
        require(self.python["version"] == "3.12.8" and sys.version_info[:3] == (3, 12, 8), "Python version binding")
        require(self.tools["python3"]["canonicalPath"] == self.python["path"] == str(Path(sys.executable).resolve())
                and self.tools["python3"]["sha256"] == self.python["sha256"]
                and self.tools["python3"]["mode"] == self.python["mode"], "controller/Python binding")
        self.java = next(resource for resource in context["resources"] if resource["id"] == "androidJavaHome")
        require(Path(self.tools["java"]["alias"]) == Path(self.java["path"]) / "bin/java", "resource Java binding")
        require(Path(self.tools["python3"]["alias"]) == Path(self.python["path"]).parent / "python3", "Python alias binding")
        require(Path(self.tools["node"]["alias"]).name == "node", "Node alias binding")
        expected = list(dict.fromkeys([str(Path(self.python["path"]).parent),
                                       str(Path(self.tools["node"]["alias"]).parent), *os.defpath.split(os.pathsep)]))
        require(self.directories == expected, "finite launch path binding")
        self.path = os.pathsep.join(self.directories)
        self.validate()

    def executable(self, name):
        binding = self.tools[name]
        require(set(binding) == {"alias", "canonicalPath", "sha256", "mode", "links"}, "tool binding fields")
        current = Path(binding["alias"])
        require(current.is_absolute() and type(binding["links"]) is list and len(binding["links"]) <= 8, "alias chain bound")
        for link in binding["links"]:
            require(set(link) == {"path", "target"} and str(current) == link["path"], "alias chain path")
            ordinary(current.parent)
            require(current.is_symlink() and os.readlink(current) == link["target"], "alias link drift")
            target = Path(link["target"])
            current = Path(os.path.abspath(target if target.is_absolute() else current.parent / target))
        ordinary(current)
        require(str(current) == binding["canonicalPath"] and sha(current) == binding["sha256"]
                and type(binding["mode"]) is int and stat.S_IMODE(current.stat().st_mode) == binding["mode"], "tool target drift")
        require(os.access(current, os.X_OK), "tool not executable")
        return current

    def validate(self, *, active=False):
        for directory in self.directories:
            ordinary(Path(directory))
            require(Path(directory).is_dir(), "launch directory drift")
        for name in self.tools:
            self.executable(name)
        for name in ("python3", "node"):
            require(shutil.which(name, path=self.path) == self.tools[name]["alias"], "launch resolution drift")
        if active:
            require(os.environ.get("PATH") == self.path, "active launch path drift")

    @contextmanager
    def scoped(self):
        self.validate()
        with patch.dict(os.environ, {"PATH": self.path}):
            self.validate(active=True)
            yield self

    def environment(self, environment):
        self.validate(active=True)
        for name in ("python3", "java"):
            resolved = shutil.which(name, path=environment["PATH"])
            require(resolved == self.tools[name]["alias"] and str(Path(resolved).resolve()) == self.tools[name]["canonicalPath"],
                    "child tool resolution drift")
        require(Path(environment["JAVA_HOME"]).resolve() == Path(self.java["path"]).resolve(), "Java resource changed")

    def resolved(self, name, argv):
        if name in ("python3", "java"):
            require(argv[0] == str(self.executable(name)), "resolved executable mismatch")

    def evidence(self):
        return {"launchPath": self.directories,
                "tools": {name: {key: value[key] for key in ("alias", "canonicalPath", "sha256", "mode")}
                          for name, value in self.tools.items()}, "expectedPythonVersion": "3.12.8"}


def workload_inputs(root, check):
    from aepm.environment import validate_resource
    from aepm.io import load, snapshot
    from aepm.model import canonical, digest
    from tests import run_android_component_fixture as harness

    harness.inputs(root / "android", root / "android-context.json", check)
    require(digest(canonical(snapshot(root / "android"))) == SOURCE_DIGEST, "Android snapshot drift")
    context = load(root / "android-context.json")
    for resource in context["resources"]:
        validate_resource(resource)
    return context


class AndroidObserver:
    def __init__(self, harness, contextual, backend_type, recorder_type, observer_type, destination, inventory_digest, selection=None):
        self.harness, self.contextual, self.backend_type = harness, contextual, backend_type
        self.recorder_type, self.observer_type = recorder_type, observer_type
        self.destination, self.inventory_digest = destination, inventory_digest
        self.backends, self.runs, self.errors = [], [], []
        self.incomplete = self.errors_capped = False
        self.global_ordinal = self.selected_ordinal = self.active = 0
        self.local = threading.local()
        self.patches = ExitStack()
        self.selection = selection
        self.original_run, self.original_pack, self.original_init = contextual.run, harness.pack, backend_type.__init__

    def error(self, phase, error=None):
        self.incomplete = True
        name = type(error).__name__ if error is not None else "unavailable"
        item = {"phase": phase[:64], "exception": name if name in
                ("OSError", "ValueError", "RuntimeError", "AepmError", "PermissionError", "unavailable") else "other"}
        if item in self.errors:
            return
        if len(self.errors) < 32:
            self.errors.append(item)
        else:
            self.errors_capped = True

    def document(self):
        backends = []
        for association, observer in self.backends:
            try:
                detail = observer.document()
                require(len(encoded(detail)) <= 8192, "observer document bound")
                first = detail.get("firstFailure") or {}
                if detail.get("unavailable") or detail.get("countsCapped") or first.get("unavailable") or first.get("truncated"):
                    self.error("observer-incomplete")
            except Exception as error:
                self.error("observer-document", error)
                detail = {"unavailable": True, "firstFailure": None}
            backends.append({**association, "detail": detail})
        value = {"format": 1, "kind": "android-discovery-diagnostic", "completeProof": False,
                 "inventoryDigest": self.inventory_digest, "expectedPackage": EXPECTED,
                 "contextDigest": CONTEXT_DIGEST, "sourceSnapshotDigest": SOURCE_DIGEST, "constructorChecksObserved": False,
                 "activeCalls": self.active, "observationComplete": bool(self.backends) and not self.incomplete and self.active == 0,
                 "backends": backends, "runs": self.runs, "errors": self.errors, "errorsCapped": self.errors_capped}
        if self.selection is not None:
            value["toolSelection"] = self.selection.evidence()
        if len(encoded(value)) > LIMIT:
            self.error("sidecar-bound")
            first = next((item["detail"].get("firstFailure") for item in backends if item["detail"].get("firstFailure")), None)
            value = {"format": 1, "kind": "android-discovery-diagnostic", "completeProof": False,
                     "inventoryDigest": self.inventory_digest, "observationComplete": False,
                     "firstRecordedFailure": first, "errors": self.errors, "errorsCapped": self.errors_capped}
        return value

    def checkpoint(self):
        immediate = c.get_errno()
        try:
            atomic(self.destination / "checkpoint.json", self.document())
        except Exception as error:
            self.error("checkpoint", error)
        finally:
            c.set_errno(immediate)

    def attach(self, backend, *args, **kwargs):
        try:
            result = self.original_init(backend, *args, **kwargs)
        except BaseException:
            immediate = c.get_errno()
            try:
                self.error("constructor-gap")
            finally:
                c.set_errno(immediate)
            raise
        immediate = c.get_errno()
        try:
            if len(self.backends) >= 32:
                self.error("backend-cap")
            else:
                observer = self.observer_type(backend)
                observer.__enter__()
                association = dict(getattr(self.local, "association", {"globalRun": None, "selectedStep": None, "scope": "setup"}))
                self.backends.append((association, observer))
        except Exception as error:
            self.error("attachment", error)
        finally:
            c.set_errno(immediate)
        return result

    def run(self, *args, **kwargs):
        if self.selection is not None:
            metadata(self.selection.environment, args[2])
            if isinstance(kwargs.get("diagnostics"), self.recorder_type) or list(args[0][1:]) == ["--version"]:
                metadata(self.selection.resolved, "python3", args[0])
        incoming = c.get_errno()
        number = self.global_ordinal
        self.global_ordinal = min(number + 1, 2147483647)
        selected = isinstance(kwargs.get("diagnostics"), self.recorder_type)
        step = self.selected_ordinal if selected else None
        if selected:
            self.selected_ordinal = min(self.selected_ordinal + 1, 2147483647)
        association = {"globalRun": number, "selectedStep": step,
                       "scope": "validation-discovery" if step is None else "preparation" if step == 0 else "main" if step == 1 else "unclassified"}
        if len(self.runs) >= 64 or selected and step > 1:
            self.error("run-cap-or-selection")
            entry = None
        else:
            entry = {**association}
            self.runs.append(entry)
        previous = getattr(self.local, "association", None)
        self.local.association = association
        self.active += 1
        c.set_errno(incoming)
        try:
            result = self.original_run(*args, **kwargs)
        except BaseException as error:
            immediate = c.get_errno()
            try:
                if entry is not None:
                    entry["raised"] = type(error).__name__ if type(error).__name__ in ("AepmError", "OSError", "ValueError", "RuntimeError") else "other"
            finally:
                self.active -= 1
                self.local.association = previous or {"globalRun": None, "selectedStep": None, "scope": "setup"}
                try:
                    self.checkpoint()
                except Exception as observer_error:
                    self.error("checkpoint", observer_error)
                finally:
                    c.set_errno(immediate)
            raise
        immediate = c.get_errno()
        try:
            if entry is not None:
                code, seconds, reason, _output = result
                require(code is None or type(code) is int and -2147483648 <= code <= 2147483647, "result code")
                require(type(seconds) is int and 0 <= seconds <= 2147483647, "result duration")
                from aepm.model import EXECUTION_REASONS
                entry.update(exitCode=code, seconds=seconds, reason=reason if isinstance(reason, str) and reason in EXECUTION_REASONS else "redacted")
        except Exception as error:
            self.error("run-observation", error)
        finally:
            self.active -= 1
            self.local.association = previous or {"globalRun": None, "selectedStep": None, "scope": "setup"}
            try:
                self.checkpoint()
            except Exception as observer_error:
                self.error("checkpoint", observer_error)
            finally:
                c.set_errno(immediate)
        return result

    def pack(self, *args, **kwargs):
        if self.selection is not None:
            metadata(self.selection.validate, active=True)
        result = self.original_pack(*args, **kwargs)
        immediate = c.get_errno()
        try:
            require(all(result.get(key) == value for key, value in EXPECTED.items()), "fixed archive identity mismatch")
        except Exception as error:
            self.error("archive-refusal", error)
            raise
        finally:
            c.set_errno(immediate)
        return result

    def start(self):
        owner = self
        def init(backend, *args, **kwargs):
            return owner.attach(backend, *args, **kwargs)
        try:
            if self.selection is not None:
                original_environment = self.contextual.tool_environment
                original_resolve = self.contextual.resolve_command

                def environment(*args, **kwargs):
                    metadata(self.selection.validate, active=True)
                    result = original_environment(*args, **kwargs)
                    metadata(self.selection.environment, result)
                    return result

                def resolve(argv, *args, **kwargs):
                    metadata(self.selection.validate, active=True)
                    result = original_resolve(argv, *args, **kwargs)
                    metadata(self.selection.resolved, argv[0], result)
                    require(result[1:] == list(argv)[1:], "command arguments changed")
                    return result

                self.patches.enter_context(patch.object(self.contextual, "tool_environment", environment))
                self.patches.enter_context(patch.object(self.contextual, "resolve_command", resolve))
            self.patches.enter_context(patch.object(self.backend_type, "__init__", init))
            self.patches.enter_context(patch.object(self.contextual, "run", self.run))
            self.patches.enter_context(patch.object(self.harness, "pack", self.pack))
        except BaseException:
            self.patches.close()
            raise

    def close(self):
        if self.active:
            self.error("detach-active-call")
            return
        for _association, observer in reversed(self.backends):
            try:
                observer.__exit__(None, None, None)
            except Exception as error:
                self.error("observer-detachment", error)
        try:
            self.patches.close()
        except Exception as error:
            self.error("wrapper-detachment", error)

    def persist_final(self, binding):
        try:
            value = self.document()
            binding["accepted"] = binding["accepted"] and value["observationComplete"] and not self.incomplete
            value["harness"] = binding
            atomic(self.destination / "final.json", value)
        except Exception as error:
            self.error("final-persistence", error)
            binding["accepted"] = False
            print(json.dumps({"accepted": False, "evidencePersistenceFailed": True, "diagnostic": self.document()}, sort_keys=True))


def harness_evidence(check):
    from aepm.io import load
    from aepm.model import digest, sha256
    from aepm.supervision import validate_log_index

    result_path = check / "focused-result.json"
    ordinary(result_path)
    focused = load(result_path)
    require(focused["ref"]["digest"] == EXPECTED["digest"], "retained archive mismatch")
    suite = focused["result"]
    require(suite["package"] == EXPECTED["digest"] and suite["id"] == "android-media", "selected result mismatch")
    logs = check / "focused-evidence/logs"
    sha256(suite["logDigest"], "selected log digest")
    index = logs / (suite["logDigest"] + ".json")
    ordinary(index)
    raw = index.read_bytes()
    require(digest(raw) == suite["logDigest"], "index drift")
    events = json.loads(raw)
    validate_log_index(suite, events, logs)
    for event in events:
        if "logDigest" in event:
            sha256(event["logDigest"], "step log digest")
            require(sha(logs / (event["logDigest"] + ".log")) == event["logDigest"], "step blob drift")
    return {"resultDigest": sha(result_path), "indexDigest": suite["logDigest"], "contextDigest": CONTEXT_DIGEST,
            "harnessAccepted": focused["accepted"] is True}


def main(inventory_path, inventory_digest, out):
    inventory = inventory_check(inventory_path, inventory_digest, out)
    root = inventory_path.parent
    require(Path(__file__).resolve() == root / "installer/tests/run_android_discovery_fixture.py", "frozen entrypoint required")
    require(sha(root / "installer/tests/run_android_component_fixture.py") == HARNESS_DIGEST
            and sha(root / "installer/tests/discovery_observer.py") == OBSERVER_DIGEST, "reviewed harness/observer required")
    selection = PythonSelection(inventory, json.loads((root / "android-context.json").read_bytes()))
    with selection.scoped():
        return execute_bound(inventory_path, inventory_digest, out, selection)


def execute_bound(inventory_path, inventory_digest, out, selection):
    root = inventory_path.parent
    from aepm import contextual
    from aepm.environment import validate_resource
    from aepm.private_process import DarwinBackend
    from aepm.supervision import Recorder
    from tests import run_android_component_fixture as harness
    from tests.discovery_observer import DiscoveryObserver

    out.mkdir(mode=0o700)
    observer_root = out / "observer"
    observer_root.mkdir(mode=0o700)
    check = out / "check"
    observer = AndroidObserver(harness, contextual, DarwinBackend, Recorder, DiscoveryObserver, observer_root, inventory_digest, selection)
    binding = {"accepted": False, "returned": None, "expectedArchiveDigest": EXPECTED["digest"]}
    started = False
    try:
        context = workload_inputs(root, check)
        observer.start()
        started = True
        binding["returned"] = harness.check(root / "android", root / "android-context.json", check)
        inventory_check(inventory_path, inventory_digest, out, fresh=False)
        selection.validate(active=True)
        for resource in context["resources"]:
            validate_resource(resource)
        binding["postflightPassed"] = True
    except BaseException as error:
        observer.error("harness-or-validation", error)
    finally:
        if started:
            observer.close()
        try:
            binding.update(harness_evidence(check))
        except Exception as error:
            observer.error("normal-evidence", error)
        binding["accepted"] = (binding["returned"] == 0 and binding.get("harnessAccepted") is True
                               and binding.get("postflightPassed") is True and not observer.incomplete and observer.active == 0)
        observer.persist_final(binding)
    return 0 if binding["accepted"] and not observer.incomplete else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--inventory-digest", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(main(args.inventory, args.inventory_digest, args.out))
