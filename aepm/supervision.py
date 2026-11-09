"""Bounded supervisor observations and versioned diagnostic log validation."""

from copy import deepcopy
from collections.abc import Mapping
import json
from pathlib import Path
import re
import threading
import time

from .bundle import ordinary_path
from .model import AepmError, EXECUTION_REASONS, canonical, digest


PHASES = frozenset("startup sample exit-observation limit group-cleanup private-scan private-refresh private-signal reap reader-join return".split())
KINDS = frozenset("natural-exit timeout output-limit exception cleanup-deadline cleanup-incomplete reader-incomplete startup-failure".split())
LOCATIONS = frozenset(("private-process-identity private-process-path private-process-directory private-process-discovery "
                      "private-process-signal private-process-user private-process-layout private-process-capability "
                      "private-process-root private-process-conflict private-process-baseline-generation private-process-limit "
                      "private-process-enrollment private-process-baseline-age private-process-baseline-limit "
                      "child-ownership child-signal-disposition process-observer group-census redacted").split())
OUTCOME_KEYS = {"exitCode", "reason", "cleanupAttempted", "cleanupCompleted", "readersJoined",
                "privateFailed", "privateUnresolved", "privateLiveCount"}


def reject():
    raise AepmError("result-invalid", "verification")


def require(condition):
    if not condition:
        reject()


def integer(value, low=0, high=9223372036854775807):
    return type(value) is int and low <= value <= high


def code(value):
    return value is None or integer(value, -2147483648, 2147483647)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected))


def sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def supervision_step_index(step: object) -> int | None:
    if not isinstance(step, str) or not step.startswith("supervisor-"):
        return None
    match = re.fullmatch(r"supervisor-v1/(0|[1-9][0-9]{0,18})", step)
    if not match:
        reject()
    value = int(match[1])
    require(integer(value))
    return value


def observation(value, first=False):
    keys(value, {"phase", "atMicros", "kind", "exitCode", "error"})
    require(value["phase"] in PHASES and integer(value["atMicros"]))
    require(value["kind"] in KINDS and code(value["exitCode"]))
    if value["kind"] == "natural-exit":
        require(not first and type(value["exitCode"]) is int)
    error = value["error"]
    if error is not None:
        keys(error, {"class", "code", "location", "number"})
        require(error["class"] in ("AepmError", "OSError", "RuntimeError", "other"))
        require(error["code"] in EXECUTION_REASONS or error["code"] == "other")
        require(error["location"] in LOCATIONS and code(error["number"]))


DOCUMENT_KEYS = frozenset({"format", "kind", "package", "suiteIdDigest", "step", "preparation", "executionStop",
                           "firstFailure", "finalOutcome", "events", "truncated", "recorderFailed"})
ADOPTION_KEYS = frozenset({"uniqueIdentity", "generation", "executableRelative", "windowIndex"})
MAX_ADOPTIONS = 8


def adoption_entry(value):
    keys(value, ADOPTION_KEYS)
    require(integer(value["uniqueIdentity"], high=18446744073709551615) and integer(value["generation"], high=4294967295))
    require(integer(value["windowIndex"], high=4095))
    relative = value["executableRelative"]
    require(isinstance(relative, str) and 0 < len(relative.encode()) <= 256 and not relative.startswith("/")
            and "\\" not in relative and "\x00" not in relative
            and all(part not in ("", ".", "..") for part in relative.split("/")))


def validate_document(document, suite, event, number):
    require(type(document) is dict and DOCUMENT_KEYS <= set(document) <= DOCUMENT_KEYS | {"adoptions"})
    if "adoptions" in document:
        require(type(document["adoptions"]) is list and 0 < len(document["adoptions"]) <= MAX_ADOPTIONS)
        for entry in document["adoptions"]:
            adoption_entry(entry)
    require(type(document["format"]) is int and document["format"] == 1)
    require(document["kind"] == "aepm-supervision" and sha(document["package"]))
    require(len(canonical(document)) <= 32768)
    require(len(canonical({key: value for key, value in document.items()
                           if key not in ("executionStop", "firstFailure", "finalOutcome", "events")})) <= 4096)
    require(document["package"] == suite["package"] and document["suiteIdDigest"] == digest(canonical(suite["id"])))
    require(integer(document["step"]) and document["step"] == number)
    require(type(document["preparation"]) is bool and document["preparation"] == event["preparation"])
    for name in ("executionStop", "firstFailure"):
        slot = document[name]
        keys(slot, {"state", "observation"})
        require(slot["state"] in ("observed", "not-observed", "unavailable"))
        require(len(canonical(slot)) <= 1024)
        if slot["state"] == "observed":
            observation(slot["observation"], name == "firstFailure")
        else:
            require(slot["observation"] is None)
    slot = document["finalOutcome"]
    keys(slot, {"state", "outcome"})
    require(slot["state"] in ("observed", "unavailable") and len(canonical(slot)) <= 1024)
    if slot["state"] == "observed":
        outcome = slot["outcome"]
        keys(outcome, OUTCOME_KEYS)
        require(code(outcome["exitCode"]) and outcome["exitCode"] == event["exitCode"])
        require(isinstance(outcome["reason"], str) and len(outcome["reason"].encode()) <= 128
                and outcome["reason"] == event["reason"])
        for name in OUTCOME_KEYS - {"exitCode", "reason", "privateLiveCount"}:
            require(outcome[name] is None or type(outcome[name]) is bool)
        require(outcome["privateLiveCount"] is None or integer(outcome["privateLiveCount"], high=8192))
    else:
        require(slot["outcome"] is None)
    require(type(document["truncated"]) is bool and type(document["recorderFailed"]) is bool)
    require(type(document["events"]) is list and len(document["events"]) <= 64)
    for transition in document["events"]:
        keys(transition, {"phase", "atMicros", "action", "outcome", "target"})
        require(len(canonical(transition)) <= 384)
        require(transition["phase"] in PHASES and integer(transition["atMicros"]))
        require(transition["action"] in ("enter", "signal", "return", "failure"))
        require(transition["outcome"] in ("attempted", "succeeded", "failed", "unavailable"))
        target = transition["target"]
        if target is not None:
            keys(target, {"kind", "number", "uniqueIdentity", "generation"})
            require(target["kind"] in ("reserved-group", "owned-process") and integer(target["number"], 1, 2147483647))
            require(target["uniqueIdentity"] is None or integer(target["uniqueIdentity"], high=18446744073709551615))
            require(target["generation"] is None or integer(target["generation"], high=4294967295))
            if target["kind"] == "reserved-group":
                require(target["uniqueIdentity"] is None and target["generation"] is None)


def validate_log_index(suite: Mapping[str, object], events: list[dict[str, object]], logs_root: Path) -> tuple[Path, ...]:
    try:
        require(sha(suite["package"]) and isinstance(suite["id"], str))
        require(type(events) is list)
        root = Path(logs_root)
        ordinary_path(root)
        require(root.is_dir())
        commands, diagnostics = {}, []
        tail = False
        for event in events:
            require(type(event) is dict and "step" in event)
            number = supervision_step_index(event["step"])
            if number is None:
                require(not tail)
                if type(event["step"]) is int:
                    require(integer(event["step"]))
                    commands.setdefault(event["step"], []).append(event)
                continue
            tail = True
            diagnostics.append((number, event))
        require([number for number, _ in diagnostics] == sorted({number for number, _ in diagnostics}))
        paths, seen = [], set()
        for number, event in diagnostics:
            keys(event, {"step", "preparation", "seconds", "exitCode", "reason", "logDigest"})
            require(type(event["preparation"]) is bool and type(event["seconds"]) is int and event["seconds"] == 0)
            require(code(event["exitCode"]) and isinstance(event["reason"], str) and sha(event["logDigest"]))
            require(len(commands.get(number, [])) == 1)
            command = commands[number][0]
            require(type(command["preparation"]) is bool and code(command["exitCode"]))
            require(all(event[name] == command[name] for name in ("preparation", "exitCode", "reason")))
            path = root / (event["logDigest"] + ".log")
            ordinary_path(path)
            info = path.stat()
            require(path.is_file() and info.st_nlink == 1 and info.st_size <= 32768)
            with path.open("rb") as stream:
                raw = stream.read(32769)
            require(len(raw) <= 32768 and digest(raw) == event["logDigest"])
            document = json.loads(raw)
            require(canonical(document) == raw)
            validate_document(document, suite, event, number)
            if event["logDigest"] not in seen:
                paths.append(path.absolute())
                seen.add(event["logDigest"])
        return tuple(paths)
    except (AepmError, OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        reject()


class Recorder:
    def __init__(self):
        self.started = time.monotonic()
        self.stop = {"state": "not-observed", "observation": None}
        self.failure = {"state": "not-observed", "observation": None}
        self.final = {"state": "unavailable", "outcome": None}
        self.events = []
        self.adoptions = []
        self.truncated = self.failed = False
        self.slot_lock = threading.Lock()

    def at(self):
        return max(0, min(9223372036854775807, int((time.monotonic() - self.started) * 1000000)))

    def note(self, slot, phase, kind, error=None, exit_code=None):
        with self.slot_lock:
            self._note(slot, phase, kind, error, exit_code)

    def _note(self, slot, phase, kind, error=None, exit_code=None):
        try:
            if slot["state"] == "observed":
                return
            detail = None
            if error is not None:
                location = getattr(error, "path", "redacted")
                error_code = getattr(error, "code", "")
                number = getattr(error, "errno", None)
                detail = {"class": "AepmError" if isinstance(error, AepmError) else "OSError" if isinstance(error, OSError)
                          else "RuntimeError" if isinstance(error, RuntimeError) else "other",
                          "code": error_code if isinstance(error_code, str) and error_code in EXECUTION_REASONS else "other",
                          "location": location if isinstance(location, str) and location in LOCATIONS else "redacted",
                          "number": number if code(number) else None}
            value = {"phase": phase, "atMicros": self.at(), "kind": kind, "exitCode": exit_code, "error": detail}
            observation(value, slot is self.failure)
            require(len(canonical(value)) + 64 <= 1024)
            slot.update(state="observed", observation=value)
        except Exception:
            self.failed = True
            if slot["state"] != "observed":
                slot.update(state="unavailable", observation=None)

    def stopped(self, phase, kind, error=None, exit_code=None):
        self.note(self.stop, phase, kind, error, exit_code)

    def fault(self, phase, kind="exception", error=None):
        self.note(self.failure, phase, kind, error)

    def event(self, phase, action, outcome, target=None):
        try:
            if len(self.events) >= 64:
                self.truncated = True
                return
            value = {"phase": phase, "atMicros": self.at(), "action": action, "outcome": outcome, "target": target}
            if len(canonical(value)) > 384:
                self.truncated = True
            else:
                self.events.append(value)
        except Exception:
            self.failed = True

    def adopted(self, unique_identity, generation, executable_relative, window_index):
        try:
            value = {"uniqueIdentity": unique_identity, "generation": generation,
                     "executableRelative": executable_relative, "windowIndex": window_index}
            adoption_entry(value)
            require(len(self.adoptions) < MAX_ADOPTIONS)
            self.adoptions.append(value)
        except Exception:
            self.failed = True

    def finish(self, exit_code, reason, attempted, completed, joined, scope=None):
        with self.slot_lock:
            if self.final["state"] == "observed":
                return
            self._finish(exit_code, reason, attempted, completed, joined, scope)

    def _finish(self, exit_code, reason, attempted, completed, joined, scope=None):
        try:
            require(code(exit_code) and isinstance(reason, str) and len(reason.encode()) <= 128)
            self.final = {"state": "observed", "outcome": {
                "exitCode": exit_code, "reason": reason, "cleanupAttempted": attempted,
                "cleanupCompleted": completed, "readersJoined": joined,
                "privateFailed": getattr(scope, "failed", None), "privateUnresolved": getattr(scope, "unresolved", None),
                "privateLiveCount": getattr(scope, "last_live_count", None)}}
        except Exception:
            self.failed = True

    def document(self, suite, step, preparation):
        result = {"format": 1, "kind": "aepm-supervision", "package": suite["package"],
                  "suiteIdDigest": digest(canonical(suite["id"])), "step": step, "preparation": preparation,
                  "executionStop": {"state": "unavailable", "observation": None},
                  "firstFailure": {"state": "unavailable", "observation": None},
                  "finalOutcome": {"state": "unavailable", "outcome": None},
                  "events": [], "truncated": self.truncated, "recorderFailed": self.failed}
        event = {"preparation": preparation, "exitCode": None, "reason": ""}
        for name, slot in (("executionStop", self.stop), ("firstFailure", self.failure), ("finalOutcome", self.final)):
            previous = result[name]
            try:
                result[name] = deepcopy(slot)
                if name == "finalOutcome" and slot["state"] == "observed":
                    event.update(exitCode=slot["outcome"]["exitCode"], reason=slot["outcome"]["reason"])
                validate_document(result, suite, event, step)
            except Exception:
                result[name] = previous
                result["recorderFailed"] = True
        try:
            result["events"] = deepcopy(self.events)
            validate_document(result, suite, event, step)
        except Exception:
            result.update(events=[], truncated=True, recorderFailed=True)
        if self.adoptions:
            try:
                result["adoptions"] = deepcopy(self.adoptions)
                validate_document(result, suite, event, step)
            except Exception:
                result.pop("adoptions", None)
                result["recorderFailed"] = True
        return result


def observe(recorder, method, *args, **kwargs):
    """Observation failure must not influence process control."""
    if recorder is not None:
        try:
            getattr(recorder, method)(*args, **kwargs)
        except Exception:
            try:
                recorder.failed = True
                name = {"stopped": "stop", "fault": "failure", "finish": "final"}.get(method)
                if name:
                    slot = getattr(recorder, name)
                    if slot["state"] != "observed":
                        slot.update(state="unavailable", **{"outcome" if name == "final" else "observation": None})
            except Exception:
                pass
