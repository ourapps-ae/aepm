"""Diagnostic-only observation of existing Darwin discovery calls."""

from contextlib import ExitStack
from copy import deepcopy
import ctypes as c
import threading
from unittest.mock import patch

from aepm.model import AepmError, canonical
from aepm.private_process import CombinedInfo


LOCATIONS = frozenset("private-process-discovery private-process-identity private-process-path private-process-directory".split())


class DiscoveryObserver:
    def __init__(self, backend):
        self.backend = backend
        self.local = threading.local()
        self.lock = threading.Lock()
        self.first_failure = None
        self.unavailable = False
        self.counts = {"captureCalls": 0, "nestedCaptures": 0, "captureMissing": 0,
                       "captureFailures": 0, "listCalls": 0, "listFailures": 0}
        self.counts_capped = False

    def increment(self, name):
        with self.lock:
            if self.counts[name] < 2147483647:
                self.counts[name] += 1
            else:
                self.counts_capped = True

    def safe(self, operation, *args):
        saved = c.get_errno()
        try:
            operation(*args)
        except Exception:
            self.unavailable = True
            stack = getattr(self.local, "stack", [])
            if stack:
                stack[-1]["root"]["unavailable"] = True
        finally:
            c.set_errno(saved)

    def active(self):
        stack = getattr(self.local, "stack", [])
        return stack[-1] if stack else None

    def record(self, stage, args, result, error_number, raised):
        active = self.active()
        if active is None:
            return
        root, depth = active["root"], active["depth"]
        item = {"stage": stage, "attempt": root["attempts"], "confirmation": depth > 0,
                "result": result if type(result) is int and -9223372036854775808 <= result <= 9223372036854775807 else None,
                "error": error_number, "raised": None if raised is None else
                "AepmError" if isinstance(raised, AepmError) else "OSError" if isinstance(raised, OSError) else "other"}
        if stage == "list":
            capacity = args[3]
            item.update(capacity=capacity, integerWidth=c.sizeof(c.c_int))
            item["category"] = ("exception" if raised is not None else "nonpositive" if result <= 0 else
                                "capacity" if result >= capacity else "misaligned" if result % c.sizeof(c.c_int) else "valid")
        elif stage == "identity":
            if depth == 0:
                root["attempts"] += 1
                root["currentIdentity"] = None
            item["attempt"] = root["attempts"]
            item["stage"] = "confirmation" if depth else "identity"
            if result == c.sizeof(CombinedInfo):
                data = c.cast(args[3], c.POINTER(CombinedInfo)).contents
                current = (int(data.unique.unique), int(data.unique.generation))
                item["status"] = int(data.basic.status)
                if depth:
                    previous = root["currentIdentity"]
                    item["identityChanged"] = None if previous is None else current[0] != previous[0]
                    item["generationChanged"] = None if previous is None else current[1] != previous[1]
                else:
                    root["currentIdentity"] = current
        if len(root["stages"]) < 12 and root["attempts"] <= 3:
            root["stages"].append(item)
        else:
            root["truncated"] = True

    def binding(self, stage, original):
        def forwarded(*args, **kwargs):
            try:
                result = original(*args, **kwargs)
            except BaseException as error:
                immediate = c.get_errno()
                try:
                    self.safe(self.record, stage, args, None, immediate, error)
                finally:
                    c.set_errno(immediate)
                raise
            immediate = c.get_errno()
            try:
                self.safe(self.record, stage, args, result, immediate, None)
            finally:
                c.set_errno(immediate)
            return result
        return forwarded

    def failed(self, root, error, depth):
        root["failureDepth"] = root.get("failureDepth", depth)
        if depth:
            return
        location = getattr(error, "path", "redacted")
        document = {"operation": root["operation"], "candidate": "unclassified",
                    "attempts": min(root["attempts"], 3), "failureDepth": root["failureDepth"],
                    "stages": deepcopy(root["stages"]), "truncated": root["truncated"],
                    "unavailable": root["unavailable"],
                    "exception": "AepmError" if isinstance(error, AepmError) else "OSError" if isinstance(error, OSError) else "other",
                    "location": location if isinstance(location, str) and location in LOCATIONS else "redacted"}
        if len(canonical(document)) > 7168:
            document.update(stages=[], truncated=True, unavailable=True)
        with self.lock:
            if self.first_failure is None:
                self.first_failure = document

    def invocation(self, operation, original):
        def forwarded(*args, **kwargs):
            entry_error = c.get_errno()
            stack = getattr(self.local, "stack", None)
            if stack is None:
                stack = self.local.stack = []
            depth = len(stack)
            root = stack[-1]["root"] if stack else {"operation": operation, "attempts": 0, "stages": [],
                                                   "currentIdentity": None, "truncated": False, "unavailable": False}
            stack.append({"root": root, "depth": depth})
            self.safe(self.increment, "listCalls" if operation == "list" else "captureCalls")
            if depth:
                self.safe(self.increment, "nestedCaptures")
            c.set_errno(entry_error)
            try:
                result = original(*args, **kwargs)
            except BaseException as error:
                immediate = c.get_errno()
                try:
                    self.safe(self.increment, "listFailures" if operation == "list" else "captureFailures")
                    self.safe(self.failed, root, error, depth)
                finally:
                    stack.pop()
                    c.set_errno(immediate)
                raise
            immediate = c.get_errno()
            try:
                if operation == "capture" and result is None:
                    self.safe(self.increment, "captureMissing")
            finally:
                stack.pop()
                c.set_errno(immediate)
            return result
        return forwarded

    def __enter__(self):
        self.patches = ExitStack()
        try:
            for name, stage in (("info", "identity"), ("path", "executable-path"),
                                ("extended", "working-directory"), ("listing", "list")):
                self.patches.enter_context(patch.object(self.backend, name, self.binding(stage, getattr(self.backend, name))))
            for name, operation in (("capture", "capture"), ("pids", "list")):
                self.patches.enter_context(patch.object(self.backend, name, self.invocation(operation, getattr(self.backend, name))))
        except BaseException:
            self.patches.close()
            raise
        return self

    def __exit__(self, *error):
        return self.patches.__exit__(*error)

    def document(self):
        with self.lock:
            result = {"format": 1, "kind": "darwin-discovery-diagnostic", "completeProof": False,
                      "firstFailure": deepcopy(self.first_failure), "counts": dict(self.counts),
                      "countsCapped": self.counts_capped, "unavailable": self.unavailable}
        if len(canonical(result)) > 8192:
            result.update(firstFailure=None, unavailable=True)
        return result
