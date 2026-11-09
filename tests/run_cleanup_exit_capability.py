"""Bounded, owned-child observation of Darwin exited-process queries."""

import argparse
import ctypes as c
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time


CHILD = r'''
import json, os, sys, time
from pathlib import Path
root = Path(sys.argv[1])
deadline = time.monotonic() + 10
temporary = root / "ready.tmp"
temporary.write_text(json.dumps({"pid": os.getpid(), "at": time.monotonic()}))
temporary.replace(root / "ready.json")
while not (root / "release").exists() and time.monotonic() < deadline:
    time.sleep(.01)
'''

HELPER = r'''
import ctypes as c
import json, os, subprocess, sys, time
from pathlib import Path
from aepm.private_process import CombinedInfo
from tests.run_cleanup_exit_capability import WaitObservation
root = Path(sys.argv[1])
deadline = time.monotonic() + 20
child = None
observer = WaitObservation()
def save(name, value):
    temporary = root / (name + ".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(root / (name + ".json"))
def observe():
    while time.monotonic() < deadline:
        value = observer.poll(child.pid)
        if value is not None:
            return value
        time.sleep(.01)
    raise TimeoutError("helper exit observation")
try:
    child = subprocess.Popen([sys.executable, "-c", sys.argv[2], str(root)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    library = c.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    info = library.proc_pidinfo
    info.argtypes = [c.c_int, c.c_int, c.c_uint64, c.c_void_p, c.c_int]
    info.restype = c.c_int
    data = CombinedInfo()
    c.set_errno(0)
    size = info(child.pid, 18, 1, c.byref(data), c.sizeof(data))
    error = c.get_errno()
    save("helper-query", {"pid": child.pid, "argument": 1, "length": size,
                          "error": error, "at": time.monotonic()})
    if size != 192 or error or data.basic.pid != child.pid or data.basic.uid != os.geteuid():
        raise RuntimeError("helper identity capture failed")
    save("created", {"pid": child.pid, "parent": os.getpid(), "at": time.monotonic(),
                     "uid": data.basic.uid,
                     "identity": data.unique.unique,
                     "generation": data.unique.generation & 0xffffffff,
                     "length": size, "error": error, "status": data.basic.status})
    save("exited", observe())
    while not (root / "reap-release").exists() and time.monotonic() < deadline:
        time.sleep(.01)
finally:
    (root / "release").touch()
    if child is not None:
        while time.monotonic() < deadline:
            pid, status = os.waitpid(child.pid, os.WNOHANG)
            if pid:
                child.returncode = os.waitstatus_to_exitcode(status)
                save("reaped", {"pid": pid, "status": child.returncode,
                                "at": time.monotonic()})
                break
            time.sleep(.01)
        else:
            save("helper-failure", {"error": "child join deadline", "at": time.monotonic()})
'''


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("controller deadline")
    return value


def pause(deadline):
    time.sleep(min(.01, remaining(deadline)))


def read_when_ready(path, deadline):
    while not path.exists():
        pause(deadline)
    remaining(deadline)
    return json.loads(path.read_text())


class WaitObservation:
    def __init__(self):
        from aepm.posix_process import DarwinSignalAction, DarwinSignalInfo

        require(c.sizeof(DarwinSignalInfo) == 104, "wait record layout")
        self.record = DarwinSignalInfo
        self.library = c.CDLL(None, use_errno=True)
        self.waitid = self.library.waitid
        self.waitid.argtypes = [c.c_int, c.c_uint32, c.POINTER(DarwinSignalInfo), c.c_int]
        self.waitid.restype = c.c_int
        self.action = self.library.sigaction
        self.action.argtypes = [c.c_int, c.c_void_p, c.c_void_p]
        self.action.restype = c.c_int
        action = DarwinSignalAction()
        require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
                and self.action(signal.SIGCHLD, None, c.byref(action)) == 0
                and not action.handler and not action.flags & 0x20, "child reaping disposition")

    def poll(self, pid):
        data = self.record()
        c.set_errno(0)
        value = self.waitid(1, pid, c.byref(data), 0x25)
        error = c.get_errno()
        if value != 0 and error == errno.EINTR:
            return None
        require(value == 0, "non-reaping wait failed: " + str(error))
        if data.pid == 0:
            return None
        require(data.pid == pid, "wait identity mismatch")
        return {"pid": data.pid, "code": data.code, "status": data.status,
                "length": c.sizeof(data), "result": value, "error": error,
                "at": time.monotonic()}


def observe(child, deadline, observer):
    while True:
        remaining(deadline)
        value = observer.poll(child.pid)
        if value is not None:
            return value
        pause(deadline)


class Queries:
    def __init__(self):
        from aepm.private_process import CombinedInfo, UniqueInfo

        require(sys.platform == "darwin", "Darwin required")
        require(c.sizeof(CombinedInfo) == 192 and c.sizeof(UniqueInfo) == 56, "record layout")
        self.record = CombinedInfo
        self.library = c.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.direct = self.library.proc_pidinfo
        self.direct.argtypes = [c.c_int, c.c_int, c.c_uint64, c.c_void_p, c.c_int]
        self.direct.restype = c.c_int
        self.extended = getattr(self.library, "__proc_info_extended_id")
        self.extended.argtypes = [c.c_int32, c.c_int32, c.c_uint32, c.c_uint32,
                                 c.c_uint64, c.c_uint64, c.c_void_p, c.c_int32]
        self.extended.restype = c.c_int

    def query(self, pid, argument, identity, events, phase):
        data = self.record()
        c.set_errno(0)
        started = time.monotonic()
        if identity is None:
            size = self.direct(pid, 18, argument, c.byref(data), c.sizeof(data))
        else:
            size = self.extended(2, pid, 18, 2, identity, argument, c.byref(data), c.sizeof(data))
        error = c.get_errno()
        event = {"phase": phase, "pid": pid, "argument": argument, "boundIdentity": identity,
                 "started": started, "at": time.monotonic(), "length": size, "error": error}
        if size == c.sizeof(data):
            event["record"] = {"pid": data.basic.pid, "uid": data.basic.uid,
                               "identity": data.unique.unique,
                               "generation": data.unique.generation & 0xffffffff,
                               "status": data.basic.status}
        events.append(event)
        return event


def complete(event, pid, expected=None, exited=False):
    record = event.get("record")
    require(event["length"] == 192 and event["error"] == 0 and record is not None,
            "incomplete or failed identity query")
    require(record["pid"] == pid and record["uid"] == os.geteuid(), "process or user mismatch")
    require(record["identity"] > 0, "missing unique identity")
    require(record["status"] == 5 if exited else record["status"] in (1, 2, 3, 4),
            "unexpected process status")
    if expected is not None:
        for key in ("pid", "uid", "identity", "generation"):
            require(record[key] == expected[key], "identity or generation changed")
    return record


def missing(event, extended):
    require(event["length"] == (-1 if extended else 0) and event["error"] == errno.ESRCH
            and "record" not in event, "unexpected missing-process result")


def run_case(root, separate, queries, observer, overall):
    started = time.monotonic()
    deadline = min(overall, started + 25)
    root.mkdir(mode=0o700)
    events = []
    result = {"started": started, "events": events, "success": False, "joined": False}
    parent = None
    try:
        command = [sys.executable, "-c", HELPER, str(root), CHILD] if separate else [
            sys.executable, "-c", CHILD, str(root)]
        parent = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result["createdParent"] = {"pid": parent.pid, "at": time.monotonic()}
        ready = read_when_ready(root / "ready.json", deadline)
        result["ready"] = ready
        pid = ready["pid"]
        created = read_when_ready(root / "created.json", deadline) if separate else {"pid": parent.pid}
        result["created"] = created
        require(pid == created["pid"], "child readiness mismatch")
        base_identity = created["identity"] if separate else None
        first = complete(queries.query(pid, 0, base_identity, events, "live"), pid)
        if separate:
            require(first["identity"] == created["identity"]
                    and first["generation"] == created["generation"], "helper identity mismatch")
        for argument in (0, 1):
            remaining(deadline)
            complete(queries.query(pid, argument, base_identity, events, "live"), pid, first)
            complete(queries.query(pid, argument, first["identity"], events, "live-bound"), pid, first)
        result["released"] = time.monotonic()
        (root / "release").touch()
        exited = read_when_ready(root / "exited.json", deadline) if separate else observe(parent, deadline, observer)
        result["exited"] = exited
        require(exited["pid"] == pid and exited["code"] == 1
                and exited["status"] == 0, "exit was not confirmed successful")
        for argument in (0, 1):
            remaining(deadline)
            for identity in dict.fromkeys((base_identity, first["identity"])):
                event = queries.query(pid, argument, identity, events, "unreaped")
                if argument == 0:
                    missing(event, identity is not None)
                else:
                    complete(event, pid, first, exited=True)
        result["unreapedQueriesFinished"] = time.monotonic()
        if separate:
            (root / "reap-release").touch()
            reaped = read_when_ready(root / "reaped.json", deadline)
        else:
            code = parent.wait(timeout=remaining(deadline))
            reaped = {"pid": pid, "status": code, "at": time.monotonic()}
        result["reaped"] = reaped
        require(reaped["pid"] == pid and reaped["status"] == 0
                and reaped["at"] > result["unreapedQueriesFinished"], "premature or failed reap")
        for argument in (0, 1):
            remaining(deadline)
            missing(queries.query(pid, argument, first["identity"], events, "reaped"), True)
        result["success"] = True
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        (root / "release").touch()
        (root / "reap-release").touch()
        if parent is not None:
            try:
                code = parent.wait(timeout=remaining(deadline))
                result["joined"] = True
                result["parentExitCode"] = code
                require(code == 0, "fixture parent failed")
                if separate:
                    reaped = read_when_ready(root / "reaped.json", deadline)
                    result["finalChildReap"] = reaped
                    require(reaped["pid"] == result.get("created", {}).get("pid")
                            and reaped["status"] == 0, "helper child join unconfirmed")
            except Exception as error:
                result["success"] = False
                result["joinFailure"] = type(error).__name__ + ": " + str(error)
        result["seconds"] = time.monotonic() - started
        result["success"] = result["success"] and result["seconds"] <= 25
        write(root / "trace.json", result)
    return result


def hashes():
    source = Path(__file__).resolve().parents[1] / "aepm"
    return {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
            for name in ("process.py", "posix_process.py", "private_process.py")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    allowed = Path("/private/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode").resolve()
    require(args.out.is_absolute() and args.out.parent.resolve() == allowed, "unapproved output parent")
    args.out.mkdir(mode=0o700)
    summary = {"host": platform.uname()._asdict(), "cases": [], "success": False,
               "scriptDigest": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "sourceBefore": hashes()}
    try:
        queries = Queries()
        observer = WaitObservation()
        for name, separate in (("direct", False), ("separate-parent", True)):
            remaining(started + 60)
            result = run_case(args.out / name, separate, queries, observer, started + 60)
            summary["cases"].append(result)
            if not result["success"]:
                break
        summary["success"] = len(summary["cases"]) == 2 and all(
            item["success"] for item in summary["cases"])
    except Exception as error:
        summary["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        summary["sourceAfter"] = hashes()
        summary["sourceUnchanged"] = summary["sourceBefore"] == summary["sourceAfter"]
        summary["seconds"] = time.monotonic() - started
        summary["success"] = summary["success"] and summary["sourceUnchanged"] and summary["seconds"] <= 60
        write(args.out / "summary.json", summary)
    print(json.dumps({"success": summary["success"], "output": str(args.out)}))
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
