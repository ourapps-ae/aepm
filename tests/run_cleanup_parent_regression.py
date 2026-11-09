"""Bounded production-runner regression with separate supervising parents."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from unittest.mock import patch

from aepm.contextual import tool_environment
from aepm.io import VerificationDirectory
from aepm.private_process import DarwinBackend
from aepm.process import run
from tests.run_cleanup_concurrency import CHILD, Trace
from tests.run_cleanup_exit_capability import hashes, remaining, require, write


def worker(directory, sentinel):
    started = time.monotonic()
    result = {"success": False}
    workspace = VerificationDirectory(prefix="cleanup-parent-regression-")
    workspace.preserve = True
    root = workspace.path
    write(directory / "root.json", {"root": str(root)})
    trace = Trace({"child": root})
    signals = []
    original = DarwinBackend.terminate

    def terminate(backend, record, number):
        signals.append({"pid": record.pid, "identity": record.key, "signal": number})
        return original(backend, record, number)

    def execute():
        try:
            code, seconds, reason, output = run(
                [sys.executable, "-I", "-S", "-c", CHILD], root,
                tool_environment(root / "home", {}, []), 20)
            (directory / "output.log").write_bytes(output)
            result.update(exitCode=code, reason=reason, seconds=seconds)
            result["success"] = code == 0 and not reason
        except Exception as error:
            result["failure"] = repr(error)

    with ExitStack() as stack:
        for observer in trace.install():
            stack.enter_context(observer)
        stack.enter_context(patch.object(DarwinBackend, "terminate", terminate))
        thread = threading.Thread(target=execute, daemon=True)
        thread.start()
        thread.join(timeout=max(0, started + 35 - time.monotonic()))
        result["joined"] = not thread.is_alive()
        if thread.is_alive():
            (root / "release").touch()
    result.update(root=str(root), events=trace.events, signals=signals, traceTruncated=trace.truncated)
    cleanup = [e for e in trace.events if e["event"] == "cleanup-return"]
    reaps = [e for e in trace.events if e["event"] == "reap-enter"]
    result["success"] = (result["success"] and result["joined"] and not trace.truncated
                         and len(cleanup) == 1 and cleanup[0]["result"]
                         and len(reaps) == 1 and cleanup[0]["at"] <= reaps[0]["at"]
                         and reaps[0]["signalingFinished"]
                         and not any(e["pid"] == sentinel for e in signals))
    write(directory / "result.json", result)
    return 0 if result["success"] else 1


def controller(out):
    started = time.monotonic()
    deadline = started + 40
    require(sys.platform == "darwin", "Darwin required")
    allowed = Path("/private/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode").resolve()
    require(out.is_absolute() and out.parent.resolve() == allowed, "unapproved output parent")
    out.mkdir(mode=0o700)
    summary = {"success": False, "sourceBefore": hashes(), "results": []}
    parents, roots = [], []
    sentinel = None
    try:
        sentinel_root = out / "sentinel"
        sentinel_root.mkdir(mode=0o700)
        sentinel = subprocess.Popen([sys.executable, "-I", "-S", "-c", CHILD], cwd=sentinel_root,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        backend = DarwinBackend()
        identity = backend.capture(sentinel.pid, paths=False)
        require(identity is not None, "sentinel identity missing")
        summary["sentinel"] = {"pid": identity.pid, "identity": identity.key,
                               "generation": identity.generation}
        for name in ("A", "B"):
            directory = out / name
            directory.mkdir(mode=0o700)
            parents.append(subprocess.Popen(
                [sys.executable, "-m", "tests.run_cleanup_parent_regression", "--worker", str(directory),
                 "--sentinel", str(sentinel.pid)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for name in ("A", "B"):
            path = out / name / "root.json"
            while not path.exists():
                time.sleep(min(.01, remaining(deadline)))
            root = Path(json.loads(path.read_text())["root"])
            roots.append(root)
            while not (root / "ready.json").exists():
                time.sleep(min(.01, remaining(deadline)))
        summary["release"] = time.monotonic()
        for root in roots:
            (root / "release").touch()
        for parent in parents:
            require(parent.wait(timeout=remaining(deadline)) == 0, "runner parent failed")
        for name in ("A", "B"):
            result = json.loads((out / name / "result.json").read_text())
            summary["results"].append(result)
            require(result["success"], "production cleanup regression failed")
        current = backend.capture(sentinel.pid, paths=False)
        require(current is not None and current.key == identity.key
                and current.generation == identity.generation and current.status != 5,
                "unrelated sentinel changed or exited")
        summary["sentinelPreserved"] = True
        summary["success"] = True
    except Exception as error:
        summary["failure"] = repr(error)
    finally:
        for name in ("A", "B"):
            path = out / name / "root.json"
            if path.exists():
                root = Path(json.loads(path.read_text())["root"])
                (root / "release").touch()
        if sentinel is not None:
            (out / "sentinel" / "release").touch()
        summary["joins"] = []
        for process in parents + ([sentinel] if sentinel is not None else []):
            try:
                code = process.wait(timeout=remaining(deadline))
                summary["joins"].append({"pid": process.pid, "code": code})
                require(code == 0, "owned process failed")
            except Exception as error:
                summary["success"] = False
                summary["joins"].append({"pid": process.pid, "failure": repr(error)})
        summary["sourceAfter"] = hashes()
        summary["seconds"] = time.monotonic() - started
        summary["success"] = (summary["success"] and summary["seconds"] <= 40
                              and summary["sourceBefore"] == summary["sourceAfter"])
        write(out / "summary.json", summary)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--sentinel", type=int)
    arguments = parser.parse_args()
    if arguments.worker is not None:
        raise SystemExit(worker(arguments.worker, arguments.sentinel))
    require(arguments.out is not None, "output required")
    raise SystemExit(controller(arguments.out))
