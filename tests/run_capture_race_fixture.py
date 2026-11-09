"""One bounded corrected-source capture-race run from a frozen installer copy; release required."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
from unittest.mock import patch


TEMP = Path("/private/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode")
COPY = TEMP / "capture-race-installer-03"
OUT = TEMP / "capture-race-03"
PYTHON = Path("/Users/george/.pyenv/versions/3.12.8/bin/python3.12")
TOTAL, START_MARGIN, CHURN_SECONDS, SENTINEL_SECONDS, MAX_RUNS, MAX_BACKENDS = 120, 30, 20, 100, 40, 128

CHURN = r'''
import json, os, sys, time
from pathlib import Path
out, deadline, spawned = Path(sys.argv[1]), time.monotonic() + float(sys.argv[2]), 0
(out / "churn-ready.json").write_text(json.dumps({"pid": os.getpid(), "group": os.getpgrp()}))
while spawned < 5000 and time.monotonic() < deadline:
    child = os.posix_spawn("/usr/bin/true", ["/usr/bin/true"], {"PATH": "/usr/bin:/bin"})
    os.waitpid(child, 0)
    spawned += 1
(out / "churn-done.json").write_text(json.dumps({"spawned": spawned}))
'''

SENTINEL = r'''
import json, os, sys, time
from pathlib import Path
out, deadline = Path(sys.argv[1]), time.monotonic() + float(sys.argv[2])
(out / "sentinel-ready.json").write_text(json.dumps({"pid": os.getpid(), "group": os.getpgrp()}))
while not (out / "sentinel-release").exists() and time.monotonic() < deadline:
    time.sleep(.05)
'''


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def ordinary(path):
    for item in (path, *path.parents):
        require(not item.is_symlink(), "symbolic link refused")


def sha(path):
    ordinary(path)
    require(path.is_file(), "regular file required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory_check(expected_digest):
    path = COPY / "inventory.json"
    require(sha(path) == expected_digest, "inventory drift")
    value = json.loads(path.read_bytes())
    require(set(value) == {"format", "files", "directories", "python"} and value["format"] == 1, "inventory format")
    files = {entry["path"]: entry for entry in value["files"]}
    directories = {entry["path"]: entry for entry in value["directories"]}
    for name, entry in files.items():
        candidate = COPY / name
        require(sha(candidate) == entry["sha256"] and stat.S_IMODE(candidate.stat().st_mode) == entry["mode"], "file drift")
    for name, entry in directories.items():
        candidate = COPY / name
        ordinary(candidate)
        require(candidate.is_dir() and stat.S_IMODE(candidate.stat().st_mode) == entry["mode"], "directory drift")
    actual_files, actual_directories = set(), {"."}
    for folder, child_directories, child_files in os.walk(COPY, followlinks=False):
        for name in child_directories + child_files:
            candidate = Path(folder) / name
            ordinary(candidate)
            key = candidate.relative_to(COPY).as_posix()
            (actual_directories if candidate.is_dir() else actual_files).add(key)
    require(actual_files == set(files) | {"inventory.json"} and actual_directories == set(directories), "membership drift")
    python = value["python"]
    require(Path(sys.executable).resolve() == PYTHON == Path(python["path"]) and sys.version_info[:3] == (3, 12, 8)
            and python["version"] == "3.12.8" and sha(PYTHON) == python["sha256"]
            and stat.S_IMODE(PYTHON.stat().st_mode) == python["mode"], "interpreter drift")
    return value


def write(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def wait_file(path, deadline):
    while not path.exists():
        require(time.monotonic() < deadline, "fixture readiness deadline")
        time.sleep(.01)
    return json.loads(path.read_text())


def classify(document):
    failure = document.get("firstFailure")
    if not failure:
        return None
    stages = failure.get("stages", [])
    if failure["operation"] == "list":
        return "list-count-rejection"
    races = [item for item in stages if item["stage"] in ("executable-path", "working-directory") and item["error"] == 3
             or item["stage"] == "confirmation" and (item.get("identityChanged") or item.get("generationChanged"))]
    if failure["location"] == "private-process-discovery" and failure["attempts"] == 3 and races:
        return "capture-retry-exhaustion"
    return "other"


def succeeded(record):
    final = record.get("supervision", {}).get("finalOutcome", {})
    outcome = final.get("outcome") or {}
    return (record.get("joined") is True and not record.get("failure") and record.get("exitCode") == 0
            and record.get("reason") == "" and final.get("state") == "observed"
            and outcome.get("cleanupCompleted") is True and outcome.get("readersJoined") is True
            and outcome.get("privateFailed") is False)


def main(inventory_digest):
    started = time.monotonic()
    deadline = started + TOTAL
    require(sys.platform == "darwin", "Darwin required")
    require(Path.cwd().resolve() == COPY, "frozen copy working directory required")
    before = inventory_check(inventory_digest)
    ordinary(OUT)
    require(not OUT.exists() and OUT.parent.is_dir(), "occupied output")
    import aepm
    require(Path(aepm.__file__).resolve().is_relative_to(COPY), "frozen copy import required")
    from aepm.contextual import tool_environment
    from aepm.posix_process import ContainedProcess
    from aepm.private_process import DarwinBackend, enroll_root
    from aepm.process import run
    from aepm.supervision import Recorder
    from tests.discovery_observer import DiscoveryObserver

    OUT.mkdir(mode=0o700)
    unrelated = OUT / "unrelated"
    unrelated.mkdir(mode=0o700)
    runs_root = OUT / "runs"
    runs_root.mkdir(mode=0o700)
    summary = {"completeProof": False, "inventoryDigest": inventory_digest, "constructorChecksObserved": False,
               "exclusiveHostAssertedBy": "conductor release", "runs": [], "violations": [], "errors": []}
    observers, signals, leaders, current = [], [], {}, {"run": None}
    original_init, original_terminate, original_killpg = DarwinBackend.__init__, DarwinBackend.terminate, os.killpg
    original_contained = ContainedProcess.__init__

    def contained(process, *args, **kwargs):
        original_contained(process, *args, **kwargs)
        leaders.setdefault(current["run"], set()).add(process.pid)

    def attach(backend, *args, **kwargs):
        original_init(backend, *args, **kwargs)
        try:
            if len(observers) >= MAX_BACKENDS:
                summary["errors"].append("observer-cap")
                return
            observer = DiscoveryObserver(backend)
            observer.__enter__()
            observers.append((current["run"], observer))
        except Exception as error:
            summary["errors"].append("attachment:" + type(error).__name__)

    def terminate(backend, owned, number):
        signals.append({"run": current["run"], "kind": "owned-process", "pid": owned.pid,
                        "identity": owned.key, "group": owned.group, "signal": number,
                        "cwd": owned.cwd, "executable": owned.executable})
        return original_terminate(backend, owned, number)

    def killpg(group, number):
        signals.append({"run": current["run"], "kind": "reserved-group", "group": group, "signal": number})
        return original_killpg(group, number)

    churn = sentinel = None
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(unrelated), "TMPDIR": str(unrelated)}
    patches = [patch.object(DarwinBackend, "__init__", attach), patch.object(DarwinBackend, "terminate", terminate),
               patch("aepm.posix_process.os.killpg", killpg), patch.object(ContainedProcess, "__init__", contained)]
    for item in patches:
        item.start()
    worker = None
    try:
        sentinel = subprocess.Popen([str(PYTHON), "-I", "-S", "-c", SENTINEL, str(unrelated), str(SENTINEL_SECONDS)],
                                    cwd=unrelated, env=environment, start_new_session=True,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sentinel_info = wait_file(unrelated / "sentinel-ready.json", deadline)
        probe = DarwinBackend()
        sentinel_identity = probe.capture(sentinel.pid, paths=False)
        require(sentinel_identity is not None and sentinel_info["pid"] == sentinel.pid, "sentinel identity")
        summary["sentinel"] = {"pid": sentinel.pid, "group": sentinel_info["group"], "identity": sentinel_identity.key,
                               "generation": sentinel_identity.generation}
        churn = subprocess.Popen([str(PYTHON), "-I", "-S", "-c", CHURN, str(unrelated), str(CHURN_SECONDS)],
                                 cwd=unrelated, env=environment, start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        churn_info = wait_file(unrelated / "churn-ready.json", deadline)
        require(churn_info["pid"] == churn.pid, "churn identity")
        summary["churn"] = {"pid": churn.pid, "group": churn_info["group"]}
        foreign_groups = {churn_info["group"], sentinel_info["group"]}
        for index in range(MAX_RUNS):
            if churn.poll() is not None or deadline - time.monotonic() < START_MARGIN:
                break
            root = runs_root / ("%02d" % index)
            root.mkdir(mode=0o700)
            current["run"] = index
            record = {"run": index, "root": str(root)}
            summary["runs"].append(record)
            recorder = Recorder()
            box = {}

            def execute(root=root, recorder=recorder, box=box):
                try:
                    enroll_root(root, before_work=True)
                    child_environment = tool_environment(root / "home", {}, [])
                    box["result"] = run([str(PYTHON), "-I", "-S", "-c", "pass"], root, child_environment, 20,
                                        diagnostics=recorder)
                except Exception as error:
                    box["failure"] = {"class": type(error).__name__, "code": getattr(error, "code", None),
                                      "path": getattr(error, "path", None)}

            worker = threading.Thread(target=execute, daemon=True)
            worker.start()
            worker.join(timeout=max(0, min(30, deadline - time.monotonic())))
            record["joined"] = not worker.is_alive()
            require(record["joined"], "runner join incomplete")
            if "result" in box:
                code, seconds, reason, _ = box["result"]
                record.update(exitCode=code, seconds=seconds, reason=reason)
            if "failure" in box:
                record["failure"] = box["failure"]
            record["supervision"] = recorder.document({"package": "0" * 64, "id": "capture-race-fixture"}, index, False)
            documents = [observer.document() for run_index, observer in observers if run_index == index]
            record["observers"] = documents
            record["branches"] = sorted({value for value in map(classify, documents) if value})
            leader_groups = leaders.get(index, set())
            record["leaders"] = len(leader_groups)
            for item in (value for value in signals if value["run"] == index):
                foreign = (item.get("group") in foreign_groups or item.get("pid") in (churn.pid, sentinel.pid)
                           or item.get("identity") == sentinel_identity.key)
                inside = item.get("group") in leader_groups or item["kind"] == "owned-process" and any(
                    value and Path(value).resolve().is_relative_to(root.resolve())
                    for value in (item.get("cwd"), item.get("executable")))
                if foreign or not inside:
                    summary["violations"].append({"run": index, "signal": {k: item.get(k) for k in ("kind", "pid", "group", "signal")}})
            record["succeeded"] = succeeded(record)
            if not record["succeeded"]:
                summary["stopReason"] = "first-failure"
                break
        current["run"] = None
        if any(item["run"] is None for item in signals):
            summary["violations"].append({"signal": "outside an owned run"})
        final = probe.capture(sentinel.pid, paths=False)
        summary["sentinelPreserved"] = bool(final and final.key == sentinel_identity.key
                                            and final.generation == sentinel_identity.generation and final.status != 5)
        if not summary["sentinelPreserved"]:
            summary["violations"].append({"sentinel": "identity changed or exited"})
    except Exception as error:
        summary["errors"].append("controller:" + type(error).__name__ + ":" + str(error)[:120])
    finally:
        try:
            (unrelated / "sentinel-release").touch()
        except OSError as error:
            summary["errors"].append("sentinel-release:" + type(error).__name__)
        for name, process in (("churn", churn), ("sentinel", sentinel)):
            if process is None:
                continue
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
                summary[name + "Exit"] = process.returncode
            except subprocess.TimeoutExpired:
                summary[name + "StillAlive"] = True
        joined = worker is None or not worker.is_alive()
        if joined:
            for _, observer in reversed(observers):
                observer.__exit__(None, None, None)
            for item in reversed(patches):
                item.stop()
        summary["interceptionRemoved"] = joined
        for name in ("churn-done.json",):
            if (unrelated / name).exists():
                summary["churnDone"] = json.loads((unrelated / name).read_text())
        try:
            summary["sourceUnchanged"] = inventory_check(inventory_digest) == before
        except Exception as error:
            summary.update(sourceUnchanged=False, sourceFailure=type(error).__name__)
        summary["signals"] = len(signals)
        summary["seconds"] = time.monotonic() - started
        runs = summary["runs"]
        all_succeeded = bool(runs) and all(item.get("succeeded") for item in runs)
        tolerated = sum(1 for item in runs if item.get("succeeded") and "capture-retry-exhaustion" in item.get("branches", []))
        summary["toleratedRaceRuns"] = tolerated
        summary["outcome"] = ("invalid" if summary["violations"] or summary["errors"] or not summary["sourceUnchanged"]
                              or summary["seconds"] > TOTAL or not joined
                              else "failure" if not all_succeeded
                              else "races-tolerated" if tolerated
                              else "race-not-exercised")
        write(OUT / "summary.json", summary)
    print(json.dumps({"outcome": summary["outcome"], "runs": len(summary["runs"]), "output": str(OUT)}))
    return 0 if summary["outcome"] in ("races-tolerated", "race-not-exercised") else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory-digest", required=True)
    raise SystemExit(main(parser.parse_args().inventory_digest))
