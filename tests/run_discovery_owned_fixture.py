"""Proposed owned-only discovery experiment; invocation requires separate release."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
from unittest.mock import patch


PYTHON = Path("/Users/george/.pyenv/versions/3.12.8/bin/python3.12")
PYTHON_DIGEST = "3aa83eb80ce0ce80172b911f97f561f2b79057f99e2c00a673c3ac2297bb09fd"
OUTPUT = Path("/private/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode/discovery-owned-exec-01")
BINDINGS = {
    "aepm/__init__.py": "f4dfd4dfbbbebfd7a4457428fe9e4c618064b680ccda07e60a936c3894c4730d",
    "aepm/__main__.py": "8cacb7b5e9ed795b5793edf3314cb86100606e728235f38429514344ff79b3f7",
    "aepm/application.py": "b467a4021548a0d7bcd43408cb6dd38c3b329a399b5ba39d29349e6f102f3b4f",
    "aepm/authorization.py": "bc29be5c15e92a882a01da71e980a0f149aa6a51a129eb33a7e55a812c7eda58",
    "aepm/bundle.py": "10e57809228d0356dfcd8e254fedf4259cb176b6c3d5de7ae43544fffc1adc4a",
    "aepm/contextual.py": "e21b27f4231e3676466676e3bb751a3a770703b15aea6d010e15c415061c60e7",
    "aepm/environment.py": "9c0b699727824683ce2c179cdd93d18cb8ada695e0ac59d0b30796402e7e5356",
    "aepm/export.py": "c4e07b6e4fd4f794594a28c5acdfde182423be30834fdb2bf30972ac43dbca5d",
    "aepm/io.py": "361721a8b9bfdfa5c6cbb3b3830240981da365b573b6e53712ca9fc3ceeb418d",
    "aepm/model.py": "4ec3f9e0174ab015c536effb093a75ff3ed11e772f4b10f93c40868a57c05b96",
    "aepm/posix_process.py": "395db715742ebc844d22cc9eab38dcf7e55fff6d58da336d816f179aa2fbdcda",
    "aepm/private_process.py": "73b313f1d0029165c47cf7b0ee8df6de079be3c4e76b09bcd6e347064375bb50",
    "aepm/process.py": "0cced9faa9160c36649247a927471dae6583790b34ba82c6dc9c5ba5807be075",
    "aepm/supervision.py": "70a0d7b5461f7549079fe9e948c6599c8eb01430351b0a19690d5518aaef2b78",
    "aepm/test_identities.py": "a0a1e696f689b0a3ff40c54a26b833eb6d57566daef1c98df6c6d8849b372c0a",
    "aepm/trust.py": "c2b6a696dce81e8897a96a6bbdec4dca37f7035605fc8ea8a8f5e68df872df8d",
    "aepm/update.py": "c332cda135921238967ea4ca6fdc721d4aa014c5e93e1dc9cb75a756d55bd736",
    "aepm/verification.py": "0c150ee403976ca58e9d49a6ba4f390400edffbf22ad44c92b002cf98c493cdf",
    "aepm/windows.py": "f68e616f6c84f86a6ec853ed7910cf27f07fe26064b09292c5c65aa0bfddc33b",
    "tests/discovery_observer.py": "facb05280dc1b5fdae6e691d0175cbc5a7ff6a9d320de4b251f4e9c4684f97c9",
    "tests/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

CHILD = r'''
import json, os, subprocess, sys, time
from pathlib import Path
role, deadline, remaining, code = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
root = Path.cwd()
def save(name, value):
    temporary = root / (name + ".pending")
    temporary.write_text(json.dumps(value))
    temporary.replace(root / (name + ".json"))
if role == "leader":
    save("ready", {"pid": os.getpid(), "at": time.monotonic(), "deadline": deadline})
    while not (root / "release").exists() and time.monotonic() < deadline:
        time.sleep(.01)
    if time.monotonic() >= deadline:
        save("completed", {"expired": True, "at": time.monotonic()})
        raise SystemExit(2)
    child = subprocess.Popen([sys.executable, "-I", "-S", "-c", code, "worker", str(deadline), "64", code])
    save("worker-created", {"pid": child.pid, "parent": os.getpid(), "at": time.monotonic()})
    try:
        status = child.wait(timeout=max(.001, deadline-time.monotonic()))
    except subprocess.TimeoutExpired:
        save("completed", {"expired": True, "at": time.monotonic()})
        raise SystemExit(2)
    save("completed", {"expired": time.monotonic() >= deadline, "workerCode": status, "at": time.monotonic()})
    raise SystemExit(status)
if role != "worker":
    raise SystemExit(3)
if remaining == 64:
    save("exec-ready", {"pid": os.getpid(), "parent": os.getppid(), "at": time.monotonic()})
if time.monotonic() >= deadline:
    save("exec-completed", {"expired": True, "remaining": remaining, "at": time.monotonic()})
    raise SystemExit(2)
if remaining == 0:
    save("exec-completed", {"expired": False, "remaining": 0, "at": time.monotonic()})
    raise SystemExit(0)
os.execv(sys.executable, [sys.executable, "-I", "-S", "-c", code, "worker", str(deadline), str(remaining-1), code])
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def ordinary(path):
    for part in (path, *path.parents):
        require(not part.is_symlink(), "symbolic link refused")


def sha(path):
    ordinary(path)
    require(path.is_file(), "ordinary source/tool file required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def failure(summary, phase, error):
    summary.setdefault("controllerFailure", phase)
    errors = summary.setdefault("controllerErrors", [])
    if len(errors) < 16:
        errors.append({"phase": phase, "exception": type(error).__name__})
    else:
        summary["controllerErrorsTruncated"] = True
    summary["accepted"] = False
    summary["recordsComplete"] = False
    summary["observation"] = "inconclusive"


def release_and_join(root, worker, deadline, summary):
    try:
        (root / "release").touch()
    except Exception as error:
        summary.setdefault("releaseFailure", type(error).__name__)
        failure(summary, "release-publication", error)
    finally:
        summary["workerJoined"] = False
        try:
            if worker.ident is not None:
                worker.join(timeout=max(0, deadline-time.monotonic()))
            summary["workerJoined"] = worker.ident is not None and not worker.is_alive()
        except Exception as error:
            failure(summary, "runner-join", error)


def observer_evidence(observers, attachment, summary):
    if summary["workerJoined"]:
        for observer in reversed(observers):
            try:
                observer.__exit__(None, None, None)
            except Exception as error:
                failure(summary, "observer-detachment", error)
        try:
            attachment.stop()
        except Exception as error:
            failure(summary, "attachment-detachment", error)
    documents = []
    for observer in observers:
        try:
            documents.append(observer.document())
        except Exception as error:
            failure(summary, "observer-evidence", error)
            documents.append({"firstFailure": None, "unavailable": True, "countsCapped": False})
    summary["observerDocuments"] = documents


def retain_evidence(out, summary):
    failed = False
    try:
        write(out / "summary.json", summary)
    except Exception as error:
        failed = True
        failure(summary, "summary-write", error)
    try:
        write(out / "state.json", {"phase": "failed" if summary.get("controllerFailure") else "finished",
                                    "accepted": summary["accepted"], "completeProof": False,
                                    "controllerFailure": summary.get("controllerFailure")})
    except Exception as error:
        failed = True
        failure(summary, "state-write", error)
    if failed:
        try:
            write(out / "summary.json", summary)
        except Exception as error:
            failure(summary, "failure-summary-write", error)
        print(json.dumps({"accepted": False, "evidencePersistenceFailed": True, "summary": summary}, sort_keys=True))


def main(expected_controller):
    started = time.monotonic()
    deadline = started + 40
    source = Path(__file__).resolve().parents[1]
    require(sys.platform == "darwin" and sys.version_info[:3] == (3, 12, 8), "reviewed host/interpreter required")
    require(Path(sys.executable).resolve() == PYTHON and sha(PYTHON) == PYTHON_DIGEST, "interpreter drift")
    require(PYTHON.stat().st_mode & 0o777 == 0o755, "interpreter mode drift")
    require(sha(Path(__file__).absolute()) == expected_controller, "controller drift")
    before = {name: sha(source / name) for name in BINDINGS}
    require(before == BINDINGS, "source drift")
    ordinary(OUTPUT)
    require(not OUTPUT.exists() and OUTPUT.parent.is_dir(), "occupied output or absent parent")
    OUTPUT.mkdir(mode=0o700)
    root = OUTPUT / "private"
    root.mkdir(mode=0o700)
    summary = {"completeProof": False, "accepted": False, "started": started, "controllerDigest": expected_controller,
               "sourceBefore": before, "python": str(PYTHON), "pythonDigest": PYTHON_DIGEST,
               "attachmentScope": "post-construction-existing-calls", "constructorChecksObserved": False}
    write(OUTPUT / "state.json", {"phase": "prepared", **summary})
    from aepm.contextual import tool_environment
    from aepm.private_process import DarwinBackend, enroll_root
    from aepm.process import run
    from aepm.supervision import Recorder
    from tests.discovery_observer import DiscoveryObserver

    observers, attachment_errors, results = [], [], {}
    recorder = Recorder()
    original_init = DarwinBackend.__init__

    def attach(backend):
        try:
            original_init(backend)
        except BaseException:
            attachment_errors.append("constructor-before-attachment")
            raise
        try:
            require(len(observers) < 4, "observer capacity")
            observer = DiscoveryObserver(backend)
            observer.__enter__()
            observers.append(observer)
        except Exception:
            attachment_errors.append("attachment-unavailable")

    def execute():
        try:
            enroll_root(root, before_work=True)
            environment = tool_environment(root / "home", {}, [])
            require(deadline - time.monotonic() >= 30, "insufficient remaining controller allowance")
            child_deadline = time.monotonic() + 20
            results["childDeadline"] = child_deadline
            code, duration, reason, output = run(
                [str(PYTHON), "-I", "-S", "-c", CHILD, "leader", str(child_deadline), "64", CHILD],
                root, environment, 20, diagnostics=recorder)
            (OUTPUT / "output.log").write_bytes(output)
            results.update(exitCode=code, seconds=duration, reason=reason)
        except Exception as error:
            results["exception"] = type(error).__name__

    attachment = patch.object(DarwinBackend, "__init__", attach)
    attachment.start()
    worker = threading.Thread(target=execute, daemon=True)
    try:
        worker.start()
        while not (root / "ready.json").exists():
            require(worker.is_alive(), "runner ended before fixture readiness")
            require(time.monotonic() < deadline, "controller readiness deadline")
            time.sleep(.01)
        summary["ready"] = json.loads((root / "ready.json").read_text())
        summary["released"] = time.monotonic()
        (root / "release").touch()
    except Exception as error:
        failure(summary, "controller", error)
    finally:
        release_and_join(root, worker, deadline, summary)
        observer_evidence(observers, attachment, summary)
        summary["attachmentErrors"] = attachment_errors
        summary["results"] = dict(results)
        try:
            summary["supervision"] = recorder.document({"package": "0" * 64, "id": "owned-discovery-fixture"}, 0, False)
        except Exception as error:
            summary["supervision"] = None
            failure(summary, "supervision-evidence", error)
        for name in ("worker-created", "exec-ready", "exec-completed", "completed"):
            try:
                path = root / (name + ".json")
                if path.exists():
                    summary[name] = json.loads(path.read_text())
            except Exception as error:
                failure(summary, "fixture-evidence", error)
        try:
            summary["sourceAfter"] = {name: sha(source / name) for name in BINDINGS}
            summary["sourceUnchanged"] = (summary["sourceAfter"] == before
                                           and sha(PYTHON) == PYTHON_DIGEST
                                           and sha(Path(__file__).absolute()) == expected_controller)
        except Exception as error:
            summary.update(sourceUnchanged=False, sourceAfterFailure=type(error).__name__)
            failure(summary, "binding-evidence", error)
        summary["seconds"] = time.monotonic() - started
        failures = [item["firstFailure"] for item in summary["observerDocuments"] if item["firstFailure"] is not None]
        summary["recordsComplete"] = (summary["workerJoined"] and bool(observers) and not attachment_errors
                                       and not summary.get("controllerFailure") and summary["supervision"] is not None
                                       and not any(item["unavailable"] or item["countsCapped"] for item in summary["observerDocuments"])
                                       and not any(item["truncated"] or item["unavailable"] for item in failures)
                                       and not summary["supervision"]["recorderFailed"] and not summary["supervision"]["truncated"])
        summary["observation"] = ("inconclusive" if not summary["recordsComplete"] or not summary["sourceUnchanged"]
                                   or summary.get("controllerFailure") else "private-process-discovery-observed"
                                   if any(item["location"] == "private-process-discovery" for item in failures)
                                   else "different-failure-observed" if failures or results.get("reason")
                                   or results.get("exception") else "not-reproduced")
        summary["accepted"] = (summary["recordsComplete"] and summary["sourceUnchanged"] and summary["seconds"] <= 40
                               and all(name in summary for name in ("ready", "worker-created", "exec-ready", "exec-completed", "completed"))
                               and summary["supervision"]["finalOutcome"]["state"] == "observed"
                               and summary["supervision"]["finalOutcome"]["outcome"]["cleanupCompleted"] is True
                               and summary["supervision"]["finalOutcome"]["outcome"]["readersJoined"] is True
                               and not summary.get("controllerFailure") and results.get("exitCode") == 0
                               and results.get("reason") == "" and summary.get("completed", {}).get("expired") is False
                               and not failures and summary.get("completed", {}).get("workerCode") == 0
                               and summary.get("worker-created", {}).get("parent") == summary.get("ready", {}).get("pid")
                               and summary.get("exec-ready", {}).get("pid") == summary.get("worker-created", {}).get("pid")
                               and summary.get("exec-completed", {}).get("remaining") == 0
                               and summary.get("exec-completed", {}).get("expired") is False)
        if summary["observation"] == "not-reproduced" and not summary["accepted"]:
            summary["observation"] = "inconclusive"
        retain_evidence(OUTPUT, summary)
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-controller", required=True)
    args = parser.parse_args()
    raise SystemExit(main(args.expected_controller))
