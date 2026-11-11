"""Two version-only commands with frozen current resolution and environments."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import threading
import time
from unittest.mock import patch


TEMP = Path("/private/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode")
OUT = TEMP / "python-version-binding-01"
INPUT = TEMP / "android-discovery-inputs-02"
INSTALLER = INPUT / "installer"
INVENTORY_DIGEST = "b1ad6961aaa380fb857af739b7a64045d028fc168f69fcba33146413d0dcf1bc"
OWNER = TEMP / "media-python-resolution-01.json"
OWNER_DIGEST = "4d22fe5f61783969f1d93001749e6856daf529ced8ecbb5fa4dc8dbc2904afad"
ENVS = Path("/Users/george/Projects/com/my/.omo/pipeline/20261102-215016-ourpoker-build/python-version-probe-environments.json")
ENVS_DIGEST = "32702ebd5cd6a9dc0149d6a18ebe23dc657780ef20748f350de7ff5cceab6188"
PYTHON = Path("/Users/george/.pyenv/versions/3.12.8/bin/python3.12")
SHIM = Path("/Users/george/.pyenv/shims/python3")
PREFIX = Path("/opt/homebrew/Cellar/pyenv/2.6.32")
TREE_DIGEST = "e39d19fd5fe7d548e57c0665941ae76ef38831ce66aa2ae5c7a95790ca3542b9"
PACKAGE = "2acd6afd9cea6a8931717a4793557231bcb2acf999fef8e3ddc3218ec28993e6"
ARCHIVE = TEMP / "android-discovery-01/check/store/objects" / (PACKAGE + ".tar")
TOOLS = {
    str(PYTHON): ("3aa83eb80ce0ce80172b911f97f561f2b79057f99e2c00a673c3ac2297bb09fd", 0o755),
    str(SHIM): ("afc426a06763f18d6f07594f7d8318fb34124eaa08e373e8acd024e7ac639b25", 0o755),
    "/usr/bin/env": ("75690864f0e7397db05bcc0f4439915559ce24c2d834d530e4e619c14b938556", 0o755),
    "/bin/bash": ("16303dedab719ddb63efd9dd68092a0da37b397bfd4fcb856d5f1c86c5ee414b", 0o555),
    "/usr/bin/python3": ("b8763cf250e607a778bb4603cecb5b90338814d0a3dfcba0d57b1de242f610e9", 0o755),
    "/opt/homebrew/Cellar/pyenv/2.6.32/libexec/pyenv": ("82c9465c71f93e0c4f5173893ab674c5c959e0fade0b343cc0ad5ad12ce905cc", 0o755),
    "/Users/george/.gradle/jdks/eclipse_adoptium-17-aarch64-os_x.2/jdk-17.0.20.1+1/Contents/Home/bin/java":
        ("af8b122943345320b179c75c3404d56a981017739746b75f9caf583632f0bea0", 0o755),
}
ABSENT = ("/Users/george/.pyenv/plugins", "/Users/george/.pyenv/pyenv.d", "/Users/george/.pyenv/version",
          "/usr/etc/pyenv.d", "/opt/homebrew/etc/pyenv.d", "/etc/pyenv.d", "/usr/lib/pyenv/hooks")


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def ordinary(path, missing=False):
    for item in (path, *path.parents):
        require(not item.is_symlink(), "unexpected symbolic link")
    require(missing or path.exists(), "missing ordinary path")


def sha(path):
    ordinary(path)
    require(path.is_file(), "regular file required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_binding():
    roots = [PREFIX / "libexec", PREFIX / "pyenv.d", *sorted((PREFIX / "plugins").glob("*/bin"))]
    records = []
    for root in roots:
        paths = [root]
        for item in root.rglob("*"):
            paths.append(item)
            require(len(paths) + len(records) <= 512, "delegation tree bound")
        for item in [root, *sorted(paths[1:])]:
            ordinary(item)
            records.append([item.relative_to(PREFIX).as_posix(), stat.S_IMODE(item.stat().st_mode),
                            "directory" if item.is_dir() else sha(item)])
    raw = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    require(len(records) == 50 and hashlib.sha256(raw).hexdigest() == TREE_DIGEST, "delegation tree drift")
    return records


def bindings(controller_digest, plans):
    require(sha(Path(__file__).absolute()) == controller_digest, "controller drift")
    require(sha(OWNER) == OWNER_DIGEST and sha(ENVS) == ENVS_DIGEST, "captured input drift")
    require(Path("/opt/homebrew/opt/pyenv/bin/pyenv").resolve() == PREFIX / "libexec/pyenv", "delegation target drift")
    for name, (expected, mode) in TOOLS.items():
        path = Path(name)
        require(sha(path) == expected and stat.S_IMODE(path.stat().st_mode) == mode, "tool binding drift")
    tree = tree_binding()
    absent = set(ABSENT)
    for plan in plans:
        cwd = Path(plan["cwd"])
        absent.update(str(parent / ".python-version") for parent in (cwd, *cwd.parents))
    for name in absent:
        require(not Path(name).exists() and not Path(name).is_symlink(), "version selector/hook drift")
    return {"tools": TOOLS, "delegationTree": tree, "absentSelectorsAndHooks": sorted(absent)}


def retain(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main(expected_controller):
    started = time.monotonic()
    deadline = started + 40
    require(sys.platform == "darwin" and sys.version_info[:3] == (3, 12, 8), "reviewed interpreter required")
    require(Path(sys.executable).resolve() == PYTHON and Path.cwd().resolve() == INSTALLER, "launch binding")
    require(sha(OWNER) == OWNER_DIGEST and sha(ENVS) == ENVS_DIGEST, "input drift")
    owner, environment_document = json.loads(OWNER.read_bytes()), json.loads(ENVS.read_bytes())
    plans = environment_document["cases"]
    require([plan["id"] for plan in plans] == ["ambient", "pinned"], "case order")
    require(os.environ.get("PATH") == owner["PATH"] and os.defpath == owner["osDefpath"], "execution-owner PATH drift")
    require(shutil.which("python3", path=owner["PATH"]) == str(SHIM), "ambient resolution drift")
    before = bindings(expected_controller, plans)
    ordinary(OUT, missing=True)
    require(not OUT.exists() and OUT.parent.is_dir(), "occupied output")
    require(sha(INSTALLER / "tests/run_android_discovery_fixture.py") == "c7f120233428c6b6929b687135500b30c6b0c2ec3dc70be6a2214b41a058cd6a", "preflight helper drift")
    sys.path.insert(0, str(INSTALLER))
    from tests.run_android_discovery_fixture import inventory_check
    inventory_check(INPUT / "inventory.json", INVENTORY_DIGEST, OUT)
    from aepm import contextual
    from aepm.private_process import enroll_root
    from aepm.process import run
    from aepm.supervision import Recorder
    require(sha(ARCHIVE) == PACKAGE, "archive drift")
    with tarfile.open(ARCHIVE) as archive:
        member = archive.getmember("component.json")
        require(member.size <= 4 * 1024 * 1024, "manifest bound")
        manifest = json.load(archive.extractfile(member))
    suite = next(item for item in manifest["verification"] if item["id"] == "android-media")
    require(list(suite["tools"].items()) == [("java", "17"), ("python3", "3.12.8")], "version declaration drift")
    context = json.loads((INPUT / "android-context.json").read_bytes())
    java = next(item for item in context["resources"] if item["id"] == "androidJavaHome")
    OUT.mkdir(mode=0o700)
    summary = {"completeProof": False, "historicalClaim": False, "probeCompleted": False, "cases": [],
               "ownerCapture": owner, "environments": environment_document, "bindingsBefore": before,
               "inventoryDigest": INVENTORY_DIGEST, "archiveDigest": PACKAGE, "expectedVersion": "3.12.8",
               "javaResourceUsedForPathOnly": {key: java[key] for key in ("id", "path", "digest")}}
    active = None
    pending = []
    try:
        for plan in plans:
            require(deadline - time.monotonic() >= 18, "insufficient remaining allowance")
            bindings(expected_controller, plans)
            inventory_check(INPUT / "inventory.json", INVENTORY_DIGEST, OUT, fresh=False)
            root = OUT / plan["id"]
            root.mkdir(mode=0o700)
            record = {"id": plan["id"], "argv": plan["argv"], "cwd": plan["cwd"], "environment": plan["environment"]}
            summary["cases"].append(record)
            recorder = Recorder()
            case_deadline = min(deadline, time.monotonic() + 18)
            box = {}
            pending.append((record, box, recorder))

            def execute(plan=plan, box=box, root=root, recorder=recorder):
                try:
                    enroll_root(root, before_work=True)
                    (root / "work").mkdir(mode=0o700)
                    with patch.dict(os.environ, {"PATH": owner["PATH"]}):
                        environment = contextual.tool_environment(root / "home", suite["tools"], [java])
                    require(environment == plan["environment"], "constructed environment mismatch")
                    argv = (contextual.resolve_command(["python3", "--version"], root / "work", suite["tools"], environment)
                            if plan["id"] == "ambient" else [str(PYTHON), "--version"])
                    require(argv == plan["argv"], "command resolution drift")
                    box["initialExecutable"] = {"path": argv[0], "sha256": sha(Path(argv[0])),
                                                "mode": stat.S_IMODE(Path(argv[0]).stat().st_mode)}
                    box["result"] = run(argv, root / "work", environment, 10, 65536, diagnostics=recorder)
                except Exception as error:
                    box["failure"] = {"class": type(error).__name__, "code": getattr(error, "code", None)}

            active = threading.Thread(target=execute, daemon=True)
            active.start()
            active.join(timeout=max(0, case_deadline - time.monotonic()))
            record["joined"] = not active.is_alive()
            require(record["joined"], "runner join incomplete")
            for key in ("initialExecutable", "failure"):
                if key in box:
                    record[key] = box[key]
            result = box.get("result")
            require(result is not None, "version command unavailable")
            code, duration, reason, output = result
            record.update(exitCode=code, seconds=duration, reason=reason,
                          outputDigest=hashlib.sha256(output).hexdigest(), outputBytes=len(output))
            try:
                (root / "output.log").write_bytes(output)
            except OSError:
                record["outputBase64"] = base64.b64encode(output).decode()
                raise
            record["supervision"] = recorder.document({"package": PACKAGE, "id": "python-version-probe"}, 0, False)
            tokens = contextual.re.findall(r"(?<![0-9])([0-9]+(?:\.[0-9]+)*)", output.decode("utf-8", errors="replace"))
            record["numericTokens"], record["numericTokensTruncated"] = tokens[:256], len(tokens) > 256
            try:
                # Replay captured bytes through the production comparison without launching a tool.
                with patch.object(contextual, "run", return_value=result), patch.object(contextual, "resolve_command", return_value=plan["argv"]):
                    versions = contextual.tool_versions({"tools": {"python3": "3.12"}}, root / "work", plan["environment"])
                record["comparison"] = {"matched": True, "versions": versions}
            except Exception as error:
                record["comparison"] = {"matched": False, "class": type(error).__name__, "reason": getattr(error, "code", None)}
            retain(root / "result.json", record)
            require(code == 0 and reason == "", "version command failed containment or execution")
            final = record["supervision"]["finalOutcome"]
            require(final["state"] == "observed" and final["outcome"]["cleanupCompleted"] is True
                    and final["outcome"]["readersJoined"] is True and not record["supervision"]["recorderFailed"]
                    and not record["supervision"]["truncated"], "incomplete supervisor evidence")
            bindings(expected_controller, plans)
        summary["probeCompleted"] = len(summary["cases"]) == 2
    except Exception as error:
        summary["failure"] = {"class": type(error).__name__, "code": getattr(error, "code", None)}
    finally:
        if active is not None and active.is_alive():
            active.join(timeout=max(0, deadline-time.monotonic()))
            summary["lateJoinCompleted"] = not active.is_alive()
        for record, box, recorder in pending:
            snapshot = dict(box)
            for key in ("initialExecutable", "failure"):
                if key in snapshot and key not in record:
                    record[key] = snapshot[key]
            result = snapshot.get("result")
            if result is not None and "outputDigest" not in record:
                record["lateResult"] = {"exitCode": result[0], "seconds": result[1], "reason": result[2],
                                        "outputBase64": base64.b64encode(result[3]).decode()}
            if "supervision" not in record:
                record["supervision"] = recorder.document({"package": PACKAGE, "id": "python-version-probe"}, 0, False)
        try:
            summary["bindingsAfter"] = bindings(expected_controller, plans)
            inventory_check(INPUT / "inventory.json", INVENTORY_DIGEST, OUT, fresh=False)
            summary["bindingsUnchanged"] = summary["bindingsAfter"] == before
        except Exception as error:
            summary.update(bindingsUnchanged=False, postflightFailure=type(error).__name__)
        summary["seconds"] = time.monotonic() - started
        summary["probeCompleted"] = (summary["probeCompleted"] and not summary.get("failure")
                                     and summary["bindingsUnchanged"] and summary["seconds"] <= 40)
        try:
            retain(OUT / "summary.json", summary)
        except Exception as error:
            summary.update(probeCompleted=False, persistenceFailure=type(error).__name__)
            print(json.dumps(summary, sort_keys=True))
    return 0 if summary["probeCompleted"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-controller", required=True)
    args = parser.parse_args()
    raise SystemExit(main(args.expected_controller))
