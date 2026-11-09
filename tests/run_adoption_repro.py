"""Bounded adoption reproduction: the four local Apple suites in v5 order with adoption_root; release required per run."""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
from unittest.mock import patch


TEMP = Path("/private/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode")
PYTHON = Path("/Users/george/.pyenv/versions/3.12.8/bin/python3.12")
PYTHON_DIGEST = "3aa83eb80ce0ce80172b911f97f561f2b79057f99e2c00a673c3ac2297bb09fd"
APPLICATION = TEMP / "ourpoker-remaining-v4/application"
APPLICATION_SNAPSHOT = "a50c2857e38fa6cd8b7bb4284c84caea908af231236f535739623cd816b050fd"
PACKAGE = "96a1b903ce9b375521456d28ea0de8e6375d0095ac838fdf577f6e8cec0566b8"
SELECTION = TEMP / "tool-selection-0.1.2-01/tool-selection.json"
SELECTION_FILE_DIGEST = "780dd83c04f31cafb7b1cbc94969ce083d5f42d4174bb1d3b2d3d9fd9420a3c6"
SELECTION_DIGEST = "45d081625b3add8f57d388d122da34114a05b123ff5c97018909c57121c657f6"
ADOPTION_ROOT = Path("/Applications/Xcode.app/Contents")
ORDER = ("apple-catalyst", "apple-phone-tablet", "apple-test-build", "apple-tv")
SOURCE = {
    "aepm/__init__.py": "f4dfd4dfbbbebfd7a4457428fe9e4c618064b680ccda07e60a936c3894c4730d",
    "aepm/__main__.py": "8cacb7b5e9ed795b5793edf3314cb86100606e728235f38429514344ff79b3f7",
    "aepm/application.py": "b467a4021548a0d7bcd43408cb6dd38c3b329a399b5ba39d29349e6f102f3b4f",
    "aepm/authorization.py": "bc29be5c15e92a882a01da71e980a0f149aa6a51a129eb33a7e55a812c7eda58",
    "aepm/bundle.py": "10e57809228d0356dfcd8e254fedf4259cb176b6c3d5de7ae43544fffc1adc4a",
    "aepm/contextual.py": "b0b05bc3dc12c2f59a36568fb76feeaabbc004bcc3b198136c38f3066529a4e5",
    "aepm/crypto.mjs": "d888448b781f2794fe0c84f6b4f2ab8bba1958f87107984cabe6488dd90cc720",
    "aepm/diagram/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "aepm/diagram/generate.py": "07b878a79c077c11aaed5f4e0f4eb3af2739fd2117c3d536b766e3501d0dfad2",
    "aepm/environment.py": "9c0b699727824683ce2c179cdd93d18cb8ada695e0ac59d0b30796402e7e5356",
    "aepm/export.py": "c4e07b6e4fd4f794594a28c5acdfde182423be30834fdb2bf30972ac43dbca5d",
    "aepm/io.py": "361721a8b9bfdfa5c6cbb3b3830240981da365b573b6e53712ca9fc3ceeb418d",
    "aepm/model.py": "4ec3f9e0174ab015c536effb093a75ff3ed11e772f4b10f93c40868a57c05b96",
    "aepm/posix_process.py": "381428eaa15eb2bf0481fca960a25b632f6fc7332bb223c08d319b6a97c0bc4c",
    "aepm/private_process.py": "a5316cba5372c18952ff194d9b4b5489107ec1eac02980b7bc42695873c98c94",
    "aepm/process.py": "75d06b44c7b8035f4419d3db9265b22441abbf2dfa3a0339ce17bb0105f90b08",
    "aepm/supervision.py": "08098de198f01d9785f42c9a944b176bfe2fc535be17a56522e7fef74a982b28",
    "aepm/test_identities.py": "a0a1e696f689b0a3ff40c54a26b833eb6d57566daef1c98df6c6d8849b372c0a",
    "aepm/tool_selection.py": "dbc2d0be8c773e958706218abdb18b3dcebfe6c9033fd787b4616e3ed7a55b44",
    "aepm/trust.py": "c2b6a696dce81e8897a96a6bbdec4dca37f7035605fc8ea8a8f5e68df872df8d",
    "aepm/update.py": "d11d94fe4592440200a86f1d6039c1bf145fd9ed8a92bc28e46fa915693b9d09",
    "aepm/update_probe.mjs": "835bf9d5cb5c328e174bea4958a8ef6ef28d7c616384cc2e05b2facab31065bc",
    "aepm/verification.py": "12f8bfd008a65a2a2a542f0415788cbba72a8f426b682d0dfa64da8ca94db3b5",
    "aepm/windows.py": "f68e616f6c84f86a6ec853ed7910cf27f07fe26064b09292c5c65aa0bfddc33b",
}


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def sha(path):
    for item in (path, *path.parents):
        require(not item.is_symlink(), "symbolic link refused")
    require(path.is_file(), "regular file required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def bindings(source, controller):
    require(sha(Path(__file__).absolute()) == controller, "controller drift")
    require(sha(PYTHON) == PYTHON_DIGEST and Path(sys.executable).resolve() == PYTHON
            and sys.version_info[:3] == (3, 12, 8), "interpreter drift")
    require({name: sha(source / name) for name in SOURCE} == SOURCE, "installer source drift")
    require(sha(SELECTION) == SELECTION_FILE_DIGEST, "selection drift")


def judge(summary):
    """Accepted only with an adopted ibtoold record and its matching supervision entry in a later suite, all suites passing."""
    if summary.get("controllerFailure") or not summary.get("sourceUnchanged") or len(summary["suites"]) != len(ORDER):
        return "invalid"
    records = [record for root in summary["roots"] for record in root["records"]]
    if any(not record.get("adopted") for record in records):
        return "conflict"
    for suite in summary["suites"]:
        if not (suite["result"]["status"] == "passed" and suite["result"]["exitCode"] == 0
                and suite["result"]["reason"] == "" and suite["cleanup"]["completed"] is not False):
            return "suite-failed"
    exercised = False
    for suite in summary["suites"][1:]:
        adopted = [record for root in summary["roots"] if root["suite"] == suite["id"] for record in root["records"]
                   if record.get("adopted") and record.get("executableBasename") == "ibtoold"
                   and record.get("executableRelative") == "Developer/usr/bin/ibtoold"]
        if not adopted:
            continue
        exercised = True
        logged = {(entry["uniqueIdentity"], entry["generation"]) for entry in suite.get("supervisionAdoptions", [])
                  if entry["executableRelative"] == "Developer/usr/bin/ibtoold"}
        if not suite.get("supervisionError") and any((record["uniqueIdentity"], record["generation"]) in logged
                                                     for record in adopted):
            return "adopted-clean"
    return "log-missing" if exercised else "not-exercised"


def main(run, controller):
    started = time.monotonic()
    out = TEMP / ("adoption-repro-%02d" % run)
    source = Path(__file__).resolve().parents[1]
    require(sys.platform == "darwin" and run in (1, 2), "Darwin and run 1 or 2 required")
    bindings(source, controller)
    require(not out.exists() and not out.is_symlink() and out.parent.is_dir(), "occupied output")
    sys.path.insert(0, str(source))
    from aepm import contextual, io
    from aepm.environment import Execution
    from aepm.io import load, snapshot
    from aepm.model import canonical, digest
    from aepm.private_process import adoption_root
    from aepm.supervision import validate_log_index
    from aepm.tool_selection import load_tool_selection

    require(digest(canonical(snapshot(APPLICATION))) == APPLICATION_SNAPSHOT, "retained application drift")
    anchor = adoption_root(ADOPTION_ROOT)
    out.mkdir(mode=0o700)
    application = out / "application"
    shutil.copytree(APPLICATION, application, symlinks=True)
    require(digest(canonical(snapshot(application))) == APPLICATION_SNAPSHOT, "fresh application copy differs")
    manifest = load(application / ".aepm/packages" / PACKAGE / "component.json")
    suites = {item["id"]: {**item, "package": PACKAGE} for item in manifest["verification"]}
    for name in ORDER:
        declaration = suites[name]["execution"]
        require(declaration["kind"] == "local" and not declaration["resources"] and not declaration["operations"]
                and not declaration["secrets"] and not suites[name]["requirements"], "unexpected suite authority")
    document = json.loads(SELECTION.read_bytes())
    selection = load_tool_selection(document, set(document["tools"]))
    require(selection.digest == SELECTION_DIGEST, "selection digest")

    temporary, logs, evidence = out / "tmp", out / "logs", out / "evidence"
    temporary.mkdir(mode=0o700)
    summary = {"completeProof": False, "run": run, "order": list(ORDER), "adoptionRoot": str(anchor),
               "selectionDigest": selection.digest, "applicationSnapshot": APPLICATION_SNAPSHOT, "suites": [], "roots": []}
    current, workspaces = {"suite": None}, []

    class Retained(io.VerificationDirectory):
        """Keep every private root so adoption records survive a clean step."""

        def __init__(self, prefix):
            super().__init__(prefix)
            workspaces.append((current["suite"], self.path))

        def __exit__(self, *args):
            self.preserve = True
            return super().__exit__(*args)

    from aepm.private_process import DarwinBackend
    original_terminate = DarwinBackend.terminate
    summary["signalTargets"] = []

    def terminate(backend, owned, number):
        """Record-only pass-through; never alters arguments, ordering or result."""
        try:
            if len(summary["signalTargets"]) < 256:
                summary["signalTargets"].append({"suite": current["suite"], "pid": owned.pid, "uniqueIdentity": owned.key,
                                                 "generation": owned.generation, "signal": int(number),
                                                 "executable": owned.executable, "parentPid": owned.parent})
        except Exception:
            summary["signalRecordErrors"] = summary.get("signalRecordErrors", 0) + 1
        return original_terminate(backend, owned, number)

    with ExitStack() as stack:
        stack.enter_context(patch.object(DarwinBackend, "terminate", terminate))
        stack.enter_context(patch.dict(os.environ, {"TMPDIR": str(temporary)}))
        stack.enter_context(patch("tempfile.tempdir", str(temporary)))
        stack.enter_context(patch.object(contextual, "VerificationDirectory", Retained))
        execution = Execution({}, source / "unused-policy", evidence)
        try:
            for name in ORDER:
                current["suite"] = name
                result, record = contextual.execute(suites[name], application, True, logs, execution,
                                                    tool_selection=selection, adoption_root=anchor)
                entry = {"id": name, "result": result, "cleanup": record["cleanup"],
                         "secondsElapsed": round(time.monotonic() - started, 3), "supervisionAdoptions": []}
                try:
                    events = json.loads((logs / (result["logDigest"] + ".json")).read_bytes())
                    for path in validate_log_index(suites[name], events, logs):
                        entry["supervisionAdoptions"].extend(json.loads(path.read_bytes()).get("adoptions", []))
                except Exception as error:
                    entry["supervisionError"] = type(error).__name__
                summary["suites"].append(entry)
                write(out / "summary.json", summary)
        except Exception as error:
            summary["controllerFailure"] = type(error).__name__ + ":" + str(error)[:160]
    for suite, root in workspaces:
        records = []
        for path in sorted(root.glob("conflict-*.json"), key=lambda item: int(item.stem.split("-")[1])):
            try:
                records.append({**json.loads(path.read_text()), "file": path.name})
            except (OSError, ValueError) as error:
                records.append({"file": path.name, "unreadable": type(error).__name__})
        summary["roots"].append({"suite": suite, "root": str(root), "records": records})
    try:
        bindings(source, controller)
        summary["sourceUnchanged"] = (digest(canonical(snapshot(APPLICATION))) == APPLICATION_SNAPSHOT
                                      and digest(canonical(snapshot(application))) == APPLICATION_SNAPSHOT)
    except Exception as error:
        summary.update(sourceUnchanged=False, postflightFailure=type(error).__name__)
    summary["seconds"] = round(time.monotonic() - started, 3)
    summary["outcome"] = judge(summary)
    write(out / "summary.json", summary)
    print(json.dumps({"outcome": summary["outcome"], "output": str(out)}))
    return 0 if summary["outcome"] == "adopted-clean" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=int, required=True)
    parser.add_argument("--expected-controller", required=True)
    arguments = parser.parse_args()
    raise SystemExit(main(arguments.run, arguments.expected_controller))
