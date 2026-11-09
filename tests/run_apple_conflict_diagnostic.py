"""Bounded Apple-suite conflict diagnostic: two suites in order, conflict records named; release required."""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch


TEMP = Path("/private/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode")
OUT = TEMP / "apple-conflict-diagnostic-01"
PYTHON = Path("/Users/george/.pyenv/versions/3.12.8/bin/python3.12")
PYTHON_DIGEST = "3aa83eb80ce0ce80172b911f97f561f2b79057f99e2c00a673c3ac2297bb09fd"
APPLICATION = TEMP / "ourpoker-remaining-v4/application"
APPLICATION_SNAPSHOT = "a50c2857e38fa6cd8b7bb4284c84caea908af231236f535739623cd816b050fd"
PACKAGE = "96a1b903ce9b375521456d28ea0de8e6375d0095ac838fdf577f6e8cec0566b8"
SELECTION = TEMP / "tool-selection-0.1.2-01/tool-selection.json"
SELECTION_FILE_DIGEST = "780dd83c04f31cafb7b1cbc94969ce083d5f42d4174bb1d3b2d3d9fd9420a3c6"
SELECTION_DIGEST = "45d081625b3add8f57d388d122da34114a05b123ff5c97018909c57121c657f6"
ORDER = ("apple-catalyst", "apple-phone-tablet")
MAX_RECORDS = 16
SOURCE = {
    "aepm/__init__.py": "f4dfd4dfbbbebfd7a4457428fe9e4c618064b680ccda07e60a936c3894c4730d",
    "aepm/__main__.py": "8cacb7b5e9ed795b5793edf3314cb86100606e728235f38429514344ff79b3f7",
    "aepm/application.py": "b467a4021548a0d7bcd43408cb6dd38c3b329a399b5ba39d29349e6f102f3b4f",
    "aepm/authorization.py": "bc29be5c15e92a882a01da71e980a0f149aa6a51a129eb33a7e55a812c7eda58",
    "aepm/bundle.py": "10e57809228d0356dfcd8e254fedf4259cb176b6c3d5de7ae43544fffc1adc4a",
    "aepm/contextual.py": "0ace567366d02bac79409dd255ffc73de1e5a2d44d469186901c1a3477ae02de",
    "aepm/crypto.mjs": "d888448b781f2794fe0c84f6b4f2ab8bba1958f87107984cabe6488dd90cc720",
    "aepm/diagram/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "aepm/diagram/generate.py": "07b878a79c077c11aaed5f4e0f4eb3af2739fd2117c3d536b766e3501d0dfad2",
    "aepm/environment.py": "9c0b699727824683ce2c179cdd93d18cb8ada695e0ac59d0b30796402e7e5356",
    "aepm/export.py": "c4e07b6e4fd4f794594a28c5acdfde182423be30834fdb2bf30972ac43dbca5d",
    "aepm/io.py": "361721a8b9bfdfa5c6cbb3b3830240981da365b573b6e53712ca9fc3ceeb418d",
    "aepm/model.py": "4ec3f9e0174ab015c536effb093a75ff3ed11e772f4b10f93c40868a57c05b96",
    "aepm/posix_process.py": "395db715742ebc844d22cc9eab38dcf7e55fff6d58da336d816f179aa2fbdcda",
    "aepm/private_process.py": "249368ad37f2bca43e971a99f2e3588c626502f27257ca5d7b9f998631282fcf",
    "aepm/process.py": "4a4dcf02599b079961bbabcd209bcf0342300bea07f247b54ecd8aa2be28fdc9",
    "aepm/supervision.py": "70a0d7b5461f7549079fe9e948c6599c8eb01430351b0a19690d5518aaef2b78",
    "aepm/test_identities.py": "a0a1e696f689b0a3ff40c54a26b833eb6d57566daef1c98df6c6d8849b372c0a",
    "aepm/tool_selection.py": "dbc2d0be8c773e958706218abdb18b3dcebfe6c9033fd787b4616e3ed7a55b44",
    "aepm/trust.py": "c2b6a696dce81e8897a96a6bbdec4dca37f7035605fc8ea8a8f5e68df872df8d",
    "aepm/update.py": "e6d76e3b1febf2dcf32928cd580a60def5ebcf454fdbe796f2eacd289359aea7",
    "aepm/update_probe.mjs": "835bf9d5cb5c328e174bea4958a8ef6ef28d7c616384cc2e05b2facab31065bc",
    "aepm/verification.py": "0a876c53470063bfbce9232f49afe8ba71bcaab5a6a05ac8b05fd53fe4a154d5",
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


def observation(root_of, scope, record, started_ns, cwd_inside, executable_inside):
    """Only fields already captured by production discovery; no extra process query."""
    return {"pid": record.pid, "uniqueIdentity": record.key, "generation": record.generation,
            "executableBasename": Path(record.executable).name if record.executable else None,
            "executableInsideRoot": executable_inside, "cwdInsideRoot": cwd_inside,
            "cwdRelative": (Path(record.cwd).resolve().relative_to(root_of).as_posix() if cwd_inside else None),
            "parentPid": record.parent, "launchdParent": record.parent == 1, "group": record.group,
            "scopeGroup": scope.group, "inBaseline": record.key in scope.baseline,
            "startedBeforeScopeSeconds": (None if record.started_ns is None else
                                          round((started_ns - record.started_ns) / 1e9, 3))}


def main(controller):
    started = time.monotonic()
    source = Path(__file__).resolve().parents[1]
    require(sys.platform == "darwin", "Darwin required")
    bindings(source, controller)
    require(not OUT.exists() and not OUT.is_symlink() and OUT.parent.is_dir(), "occupied output")
    sys.path.insert(0, str(source))
    from aepm import contextual, private_process
    from aepm.environment import Execution
    from aepm.io import load, snapshot
    from aepm.model import canonical, digest
    from aepm.tool_selection import load_tool_selection

    require(digest(canonical(snapshot(APPLICATION))) == APPLICATION_SNAPSHOT, "application drift")
    manifest = load(APPLICATION / ".aepm/packages" / PACKAGE / "component.json")
    suites = {item["id"]: {**item, "package": PACKAGE} for item in manifest["verification"]}
    for name in ORDER:
        execution = suites[name]["execution"]
        require(execution["kind"] == "local" and not execution["resources"] and not execution["operations"]
                and not execution["secrets"] and not suites[name]["requirements"], "unexpected suite authority")
    document = json.loads(SELECTION.read_bytes())
    selection = load_tool_selection(document, set(document["tools"]))
    require(selection.digest == SELECTION_DIGEST, "selection digest")

    OUT.mkdir(mode=0o700)
    temporary, logs, evidence = OUT / "tmp", OUT / "logs", OUT / "evidence"
    temporary.mkdir(mode=0o700)
    summary = {"completeProof": False, "order": list(ORDER), "selectionDigest": selection.digest,
               "applicationSnapshot": APPLICATION_SNAPSHOT, "suites": [], "conflicts": [], "conflictsCapped": False}
    scopes = {}
    original_init, original_matches = private_process.PrivateScope.__init__, private_process.PrivateScope.matches_root

    def init(scope, root, *args, **kwargs):
        scopes[id(scope)] = time.time_ns()
        return original_init(scope, root, *args, **kwargs)

    def matches(scope, record):
        result = original_matches(scope, record)
        try:
            if result and record.key in scope.baseline and record.key not in scope.ancestors:
                if len(summary["conflicts"]) >= MAX_RECORDS:
                    summary["conflictsCapped"] = True
                else:
                    root_of = scope.root.resolve()
                    inside = lambda value: bool(value) and Path(value).is_absolute() and Path(value).resolve().is_relative_to(root_of)
                    summary["conflicts"].append({"suite": current["suite"], "atSeconds": round(time.monotonic() - started, 3),
                                                 **observation(root_of, scope, record, scopes.get(id(scope), time.time_ns()),
                                                               inside(record.cwd), inside(record.executable))})
        except Exception as error:
            summary.setdefault("recordingErrors", []).append(type(error).__name__)
        return result

    current = {"suite": None}
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"TMPDIR": str(temporary)}))
        stack.enter_context(patch("tempfile.tempdir", str(temporary)))
        stack.enter_context(patch.object(private_process.PrivateScope, "__init__", init))
        stack.enter_context(patch.object(private_process.PrivateScope, "matches_root", matches))
        execution = Execution({}, source / "unused-policy", evidence)
        try:
            for name in ORDER:
                current["suite"] = name
                result, record = contextual.execute(suites[name], APPLICATION, True, logs, execution, tool_selection=selection)
                summary["suites"].append({"id": name, "result": result, "cleanup": record["cleanup"],
                                          "secondsElapsed": round(time.monotonic() - started, 3)})
                write(OUT / "summary.json", summary)
        except Exception as error:
            summary["controllerFailure"] = type(error).__name__ + ":" + str(error)[:160]
    try:
        bindings(source, controller)
        summary["sourceUnchanged"] = digest(canonical(snapshot(APPLICATION))) == APPLICATION_SNAPSHOT
    except Exception as error:
        summary.update(sourceUnchanged=False, postflightFailure=type(error).__name__)
    summary["seconds"] = round(time.monotonic() - started, 3)
    summary["outcome"] = ("invalid" if summary.get("controllerFailure") or not summary["sourceUnchanged"]
                          or summary.get("recordingErrors")
                          else "conflict-named" if summary["conflicts"] else "not-reproduced")
    write(OUT / "summary.json", summary)
    print(json.dumps({"outcome": summary["outcome"], "conflicts": len(summary["conflicts"]), "output": str(OUT)}))
    return 0 if summary["outcome"] != "invalid" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-controller", required=True)
    raise SystemExit(main(parser.parse_args().expected_controller))
