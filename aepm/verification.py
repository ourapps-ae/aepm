"""Explicitly trusted execution with rooted copies and complete evidence."""

import os
from pathlib import Path
import re
import shutil
import tempfile

from .application import read_assembly, validate_retained_assembly
from .io import VerificationDirectory, fail, immutable_blob, load, rooted, snapshot, write
from .model import Report, canonical, digest, guarded, validate_component
from .tool_selection import require_selection


SCOPES = ("required-local", "platform", "deployed")
OUTPUT_LIMIT = 8 * 1024 * 1024


def declarations(packages, manifests, context):
    result = []
    seen = set()
    for ref in packages:
        for suite in manifests[ref["digest"]]["verification"]:
            if context == "review" and suite["root"] != "package":
                continue
            key = (ref["digest"], suite["id"])
            if key in seen:
                fail("duplicate-suite", "verification")
            seen.add(key)
            result.append({**suite, "package": ref["digest"]})
    return sorted(result, key=lambda item: (item["package"], item["id"]))


def package_records(lock):
    return [{**{key: ref[key] for key in ("name", "version", "digest")},
             "dependencies": sorted(item["digest"] for item in ref["dependencies"])} for ref in lock["packages"]]


def summary(suites):
    result = {}
    for scope in SCOPES:
        statuses = [suite["status"] for suite in suites if suite["scope"] == scope]
        result[scope] = ("not-applicable" if not statuses else "failed" if "failed" in statuses else
                         "blocked" if "blocked" in statuses else "passed")
    return result


def check_report(report, lock, assembly_digest, manifests, context="application", *, evidence_root=None, policy=None, adoption=False):
    from .authorization import bindings
    from .trust import validate_report_evidence
    return validate_report_evidence(report, bindings(lock, assembly_digest, manifests, context), context,
                                    evidence_root, policy, adoption=adoption)


def retained_manifests(root, policy):
    from .bundle import source_tree_digest, validate_extracted_mode
    from .trust import verify

    root = Path(root)
    assembly = read_assembly(root)
    manifests = {}
    for ref in assembly["lock"]["packages"]:
        package_root = rooted(root, ".aepm/packages/" + ref["digest"])
        manifest = validate_component(load(package_root / "component.json"))
        payloads = {item["path"]: rooted(package_root, item["path"]).read_bytes() for item in manifest["files"]}
        receipts = root / ".aepm/receipts" / ref["digest"]
        release = verify((receipts / "release.json").read_bytes(), (receipts / "release.sig").read_bytes(), "release", Path(policy))
        identity = manifest["identity"]
        if any(release[key] != ref[key] for key in ("name", "version", "digest")) or any(identity[key] != ref[key] for key in ("name", "version")):
            fail("retained-identity", "packages")
        if source_tree_digest(manifest, payloads) != release["sourceTreeDigest"] or identity["sourceTreeDigest"] != release["sourceTreeDigest"]:
            fail("retained-source", "packages")
        files = {item["path"] for item in snapshot(package_root) if item["kind"] == "file"}
        if files != set(payloads) | {"component.json"}:
            fail("retained-membership", "packages")
        for item in manifest["files"]:
            validate_extracted_mode(rooted(package_root, item["path"]), item["executable"])
        manifests[ref["digest"]] = manifest
    by_name = {item["name"]: item for item in assembly["lock"]["packages"]}
    for ref in assembly["lock"]["packages"]:
        dependencies = []
        for requirement in manifests[ref["digest"]]["dependencies"]:
            dependency = by_name.get(requirement["name"])
            if dependency is None or dependency["version"] != requirement["version"]:
                fail("retained-dependencies", "lock")
            dependencies.append({"name": dependency["name"], "digest": dependency["digest"]})
        if ref["dependencies"] != sorted(dependencies, key=lambda item: item["name"]):
            fail("retained-dependencies", "lock")
    validate_retained_assembly(root, assembly, manifests)
    return assembly, manifests


def run(argv, cwd, environment, timeout, output_limit=OUTPUT_LIMIT, **options):
    from .process import run as contained_run
    return contained_run(argv, cwd, environment, timeout, output_limit, **options)


def execution_environment(home, tools, *, tool_selection=None):
    tool_selection = require_selection(tool_selection)
    if os.name == "nt":
        from .contextual import tool_environment
        from .model import AepmError
        try:
            return tool_environment(home, tools, [])
        except AepmError:
            return None
    home.mkdir()
    bin_path = home / "bin"
    bin_path.mkdir()
    for name in tools:
        if "/" in name or "\\" in name:
            fail("tool-name", "tools")
        if tool_selection is not None:
            from .model import AepmError
            try:
                executable = tool_selection.canonical(name)
            except AepmError as error:
                if error.code == "tool-unavailable":
                    return None
                raise
        else:
            executable = shutil.which(name)
            if executable is None:
                return None
        (bin_path / name).symlink_to(Path(executable).resolve())
    tail = tool_selection.path if tool_selection is not None else os.defpath
    environment = {"PATH": str(bin_path) + os.pathsep + tail, "HOME": str(home), "AEPM_PRIVATE_ROOT": str(home.parent),
            "TMPDIR": str(home), "XDG_CACHE_HOME": str(home / "cache"), "XDG_CONFIG_HOME": str(home / "config"),
            "npm_config_cache": str(home / "npm"), "npm_config_userconfig": str(home / "npmrc"),
            "GRADLE_USER_HOME": str(home / "gradle"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "CI": "true", "PYTHONDONTWRITEBYTECODE": "1"}
    if tool_selection is not None:
        check_links(home, tools, tool_selection)
    return environment


def check_links(home, tools, tool_selection):
    for name in tools:
        tool_selection.check(name, os.readlink(home / "bin" / name), tool_selection.path)


def execute_suite(suite, source, allow_network, logs, *, tool_selection=None, adoption_root=None):
    tool_selection = require_selection(tool_selection)
    adoption = {} if adoption_root is None else {"adoption_root": adoption_root}
    status, code, reason, seconds = "blocked", None, "", 0
    events = []
    output_remaining = OUTPUT_LIMIT
    if suite["requirements"]:
        reason = "external-prerequisites-unavailable:" + ",".join(sorted(suite["requirements"]))
    elif suite["scope"] == "deployed":
        reason = "deployed-environment-not-authorized"
    elif suite["network"] and not allow_network:
        reason = "network-not-authorized"
    if not reason:
        workspace = VerificationDirectory(prefix="aepm-verification-")
        with workspace as directory:
            private = Path(directory).resolve()
            snapshot(source)
            shutil.copytree(source, private / "root")
            root = private / "root"
            environment = execution_environment(private / "home", suite["tools"], tool_selection=tool_selection)
            if environment is None:
                reason = "tool-unavailable"
            if environment is not None:
                for name, expected_version in suite["tools"].items():
                    version_flag = "-version" if name in ("java", "javac", "swift", "xcodebuild", "kotlinc") else "--version"
                    if tool_selection is not None:
                        check_links(private / "home", suite["tools"], tool_selection)
                    tool_code, _, tool_reason, version_output = run([name, version_flag], root, environment, 10, 65536)
                    if tool_reason == "cleanup-failed":
                        workspace.preserve = True
                        status, reason = "failed", "cleanup-failed"
                        break
                    if tool_code != 0 or tool_reason:
                        reason = "tool-version-unavailable"
                        break
                    versions = re.findall(r"(?<![0-9])([0-9]+(?:\.[0-9]+)*)", version_output.decode("utf-8", errors="replace"))
                    if not any(value == expected_version or value.startswith(expected_version + ".") for value in versions):
                        reason = "tool-version-mismatch"
                        break
            for name in [*suite["fixtures"], *suite["locks"]]:
                if not rooted(root, name).exists():
                    fail("verification-input", name)
            steps = [*suite["prepare"], {"argv": suite["argv"], "cwd": suite["cwd"], "network": suite["network"]}]
            for index, step in enumerate(steps):
                if reason:
                    break
                if step["network"] and not allow_network:
                    reason = "preparation-network-not-authorized"
                    break
                cwd = rooted(root, step["cwd"], dot=True)
                if not cwd.is_dir():
                    fail("verification-cwd", "verification")
                argv = list(step["argv"])
                if "/" in argv[0]:
                    executable = rooted(cwd, argv[0][2:] if argv[0].startswith("./") else argv[0])
                    if not executable.is_file():
                        reason = "tool-unavailable"
                        break
                    argv[0] = str(executable)
                elif argv[0] not in suite["tools"]:
                    reason = "undeclared-tool"
                    break
                if tool_selection is not None:
                    check_links(private / "home", suite["tools"], tool_selection)
                code, duration, failure, output = run(argv, cwd, environment, suite["timeoutSeconds"], output_remaining, **adoption)
                if failure == "cleanup-failed":
                    workspace.preserve = True
                output_remaining -= len(output)
                seconds += duration
                # Only scrubbed-environment output is retained; no real credentials are supplied.
                log_digest = digest(output)
                logs.mkdir(parents=True, exist_ok=True)
                immutable_blob(logs / (log_digest + ".log"), output)
                events.append({"step": index, "preparation": index < len(steps) - 1,
                               "seconds": duration, "exitCode": code, "reason": failure, "logDigest": log_digest})
                if failure or code != 0:
                    reason = failure or ("preparation-failed" if index < len(steps) - 1 else "nonzero-exit")
                    status = "failed" if index == len(steps) - 1 or failure == "cleanup-failed" else "blocked"
                    break
            else:
                status = "passed"
            if workspace.preserve:
                events.append({"step": "retained-private-root", "preparation": False, "seconds": 0,
                               "exitCode": None, "reason": "cleanup-failed", "path": str(private)})
    evidence = canonical(events)
    log_digest = digest(evidence)
    logs.mkdir(parents=True, exist_ok=True)
    immutable_blob(logs / (log_digest + ".json"), evidence)
    return {"package": suite["package"], "id": suite["id"], "scope": suite["scope"], "status": status,
            "exitCode": code, "seconds": seconds, "reason": reason, "logDigest": log_digest}


def make_report(lock, assembly_digest, manifests, roots, application_root, policy, trusted, allow_network, context, logs, *,
                tool_selection=None, adoption_root=None, **execution_options):
    from .private_process import adoption_root as validate_adoption_root
    tool_selection = require_selection(tool_selection)
    adoption_root = validate_adoption_root(adoption_root)
    adoption = {} if adoption_root is None else {"adoption_root": adoption_root}
    from .authorization import bindings
    from .contextual import execute, evidence_record
    from .environment import Execution, clock
    from .trust import load_policy
    if trusted is not True:
        fail("trusted-execution-required", "trusted")
    policy_data = load_policy(Path(policy))
    if not set(ref["digest"] for ref in lock["packages"]).issubset(set(policy_data["trustedExecution"])):
        fail("untrusted-package-execution", "policy")
    suites = declarations(lock["packages"], manifests, context)
    use_context = any("execution" in suite for suite in suites) or any(execution_options.values())
    execution = Execution({**bindings(lock, assembly_digest, manifests, context), "context": context}, policy, logs.parent,
                          forbidden_roots=[*roots.values(), logs.parent, *([application_root] if application_root else [])],
                          **execution_options) if use_context else None
    results, records = [], []
    for suite in suites:
        source = roots[suite["package"]] if suite["root"] == "package" else application_root
        if "execution" in suite:
            result, record = execute(suite, source, allow_network, logs, execution, tool_selection=tool_selection, **adoption)
        else:
            started = clock()
            result = execute_suite(suite, source, allow_network, logs, tool_selection=tool_selection, **adoption)
            record = evidence_record(suite)
            if result["status"] == "passed" or result["status"] == "failed" and result["exitCode"] is not None:
                record.update(kind="local", startedAt=started, completedAt=clock(), phase="complete", checkStarted=True)
            if result["reason"] == "cleanup-failed":
                record["cleanup"] = {"required": True, "attempted": True, "completed": False, "reason": "cleanup-failed"}
            for prerequisite in record["prerequisites"]:
                prerequisite["reason"] = "unsupported-prerequisite"
        results.append(result)
        records.append(record)
    report = {"format": 1, "context": context, "lockDigest": digest(canonical(lock)), "assemblyDigest": assembly_digest,
            "packages": package_records(lock), "suiteSetDigest": digest(canonical(suites)), "suites": results,
            "summary": summary(results)}
    return execution.publish(report, records) if execution else report


def transaction_path(root):
    root = Path(root).absolute()
    return root.parent / ("." + root.name + ".aepm-transaction")


@guarded
def verify_application(root: Path, policy: Path, trusted: bool, *, allow_network: bool = False,
                       execution_context=None, authorization=None, execution_state=None, secrets=None, allow_live=False,
                       tool_selection=None, adoption_root=None) -> Report:
    from .private_process import adoption_root as validate_adoption_root
    require_selection(tool_selection)
    adoption_root = validate_adoption_root(adoption_root)
    root = Path(root)
    assembly, manifests = retained_manifests(root, policy)
    evidence = transaction_path(root) / "verification"
    if evidence.parent.is_symlink() or evidence.is_symlink():
        fail("symlink", "verification")
    report = make_report(assembly["lock"], digest(canonical(assembly)), manifests,
                         {key: root / ".aepm/packages" / key for key in manifests}, root, policy, trusted,
                         allow_network, "application", evidence / "logs", tool_selection=tool_selection, adoption_root=adoption_root, execution_context=execution_context,
                         authorization=authorization, execution_state=execution_state, secrets=secrets, allow_live=allow_live)
    write(evidence / (digest(canonical(report)) + ".json"), report)
    return report


@guarded
def review_package(ref, store: Path, policy: Path, trusted: bool, *, allow_network: bool = False,
                   execution_context=None, authorization=None, execution_state=None, secrets=None, allow_live=False,
                   tool_selection=None, adoption_root=None) -> Report:
    from .bundle import extract_review, read_package, resolve
    from .private_process import adoption_root as validate_adoption_root

    require_selection(tool_selection)
    adoption_root = validate_adoption_root(adoption_root)

    if trusted is not True:
        fail("trusted-execution-required", "trusted")
    store = Path(store)
    manifest, _ = read_package(ref, store)
    lock = resolve([{key: ref[key] for key in ("name", "version")}], store / "catalogue.json",
                   "review/" + ref["name"], digest(canonical(manifest)))
    refs = [{key: item[key] for key in ("name", "version", "digest")} for item in lock["packages"]]
    with tempfile.TemporaryDirectory(prefix="aepm-review-") as directory:
        roots, manifests = {}, {}
        for item in refs:
            root = Path(directory).resolve() / item["digest"]
            manifests[item["digest"]] = extract_review(item, store, root, Path(policy))
            roots[item["digest"]] = root
        report = make_report(lock, digest(canonical({"packages": refs})), manifests, roots, None, policy, trusted,
                             allow_network, "review", store / "logs", tool_selection=tool_selection, adoption_root=adoption_root, execution_context=execution_context,
                             authorization=authorization, execution_state=execution_state, secrets=secrets, allow_live=allow_live)
    report_path = store / "reports" / (digest(canonical(report)) + ".json")
    if report_path.exists() and load(report_path) != report:
        fail("immutable-report", "report")
    write(report_path, report)
    return report
