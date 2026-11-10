"""Whole-tree owner-approved replacement with a durable sibling journal."""

from contextlib import contextmanager
import os
from pathlib import Path
import shutil

from .application import assemble, read_assembly, requirements, validate_definition
from .io import exact, fail, fields, load, rooted, snapshot, sync_directory, write
from .model import AepmError, Assembly, Proposal, canonical, digest, guarded
from .verification import check_report, retained_manifests, transaction_path, verify_application


from .trust import UPDATE_BINDINGS as BINDINGS


@contextmanager
def transaction(root):
    if os.name == "nt":
        fail("unsupported-host", "update")
    import fcntl
    root = Path(root).absolute()
    for path in (root.parent, *root.parent.parents):
        if path.is_symlink() or not path.is_dir():
            fail("ordinary-parent", "application")
    directory = transaction_path(root)
    if directory.is_symlink():
        fail("symlink", "transaction")
    directory.mkdir(exist_ok=True)
    lock = directory / "lock"
    if lock.is_symlink():
        fail("symlink", "transaction")
    with lock.open("a+b") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("transaction-busy", "transaction")
        try:
            yield directory
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def tree_digest(root, assembly):
    return digest(canonical(snapshot(root, assembly)))


@guarded
def propose(root: Path, definition, store: Path, policy: Path, trusted: bool, *, allow_network: bool = False,
            execution_context=None, authorization=None, execution_state=None, secrets=None, allow_live=False,
            tool_selection=None, adoption_root=None) -> Proposal:
    from .bundle import resolve
    from .private_process import adoption_root as validate_adoption_root
    from .tool_selection import require_selection

    require_selection(tool_selection)
    adoption_root = validate_adoption_root(adoption_root)

    root = Path(root).absolute()
    definition = validate_definition(definition)
    if trusted is not True:
        fail("trusted-execution-required", "trusted")
    with transaction(root) as directory:
        if (directory / "journal.json").exists() or (directory / "backup").exists():
            fail("pending-recovery-or-cleanup", "transaction")
        previous, old_manifests = retained_manifests(root, policy)
        before = snapshot(root, previous)
        if definition["id"] != previous["application"]:
            fail("application-mismatch", "definition")
        lock = resolve(requirements(definition), Path(store) / "catalogue.json", definition["id"], digest(canonical(definition)))
        old_refs = {item["name"]: item for item in previous["lock"]["packages"]}
        for ref in lock["packages"]:
            if ref["name"] not in old_refs:
                continue
            old_ref = old_refs[ref["name"]]
            old, new = exact(old_ref["version"]), exact(ref["version"])
            policy_name = old_manifests[old_ref["digest"]]["upgrade"]["policy"]
            if new < old or new[:2] != old[:2] or (policy_name == "none" and new != old):
                fail("update-policy", "packages")
        stage = directory / "stage"
        if stage.exists():
            snapshot(stage)
            shutil.rmtree(stage)
        next_assembly = assemble(definition, lock, Path(store), stage, Path(policy))
        stage.chmod(root.stat().st_mode & 0o7777)
        old_owned = {item["path"] for item in previous["files"]}
        new_owned = {item["path"] for item in next_assembly["files"]}
        old_directories = {str(parent) for path in old_owned for parent in Path(path).parents if str(parent) != "."}
        # Preserve every unmanaged file and directory; never adopt an unmanaged collision.
        for record in before:
            path = record["path"]
            if path in (".", ".aepm") or path.startswith(".aepm/") or path in old_owned:
                continue
            collision = any(path.casefold() == owned.casefold() or path.casefold().startswith(owned.casefold() + "/")
                            or ((record["kind"] == "file" or path not in old_directories)
                                and owned.casefold().startswith(path.casefold() + "/")) for owned in new_owned)
            if collision:
                fail("unmanaged-collision", path)
            destination = rooted(stage, path)
            if record["kind"] == "directory":
                destination.mkdir(parents=True, exist_ok=True)
                destination.chmod(record["mode"])
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / path, destination)
        # Unmanaged metadata also survives unless the installer now owns that exact path.
        new_metadata = {item["path"] for item in snapshot(stage) if item["path"].startswith(".aepm/")}
        old_generated_metadata = {".aepm/lock.json", ".aepm/assembly.json", ".aepm/definition.json"}
        for ref in previous["lock"]["packages"]:
            old_generated_metadata.add(".aepm/archives/" + ref["digest"] + ".tar")
            receipt = root / ".aepm/receipts" / ref["digest"] / "guardian.dsse.json"
            if receipt.exists():
                from .trust import review_report_digest
                report_digest = review_report_digest(receipt, Path(policy))
                old_generated_metadata.add(".aepm/evidence/reports/" + report_digest + ".json")
                retained_report = load(root / ".aepm/evidence/reports" / (report_digest + ".json"))
                if retained_report["format"] == 2:
                    for name, key in (("contexts", "contextDigest"), ("authorizations", "authorizationDigest"), ("execution-evidence", "evidenceDigest")):
                        value = retained_report["execution"][key]
                        if value is not None:
                            old_generated_metadata.add(".aepm/evidence/" + name + "/" + value + ".json")
            prefix = ".aepm/packages/" + ref["digest"]
            old_generated_metadata.update(item["path"] for item in before if item["path"] == prefix or item["path"].startswith(prefix + "/"))
            prefix = ".aepm/receipts/" + ref["digest"]
            old_generated_metadata.update(item["path"] for item in before if item["path"] == prefix or item["path"].startswith(prefix + "/"))
        for record in before:
            path = record["path"]
            if not path.startswith(".aepm/") or path in old_generated_metadata:
                continue
            if record["kind"] == "directory":
                target = rooted(stage, path)
                if target.is_file():
                    fail("unmanaged-collision", path)
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(record["mode"])
                continue
            if path in new_metadata:
                fail("unmanaged-collision", path)
            target = rooted(stage, path)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / path, target)
        report = verify_application(stage, Path(policy), trusted, allow_network=allow_network, tool_selection=tool_selection,
                                    adoption_root=adoption_root,
                                    execution_context=execution_context, authorization=authorization,
                                    execution_state=execution_state, secrets=secrets, allow_live=allow_live)
        evidence = transaction_path(stage) / "verification"
        for name in ("contexts", "authorizations", "execution-evidence", "reports"):
            if (evidence / name).exists():
                shutil.copytree(evidence / name, directory / name, dirs_exist_ok=True)
        _, manifests = retained_manifests(stage, policy)
        check_report(report, lock, digest(canonical(next_assembly)), manifests, evidence_root=directory, policy=policy, adoption=True)
        if snapshot(root, previous) != before:
            fail("snapshot-changed", "application")
        write(directory / "report.json", report)
        previous_files = {item["path"]: item["digest"] for item in previous["files"]}
        next_files = {item["path"]: item["digest"] for item in next_assembly["files"]}
        changes = [{"path": path, "before": previous_files.get(path), "after": next_files.get(path)}
                   for path in sorted(previous_files.keys() | next_files.keys()) if previous_files.get(path) != next_files.get(path)]
        proposal = {"format": 1, "application": definition["id"], "previousLockDigest": digest(canonical(previous["lock"])),
                    "nextLockDigest": digest(canonical(lock)), "configurationDigest": digest(canonical(next_assembly["configuration"])),
                    "designDigest": digest(canonical(next_assembly["design"])), "assemblyDigest": digest(canonical(next_assembly)),
                    "reportDigest": digest(canonical(report)), "snapshotDigest": digest(canonical(before)),
                    "stageDigest": tree_digest(stage, next_assembly), "stage": str(stage), "changes": changes}
        write(directory / "proposal.json", proposal)
        return proposal


def proposal_context(path):
    proposal = load(path)
    fields(proposal, ("format", *BINDINGS, "stage", "changes"))
    stage = Path(proposal["stage"])
    directory = stage.parent
    suffix = ".aepm-transaction"
    if not stage.is_absolute() or stage.name != "stage" or not directory.name.startswith(".") or not directory.name.endswith(suffix):
        fail("proposal-stage", "proposal")
    root = directory.parent / directory.name[1:-len(suffix)]
    if transaction_path(root) != directory or proposal != load(directory / "proposal.json"):
        fail("proposal-copy", "proposal")
    return root, directory, proposal


def validate_proposal(root, directory, proposal, policy):
    previous = read_assembly(root)
    stage = directory / "stage"
    assembly, manifests = retained_manifests(stage, policy)
    if not {item["digest"] for item in assembly["lock"]["packages"]}.issubset(set(load(policy)["trustedExecution"])):
        fail("untrusted-package-execution", "policy")
    report = load(directory / "report.json")
    check_report(report, assembly["lock"], digest(canonical(assembly)), manifests, evidence_root=directory, policy=policy, adoption=True)
    values = {"application": assembly["application"], "previousLockDigest": digest(canonical(previous["lock"])),
              "nextLockDigest": digest(canonical(assembly["lock"])), "assemblyDigest": digest(canonical(assembly)),
              "configurationDigest": digest(canonical(assembly["configuration"])), "designDigest": digest(canonical(assembly["design"])),
              "reportDigest": digest(canonical(report)), "snapshotDigest": tree_digest(root, previous),
              "stageDigest": tree_digest(stage, assembly)}
    if any(proposal[key] != values[key] for key in BINDINGS):
        fail("proposal-stale", "proposal")
    return assembly, previous


@guarded
def approve(proposal: Path, private_key: Path, policy: Path) -> Path:
    from .trust import UPDATE_APPROVAL, approval_statement, sign, verify

    root, directory, value = proposal_context(proposal)
    with transaction(root):
        validate_proposal(root, directory, value, policy)
        envelope = sign(approval_statement(digest(canonical(value)), value), "owner", Path(private_key))
        try:
            verify(canonical(envelope), "owner", Path(policy), UPDATE_APPROVAL)
        except AepmError:
            fail("owner-key", "policy")
        output = directory / "approval.dsse.json"
        write(output, envelope)
        return output


def journal(directory, value, phase):
    value["phase"] = phase
    write(directory / "journal.json", value)


def rename(source, destination):
    os.rename(source, destination)
    sync_directory(Path(source).parent)
    if Path(source).parent != Path(destination).parent:
        sync_directory(Path(destination).parent)


@guarded
def apply(root: Path, proposal: Path, approval: Path, policy: Path) -> Assembly:
    from .trust import UPDATE_APPROVAL, verify

    root = Path(root).absolute()
    expected_root, directory, value = proposal_context(proposal)
    if root != expected_root:
        fail("proposal-root", "application")
    with transaction(root):
        if (directory / "journal.json").exists() or (directory / "backup").exists():
            fail("pending-recovery-or-cleanup", "transaction")
        assembly, previous = validate_proposal(root, directory, value, policy)
        from .bundle import ordinary_path
        approval = Path(approval)
        ordinary_path(approval)
        statement, _ = verify(approval.read_bytes(), "owner", Path(policy), UPDATE_APPROVAL)
        if (any(statement["predicate"][key] != value[key] for key in BINDINGS)
                or statement["subject"][0]["digest"]["sha256"] != digest(canonical(value))):
            fail("owner-binding", "approval")
        state = {"format": 1, "root": str(root), "snapshotDigest": value["snapshotDigest"], "stageDigest": value["stageDigest"],
                 "proposalDigest": digest(canonical(value)), "oldAssembly": previous, "newAssembly": assembly}
        stage, backup = directory / "stage", directory / "backup"
        journal(directory, state, "prepared")
        validate_proposal(root, directory, value, policy)
        journal(directory, state, "moving-old")
        rename(root, backup)
        journal(directory, state, "old-moved")
        if tree_digest(backup, previous) != value["snapshotDigest"] or tree_digest(stage, assembly) != value["stageDigest"]:
            fail("transaction-tree-changed", "transaction")
        journal(directory, state, "moving-new")
        rename(stage, root)
        journal(directory, state, "new-moved")
        if tree_digest(root, assembly) != value["stageDigest"] or tree_digest(backup, previous) != value["snapshotDigest"]:
            fail("transaction-tree-changed", "transaction")
        journal(directory, state, "committed")
        return assembly


@guarded
def recover(root: Path) -> Assembly:
    root = Path(root).absolute()
    with transaction(root) as directory:
        state = load(directory / "journal.json")
        if state.get("root") != str(root):
            fail("journal-root", "journal")
        backup, stage = directory / "backup", directory / "stage"
        previous, next_assembly = state["oldAssembly"], state["newAssembly"]
        old_digest, new_digest = state["snapshotDigest"], state["stageDigest"]
        if state["phase"] == "committed":
            if not root.exists() or tree_digest(root, next_assembly) != new_digest or not backup.exists() or tree_digest(backup, previous) != old_digest:
                fail("recovery-ambiguous", "transaction")
            return read_assembly(root)
        if stage.exists() and tree_digest(stage, next_assembly) != new_digest:
            fail("recovery-stage-changed", "transaction")
        if backup.exists():
            if tree_digest(backup, previous) != old_digest:
                fail("recovery-backup-changed", "transaction")
            if root.exists():
                if stage.exists() or tree_digest(root, next_assembly) != new_digest or (directory / "failed-new").exists():
                    fail("recovery-root-changed", "transaction")
                rename(root, directory / "failed-new")
            rename(backup, root)
        elif not root.exists() or tree_digest(root, previous) != old_digest:
            fail("recovery-ambiguous", "transaction")
        journal(directory, state, "restored")
        return read_assembly(root)
