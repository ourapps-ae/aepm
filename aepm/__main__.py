"""Frozen local installer commands."""

import argparse
import os
from pathlib import Path
import shutil
import sys

from .application import assemble, read_assembly, requirements, validate_definition
from .bundle import pack, read_package, resolve
from .export import export_design
from .io import fail, load, write
from .model import AepmError, canonical, digest
from .trust import sign
from .verification import review_package, verify_application


class Parser(argparse.ArgumentParser):
    def error(self, message):
        fail("arguments", "command")


def parser():
    root = Parser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    specifications = {
        "pack": ("source", ("store",)), "inspect": ("digest", ("store",)),
        "resolve": ("definition", ("catalogue", "out")), "sign": ("statement", ("role", "key", "out")),
        "install": ("definition", ("lock", "store", "policy", "target")),
        "verify": ("app", ("policy",)), "review": ("digest", ("store", "policy")),
        "export": ("app", ("out",)), "propose-update": ("app definition", ("store", "policy", "out")),
        "approve": ("proposal", ("key", "policy", "out")), "apply": ("app proposal", ("approval", "policy")),
        "recover": ("app", ()),
    }
    for command, (positions, flags) in specifications.items():
        child = commands.add_parser(command)
        for position in positions.split():
            child.add_argument(position)
        for flag in flags:
            child.add_argument("--" + flag, required=True)
        if command in ("verify", "review", "propose-update"):
            child.add_argument("--trusted", action="store_true")
            child.add_argument("--allow-network", action="store_true")
            for option in ("context", "authorization", "execution-state", "secrets"):
                child.add_argument("--" + option, type=Path)
            child.add_argument("--allow-live", action="store_true")
    request = commands.add_parser("execution-request")
    target = request.add_mutually_exclusive_group(required=True)
    target.add_argument("--app", type=Path)
    target.add_argument("--review")
    request.add_argument("--store", type=Path)
    for option in ("context", "policy", "execution-state", "out"):
        request.add_argument("--" + option, type=Path, required=True)
    request.add_argument("--expires-at", type=int, required=True)
    request.add_argument("--suite", action="append")
    authorize = commands.add_parser("authorize-execution")
    authorize.add_argument("request", type=Path)
    for option in ("key", "policy", "out"):
        authorize.add_argument("--" + option, type=Path, required=True)
    return root


def reference(archive_digest, store):
    catalogue = load(Path(store) / "catalogue.json")
    matches = [item for item in catalogue["entries"] if item["digest"] == archive_digest]
    if len(matches) != 1:
        fail("unknown-package", "digest")
    return matches[0]


def dispatch(args):
    command = args.command
    if os.name == "nt" and command in ("pack", "propose-update", "approve", "apply", "recover"):
        fail("unsupported-host", command)
    execution_options = {}
    if command in ("verify", "review", "propose-update"):
        execution_options = {"execution_context": args.context, "authorization": args.authorization,
                             "execution_state": args.execution_state, "secrets": args.secrets, "allow_live": args.allow_live}
    if command == "execution-request":
        from .authorization import execution_request
        if args.review is not None and args.store is None:
            fail("arguments", "store")
        selected_pairs = None
        if args.suite is not None:
            selected_pairs = []
            for value in args.suite:
                package, separator, identifier = value.partition(":")
                if not separator or not package or not identifier:
                    fail("invalid-selection", "suite")
                selected_pairs.append({"package": package, "id": identifier})
        return execution_request(app=args.app, ref=reference(args.review, args.store) if args.review else None,
                                 store=args.store, context=args.context, policy=args.policy,
                                 execution_state=args.execution_state, expires_at=args.expires_at, out=args.out, selected_pairs=selected_pairs)
    if command == "authorize-execution":
        from .authorization import authorize_execution
        return authorize_execution(args.request, args.key, args.policy, args.out)
    if command == "pack":
        return pack(Path(args.source), Path(args.store))
    if command == "inspect":
        return read_package(reference(args.digest, args.store), Path(args.store))[0]
    if command == "resolve":
        definition = validate_definition(load(args.definition))
        result = resolve(requirements(definition), Path(args.catalogue), definition["id"], digest(canonical(definition)))
        write(args.out, result)
        return result
    if command == "sign":
        signature = sign(load(args.statement), args.role, Path(args.key))
        output = Path(args.out)
        if output.is_symlink():
            fail("symlink", "signature")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(signature)
        return {"signature": str(output)}
    if command == "install":
        return assemble(validate_definition(load(args.definition)), load(args.lock), Path(args.store), Path(args.target), Path(args.policy))
    if command == "verify":
        return verify_application(Path(args.app), Path(args.policy), args.trusted, allow_network=args.allow_network, **execution_options)
    if command == "review":
        return review_package(reference(args.digest, args.store), Path(args.store), Path(args.policy), args.trusted, allow_network=args.allow_network, **execution_options)
    if command == "export":
        return export_design(read_assembly(Path(args.app)), Path(args.out))
    if command == "propose-update":
        from .update import propose
        result = propose(Path(args.app), validate_definition(load(args.definition)), Path(args.store), Path(args.policy), args.trusted,
                         allow_network=args.allow_network, **execution_options)
        write(args.out, result)
        return result
    if command == "approve":
        from .update import approve
        source = approve(Path(args.proposal), Path(args.key), Path(args.policy))
        destination = Path(args.out)
        if source.absolute() != destination.absolute():
            if destination.exists() or destination.is_symlink():
                fail("approval-output-exists", "approval")
            shutil.copytree(source, destination)
        return {"statement": str(destination / "owner.json"), "signature": str(destination / "owner.sig")}
    if command == "apply":
        from .update import apply
        return apply(Path(args.app), Path(args.proposal), Path(args.approval), Path(args.policy))
    from .update import recover
    return recover(Path(args.app))


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        result = dispatch(args)
        print(canonical({"ok": True, "result": result}).decode("utf-8"))
        return int(args.command in ("verify", "review") and result["summary"]["required-local"] != "passed")
    except AepmError as error:
        print(canonical({"ok": False, "error": {"code": error.code, "path": error.path}}).decode("utf-8"))
    except (OSError, ValueError, KeyError, TypeError):
        print(canonical({"ok": False, "error": {"code": "invalid-input-or-filesystem", "path": "command"}}).decode("utf-8"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
