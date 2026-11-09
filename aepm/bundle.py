"""Deterministic allowlisted archives and exact dependency acquisition."""

from __future__ import annotations

import copy
import io
import os
import re
from pathlib import Path
import stat
import tarfile
import tempfile
from typing import BinaryIO, cast

from .model import (AepmError, Component, Lock, PackageRef, Requirement, array,
                    canonical, digest, fail, fields, guarded, loads, package_ref, read_json,
                    requirement, safe_path, sha256, unique, validate_component,
                    validate_lock)

MAX_FILE = 64 * 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MEMBERS = 100_000


def ordinary_path(path: Path, *, missing: bool = False) -> None:
    """Reject links in every existing path segment."""
    absolute = path.absolute()
    for part in (*reversed(absolute.parents), absolute):
        try:
            info = part.lstat()
            mode = info.st_mode
        except FileNotFoundError:
            if missing:
                continue
            fail("missing-path", str(path))
        except OSError:
            fail("read-failed", str(path))
        if (getattr(info, "st_file_attributes", 0) & 0x400
                or stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
            fail("unsafe-file", str(path))


@guarded
def validate_extracted_mode(path: Path, executable: bool) -> None:
    """Check extracted files against an already verified archive declaration."""
    from .model import boolean
    boolean(executable, "executable")
    ordinary_path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("unsafe-file", str(path))
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != (0o755 if executable else 0o644):
        fail("mode-mismatch", str(path))


def allowed_path(path: str) -> None:
    safe_path(path)
    banned = {".git", ".aepm", "node_modules", "__pycache__", ".gradle", "deriveddata", "local.properties"}
    parts = path.casefold().split("/")
    if any(p in banned or p.startswith(".env") for p in parts):
        fail("excluded-path", path)
    if parts[-1].endswith((".pem", ".key", ".p12", ".pfx", ".cer", ".crt", ".keystore", ".jks", ".tar", ".tgz", ".zip")):
        fail("excluded-path", path)


def check_paths(paths: list[str]) -> None:
    unique(paths, "archive", folded=True)
    spellings = {}
    files = set(paths)
    for path in paths:
        safe_path(path)
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            key = prefix.casefold()
            if key in spellings and spellings[key] != prefix:
                fail("case-collision", path)
            spellings[key] = prefix
            if i < len(parts) and prefix in files:
                fail("path-collision", path)


def validate_windows_paths(paths: list[str]) -> None:
    """Reject archive names with Windows device or normalization semantics."""
    check_paths(paths)
    for path in paths:
        for part in path.split("/"):
            stem = part.split(".", 1)[0].rstrip(" ")
            if (part.endswith((".", " ")) or re.search(r'[<>"|?*]', part)
                    or re.fullmatch(r"(?i:con|prn|aux|nul|conin\$|conout\$|clock\$|com[0-9¹²³]|lpt[0-9¹²³])", stem)):
                fail("unsafe-windows-path", path)


def source_tree_digest(component: Component, payloads: dict[str, bytes]) -> str:
    manifest = copy.deepcopy(component)
    del manifest["identity"]["sourceTreeDigest"]
    modes = {item["path"]: 0o755 if item["executable"] else 0o644 for item in component["files"]}
    modes["component.json"] = 0o644
    records = [{"path": p, "mode": modes[p],
                "sha256": digest(canonical(manifest) if p == "component.json" else payloads[p])}
               for p in sorted(modes)]
    return digest(canonical(records))


def catalogue_entries(path: Path) -> list[PackageRef]:
    ordinary_path(path)
    value = fields(read_json(path), "format entries", "catalogue")
    if type(value["format"]) is not int or value["format"] != 1:
        fail("invalid-format", "catalogue")
    entries = array(value["entries"], "catalogue.entries")
    for entry in entries:
        package_ref(entry)
    unique([(p["name"], p["version"]) for p in entries], "catalogue.entries")
    return entries


def atomic_write(path: Path, data: bytes) -> None:
    ordinary_path(path, missing=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        fail("write-failed", str(path))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@guarded
def pack(source: Path, store: Path) -> PackageRef:
    if os.name == "nt":
        fail("unsupported-host", "pack")
    ordinary_path(source)
    ordinary_path(store, missing=True)
    ordinary_path(source / "component.json")
    component = validate_component(read_json(source / "component.json"))
    paths = ["component.json"] + [f["path"] for f in component["files"]]
    if len(paths) > MAX_MEMBERS:
        fail("member-limit", "files")
    check_paths(paths)
    payloads = {}
    total = 0
    for item in component["files"]:
        p = item["path"]
        allowed_path(p)
        file = source / p
        ordinary_path(file)
        if file.resolve().is_relative_to(store.resolve()):
            fail("store-listed", p)
        if not file.is_file():
            fail("not-file", p)
        if file.stat().st_nlink != 1:
            fail("unsafe-file", p)
        if file.stat().st_size > MAX_FILE:
            fail("file-limit", p)
        # Source execute bits must agree; write bits are normalized.
        if bool(file.stat().st_mode & 0o111) != item["executable"]:
            fail("mode-mismatch", p)
        data = file.read_bytes()
        if any(marker in data for marker in (
                b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----",
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----")):
            fail("private-key", p)
        total += len(data)
        if total > MAX_ARCHIVE:
            fail("archive-limit", "files")
        payloads[p] = data
    component["identity"]["sourceTreeDigest"] = source_tree_digest(component, payloads)
    payloads["component.json"] = canonical(component)
    if len(payloads["component.json"]) > 1024 * 1024:
        fail("metadata-limit", "component.json")
    modes = {i["path"]: 0o755 if i["executable"] else 0o644 for i in component["files"]}
    modes["component.json"] = 0o644
    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for p in sorted(payloads):
                info = tarfile.TarInfo(p)
                info.size, info.mode = len(payloads[p]), modes[p]
                archive.addfile(info, io.BytesIO(payloads[p]))
    except (ValueError, OSError):
        fail("invalid-archive-path", "files")
    data = output.getvalue()
    if len(data) > MAX_ARCHIVE:
        fail("archive-limit", "files")
    ref: PackageRef = {"name": component["identity"]["name"], "version": component["identity"]["version"], "digest": digest(data)}
    store.mkdir(parents=True, exist_ok=True)
    lock_path = store / ".catalogue-lock"
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        fail("store-busy", "catalogue")
    try:
        _publish_archive(ref, store, data)
    finally:
        os.close(descriptor)
        lock_path.unlink()
    return ref


def _publish_archive(ref: PackageRef, store: Path, data: bytes) -> None:
    catalogue = store / "catalogue.json"
    entries = catalogue_entries(catalogue) if catalogue.exists() else []
    for entry in entries:
        if (entry["name"], entry["version"]) == (ref["name"], ref["version"]):
            if entry != ref:
                fail("identity-rebinding", "catalogue")
            break
    else:
        entries.append(ref)
    object_path = store / "objects" / (ref["digest"] + ".tar")
    ordinary_path(object_path, missing=True)
    if object_path.exists():
        if object_path.read_bytes() != data:
            fail("object-rebinding", str(object_path))
    else:
        atomic_write(object_path, data)
    atomic_write(catalogue, canonical({"format": 1, "entries": sorted(entries, key=lambda e: (e["name"], e["version"]))}))


@guarded
def read_package(ref: PackageRef, store: Path) -> tuple[Component, dict[str, bytes]]:
    """Read and fully validate an archive without writing extracted files."""
    package_ref(ref)
    path = store / "objects" / (ref["digest"] + ".tar")
    ordinary_path(path)
    if path.stat().st_size > MAX_ARCHIVE:
        fail("archive-limit", str(path))
    data = path.read_bytes()
    if digest(data) != ref["digest"]:
        fail("archive-digest", str(path))
    payloads, modes = {}, {}
    order = []
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                p = safe_path(member.name)
                if p in payloads:
                    fail("duplicate-member", p)
                if not member.isfile() or member.type != tarfile.REGTYPE or member.pax_headers:
                    fail("unsafe-member", p)
                if member.size > MAX_FILE or member.size < 0:
                    fail("file-limit", p)
                if (member.uid or member.gid or member.mtime or member.uname or member.gname
                        or member.mode not in (0o644, 0o755)):
                    fail("archive-metadata", p)
                total += member.size
                if total > MAX_ARCHIVE or len(payloads) >= MAX_MEMBERS:
                    fail("archive-limit", p)
                stream = cast(BinaryIO, archive.extractfile(member))
                payloads[p] = stream.read()
                modes[p] = member.mode
                order.append(p)
    except (tarfile.TarError, OSError, ValueError):
        fail("invalid-archive", str(path))
    check_paths(order)
    if order != sorted(order):
        fail("unsorted-archive", str(path))
    if "component.json" not in payloads:
        fail("missing-manifest", str(path))
    c = validate_component(loads(payloads["component.json"], "component.json"))
    if payloads["component.json"] != canonical(c):
        fail("noncanonical-manifest", "component.json")
    if any(c["identity"][k] != ref[k] for k in ("name", "version")):
        fail("identity-mismatch", "component.json")
    expected = {f["path"]: 0o755 if f["executable"] else 0o644 for f in c["files"]}
    expected["component.json"] = 0o644
    if modes != expected:
        fail("membership-mismatch", "archive")
    for p in expected:
        allowed_path(p)
        if any(marker in payloads[p] for marker in (
                b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----",
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----")):
            fail("private-key", p)
    if source_tree_digest(c, payloads) != c["identity"]["sourceTreeDigest"]:
        fail("source-digest", "component.json")
    # Re-encoding also rejects hidden extended headers and nonzero trailing bytes.
    normalized = io.BytesIO()
    with tarfile.open(fileobj=normalized, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for p in sorted(payloads):
            info = tarfile.TarInfo(p)
            info.size, info.mode = len(payloads[p]), modes[p]
            archive.addfile(info, io.BytesIO(payloads[p]))
    if normalized.getvalue() != data:
        fail("noncanonical-archive", "archive")
    return c, payloads


@guarded
def resolve(requirements: list[Requirement], catalogue: Path,
            application: str, definition_digest: str) -> Lock:
    entries = catalogue_entries(catalogue)
    index = {(e["name"], e["version"]): e for e in entries}
    selected = {}
    pending = list(requirements)
    while pending:
        req = requirement(pending.pop(), "requirements")
        previous = selected.get(req["name"])
        if previous:
            if previous["version"] != req["version"]:
                fail("dependency-conflict", req["name"])
            continue
        ref = index.get((req["name"], req["version"]))
        if ref is None:
            fail("package-unavailable", req["name"])
        c, _ = read_package(ref, catalogue.parent)
        selected[req["name"]] = {**ref, "dependencies": c["dependencies"]}
        pending.extend(c["dependencies"])
    packages = []
    for name in sorted(selected):
        p = selected[name]
        packages.append({**p, "dependencies": sorted(
            [{"name": d["name"], "digest": selected[d["name"]]["digest"]} for d in p["dependencies"]],
            key=lambda d: d["name"])})
    return validate_lock({"format": 1, "application": application,
                          "definitionDigest": definition_digest, "packages": packages})


def _extract(ref: PackageRef, store: Path, destination: Path, policy: Path, review: bool) -> Component:
    from .trust import verify_package, verify_release
    c, payloads = read_package(ref, store)
    if os.name == "nt":
        validate_windows_paths(list(payloads))
    (verify_release if review else verify_package)(ref, store, policy)
    ordinary_path(destination, missing=True)
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            fail("destination-not-empty", str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".aepm-extract-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "payload"
        stage.mkdir()
        executable = {f["path"] for f in c["files"] if f["executable"]}
        for p, data in payloads.items():
            target = stage / p
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o755 if p in executable else 0o644)
            validate_extracted_mode(target, p in executable)
        os.replace(stage, destination)
    return c


@guarded
def extract(ref: PackageRef, store: Path, destination: Path, policy: Path) -> Component:
    return _extract(ref, store, destination, policy, False)


@guarded
def extract_review(ref: PackageRef, store: Path, destination: Path, policy: Path) -> Component:
    return _extract(ref, store, destination, policy, True)
