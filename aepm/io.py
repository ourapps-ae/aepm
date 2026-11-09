"""Bounded documents and ordinary filesystem paths."""

import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, NoReturn

from .model import AepmError, canonical, digest


class VerificationDirectory:
    """Preserve private files when owned-process cleanup cannot be confirmed."""

    def __init__(self, prefix):
        self.temporary = tempfile.TemporaryDirectory(prefix=prefix, delete=False)
        self.path = Path(self.temporary.name).resolve()
        self.preserve = False
        if os.name == "posix":
            try:
                from .private_process import enroll_root
                enroll_root(self.path, before_work=True)
            except BaseException:
                self.temporary.cleanup()
                raise

    def __enter__(self):
        return self.path

    def __exit__(self, *_):
        if not self.preserve:
            self.temporary.cleanup()


def fail(code: str, path: object) -> NoReturn:
    raise AepmError(code, str(path))


def fields(value, required, optional=(), path="document"):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        fail("fields", path)


def load(path: str | Path) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("duplicate-key", path)
            result[key] = value
        return result

    try:
        with Path(path).open("rb") as stream:
            data = stream.read(1_048_577)
        if len(data) > 1_048_576:
            fail("metadata-limit", path)
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: fail("nonfinite", path))
    except (OSError, ValueError, UnicodeError, RecursionError):
        fail("document", path)


def sync_directory(path):
    if os.name == "nt":
        from .windows import ntfs
        ntfs(path)
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        fail("symlink", path)
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            from .windows import publish
            publish(temporary, path, replace=True)
        else:
            os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path):
    path = Path(path)
    from .bundle import ordinary_path
    ordinary_path(path, missing=True)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt":
        from .windows import protect
        protect(path)
    else:
        path.chmod(0o700)
    return path


def exclusive(path, value):
    """Publish once; even an interrupted creation consumes this filename."""
    path = Path(path)
    from .bundle import ordinary_path
    ordinary_path(path.parent)
    data = canonical(value)
    if os.name == "nt":
        from .windows import exclusive_bytes
        exclusive_bytes(path, data)
        return
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        fail("execution-replayed", "execution-state")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def immutable(path, value):
    immutable_blob(path, canonical(value))


def immutable_blob(path, data):
    path = Path(path)
    private_directory(path.parent)
    if path.is_symlink():
        fail("immutable-evidence", "evidence")
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            fail("immutable-evidence", "evidence")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".evidence-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            from .windows import publish
            publish(temporary, path)
        else:
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                    fail("immutable-evidence", "evidence")
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def relative(value, path="path", dot=False):
    if dot and value == ".":
        return value
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        fail("unsafe-path", path)
    if any(part in ("", ".", "..") for part in value.split("/")) or value.startswith("/"):
        fail("unsafe-path", path)
    return value


def rooted(root, value, dot=False):
    relative(value, dot=dot)
    root = Path(root)
    candidate = root / value
    for parent in (candidate, *candidate.parents):
        if parent.is_symlink():
            fail("symlink", value)
        if parent == root:
            break
    if not candidate.resolve().is_relative_to(root.resolve()):
        fail("path-escape", value)
    return candidate


def exact(value, path="version"):
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        fail("version", path)
    return tuple(map(int, value.split(".")))


def package_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"ourapps-ae/[a-z][a-z0-9-]*", value):
        fail("package-name", "name")
    return value


def snapshot(root, assembly=None):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        fail("ordinary-directory", root)
    owners = {item["path"]: item["owner"] for item in (assembly or {}).get("files", [])}
    records = [{"path": ".", "kind": "directory", "digest": None,
                "mode": stat.S_IMODE(root.stat().st_mode), "owner": None}]
    seen = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(directory) / name
            key = path.relative_to(root).as_posix()
            relative(key)
            if key.casefold() in seen:
                fail("case-collision", key)
            seen.add(key.casefold())
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                fail("special-file", key)
            records.append({"path": key, "kind": "directory" if path.is_dir() else "file",
                            "digest": None if path.is_dir() else digest(path.read_bytes()),
                            "mode": stat.S_IMODE(info.st_mode), "owner": owners.get(key)})
    return sorted(records, key=lambda item: item["path"])
