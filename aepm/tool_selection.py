"""Frozen tool selection: one validated binding per tool name, checked without launching anything."""

from collections.abc import Collection, Mapping
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat

from .model import AepmError, canonical


SYSTEM_DIRECTORIES = ("/usr/bin", "/bin")


def _invalid():
    raise AepmError("tool-selection-invalid", "toolSelection")


def _changed():
    raise AepmError("resource-changed", "tool")


def _require(condition):
    if not condition:
        _invalid()


def _ordinary_ancestors(path):
    for parent in path.parents:
        if parent.is_symlink():
            _changed()


def _digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def _absolute(value):
    _require(isinstance(value, str) and value.startswith("/") and "\x00" not in value
             and os.path.normpath(value) == value)
    return value


def _check_binding(binding):
    """Recheck links, canonical path, digest and mode; return the alias."""
    try:
        current = Path(binding["alias"])
        for link in binding["links"]:
            if str(current) != link["path"]:
                _changed()
            _ordinary_ancestors(current)
            if not current.is_symlink() or os.readlink(current) != link["target"]:
                _changed()
            target = Path(link["target"])
            current = Path(os.path.normpath(target if target.is_absolute() else current.parent / target))
        if str(current) != binding["canonicalPath"]:
            _changed()
        _ordinary_ancestors(current)
        info = current.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != binding["mode"]
                or not info.st_mode & 0o111 or _digest(current) != binding["sha256"]):
            _changed()
    except OSError:
        _changed()
    return Path(binding["alias"])


def _parse_binding(name, value):
    _require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", name) is not None)
    _require(isinstance(value, Mapping) and "status" in value)
    if value["status"] == "unavailable":
        _require(set(value) == {"status"})
        return {"status": "unavailable"}
    _require(value["status"] == "bound"
             and set(value) == {"status", "alias", "links", "canonicalPath", "sha256", "mode"})
    alias, canonical_path = _absolute(value["alias"]), _absolute(value["canonicalPath"])
    _require(Path(alias).name == name)
    _require(isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None)
    _require(type(value["mode"]) is int and 0 <= value["mode"] <= 0o7777)
    links = value["links"]
    _require(isinstance(links, list) and len(links) <= 8)
    parsed = []
    for link in links:
        _require(isinstance(link, Mapping) and set(link) == {"path", "target"})
        _require(isinstance(link["target"], str) and link["target"] and "\x00" not in link["target"])
        parsed.append({"path": _absolute(link["path"]), "target": link["target"]})
    _require(bool(parsed) == (alias != canonical_path))
    return {"status": "bound", "alias": alias, "links": parsed, "canonicalPath": canonical_path,
            "sha256": value["sha256"], "mode": value["mode"]}


class ToolSelection:
    """Immutable; members only read the filesystem."""

    __slots__ = ("_tools", "_directories", "_digest")

    def __init__(self, tools, directories, digest):
        object.__setattr__(self, "_tools", tools)
        object.__setattr__(self, "_directories", directories)
        object.__setattr__(self, "_digest", digest)

    def __setattr__(self, name, value):
        raise AttributeError("ToolSelection is immutable")

    @property
    def digest(self):
        return self._digest

    @property
    def directories(self):
        return self._directories

    @property
    def path(self):
        return os.pathsep.join(self._directories)

    def _binding(self, name):
        binding = self._tools.get(name)
        if binding is None:
            raise AepmError("tool-unavailable", "tools")
        if binding["status"] == "unavailable":
            raise AepmError("tool-unavailable", name)
        return binding

    def validate(self):
        for directory in self._directories:
            path = Path(directory)
            _ordinary_ancestors(path)
            if path.is_symlink() or not path.is_dir():
                _changed()
        for name, binding in self._tools.items():
            if binding["status"] == "bound":
                alias = _check_binding(binding)
                if shutil.which(name, path=self.path) != str(alias):
                    _changed()

    def resolve(self, name):
        return _check_binding(self._binding(name))

    def canonical(self, name):
        binding = self._binding(name)
        _check_binding(binding)
        return binding["canonicalPath"]

    def check(self, name, resolved, search_path):
        binding = self._binding(name)
        alias = _check_binding(binding)
        if shutil.which(name, path=search_path) != str(alias) or str(resolved) != binding["canonicalPath"]:
            _changed()


def require_selection(value):
    if value is not None and not isinstance(value, ToolSelection):
        _invalid()
    return value


def load_tool_selection(value, required: Collection[str]) -> ToolSelection:
    if os.name != "posix":
        _invalid()
    try:
        _require(isinstance(value, Mapping)
                 and set(value) == {"format", "platform", "python", "searchPath", "tools"})
        _require(type(value["format"]) is int and value["format"] == 1 and value["platform"] == "posix")
        python = value["python"]
        _require(isinstance(python, Mapping) and set(python) == {"name", "version"}
                 and isinstance(python["name"], str) and isinstance(python["version"], str))
        directories = value["searchPath"]
        _require(isinstance(directories, list) and 0 < len(directories) <= 64)
        directories = tuple(_absolute(item) for item in directories)
        _require(len(set(directories)) == len(directories))
        _require(all(item in directories for item in SYSTEM_DIRECTORIES))
        tools = value["tools"]
        _require(isinstance(tools, Mapping) and 0 < len(tools) <= 256)
        required = set(required)
        _require(all(isinstance(item, str) for item in required) and set(tools) == required)
        parsed = {name: _parse_binding(name, binding) for name, binding in tools.items()}
        _require(parsed.get(python["name"], {}).get("status") == "bound")
        digest = hashlib.sha256(canonical(deepcopy(dict(value)))).hexdigest()
    except AepmError:
        raise
    except (TypeError, KeyError, ValueError):
        _invalid()
    selection = ToolSelection(parsed, directories, digest)
    selection.validate()
    return selection
