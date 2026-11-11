"""Find a declared tool on the user's PATH as the real executable, resolving version-manager shims."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

SHIM_MANAGERS = ("pyenv", "rbenv", "nodenv", "goenv", "jenv", "asdf", "mise")
PIN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?")


def _manager(shims: Path) -> list[str] | None:
    """The `which` command of the version manager owning a shims directory (for example ~/.pyenv/shims)."""
    root = shims.parent
    owner = root.name.lstrip(".")
    for manager in SHIM_MANAGERS:
        if owner == manager or owner.startswith(manager):
            for candidate in (root / "bin" / manager, shutil.which(manager)):
                if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
                    return [str(candidate), "which"]
    return None


def host_tool(name: str, path: str | None = None) -> Path | None:
    """The real executable `name` resolves to on PATH, or None. A shim is replaced by the executable its manager selects."""
    found = shutil.which(name, path=path)
    if found is None:
        return None
    executable = Path(found).resolve()
    if executable.parent.name != "shims":
        return executable
    command = _manager(executable.parent)
    if command is None:
        return None
    try:
        result = subprocess.run([*command, name], capture_output=True, text=True, timeout=20, env=os.environ.copy())
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = result.stdout.strip().splitlines()
    if result.returncode or len(lines) != 1 or not Path(lines[0]).is_absolute():
        return None
    real = Path(lines[0]).resolve()
    if not real.is_file() or real.parent.name == "shims" or not os.access(real, os.X_OK):
        return None
    return real


def version_matches(output: str, pin: str) -> str | None:
    """The first version in a tool's output whose leading components equal the pin (MAJOR or MAJOR.MINOR), or None."""
    wanted = pin.split(".")
    for value in re.findall(r"(?<![0-9])([0-9]+(?:\.[0-9]+)*)", output):
        if value.split(".")[:len(wanted)] == wanted:
            return value
    return None
