"""The retained documents a review report names, carried with a release as one ustar archive of store-relative paths."""

from __future__ import annotations

import io
from pathlib import Path
import tarfile

from .model import digest, fail, guarded, sha256

FOLDERS = (("contexts", "contextDigest"), ("authorizations", "authorizationDigest"), ("execution-evidence", "evidenceDigest"))
LIMIT = 64 * 1024 * 1024


def evidence_paths(report: dict) -> list[str]:
    """Store-relative paths of every document a format-2 report names; each file's name is the SHA-256 of its bytes."""
    if report.get("format") != 2:
        return []
    paths = []
    for folder, key in FOLDERS:
        value = report["execution"][key]
        if value is not None:
            paths.append(f"{folder}/{sha256(value, 'report.execution.' + key)}.json")
    return sorted(paths)


@guarded
def pack_evidence(store: Path, report: dict) -> bytes | None:
    """The evidence archive for a report, from the store; None when the report names nothing. A missing file is refused."""
    paths = evidence_paths(report)
    if not paths:
        return None
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in paths:
            source = Path(store) / path
            if not source.is_file() or source.is_symlink():
                fail("evidence-missing", path)
            data = source.read_bytes()
            if digest(data) != Path(path).stem:
                fail("evidence-digest", path)
            info = tarfile.TarInfo(path)
            info.size, info.mode = len(data), 0o644
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


@guarded
def unpack_evidence(store: Path, report: dict, data: bytes) -> list[str]:
    """Add the documents a report names from an evidence archive to the store, each checked against its digest."""
    expected = evidence_paths(report)
    if len(data) > LIMIT:
        fail("evidence-limit", "evidence")
    found = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                if not member.isfile() or member.type != tarfile.REGTYPE or member.name not in expected or member.name in found:
                    fail("evidence-member", member.name)
                stream = archive.extractfile(member)
                found[member.name] = stream.read() if stream is not None else b""
    except tarfile.TarError:
        fail("invalid-archive", "evidence")
    if sorted(found) != expected:
        fail("evidence-missing", "evidence")
    for path, content in found.items():
        if digest(content) != Path(path).stem:
            fail("evidence-digest", path)
    for path, content in found.items():
        target = Path(store) / path
        if target.is_symlink():
            fail("symlink", path)
        if target.exists():
            if target.read_bytes() != content:
                fail("evidence-rebinding", path)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        from .bundle import atomic_write
        atomic_write(target, content)
    return expected
