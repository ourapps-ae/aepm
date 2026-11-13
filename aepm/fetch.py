"""Download published packages, their attestations and review reports from a catalogue into a store."""

from __future__ import annotations

import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

from .bundle import add_archive, read_package
from .evidence import evidence_paths, unpack_evidence
from .io import write
from .model import PackageRef, canonical, digest, fail, guarded, loads, name, sha256, version

CATALOGUE = "https://ourapps.app"
ASSETS = "https://github.com"
USER_AGENT = "aepm-fetch/1 (+https://ourapps.app)"
LIMIT = 512 * 1024 * 1024
ATTESTATIONS = ("release", "guardian")


def _get(url: str, limit: int = LIMIT) -> bytes | None:
    """The body at url, or None for 404."""
    if urllib.parse.urlsplit(url).scheme not in ("https", "http"):
        fail("invalid-url", url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        fail("download-failed", f"{url} {error.code}")
    except (urllib.error.URLError, OSError, ValueError):
        fail("download-failed", url)
    if len(data) > limit:
        fail("download-limit", url)
    return data


def _json(url: str) -> dict | None:
    data = _get(url, 4 * 1024 * 1024)
    if data is None:
        return None
    try:
        value = json.loads(data)
    except ValueError:
        fail("invalid-response", url)
    if type(value) is not dict:
        fail("invalid-response", url)
    return value


def _digest(value: object, path: str) -> str:
    if type(value) is not str or not value.startswith("sha256:"):
        fail("invalid-digest", path)
    return sha256(value[len("sha256:"):], path)


def _metadata(origin: str, package: str, number: str) -> tuple[str, dict]:
    short = package.split("/", 1)[1]
    for kind in ("components", "recipes"):
        value = _json(f"{origin}/api/{kind}/{urllib.parse.quote(short)}/{urllib.parse.quote(number)}")
        if value is not None:
            if (value.get("name"), value.get("version")) != (package, number):
                fail("catalogue-identity", f"{package}@{number}")
            return kind, value
    fail("unknown-package", f"{package}@{number}")


@guarded
def fetch_one(store: Path, package: str, number: str, *, origin: str = CATALOGUE, assets: str = ASSETS) -> dict:
    """Fetch one package: the archive checked against the catalogue digest, then any release assets beside it."""
    name(package, "package")
    version(number, "package")
    kind, metadata = _metadata(origin, package, number)
    expected = _digest(metadata.get("digest"), "digest")
    short = package.split("/", 1)[1]
    link = _json(f"{origin}/api/{kind}/{urllib.parse.quote(short)}/{urllib.parse.quote(number)}/bundle")
    if link is None or type(link.get("url")) is not str or _digest(link.get("digest"), "bundle.digest") != expected:
        fail("bundle-unavailable", f"{package}@{number}")
    data = _get(link["url"])
    if data is None or digest(data) != expected:
        fail("archive-digest", f"{package}@{number}")
    ref: PackageRef = {"name": package, "version": number, "digest": expected}
    component = add_archive(Path(store), ref, data)
    source = metadata.get("source") or {}
    fetched = []
    if type(source.get("repository")) is str and type(source.get("tag")) is str:
        base = f"{assets}/{source['repository']}/releases/download/{urllib.parse.quote(source['tag'])}/{short}-{number}"
        for role in ATTESTATIONS:
            envelope = _get(f"{base}.{role}.dsse.json", 1024 * 1024)
            if envelope is not None:
                value = loads(envelope, role)
                if set(value) != {"payload", "payloadType", "signatures"}:
                    fail("invalid-envelope", role)
                write(Path(store) / "statements" / expected / (role + ".dsse.json"), value)
                fetched.append(role)
        report = _get(f"{base}.review.json", 1024 * 1024)
        if report is not None:
            value = loads(report, "review")
            data = canonical(value)
            if data != report:
                fail("invalid-report", "review")
            if evidence_paths(value):
                archive = _get(f"{base}.evidence.tar", LIMIT)
                if archive is None:
                    fail("evidence-missing", f"{short}-{number}.evidence.tar")
                unpack_evidence(Path(store), value, archive)
                fetched.append("evidence")
            write(Path(store) / "reports" / (digest(data) + ".json"), value)
            fetched.append("review")
    return {"name": package, "version": number, "digest": expected, "kind": component["kind"], "assets": fetched}


@guarded
def fetch(store: Path, packages: list[tuple[str, str]], *, with_dependencies: bool = False, origin: str = CATALOGUE,
          assets: str = ASSETS) -> list[dict]:
    """Fetch each package; with dependencies, also every component a recipe names and every declared dependency."""
    store = Path(store)
    pending, done, results = list(packages), set(), []
    while pending:
        package, number = pending.pop(0)
        if (package, number) in done:
            continue
        done.add((package, number))
        result = fetch_one(store, package, number, origin=origin.rstrip("/"), assets=assets.rstrip("/"))
        results.append(result)
        if not with_dependencies:
            continue
        component, payloads = read_package({"name": package, "version": number, "digest": result["digest"]}, store)
        needed = [(item["name"], item["version"]) for item in component["dependencies"]]
        if component["kind"] == "recipe" and "recipe.json" in payloads:
            from .recipe import World
            needed += [key for key in World(loads(payloads["recipe.json"], "recipe.json"), component, {}).wanted() if key[1] is not None]
        pending.extend(item for item in needed if item not in done)
    return results


@guarded
def providers(provided_types: list[str], *, origin: str = CATALOGUE) -> list[tuple[str, str]]:
    """(name, latest version) of every catalogue component providing all of the given interface types."""
    found = None
    for interface in provided_types:
        value = _json(f"{origin.rstrip('/')}/api/components?provides={urllib.parse.quote(interface, safe='')}&limit=100")
        if value is None or type(value.get("components")) is not list:
            fail("invalid-response", "components")
        names = set()
        for item in value["components"]:
            if type(item) is dict and type(item.get("name")) is str and type(item.get("version")) is str:
                names.add((name(item["name"], "components.name"), version(item["version"], "components.version")))
        found = names if found is None else found & names
    return sorted(found or [])
