"""CycloneDX 1.6 JSON bill of materials for one stored package archive."""

from __future__ import annotations

from pathlib import Path
import uuid

from .bundle import read_package
from .model import PackageRef, digest, guarded

SPEC_VERSION = "1.6"
SERIAL_NAMESPACE = uuid.UUID("6f1c0a52-3e7d-5b8a-9c41-0d2e8f7a6b13")


def repository(name: str, kind: str) -> str:
    """GitHub repository of a package: ourapps-ae/<name>, with a -recipe suffix for recipes."""
    short = name.split("/", 1)[1]
    return short + "-recipe" if kind == "recipe" else short


def purl(name: str, version: str, kind: str = "component") -> str:
    return f"pkg:github/ourapps-ae/{repository(name, kind)}@v{version}"


@guarded
def bill_of_materials(ref: PackageRef, store: Path) -> dict:
    component, payloads = read_package(ref, Path(store))
    identity = component["identity"]
    root = purl(identity["name"], identity["version"], component["kind"])
    files = [{"type": "file", "bom-ref": "file:" + item["path"], "name": item["path"],
              "hashes": [{"alg": "SHA-256", "content": digest(payloads[item["path"]])}]}
             for item in component["files"]]
    libraries = [{"type": "library", "bom-ref": purl(item["name"], item["version"]), "group": "ourapps-ae",
                  "name": item["name"].split("/", 1)[1], "version": item["version"], "purl": purl(item["name"], item["version"]),
                  "scope": "required"}
                 for item in component["dependencies"]]
    return {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION, "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(SERIAL_NAMESPACE, ref["digest"])),
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "aepm"}]},
            "component": {"type": "application" if component["kind"] == "recipe" else "library", "bom-ref": root,
                          "group": "ourapps-ae", "name": identity["name"].split("/", 1)[1], "version": identity["version"],
                          "purl": root, "licenses": [{"expression": identity["licence"]}],
                          "hashes": [{"alg": "SHA-256", "content": ref["digest"]}]},
        },
        "components": files + libraries,
        "dependencies": [{"ref": root, "dependsOn": [item["bom-ref"] for item in libraries]},
                         *[{"ref": item["bom-ref"]} for item in libraries]],
    }
