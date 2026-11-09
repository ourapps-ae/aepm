"""Render diagrams directly from persisted assembly records."""

from copy import deepcopy
from pathlib import Path

from .diagram import generate as renderer
from .io import fail, write
from .model import Assembly, canonical, digest, guarded


@guarded
def export_design(assembly: Assembly, destination: Path) -> dict:
    design = deepcopy(assembly["design"])
    if design["lockDigest"] != digest(canonical(assembly["lock"])):
        fail("design-lock", "design")
    for instance in design["instances"]:
        if instance["id"] in assembly["configuration"]:
            if instance["configuration"] != assembly["configuration"][instance["id"]]:
                fail("design-configuration", "design")
        for key, value in instance["configuration"].items():
            if isinstance(value, dict) and set(value) == {"secretRef"}:
                instance["configuration"][key] = {"secretRef": "redacted"}
    try:
        renderer.validate_design(design)
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / "design.json"
        write(path, design)
        vector, raster = renderer.generate(path, destination / "design")
    except renderer.DesignError:
        fail("diagram-render", "design")
    return {"design": str(path), "svg": str(vector), "png": str(raster)}
