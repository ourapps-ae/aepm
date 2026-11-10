"""Assemble verified archives without running their contents."""

from copy import deepcopy
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit

from .model import Assembly, Definition, Lock, canonical, digest, guarded, validate_lock
from .io import exact, fail, fields, load, package_name, relative, rooted, snapshot, write
from .diagram import generate as renderer


GRAMMARS = {
    "identifier": r"[A-Za-z][A-Za-z0-9_]{0,63}",
    "qualified": r"[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+",
    "slug": r"[a-z][a-z0-9-]{0,63}",
    "label": r"[A-Za-z][A-Za-z0-9 -]{0,63}",
    "environment": r"[A-Z][A-Z0-9_]{0,63}",
    "address": r"https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9_/-]*)?",
}
MAXIMUM_RECORDED = 65536
TOKEN = re.compile(r"\{\{([A-Za-z][A-Za-z0-9_.-]*)\}\}")


def shell_template(name, text):
    return name.endswith((".sh", ".bash", ".zsh", ".ksh", ".ps1", ".cmd", ".bat")) or bool(re.match(r"#![^\n]*\b(?:sh|bash|zsh|dash|ksh)\b", text))


@guarded
def validate_definition(value: object) -> Definition:
    fields(value, ("format", "id", "title", "recipe", "components", "configuration", "design", "updatePolicy"), ("answers", "selections"))
    if type(value["format"]) is not int or value["format"] != 1 or value["updatePolicy"] != "patch":
        fail("definition-format", "definition")
    if not isinstance(value["id"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", value["id"]):
        fail("application-id", "id")
    if not isinstance(value["title"], str) or not value["title"] or len(value["title"]) > 256:
        fail("application-title", "title")
    fields(value["recipe"], ("name", "version"), path="recipe")
    package_name(value["recipe"]["name"])
    exact(value["recipe"]["version"])
    if not isinstance(value["components"], list) or not isinstance(value["configuration"], dict):
        fail("definition-shape", "definition")
    names, ids = {value["recipe"]["name"]}, {"application"}
    for item in value["components"]:
        fields(item, ("id", "name", "version", "configuration"), path="components")
        package_name(item["name"])
        exact(item["version"])
        if not isinstance(item["id"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", item["id"]):
            fail("instance-id", "components")
        if item["id"] in ids or item["name"] in names or not isinstance(item["configuration"], dict):
            fail("duplicate-component", "components")
        names.add(item["name"])
        ids.add(item["id"])
    fields(value["design"], ("definitions", "instances", "connections"), path="design")
    if any(not isinstance(value["design"][key], list) for key in value["design"]):
        fail("design-shape", "design")
    for key in ("answers", "selections"):
        if key in value:
            if not isinstance(value[key], dict) or len(canonical(value[key])) > MAXIMUM_RECORDED:
                fail("definition-" + key, key)
    canonical(value)
    return deepcopy(value)


def present_components(definition):
    return {definition["recipe"]["name"], *(item["name"] for item in definition["components"])}


def installed_artefacts(manifest, present):
    """Artefacts without a `component` condition, or whose component is in the design."""
    return [item for item in manifest["artefacts"] if "component" not in item or item["component"] in present]


def configuration(declarations, supplied):
    if not isinstance(supplied, dict):
        fail("configuration", "configuration")
    settings = {item["id"]: item for item in declarations}
    if set(supplied) - settings.keys():
        fail("unknown-setting", "configuration")
    result = {}
    for key, setting in settings.items():
        if key not in supplied and "default" not in setting:
            if setting["required"]:
                fail("required-setting", key)
            continue
        value = supplied.get(key, setting.get("default"))
        if setting["secret"]:
            fields(value, ("secretRef",), path=key)
            if not isinstance(value["secretRef"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_./-]{0,127}", value["secretRef"]):
                fail("secret-reference", key)
        elif setting["type"] == "boolean":
            if type(value) is not bool or setting["grammar"] != "boolean":
                fail("setting-type", key)
        elif setting["type"] == "integer":
            if type(value) is not int or not -(2 ** 31) <= value < 2 ** 31 or setting["grammar"] != "integer":
                fail("setting-type", key)
        else:
            grammar = setting["grammar"]
            if grammar not in GRAMMARS or not isinstance(value, str) or not re.fullmatch(GRAMMARS[grammar], value):
                fail("setting-grammar", key)
            if grammar == "address":
                try:
                    parsed = urlsplit(value)
                    if not parsed.hostname or (parsed.port is not None and not 1 <= parsed.port <= 65535):
                        fail("setting-address", key)
                    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", part) for part in parsed.hostname.split(".")):
                        fail("setting-address", key)
                except ValueError:
                    fail("setting-address", key)
        result[key] = deepcopy(value)
    return result


def substitute(text, declarations, values, *, destination=False, shell=False):
    settings = {item["id"]: item for item in declarations}
    remainder = TOKEN.sub("", text)
    if "{{" in remainder or "}}" in remainder:
        fail("template-token", "template")

    def replace(match):
        if (match.start() and text[match.start() - 1] == "{") or (match.end() < len(text) and text[match.end()] == "}"):
            fail("template-token", "template")
        key = match[1]
        if key not in settings or key not in values or settings[key]["secret"]:
            fail("template-setting", key)
        grammar = settings[key]["grammar"]
        if destination and grammar not in ("identifier", "qualified", "slug"):
            fail("template-path-type", key)
        if shell and grammar not in ("environment", "identifier", "slug"):
            fail("template-shell-type", key)
        if settings[key]["type"] == "string" and not destination and not shell:
            quoted, escaped = None, False
            for char in text[text.rfind("\n", 0, match.start()) + 1:match.start()]:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif quoted:
                    if char == quoted:
                        quoted = None
                elif char in ("'", '"'):
                    quoted = char
            if quoted is None:
                fail("template-string-position", key)
        value = values[key]
        return str(value).lower() if type(value) is bool else str(value)

    return TOKEN.sub(replace, text)


def projected_definition(manifest, package_root, ref):
    source = manifest["visual"]["definition"]
    visual = load(rooted(package_root, source))
    try:
        renderer.validate_definition(visual, "visual.definition")
    except renderer.DesignError:
        fail("diagram-definition", "visual.definition")
    expected = []
    authored = {item["id"]: item for item in visual["settings"]}
    for declaration in manifest["collect"]:
        item = {key: deepcopy(declaration[key]) for key in ("id", "type", "required", "secret")}
        item["type"] = "number" if item["type"] == "integer" else item["type"]
        item["name"] = authored.get(item["id"], {}).get("name", item["id"])
        if "default" in declaration:
            item["default"] = declaration["default"]
        expected.append(item)
    if sorted(visual["settings"], key=lambda x: x["id"]) != sorted(expected, key=lambda x: x["id"]):
        fail("diagram-settings", "visual.definition")
    expected_id = ref["name"].replace("/", ".")
    if visual["id"] != expected_id:
        fail("diagram-identity", "visual.definition")
    ports = {item["id"]: item for item in visual["ports"]}
    declared = set()
    for direction, key in (("output", "provides"), ("input", "requires")):
        for interface in manifest[key]:
            declared.add(interface["id"])
            port = ports.get(interface["id"], {})
            expected_port = {"direction": direction, "kind": "interface", "type": interface["type"], "version": interface["version"]}
            if direction == "input" and interface.get("optional", False):
                expected_port["required"] = False
            if any(port.get(k) != v for k, v in expected_port.items()):
                fail("diagram-interface", "visual.definition")
    for port in visual["ports"]:
        if port["id"] not in declared and not (port["kind"] == "setting" and port["id"] in authored):
            fail("diagram-port", "visual.definition")
    visual["status"] = "assembled"
    if manifest["kind"] == "recipe":
        visual["kind"] = "application"
        visual.pop("package", None)
        visual.pop("version", None)
        visual["revision"] = ref["version"]
    else:
        if visual.get("package") != ref["name"] or visual.get("version") != ref["version"]:
            fail("diagram-version", "visual.definition")
        visual.update(kind="component", digest=ref["digest"])
    return visual


def requirements(definition):
    return [definition["recipe"], *[{key: item[key] for key in ("name", "version")} for item in definition["components"]]]


def validate_retained_assembly(root, assembly, manifests):
    definition = validate_definition(load(Path(root) / ".aepm/definition.json"))
    if digest(canonical(definition)) != assembly["lock"]["definitionDigest"]:
        fail("definition-digest", "definition")
    expected_files, expected_configuration = [], {}
    present = present_components(definition)
    generated_definitions, generated_instances = {}, {}
    for ref in assembly["lock"]["packages"]:
        manifest = manifests[ref["digest"]]
        is_recipe = ref["name"] == definition["recipe"]["name"]
        choices = [item for item in definition["components"] if item["name"] == ref["name"]]
        if not is_recipe and len(choices) != 1:
            fail("missing-component-instance", "definition")
        instance_id = "application" if is_recipe else choices[0]["id"]
        declared_version = definition["recipe"]["version"] if is_recipe else choices[0]["version"]
        if declared_version != ref["version"]:
            fail("definition-version", "definition")
        supplied = definition["configuration"] if is_recipe else choices[0]["configuration"]
        values = configuration(manifest["collect"], supplied)
        expected_configuration[instance_id] = values
        package_root = Path(root) / ".aepm/packages" / ref["digest"]
        visual = projected_definition(manifest, package_root, ref)
        generated_definitions[visual["id"]] = visual
        generated_instances[instance_id] = {"id": instance_id, "name": definition["title"] if is_recipe else visual["name"],
                                            "definition": visual["id"], "configuration": values}
        for artefact in installed_artefacts(manifest, present):
            name = substitute(artefact["destination"], manifest["collect"], values, destination=True)
            data = rooted(package_root, artefact["source"]).read_bytes()
            if artefact["template"]:
                text = data.decode("utf-8")
                data = substitute(text, manifest["collect"], values,
                                  shell=shell_template(name, text)).encode("utf-8")
            expected_files.append({"path": name, "owner": ref["name"], "source": artefact["source"],
                                   "digest": digest(data), "executable": artefact["executable"]})
    if assembly["files"] != sorted(expected_files, key=lambda item: item["path"]) or assembly["configuration"] != expected_configuration:
        fail("assembly-records", "assembly")
    for authored in definition["design"]["definitions"]:
        if authored["id"] not in generated_definitions:
            generated_definitions[authored["id"]] = {**authored, "status": "assembled"}
    for authored in definition["design"]["instances"]:
        if authored["id"] not in generated_instances:
            generated_instances[authored["id"]] = authored
    design = assembly["design"]
    try:
        renderer.validate_design(design)
    except renderer.DesignError:
        fail("diagram", "design")
    if (design["id"] != definition["id"] or design["title"] != definition["title"]
            or design["lockDigest"] != digest(canonical(assembly["lock"])) or design["connections"] != definition["design"]["connections"]
            or design["definitions"] != list(generated_definitions.values()) or design["instances"] != list(generated_instances.values())):
        fail("assembly-design", "design")


@guarded
def assemble(definition: Definition, lock: Lock, store: Path, destination: Path, policy: Path) -> Assembly:
    from .bundle import extract, resolve

    definition = validate_definition(definition)
    lock = validate_lock(lock)
    expected = resolve(requirements(definition), Path(store) / "catalogue.json", definition["id"], digest(canonical(definition)))
    if lock != expected:
        fail("lock-definition", "lock")
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir() or destination.parent.is_symlink():
        fail("target-exists", "target")
    with tempfile.TemporaryDirectory(prefix=".aepm-assembly-", dir=destination.parent) as temporary:
        root = Path(temporary) / "application"
        root.mkdir()
        owned, effective, definitions, instances = [], {}, [], []
        component_map = {item["name"]: item for item in definition["components"]}
        present = present_components(definition)
        recipe_name = definition["recipe"]["name"]
        seen = set()
        spellings = {}
        for ref in lock["packages"]:
            package_root = root / ".aepm" / "packages" / ref["digest"]
            package_root.parent.mkdir(parents=True, exist_ok=True)
            manifest = extract({key: ref[key] for key in ("name", "version", "digest")}, Path(store), package_root, Path(policy))
            archive_root = root / ".aepm/archives"
            archive_root.mkdir(exist_ok=True)
            shutil.copyfile(Path(store) / "objects" / (ref["digest"] + ".tar"), archive_root / (ref["digest"] + ".tar"))
            receipts = root / ".aepm/receipts" / ref["digest"]
            receipts.mkdir(parents=True)
            for filename in ("release.dsse.json", "guardian.dsse.json"):
                shutil.copyfile(Path(store) / "statements" / ref["digest"] / filename, receipts / filename)
            from .trust import review_report_digest
            report_digest = review_report_digest(receipts / "guardian.dsse.json", Path(policy))
            report = load(Path(store) / "reports" / (report_digest + ".json"))
            write(root / ".aepm/evidence/reports" / (report_digest + ".json"), report)
            if report["format"] == 2:
                for folder, key in (("contexts", "contextDigest"), ("authorizations", "authorizationDigest"), ("execution-evidence", "evidenceDigest")):
                    value = report["execution"][key]
                    if value is not None:
                        directory = root / ".aepm/evidence" / folder
                        directory.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(Path(store) / folder / (value + ".json"), directory / (value + ".json"))
            is_recipe = ref["name"] == recipe_name
            if (manifest["kind"] == "recipe") != is_recipe:
                fail("recipe-identity", "packages")
            if not is_recipe and ref["name"] not in component_map:
                fail("missing-component-instance", "components")
            instance_id = "application" if is_recipe else component_map[ref["name"]]["id"]
            supplied = definition["configuration"] if is_recipe else component_map[ref["name"]]["configuration"]
            values = configuration(manifest["collect"], supplied)
            effective[instance_id] = values
            visual = projected_definition(manifest, package_root, ref)
            definitions.append(visual)
            instances.append({"id": instance_id, "name": definition["title"] if is_recipe else visual["name"],
                              "definition": visual["id"], "configuration": deepcopy(values)})
            for artefact in installed_artefacts(manifest, present):
                name = substitute(artefact["destination"], manifest["collect"], values, destination=True)
                relative(name)
                if name.split("/")[0].casefold() == ".aepm":
                    fail("reserved-destination", name)
                prefix = "components/" + ref["name"].split("/")[1] + "/"
                if (not is_recipe and not name.startswith(prefix)) or (is_recipe and name.startswith("components/")):
                    fail("artefact-owner", name)
                folded = name.casefold()
                if folded in seen or any(folded.startswith(old + "/") or old.startswith(folded + "/") for old in seen):
                    fail("artefact-collision", name)
                seen.add(folded)
                for length in range(1, len(name.split("/")) + 1):
                    prefix_path = "/".join(name.split("/")[:length])
                    if spellings.setdefault(prefix_path.casefold(), prefix_path) != prefix_path:
                        fail("artefact-case-collision", name)
                source = rooted(package_root, artefact["source"])
                data = source.read_bytes()
                if artefact["template"]:
                    try:
                        text = data.decode("utf-8")
                    except UnicodeError:
                        fail("template-encoding", name)
                    data = substitute(text, manifest["collect"], values,
                                      shell=shell_template(name, text)).encode("utf-8")
                target = rooted(root, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(0o755 if artefact["executable"] else 0o644)
                owned.append({"path": name, "owner": ref["name"], "source": artefact["source"],
                              "digest": digest(data), "executable": artefact["executable"]})
        # Authored package copies must agree with records; external service blocks remain authored.
        by_id = {item["id"]: item for item in definitions}
        for authored in definition["design"]["definitions"]:
            try:
                renderer.validate_definition(authored, "design.definition")
            except renderer.DesignError:
                fail("diagram-definition", "design.definition")
            if authored["id"] in by_id:
                expected_visual = deepcopy(by_id[authored["id"]])
                expected_visual.pop("digest", None)
                expected_visual["status"] = authored["status"]
                if expected_visual != authored:
                    fail("authored-definition-mismatch", "design")
            else:
                if authored["kind"] == "component":
                    fail("unlocked-definition", "design")
                authored = deepcopy(authored)
                authored["status"] = "assembled"
                definitions.append(authored)
        by_instance = {item["id"]: item for item in instances}
        for authored in definition["design"]["instances"]:
            if authored.get("id") in by_instance:
                expected_instance = by_instance[authored["id"]]
                if authored != expected_instance:
                    fail("authored-instance-mismatch", "design")
            else:
                instances.append(deepcopy(authored))
        design = {"schemaVersion": 2, "id": definition["id"], "title": definition["title"], "status": "assembled",
                  "view": "application", "lockDigest": digest(canonical(lock)), "definitions": definitions,
                  "instances": instances, "connections": deepcopy(definition["design"]["connections"])}
        try:
            renderer.validate_design(design)
        except renderer.DesignError:
            fail("diagram", "design")
        assembly = {"format": 1, "application": definition["id"], "lock": lock, "configuration": effective,
                    "design": design, "files": sorted(owned, key=lambda x: x["path"])}
        write(root / ".aepm/lock.json", lock)
        write(root / ".aepm/assembly.json", assembly)
        write(root / ".aepm/definition.json", definition)
        os.rename(root, destination)
        return assembly


def read_assembly(root):
    from .bundle import validate_extracted_mode
    root = Path(root)
    snapshot(root)
    assembly = load(root / ".aepm/assembly.json")
    fields(assembly, ("format", "application", "lock", "configuration", "design", "files"))
    validate_lock(assembly["lock"])
    if assembly["lock"] != load(root / ".aepm/lock.json") or assembly["application"] != assembly["lock"]["application"]:
        fail("assembly-lock", "assembly")
    seen = set()
    for item in assembly["files"]:
        fields(item, ("path", "owner", "source", "digest", "executable"))
        path = rooted(root, item["path"])
        if item["path"].casefold() in seen or not path.is_file() or digest(path.read_bytes()) != item["digest"]:
            fail("owned-file-edited", item["path"])
        seen.add(item["path"].casefold())
        validate_extracted_mode(path, item["executable"])
    return assembly
