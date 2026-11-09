#!/usr/bin/env python3
"""Validate a component design and render its two review images."""

import argparse
import html
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import xml.etree.ElementTree as ET
import zlib


MAX_INPUT_BYTES = 1_048_576
MAX_DEPTH = 16
MAX_DEFINITIONS = 64
MAX_INSTANCES = 64
MAX_CONNECTIONS = 256
MAX_PORTS = 32
MAX_SETTINGS = 32
MAX_IDENTIFIER = 128
MAX_STRING = 256
RENDER_TIMEOUT = 10
MAX_OUTPUT_BYTES = 8_388_608
MAX_DIAGNOSTIC_BYTES = 65_536
MAX_AXIS = 8_192
MAX_PIXELS = 16_000_000
DPI = 96
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*\Z")
QUALIFIED = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*(?:/[A-Za-z][A-Za-z0-9_.-]*)*\Z")
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*))*)?"
    r"(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?\Z"
)
SVG_NAMESPACE = "http://www.w3.org/2000/svg"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class DesignError(Exception):
    """A diagnostic containing a field location, never a submitted value."""


def fail(path, reason):
    raise DesignError(f"{path}: {reason}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("design", "duplicate object key")
        result[key] = value
    return result


def reject_constant(_value):
    fail("design", "numbers must be finite")


def parse_document(data):
    if len(data) > MAX_INPUT_BYTES:
        fail("design", "input byte limit exceeded")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        fail("design", "expected UTF-8 text")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                fail("design", "nesting limit exceeded")
        elif char in "]}":
            depth -= 1
    try:
        document = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        fail("design", "malformed document")
    check_structure(document)
    return document


def check_structure(value, depth=0):
    if isinstance(value, (dict, list)):
        if depth >= MAX_DEPTH:
            fail("design", "nesting limit exceeded")
        children = list(value.keys()) + list(value.values()) if isinstance(value, dict) else value
        for child in children:
            check_structure(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > MAX_STRING:
            fail("design", "string length limit exceeded")
        if any(0xD800 <= ord(char) <= 0xDFFF or ord(char) in (0xFFFE, 0xFFFF) for char in value):
            fail("design", "invalid Unicode text")
    elif isinstance(value, float) and not math.isfinite(value):
        fail("design", "numbers must be finite")


def load_design(path):
    try:
        with Path(path).open("rb") as source:
            data = source.read(MAX_INPUT_BYTES + 1)
    except OSError:
        fail("design", "cannot read input file")
    return validate_design(parse_document(data))


def fields(value, required, optional, path):
    if not isinstance(value, dict):
        fail(path, "expected an object")
    if set(value) - set(required) - set(optional):
        fail(path, "unknown field")
    for key in required:
        if key not in value:
            fail(f"{path}.{key}", "missing field")


def string(value, path, identifier=False, qualified=False):
    if not isinstance(value, str) or not value.strip():
        fail(path, "expected a nonempty string")
    limit = MAX_IDENTIFIER if identifier or qualified else MAX_STRING
    if len(value) > limit:
        fail(path, "length limit exceeded")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        fail(path, "control characters are not allowed")
    pattern = QUALIFIED if qualified else IDENTIFIER if identifier else None
    if pattern and not pattern.fullmatch(value):
        fail(path, "invalid identifier")


def choice(value, choices, path):
    if not isinstance(value, str) or value not in choices:
        fail(path, "unsupported value")


def boolean(value, path):
    if type(value) is not bool:
        fail(path, "expected a boolean")


def version(value, path):
    string(value, path)
    if not VERSION.fullmatch(value):
        fail(path, "expected an exact three-part version")


def sequence(value, limit, path):
    if not isinstance(value, list):
        fail(path, "expected an array")
    if len(value) > limit:
        fail(path, "item limit exceeded")


def index_unique(items, path):
    result = {}
    for number, item in enumerate(items):
        if item["id"] in result:
            fail(f"{path}[{number}].id", "duplicate identifier")
        result[item["id"]] = item
    return result


def scalar(value, kind, path):
    valid = {
        "string": isinstance(value, str),
        "boolean": type(value) is bool,
        "number": type(value) in (int, float),
    }[kind]
    if not valid:
        fail(path, "incorrect scalar type")
    if kind == "string":
        if len(value) > MAX_STRING or any(ord(char) < 32 or ord(char) == 127 for char in value):
            fail(path, "invalid setting text")
    elif kind == "number" and isinstance(value, float) and not math.isfinite(value):
        fail(path, "numbers must be finite")


def validate_port(port, path):
    fields(port, ("id", "name", "direction", "kind", "type", "version"), ("required", "cardinality"), path)
    string(port["id"], f"{path}.id", identifier=True)
    string(port["name"], f"{path}.name")
    choice(port["direction"], ("input", "output"), f"{path}.direction")
    choice(port["kind"], ("interface", "setting"), f"{path}.kind")
    string(port["type"], f"{path}.type", qualified=True)
    version(port["version"], f"{path}.version")
    if port["direction"] == "input":
        fields(port, ("id", "name", "direction", "kind", "type", "version", "required", "cardinality"), (), path)
        boolean(port["required"], f"{path}.required")
        choice(port["cardinality"], ("one", "many"), f"{path}.cardinality")
    elif "required" in port or "cardinality" in port:
        fail(path, "outputs do not declare input cardinality")


def validate_setting(setting, path):
    fields(setting, ("id", "name", "type", "required", "secret"), ("default",), path)
    string(setting["id"], f"{path}.id", identifier=True)
    string(setting["name"], f"{path}.name")
    choice(setting["type"], ("string", "number", "boolean"), f"{path}.type")
    boolean(setting["required"], f"{path}.required")
    boolean(setting["secret"], f"{path}.secret")
    if "default" in setting:
        if setting["secret"]:
            fail(f"{path}.default", "secret defaults are forbidden")
        scalar(setting["default"], setting["type"], f"{path}.default")


def validate_definition(definition, path, assembled=False):
    fields(definition, ("id", "name", "kind", "status", "ports", "settings"), ("package", "version", "revision", "digest") if assembled else ("package", "version", "revision"), path)
    string(definition["id"], f"{path}.id", identifier=True)
    string(definition["name"], f"{path}.name")
    choice(definition["kind"], ("component", "application", "service"), f"{path}.kind")
    choice(definition["status"], ("assembled",) if assembled else ("proposed", "example"), f"{path}.status")
    if assembled:
        if definition["kind"] == "component":
            if not isinstance(definition.get("digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", definition["digest"]):
                fail(path, "component requires archive digest")
        elif "digest" in definition:
            fail(path, "digest belongs to components")
        revision = definition.get("version", definition.get("revision", ""))
        if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", revision):
            fail(path, "assembled revision must be exact")
    if definition["kind"] == "component":
        if "package" not in definition or "version" not in definition or "revision" in definition:
            fail(path, "components require package and version, without revision")
        string(definition["package"], f"{path}.package", qualified=True)
        if definition["package"].count("/") != 1:
            fail(f"{path}.package", "expected owner/name")
        version(definition["version"], f"{path}.version")
    else:
        if "revision" not in definition or "package" in definition or "version" in definition:
            fail(path, "non-package blocks require only an example revision")
        version(definition["revision"], f"{path}.revision")
    for key, limit, validator in (("ports", MAX_PORTS, validate_port), ("settings", MAX_SETTINGS, validate_setting)):
        sequence(definition[key], limit, f"{path}.{key}")
        for index, item in enumerate(definition[key]):
            validator(item, f"{path}.{key}[{index}]")
        index_unique(definition[key], f"{path}.{key}")


def effective_configuration(instance, definition, path):
    supplied = instance["configuration"]
    if not isinstance(supplied, dict):
        fail(f"{path}.configuration", "expected an object")
    declared = {setting["id"] for setting in definition["settings"]}
    if set(supplied) - declared:
        fail(f"{path}.configuration", "undeclared setting")
    result = {}
    for index, setting in enumerate(definition["settings"]):
        location = f"{path}.configuration[{index}]"
        key = setting["id"]
        if key not in supplied and "default" not in setting:
            if setting["required"]:
                fail(location, "missing required setting")
            continue
        value = supplied[key] if key in supplied else setting["default"]
        if setting["secret"]:
            if not isinstance(value, dict) or set(value) != {"secretRef"}:
                fail(location, "expected only a symbolic secret reference")
            string(value["secretRef"], f"{location}.secretRef", qualified=True)
            result[key] = "[secret reference]"
        else:
            scalar(value, setting["type"], location)
            result[key] = value
    return result


def validate_design(document):
    check_structure(document)
    assembled = isinstance(document, dict) and document.get("schemaVersion") == 2
    fields(document, ("schemaVersion", "id", "title", "status", "view", "definitions", "instances", "connections"), ("focus", "lockDigest") if assembled else ("focus",), "design")
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] not in (1, 2):
        fail("design.schemaVersion", "unsupported schema version")
    if assembled and (not isinstance(document.get("lockDigest"), str) or not re.fullmatch(r"[0-9a-f]{64}", document["lockDigest"])):
        fail("design.lockDigest", "expected lock digest")
    string(document["id"], "design.id", identifier=True)
    string(document["title"], "design.title")
    choice(document["status"], ("assembled",) if assembled else ("proposed", "example"), "design.status")
    choice(document["view"], ("application", "component"), "design.view")
    for key, limit in (("definitions", MAX_DEFINITIONS), ("instances", MAX_INSTANCES), ("connections", MAX_CONNECTIONS)):
        sequence(document[key], limit, f"design.{key}")
    if not document["definitions"] or not document["instances"]:
        fail("design", "at least one definition and instance are required")
    for index, definition in enumerate(document["definitions"]):
        validate_definition(definition, f"design.definitions[{index}]", assembled)
    definitions = index_unique(document["definitions"], "design.definitions")
    for index, instance in enumerate(document["instances"]):
        path = f"design.instances[{index}]"
        fields(instance, ("id", "name", "definition", "configuration"), (), path)
        string(instance["id"], f"{path}.id", identifier=True)
        string(instance["name"], f"{path}.name")
        string(instance["definition"], f"{path}.definition", identifier=True)
        if instance["definition"] not in definitions:
            fail(f"{path}.definition", "unknown definition")
        effective_configuration(instance, definitions[instance["definition"]], path)
    instances = index_unique(document["instances"], "design.instances")
    if document["view"] == "component":
        if "focus" not in document:
            fail("design.focus", "component view requires a focus instance")
        string(document["focus"], "design.focus", identifier=True)
        if document["focus"] not in instances:
            fail("design.focus", "unknown instance")
    elif "focus" in document:
        fail("design.focus", "focus belongs to component views")
    ports = {key: {p["id"]: p for p in definitions[value["definition"]]["ports"]} for key, value in instances.items()}
    seen, incoming = set(), {}
    for index, connection in enumerate(document["connections"]):
        path = f"design.connections[{index}]"
        fields(connection, ("source", "target"), (), path)
        endpoints = []
        for end, direction in (("source", "output"), ("target", "input")):
            endpoint = connection[end]
            fields(endpoint, ("instance", "port"), (), f"{path}.{end}")
            for key in ("instance", "port"):
                string(endpoint[key], f"{path}.{end}.{key}", identifier=True)
            if endpoint["instance"] not in ports:
                fail(f"{path}.{end}.instance", "unknown instance")
            port = ports[endpoint["instance"]].get(endpoint["port"])
            if port is None:
                fail(f"{path}.{end}.port", "unknown port")
            if port["direction"] != direction:
                fail(f"{path}.{end}", f"expected an {direction} port")
            endpoints.append(port)
        if any(endpoints[0][key] != endpoints[1][key] for key in ("kind", "type", "version")):
            fail(path, "incompatible port kind, type or version")
        identity = tuple(connection[end][key] for end in ("source", "target") for key in ("instance", "port"))
        if identity in seen:
            fail(path, "duplicate connection")
        seen.add(identity)
        target = identity[2:]
        incoming[target] = incoming.get(target, 0) + 1
    for instance_index, instance in enumerate(document["instances"]):
        for port_index, port in enumerate(ports[instance["id"]].values()):
            if port["direction"] != "input":
                continue
            count = incoming.get((instance["id"], port["id"]), 0)
            path = f"design.instances[{instance_index}].inputs[{port_index}]"
            if port["required"] and count == 0:
                fail(path, "missing required input connection")
            if port["cardinality"] == "one" and count > 1:
                fail(path, "input accepts only one connection")
    return document


def label(text, width=32):
    lines = textwrap.wrap(str(text), width, break_long_words=True, break_on_hyphens=False) or [""]
    # Numeric entities keep Graphviz substitutions such as backslash-N literal.
    return '<BR ALIGN="LEFT"/>'.join(html.escape(line, quote=True).replace("\\", "&#92;") for line in lines)


def port_cell(port, number):
    if port is None:
        return '<TD BGCOLOR="#222b3a"></TD>'
    incoming = port["direction"] == "input"
    colour = "#65d6ff" if port["kind"] == "interface" else "#ffd166"
    details = f'{port["kind"]}: {port["type"]} @ {port["version"]}'
    cardinality = f'{"required" if port["required"] else "optional"} / {port["cardinality"]}' if incoming else "provided output"
    pin = f'<FONT COLOR="{colour}">&#9679;</FONT>'
    title = f'{pin} {label(port["name"], 27)}' if incoming else f'{label(port["name"], 27)} {pin}'
    return (f'<TD PORT="p{number}" ALIGN="{"LEFT" if incoming else "RIGHT"}" BGCOLOR="#222b3a" CELLPADDING="9">'
            f'<B>{title}</B><BR/><FONT POINT-SIZE="10">{label(details, 32)}<BR/>{cardinality}</FONT></TD>')


def to_dot(document):
    validate_design(document)
    definitions = {item["id"]: item for item in document["definitions"]}
    nodes = {item["id"]: f"n{index}" for index, item in enumerate(document["instances"])}
    port_numbers = {}
    title = label(document["title"], 64)
    subtitle = f'{document["status"].title()} {document["view"]} design | {document["id"]}'
    legend = ("Arrows: provided output to required/optional input; not execution order."
              "<BR/>Blue: interface | Gold: setting | Left pins: inputs | Right pins: outputs"
               "<BR/>Definitions and versions are proposed/example snapshots, not published packages.")
    if document["schemaVersion"] == 2:
        legend = ("Arrows: provided output to required/optional input; not execution order."
                  "<BR/>Blue: interface | Gold: setting | Left pins: inputs | Right pins: outputs"
                  "<BR/>Assembled from verified package records.")
    result = ["digraph components {", f'graph [rankdir=LR, bgcolor="#101722", pad="0.35", nodesep="0.5", ranksep="0.8", splines=spline, dpi={DPI}, fontname="Helvetica", fontcolor="#edf2fa", labelloc=t, label=<'
              f'<FONT POINT-SIZE="24"><B>{title}</B></FONT><BR/>{label(subtitle, 100)}<BR/><BR/><FONT POINT-SIZE="11">{legend}</FONT>>];',
              'node [shape=plain, fontname="Helvetica", fontcolor="#edf2fa", fontsize=12];',
              'edge [color="#65d6ff", penwidth=1.6, arrowsize=0.8, fontname="Helvetica", fontsize=10, fontcolor="#edf2fa"];']
    kinds = {"component": ("Component", "#254d79"), "application": ("Application-owned code", "#594180"), "service": ("External service", "#286557")}
    for index, instance in enumerate(document["instances"]):
        definition = definitions[instance["definition"]]
        kind, colour = kinds[definition["kind"]]
        is_focus = document.get("focus") == instance["id"]
        heading = instance["name"] + (" (focus component)" if is_focus else "")
        metadata = [f'{kind} | {definition["status"].title()} definition', definition["name"]]
        if definition["kind"] == "component":
            metadata.extend([definition["package"], f'{definition["status"].title()} version {definition["version"]}'])
        else:
            metadata.append(f'{"Assembled" if document["schemaVersion"] == 2 else "Example"} revision {definition["revision"]}')
        rows = [f'<TR><TD COLSPAN="2" BGCOLOR="{colour}" CELLPADDING="10"><B>{label(heading, 48)}</B><BR/><FONT POINT-SIZE="10">'
                + '<BR/>'.join(label(item, 58) for item in metadata) + '</FONT></TD></TR>',
                '<TR><TD ALIGN="LEFT" CELLPADDING="6">INPUTS</TD><TD ALIGN="RIGHT" CELLPADDING="6">OUTPUTS</TD></TR>']
        inputs, outputs = [], []
        for number, port in enumerate(definition["ports"]):
            port_numbers[(instance["id"], port["id"])] = number
            (inputs if port["direction"] == "input" else outputs).append((number, port))
        for row in range(max(len(inputs), len(outputs))):
            left = inputs[row] if row < len(inputs) else (0, None)
            right = outputs[row] if row < len(outputs) else (0, None)
            rows.append(f'<TR>{port_cell(left[1], left[0])}{port_cell(right[1], right[0])}</TR>')
        configuration = effective_configuration(instance, definition, f"design.instances[{index}]")
        for setting in definition["settings"]:
            value = configuration.get(setting["id"], "[not set]")
            if type(value) is bool:
                value = "true" if value else "false"
            rows.append(f'<TR><TD COLSPAN="2" ALIGN="LEFT" CELLPADDING="6"><FONT POINT-SIZE="11">{label(setting["name"] + ": " + str(value), 62)}</FONT></TD></TR>')
        border = "#ffd166" if is_focus else "#6b7d95"
        result.append(f'{nodes[instance["id"]]} [label=<<TABLE BORDER="{2 if is_focus else 1}" COLOR="{border}" CELLBORDER="0" CELLSPACING="1" BGCOLOR="#1a2332">' + ''.join(rows) + '</TABLE>>];')
    for connection in document["connections"]:
        source, target = connection["source"], connection["target"]
        source_port = port_numbers[(source["instance"], source["port"])]
        target_port = port_numbers[(target["instance"], target["port"])]
        instance = next(item for item in document["instances"] if item["id"] == source["instance"])
        port = definitions[instance["definition"]]["ports"][source_port]
        colour = "#65d6ff" if port["kind"] == "interface" else "#ffd166"
        result.append(f'{nodes[source["instance"]]}:p{source_port}:e -> {nodes[target["instance"]]}:p{target_port}:w [color="{colour}", label="{port["kind"]}"];')
    result.append("}")
    return '\n'.join(result).encode("utf-8")


def resolve_dot():
    executable = shutil.which("dot")
    if not executable:
        fail("renderer", "Graphviz dot was not found on the local search path")
    return str(Path(executable).resolve())


def renderer_environment(executable):
    return {"PATH": str(Path(executable).parent) + os.pathsep + os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def run_renderer(executable, image_format, description):
    if image_format not in ("svg", "png"):
        fail("renderer", "unsupported output format")
    process = None
    try:
        process = subprocess.Popen([executable, f"-T{image_format}"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                                   env=renderer_environment(executable), start_new_session=True)
        deadline = time.monotonic() + RENDER_TIMEOUT
        output, diagnostics, written = bytearray(), 0, 0
        with selectors.DefaultSelector() as selector:
            for stream, event in ((process.stdin, selectors.EVENT_WRITE), (process.stdout, selectors.EVENT_READ), (process.stderr, selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    fail("renderer", "time limit exceeded")
                for key, _event in selector.select(remaining):
                    stream = key.fileobj
                    if stream is process.stdin:
                        try:
                            written += os.write(stream.fileno(), description[written:written + 65_536])
                        except BrokenPipeError:
                            written = len(description)
                        if written == len(description):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        data = os.read(stream.fileno(), 65_536)
                        if not data:
                            selector.unregister(stream)
                            stream.close()
                        elif stream is process.stdout:
                            if len(output) + len(data) > MAX_OUTPUT_BYTES:
                                fail("renderer", "output byte limit exceeded")
                            output.extend(data)
                        else:
                            diagnostics += len(data)
                            if diagnostics > MAX_DIAGNOSTIC_BYTES:
                                fail("renderer", "diagnostic byte limit exceeded")
            try:
                result = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                fail("renderer", "time limit exceeded")
            if result:
                fail("renderer", "Graphviz returned a nonzero exit status")
            return bytes(output)
    except OSError:
        fail("renderer", "cannot start or communicate with local Graphviz")
    finally:
        if process is not None:
            # The owned session's group can outlive its original process.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def dimensions(width, height, path):
    if not (math.isfinite(width) and math.isfinite(height)) or width <= 0 or height <= 0:
        fail(path, "invalid image dimensions")
    if math.ceil(width) > MAX_AXIS or math.ceil(height) > MAX_AXIS or math.ceil(width) * math.ceil(height) > MAX_PIXELS:
        fail(path, "image dimension limit exceeded")
    return math.ceil(width), math.ceil(height)


def svg_dimensions(data):
    try:
        if b"<!ENTITY" in data:
            fail("renderer.svg", "entity declarations are forbidden")
        root = ET.fromstring(data)
        if root.tag != f"{{{SVG_NAMESPACE}}}svg":
            fail("renderer.svg", "invalid vector root")
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] in ("script", "image", "a", "foreignObject"):
                fail("renderer.svg", "unexpected active vector content")
            if any(key.rsplit("}", 1)[-1].lower().startswith("on") or key.rsplit("}", 1)[-1] == "href" for key in element.attrib):
                fail("renderer.svg", "unexpected vector link or event")
        values = []
        for axis in ("width", "height"):
            match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(pt|px)?", root.attrib[axis])
            if match is None:
                fail("renderer.svg", "invalid vector dimensions")
            values.append(float(match[1]) * (DPI / 72 if match[2] == "pt" else 1))
        return dimensions(*values, "renderer.svg")
    except (ET.ParseError, KeyError, ValueError, OverflowError):
        fail("renderer.svg", "invalid or truncated vector output")


def png_dimensions(data):
    if not data.startswith(PNG_SIGNATURE):
        fail("renderer.png", "invalid raster signature")
    offset, size, decoder, decoded, expected = 8, None, zlib.decompressobj(), 0, 0
    ended, had_data = False, False
    try:
        while offset < len(data):
            length = struct.unpack_from(">I", data, offset)[0]
            kind = data[offset + 4:offset + 8]
            end = offset + 12 + length
            if end > len(data):
                fail("renderer.png", "truncated raster chunk")
            body = data[offset + 8:offset + 8 + length]
            crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
            if zlib.crc32(kind + body) != crc:
                fail("renderer.png", "invalid raster checksum")
            if size is None:
                if kind != b"IHDR" or length != 13:
                    fail("renderer.png", "missing raster header")
                width, height, depth, colour, compression, filtering, interlace = struct.unpack(">IIBBBBB", body)
                size = dimensions(width, height, "renderer.png")
                channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colour)
                if channels is None or depth not in (1, 2, 4, 8, 16) or compression or filtering or interlace:
                    fail("renderer.png", "unsupported raster encoding")
                expected = height * (1 + (width * channels * depth + 7) // 8)
            elif kind == b"IHDR":
                fail("renderer.png", "duplicate raster header")
            elif kind == b"IDAT":
                had_data = True
                pending = body
                while pending:
                    decoded += len(decoder.decompress(pending, 65_536))
                    if decoded > expected:
                        fail("renderer.png", "excessive decoded raster data")
                    pending = decoder.unconsumed_tail
                if decoder.unused_data:
                    fail("renderer.png", "unexpected raster data")
            elif kind == b"IEND":
                if length or end != len(data):
                    fail("renderer.png", "invalid raster ending")
                ended = True
            offset = end
        if not ended or not had_data or not decoder.eof or decoded != expected:
            fail("renderer.png", "incomplete raster output")
        return size
    except (struct.error, zlib.error):
        fail("renderer.png", "invalid or truncated raster output")


def publish_pair(prefix, vector, raster):
    prefix = Path(prefix)
    destinations = [Path(str(prefix) + ".svg"), Path(str(prefix) + ".png")]
    try:
        prefix.parent.mkdir(parents=True, exist_ok=True)
        for destination in destinations:
            if destination.is_symlink() or (destination.exists() and not destination.is_file()):
                fail("output", "destination must be a regular file")
        with tempfile.TemporaryDirectory(prefix=".component-diagram-", dir=prefix.parent) as directory:
            staging = Path(directory)
            backups, published = {}, []
            for number, (destination, data) in enumerate(zip(destinations, (vector, raster))):
                (staging / f"new{number}").write_bytes(data)
                if destination.exists():
                    backup = staging / f"old{number}"
                    shutil.copyfile(destination, backup)
                    backups[destination] = backup
            try:
                for number, destination in enumerate(destinations):
                    os.replace(staging / f"new{number}", destination)
                    published.append(destination)
            except OSError:
                for destination in reversed(published):
                    if destination in backups:
                        os.replace(backups[destination], destination)
                    else:
                        destination.unlink()
                raise
    except OSError:
        fail("output", "cannot publish image pair")
    return destinations


def generate(design_path, output_prefix):
    document = load_design(design_path)
    description = to_dot(document)
    executable = resolve_dot()
    vector = run_renderer(executable, "svg", description)
    svg_dimensions(vector)
    raster = run_renderer(executable, "png", description)
    png_dimensions(raster)
    return publish_pair(output_prefix, vector, raster)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("design", metavar="DESIGN")
    parser.add_argument("--output-prefix", required=True, metavar="PREFIX")
    arguments = parser.parse_args(argv)
    try:
        paths = generate(arguments.design, arguments.output_prefix)
    except DesignError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Generated " + " and ".join(str(path) for path in paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
