"""Contract checks, controlled process failures and real Graphviz rendering."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zlib

from aepm.diagram import generate as g


ROOT = Path(g.__file__).resolve().parent
SENTINEL = "DISTINCTIVE_PRIVATE_VALUE_6b20"


def port(identifier, direction, required=True, cardinality="one"):
    result = {"id": identifier, "name": "Shared label", "direction": direction,
              "kind": "interface", "type": "ae/contract", "version": "1.0.0"}
    if direction == "input":
        result.update(required=required, cardinality=cardinality)
    return result


def setting(secret=False, kind="string", required=True):
    return {"id": "value", "name": "Visible setting", "type": kind, "required": required, "secret": secret}


def connection(source="source", target="target", source_port="out", target_port="in"):
    return {"source": {"instance": source, "port": source_port},
            "target": {"instance": target, "port": target_port}}


def design():
    return {"schemaVersion": 1, "id": "example", "title": "Example", "status": "proposed", "view": "application",
            "definitions": [
                {"id": "producer", "name": "Shared label", "kind": "component", "status": "proposed",
                 "package": "ourapps-ae/example", "version": "0.1.0", "ports": [port("out", "output")], "settings": []},
                {"id": "consumer", "name": "Shared label", "kind": "application", "status": "example",
                 "revision": "0.1.0", "ports": [port("in", "input")], "settings": []}],
            "instances": [
                {"id": "source", "name": "Same name", "definition": "producer", "configuration": {}},
                {"id": "target", "name": "Same name", "definition": "consumer", "configuration": {}}],
            "connections": [connection()]}


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png(width=1, height=1):
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return g.PNG_SIGNATURE + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff")) + chunk(b"IEND", b"")


def svg(width="1pt", height="1pt"):
    return f'<svg xmlns="{g.SVG_NAMESPACE}" width="{width}" height="{height}"></svg>'.encode()


class ValidationTests(unittest.TestCase):
    def assert_invalid(self, value, reason=None):
        with self.assertRaises(g.DesignError) as caught:
            g.validate_design(value)
        self.assertNotIn(SENTINEL, str(caught.exception))
        if reason:
            self.assertIn(reason, str(caught.exception))

    def test_examples_are_self_contained(self):
        for path in sorted((ROOT / "examples").glob("*.json")):
            with self.subTest(path=path.name):
                value = g.load_design(path)
                self.assertIn(value["status"], ("proposed", "example"))
                for definition in value["definitions"]:
                    if definition["kind"] == "component":
                        self.assertTrue(definition["package"].startswith("ourapps-ae/"))

    def test_matching_example_packages_have_identical_contracts(self):
        contracts = {}
        shared = 0
        for path in sorted((ROOT / "examples").glob("*.json")):
            for definition in g.load_design(path)["definitions"]:
                if definition["kind"] != "component":
                    continue
                identity = (definition["package"], definition["version"])
                contract = {field: {item["id"]: item for item in definition[field]} for field in ("ports", "settings")}
                if identity in contracts:
                    shared += 1
                    self.assertEqual(contracts[identity], contract, f"Conflicting contract: {identity} in {path.name}")
                contracts[identity] = contract
        self.assertGreater(shared, 0, "Examples must exercise a shared package contract")

    def test_duplicate_labels_scoped_ports_and_multiple_instances(self):
        value = design()
        value["definitions"][1]["ports"].append(port("out", "output"))
        value["instances"].append({"id": "another", "name": "Same name", "definition": "consumer", "configuration": {}})
        value["connections"].append(connection(target="another"))
        self.assertIs(g.validate_design(value), value)

    def test_duplicate_identifiers(self):
        for collection in ("definitions", "instances", "ports", "settings"):
            with self.subTest(collection=collection):
                value = design()
                if collection == "settings":
                    value["definitions"][0]["settings"] = [setting(required=False)]
                items = value[collection] if collection in value else value["definitions"][0][collection]
                items.append(copy.deepcopy(items[0]))
                self.assert_invalid(value, "duplicate identifier")

    def test_unknown_fields_at_every_level(self):
        for level in ("root", "definition", "port", "setting", "instance", "connection", "endpoint"):
            for key in ("image", "href", "renderer", "outputPath"):
                with self.subTest(level=level, key=key):
                    value = design()
                    value["definitions"][0]["settings"] = [setting(required=False)]
                    objects = {"root": value, "definition": value["definitions"][0], "port": value["definitions"][0]["ports"][0],
                               "setting": value["definitions"][0]["settings"][0], "instance": value["instances"][0],
                               "connection": value["connections"][0], "endpoint": value["connections"][0]["source"]}
                    objects[level][key] = SENTINEL
                    self.assert_invalid(value, "unknown field")

    def test_missing_fields_and_wrong_types(self):
        for field in design():
            with self.subTest(missing=field):
                value = design()
                del value[field]
                self.assert_invalid(value, "missing field")
        for field, invalid in (("schemaVersion", True), ("schemaVersion", 2), ("title", ""), ("title", 2), ("title", "\x00"),
                               ("status", "published"), ("view", []), ("definitions", {}), ("instances", []), ("connections", None)):
            with self.subTest(field=field, invalid=invalid):
                value = design()
                value[field] = invalid
                self.assert_invalid(value)
        for root in (None, [], True, "text"):
            self.assert_invalid(root)

    def test_definition_metadata_and_exact_versions(self):
        for bad_version in ("", "latest", "1", "1.0", ">=1.0.0", "^1.0.0", "01.0.0", "1.0.0-01", "1.0.0+", 1):
            for field in ("package-version", "revision", "port-version"):
                with self.subTest(version=bad_version, field=field):
                    value = design()
                    if field == "package-version":
                        value["definitions"][0]["version"] = bad_version
                    elif field == "revision":
                        value["definitions"][1]["revision"] = bad_version
                    else:
                        value["definitions"][0]["ports"][0]["version"] = bad_version
                    self.assert_invalid(value)
        value = design()
        value["definitions"][0]["version"] = "1.2.3-beta.1+build.7"
        g.validate_design(value)
        for updates in ({"package": "unowned"}, {"package": "a/b/c"}, {"revision": "0.1.0"}, {"kind": "unknown"}, {"status": "live"}):
            value = design()
            value["definitions"][0].update(updates)
            self.assert_invalid(value)
        value = design()
        value["definitions"][1]["package"] = "ourapps-ae/rules"
        self.assert_invalid(value)

    def test_port_fields_and_identifiers(self):
        for field, bad in (("id", "../bad"), ("name", ""), ("type", ""), ("type", "a b"), ("direction", "both"),
                           ("kind", "event"), ("required", 1), ("cardinality", "several")):
            value = design()
            value["definitions"][1]["ports"][0][field] = bad
            self.assert_invalid(value)
        for field in ("required", "cardinality"):
            value = design()
            del value["definitions"][1]["ports"][0][field]
            self.assert_invalid(value)
        value = design()
        value["definitions"][0]["ports"][0]["required"] = True
        self.assert_invalid(value)

    def test_unknown_definitions_and_endpoints(self):
        value = design()
        value["instances"][0]["definition"] = "missing"
        self.assert_invalid(value, "unknown definition")
        for end in ("source", "target"):
            for key in ("instance", "port"):
                value = design()
                value["connections"][0][end][key] = "missing"
                self.assert_invalid(value, "unknown")

    def test_reversed_and_incompatible_connections(self):
        value = design()
        value["connections"][0] = connection("target", "source", "in", "out")
        self.assert_invalid(value, "expected an output")
        value = design()
        value["definitions"][1]["ports"][0] = port("in", "output")
        self.assert_invalid(value, "expected an input")
        for key, bad in (("kind", "setting"), ("type", "ae/other"), ("version", "1.0.1")):
            value = design()
            value["definitions"][1]["ports"][0][key] = bad
            self.assert_invalid(value, "incompatible")
        value = design()
        value["connections"].append(copy.deepcopy(value["connections"][0]))
        self.assert_invalid(value, "duplicate connection")

    def test_all_input_cardinalities(self):
        for required in (False, True):
            for cardinality in ("one", "many"):
                for count in (0, 1, 2):
                    with self.subTest(required=required, cardinality=cardinality, count=count):
                        value = design()
                        value["definitions"][1]["ports"][0].update(required=required, cardinality=cardinality)
                        value["instances"].append({"id": "second", "name": "Second", "definition": "producer", "configuration": {}})
                        value["connections"] = [connection(), connection(source="second")][:count]
                        if (required and count == 0) or (cardinality == "one" and count > 1):
                            self.assert_invalid(value)
                        else:
                            g.validate_design(value)

    def test_cycles_are_valid(self):
        value = design()
        value["definitions"][0]["ports"].append(port("in", "input"))
        value["definitions"][1]["ports"].append(port("out", "output"))
        value["connections"].append(connection("target", "source"))
        g.validate_design(value)
        self.assertEqual(g.to_dot(value).count(b" -> "), 2)

    def test_defaults_and_scalar_values(self):
        for kind, good, bad_values in (("string", "", (1, False, None, [])), ("number", 1.5, (True, "1", None, float("inf"), float("nan"))),
                                       ("boolean", False, (0, "false", None, {}))):
            value = design()
            value["definitions"][0]["settings"] = [dict(setting(kind=kind), default=good)]
            g.validate_design(value)
            config = g.effective_configuration(value["instances"][0], value["definitions"][0], "instance")
            self.assertEqual(config, {"value": good})
            for bad in bad_values:
                for use_default in (True, False):
                    with self.subTest(kind=kind, default=use_default):
                        invalid = copy.deepcopy(value)
                        if use_default:
                            invalid["definitions"][0]["settings"][0]["default"] = bad
                        else:
                            invalid["instances"][0]["configuration"]["value"] = bad
                        self.assert_invalid(invalid)

    def test_missing_unknown_and_malformed_configuration(self):
        value = design()
        value["definitions"][0]["settings"] = [setting()]
        self.assert_invalid(value, "missing required setting")
        for configuration in ({"unknown": SENTINEL}, [], None):
            value = design()
            value["instances"][0]["configuration"] = configuration
            self.assert_invalid(value)
        for key, invalid in (("type", "integer"), ("required", 1), ("secret", "true"), ("name", "")):
            value = design()
            value["definitions"][0]["settings"] = [setting(required=False)]
            value["definitions"][0]["settings"][0][key] = invalid
            self.assert_invalid(value)

    def test_secret_references_never_enter_description(self):
        value = design()
        value["definitions"][0]["settings"] = [setting(secret=True)]
        value["instances"][0]["configuration"]["value"] = {"secretRef": SENTINEL}
        before = copy.deepcopy(value)
        text = g.to_dot(value).decode()
        self.assertNotIn(SENTINEL, text)
        self.assertIn("[secret reference]", text)
        self.assertEqual(value, before)

    def test_secret_literals_defaults_and_malformed_references(self):
        for bad in (SENTINEL, 10, True, None, [], {"secretRef": ""}, {"secretRef": 7}, {"secretRef": "../invalid"},
                    {"secretRef": SENTINEL, "value": SENTINEL}, {"value": SENTINEL}):
            value = design()
            value["definitions"][0]["settings"] = [setting(secret=True)]
            value["instances"][0]["configuration"]["value"] = bad
            self.assert_invalid(value)
        value = design()
        value["definitions"][0]["settings"] = [dict(setting(secret=True), default={"secretRef": SENTINEL})]
        self.assert_invalid(value, "secret defaults")

    def test_component_focus(self):
        value = design()
        value["view"] = "component"
        self.assert_invalid(value, "focus")
        value["focus"] = "missing"
        self.assert_invalid(value, "unknown instance")
        value["focus"] = "source"
        g.validate_design(value)
        self.assertIn(b"focus component", g.to_dot(value))
        value["view"] = "application"
        self.assert_invalid(value, "focus belongs")

    def test_malformed_documents_and_duplicate_keys(self):
        for data in (b"", b"{", b"[] trailing", b"\xff", b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}'):
            with self.subTest(data=data), self.assertRaises(g.DesignError):
                g.parse_document(data)

    def test_invalid_unicode_fails_before_rendering(self):
        for character in ("\ud800", "\udfff", "\ufffe", "\uffff"):
            value = design()
            value["title"] = character
            self.assert_invalid(value, "Unicode")
            with self.assertRaisesRegex(g.DesignError, "Unicode"):
                g.parse_document(json.dumps(value).encode())

    def test_byte_limit_boundary(self):
        data = json.dumps(design()).encode()
        data += b" " * (g.MAX_INPUT_BYTES - len(data))
        g.validate_design(g.parse_document(data))
        with self.assertRaisesRegex(g.DesignError, "byte limit"):
            g.parse_document(data + b" ")

    def test_depth_limit_boundary_and_brackets_in_strings(self):
        g.parse_document(b"[" * g.MAX_DEPTH + b"0" + b"]" * g.MAX_DEPTH)
        with self.assertRaisesRegex(g.DesignError, "nesting"):
            g.parse_document(b"[" * (g.MAX_DEPTH + 1) + b"0" + b"]" * (g.MAX_DEPTH + 1))
        g.parse_document(json.dumps({"text": '[' * 30 + '\\"' + ']' * 30}).encode())

    def test_string_and_identifier_boundaries(self):
        for key, limit in (("title", g.MAX_STRING), ("id", g.MAX_IDENTIFIER)):
            value = design()
            value[key] = "a" * limit
            g.validate_design(value)
            value[key] += "a"
            self.assert_invalid(value, "limit")
        value = design()
        value["definitions"][0]["settings"] = [dict(setting(), default="s" * g.MAX_STRING)]
        g.validate_design(value)
        value["definitions"][0]["settings"][0]["default"] += "s"
        self.assert_invalid(value, "limit")
        for length in (g.MAX_IDENTIFIER, g.MAX_IDENTIFIER + 1):
            value = design()
            value["definitions"][0]["settings"] = [setting(secret=True)]
            value["instances"][0]["configuration"]["value"] = {"secretRef": "s" * length}
            if length == g.MAX_IDENTIFIER:
                g.validate_design(value)
            else:
                self.assert_invalid(value)

    def test_definition_and_instance_count_boundaries(self):
        for field, limit in (("definitions", g.MAX_DEFINITIONS), ("instances", g.MAX_INSTANCES)):
            value = design()
            while len(value[field]) < limit:
                addition = copy.deepcopy(value[field][0])
                addition["id"] = f"extra{len(value[field])}"
                value[field].append(addition)
            g.validate_design(value)
            value[field].append(copy.deepcopy(value[field][0]))
            self.assert_invalid(value, "item limit")

    def test_port_and_setting_count_boundaries(self):
        for field, limit in (("ports", g.MAX_PORTS), ("settings", g.MAX_SETTINGS)):
            value = design()
            items = value["definitions"][0][field]
            while len(items) < limit:
                addition = port(f"p{len(items)}", "output") if field == "ports" else dict(setting(required=False), id=f"s{len(items)}")
                items.append(addition)
            g.validate_design(value)
            items.append(copy.deepcopy(items[0]))
            self.assert_invalid(value, "item limit")

    def test_connection_count_boundary(self):
        value = design()
        value["definitions"][0]["ports"] = [port(f"out{index}", "output") for index in range(16)]
        value["definitions"][1]["ports"] = [port(f"in{index}", "input", cardinality="many") for index in range(16)]
        value["connections"] = [connection(source_port=f"out{source}", target_port=f"in{target}") for source in range(16) for target in range(16)]
        self.assertEqual(len(value["connections"]), g.MAX_CONNECTIONS)
        g.validate_design(value)
        value["connections"].append(copy.deepcopy(value["connections"][0]))
        self.assert_invalid(value, "item limit")


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def renderer(self, body):
        path = self.directory / "controlled-dot"
        path.write_text(f"#!{sys.executable}\nimport os, sys, time\n" + body + "\n")
        path.chmod(0o700)
        return str(path)

    def test_exact_arguments_input_no_shell_and_restricted_environment(self):
        executable = self.renderer('assert sys.argv[1:] in (["-Tsvg"], ["-Tpng"])\nassert sys.stdin.buffer.read() == b"description"\nassert "PRIVATE_TEST_CREDENTIAL" not in os.environ\nsys.stdout.buffer.write(b"result")')
        with mock.patch.dict(os.environ, {"PRIVATE_TEST_CREDENTIAL": SENTINEL}), mock.patch.object(g.subprocess, "Popen", wraps=subprocess.Popen) as popen:
            for image_format in ("svg", "png"):
                self.assertEqual(g.run_renderer(executable, image_format, b"description"), b"result")
                arguments, options = popen.call_args
                self.assertEqual(arguments, ([executable, "-T" + image_format],))
                self.assertIs(options["shell"], False)
                self.assertEqual(set(options["env"]), {"PATH", "LANG", "LC_ALL"})
                self.assertEqual(options["stdin"], subprocess.PIPE)
                self.assertTrue(options["start_new_session"])

    def test_wrong_format_is_rejected_before_process_start(self):
        with mock.patch.object(g.subprocess, "Popen") as popen, self.assertRaisesRegex(g.DesignError, "unsupported output"):
            g.run_renderer("unused", "pdf", b"text")
        popen.assert_not_called()

    def test_absent_renderer(self):
        with mock.patch.object(g.shutil, "which", return_value=None), self.assertRaisesRegex(g.DesignError, "not found"):
            g.resolve_dot()
        with self.assertRaisesRegex(g.DesignError, "cannot start"):
            g.run_renderer(str(self.directory / "absent"), "svg", b"text")

    def test_nonzero_exit_discards_private_diagnostics(self):
        executable = self.renderer(f'sys.stderr.write("{SENTINEL}")\nsys.exit(12)')
        with self.assertRaisesRegex(g.DesignError, "nonzero") as caught:
            g.run_renderer(executable, "svg", b"text")
        self.assertNotIn(SENTINEL, str(caught.exception))

    def test_timeout_terminates_and_reaps_process(self):
        executable = self.renderer('time.sleep(60)')
        processes = []
        original = subprocess.Popen

        def record_process(*arguments, **options):
            process = original(*arguments, **options)
            processes.append(process)
            return process

        with mock.patch.object(g, "RENDER_TIMEOUT", 0.15), mock.patch.object(g.subprocess, "Popen", side_effect=record_process):
            with self.assertRaisesRegex(g.DesignError, "time limit"):
                g.run_renderer(executable, "svg", b"text")
        self.assertEqual(len(processes), 1)
        self.assertLess(processes[0].returncode, 0)
        self.assertTrue(processes[0].stdin.closed)
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_exited_parent_does_not_leave_owned_child_executing(self):
        for failure, reason in (("timeout", "time limit"), ("stdout", "output byte limit"),
                                ("stderr", "diagnostic byte limit"), ("exit", "nonzero")):
            with self.subTest(failure=failure):
                self.check_exited_parent_cleanup(failure, reason)

    def check_exited_parent_cleanup(self, failure, reason):
        ready = self.directory / f"{failure}-ready"
        trigger = self.directory / f"{failure}-trigger"
        marker = self.directory / f"{failure}-executed-after-return"
        child_code = (
            "import os, sys, time\nfrom pathlib import Path\n"
            "parent = int(sys.argv[1])\n"
            f"Path({str(ready)!r}).write_text(str(os.getpid()))\n"
            "while os.getppid() == parent:\n    time.sleep(0.005)\n"
        )
        if failure in ("stdout", "stderr"):
            child_code += f"os.write({1 if failure == 'stdout' else 2}, b'x' * 129)\n"
        elif failure == "exit":
            child_code += "for descriptor in (0, 1, 2):\n    os.close(descriptor)\n"
        child_code += (
            f"while not Path({str(trigger)!r}).exists():\n    time.sleep(0.005)\n"
            f"Path({str(marker)!r}).write_text('child executed after renderer returned')\n"
            "time.sleep(30)\n"
        )
        executable = self.renderer(
            "import subprocess\nfrom pathlib import Path\n"
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}, str(os.getpid())])\n"
            f"while not Path({str(ready)!r}).exists():\n    time.sleep(0.005)\n"
            f"os._exit({23 if failure == 'exit' else 0})"
        )
        processes = []
        original_popen, original_killpg = subprocess.Popen, os.killpg

        def capture(*arguments, **options):
            process = original_popen(*arguments, **options)
            processes.append(process)
            return process

        try:
            with mock.patch.object(g.subprocess, "Popen", side_effect=capture), \
                    mock.patch.object(g.os, "killpg", wraps=original_killpg) as kill_group, \
                    mock.patch.object(g, "RENDER_TIMEOUT", 0.6), \
                    mock.patch.object(g, "MAX_OUTPUT_BYTES", 128), \
                    mock.patch.object(g, "MAX_DIAGNOSTIC_BYTES", 128):
                with self.assertRaisesRegex(g.DesignError, reason):
                    g.run_renderer(executable, "svg", b"")
            self.assertEqual(len(processes), 1)
            self.assertEqual(processes[0].poll(), 23 if failure == "exit" else 0)
            self.assertTrue(ready.exists(), "Child must start before the renderer parent exits")
            trigger.touch()
            deadline = time.monotonic() + 0.3
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertFalse(marker.exists(), "Owned child performed new work after renderer returned")
            kill_group.assert_called_once_with(processes[0].pid, signal.SIGKILL)
            for stream in (processes[0].stdin, processes[0].stdout, processes[0].stderr):
                self.assertTrue(stream.closed)
        finally:
            # The reproduction must clean its own group even when an assertion fails.
            for process in processes:
                try:
                    original_killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

    def test_output_stream_limit_boundary(self):
        for amount in (g.MAX_OUTPUT_BYTES, g.MAX_OUTPUT_BYTES + 1):
            executable = self.renderer(f'sys.stdout.buffer.write(b"x" * {amount})')
            if amount == g.MAX_OUTPUT_BYTES:
                self.assertEqual(len(g.run_renderer(executable, "svg", b"")), amount)
            else:
                with self.assertRaisesRegex(g.DesignError, "output byte limit"):
                    g.run_renderer(executable, "svg", b"")

    def test_diagnostic_stream_limit_boundary(self):
        for amount in (g.MAX_DIAGNOSTIC_BYTES, g.MAX_DIAGNOSTIC_BYTES + 1):
            executable = self.renderer(f'sys.stderr.buffer.write(b"x" * {amount})\nsys.stdout.buffer.write(b"ok")')
            if amount == g.MAX_DIAGNOSTIC_BYTES:
                self.assertEqual(g.run_renderer(executable, "svg", b""), b"ok")
            else:
                with self.assertRaisesRegex(g.DesignError, "diagnostic byte limit"):
                    g.run_renderer(executable, "svg", b"")

    def test_large_standard_input_does_not_deadlock(self):
        executable = self.renderer(f'sys.stdout.buffer.write(b"x" * 100000)\nsys.stdout.flush()\nassert len(sys.stdin.buffer.read()) == {g.MAX_INPUT_BYTES}')
        self.assertEqual(len(g.run_renderer(executable, "svg", b"a" * g.MAX_INPUT_BYTES)), 100000)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.input = self.directory / "design.json"
        self.input.write_text(json.dumps(design()))
        self.prefix = self.directory / "images" / "result"

    def test_vector_dimensions_and_invalid_markup(self):
        self.assertEqual(g.svg_dimensions(svg("72pt", "96px")), (96, 96))
        for data in (b"", b"<svg", b"<html/>", svg("0pt"), svg("2em"), b'<svg xmlns="http://www.w3.org/2000/svg"/>',
                     b'<!DOCTYPE svg [<!ENTITY a "x">]>' + svg(),
                     svg().replace(b"></svg>", b'><image href="file:///private"/></svg>'),
                     svg().replace(b"></svg>", b'><script>bad()</script></svg>'),
                     svg().replace(b"></svg>", b'><g onload="bad()"/></svg>')):
            with self.subTest(data=data), self.assertRaises(g.DesignError):
                g.svg_dimensions(data)

    def test_resolution_constant_controls_graph_and_dimension_conversion(self):
        with mock.patch.object(g, "DPI", 144):
            self.assertTrue(b"dpi=144," in g.to_dot(design()), "Graph resolution must use the declared constant")
            self.assertEqual(g.svg_dimensions(svg("72pt", "72pt")), (144, 144))

    def test_raster_structure_checks(self):
        self.assertEqual(g.png_dimensions(png()), (1, 1))
        for data in (b"", png()[:20], png()[:-1], png()[:-12], png() + b"extra", png().replace(b"IDAT", b"BAD!"),
                     g.PNG_SIGNATURE + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)) + chunk(b"IDAT", b"bad") + chunk(b"IEND", b"")):
            with self.subTest(length=len(data)), self.assertRaises(g.DesignError):
                g.png_dimensions(data)

    def test_image_axis_and_canvas_boundaries(self):
        self.assertEqual(g.svg_dimensions(svg(f"{g.MAX_AXIS}px", "1px")), (g.MAX_AXIS, 1))
        self.assertEqual(g.svg_dimensions(svg("4000px", "4000px")), (4000, 4000))
        for width, height in ((g.MAX_AXIS + 1, 1), (1, g.MAX_AXIS + 1), (4000, 4001)):
            with self.assertRaisesRegex(g.DesignError, "dimension limit"):
                g.svg_dimensions(svg(f"{width}px", f"{height}px"))
            with self.assertRaisesRegex(g.DesignError, "dimension limit"):
                g.png_dimensions(png(width, height))
        self.assertEqual(g.dimensions(g.MAX_AXIS, 1, "test"), (g.MAX_AXIS, 1))
        self.assertEqual(g.dimensions(4000, 4000, "test"), (4000, 4000))

    def test_invalid_design_never_invokes_renderer(self):
        invalids = [b"{", b'{"duplicate":1,"duplicate":2}', b"[" * 17 + b"]" * 17]
        for field, bad in (("schemaVersion", True), ("connections", []), ("definitions", []), ("title", "x" * 257), ("instances", {})):
            value = design()
            value[field] = bad
            invalids.append(json.dumps(value).encode())
        value = design()
        value["definitions"][0]["settings"] = [setting(secret=True)]
        value["instances"][0]["configuration"] = {"value": SENTINEL}
        invalids.append(json.dumps(value).encode())
        with mock.patch.object(g, "run_renderer") as renderer, mock.patch.object(g, "resolve_dot") as resolve:
            for data in invalids:
                self.input.write_bytes(data)
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(g.main([str(self.input), "--output-prefix", str(self.prefix)]), 1)
                self.assertNotIn(SENTINEL, errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())
            renderer.assert_not_called()
            resolve.assert_not_called()
        self.assertFalse(self.prefix.parent.exists())

    def test_missing_and_unreadable_input(self):
        with self.assertRaisesRegex(g.DesignError, "cannot read"):
            g.load_design(self.directory / "absent")
        with mock.patch.object(Path, "open", side_effect=PermissionError), self.assertRaisesRegex(g.DesignError, "cannot read"):
            g.load_design(self.input)

    def test_svg_preflight_blocks_raster(self):
        with mock.patch.object(g, "resolve_dot", return_value="trusted"), mock.patch.object(g, "run_renderer", return_value=svg("9000px")) as renderer:
            with self.assertRaisesRegex(g.DesignError, "dimension limit"):
                g.generate(self.input, self.prefix)
            self.assertEqual(renderer.call_count, 1)
            self.assertEqual(renderer.call_args.args[1], "svg")
        self.assertFalse(self.prefix.parent.exists())

    def test_all_renderer_failures_preserve_existing_outputs(self):
        self.prefix.parent.mkdir()
        for extension in ("svg", "png"):
            Path(str(self.prefix) + "." + extension).write_bytes(b"original-" + extension.encode())
        failures = [[g.DesignError("renderer: unavailable")], [g.DesignError("renderer: time limit")],
                    [g.DesignError("renderer: output byte limit")], [b"bad vector"], [svg(), b"bad raster"],
                    [svg(), g.DesignError("renderer: nonzero")], [svg(), png(9000, 1)]]
        for outputs in failures:
            with self.subTest(outputs=len(outputs)), mock.patch.object(g, "resolve_dot", return_value="trusted"), mock.patch.object(g, "run_renderer", side_effect=outputs):
                with self.assertRaises(g.DesignError):
                    g.generate(self.input, self.prefix)
                for extension in ("svg", "png"):
                    self.assertEqual(Path(str(self.prefix) + "." + extension).read_bytes(), b"original-" + extension.encode())
                self.assertEqual(len(list(self.prefix.parent.iterdir())), 2)

    def test_renderer_failure_leaves_no_new_pair(self):
        with mock.patch.object(g, "resolve_dot", return_value="trusted"), mock.patch.object(g, "run_renderer", side_effect=[svg(), b"broken"]):
            with self.assertRaises(g.DesignError):
                g.generate(self.input, self.prefix)
        self.assertFalse(self.prefix.parent.exists())

    def test_publish_and_replace_pair(self):
        for vector, raster in ((svg(), png()), (svg("2px"), png())):
            paths = g.publish_pair(self.prefix, vector, raster)
            self.assertEqual([path.read_bytes() for path in paths], [vector, raster])
            self.assertEqual(len(list(self.prefix.parent.iterdir())), 2)

    def test_publication_failure_rolls_back_both_new_and_existing_files(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                prefix = self.directory / str(existing) / "pair"
                if existing:
                    g.publish_pair(prefix, b"old vector", b"old raster")
                replace = os.replace
                calls = 0

                def fail_second(source, destination):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise PermissionError("controlled failure")
                    return replace(source, destination)

                with mock.patch.object(g.os, "replace", side_effect=fail_second), self.assertRaisesRegex(g.DesignError, "cannot publish"):
                    g.publish_pair(prefix, svg(), png())
                actual = list(prefix.parent.iterdir())
                if existing:
                    self.assertEqual(Path(str(prefix) + ".svg").read_bytes(), b"old vector")
                    self.assertEqual(Path(str(prefix) + ".png").read_bytes(), b"old raster")
                    self.assertEqual(len(actual), 2)
                else:
                    self.assertEqual(actual, [])

    def test_output_permissions_and_nonfile_destinations(self):
        self.prefix.parent.mkdir()
        Path(str(self.prefix) + ".svg").mkdir()
        with self.assertRaisesRegex(g.DesignError, "regular file"):
            g.publish_pair(self.prefix, svg(), png())
        with mock.patch.object(g.tempfile, "TemporaryDirectory", side_effect=PermissionError), self.assertRaisesRegex(g.DesignError, "cannot publish"):
            g.publish_pair(self.directory / "denied" / "pair", svg(), png())
        Path(str(self.directory / "link") + ".svg").symlink_to(self.input)
        with self.assertRaisesRegex(g.DesignError, "regular file"):
            g.publish_pair(self.directory / "link", svg(), png())

    def test_command_errors_are_nonzero_and_do_not_echo_secrets(self):
        value = design()
        value["definitions"][0]["settings"] = [setting(secret=True)]
        value["instances"][0]["configuration"] = {"value": SENTINEL}
        self.input.write_text(json.dumps(value))
        result = subprocess.run([sys.executable, str(ROOT / "generate.py"), str(self.input), "--output-prefix", str(self.prefix)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("configuration", result.stderr)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class RealGraphvizTests(unittest.TestCase):
    def setUp(self):
        self.executable = g.resolve_dot()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_both_examples_through_documented_command(self):
        for name, edges, nodes in (("ourpoker-proposed", 8, 7), ("realtime-rooms-neighbours", 3, 4)):
            with self.subTest(example=name):
                prefix = self.directory / name
                result = subprocess.run([sys.executable, str(ROOT / "generate.py"), str(ROOT / "examples" / f"{name}.json"),
                                         "--output-prefix", str(prefix)], capture_output=True, text=True, timeout=30, cwd=self.directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                vector = Path(str(prefix) + ".svg").read_bytes()
                raster = Path(str(prefix) + ".png").read_bytes()
                g.svg_dimensions(vector)
                g.png_dimensions(raster)
                root = ET.fromstring(vector)
                texts = " ".join(root.itertext())
                self.assertIn("ourapps-ae/realtime-rooms", texts)
                self.assertIn("Proposed definition", texts)
                self.assertIn("Proposed version 0.1.0", texts)
                self.assertIn("[secret reference]", texts)
                self.assertIn("Optional room observer", texts)
                if name == "ourpoker-proposed":
                    self.assertIn("OurPoker", texts)
                    self.assertIn("setting", texts)
                    self.assertIn("External service", texts)
                groups = root.findall(f".//{{{g.SVG_NAMESPACE}}}g")
                self.assertEqual(sum(item.get("class") == "node" for item in groups), nodes)
                edge_groups = [item for item in groups if item.get("class") == "edge"]
                self.assertEqual(len(edge_groups), edges)
                for edge in edge_groups:
                    self.assertIsNotNone(edge.find(f"{{{g.SVG_NAMESPACE}}}path"))
                    self.assertIsNotNone(edge.find(f"{{{g.SVG_NAMESPACE}}}polygon"))
                    self.assertIn(":e->", edge.find(f"{{{g.SVG_NAMESPACE}}}title").text)
                    self.assertTrue(edge.find(f"{{{g.SVG_NAMESPACE}}}title").text.endswith(":w"))
                value = g.load_design(ROOT / "examples" / f"{name}.json")
                for instance in value["instances"]:
                    for configured in instance["configuration"].values():
                        if isinstance(configured, dict):
                            self.assertNotIn(configured["secretRef"].encode(), vector + raster)

    def test_hostile_labels_are_literal_and_secrets_absent(self):
        value = design()
        hostile = 'Quotes " \\N <script> & <IMG SRC="x">'
        value["title"] = hostile
        value["instances"][0]["name"] = hostile
        value["definitions"][0]["settings"] = [setting(secret=True), dict(setting(required=False), id="public", default=hostile)]
        value["instances"][0]["configuration"]["value"] = {"secretRef": SENTINEL}
        description = g.to_dot(value)
        self.assertNotIn(SENTINEL.encode(), description)
        vector = g.run_renderer(self.executable, "svg", description)
        raster = g.run_renderer(self.executable, "png", description)
        g.svg_dimensions(vector)
        g.png_dimensions(raster)
        self.assertNotIn(SENTINEL.encode(), vector + raster)
        root = ET.fromstring(vector)
        texts = " ".join(root.itertext())
        self.assertIn(hostile, texts)
        self.assertIn("\\N", texts)
        for element in root.iter():
            self.assertNotIn(element.tag.rsplit("}", 1)[-1], ("script", "image", "a", "foreignObject"))

    def test_real_cycle_renders(self):
        value = design()
        value["definitions"][0]["ports"].append(port("in", "input"))
        value["definitions"][1]["ports"].append(port("out", "output"))
        value["connections"].append(connection("target", "source"))
        description = g.to_dot(value)
        g.svg_dimensions(g.run_renderer(self.executable, "svg", description))
        g.png_dimensions(g.run_renderer(self.executable, "png", description))


if __name__ == "__main__":
    unittest.main()
