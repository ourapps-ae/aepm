"""Recipe evaluation: rules 1 to 25 of the recipe evaluation rules in the component standard.

`evaluate(world, answers)` turns a recipe (recipe.json), the manifests and suitability files of the components it names and the
recipe's own manifest into an aepm application definition (format 1) for one set of answers. Errors are values (rule 12):
{"ok": True, "design": {...}} or {"ok": False, "errors": [{"code": ..., "path": ...}]}, codes unanswered, invalid-answer,
missing-setting, uncovered, unconnected, conflicting-sets, unknown-component, unknown-setting.

Conditions (`includedWhen`, `askWhen`) are CEL expressions; the parser, type check and evaluation below cover exactly the subset
the standard allows. A `World` is read from stored package archives (`World.from_store`) or from source directories
(`World.from_directories`).
"""
import json
import re
from pathlib import Path

APPLICATION = "application"
UNSET = object()  # a secretRef question that was not asked: the reference is left unset (clarification a)

GRAMMARS = {
    "identifier": r"[A-Za-z][A-Za-z0-9_]{0,63}",
    "qualified": r"[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+",
    "slug": r"[a-z][a-z0-9-]{0,63}",
    "label": r"[A-Za-z][A-Za-z0-9 -]{0,63}",
    "environment": r"[A-Z][A-Z0-9_]{0,63}",
    "address": r"https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9_/-]*)?",
}
SECRET_REFERENCE = r"[A-Za-z][A-Za-z0-9_./-]{0,127}"
COST_RANK = {"none": 0, "free": 1, "paid": 2, "metered": 3}
SCALE_KEYS = ("concurrentPeople", "requestsPerDay", "storedMegabytes")


def read(path):
    return json.loads(Path(path).read_text())


class Package:
    """One component: its manifest, suitability profiles and packaged file bytes."""

    def __init__(self, manifest, read_file):
        self.manifest, self._read = manifest, read_file
        self.name, self.version = manifest["identity"]["name"], manifest["identity"]["version"]
        data = self.file("suitability.json")
        self.suitability = json.loads(data) if data is not None else {"profiles": []}

    def file(self, path):
        """Bytes of a packaged file, or None."""
        listed = {item["path"] for item in self.manifest["files"]}
        return self._read(path) if path in listed else None


class World:
    """A recipe, the component in each of its slots, the job candidates, and the recipe's own manifest.

    `manifests` and `suitability` are by slot id (and `application`) for the components that fill the slots."""

    def __init__(self, recipe, application, packages, substitutes=None):
        self.recipe, self.application, self.packages = recipe, application, packages
        self.substitutes = dict(substitutes or {})
        self.slots = {slot["id"]: slot for slot in recipe["components"]}
        self.filling = {}
        for slot in recipe["components"]:
            key = self.substitutes.get(slot["id"]) or (slot["preferred"]["name"], slot["preferred"]["version"])
            if key in packages:
                self.filling[slot["id"]] = packages[key]
        self.manifests = {slot: package.manifest for slot, package in self.filling.items()}
        self.manifests[APPLICATION] = application
        self.suitability = {slot: package.suitability for slot, package in self.filling.items()}

    def wanted(self):
        """(name, version) of every package the recipe may place: preferred components and job candidates."""
        keys = [(slot["preferred"]["name"], slot["preferred"]["version"]) for slot in self.recipe["components"]]
        for job in self.recipe.get("jobs", []):
            preferred = self.slots.get(job.get("slot"), {}).get("preferred", {})
            keys += [candidate_key(candidate, preferred) for candidate in job["candidates"]]
        return keys

    @classmethod
    def from_directories(cls, recipe_directory, components_directory):
        """Source layout: recipe_directory holds recipe.json and component.json; components_directory/<short name>/ each
        component, at the version its manifest declares."""
        recipe = read(Path(recipe_directory) / "recipe.json")
        packages = {}
        for directory in sorted(Path(components_directory).iterdir()):
            if (directory / "component.json").is_file():
                package = Package(read(directory / "component.json"), lambda path, root=directory: (root / path).read_bytes())
                packages[(package.name, package.version)] = package
        return cls(recipe, read(Path(recipe_directory) / "component.json"), packages)

    @classmethod
    def from_store(cls, name, version, store, substitutes=None):
        """Everything from stored archives: the recipe package `name` at `version`, every preferred component and job
        candidate, and each substitute {slot: (name, version)}; a substitute missing from the store is refused."""
        from .bundle import read_package
        from .model import fail, loads
        store = Path(store)
        entries = {(e["name"], e["version"]): e for e in loads((store / "catalogue.json").read_bytes(), "catalogue")["entries"]}

        def package(key):
            entry = entries.get(key)
            if entry is None:
                return None
            manifest, payloads = read_package(entry, store)
            return Package(manifest, payloads.__getitem__)

        found = entries.get((name, version))
        if found is None:
            fail("unknown-package", f"{name}@{version}")
        manifest, payloads = read_package(found, store)
        if manifest["kind"] != "recipe" or "recipe.json" not in payloads:
            fail("not-a-recipe", f"{name}@{version}")
        recipe = loads(payloads["recipe.json"], "recipe.json")
        if (recipe.get("name"), recipe.get("version")) != (name, version):
            fail("recipe-identity", "recipe.json")
        for slot, key in (substitutes or {}).items():
            if key not in entries:
                fail("unknown-package", f"{slot}={key[0]}@{key[1]}")
        world = cls(recipe, manifest, {})
        keys = set(world.wanted()) | set((substitutes or {}).values())
        packages = {key: loaded for key in sorted(keys) if (loaded := package(key)) is not None}
        return cls(recipe, manifest, packages, substitutes)

    def with_recipe(self, recipe):
        return World(recipe, self.application, self.packages, self.substitutes)


def candidate_key(candidate, preferred):
    """A job candidate's (name, version): its own version, or the slot's preferred version for the preferred component."""
    if "version" in candidate:
        return candidate["component"], candidate["version"]
    return candidate["component"], preferred.get("version") if preferred.get("name") == candidate["component"] else None


# ---- slots: the class of a slot and the fit rule (component standard, "Recipe slots and component classes") ----

SETTING_TYPES = {"string": "string", "boolean": "boolean", "integer": "integer"}


def setting_schema(declaration):
    """The JSON Schema property a class uses for one setting: its type, and for a string its grammar as an anchored pattern."""
    schema = {"type": SETTING_TYPES[declaration["type"]]}
    if declaration["type"] == "string":
        schema["pattern"] = "^" + GRAMMARS[declaration["grammar"]] + "$"
    return schema


def module_paths(documents):
    """platform -> entry path for every x-ourapps-modules map of the class's interface documents."""
    modules = []
    for document in documents:
        try:
            value = json.loads(document)
        except ValueError:
            continue
        for platform, path in (value.get("x-ourapps-modules") or {}).items() if isinstance(value, dict) else ():
            modules.append((platform, path))
    return modules


NATIVE = ("apple", "android")


def fit(slot_class, package, preferred):
    """Why `package` does not fit `slot_class` (rules 1 to 4), or an empty list when it fits. `preferred` is the slot's
    preferred component, whose interface documents define the class's documents."""
    reasons = []
    manifest = package.manifest
    provided = {(port["type"], port["version"]): port for port in manifest["provides"]}
    preferred_ports = {(port["type"], port["version"]): port for port in preferred.manifest["provides"]}
    documents = []
    for interface in slot_class["provides"]:
        key = (interface["type"], interface["version"])
        theirs, ours = provided.get(key), preferred_ports.get(key)
        if theirs is None:
            reasons.append(f"provides:{key[0]}@{key[1]}")
            continue
        expected = preferred.file(ours["path"]) if ours is not None else None
        if expected is None or package.file(theirs["path"]) != expected:
            reasons.append(f"document:{key[0]}@{key[1]}")
            continue
        documents.append(expected)
    allowed = {(interface["type"], interface["version"]) for interface in slot_class["requires"]}
    for port in manifest["requires"]:
        if not port.get("optional") and (port["type"], port["version"]) not in allowed:
            reasons.append(f"requires:{port['type']}@{port['version']}")
    settings = {item["id"]: item for item in manifest["collect"]}
    schema = slot_class["configuration"]
    for name, wanted in schema.get("properties", {}).items():
        declaration = settings.get(name)
        if declaration is None:
            reasons.append(f"setting:{name}")
        elif {key: wanted.get(key) for key in setting_schema(declaration)} != setting_schema(declaration) or wanted.get("type") != setting_schema(declaration)["type"]:
            reasons.append(f"setting-type:{name}")
    required = set(schema.get("required", []))
    for declaration in manifest["collect"]:
        if declaration["required"] and "default" not in declaration and declaration["id"] not in required:
            reasons.append(f"unset-setting:{declaration['id']}")
    short = "components/" + package.name.split("/", 1)[1] + "/"
    destinations = [item["destination"] for item in manifest["artefacts"]]
    for platform, path in module_paths(documents):
        if not isinstance(path, str):
            reasons.append(f"module:{platform}")
        elif platform in NATIVE:
            if not any(item.startswith(short + path.rstrip("/") + "/") for item in destinations):
                reasons.append(f"module:{platform}:{path}")
        elif short + path not in destinations:
            reasons.append(f"module:{platform}:{path}")
    return reasons


def questions(recipe):
    """What to ask: each question's id, wording, type, choices or range, default and askWhen condition."""
    out = []
    for q in recipe["questions"]:
        item = {key: q[key] for key in ("id", "ask", "askAgent", "type") if key in q}
        for key in ("options", "min", "max", "default"):
            if key in q:
                item[key] = q[key]
        item["askWhen"] = q.get("askWhen")
        out.append(item)
    return out


def fits_grammar(grammar, value):
    return isinstance(value, str) and grammar in GRAMMARS and re.fullmatch(GRAMMARS[grammar], value) is not None


# ---- rule 3: conditions are CEL (Common Expression Language) expressions of type bool ----
# Only the subset component-standard.md ("Standards") allows: literals (text, 64-bit integers, true, false, lists of one type),
# question ids, == != < <= > >=, `in` (list membership), && || !, parentheses and size(). Anything else is a CelError.

class CelError(ValueError):
    pass


KIND = {"set": "list(string)", "boolean": "bool", "integer": "int", "choice": "string", "text": "string", "secretRef": "string", "account": "string"}
ZERO = {"list(string)": [], "bool": False, "int": 0, "string": ""}  # the value of a question that has none (an unset reference)
INT64 = (-(2 ** 63), 2 ** 63 - 1)
RESERVED = {"as", "break", "const", "continue", "else", "for", "function", "if", "import", "let", "loop", "package", "namespace", "return", "var", "void", "while", "in", "null"}
ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "?": "?", "'": "'", '"': '"', "`": "`"}
_TOKEN = re.compile(r"""
    (?P<space>\s+|//[^\n]*)
  | (?P<number>0[xX][0-9a-fA-F]+[uU]?|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?[uU]?|\.\d+(?:[eE][+-]?\d+)?)
  | (?P<string>(?:[rRbB]{1,2})?(?:'''(?:\\.|[^\\])*?'''|\"\"\"(?:\\.|[^\\])*?\"\"\"|'(?:\\.|[^\\'\n])*'|"(?:\\.|[^\\"\n])*"))
  | (?P<name>[_A-Za-z][_A-Za-z0-9]*)
  | (?P<op>==|!=|<=|>=|&&|\|\||[<>!()\[\],.\-+*/%?:{}])
""", re.X | re.S)


def _tokens(text):
    out, at = [], 0
    while at < len(text):
        m = _TOKEN.match(text, at)
        if not m:
            raise CelError(f"cannot read {text[at:at + 10]!r}")
        at = m.end()
        if m.lastgroup != "space":
            out.append((m.lastgroup, m.group(), m.start()))
    return out + [("end", "", len(text))]


def _string(token):
    prefix = re.match(r"[rRbB]*", token).group().lower()
    if "b" in prefix:
        raise CelError("a bytes literal is not allowed; literals are quoted text, whole numbers, true and false")
    body = token[len(prefix):]
    quote = 3 if body[:3] in ("'''", '"""') else 1
    body = body[quote:-quote]
    if "r" in prefix:
        return body
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        e = body[i + 1]
        if e in ESCAPES:
            out.append(ESCAPES[e])
            i += 2
        elif e in "xX" and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 2:i + 4]):
            out.append(chr(int(body[i + 2:i + 4], 16)))
            i += 4
        elif e == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", body[i + 2:i + 6]):
            out.append(chr(int(body[i + 2:i + 6], 16)))
            i += 6
        elif e == "U" and re.fullmatch(r"[0-9a-fA-F]{8}", body[i + 2:i + 10]):
            out.append(chr(int(body[i + 2:i + 10], 16)))
            i += 10
        elif re.fullmatch(r"[0-3][0-7]{2}", body[i + 1:i + 4]):
            out.append(chr(int(body[i + 1:i + 4], 8)))
            i += 4
        else:
            raise CelError(f"unknown escape \\{e}")
    return "".join(out)


class _Parser:
    """Recursive descent over CEL's grammar, keeping only the allowed subset. Trees: ("lit", value), ("id", name),
    ("list", [trees]), ("call", operator, [trees]) with operator one of == != < <= > >= in && || ! size."""

    NOT_ALLOWED = {"+": "+", "*": "*", "/": "/", "%": "%", "?": "the conditional ?:", "{": "a map or message literal"}

    def __init__(self, text):
        self.tokens, self.at = _tokens(text), 0

    def peek(self):
        return self.tokens[self.at][:2]

    def take(self, value=None):
        token = self.tokens[self.at]
        if value is not None and token[1] != value:
            raise CelError(f"expected {value!r}, found {token[1] or 'the end'!r}")
        self.at += 1
        return token[:2]

    def refuse_operator(self):
        kind, value = self.peek()
        if kind == "op" and value in self.NOT_ALLOWED:
            raise CelError(f"{self.NOT_ALLOWED[value]} is not allowed")
        if kind == "op" and value == "-":
            raise CelError("- is not allowed")

    def parse(self):
        tree = self.disjunction()
        self.refuse_operator()
        if self.peek()[0] != "end":
            raise CelError(f"unexpected {self.peek()[1]!r}")
        return tree

    def disjunction(self):
        tree = self.conjunction()
        while self.peek() == ("op", "||"):
            self.take()
            tree = ("call", "||", [tree, self.conjunction()])
        return tree

    def conjunction(self):
        tree = self.relation()
        while self.peek() == ("op", "&&"):
            self.take()
            tree = ("call", "&&", [tree, self.relation()])
        return tree

    def relation(self):
        tree = self.unary()
        self.refuse_operator()
        while self.peek() in (("op", "=="), ("op", "!="), ("op", "<"), ("op", "<="), ("op", ">"), ("op", ">="), ("name", "in")):
            op = self.take()[1]
            tree = ("call", op, [tree, self.unary()])
            self.refuse_operator()
        return tree

    def unary(self):
        bangs = 0
        while self.peek() == ("op", "!"):
            self.take()
            bangs += 1
        minuses = 0
        while self.peek() == ("op", "-") and not (minuses == 0 and self.signed_number()):
            # as CEL's grammar: a run of minuses written together cancels in pairs; an odd run is unary minus, not allowed
            minuses += 1
            end = self.tokens[self.at][2] + 1
            self.take()
            if self.peek() != ("op", "-") or self.tokens[self.at][2] != end:
                break
        if minuses % 2:
            raise CelError("unary minus is not allowed")
        if self.signed_number():
            self.take()
            tree = ("lit", -self.number(self.take()[1]))
        else:
            tree = self.member()
        return ("call", "!", [tree]) if bangs % 2 else tree

    def signed_number(self):
        """A minus written directly before a number is part of the literal."""
        token, after = self.tokens[self.at], self.tokens[self.at + 1] if self.at + 1 < len(self.tokens) else ("end", "", 0)
        return token[:2] == ("op", "-") and after[0] == "number" and after[2] == token[2] + 1

    def number(self, text):
        if text[-1] in "uU":
            raise CelError("a uint64 literal is not allowed; literals are quoted text, whole numbers, true and false")
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
            return int(text, 16)
        if not text.isdigit():
            raise CelError("a double literal is not allowed; literals are quoted text, whole numbers, true and false")
        return int(text)

    def member(self):
        tree = self.primary()
        while True:
            if self.peek() == ("op", "["):
                raise CelError("indexing is not allowed")
            if self.peek() != ("op", "."):
                return tree
            self.take()
            kind, name = self.take()
            if kind != "name":
                raise CelError("a name must follow '.'")
            if self.peek() != ("op", "("):
                raise CelError(f"field selection (.{name}) is not allowed")
            self.take("(")
            if name != "size" or self.peek() != ("op", ")"):
                raise CelError(f"the method {name}() is not allowed")
            self.take(")")
            tree = ("call", "size", [tree])

    def primary(self):
        kind, value = self.take()
        if kind == "number":
            return ("lit", self.number(value))
        if kind == "string":
            return ("lit", _string(value))
        if kind == "name":
            if value in ("true", "false"):
                return ("lit", value == "true")
            if value == "null":
                raise CelError("a null literal is not allowed; literals are quoted text, whole numbers, true and false")
            if value in RESERVED:
                raise CelError(f"{value} is a reserved word")
            if self.peek() == ("op", "("):
                self.take()
                args = self.arguments(")")
                if value in ("has", "all", "exists", "exists_one", "map", "filter"):
                    raise CelError("macros (has, all, exists, exists_one, map, filter) are not allowed")
                if value != "size" or len(args) != 1:
                    raise CelError(f"the function {value}() is not allowed")
                return ("call", "size", args)
            return ("id", value)
        if (kind, value) == ("op", "("):
            tree = self.disjunction()
            self.refuse_operator()
            self.take(")")
            return tree
        if (kind, value) == ("op", "["):
            return ("list", self.arguments("]"))
        if kind == "op" and value in self.NOT_ALLOWED:
            raise CelError(f"{self.NOT_ALLOWED[value]} is not allowed")
        raise CelError(f"unexpected {value or 'end'!r}")

    def arguments(self, close):
        items = []
        while self.peek() != ("op", close):
            items.append(self.disjunction())
            if self.peek() != ("op", ","):
                break
            self.take()
        self.take(close)
        return items


_PARSED = {}


def parse_condition(text):
    """The tree of a condition; raises CelError for anything outside the allowed subset."""
    if not isinstance(text, str) or not text.strip() or len(text) > 1000:
        raise CelError("a condition must be a CEL expression of 1 to 1000 characters")
    if text not in _PARSED:
        _PARSED[text] = _Parser(text).parse()
    return _PARSED[text]


def kind_of(tree, kinds):
    """The CEL type of a tree, given the type of each question id (`KIND`); raises CelError on a type error."""
    tag = tree[0]
    if tag == "lit":
        value = tree[1]
        if type(value) is bool:
            return "bool"
        if type(value) is int:
            if not INT64[0] <= value <= INT64[1]:
                raise CelError(f"{value} is outside the 64-bit integer range")
            return "int"
        return "string"
    if tag == "id":
        if tree[1] not in kinds:
            raise CelError(f"{tree[1]} is not a question of the recipe")
        return kinds[tree[1]]
    if tag == "list":
        if not 1 <= len(tree[1]) <= 50:
            raise CelError("a list needs 1 to 50 values")
        if any(item[0] != "lit" for item in tree[1]):
            raise CelError("a list holds only literals")
        item_kinds = {kind_of(item, kinds) for item in tree[1]}
        if len(item_kinds) != 1:
            raise CelError("a list holds values of one type")
        return f"list({item_kinds.pop()})"
    op, args = tree[1], tree[2]
    got = [kind_of(a, kinds) for a in args]
    if op in ("&&", "||", "!"):
        if any(k != "bool" for k in got):
            raise CelError(f"{op} takes true or false")
        return "bool"
    if op == "size":
        if got[0] != "string" and not got[0].startswith("list("):
            raise CelError(f"size() takes text or a set, not {got[0]}")
        return "int"
    if op == "in":
        if got[1] != f"list({got[0]})":
            raise CelError(f"in needs a value and a list of the same type, not {got[0]} in {got[1]}")
        return "bool"
    if got[0] != got[1]:
        raise CelError(f"{op} compares {got[0]} with {got[1]}")
    if got[0].startswith("list("):
        raise CelError(f"{op} cannot compare sets")
    if op not in ("==", "!=") and got[0] == "bool":
        raise CelError(f"{op} cannot order true and false")
    return "bool"


def names_in(tree):
    if tree[0] == "id":
        return {tree[1]}
    if tree[0] == "lit":
        return set()
    return set().union(*(names_in(t) for t in (tree[1] if tree[0] == "list" else tree[2])))


def _utf16(text):
    # @bufbuild/cel orders text as JavaScript does, by UTF-16 code units
    return text.encode("utf-16-be")


def _value(tree, bindings):
    tag = tree[0]
    if tag == "lit":
        return tree[1]
    if tag == "id":
        return bindings[tree[1]]
    if tag == "list":
        return [_value(t, bindings) for t in tree[1]]
    op, args = tree[1], tree[2]
    if op == "&&":
        return _value(args[0], bindings) and _value(args[1], bindings)
    if op == "||":
        return _value(args[0], bindings) or _value(args[1], bindings)
    if op == "!":
        return not _value(args[0], bindings)
    if op == "size":
        return len(_value(args[0], bindings))
    a, b = (_value(t, bindings) for t in args)
    if op == "in":
        return a in b
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    if isinstance(a, str):
        a, b = _utf16(a), _utf16(b)
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def evaluate_condition(text, bindings, kinds):
    """True or false: the condition `text` with each question id bound to its CEL value (`bindings`) of type `kinds`."""
    tree = parse_condition(text)
    if kind_of(tree, kinds) != "bool":
        raise CelError(f"{text!r} is not true or false")
    return bool(_value(tree, bindings))


def evaluate(world, answers, application_id=None):
    return _Evaluation(world, answers, application_id).run()


def question_kinds(recipe):
    """The CEL type of each question id."""
    return {q["id"]: KIND[q["type"]] for q in recipe["questions"]}


def bindings(world, answers):
    """Each question id bound to its CEL value for these answers, as every condition sees them (rule 3)."""
    evaluation = _Evaluation(world, answers, None)
    return {qid: evaluation.cel_value(qid) for qid in evaluation.questions}


class _Evaluation:
    def __init__(self, world, answers, application_id):
        self.world, self.recipe, self.supplied = world, world.recipe, answers
        self.application_id = application_id or self.recipe["name"].replace("/", ".")
        self.errors = []
        self.questions = {q["id"]: q for q in self.recipe["questions"]}
        self.components = {c["id"]: c for c in self.recipe["components"]}
        self.values, self.asked = {}, {}
        self.in_progress = set()
        self.manifests = dict(world.manifests)
        self.filling = dict(world.filling)

    def error(self, code, path):
        item = {"code": code, "path": path}
        if item not in self.errors:
            self.errors.append(item)

    # ---- rule 1, 2: answers and askWhen ----

    def resolve(self, qid):
        if qid in self.values:
            return self.values[qid]
        q = self.questions[qid]
        asked = True
        if q.get("askWhen") is not None:
            asked = self.holds(q["askWhen"])
        self.asked[qid] = asked
        if not asked:
            # Not asked: the default, or an unset reference. A supplied answer is ignored.
            value = UNSET if q["type"] == "secretRef" else q.get("default", UNSET)
        elif qid in self.supplied:
            value = self.checked(q, self.supplied[qid])
        elif q["type"] != "secretRef" and "default" in q:
            value = q["default"]
        else:
            self.error("unanswered", f"answers.{qid}")
            value = UNSET
        if q["type"] == "set" and isinstance(value, list):
            value = [o for o in q["options"] if o in value]  # rule 13: a set answer is kept in option order, without repeats, so equal answers give equal bytes
        self.values[qid] = value
        return value

    def checked(self, q, value):
        path = f"answers.{q['id']}"
        kind = q["type"]
        ok = False
        if kind == "boolean":
            ok = type(value) is bool
        elif kind == "integer":
            ok = type(value) is int and -(2 ** 31) <= value < 2 ** 31 and ("min" not in q or value >= q["min"]) and ("max" not in q or value <= q["max"])
        elif kind == "choice":
            ok = value in q["options"] and type(value) is type(q["options"][q["options"].index(value)])
        elif kind == "set":
            ok = isinstance(value, list) and all(v in q["options"] for v in value)
        elif kind in ("text", "account"):
            ok = isinstance(value, str) and len(value) <= 500
        elif kind == "secretRef":
            ok = isinstance(value, str) and re.fullmatch(SECRET_REFERENCE, value) is not None
        if not ok:
            self.error("invalid-answer", path)
            return UNSET
        return value

    # ---- rule 3: conditions ----

    def kinds(self):
        return {qid: KIND[q["type"]] for qid, q in self.questions.items()}

    def cel_value(self, qid):
        """A question's answer as a CEL value (rules 1 and 13); a question with no value (an unset reference, an unanswered or
        invalid answer, already reported) is the zero value of its type."""
        value = self.resolve(qid)
        return ZERO[KIND[self.questions[qid]["type"]]] if value is UNSET else value

    def holds(self, condition):
        names = names_in(parse_condition(condition)) & set(self.questions)
        return evaluate_condition(condition, {qid: self.cel_value(qid) for qid in names}, self.kinds())

    # ---- the run ----

    def run(self):
        recipe = self.recipe
        for qid in self.supplied:
            if qid not in self.questions:
                self.error("invalid-answer", f"answers.{qid}")
        for q in recipe["questions"]:
            self.resolve(q["id"])

        for slot in self.world.substitutes:
            if slot not in self.components:
                self.error("unknown-slot", slot)
        for c in recipe["components"]:  # unknown components, and the preferred component must fit its slot
            if c["id"] not in self.filling:
                self.error("unknown-component", c["id"])
                continue
            preferred = self.world.packages.get((c["preferred"]["name"], c["preferred"]["version"]))
            if preferred is None:
                self.error("unknown-component", c["id"])
                continue
            for reason in fit(c["class"], self.filling[c["id"]], preferred):
                self.error("unfit", f"{c['id']}:{reason}")
        if self.errors:
            return self.failure()

        order = [c["id"] for c in recipe["components"] if c.get("includedWhen") is None or self.holds(c["includedWhen"])] + [APPLICATION]
        included = set(order)
        self.order = order

        selections, selected_settings = self.select(included)
        included_components = [c for c in recipe["components"] if c["id"] in included]

        settings = self.settings(included, selected_settings)
        connections = self.connections(included)
        if self.errors:
            return self.failure()

        design = {
            "format": 1,
            "id": self.application_id,
            "title": recipe["title"],
            "recipe": {"name": recipe["name"], "version": recipe["version"]},
            "components": [{"id": c["id"], "name": self.filling[c["id"]].name, "version": self.filling[c["id"]].version,
                            "configuration": settings[c["id"]]} for c in included_components],
            "configuration": settings[APPLICATION],
            "design": {"definitions": [], "instances": [], "connections": connections},
            "updatePolicy": "patch",
            "answers": {qid: v for qid, v in self.values.items() if self.asked[qid] and v is not UNSET},
            "selections": selections,
        }
        return {"ok": True, "design": design}

    def failure(self):
        return {"ok": False, "errors": self.errors}

    # ---- rule 7: jobs and scale ----

    def band(self):
        scale = self.recipe.get("scale")
        if not scale:
            return None
        answer = self.values.get(scale["question"])
        return next((b for b in scale["bands"] if b["id"] == answer), None)

    @staticmethod
    def words(text):
        return re.sub(r"[^a-z0-9]+", " ", str(text).lower()).split()

    def names(self, answer, profile):
        """Rule 14: "the named profile or provider". The answer names a candidate when its words begin the words of the
        profile id or of the provider's name (`cloudflare` names cloudflare-free and a provider "Cloudflare Workers ...";
        `own-hardware` names the profile own-hardware)."""
        wanted = self.words(answer)
        for text in (profile["id"], (profile.get("provider") or {}).get("name") or ""):
            have = self.words(text)
            if wanted and have[: len(wanted)] == wanted:
                return True
        return False

    def select(self, included):
        """Rule 7 per job: the job's slot takes the lowest-cost candidate that fits the scale; a substituted slot is fixed."""
        selections, writes = {}, {}
        band = self.band()
        for slot, (name, version) in self.world.substitutes.items():
            if slot in included:
                selections[slot] = {"component": name, "version": version, "reason": "substituted"}
        for job in self.recipe.get("jobs", []):
            slot = job.get("slot")
            if slot not in self.components:
                self.error("unknown-slot", f"jobs.{job['id']}.{slot}")
                continue
            if slot not in included or slot in self.world.substitutes:
                continue  # rule 15: a job whose slot is left out selects nothing and cannot be uncovered
            spec = self.components[slot]
            preferred = self.world.packages[(spec["preferred"]["name"], spec["preferred"]["version"])]
            candidates = []
            for candidate in job["candidates"]:
                key = candidate_key(candidate, spec["preferred"])
                package = self.world.packages.get(key)
                if package is None:
                    self.error("unknown-component", f"jobs.{job['id']}.{candidate['component']}")
                    continue
                for reason in fit(spec["class"], package, preferred):
                    self.error("unfit", f"{slot}:{candidate['component']}:{reason}")
                if candidate.get("includedWhen") is not None and not self.holds(candidate["includedWhen"]):
                    continue
                profile = next((p for p in package.suitability["profiles"] if p["id"] == candidate["profile"]), None)
                if profile is None:
                    self.error("unknown-component", f"jobs.{job['id']}.{candidate['component']}.{candidate['profile']}")
                    continue
                candidates.append((package, candidate, profile))
            if not candidates:
                continue
            override = job.get("overrideQuestion")
            restricted = candidates
            if override is not None and self.values.get(override) not in (None, UNSET):
                restricted = [c for c in candidates if self.names(self.values[override], c[2])]
            load = band["load"] if band else {}
            # rule 16: no source for a requested region or compliance; the recipe asks for neither.
            fitting = [c for c in restricted
                       if all(v >= load.get(k, 0) for k, v in c[2]["load"].items()) and "any" in c[2]["regions"]]
            if not fitting:
                self.error("uncovered", job["id"])
                continue
            best = min(COST_RANK[c[2]["cost"]] for c in fitting)
            package, candidate, profile = next(c for c in fitting if COST_RANK[c[2]["cost"]] == best)
            why = f"scale {band['id'] if band else 'unstated'}; {len(fitting)} of {len(candidates)} candidates fit"
            if len(restricted) != len(candidates):
                why += f"; the {override} answer {self.values[override]} named {len(restricted)}"
            why += f"; lowest cost {profile['cost']}"
            selections[job["id"]] = {"component": package.name, "version": package.version, "profile": profile["id"], "reason": why}
            self.filling[slot] = package
            self.manifests[slot] = package.manifest
            # rule 23: a profile's own settings are applied after the recipe's configuration and before question sets.
            values = dict(profile.get("settings") or {})
            # rule 17: the selection writes a `provider` setting from the selected profile id.
            if any(s["id"] == "provider" for s in package.manifest["collect"]):
                values.setdefault("provider", profile["id"])
            writes[slot] = values
        return selections, writes

    # ---- rules 5, 6: settings ----

    def declaration(self, instance, setting):
        return next((s for s in self.manifests[instance]["collect"] if s["id"] == setting), None)

    def target(self, text):
        best = None
        for instance in list(self.components) + [APPLICATION]:
            if text.startswith(instance + ".") and (best is None or len(instance) > len(best)):
                best = instance
        return (best, text[len(best) + 1:]) if best else (None, None)

    def form_value(self, q, value, instance, setting):
        """The value one `sets` form gives, UNSET when it gives none (rule 6)."""
        answer = self.values[q["id"]]
        decl = self.declaration(instance, setting)
        if value == "$answer":
            if answer is UNSET:
                return UNSET
            if q["type"] == "set":
                return " ".join(answer)
            if q["type"] == "text" and answer == "":
                return UNSET  # rule 18: an empty text answer writes nothing, so the lower precedence value (or none) stays
            return answer
        if isinstance(value, dict):
            (kind, argument), = value.items()
            if kind == "map":
                return argument[str(answer)] if answer is not UNSET else UNSET
            if kind == "fromScale":
                band = self.band()
                return band["load"][argument] if band else UNSET
            if kind == "template":
                if answer is UNSET or answer == "":
                    return UNSET
                return argument.replace("{{answer}}", str(answer))
            if kind == "ref":
                return self.resolve(argument)
        return value  # a literal

    def settings(self, included, selected):
        """Effective settings of every included instance: collect default < recipe configuration < selection < question sets."""
        out, origin = {}, {}
        for instance in self.order:
            manifest = self.manifests[instance]
            values = {s["id"]: s["default"] for s in manifest["collect"] if "default" in s}
            configuration = {} if instance == APPLICATION else self.components[instance].get("configuration", {})
            for setting, value in {**configuration, **selected.get(instance, {})}.items():
                if self.declaration(instance, setting) is None:
                    self.error("unknown-setting", f"{instance}.{setting}")
                else:
                    values[setting] = value
            out[instance] = values
        # question sets, in question order
        records = {}
        for q in self.recipe["questions"]:
            for effect in q.get("effects", []):
                for target, form in effect.get("sets", {}).items():
                    instance, setting = self.target(target)
                    if instance is None:
                        self.error("unknown-component", target)
                        continue
                    if self.declaration(instance, setting) is None:
                        self.error("unknown-setting", target)
                        continue
                    if instance not in included:
                        continue  # rule 5: ignored on an excluded component
                    value = self.form_value(q, form, instance, setting)
                    if value is UNSET:
                        continue
                    records.setdefault((instance, setting), []).append((q["id"], self.asked[q["id"]], value))
        for (instance, setting), items in records.items():
            # rule 19: effects of unasked questions still apply (clarification c), so two questions that exclude each other by
            # askWhen both write; the asked one wins. Two asked questions giving different values conflict.
            winners = [i for i in items if i[1]] or items
            if len({json.dumps(i[2]) for i in winners if i[1]}) > 1:
                self.error("conflicting-sets", f"{instance}.{setting}")
            out[instance][setting] = winners[-1][2]
            origin[(instance, setting)] = f"answers.{winners[-1][0]}"
        # secret references and types; required settings
        for instance in self.order:
            for decl in self.manifests[instance]["collect"]:
                sid, path = decl["id"], f"{instance}.{decl['id']}"
                if sid not in out[instance]:
                    if decl["required"]:
                        self.error("missing-setting", path)
                    continue
                value = out[instance][sid]
                problem = self.setting_problem(decl, value)
                # rules 21 and 22: a text answer has no grammar of its own and a secretRef answer's grammar is that of the setting it fills (a
                # secret setting takes a reference name, a plain one such as accountReference its grammar), so both are checked here and a
                # failure is an `invalid-answer` at the answer.
                if problem:
                    self.error("invalid-answer", origin.get((instance, sid), path))
                elif decl["secret"] and not isinstance(value, dict):
                    out[instance][sid] = {"secretRef": value}
        return out

    @staticmethod
    def setting_problem(decl, value):
        if decl["secret"]:
            name = value["secretRef"] if isinstance(value, dict) and set(value) == {"secretRef"} else value
            return not (isinstance(name, str) and re.fullmatch(SECRET_REFERENCE, name))
        if decl["type"] == "boolean":
            return type(value) is not bool
        if decl["type"] == "integer":
            return not (type(value) is int and -(2 ** 31) <= value < 2 ** 31)
        return not fits_grammar(decl["grammar"], value)

    # ---- rules 8, 9: connections ----

    def connections(self, included):
        kept = []
        for c in self.recipe["connections"]:
            s, t = c["source"], c["target"]
            for end in (s, t):
                if end["instance"] != APPLICATION and end["instance"] not in self.components:
                    self.error("unknown-component", end["instance"])
            if s["instance"] in included and t["instance"] in included:
                kept.append({"source": dict(s), "target": dict(t)})
        count = {}
        for c in kept:
            key = (c["target"]["instance"], c["target"]["port"])
            count[key] = count.get(key, 0) + 1
        for instance in self.order:
            for port in self.manifests[instance]["requires"]:
                if port.get("optional"):
                    continue
                if count.get((instance, port["id"]), 0) != 1:  # rule 20: no code for "connected twice"; it is reported as unconnected too
                    self.error("unconnected", f"{instance}.{port['id']}")
        return kept


def to_json(result):
    """Canonical bytes: every object's keys sorted, two-space indent, a final newline."""
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def slot_fit(world, slot, package):
    """Why `package` does not fit `slot` of the world's recipe, or an empty list when it fits."""
    spec = world.slots[slot]
    preferred = world.packages[(spec["preferred"]["name"], spec["preferred"]["version"])]
    return fit(spec["class"], package, preferred)
